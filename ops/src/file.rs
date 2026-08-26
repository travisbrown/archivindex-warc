//! Reading and writing WARC files by path, where the path `-` names standard input.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read};
use std::path::{Path, PathBuf};

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::io::write::{Compression, WarcWriter};
use archivindex_warc::parse::raw;
use tempfile::TempPath;

use crate::gzip::{Framing, MemberReader};
use crate::{Error, Result};

/// The path that names standard input.
const STDIN: &str = "-";

/// The two bytes every gzip member begins with.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Open a file, or standard input for `-`, and decompress gzip input.
///
/// A path names a gzip file by its extension; standard input is gzip when it begins with the
/// gzip magic number.
pub fn read(path: &Path) -> Result<Box<dyn BufRead>> {
    read_framed(path).map(|(reader, _)| reader)
}

/// Open a file, or standard input for `-`, for reading, reporting where its gzip members end.
///
/// A path names a gzip file by its extension; standard input is gzip when it begins with the
/// gzip magic number. Input that is not gzip has no members, and yields no framing.
pub fn read_framed(path: &Path) -> Result<(Box<dyn BufRead>, Option<Framing>)> {
    let open = |source| Error::Open {
        path: path.to_owned(),
        source,
    };

    if is_stdin(path) {
        framed_by_magic(io::stdin().lock()).map_err(open)
    } else {
        let file = File::open(path).map_err(open)?;

        Ok(framed(BufReader::new(file), is_gzip(path)))
    }
}

/// Open a WARC file, or standard input for `-`, for reading, decompressing gzip as [`read`] does.
pub fn open(path: &Path) -> Result<WarcReader<Box<dyn BufRead>>> {
    read(path).map(WarcReader::new)
}

/// Whether a path names standard input.
#[must_use]
pub fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == STDIN
}

/// Read `reader` as gzip when it begins with the gzip magic number.
///
/// The bytes read to decide are chained back in front of the rest.
fn framed_by_magic(
    mut reader: impl BufRead + 'static,
) -> io::Result<(Box<dyn BufRead>, Option<Framing>)> {
    let mut head = Vec::with_capacity(GZIP_MAGIC.len());
    reader
        .by_ref()
        .take(GZIP_MAGIC.len() as u64)
        .read_to_end(&mut head)?;
    let gzip = head == GZIP_MAGIC;

    Ok(framed(Cursor::new(head).chain(reader), gzip))
}

/// Read `reader` as gzip members when `gzip`, reporting where they end.
fn framed(reader: impl BufRead + 'static, gzip: bool) -> (Box<dyn BufRead>, Option<Framing>) {
    if gzip {
        let reader = MemberReader::new(reader);
        let framing = reader.framing();
        (Box::new(reader), Some(framing))
    } else {
        (Box::new(reader), None)
    }
}

/// The compression to write at a path, gzip when the path names a gzip file.
#[must_use]
pub fn compression(path: &Path) -> Compression {
    if is_gzip(path) {
        Compression::gzip()
    } else {
        Compression::NONE
    }
}

/// Whether a path names a gzip-compressed file.
#[must_use]
pub fn is_gzip(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}

/// Stream the records of `inputs` through `transform` into `output`, returning the number of
/// records written.
///
/// The records of each input are read in order, with all of one input's records preceding the
/// next's, and are numbered from zero across the inputs. A record the closure returns as `None`
/// is dropped. Both inputs and output are compressed when their paths end in `.gz`, and a
/// compressed output holds one gzip member per record.
///
/// The records are written to `<output>.partial`, synced, and moved into place once the last
/// one is written, so a failure partway through leaves any file already at `output` as it was,
/// and a crash after this returns cannot lose the output.
pub(crate) fn transform<F: FnMut(usize, raw::Record) -> Result<Option<raw::Record>>>(
    inputs: &[&Path],
    output: &Path,
    mut transform: F,
) -> Result<usize> {
    if let Some(path) = inputs.iter().find(|input| is_same_file(input, output)) {
        return Err(Error::SameInputAndOutput {
            path: (*path).to_owned(),
        });
    }

    let readers = inputs
        .iter()
        .map(|input| open(input).map(|reader| (*input, reader)))
        .collect::<Result<Vec<_>>>()?;
    let partial = partial_path(output);
    let file = File::create(&partial).map_err(|source| Error::Create {
        path: partial.clone(),
        source,
    })?;
    // The path owns the file from here on, so every early return removes it.
    let partial = TempPath::try_from_path(&partial).map_err(|source| Error::Create {
        path: partial.clone(),
        source,
    })?;
    let mut writer = WarcWriter::new(BufWriter::new(file)).with_compression(compression(output));
    let mut records = 0;
    let mut index = 0;

    for (path, reader) in readers {
        log::info!("copying records from {}", path.display());

        for result in reader.iter_raw_records() {
            let record = result.map_err(|source| Error::Read {
                path: path.to_owned(),
                source,
            })?;

            if let Some(record) = transform(index, record)? {
                let written = writer.write(&record).map_err(|source| Error::Write {
                    path: partial.to_path_buf(),
                    source,
                })?;
                log::trace!(
                    "wrote {} bytes at offset {}",
                    written.length,
                    written.offset
                );
                records += 1;
            }
            index += 1;
        }
    }

    writer
        .finish()
        .map_err(io::IntoInnerError::into_error)
        .and_then(|file| file.sync_all())
        .map_err(|source| Error::Flush {
            path: partial.to_path_buf(),
            source,
        })?;
    partial.persist(output).map_err(|error| Error::Publish {
        path: output.to_owned(),
        source: error.error,
    })?;
    sync_directory(output).map_err(|source| Error::Publish {
        path: output.to_owned(),
        source,
    })?;

    Ok(records)
}

/// Make the rename that published `output` durable.
///
/// On Unix a rename is durable only once the directory holding it is synced. Windows does not
/// open directories, and its renames need no such step.
fn sync_directory(output: &Path) -> io::Result<()> {
    if cfg!(unix) {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// The path a transformed output is written to before it is moved into place.
fn partial_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".partial");

    path.into()
}

/// Whether an existing input and a not necessarily existing output name the same file.
///
/// Only the output's parent is resolved, so an output that is itself a symbolic link to the input
/// is not recognized. Replacing that link is not destructive.
fn is_same_file(input: &Path, output: &Path) -> bool {
    if input == output {
        return true;
    }

    let Ok(input) = input.canonicalize() else {
        return false;
    };
    let Some(name) = output.file_name() else {
        return false;
    };
    let parent = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    parent
        .canonicalize()
        .is_ok_and(|parent| parent.join(name) == input)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Write;

    use super::*;

    /// A WARC 1.1 resource record framed by the body's length.
    fn render(body: &str) -> Vec<u8> {
        format!(
            "WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: {}\r\n\r\n{body}\r\n\r\n",
            body.len()
        )
        .into_bytes()
    }

    /// A file compressed record by record has a member for each record, which the framing of a
    /// read over it reports.
    #[test]
    fn reports_the_member_framing_of_a_gzip_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.warc.gz");
        let records = [render("first"), render("second")];
        let mut compressed = Vec::new();
        crate::compress::compress(&records.concat()[..], 1, &mut compressed).unwrap();
        std::fs::write(&path, compressed).unwrap();

        let (reader, framing) = read_framed(&path).unwrap();
        let framing = framing.expect("a gzip file reports its framing");
        assert_eq!(WarcReader::new(reader).iter_raw_records().count(), 2);
        let mut boundaries = VecDeque::new();
        framing.take_boundaries(&mut boundaries);

        assert_eq!(
            Vec::from(boundaries),
            [
                records[0].len() as u64,
                (records[0].len() + records[1].len()) as u64
            ]
        );
    }

    /// A file that is not gzip has no members, and so no framing to check.
    #[test]
    fn reports_no_framing_for_an_uncompressed_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.warc");
        std::fs::write(&path, render("body")).unwrap();

        assert!(read_framed(&path).unwrap().1.is_none());
    }

    /// Standard input has no extension, so it is gzip when it begins as a gzip member does.
    #[test]
    fn reads_standard_input_as_gzip_by_its_magic_number() {
        let record = render("body");
        let mut compressed = Vec::new();
        crate::compress::compress(&record[..], 1, &mut compressed).unwrap();

        let (reader, framing) = framed_by_magic(Cursor::new(compressed)).unwrap();
        let framing = framing.expect("gzip standard input reports its framing");
        let records = WarcReader::new(reader)
            .iter_raw_records()
            .map(Result::unwrap)
            .count();
        let mut boundaries = VecDeque::new();
        framing.take_boundaries(&mut boundaries);

        assert_eq!(records, 1);
        assert_eq!(Vec::from(boundaries), [record.len() as u64]);
    }

    /// The bytes read to look for the magic number are read again as part of the input.
    #[test]
    fn reads_uncompressed_standard_input_from_its_first_byte() {
        let record = render("body");

        let (mut reader, framing) = framed_by_magic(Cursor::new(record.clone())).unwrap();
        let mut read = Vec::new();
        reader.read_to_end(&mut read).unwrap();

        assert!(framing.is_none());
        assert_eq!(read, record);
    }

    /// Input shorter than the magic number is not gzip, and is read whole.
    #[test]
    fn reads_standard_input_shorter_than_the_magic_number() {
        let (mut reader, framing) = framed_by_magic(Cursor::new(vec![0x1f])).unwrap();
        let mut read = Vec::new();
        reader.read_to_end(&mut read).unwrap();

        assert!(framing.is_none());
        assert_eq!(read, [0x1f]);
    }

    #[test]
    fn refuses_an_output_that_spells_an_input_differently() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        std::fs::write(&input, render("body")).unwrap();
        let output = directory.path().join(".").join("input.warc");

        let error = transform(&[&input], &output, |_, record| Ok(Some(record))).unwrap_err();

        assert!(matches!(&error, Error::SameInputAndOutput { path } if path == &input));
    }

    #[test]
    fn leaves_the_previous_output_in_place_when_a_record_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        let mut contents = render("body");
        contents.extend_from_slice(b"WARC/1.1\r\nWARC-Type: resource\r\n");
        std::fs::write(&input, contents).unwrap();
        std::fs::write(&output, b"previous").unwrap();

        let error = transform(&[&input], &output, |_, record| Ok(Some(record))).unwrap_err();

        assert!(matches!(error, Error::Read { .. }));
        assert_eq!(std::fs::read(&output).unwrap(), b"previous");
        assert!(!partial_path(&output).exists());
    }

    #[test]
    fn writes_through_a_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        std::fs::write(&input, render("body")).unwrap();
        let mut stale = File::create(partial_path(&output)).unwrap();
        stale.write_all(b"stale").unwrap();
        drop(stale);

        let records = transform(&[&input], &output, |_, record| Ok(Some(record))).unwrap();

        assert_eq!(records, 1);
        assert!(!partial_path(&output).exists());
        assert_eq!(open(&output).unwrap().iter_raw_records().count(), 1);
    }
}
