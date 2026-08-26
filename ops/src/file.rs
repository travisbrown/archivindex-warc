//! Reading and writing WARC files by path.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::io::write::{Compression, WarcWriter};
use archivindex_warc::parse::raw;
use flate2::bufread::MultiGzDecoder;
use tempfile::TempPath;

use crate::{Error, Result};

/// Open a file for reading, decompressing when the path names a gzip file.
pub fn read(path: &Path) -> Result<Box<dyn BufRead>> {
    let file = File::open(path).map_err(|source| Error::Open {
        path: path.to_owned(),
        source,
    })?;
    let file = BufReader::new(file);

    Ok(if is_gzip(path) {
        Box::new(BufReader::new(MultiGzDecoder::new(file)))
    } else {
        Box::new(file)
    })
}

/// Open a WARC file for reading, decompressing when the path names a gzip file.
pub fn open(path: &Path) -> Result<WarcReader<Box<dyn BufRead>>> {
    read(path).map(WarcReader::new)
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
