//! Reading and writing WARC files by path.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::Path;

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::io::write::{Compression, WarcWriter};
use archivindex_warc::parse::raw;
use flate2::bufread::MultiGzDecoder;

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
pub(crate) fn transform<F: FnMut(usize, raw::Record) -> Result<Option<raw::Record>>>(
    inputs: &[&Path],
    output: &Path,
    mut transform: F,
) -> Result<usize> {
    if let Some(path) = inputs.iter().find(|input| **input == output) {
        return Err(Error::SameInputAndOutput {
            path: (*path).to_owned(),
        });
    }

    let readers = inputs
        .iter()
        .map(|input| open(input).map(|reader| (*input, reader)))
        .collect::<Result<Vec<_>>>()?;
    let file = File::create(output).map_err(|source| Error::Create {
        path: output.to_owned(),
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
                    path: output.to_owned(),
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

    writer.flush().map_err(|source| Error::Flush {
        path: output.to_owned(),
        source,
    })?;

    Ok(records)
}
