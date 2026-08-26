//! Opening WARC files by path.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::io::write::Compression;
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
