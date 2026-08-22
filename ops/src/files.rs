//! Opening WARC files by path.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use archivindex_warc::io::read::WarcReader;
use flate2::bufread::MultiGzDecoder;

use crate::{Error, Result};

/// Open a WARC file for reading, decompressing when the path names a gzip file.
pub fn open(path: &Path) -> Result<WarcReader<Box<dyn BufRead>>> {
    let file = File::open(path).map_err(|source| Error::Open {
        path: path.to_owned(),
        source,
    })?;
    let file = BufReader::new(file);
    let reader: Box<dyn BufRead> = if is_gzip(path) {
        Box::new(BufReader::new(MultiGzDecoder::new(file)))
    } else {
        Box::new(file)
    };

    Ok(WarcReader::new(reader))
}

/// Whether a path names a gzip-compressed file.
pub fn is_gzip(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}
