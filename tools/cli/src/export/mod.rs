//! The `export` command.
//!
//! Each format reads semantic WARC records and writes them to a sink, stopping at the first record
//! that cannot be read.

pub mod csv;
pub mod json;

use std::io::BufRead;

use anyhow::{Context, Result};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::Record;

/// The records of `reader` with their positions, each read error naming its record.
fn records<R: BufRead>(reader: R) -> impl Iterator<Item = Result<(usize, Record)>> {
    WarcReader::new(reader)
        .iter_records()
        .records()
        .enumerate()
        .map(|(index, result)| {
            result
                .map(|record| (index, record))
                .with_context(|| format!("cannot read record {index}"))
        })
}
