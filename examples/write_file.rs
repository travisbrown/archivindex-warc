//! Write a `warcinfo` record built at the semantic layer.
//!
//! A [`Record`] holds what a record means rather than how it is spelled: its fields are typed,
//! only the fields its type permits can be set, and its block is the `warc-fields` body the
//! `warcinfo` type calls for. Rendering it with `into_raw` is what turns that into field lines,
//! in the conventional order and under this crate's own spelling.

mod common;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::record::{Record, fields};
use chrono::Utc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = fields::Body::new();
    body.push(WarcinfoField::Software, "archivindex-warc/0.1.0")?;
    body.push(WarcinfoField::Hostname, "localhost")?;

    // The builder is chosen by record type, so `WARC-Filename` is a method here and would not be
    // one on any other type, and the record declares the `application/warc-fields` type a
    // `warcinfo` block customarily has. The record is left to name itself, which it does with a
    // generated `urn:uuid` identifier.
    let record: Record = Record::warcinfo(Utc::now())
        .filename("warc_example.warc")?
        .fields(body)?;

    // The record declares its own version, which is WARC 1.1 unless the builder is told
    // otherwise, and that is the version it is written under.
    let record = record.into_raw()?;

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let bytes_written = file.write(&record)?;

    println!("{bytes_written} bytes written.");

    Ok(())
}
