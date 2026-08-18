//! Write a `warcinfo` record built at the semantic layer.
//!
//! A semantic [`Record`] has typed fields and enforces the fields allowed for its record type.

mod common;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::record::Record;
use chrono::Utc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The builder is chosen by record type, so `WARC-Filename` is a method here and would not be
    // one on any other type, as are the fields a `warcinfo` block is written from. The record is
    // left to name itself, which it does with a generated `urn:uuid` identifier, and its body
    // opens naming this software and the version of the standard the record declares.
    let record: Record = Record::warcinfo(Utc::now())
        .filename("warc_example.warc")?
        .hostname("localhost")?
        .build();

    // Render the semantic record into raw field lines and a body.
    let record = record.into_raw()?;

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let bytes_written = file.write(&record)?;

    println!("{bytes_written} bytes written.");

    Ok(())
}
