//! Write a `warcinfo` record built at the semantic layer.
//!
//! A semantic [`Record`] has typed fields and enforces the fields allowed for its record type.

mod common;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::record::{Record, fields};
use archivindex_warc::value::Text;
use chrono::Utc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = fields::Body::new();
    body.push(WarcinfoField::Software, "archivindex-warc/0.1.0")?;
    body.push(WarcinfoField::Hostname, "localhost")?;

    // The builder is chosen by record type, so `WARC-Filename` is a method here and would not be
    // one on any other type, and a block given as fields declares itself as `warc-fields`. The
    // record is left to name itself, which it does with a generated `urn:uuid` identifier.
    let record: Record = Record::warcinfo(Utc::now())
        .filename(Text::parse(b"warc_example.warc")?)
        .fields(body)?;

    // Render the semantic record into raw field lines and a body.
    let record = record.into_raw()?;

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let bytes_written = file.write(&record)?;

    println!("{bytes_written} bytes written.");

    Ok(())
}
