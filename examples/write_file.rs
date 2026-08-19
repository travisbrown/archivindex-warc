//! Write a `warcinfo` record built at the semantic layer.
//!
//! A semantic [`Record`] has typed fields and enforces the fields allowed for its record type.

mod common;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::record::Record;
use chrono::Utc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The builder generates a `urn:uuid` record identifier and a body describing WARC 1.1.
    let record: Record = Record::warcinfo(Utc::now())
        .filename("warc_example.warc")?
        .hostname("localhost")?
        .build();

    // Render the semantic record into raw field lines and a body.
    let record = record.into_raw()?;

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let written = file.write(&record)?;

    println!("{} bytes written.", written.length);

    Ok(())
}
