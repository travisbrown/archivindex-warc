//! Write a `warcinfo` record built at the semantic layer.
//!
//! A [`Record`] holds what a record means rather than how it is spelled: its fields are typed,
//! only the fields its type permits can be set, and its block is the `warc-fields` body the
//! `warcinfo` type calls for. Rendering it with `into_raw` is what turns that into field lines,
//! in the conventional order and under this crate's own spelling.

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

    // The record declares its own version, which is WARC 1.1 unless the builder is told
    // otherwise, and that is the version it is written under.
    let record = record.into_raw()?;

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let written = file.write(&record)?;

    println!("{} bytes written.", written.length);

    Ok(())
}
