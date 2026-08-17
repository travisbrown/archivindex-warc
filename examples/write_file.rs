//! Write a `warcinfo` record whose block is a `warc-fields` body.
//!
//! A `warcinfo` record describes the file it opens in named fields rather than carrying a
//! payload, and [`fields::Body`] is what holds those fields and renders the block. The header
//! block is given as the field lines to write, since nothing at this layer reads a field for what
//! it means.

mod common;

use archivindex_warc::fields;
use archivindex_warc::fields::warcinfo::WarcinfoField;
use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::parse::raw::RecordHeader;
use archivindex_warc::version::WarcVersion;
use chrono::{SecondsFormat, Utc};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut body: fields::Body<WarcinfoField> = fields::Body::new();
    body.push(WarcinfoField::Software, "archivindex-warc/0.4.0");
    body.push(WarcinfoField::Hostname, "localhost");

    let block = body.to_string().into_bytes();

    let mut header = RecordHeader::new(WarcVersion::V1_1);
    header.headers = vec![
        ("WARC-Type".to_owned(), b" warcinfo".to_vec()),
        (
            "WARC-Record-ID".to_owned(),
            format!(" <urn:uuid:{}>", Uuid::new_v4()).into_bytes(),
        ),
        (
            "WARC-Date".to_owned(),
            format!(" {}", Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)).into_bytes(),
        ),
        ("WARC-Filename".to_owned(), b" warc_example.warc".to_vec()),
        (
            "Content-Type".to_owned(),
            b" application/warc-fields".to_vec(),
        ),
        (
            "Content-Length".to_owned(),
            format!(" {}", block.len()).into_bytes(),
        ),
    ];

    let record = header.with_body(block);

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let bytes_written = file.write(&record)?;

    println!("{bytes_written} bytes written.");

    Ok(())
}
