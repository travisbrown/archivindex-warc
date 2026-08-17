//! Build a record at the lowest layer and print the bytes it writes as.
//!
//! A record is a header, which declares a version and lists field lines, together with a
//! block, and nothing here is read for its meaning. Every value is written out in full,
//! including the space after
//! the colon that the standard's own examples use, because a raw record keeps a value exactly
//! as it is given.

use archivindex_warc::parse::raw::RecordHeader;
use archivindex_warc::version::WarcVersion;
use chrono::{SecondsFormat, Utc};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = "hello warc! 👋";

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
        (
            "Content-Length".to_owned(),
            format!(" {}", body.len()).into_bytes(),
        ),
    ];

    // Writing checks that the record can be written at all, which for a record built by hand
    // is mostly that its `Content-Length` is the length of the block it is given.
    let record = header.with_body(body.as_bytes());

    print!("{}", String::from_utf8_lossy(&record.to_bytes()?));

    Ok(())
}
