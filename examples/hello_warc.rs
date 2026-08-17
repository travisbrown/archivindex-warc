//! Build a record at the lowest layer and print the bytes it writes as.
//!
//! Raw records contain a version, header fields, and a body. Values are written exactly as
//! supplied, including spacing after the colon.

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

    // Writing validates header framing and checks `Content-Length` against the body.
    let record = header.with_body(body.as_bytes());

    print!("{}", String::from_utf8_lossy(&record.to_bytes()?));

    Ok(())
}
