//! Append a record to an archive at the lowest layer.
//!
//! Nothing here is read for its meaning, so the field lines are given exactly as they are to
//! be written. This is the escape hatch for a record the semantic layer would refuse, and for
//! one whose spelling has to be preserved as it stands.

mod common;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::parse::raw::RecordHeader;
use archivindex_warc::version::WarcVersion;
use chrono::{SecondsFormat, Utc};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let date = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let body = format!("wrote to the file on {date}").into_bytes();

    let mut header = RecordHeader::new(WarcVersion::V1_1);
    header.headers = vec![
        ("WARC-Type".to_owned(), b" resource".to_vec()),
        (
            "WARC-Record-ID".to_owned(),
            format!(" <urn:uuid:{}>", Uuid::new_v4()).into_bytes(),
        ),
        (
            "WARC-Target-URI".to_owned(),
            b" http://example.com/index.html".to_vec(),
        ),
        ("WARC-Date".to_owned(), format!(" {date}").into_bytes()),
        ("WARC-IP-Address".to_owned(), b" 127.0.0.1".to_vec()),
        ("Content-Type".to_owned(), b" text/plain".to_vec()),
        (
            "Content-Length".to_owned(),
            format!(" {}", body.len()).into_bytes(),
        ),
    ];
    let record = header.with_body(body);

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;
    let bytes_written = file.write(&record)?;

    println!("{bytes_written} bytes written.");

    Ok(())
}
