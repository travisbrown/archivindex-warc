//! Write a gzip-compressed archive holding two records.
//!
//! The second record carries a `WARC-Target-URI`, which is what the `read_filtered` example
//! filters this archive on.

mod common;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::parse::raw::{Record, RecordHeader};
use archivindex_warc::version::WarcVersion;
use chrono::{SecondsFormat, Utc};
use uuid::Uuid;

/// Build a raw record with the given type, body, and additional field lines.
fn record(record_type: &str, lines: &[(&str, &str)], body: Vec<u8>) -> Record {
    let mut header = RecordHeader::new(WarcVersion::V1_1);
    header.headers = vec![
        (
            "WARC-Type".to_owned(),
            format!(" {record_type}").into_bytes(),
        ),
        (
            "WARC-Record-ID".to_owned(),
            format!(" <urn:uuid:{}>", Uuid::new_v4()).into_bytes(),
        ),
        (
            "WARC-Date".to_owned(),
            format!(" {}", Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)).into_bytes(),
        ),
    ];
    header.headers.extend(
        lines
            .iter()
            .map(|(name, value)| ((*name).to_owned(), format!(" {value}").into_bytes())),
    );
    header.headers.push((
        "Content-Length".to_owned(),
        format!(" {}", body.len()).into_bytes(),
    ));

    header.with_body(body)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let date = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    let warcinfo = record(
        "warcinfo",
        &[("Content-Type", "application/warc-fields")],
        b"software: archivindex-warc/0.1.0\r\n".to_vec(),
    );
    let resource = record(
        "resource",
        &[
            ("WARC-Target-URI", "http://example.com/index.html"),
            ("Content-Type", "text/plain"),
        ],
        format!("wrote to the file on {date}").into_bytes(),
    );

    let mut file = WarcWriter::from_path_gzip(common::tmp_path("warc_example.warc.gz")?)?;
    let bytes_written = file.write(&warcinfo)? + file.write(&resource)?;

    // NB: the compression stream must be finish()ed, or the file will be truncated
    let gzip_stream = file.finish()?;
    gzip_stream.finish()?;

    println!("{bytes_written} bytes written.");

    Ok(())
}
