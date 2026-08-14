mod common;

use chrono::prelude::*;
use warc::{RawRecordHeader, Record, RecordType, WarcHeader, WarcWriter};

fn main() -> Result<(), std::io::Error> {
    let date = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let body = format!("wrote to the file on {}", date);
    let body = body.into_bytes();

    let headers = RawRecordHeader {
        version: warc::WarcVersion::V1_0,
        headers: vec![
            (
                WarcHeader::RecordID,
                Record::generate_record_id().into_bytes(),
            ),
            (
                WarcHeader::WarcType,
                RecordType::WarcInfo.to_string().into_bytes(),
            ),
            (WarcHeader::Date, date.into_bytes()),
            (WarcHeader::IPAddress, "127.0.0.1".to_owned().into_bytes()),
            (
                WarcHeader::ContentLength,
                body.len().to_string().into_bytes(),
            ),
        ]
        .into_iter()
        .collect(),
        concurrent_to: Vec::new(),
    };

    let mut file = WarcWriter::from_path_gzip(common::tmp_path("warc_example.warc.gz")?)?;

    let bytes_written = file.write_raw(&headers, &body)?;

    // NB: the compression stream must be finish()ed, or the file will be truncated
    let gzip_stream = file.into_inner()?;
    gzip_stream.finish()?;

    println!("{} bytes written.", bytes_written);

    Ok(())
}
