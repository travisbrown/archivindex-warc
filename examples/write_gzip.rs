mod common;

use archivindex_warc::{RawRecordHeader, Record, RecordType, WarcHeader, WarcWriter};
use chrono::prelude::*;

fn main() -> Result<(), std::io::Error> {
    let date = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let body = format!("wrote to the file on {}", date);
    let body = body.into_bytes();

    let headers = RawRecordHeader::from_fields(
        archivindex_warc::WarcVersion::V1_0,
        [
            (
                WarcHeader::RecordID,
                Record::generate_record_id().into_bytes(),
            ),
            (
                WarcHeader::WarcType,
                RecordType::Warcinfo.to_string().into_bytes(),
            ),
            (WarcHeader::Date, date.into_bytes()),
            (WarcHeader::IPAddress, "127.0.0.1".to_owned().into_bytes()),
            (
                WarcHeader::ContentLength,
                body.len().to_string().into_bytes(),
            ),
        ],
    );

    let mut file = WarcWriter::from_path_gzip(common::tmp_path("warc_example.warc.gz")?)?;

    let bytes_written = file.write_raw(&headers, &body)?;

    // NB: the compression stream must be finish()ed, or the file will be truncated
    let gzip_stream = file.finish()?;
    gzip_stream.finish()?;

    println!("{} bytes written.", bytes_written);

    Ok(())
}
