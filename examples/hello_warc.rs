use archivindex_warc::{RawRecordHeader, Record, RecordType, WarcHeader};
use chrono::prelude::*;

fn main() {
    let body = "hello warc! 👋".to_owned();

    let headers = RawRecordHeader::from_fields(
        archivindex_warc::WarcVersion::V1_0,
        [
            (
                WarcHeader::RecordID,
                Record::generate_record_id().into_bytes(),
            ),
            (
                WarcHeader::WarcType,
                RecordType::WarcInfo.to_string().into_bytes(),
            ),
            (
                WarcHeader::Date,
                Utc::now()
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .into_bytes(),
            ),
            (WarcHeader::IPAddress, "127.0.0.1".to_owned().into_bytes()),
            (
                WarcHeader::ContentLength,
                body.len().to_string().into_bytes(),
            ),
        ],
    );

    println!("{}{}", headers, body);
}
