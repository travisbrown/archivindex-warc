mod common;

use chrono::prelude::*;
use warc::{Record, RecordType, WarcHeader, WarcWriter};

fn main() -> Result<(), std::io::Error> {
    let date = Utc::now();
    let body = format!("wrote to the file on {}", date);
    let body = body.into_bytes();

    let mut headers = Record::new();
    headers.set_warc_type(RecordType::WarcInfo);
    headers.set_date(date);
    headers
        .set_header(WarcHeader::IPAddress, "127.0.0.1")
        .expect("BUG: should be a valid IP address");
    let record = headers.add_body(body);

    let mut file = WarcWriter::from_path(common::tmp_path("warc_example.warc")?)?;

    let bytes_written = file.write(&record)?;

    println!("{} bytes written.", bytes_written);

    Ok(())
}
