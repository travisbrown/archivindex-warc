//! Read an archive all the way up to the semantic layer.
//!
//! Semantic records have typed fields checked against the record type and declared WARC version.

mod common;

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = WarcReader::from_path(common::tmp_path("warc_example.warc")?)?;

    let mut count = 0;
    // No extension is in force, so only standard record types and fields are recognized.
    for record in file.iter_records::<NoExtension>().records() {
        count += 1;
        match record {
            Err(error) => println!("ERROR: {error}\r\n"),
            Ok(record) => {
                let core = record.core();
                println!("{}", record.type_name());
                println!("  id:   {}", core.record_id.as_str());
                println!("  date: {}", core.date);
                println!("  size: {} bytes", record.content_length());
                println!();
            }
        }
    }

    println!("Total records: {count}");

    Ok(())
}
