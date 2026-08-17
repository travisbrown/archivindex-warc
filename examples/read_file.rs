//! Read an archive all the way up to the semantic layer.
//!
//! Each record is read against the grammars first, then lifted into a semantic record, which is
//! where a field is checked against the record's type and its declared version. A record the
//! standard does not permit stops here rather than at the layers below it.

mod common;

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = WarcReader::from_path(common::tmp_path("warc_example.warc")?)?;

    let mut count = 0;
    // No extension is in force, so the only record types and fields recognized are the ones the
    // standard itself defines.
    for record in file.iter_records::<NoExtension>() {
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
