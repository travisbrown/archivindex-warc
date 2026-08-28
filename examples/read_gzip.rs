//! Read a gzip-compressed archive at the grammar layer.
//!
//! The grammar layer parses identifiers as URIs and dates as timestamps. It accepts both WARC
//! versions' value syntax without enforcing record-type restrictions.

mod common;

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::parse::untyped::value::HeaderValue;

/// The reading of a field's value, or a note that the record does not carry the field.
fn form(record: &archivindex_warc::parse::untyped::Record, field: Field) -> String {
    record
        .header
        .get(field)
        .and_then(HeaderValue::form)
        .map_or_else(|| "(none)".to_owned(), ToString::to_string)
}

fn main() -> Result<(), std::io::Error> {
    let file = WarcReader::from_path_gzip(common::tmp_path("warc_example.warc.gz")?)?;

    let mut count = 0;
    for record in file.iter_untyped_records().records() {
        count += 1;
        match record {
            Err(error) => println!("ERROR: {error}\r\n"),
            Ok(record) => {
                println!("{}", form(&record, Field::WarcType));
                println!("  id:   {}", form(&record, Field::RecordID));
                println!("  date: {}", form(&record, Field::Date));
                println!("  uri:  {}", form(&record, Field::TargetURI));
                println!();
            }
        }
    }

    println!("Total records: {count}");

    Ok(())
}
