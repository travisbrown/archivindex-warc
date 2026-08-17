//! Read an archive at the grammar layer, reporting what each record's core fields say.
//!
//! Each value is read against the rule its field name selects, so a record identifier comes back
//! as a URI and a date as a timestamp. A record's block is framed by the `Content-Length` it
//! declares, which is the one field the layer below this one has to read.

mod common;

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::parse::untyped::Record;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::parse::untyped::value::HeaderValue;

/// The reading of a field's value, or a note that the record does not carry the field.
fn form(record: &Record, field: Field) -> String {
    record
        .header
        .get(field)
        .and_then(HeaderValue::form)
        .map_or_else(|| "(none)".to_owned(), ToString::to_string)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = WarcReader::from_path(common::tmp_path("warc_example.warc")?)?;

    let mut count = 0;
    for record in file.iter_untyped_records() {
        count += 1;
        match record {
            Err(error) => println!("ERROR: {error}\r\n"),
            Ok(record) => {
                println!("{}", form(&record, Field::WarcType));
                println!("  id:   {}", form(&record, Field::RecordID));
                println!("  date: {}", form(&record, Field::Date));
                println!("  size: {} bytes", record.content_length());
                println!();
            }
        }
    }

    println!("Total records: {count}");

    Ok(())
}
