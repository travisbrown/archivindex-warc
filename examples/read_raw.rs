//! Read an archive at the lowest layer, printing every field line as it was written.
//!
//! Raw records preserve field-name case, values, and white space.

mod common;

use archivindex_warc::io::read::WarcReader;

fn main() -> Result<(), std::io::Error> {
    let file = WarcReader::from_path(common::tmp_path("warc_example.warc")?)?;

    let mut count = 0;
    for record in file.iter_raw_records() {
        count += 1;
        match record {
            Err(error) => println!("ERROR: {error}\r\n"),
            Ok(record) => {
                println!("WARC/{}", record.header.version.as_str());
                for (name, value) in &record.header.headers {
                    println!("  {name}:{}", String::from_utf8_lossy(value).escape_debug());
                }
                println!();
            }
        }
    }

    println!("Total records: {count}");

    Ok(())
}
