//! Read a gzip-compressed archive, skipping the records whose target URI names one of the
//! files given on the command line.
//!
//! The filter reads the header block alone, so a skipped record's body is consumed without ever
//! being buffered.

mod common;

use archivindex_warc::io::read::WarcReader;

macro_rules! usage_err {
    ($str:expr) => {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, $str.to_string())
    };
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args_os().skip(1);

    let warc_name = args
        .next()
        .ok_or_else(|| usage_err!("compressed warc filename not supplied"))?;

    let filtered_file_names: Vec<_> = args.map(|s| s.to_string_lossy().to_string()).collect();
    if filtered_file_names.is_empty() {
        Err(usage_err!("one or more filtered file names not supplied"))?;
    }

    let file = WarcReader::from_path_gzip(common::tmp_path(warc_name)?)?;

    let mut count = 0;
    let mut skipped = 0;
    // The closure borrows the counter for as long as the iterator lives, which is the loop, so
    // the count can be read again once the loop has ended.
    let kept = file
        .filter_raw_records(|header| {
            // A raw record keeps the white space a value was written with, so the value is trimmed
            // before it is read as a URI.
            let target_uri = header
                .get("WARC-Target-URI")
                .map(|value| String::from_utf8_lossy(value).trim().to_owned());

            match target_uri {
                Some(uri) if has_matching_filename(&uri, &filtered_file_names) => {
                    println!("Matches filename, skipping record");
                    skipped += 1;
                    false
                }
                _ => true,
            }
        })
        .records();

    for record in kept {
        let record = record.expect("read of record ok");
        count += 1;
        println!(
            "Found record. Data:\n{}",
            String::from_utf8_lossy(&record.body)
        );
    }

    println!(
        "Total records: {}\nSkipped records: {skipped}",
        count + skipped
    );

    Ok(())
}

fn has_matching_filename(u: &str, matches: &[String]) -> bool {
    let url = url::Url::parse(u).expect("Target URI is not a URI!?");
    url.path_segments()
        .and_then(|mut segments| segments.next_back())
        .is_some_and(|last_segment| matches.iter().any(|name| name == last_segment))
}
