use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use warc::WarcReader;

use crate::model::ValidationResult;

pub fn run_warc(file: &Path) -> ValidationResult {
    const NAME: &str = "warc 0.4";
    match validate(file) {
        Ok(0) => ValidationResult::failed(NAME, "file contains no WARC records", String::new()),
        Ok(count) => ValidationResult::passed(NAME, record_count(count), String::new()),
        Err(error) => ValidationResult::failed(NAME, format!("{error:#}"), String::new()),
    }
}

fn validate(file: &Path) -> Result<usize> {
    if is_gzip(file) {
        let mut reader =
            WarcReader::from_path_gzip(file).context("could not open gzip WARC file")?;
        count_records(&mut reader)
    } else {
        // warc 0.4.0's `from_path` combines read-only access with `create(true)`, which
        // `OpenOptions` rejects. Constructing the public reader directly avoids that bug.
        let input = File::open(file).context("could not open WARC file")?;
        let mut reader = WarcReader::new(BufReader::new(input));
        count_records(&mut reader)
    }
}

fn count_records<R>(reader: &mut WarcReader<R>) -> Result<usize>
where
    R: BufRead,
{
    let mut count = 0;
    let mut records = reader.stream_records();
    while let Some(record) = records.next_item() {
        record.with_context(|| format!("record {} is invalid", count + 1))?;
        count += 1;
    }
    Ok(count)
}

fn is_gzip(file: &Path) -> bool {
    file.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}

fn record_count(count: usize) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} record{suffix} parsed")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tempfile::{Builder, NamedTempFile};

    use super::*;

    const VALID_WARC: &[u8] = concat!(
        "WARC/1.1\r\n",
        "WARC-Type: resource\r\n",
        "WARC-Record-ID: <urn:uuid:12345678-1234-1234-1234-123456789abc>\r\n",
        "WARC-Date: 2026-08-14T12:00:00Z\r\n",
        "WARC-Target-URI: https://example.com/\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
        "\r\n\r\n",
    )
    .as_bytes();

    #[test]
    fn validates_a_minimal_warc() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), VALID_WARC).unwrap();
        assert_eq!(validate(file.path()).unwrap(), 1);
    }

    #[test]
    fn validates_a_minimal_gzip_warc() {
        let mut file = Builder::new().suffix(".warc.gz").tempfile().unwrap();
        let mut encoder = GzEncoder::new(file.as_file_mut(), Compression::default());
        encoder.write_all(VALID_WARC).unwrap();
        encoder.finish().unwrap();
        assert_eq!(validate(file.path()).unwrap(), 1);
    }

    #[test]
    fn rejects_an_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let result = run_warc(file.path());
        assert!(!result.is_success());
    }
}
