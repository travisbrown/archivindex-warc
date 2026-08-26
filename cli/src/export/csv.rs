//! One CSV row per record.

use std::fmt::Write as _;
use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use fluent_uri::Uri;

use super::records;

/// The column names written before the first row.
const HEADER: [&str; 4] = ["type", "date", "record_uuid", "target_uri"];

/// The scheme and namespace nearly every record identifier is written in.
const UUID_PREFIX: &str = "urn:uuid:";

/// Write the type, date, record identifier, and target URI of every record as a CSV row.
///
/// A record identifier in the `urn:uuid` namespace is written as a bare UUID and any other is
/// written in full. A record without a target URI leaves that field empty. Returns the number of
/// rows written after the header.
pub fn export<R: BufRead, W: Write>(reader: R, writer: W) -> Result<usize> {
    let mut rows = csv::Writer::from_writer(writer);
    rows.write_record(HEADER)
        .context("cannot write CSV header")?;
    let mut date = String::new();
    let mut count = 0;

    for result in records(reader) {
        let (index, record) = result?;
        let core = record.core();
        date.clear();
        write!(date, "{}", core.date).expect("invariant violation: writing to a String");
        rows.write_record([
            record.type_name(),
            &date,
            record_uuid(&core.record_id),
            record.target_uri().map_or("", Uri::as_str),
        ])
        .with_context(|| format!("cannot write record {index}"))?;
        count += 1;
    }

    rows.flush().context("cannot flush CSV output")?;

    Ok(count)
}

/// A record identifier as a bare UUID, or in full when it is not a `urn:uuid` URI.
fn record_uuid(uri: &Uri<String>) -> &str {
    let id = uri.as_str();

    match id.split_at_checked(UUID_PREFIX.len()) {
        Some((prefix, uuid)) if prefix.eq_ignore_ascii_case(UUID_PREFIX) => uuid,
        _ => id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A WARC 1.1 record with the given fields, framed by the body's length.
    fn render(fields: &[(&str, &str)], body: &str) -> String {
        use std::fmt::Write as _;

        let mut record = String::from("WARC/1.1\r\n");

        for (name, value) in fields {
            write!(record, "{name}: {value}\r\n")
                .expect("invariant violation: writing to a String");
        }
        write!(
            record,
            "Content-Length: {}\r\n\r\n{body}\r\n\r\n",
            body.len()
        )
        .expect("invariant violation: writing to a String");

        record
    }

    #[test]
    fn writes_a_header_and_one_row_per_record() {
        let mut input = render(
            &[
                ("WARC-Type", "warcinfo"),
                ("WARC-Record-ID", "<urn:uuid:1>"),
                ("WARC-Date", "2024-01-02T03:04:05Z"),
                ("Content-Type", "application/warc-fields"),
            ],
            "",
        );
        input.push_str(&render(
            &[
                ("WARC-Type", "resource"),
                ("WARC-Record-ID", "<https://example.com/ids/2>"),
                ("WARC-Date", "2024-01-02T03:04:05.678Z"),
                ("WARC-Target-URI", "https://example.com/a,b"),
            ],
            "body",
        ));
        let mut output = Vec::new();

        let count = export(input.as_bytes(), &mut output).unwrap();

        assert_eq!(count, 2);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "type,date,record_uuid,target_uri\n\
             warcinfo,2024-01-02T03:04:05Z,1,\n\
             resource,2024-01-02T03:04:05.678Z,https://example.com/ids/2,\
             \"https://example.com/a,b\"\n"
        );
    }

    #[test]
    fn an_unreadable_record_fails_the_export() {
        let mut output = Vec::new();

        let error = export(&b"WARC/1.1\r\nbroken"[..], &mut output).unwrap_err();

        assert_eq!(error.to_string(), "cannot read record 0");
    }
}
