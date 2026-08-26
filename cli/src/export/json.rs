//! One JSON line per record with a JSON payload.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use archivindex_warc::value::MediaType;

use super::records;

/// Write the payload of every record whose `WARC-Identified-Payload-Type` is JSON as one line.
///
/// The payload is written byte for byte after any transfer coding is removed, followed by a line
/// feed. A payload may end with one line terminator, which is not repeated. Returns the number of
/// lines written.
///
/// # Errors
///
/// Fails when a record cannot be read, when a JSON-typed record has no payload or a payload that
/// cannot be extracted, when the payload is not JSON, and when it spans more than one line.
pub fn export<R: BufRead, W: Write>(reader: R, mut writer: W) -> Result<usize> {
    let mut count = 0;

    for result in records(reader) {
        let (index, record) = result?;
        if !record
            .payload()
            .and_then(|payload| payload.identified_payload_type.as_ref())
            .is_some_and(is_json)
        {
            continue;
        }

        let id = &record.core().record_id;
        let payload = record
            .payload_bytes()
            .with_context(|| format!("record {index} ({id}): cannot extract the payload"))?;
        let Some(payload) = payload else {
            bail!("record {index} ({id}): the record type has no payload");
        };
        serde_json::from_slice::<serde::de::IgnoredAny>(&payload)
            .with_context(|| format!("record {index} ({id}): the payload is not JSON"))?;
        let Some(line) = single_line(&payload) else {
            bail!("record {index} ({id}): the payload spans more than one line");
        };

        writer
            .write_all(line)
            .and_then(|()| writer.write_all(b"\n"))
            .with_context(|| format!("cannot write record {index}"))?;
        count += 1;
    }

    writer.flush().context("cannot flush JSON output")?;

    Ok(count)
}

/// Whether a media type names JSON: a `json` subtype or a `+json` suffix.
fn is_json(media_type: &MediaType) -> bool {
    let subtype = media_type.subtype().as_bytes();

    subtype.eq_ignore_ascii_case(b"json")
        || subtype
            .len()
            .checked_sub(5)
            .is_some_and(|start| subtype[start..].eq_ignore_ascii_case(b"+json"))
}

/// The payload without one trailing line terminator, or `None` if a line feed remains.
fn single_line(payload: &[u8]) -> Option<&[u8]> {
    let line = payload.strip_suffix(b"\n").unwrap_or(payload);
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    (!line.contains(&b'\n')).then_some(line)
}

#[cfg(test)]
mod tests {
    use archivindex_test_support::render;

    use super::*;

    /// A resource record whose payload is identified as `identified`.
    fn resource(identified: &str, body: &str) -> Vec<u8> {
        render(
            &[
                ("WARC-Type", "resource"),
                ("WARC-Record-ID", "<urn:uuid:1>"),
                ("WARC-Date", "2024-01-02T03:04:05Z"),
                ("WARC-Target-URI", "https://example.com/"),
                ("WARC-Identified-Payload-Type", identified),
            ],
            body,
        )
    }

    fn export_string(input: &[u8]) -> Result<(usize, String)> {
        let mut output = Vec::new();
        let count = export(input, &mut output)?;
        Ok((count, String::from_utf8(output).unwrap()))
    }

    #[test]
    fn writes_json_payloads_verbatim_and_skips_the_rest() {
        let mut input = resource("application/json", r#"{"a": [1, 2]}"#);
        input.extend_from_slice(&resource("text/plain", "not exported"));
        input.extend_from_slice(&resource("application/ld+json", "[1,2]\r\n"));
        input.extend_from_slice(&render(
            &[
                ("WARC-Type", "response"),
                ("WARC-Record-ID", "<urn:uuid:2>"),
                ("WARC-Date", "2024-01-02T03:04:05Z"),
                ("WARC-Target-URI", "https://example.com/"),
                ("Content-Type", "application/http; msgtype=response"),
                ("WARC-Identified-Payload-Type", "application/json"),
            ],
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"b\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        ));

        let (count, output) = export_string(&input).unwrap();

        assert_eq!(count, 3);
        assert_eq!(output, "{\"a\": [1, 2]}\n[1,2]\n{\"b\":1}\n");
    }

    #[test]
    fn a_payload_that_is_not_json_fails() {
        let error = export_string(&resource("application/json", "{oops")).unwrap_err();

        assert_eq!(
            error.to_string(),
            "record 0 (urn:uuid:1): the payload is not JSON"
        );
    }

    #[test]
    fn a_payload_spanning_several_lines_fails() {
        let error = export_string(&resource("application/json", "{\n\"a\": 1\n}")).unwrap_err();

        assert_eq!(
            error.to_string(),
            "record 0 (urn:uuid:1): the payload spans more than one line"
        );
    }

    #[test]
    fn a_record_type_without_a_payload_fails() {
        let input = render(
            &[
                ("WARC-Type", "revisit"),
                ("WARC-Record-ID", "<urn:uuid:1>"),
                ("WARC-Date", "2024-01-02T03:04:05Z"),
                ("WARC-Target-URI", "https://example.com/"),
                (
                    "WARC-Profile",
                    "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
                ),
                ("WARC-Identified-Payload-Type", "application/json"),
            ],
            "",
        );

        let error = export_string(&input).unwrap_err();

        assert_eq!(
            error.to_string(),
            "record 0 (urn:uuid:1): the record type has no payload"
        );
    }
}
