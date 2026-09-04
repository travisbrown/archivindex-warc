//! Propagate fields from records to the records that refer to them.
//!
//! A revisit stands for the payload of the record its `WARC-Refers-To` names, so it can carry
//! that record's `WARC-Identified-Payload-Type`. Records are copied as read, in the order read;
//! the only change is the field added to a revisit that lacks it.

use std::collections::HashMap;
use std::path::Path;

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::value::MediaType;

use crate::file::{compression, is_stdin, open, transform};
use crate::header::{is_response, is_revisit, normalize_id};
use crate::{Error, Result};

/// The field a revisit takes from its original.
const IDENTIFIED_PAYLOAD_TYPE: Field = Field::IdentifiedPayloadType;

/// What was written to the output file.
#[derive(Debug)]
pub struct PropagateSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of revisit records given a field.
    pub propagated: usize,
}

/// Propagate the `WARC-Identified-Payload-Type` of each response in `input` to the revisits that
/// refer to it, and write every record to `output`.
///
/// A revisit without the field receives, as read, the value declared by the response record
/// whose `WARC-Record-ID` its `WARC-Refers-To` names, when that response is in `input` and its
/// value is a media type. The field is placed where the conventional header order puts it among
/// the fields the revisit has. Every other record, and every revisit whose original is not
/// such a response, is copied as read. A path with a `.gz` extension names a gzip-compressed
/// file; a compressed output holds one gzip member per record. A temporary file beside `output`
/// is moved into place after the last record is written.
///
/// # Errors
///
/// Returns an error when the input and output paths are the same, the input is standard input
/// (the operation reads it twice), a file cannot be opened, a record cannot be read or written,
/// or the output cannot be flushed or moved into place.
pub fn identified_payload_type(input: &Path, output: &Path) -> Result<PropagateSummary> {
    if is_stdin(input) {
        return Err(Error::StandardInputReadTwice);
    }
    let originals = response_payload_types(input)?;
    let mut propagated = 0;
    let summary = transform(&[input], output, compression(output), |_, mut record| {
        if is_revisit(&record.header)
            && record
                .header
                .get(IDENTIFIED_PAYLOAD_TYPE.standard_name())
                .is_none()
            && let Some(value) = record
                .header
                .get(Field::RefersTo.standard_name())
                .and_then(|id| originals.get(normalize_id(id)))
        {
            insert_field(&mut record.header, IDENTIFIED_PAYLOAD_TYPE, value.clone());
            propagated += 1;
        }

        Ok(Some(record))
    })?;

    Ok(PropagateSummary {
        records: summary.records,
        propagated,
    })
}

/// The `WARC-Identified-Payload-Type` value, as read, of each response record in `input` that
/// declares one, by normalized record identifier.
///
/// A value that is not a media type is not repeated, and the first of several responses sharing
/// an identifier is the one whose value is kept.
fn response_payload_types(input: &Path) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    let mut originals = HashMap::new();

    for result in open(input)?.filter_raw_records(is_response).records() {
        let record = result.map_err(|source| Error::Read {
            path: input.to_owned(),
            source,
        })?;
        let Some(id) = record.header.get(Field::RecordID.standard_name()) else {
            continue;
        };
        let Some(value) = record.header.get(IDENTIFIED_PAYLOAD_TYPE.standard_name()) else {
            continue;
        };
        if MediaType::parse(value.trim_ascii()).is_err() {
            log::warn!(
                "not repeating the malformed identified payload type of {}",
                String::from_utf8_lossy(id.trim_ascii())
            );
            continue;
        }
        originals
            .entry(normalize_id(id).to_vec())
            .or_insert_with(|| value.to_vec());
    }

    log::info!(
        "found {} response records with an identified payload type",
        originals.len()
    );

    Ok(originals)
}

/// Add `field` to a header block before the first field that follows it in conventional order.
///
/// A header whose fields are already in that order stays in it. Extension fields follow every
/// standard field.
fn insert_field(header: &mut raw::RecordHeader, field: Field, value: Vec<u8>) {
    let rank = field.canonical_rank();
    let position = header
        .headers
        .iter()
        .position(|(name, _)| {
            Field::from_name(name).is_none_or(|existing| existing.canonical_rank() > rank)
        })
        .unwrap_or(header.headers.len());

    header
        .headers
        .insert(position, (field.standard_name().to_owned(), value));
}

#[cfg(test)]
mod tests {
    use archivindex_test_support::warc::render;

    use super::*;
    use crate::file::open;

    /// A record of the given type and identifier, with the given further fields.
    fn record(record_type: &str, id: &str, fields: &[(&str, &str)], body: &str) -> Vec<u8> {
        let headers = [
            &[
                ("WARC-Type", record_type),
                ("WARC-Record-ID", id),
                ("WARC-Date", "2026-01-01T00:00:00Z"),
            ],
            fields,
        ]
        .concat();

        render(&headers, body)
    }

    /// The field names of a raw record's header, in order.
    fn names(record: &raw::Record) -> Vec<&str> {
        record
            .header
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Write `contents` as the input, propagate across it, and read back the records of both files.
    fn propagated(contents: &[u8]) -> (PropagateSummary, Vec<raw::Record>, Vec<raw::Record>) {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        std::fs::write(&input, contents).unwrap();

        let summary = identified_payload_type(&input, &output).unwrap();

        let read = |path| {
            open(path)
                .unwrap()
                .iter_raw_records()
                .records()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };

        (summary, read(&input), read(&output))
    }

    #[test]
    fn gives_each_revisit_the_type_of_its_original_and_copies_the_rest() {
        let contents = [
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Identified-Payload-Type", "text/plain")],
                "HTTP/1.1 200 OK\r\n\r\nfirst",
            ),
            record(
                "revisit",
                "<urn:uuid:2>",
                &[
                    ("WARC-Refers-To", "urn:uuid:1"),
                    ("WARC-Payload-Digest", "sha1:AAAA"),
                    ("X-Extension", "kept"),
                ],
                "",
            ),
            record(
                "revisit",
                "<urn:uuid:3>",
                &[
                    ("WARC-Refers-To", "<urn:uuid:1>"),
                    ("warc-identified-payload-type", "application/json"),
                ],
                "",
            ),
            record(
                "revisit",
                "<urn:uuid:4>",
                &[("WARC-Refers-To", "<urn:uuid:9>")],
                "",
            ),
            record(
                "response",
                "<urn:uuid:5>",
                &[],
                "HTTP/1.1 200 OK\r\n\r\nuntyped",
            ),
            record(
                "revisit",
                "<urn:uuid:6>",
                &[("WARC-Refers-To", "<urn:uuid:5>")],
                "",
            ),
            record(
                "revisit",
                "<urn:uuid:7>",
                &[
                    ("WARC-Refers-To", "<urn:uuid:8>"),
                    ("Content-Type", "text/x-c"),
                ],
                "",
            ),
            record(
                "response",
                "<urn:uuid:8>",
                &[("WARC-Identified-Payload-Type", " image/png ")],
                "HTTP/1.1 200 OK\r\n\r\nlater",
            ),
        ]
        .concat();

        let (summary, input, output) = propagated(&contents);

        assert_eq!(summary.records, 8);
        assert_eq!(summary.propagated, 2);
        assert_eq!(output.len(), input.len());
        for (index, (read, written)) in input.iter().zip(&output).enumerate() {
            if index == 1 || index == 6 {
                assert_eq!(written.header.version, read.header.version);
                assert_eq!(written.body, read.body);
            } else {
                assert_eq!(written, read);
            }
        }
        assert_eq!(
            names(&output[1]),
            [
                "WARC-Type",
                "WARC-Record-ID",
                "WARC-Date",
                "WARC-Refers-To",
                "WARC-Identified-Payload-Type",
                "WARC-Payload-Digest",
                "X-Extension",
                "Content-Length",
            ]
        );
        assert_eq!(output[1].header.headers[4].1, b" text/plain");
        assert_eq!(
            names(&output[6]),
            [
                "WARC-Type",
                "WARC-Record-ID",
                "WARC-Date",
                "WARC-Refers-To",
                "WARC-Identified-Payload-Type",
                "Content-Type",
                "Content-Length",
            ]
        );
        assert_eq!(output[6].header.headers[4].1, b"  image/png ");
    }

    #[test]
    fn does_not_repeat_a_value_that_is_not_a_media_type() {
        let contents = [
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Identified-Payload-Type", "not a media type")],
                "HTTP/1.1 200 OK\r\n\r\nbody",
            ),
            record(
                "revisit",
                "<urn:uuid:2>",
                &[("WARC-Refers-To", "<urn:uuid:1>")],
                "",
            ),
        ]
        .concat();

        let (summary, input, output) = propagated(&contents);

        assert_eq!(summary.records, 2);
        assert_eq!(summary.propagated, 0);
        assert_eq!(output, input);
    }

    #[test]
    fn keeps_the_first_of_two_responses_sharing_an_identifier() {
        let contents = [
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Identified-Payload-Type", "text/plain")],
                "HTTP/1.1 200 OK\r\n\r\nfirst",
            ),
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Identified-Payload-Type", "text/html")],
                "HTTP/1.1 200 OK\r\n\r\nsecond",
            ),
            record(
                "revisit",
                "<urn:uuid:2>",
                &[("WARC-Refers-To", "<urn:uuid:1>")],
                "",
            ),
        ]
        .concat();

        let (summary, _, output) = propagated(&contents);

        assert_eq!(summary.propagated, 1);
        assert_eq!(
            output[2].header.get("WARC-Identified-Payload-Type"),
            Some(&b" text/plain"[..])
        );
    }

    #[test]
    fn places_the_field_before_the_first_that_follows_it_in_conventional_order() {
        let mut header = raw::RecordHeader::parse(
            b"WARC/1.1\r\nContent-Length: 0\r\nWARC-Type: revisit\r\n\
              WARC-Refers-To: <urn:uuid:1>\r\n\r\n",
        )
        .unwrap()
        .0;

        insert_field(
            &mut header,
            Field::IdentifiedPayloadType,
            b" text/plain".to_vec(),
        );

        assert_eq!(
            header
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            [
                "WARC-Identified-Payload-Type",
                "Content-Length",
                "WARC-Type",
                "WARC-Refers-To",
            ]
        );
    }

    /// Standard input cannot serve both passes, so it is refused before either.
    #[test]
    fn refuses_standard_input() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.warc");

        let error = identified_payload_type(Path::new("-"), &output).unwrap_err();

        assert!(matches!(error, Error::StandardInputReadTwice));
        assert!(!output.exists());
    }
}
