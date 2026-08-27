//! Remove records from a file.
//!
//! Records are copied as read, in the order read; the only change is the records left out.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use archivindex_warc::parse::untyped::name::Field;

use crate::file::{compression, is_stdin, open, transform};
use crate::header::{is_response, is_revisit, normalize_id};

/// The field linking the records of one capture.
const CONCURRENT_TO: &str = "WARC-Concurrent-To";
use crate::{Error, Result};

/// What was written to the output file, and what was not.
#[derive(Debug)]
pub struct RemoveSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of revisit records removed.
    pub revisits: usize,
    /// The number of other records removed for belonging to a removed revisit's capture.
    pub captured: usize,
}

/// Remove from `input` every revisit whose target URI is that of its original, and write every
/// other record to `output`.
///
/// A revisit is removed when its `WARC-Target-URI` equals, apart from surrounding white space,
/// that of the response record whose `WARC-Record-ID` its `WARC-Refers-To` names, when that
/// response is in `input`. The rest of its capture is removed with it: every record that
/// `WARC-Concurrent-To` links to the revisit, in either direction and through any number of
/// records, such as its request and the metadata naming either. Every other record is copied as
/// read. A path with a `.gz` extension names a gzip-compressed file; a compressed output holds
/// one gzip member per record. A temporary file beside `output` is moved into place after the
/// last record is written.
///
/// # Errors
///
/// Returns an error when the input and output paths are the same, the input is standard input
/// (the operation reads it twice), a file cannot be opened, a record cannot be read or written,
/// or the output cannot be flushed or moved into place.
pub fn same_target_revisits(input: &Path, output: &Path) -> Result<RemoveSummary> {
    if is_stdin(input) {
        return Err(Error::StandardInputReadTwice);
    }
    let removed = same_target_captures(input)?;
    let mut revisits = 0;
    let mut captured = 0;
    let summary = transform(&[input], output, compression(output), |_, record| {
        let header = &record.header;
        let is_removed = header
            .get(Field::RecordID.standard_name())
            .into_iter()
            .chain(header.get_all(CONCURRENT_TO))
            .any(|id| removed.contains(normalize_id(id)));
        if !is_removed {
            return Ok(Some(record));
        }
        if is_revisit(header) {
            revisits += 1;
        } else {
            captured += 1;
        }

        Ok(None)
    })?;

    Ok(RemoveSummary {
        records: summary.records,
        revisits,
        captured,
    })
}

/// The normalized identifiers of the records in `input` making up the captures of the revisit
/// records whose target URI is that of the response record their `WARC-Refers-To` names.
///
/// A capture is the records `WARC-Concurrent-To` links to such a revisit, in either direction
/// and through any number of records. The first of several responses sharing an identifier is
/// the one whose target URI counts.
fn same_target_captures(input: &Path) -> Result<HashSet<Vec<u8>>> {
    let mut responses = HashMap::new();
    let mut revisits = Vec::new();
    let mut links: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();

    for result in open(input)?.filter_raw_records(|header| {
        is_response(header) || is_revisit(header) || header.get(CONCURRENT_TO).is_some()
    }) {
        let record = result.map_err(|source| Error::Read {
            path: input.to_owned(),
            source,
        })?;
        let header = &record.header;
        let Some(id) = header.get(Field::RecordID.standard_name()) else {
            continue;
        };
        let id = normalize_id(id);
        for concurrent in header.get_all(CONCURRENT_TO) {
            let concurrent = normalize_id(concurrent);
            links
                .entry(id.to_vec())
                .or_default()
                .push(concurrent.to_vec());
            links
                .entry(concurrent.to_vec())
                .or_default()
                .push(id.to_vec());
        }
        let Some(target_uri) = header.get(Field::TargetURI.standard_name()) else {
            continue;
        };
        if is_revisit(header) {
            if let Some(refers_to) = header.get(Field::RefersTo.standard_name()) {
                revisits.push((
                    id.to_vec(),
                    normalize_id(refers_to).to_vec(),
                    target_uri.trim_ascii().to_vec(),
                ));
            }
        } else if is_response(header) {
            responses
                .entry(id.to_vec())
                .or_insert_with(|| target_uri.trim_ascii().to_vec());
        }
    }

    let mut pending = revisits
        .into_iter()
        .filter(|(_, refers_to, target_uri)| responses.get(refers_to) == Some(target_uri))
        .map(|(id, _, _)| id)
        .collect::<Vec<_>>();
    log::info!(
        "found {} revisit records of their originals' target URIs",
        pending.len()
    );

    // Walk the links out from each revisit to the rest of its capture.
    let mut removed = HashSet::new();
    while let Some(id) = pending.pop() {
        let linked = links.get(&id).cloned().unwrap_or_default();
        if removed.insert(id) {
            pending.extend(linked);
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use archivindex_test_support::render;
    use archivindex_warc::parse::raw;

    use super::*;
    use crate::file::open;

    /// A record of the given type and identifier, with the given further fields.
    fn record(record_type: &str, id: &str, fields: &[(&str, &str)]) -> Vec<u8> {
        let headers = [
            &[
                ("WARC-Type", record_type),
                ("WARC-Record-ID", id),
                ("WARC-Date", "2026-01-01T00:00:00Z"),
            ],
            fields,
        ]
        .concat();

        render(&headers, "")
    }

    /// Write `contents` as the input, remove across it, and read back the records of both files.
    fn removed(contents: &[u8]) -> (RemoveSummary, Vec<raw::Record>, Vec<raw::Record>) {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        std::fs::write(&input, contents).unwrap();

        let summary = same_target_revisits(&input, &output).unwrap();

        let read = |path| {
            open(path)
                .unwrap()
                .iter_raw_records()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };

        (summary, read(&input), read(&output))
    }

    #[test]
    fn removes_each_revisit_of_its_originals_uri_with_its_capture() {
        let contents = [
            // The original and its request, kept.
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Target-URI", "http://example.com/a")],
            ),
            record(
                "request",
                "<urn:uuid:2>",
                &[
                    ("WARC-Target-URI", "http://example.com/a"),
                    ("WARC-Concurrent-To", "<urn:uuid:1>"),
                ],
            ),
            // A revisit of the original's URI, removed with the request it names and the
            // metadata naming that request.
            record(
                "request",
                "<urn:uuid:3>",
                &[("WARC-Target-URI", "http://example.com/a")],
            ),
            record(
                "revisit",
                "<urn:uuid:4>",
                &[
                    ("WARC-Target-URI", " http://example.com/a"),
                    ("WARC-Refers-To", "urn:uuid:1"),
                    ("warc-concurrent-to", "urn:uuid:3"),
                ],
            ),
            record(
                "metadata",
                "<urn:uuid:5>",
                &[
                    ("WARC-Target-URI", "http://example.com/a"),
                    ("WARC-Concurrent-To", "<urn:uuid:3>"),
                ],
            ),
            // A revisit of the original from another URI, kept with its metadata.
            record(
                "revisit",
                "<urn:uuid:6>",
                &[
                    ("WARC-Target-URI", "http://example.com/b"),
                    ("WARC-Refers-To", "<urn:uuid:1>"),
                ],
            ),
            record(
                "metadata",
                "<urn:uuid:7>",
                &[("WARC-Concurrent-To", "<urn:uuid:6>")],
            ),
            // A revisit of a record that is not a response in the file, kept.
            record(
                "revisit",
                "<urn:uuid:8>",
                &[
                    ("WARC-Target-URI", "http://example.com/a"),
                    ("WARC-Refers-To", "<urn:uuid:4>"),
                ],
            ),
            record(
                "revisit",
                "<urn:uuid:9>",
                &[
                    ("WARC-Target-URI", "http://example.com/a"),
                    ("WARC-Refers-To", "<urn:uuid:99>"),
                ],
            ),
        ]
        .concat();

        let (summary, input, output) = removed(&contents);

        assert_eq!(summary.records, 6);
        assert_eq!(summary.revisits, 1);
        assert_eq!(summary.captured, 2);
        assert_eq!(
            output,
            [0, 1, 5, 6, 7, 8]
                .into_iter()
                .map(|index| input[index].clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn removes_the_records_naming_a_revisit_of_an_original_written_after_it() {
        let contents = [
            record(
                "request",
                "<urn:uuid:1>",
                &[("WARC-Concurrent-To", "<urn:uuid:2>")],
            ),
            record(
                "revisit",
                "<urn:uuid:2>",
                &[
                    ("WARC-Target-URI", "http://example.com/c"),
                    ("WARC-Refers-To", "<urn:uuid:4>"),
                ],
            ),
            record(
                "metadata",
                "<urn:uuid:3>",
                &[
                    ("WARC-Concurrent-To", "<urn:uuid:2>"),
                    ("WARC-Concurrent-To", "<urn:uuid:1>"),
                ],
            ),
            record(
                "response",
                "<urn:uuid:4>",
                &[("WARC-Target-URI", "http://example.com/c")],
            ),
        ]
        .concat();

        let (summary, input, output) = removed(&contents);

        assert_eq!(summary.records, 1);
        assert_eq!(summary.revisits, 1);
        assert_eq!(summary.captured, 2);
        assert_eq!(output, input[3..]);
    }

    #[test]
    fn compares_target_uris_exactly_apart_from_surrounding_space() {
        let contents = [
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Target-URI", "http://example.com/a")],
            ),
            record(
                "revisit",
                "<urn:uuid:2>",
                &[
                    ("WARC-Target-URI", "http://example.com/A"),
                    ("WARC-Refers-To", "<urn:uuid:1>"),
                ],
            ),
            record(
                "revisit",
                "<urn:uuid:3>",
                &[
                    ("WARC-Target-URI", "http://example.com/a/"),
                    ("WARC-Refers-To", "<urn:uuid:1>"),
                ],
            ),
            record(
                "revisit",
                "<urn:uuid:4>",
                &[
                    ("WARC-Target-URI", "  http://example.com/a  "),
                    ("WARC-Refers-To", "<urn:uuid:1>"),
                ],
            ),
        ]
        .concat();

        let (summary, input, output) = removed(&contents);

        assert_eq!(summary.revisits, 1);
        assert_eq!(summary.captured, 0);
        assert_eq!(output, input[..3]);
    }

    #[test]
    fn keeps_the_first_of_two_responses_sharing_an_identifier() {
        let contents = [
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Target-URI", "http://example.com/a")],
            ),
            record(
                "response",
                "<urn:uuid:1>",
                &[("WARC-Target-URI", "http://example.com/b")],
            ),
            record(
                "revisit",
                "<urn:uuid:2>",
                &[
                    ("WARC-Target-URI", "http://example.com/b"),
                    ("WARC-Refers-To", "<urn:uuid:1>"),
                ],
            ),
        ]
        .concat();

        let (summary, input, output) = removed(&contents);

        assert_eq!(summary.revisits, 0);
        assert_eq!(output, input);
    }

    /// Standard input cannot serve both passes, so it is refused before either.
    #[test]
    fn refuses_standard_input() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.warc");

        let error = same_target_revisits(Path::new("-"), &output).unwrap_err();

        assert!(matches!(error, Error::StandardInputReadTwice));
        assert!(!output.exists());
    }
}
