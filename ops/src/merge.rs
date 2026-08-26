//! Merge two WARC files.
//!
//! Two WARC files are merged into one, with every record of the first file preceding every
//! record of the second. Warcinfo records that match up to incidental fields are merged: the
//! matching record with the earliest `WARC-Date` is written where the first of them stood, the
//! rest are dropped, and every reference to a dropped record is redirected to the kept one.
//!
//! Two warcinfo records match when they declare the same WARC version, carry the same body, and
//! carry the same fields other than `WARC-Record-ID`, `WARC-Date`, `WARC-Filename`,
//! `WARC-Block-Digest`, and `WARC-Payload-Digest`. Field order, field name case, and white space
//! around values do not affect matching.
//!
//! A warcinfo record that declares a `WARC-Filename` has it rewritten to the name of the output,
//! which is the file it is then in.

use std::collections::HashMap;
use std::path::Path;

use archivindex_warc::parse::raw;
use archivindex_warc::value::{Text, WarcDate};
use archivindex_warc::version::WarcVersion;

use crate::file::{is_stdin, open, transform};
use crate::{Error, Result};

/// Fields whose values are record identifiers that may point at a warcinfo record.
const REFERENCE_FIELDS: [&str; 4] = [
    "WARC-Warcinfo-ID",
    "WARC-Refers-To",
    "WARC-Concurrent-To",
    "WARC-Segment-Origin-ID",
];

/// Fields that vary between otherwise identical warcinfo records: the generated identifier, the
/// capture date, the name of the enclosing file, and the digests.
const INCIDENTAL_FIELDS: [&str; 5] = [
    "WARC-Record-ID",
    "WARC-Date",
    "WARC-Filename",
    "WARC-Block-Digest",
    "WARC-Payload-Digest",
];

/// What became of the merged files' records.
#[derive(Debug)]
pub struct MergeSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of duplicate warcinfo records dropped.
    pub merged: usize,
}

/// Merge the records of two WARC files into `output`.
///
/// Records keep their order, with all of `first` preceding all of `second`. Matching warcinfo
/// records are merged and `WARC-Filename` is rewritten as described in the module documentation.
/// A path with a `.gz` extension names a gzip-compressed file; a compressed output holds one gzip
/// member per record. A temporary file beside `output` is moved into place after the last record
/// is written.
///
/// # Errors
///
/// Returns an error when the output path is also an input path, either input is standard input
/// (the operation reads both inputs twice), a file cannot be opened, a record cannot be read or
/// written, a duplicate's references must be redirected but the surviving warcinfo record has no
/// `WARC-Record-ID`, or the output cannot be moved into place.
pub fn merge(first: &Path, second: &Path, output: &Path) -> Result<MergeSummary> {
    if is_stdin(first) || is_stdin(second) {
        return Err(Error::StandardInputReadTwice);
    }
    let plan = MergePlan::build(first, second)?;

    plan.write(first, second, output)
}

/// What to do with a warcinfo record when it is reached in stream order.
enum WarcinfoAction {
    /// Write this record in place of the one read.
    Emit(raw::Record),
    /// Drop the record read.
    Skip,
}

/// The fate of each warcinfo record, in stream order, and the reference values to rewrite.
struct MergePlan {
    actions: Vec<WarcinfoAction>,
    redirects: HashMap<Vec<u8>, Vec<u8>>,
}

impl MergePlan {
    /// Read the warcinfo records of both files and decide which survive.
    fn build(first: &Path, second: &Path) -> Result<Self> {
        let mut records = Vec::new();
        for path in [first, second] {
            for result in open(path)?.filter_raw_records(is_warcinfo) {
                records.push(result.map_err(|source| Error::Read {
                    path: path.to_owned(),
                    source,
                })?);
            }
        }

        let mut groups: HashMap<GroupKey, Vec<usize>> = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            groups.entry(group_key(record)).or_default().push(index);
        }

        log::info!(
            "merging {} warcinfo records into {}",
            records.len(),
            groups.len()
        );

        let mut actions: Vec<_> = records.iter().map(|_| WarcinfoAction::Skip).collect();
        let mut redirects = HashMap::new();

        for members in groups.into_values() {
            let kept = *members
                .iter()
                .min_by_key(|&&index| {
                    let date = record_date(&records[index]).map(WarcDate::date_time);
                    // An undated record sorts after every dated one, and the arrival index
                    // breaks ties in favor of the first file.
                    (date.is_none(), date, index)
                })
                .expect("invariant violation: every group has a member");

            let kept_id = record_id(&records[kept]);
            for &member in &members {
                if member == kept {
                    continue;
                }
                let Some(dropped_id) = record_id(&records[member]) else {
                    continue;
                };
                let Some(kept_id) = kept_id else {
                    return Err(Error::MissingWarcinfoRecordId);
                };
                if normalize_id(dropped_id) != normalize_id(kept_id) {
                    log::debug!(
                        "redirecting references from {} to {}",
                        String::from_utf8_lossy(dropped_id),
                        String::from_utf8_lossy(kept_id)
                    );
                    let mut value = Vec::with_capacity(kept_id.len() + 1);
                    value.push(b' ');
                    value.extend_from_slice(kept_id);
                    redirects.insert(normalize_id(dropped_id).to_vec(), value);
                }
            }

            actions[members[0]] = WarcinfoAction::Emit(records[kept].clone());
        }

        Ok(Self { actions, redirects })
    }

    /// Stream both files into the output, applying the plan.
    fn write(self, first: &Path, second: &Path, output: &Path) -> Result<MergeSummary> {
        let Self { actions, redirects } = self;
        let mut actions = actions.into_iter();
        let mut merged = 0;
        let filename = output_filename(output);
        let records = transform(&[first, second], output, |_, mut record| {
            if is_warcinfo(&record.header) {
                match actions.next().ok_or(Error::WarcinfoRecordsChanged)? {
                    WarcinfoAction::Emit(kept) => record = kept,
                    WarcinfoAction::Skip => {
                        log::debug!(
                            "dropping the duplicate warcinfo record {}",
                            String::from_utf8_lossy(record_id(&record).unwrap_or_default())
                        );
                        merged += 1;

                        return Ok(None);
                    }
                }

                set_filename(&mut record.header, filename.as_deref());
            }

            redirect_references(&mut record.header, &redirects);

            Ok(Some(record))
        })?;

        Ok(MergeSummary { records, merged })
    }
}

/// A warcinfo record's identity for matching: its version, its fields other than the incidental
/// ones with names lowercased and values trimmed and sorted, and its body.
type GroupKey = (WarcVersion, Vec<(String, Vec<u8>)>, Vec<u8>);

/// The matching identity of a warcinfo record.
fn group_key(record: &raw::Record) -> GroupKey {
    let mut headers: Vec<(String, Vec<u8>)> = record
        .header
        .headers
        .iter()
        .filter(|(name, _)| {
            !INCIDENTAL_FIELDS
                .iter()
                .any(|field| name.eq_ignore_ascii_case(field))
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim_ascii().to_vec()))
        .collect();
    headers.sort_unstable();

    (record.header.version, headers, record.body.clone())
}

/// Point references to merged warcinfo records at the surviving record.
fn redirect_references(header: &mut raw::RecordHeader, redirects: &HashMap<Vec<u8>, Vec<u8>>) {
    if redirects.is_empty() {
        return;
    }

    for (name, value) in &mut header.headers {
        if REFERENCE_FIELDS
            .iter()
            .any(|field| name.eq_ignore_ascii_case(field))
            && let Some(replacement) = redirects.get(normalize_id(value))
        {
            value.clone_from(replacement);
        }
    }
}

/// The `WARC-Filename` value naming the output, when its name can be written as one.
///
/// A name that is not valid UTF-8, or that no `TEXT` value can spell, has no accurate field value.
fn output_filename(output: &Path) -> Option<Vec<u8>> {
    let name = output.file_name()?.to_str()?;
    let spelled = Text::parse(name.as_bytes()).ok()?;
    let spelled = spelled.to_bytes();
    let mut value = Vec::with_capacity(spelled.len() + 1);
    value.push(b' ');
    value.extend_from_slice(&spelled);

    Some(value)
}

/// Name the file a warcinfo record is now in, dropping the field when it cannot be named.
///
/// WARC 1.1 clause 5.17 defines `WARC-Filename` as the name of the containing file, so a record
/// written into the output cannot keep the name of the file it was read from.
fn set_filename(header: &mut raw::RecordHeader, filename: Option<&[u8]>) {
    header.headers.retain_mut(|(name, value)| {
        if !name.eq_ignore_ascii_case("WARC-Filename") {
            return true;
        }
        let Some(filename) = filename else {
            return false;
        };
        value.clear();
        value.extend_from_slice(filename);

        true
    });
}

/// Whether a header block declares a warcinfo record.
fn is_warcinfo(header: &raw::RecordHeader) -> bool {
    header
        .get("WARC-Type")
        .is_some_and(|value| value.trim_ascii().eq_ignore_ascii_case(b"warcinfo"))
}

/// The trimmed `WARC-Record-ID` value of a record.
fn record_id(record: &raw::Record) -> Option<&[u8]> {
    record
        .header
        .get("WARC-Record-ID")
        .map(<[u8]>::trim_ascii)
        .filter(|value| !value.is_empty())
}

/// A record identifier without its surrounding white space and angle brackets, for comparison.
fn normalize_id(value: &[u8]) -> &[u8] {
    let value = value.trim_ascii();

    value
        .strip_prefix(b"<")
        .and_then(|inner| inner.strip_suffix(b">"))
        .unwrap_or(value)
}

/// The instant a record's `WARC-Date` declares, when it can be read.
fn record_date(record: &raw::Record) -> Option<WarcDate> {
    let value = record.header.get("WARC-Date")?;
    let value = std::str::from_utf8(value.trim_ascii()).ok()?;

    WarcDate::parse(value, record.header.version)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use super::*;

    const ID_A: &str = "<urn:uuid:aaaaaaaa-0000-4000-8000-000000000000>";
    const ID_B: &str = "<urn:uuid:bbbbbbbb-0000-4000-8000-000000000000>";
    const ID_RESPONSE_A: &str = "<urn:uuid:cccccccc-0000-4000-8000-000000000000>";

    /// A WARC 1.1 record with the given fields, framed by the body's length.
    fn render(headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut record = b"WARC/1.1\r\n".to_vec();
        for (name, value) in headers {
            record.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        record.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        record.extend_from_slice(body.as_bytes());
        record.extend_from_slice(b"\r\n\r\n");

        record
    }

    fn warcinfo(id: &str, date: &str, digest: &str, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut headers = vec![
            ("WARC-Type", "warcinfo"),
            ("WARC-Record-ID", id),
            ("WARC-Date", date),
            ("WARC-Block-Digest", digest),
            ("Content-Type", "application/warc-fields"),
        ];
        headers.extend_from_slice(extra);

        render(&headers, "software: tool/1.0\r\n")
    }

    fn response(id: &str, warcinfo_id: &str) -> Vec<u8> {
        render(
            &[
                ("WARC-Type", "response"),
                ("WARC-Record-ID", id),
                ("WARC-Date", "2024-05-03T00:00:00Z"),
                ("WARC-Target-URI", "https://example.com/"),
                ("WARC-Warcinfo-ID", warcinfo_id),
            ],
            "HTTP/1.1 200 OK\r\n\r\nok",
        )
    }

    fn write_file(directory: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, contents).unwrap();

        path
    }

    fn read_records(path: &Path) -> Vec<raw::Record> {
        open(path)
            .unwrap()
            .iter_raw_records()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn trimmed(record: &raw::Record, name: &str) -> Option<String> {
        record
            .header
            .get(name)
            .map(|value| String::from_utf8(value.trim_ascii().to_vec()).unwrap())
    }

    /// The record with the earliest date survives at the first record's position, references
    /// to the dropped record are redirected, and other references and records are untouched.
    #[test]
    fn merges_matching_warcinfo_records() {
        let directory = tempfile::tempdir().unwrap();

        let mut first_contents = warcinfo(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA", &[]);
        first_contents.extend_from_slice(&response(ID_RESPONSE_A, ID_A));
        first_contents.extend_from_slice(&render(
            &[
                ("WARC-Type", "metadata"),
                (
                    "WARC-Record-ID",
                    "<urn:uuid:dddddddd-0000-4000-8000-000000000000>",
                ),
                ("WARC-Date", "2024-05-03T00:00:00Z"),
                ("WARC-Refers-To", ID_RESPONSE_A),
                ("WARC-Warcinfo-ID", ID_A),
            ],
            "via: https://example.com/\r\n",
        ));

        let second_response = response("<urn:uuid:eeeeeeee-0000-4000-8000-000000000000>", ID_B);
        let mut second_contents = warcinfo(
            ID_B,
            "2024-05-01T00:00:00Z",
            "sha1:BBBB",
            &[("WARC-Filename", "second.warc")],
        );
        second_contents.extend_from_slice(&second_response);

        let first = write_file(directory.path(), "first.warc", &first_contents);
        let second = write_file(directory.path(), "second.warc", &second_contents);
        let output = directory.path().join("merged.warc");

        let summary = merge(&first, &second, &output).unwrap();
        assert_eq!(summary.records, 4);
        assert_eq!(summary.merged, 1);

        let records = read_records(&output);
        assert_eq!(records.len(), 4);

        // The second file's warcinfo record is kept, at the first file's position, under the
        // name of the file it is now in.
        assert_eq!(
            records[0].to_bytes().unwrap(),
            warcinfo(
                ID_B,
                "2024-05-01T00:00:00Z",
                "sha1:BBBB",
                &[("WARC-Filename", "merged.warc")]
            )
        );

        // References to the dropped record point at the kept one; others are untouched.
        assert_eq!(trimmed(&records[1], "WARC-Warcinfo-ID").unwrap(), ID_B);
        assert_eq!(trimmed(&records[2], "WARC-Warcinfo-ID").unwrap(), ID_B);
        assert_eq!(
            trimmed(&records[2], "WARC-Refers-To").unwrap(),
            ID_RESPONSE_A
        );

        // A record referencing the kept warcinfo record round-trips byte for byte.
        assert_eq!(records[3].to_bytes().unwrap(), second_response);
    }

    /// A `WARC-Filename` that cannot be spelled as a `TEXT` value is dropped rather than left
    /// naming a file the record is not in.
    #[test]
    fn drops_a_filename_the_output_cannot_be_named_by() {
        let directory = tempfile::tempdir().unwrap();

        let first = write_file(
            directory.path(),
            "first.warc",
            &warcinfo(
                ID_A,
                "2024-05-01T00:00:00Z",
                "sha1:AAAA",
                &[("WARC-Filename", "first.warc")],
            ),
        );
        let second = write_file(
            directory.path(),
            "second.warc",
            &warcinfo(ID_B, "2024-05-02T00:00:00Z", "sha1:BBBB", &[]),
        );
        // A name opening with a quote is read as a quoted string, which it does not close.
        let output = directory.path().join("\"merged.warc");

        merge(&first, &second, &output).unwrap();

        let records = read_records(&output);
        assert_eq!(records.len(), 1);
        assert_eq!(trimmed(&records[0], "WARC-Filename"), None);
    }

    /// A date tie is broken in favor of the first file's record.
    #[test]
    fn keeps_the_first_record_on_a_date_tie() {
        let directory = tempfile::tempdir().unwrap();

        let first = write_file(
            directory.path(),
            "first.warc",
            &warcinfo(ID_A, "2024-05-01T00:00:00Z", "sha1:AAAA", &[]),
        );
        let mut second_contents = warcinfo(ID_B, "2024-05-01T00:00:00Z", "sha1:BBBB", &[]);
        second_contents.extend_from_slice(&response(
            "<urn:uuid:eeeeeeee-0000-4000-8000-000000000000>",
            ID_B,
        ));
        let second = write_file(directory.path(), "second.warc", &second_contents);
        let output = directory.path().join("merged.warc");

        let summary = merge(&first, &second, &output).unwrap();
        assert_eq!(summary.merged, 1);

        let records = read_records(&output);
        assert_eq!(records.len(), 2);
        assert_eq!(trimmed(&records[0], "WARC-Record-ID").unwrap(), ID_A);
        assert_eq!(trimmed(&records[1], "WARC-Warcinfo-ID").unwrap(), ID_A);
    }

    /// Warcinfo records with different contents are all kept, byte for byte.
    #[test]
    fn keeps_distinct_warcinfo_records() {
        let directory = tempfile::tempdir().unwrap();

        let mut first_contents = warcinfo(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA", &[]);
        first_contents.extend_from_slice(&response(ID_RESPONSE_A, ID_A));
        let mut second_contents = render(
            &[
                ("WARC-Type", "warcinfo"),
                ("WARC-Record-ID", ID_B),
                ("WARC-Date", "2024-05-01T00:00:00Z"),
                ("Content-Type", "application/warc-fields"),
            ],
            "software: other/2.0\r\n",
        );
        second_contents.extend_from_slice(&response(
            "<urn:uuid:eeeeeeee-0000-4000-8000-000000000000>",
            ID_B,
        ));

        let first = write_file(directory.path(), "first.warc", &first_contents);
        let second = write_file(directory.path(), "second.warc", &second_contents);
        let output = directory.path().join("merged.warc");

        let summary = merge(&first, &second, &output).unwrap();
        assert_eq!(summary.records, 4);
        assert_eq!(summary.merged, 0);

        let mut expected = first_contents;
        expected.extend_from_slice(&second_contents);
        assert_eq!(std::fs::read(&output).unwrap(), expected);
    }

    /// Compressed files are read and written by their extension.
    #[test]
    fn merges_gzip_files() {
        let directory = tempfile::tempdir().unwrap();

        let mut first_contents = warcinfo(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA", &[]);
        first_contents.extend_from_slice(&response(ID_RESPONSE_A, ID_A));
        let second_contents = warcinfo(ID_B, "2024-05-01T00:00:00Z", "sha1:BBBB", &[]);

        let first = directory.path().join("first.warc.gz");
        let second = directory.path().join("second.warc.gz");
        for (path, contents) in [(&first, &first_contents), (&second, &second_contents)] {
            let mut encoder = flate2::write::GzEncoder::new(
                std::fs::File::create(path).unwrap(),
                flate2::Compression::default(),
            );
            encoder.write_all(contents).unwrap();
            encoder.finish().unwrap();
        }

        let output = directory.path().join("merged.warc.gz");
        let summary = merge(&first, &second, &output).unwrap();
        assert_eq!(summary.records, 2);
        assert_eq!(summary.merged, 1);

        let records = read_records(&output);
        assert_eq!(records.len(), 2);
        assert_eq!(trimmed(&records[0], "WARC-Record-ID").unwrap(), ID_B);
        assert_eq!(trimmed(&records[1], "WARC-Warcinfo-ID").unwrap(), ID_B);
    }

    /// Merging into one of its own inputs is refused before the file is touched.
    #[test]
    fn refuses_an_output_that_is_an_input() {
        let directory = tempfile::tempdir().unwrap();
        let contents = warcinfo(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA", &[]);
        let first = write_file(directory.path(), "first.warc", &contents);
        let second = write_file(directory.path(), "second.warc", &contents);

        let error = merge(&first, &second, &first).unwrap_err();

        assert!(matches!(
            &error,
            Error::SameInputAndOutput { path } if path == &first
        ));
        assert_eq!(std::fs::read(first).unwrap(), contents);
    }

    /// Standard input cannot serve both passes, so it is refused before either.
    #[test]
    fn refuses_standard_input() {
        let directory = tempfile::tempdir().unwrap();
        let contents = warcinfo(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA", &[]);
        let first = write_file(directory.path(), "first.warc", &contents);
        let output = directory.path().join("merged.warc");

        let error = merge(&first, Path::new("-"), &output).unwrap_err();

        assert!(matches!(error, Error::StandardInputReadTwice));
        assert!(!output.exists());
    }
}
