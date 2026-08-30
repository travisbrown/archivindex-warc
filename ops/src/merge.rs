//! Merge two WARC files.
//!
//! Two WARC files are merged into one, with every record of the first file preceding every
//! record of the second. Warcinfo records that match up to incidental fields are merged: the
//! matching record with the earliest `WARC-Date` is written where the first of them stood, the
//! rest are dropped, and every reference to a dropped record is redirected to the kept one.
//!
//! Two warcinfo records match when they declare the same WARC version, carry the same body after
//! ignored fields are removed, and carry the same header fields other than `WARC-Record-ID`,
//! `WARC-Date`, `WARC-Filename`, `WARC-Block-Digest`, `WARC-Payload-Digest`, and `Content-Length`.
//! `isPartOf` is always ignored; callers may ignore additional warcinfo body fields. Header field
//! order, field name case, and white space around values do not affect matching.
//!
//! A warcinfo record that declares a `WARC-Filename` has it rewritten to the name of the output,
//! which is the file it is then in.

use std::collections::HashMap;
use std::path::Path;

use archivindex_warc::parse::raw;
use archivindex_warc::record::fields::warcinfo::WarcinfoBody;
use archivindex_warc::value::WarcDate;
use archivindex_warc::version::WarcVersion;

use crate::file::{compression, is_stdin, open, transform};
use crate::header::{REFERENCE_FIELDS, is_warcinfo, normalize_id, output_filename, set_filename};
use crate::{Error, Result};

/// Fields that vary between otherwise identical warcinfo records: the generated identifier, the
/// capture date, the name of the enclosing file, the digests, and the length that changes with an
/// incidental `isPartOf` value.
const INCIDENTAL_FIELDS: [&str; 6] = [
    "WARC-Record-ID",
    "WARC-Date",
    "WARC-Filename",
    "WARC-Block-Digest",
    "WARC-Payload-Digest",
    "Content-Length",
];

/// What became of the merged files' records.
#[derive(Debug)]
pub struct MergeSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of duplicate warcinfo records dropped.
    pub merged: usize,
    /// The number of distinct warcinfo records written.
    pub distinct_warcinfo: usize,
    /// Why the distinct warcinfo records could not all be merged.
    pub warcinfo_differences: Vec<WarcinfoDifference>,
}

/// A part of otherwise mergeable warcinfo records that differs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WarcinfoDifference {
    /// The records declare different WARC versions.
    Version,
    /// Header fields other than the incidental fields differ.
    HeaderFields,
    /// The bodies differ after ignored fields are removed.
    Body,
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
    merge_ignoring_warcinfo_fields(first, second, output, &[] as &[&str])
}

/// Merge two WARC files, allowing the named warcinfo body fields to vary.
///
/// Field names are matched case-insensitively. `isPartOf` is always allowed to vary, whether or
/// not it appears in `ignored_fields`.
///
/// # Errors
///
/// Returns the errors described by [`merge`].
pub fn merge_ignoring_warcinfo_fields<S: AsRef<str>>(
    first: &Path,
    second: &Path,
    output: &Path,
    ignored_fields: &[S],
) -> Result<MergeSummary> {
    if is_stdin(first) || is_stdin(second) {
        return Err(Error::StandardInputReadTwice);
    }
    let plan = MergePlan::build(first, second, ignored_fields)?;

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
    distinct_warcinfo: usize,
    warcinfo_differences: Vec<WarcinfoDifference>,
}

impl MergePlan {
    /// Read the warcinfo records of both files and decide which survive.
    fn build<S: AsRef<str>>(first: &Path, second: &Path, ignored_fields: &[S]) -> Result<Self> {
        let mut records = Vec::new();
        for path in [first, second] {
            for result in open(path)?.filter_raw_records(is_warcinfo).records() {
                records.push(result.map_err(|source| Error::Read {
                    path: path.to_owned(),
                    source,
                })?);
            }
        }

        let mut groups: HashMap<GroupKey, Vec<usize>> = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            groups
                .entry(group_key(record, ignored_fields))
                .or_default()
                .push(index);
        }

        log::info!(
            "merging {} warcinfo records into {}",
            records.len(),
            groups.len()
        );

        let distinct_warcinfo = groups.len();
        let mut warcinfo_differences = Vec::new();
        if let Some(first) = groups.keys().next() {
            if groups.keys().any(|key| key.0 != first.0) {
                warcinfo_differences.push(WarcinfoDifference::Version);
            }
            if groups.keys().any(|key| key.1 != first.1) {
                warcinfo_differences.push(WarcinfoDifference::HeaderFields);
            }
            if groups.keys().any(|key| key.2 != first.2) {
                warcinfo_differences.push(WarcinfoDifference::Body);
            }
        }

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

        Ok(Self {
            actions,
            redirects,
            distinct_warcinfo,
            warcinfo_differences,
        })
    }

    /// Stream both files into the output, applying the plan.
    fn write(self, first: &Path, second: &Path, output: &Path) -> Result<MergeSummary> {
        let Self {
            actions,
            redirects,
            distinct_warcinfo,
            warcinfo_differences,
        } = self;
        let mut actions = actions.into_iter();
        let mut merged = 0;
        let filename = output_filename(output);
        let summary = transform(
            &[first, second],
            output,
            compression(output),
            |_, mut record| {
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
            },
        )?;

        Ok(MergeSummary {
            records: summary.records,
            merged,
            distinct_warcinfo,
            warcinfo_differences,
        })
    }
}

/// A warcinfo record's identity for matching: its version, its fields other than the incidental
/// ones with names lowercased and values trimmed and sorted, and its body without ignored fields.
type GroupKey = (WarcVersion, Vec<(String, Vec<u8>)>, Vec<u8>);

/// The matching identity of a warcinfo record.
fn group_key<S: AsRef<str>>(record: &raw::Record, ignored_fields: &[S]) -> GroupKey {
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

    (
        record.header.version,
        headers,
        body_key(&record.body, ignored_fields),
    )
}

/// A body with `isPartOf` and every caller-ignored field removed, when it is a valid warc-fields
/// block.
///
/// Ignored names match case-insensitively. The bytes of every other field are retained exactly, so
/// ignoring a field does not make differences in spelling, white space, folding, or line endings
/// elsewhere incidental too. A body that is not warc-fields retains its original identity.
fn body_key<S: AsRef<str>>(body: &[u8], ignored_fields: &[S]) -> Vec<u8> {
    if WarcinfoBody::parse(body).is_err() {
        return body.to_vec();
    }

    let mut key = Vec::with_capacity(body.len());
    let mut cursor = 0;
    while cursor < body.len() {
        let field_start = cursor;
        let (line, next) = body_line(body, cursor);
        if line.is_empty() {
            key.extend_from_slice(&body[cursor..]);
            break;
        }

        cursor = next;
        while body
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            cursor = body_line(body, cursor).1;
        }

        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .expect("invariant violation: parsed warc-fields line has no colon");
        let name = line[..colon].trim_ascii_end();
        let ignored = name.eq_ignore_ascii_case(b"isPartOf")
            || ignored_fields
                .iter()
                .any(|field| name.eq_ignore_ascii_case(field.as_ref().as_bytes()));
        if !ignored {
            key.extend_from_slice(&body[field_start..cursor]);
        }
    }

    key
}

/// A line's content and the offset at which the following line begins.
fn body_line(body: &[u8], start: usize) -> (&[u8], usize) {
    let Some(relative_end) = body[start..].iter().position(|byte| *byte == b'\n') else {
        return (&body[start..], body.len());
    };
    let line_feed = start + relative_end;
    let content_end = if line_feed > start && body[line_feed - 1] == b'\r' {
        line_feed - 1
    } else {
        line_feed
    };

    (&body[start..content_end], line_feed + 1)
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

/// The trimmed `WARC-Record-ID` value of a record.
fn record_id(record: &raw::Record) -> Option<&[u8]> {
    record
        .header
        .get("WARC-Record-ID")
        .map(<[u8]>::trim_ascii)
        .filter(|value| !value.is_empty())
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

    use archivindex_test_support::warc::render;

    use super::*;

    const ID_A: &str = "<urn:uuid:aaaaaaaa-0000-4000-8000-000000000000>";
    const ID_B: &str = "<urn:uuid:bbbbbbbb-0000-4000-8000-000000000000>";
    const ID_RESPONSE_A: &str = "<urn:uuid:cccccccc-0000-4000-8000-000000000000>";

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
            .records()
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

    /// A collection name describes where a WARC belongs, not whether its crawl metadata is the
    /// same. The kept record retains the collection name it carried.
    #[test]
    fn merges_warcinfo_records_with_different_collections() {
        let directory = tempfile::tempdir().unwrap();

        let headers = |id, date, digest| {
            [
                ("WARC-Type", "warcinfo"),
                ("WARC-Record-ID", id),
                ("WARC-Date", date),
                ("WARC-Block-Digest", digest),
                ("Content-Type", "application/warc-fields"),
            ]
        };
        let first = write_file(
            directory.path(),
            "first.warc",
            &render(
                &headers(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA"),
                "software: tool/1.0\r\nisPartOf: first-collection\r\noperator: Example\r\n",
            ),
        );
        let second = write_file(
            directory.path(),
            "second.warc",
            &render(
                &headers(ID_B, "2024-05-01T00:00:00Z", "sha1:BBBB"),
                "software: tool/1.0\r\nISPARTOF:\r\n second-collection\r\noperator: Example\r\n",
            ),
        );
        let output = directory.path().join("merged.warc");

        let summary = merge(&first, &second, &output).unwrap();

        assert_eq!(summary.records, 1);
        assert_eq!(summary.merged, 1);
        let records = read_records(&output);
        assert_eq!(trimmed(&records[0], "WARC-Record-ID").unwrap(), ID_B);
        assert_eq!(
            records[0].body,
            b"software: tool/1.0\r\nISPARTOF:\r\n second-collection\r\noperator: Example\r\n"
        );
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
        // DEL is a control character, which no platform forbids in a file name.
        let output = directory.path().join("merged\u{7f}.warc");

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

    #[test]
    fn ignores_named_warcinfo_fields_case_insensitively() {
        let directory = tempfile::tempdir().unwrap();
        let headers = |id, date, digest| {
            [
                ("WARC-Type", "warcinfo"),
                ("WARC-Record-ID", id),
                ("WARC-Date", date),
                ("WARC-Block-Digest", digest),
                ("Content-Type", "application/warc-fields"),
            ]
        };
        let first = write_file(
            directory.path(),
            "first.warc",
            &render(
                &headers(ID_A, "2024-05-02T00:00:00Z", "sha1:AAAA"),
                "software: tool/1.0\r\n\
                 http-header-user-agent: Mozilla/5.0 (Intel Mac\u{a0} OS X)\r\n\
                 isPartOf: first\r\n",
            ),
        );
        let second = write_file(
            directory.path(),
            "second.warc",
            &render(
                &headers(ID_B, "2024-05-01T00:00:00Z", "sha1:BBBB"),
                "software: tool/1.0\r\n\
                 HTTP-HEADER-USER-AGENT: Mozilla/5.0 (Intel Mac  OS X)\r\n\
                 isPartOf: second\r\n",
            ),
        );

        let distinct_output = directory.path().join("distinct.warc");
        let distinct = merge(&first, &second, &distinct_output).unwrap();
        assert_eq!(distinct.merged, 0);
        assert_eq!(distinct.distinct_warcinfo, 2);
        assert_eq!(distinct.warcinfo_differences, [WarcinfoDifference::Body]);

        let merged_output = directory.path().join("merged.warc");
        let merged = merge_ignoring_warcinfo_fields(
            &first,
            &second,
            &merged_output,
            &["HTTP-header-USER-agent"],
        )
        .unwrap();
        assert_eq!(merged.merged, 1);
        assert_eq!(merged.distinct_warcinfo, 1);
        assert!(merged.warcinfo_differences.is_empty());
        assert_eq!(read_records(&merged_output).len(), 1);
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
