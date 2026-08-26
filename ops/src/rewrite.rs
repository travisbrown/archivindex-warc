//! Rewrite the `warcinfo` records of a WARC file.
//!
//! Records of other types are copied as read.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::parse::{raw, untyped};
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::fields::Body;
use archivindex_warc::record::fields::dcmi::DcmiTerm;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::record::{self, FieldsBlock, Record, RenderError};
use archivindex_warc::value::{LabelledDigest, Text};

use crate::files::{compression, open};
use crate::{Error, Result};

/// What was written to the rewritten file.
#[derive(Debug)]
pub struct RewriteSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of warcinfo records rewritten.
    pub rewritten: usize,
}

/// The values to set in every warcinfo record.
///
/// A value left `None` keeps what the record has. The `software` field is written as
/// `name/version` and the `operator` field as `name <email>`, so a name given alone keeps the
/// version or email address the record already has, and a version or email address given alone
/// replaces the one the record has.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WarcinfoValues {
    /// The `WARC-Filename` header field.
    pub filename: Option<Text>,
    /// The name written first in the `software` field.
    pub software_name: Option<String>,
    /// The version written after the software name.
    pub software_version: Option<String>,
    /// The name written first in the `operator` field.
    pub operator_name: Option<String>,
    /// The email address written after the operator name.
    pub operator_email: Option<String>,
    /// The value of the `isPartOf` field: the collection the file belongs to.
    pub collection_id: Option<String>,
}

/// Why a warcinfo record could not be rewritten.
#[derive(Debug, thiserror::Error)]
pub enum WarcinfoError {
    /// A header field's value does not match the grammar its name selects.
    #[error(transparent)]
    Untyped(#[from] untyped::Error),
    /// The record is not one the standard permits.
    #[error(transparent)]
    Record(#[from] record::Error),
    /// The record's block is not `application/warc-fields`, so it has no fields to set.
    #[error("the block is not application/warc-fields")]
    NotFields,
    /// A field or its value cannot be written as warc-fields.
    #[error(transparent)]
    Field(#[from] record::fields::Error),
    /// The rewritten record cannot be rendered.
    #[error(transparent)]
    Render(#[from] RenderError),
    /// The record's block digest is under an algorithm this build cannot compute, so the rewritten
    /// block cannot be digested again.
    #[error("cannot compute a {label} digest")]
    UnsupportedDigestAlgorithm {
        /// The algorithm as the record spells it.
        label: String,
    },
    /// Part of a field's value was to be replaced in a record whose value does not have it.
    #[error("the {field} field has no {part} to replace")]
    MissingPart {
        /// The field.
        field: WarcinfoField,
        /// The part of the value that is missing.
        part: &'static str,
    },
}

/// A field whose value is a head followed by an optional tail.
struct TwoPartField {
    field: WarcinfoField,
    /// What the tail is called in an error.
    part: &'static str,
    /// The text between the head and the tail.
    separator: &'static str,
    /// The text after the tail.
    terminator: &'static str,
}

/// The `software` field, written as `name/version`.
const SOFTWARE: TwoPartField = TwoPartField {
    field: WarcinfoField::Software,
    part: "version",
    separator: "/",
    terminator: "",
};

/// The `operator` field, written as `name <email>`.
const OPERATOR: TwoPartField = TwoPartField {
    field: WarcinfoField::Operator,
    part: "email address",
    separator: " <",
    terminator: ">",
};

impl TwoPartField {
    /// Split a value into its head and its tail, if it has one.
    fn split<'a>(&self, value: &'a str) -> (&'a str, Option<&'a str>) {
        value
            .strip_suffix(self.terminator)
            .and_then(|value| value.split_once(self.separator))
            .map_or((value, None), |(head, tail)| (head, Some(tail)))
    }

    /// Set the parts given, keeping those not given from the value the block holds.
    ///
    /// A tail given alone replaces the one the value has, and is an error when the value has
    /// none.
    fn set(
        &self,
        block: &mut Body<WarcinfoField>,
        head: Option<&str>,
        tail: Option<&str>,
    ) -> std::result::Result<(), WarcinfoError> {
        let current = block.get(&self.field).map(|value| self.split(value));
        let (head, tail) = match (head, tail) {
            (Some(head), Some(tail)) => (head, Some(tail)),
            (Some(head), None) => (head, current.and_then(|(_, tail)| tail)),
            (None, Some(tail)) => match current {
                Some((head, Some(_))) => (head, Some(tail)),
                Some((_, None)) | None => {
                    return Err(WarcinfoError::MissingPart {
                        field: self.field.clone(),
                        part: self.part,
                    });
                }
            },
            (None, None) => return Ok(()),
        };
        let value = tail.map_or_else(
            || head.to_owned(),
            |tail| format!("{head}{}{tail}{}", self.separator, self.terminator),
        );

        Ok(block.set(self.field.clone(), value)?)
    }
}

/// Set `values` in every warcinfo record of `input` and write every record to `output`.
///
/// Each field set is given one value, in place of any it had, and is appended to a warcinfo
/// record that lacks it. The record's `Content-Length` and `WARC-Block-Digest` are
/// recomputed, the digest under its declared algorithm when this crate knows it and as SHA-256
/// otherwise; its other header fields keep their values. Records of other types are copied as
/// read. A path with a `.gz` extension names a gzip-compressed file; a compressed output holds
/// one gzip member per record.
///
/// # Errors
///
/// Returns an error when the input and output paths are the same, a file cannot be opened, a
/// record cannot be read or written, a warcinfo record cannot be rewritten, or the output cannot
/// be flushed.
pub fn warcinfo(input: &Path, output: &Path, values: &WarcinfoValues) -> Result<RewriteSummary> {
    if input == output {
        return Err(Error::SameInputAndOutput {
            path: input.to_owned(),
        });
    }

    let file = File::create(output).map_err(|source| Error::Create {
        path: output.to_owned(),
        source,
    })?;
    let mut writer = WarcWriter::new(BufWriter::new(file)).with_compression(compression(output));
    let mut records = 0;
    let mut rewritten = 0;

    for (index, result) in open(input)?.iter_raw_records().enumerate() {
        let mut record = result.map_err(|source| Error::Read {
            path: input.to_owned(),
            source,
        })?;
        if is_warcinfo(&record.header) {
            record = rewrite_warcinfo(record, values).map_err(|source| Error::RewriteWarcinfo {
                path: input.to_owned(),
                index,
                source,
            })?;
            rewritten += 1;
        }

        let written = writer.write(&record).map_err(|source| Error::Write {
            path: output.to_owned(),
            source,
        })?;
        log::trace!(
            "wrote {} bytes at offset {}",
            written.length,
            written.offset
        );
        records += 1;
    }

    writer.flush().map_err(|source| Error::Flush {
        path: output.to_owned(),
        source,
    })?;

    Ok(RewriteSummary { records, rewritten })
}

/// Whether a header block declares the `warcinfo` record type.
fn is_warcinfo(header: &raw::RecordHeader) -> bool {
    header
        .get("WARC-Type")
        .is_some_and(|value| value.trim_ascii().eq_ignore_ascii_case(b"warcinfo"))
}

/// Lift a warcinfo record, set `values` in its block, and render it again.
fn rewrite_warcinfo(
    record: raw::Record,
    values: &WarcinfoValues,
) -> std::result::Result<raw::Record, WarcinfoError> {
    let record = Record::<NoExtension>::try_from(untyped::Record::try_from(record)?)?;
    let Record::Warcinfo {
        mut header,
        mut body,
    } = record
    else {
        unreachable!(
            "invariant violation: a header declaring the warcinfo type lifts to another record type"
        );
    };
    if let Some(filename) = &values.filename {
        header.filename = Some(filename.clone());
    }
    let FieldsBlock::Fields(block) = &mut body else {
        return Err(WarcinfoError::NotFields);
    };
    SOFTWARE.set(
        block,
        values.software_name.as_deref(),
        values.software_version.as_deref(),
    )?;
    OPERATOR.set(
        block,
        values.operator_name.as_deref(),
        values.operator_email.as_deref(),
    )?;
    if let Some(id) = &values.collection_id {
        block.set(WarcinfoField::Dcmi(DcmiTerm::IsPartOf), id.clone())?;
    }

    // Rendering measures the block and adds a SHA-256 digest when none is declared.
    header.core.content_length = None;
    let mut record = Record::Warcinfo { header, body };
    let declared = record.core().block_digest.clone();
    if let Some(declared) = declared {
        record.core_mut().block_digest = Some(refreshed_digest(&declared, &record.body_bytes())?);
    }

    Ok(record.into_raw()?)
}

/// The digest of `block` under the algorithm `declared` names.
fn refreshed_digest(
    declared: &LabelledDigest,
    block: &[u8],
) -> std::result::Result<LabelledDigest, WarcinfoError> {
    declared
        .algorithm()
        .and_then(|algorithm| LabelledDigest::compute(algorithm, block))
        .ok_or_else(|| WarcinfoError::UnsupportedDigestAlgorithm {
            label: declared.algorithm_as_read().into_owned(),
        })
}

#[cfg(test)]
mod tests {
    use archivindex_warc::record::fields::Field as _;
    use archivindex_warc::value::Algorithm;

    use super::*;

    const WARCINFO_BODY: &str =
        "software: old/1\r\noperator: Old <old@example.com>\r\nrobots: classic\r\n";

    /// The header fields of a warcinfo record with the given identifier.
    fn warcinfo_headers(id: &str) -> Vec<(&str, &str)> {
        let mut headers = core("warcinfo", id).to_vec();
        headers.push(("Content-Type", "application/warc-fields"));

        headers
    }

    /// Rewrite one warcinfo record with the given body and return its fields.
    fn rewritten(body: &str, values: &WarcinfoValues) -> Result<Vec<(String, String)>> {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        std::fs::write(&input, render(&warcinfo_headers("<urn:uuid:1>"), body)).unwrap();

        warcinfo(&input, &output, values)?;

        let record = open(&output)
            .unwrap()
            .iter_records::<NoExtension>()
            .next()
            .unwrap()
            .unwrap();

        Ok(fields_of(&record)
            .into_iter()
            .map(|(field, value)| (field.to_owned(), value.to_owned()))
            .collect())
    }

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

    /// The header fields every test record needs, with the given type and numbered identifier.
    fn core<'a>(record_type: &'a str, id: &'a str) -> [(&'a str, &'a str); 3] {
        [
            ("WARC-Type", record_type),
            ("WARC-Record-ID", id),
            ("WARC-Date", "2026-01-01T00:00:00Z"),
        ]
    }

    fn sha1(body: &str) -> LabelledDigest {
        LabelledDigest::compute(Algorithm::Sha1, body.as_bytes()).expect("a SHA-1 digest")
    }

    fn fields_of(record: &Record<NoExtension>) -> Vec<(&str, &str)> {
        let Record::Warcinfo {
            body: FieldsBlock::Fields(block),
            ..
        } = record
        else {
            panic!("not a warcinfo record with fields");
        };

        block
            .iter()
            .map(|(field, value)| (field.name(), value))
            .collect()
    }

    #[test]
    fn sets_fields_in_every_warcinfo_record_and_copies_the_rest() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        let declared = sha1(WARCINFO_BODY);
        let declared = format!("{}:{}", declared.algorithm_as_read(), declared.value());
        let headers = warcinfo_headers("<urn:uuid:1>");
        let mut contents = render(
            &[
                headers.as_slice(),
                &[
                    ("WARC-Block-Digest", &declared),
                    ("WARC-Filename", "old.warc"),
                ],
            ]
            .concat(),
            WARCINFO_BODY,
        );
        contents.extend_from_slice(&render(
            &[
                ("X-Extension", "kept as read"),
                ("WARC-Target-URI", "http://example.com/"),
            ]
            .into_iter()
            .chain(core("response", "<urn:uuid:2>"))
            .collect::<Vec<_>>(),
            "response body",
        ));
        contents.extend_from_slice(&render(
            &warcinfo_headers("<urn:uuid:3>"),
            "robots: classic\r\n",
        ));
        std::fs::write(&input, &contents).unwrap();
        let filename = Text::parse(b"new.warc").unwrap();
        let values = WarcinfoValues {
            filename: Some(filename.clone()),
            software_name: Some("new".to_owned()),
            software_version: Some("2".to_owned()),
            collection_id: Some("collection".to_owned()),
            ..WarcinfoValues::default()
        };

        let summary = warcinfo(&input, &output, &values).unwrap();

        assert_eq!(summary.records, 3);
        assert_eq!(summary.rewritten, 2);
        let records: Vec<_> = open(&output)
            .unwrap()
            .iter_records::<NoExtension>()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(
            fields_of(&records[0]),
            [
                ("software", "new/2"),
                ("operator", "Old <old@example.com>"),
                ("robots", "classic"),
                ("isPartOf", "collection"),
            ]
        );
        let body = "software: new/2\r\noperator: Old <old@example.com>\r\nrobots: classic\r\n\
                    isPartOf: collection\r\n";
        assert_eq!(records[0].core().content_length, Some(body.len() as u64));
        assert_eq!(records[0].core().block_digest, Some(sha1(body)));
        assert_eq!(
            fields_of(&records[2]),
            [
                ("robots", "classic"),
                ("software", "new/2"),
                ("isPartOf", "collection"),
            ]
        );
        assert_eq!(
            records[2]
                .core()
                .block_digest
                .as_ref()
                .and_then(LabelledDigest::algorithm),
            Some(Algorithm::Sha256)
        );
        for record in [&records[0], &records[2]] {
            let Record::Warcinfo { header, .. } = record else {
                panic!("not a warcinfo record");
            };
            assert_eq!(header.filename.as_ref(), Some(&filename));
        }
        let raw = |path| {
            open(path)
                .unwrap()
                .iter_raw_records()
                .nth(1)
                .unwrap()
                .unwrap()
        };
        assert_eq!(raw(&output), raw(&input));
    }

    #[test]
    fn keeps_the_part_of_a_value_not_given() {
        let values = |name: Option<&str>, tail: Option<&str>| WarcinfoValues {
            software_name: name.map(str::to_owned),
            software_version: tail.map(str::to_owned),
            operator_name: name.map(str::to_owned),
            operator_email: tail.map(str::to_owned),
            ..WarcinfoValues::default()
        };
        let first_two = |body, values: &WarcinfoValues| {
            let mut fields = rewritten(body, values).unwrap();
            fields.truncate(2);
            fields
        };
        let pair = |software: &str, operator: &str| {
            [
                ("software".to_owned(), software.to_owned()),
                ("operator".to_owned(), operator.to_owned()),
            ]
        };

        assert_eq!(
            first_two(WARCINFO_BODY, &values(Some("new"), None)),
            pair("new/1", "new <old@example.com>")
        );
        assert_eq!(
            first_two(WARCINFO_BODY, &values(None, Some("2"))),
            pair("old/2", "Old <2>")
        );
        assert_eq!(
            first_two(
                "software: old\r\noperator: Old\r\n",
                &values(Some("new"), None)
            ),
            pair("new", "new")
        );
        assert_eq!(
            first_two("robots: classic\r\n", &values(Some("new"), None)),
            [
                ("robots".to_owned(), "classic".to_owned()),
                ("software".to_owned(), "new".to_owned()),
            ]
        );
    }

    #[test]
    fn refuses_to_replace_a_part_a_value_does_not_have() {
        for body in ["software: old\r\noperator: Old\r\n", ""] {
            for (values, field, part) in [
                (
                    WarcinfoValues {
                        software_version: Some("2".to_owned()),
                        ..WarcinfoValues::default()
                    },
                    WarcinfoField::Software,
                    "version",
                ),
                (
                    WarcinfoValues {
                        operator_email: Some("new@example.com".to_owned()),
                        ..WarcinfoValues::default()
                    },
                    WarcinfoField::Operator,
                    "email address",
                ),
            ] {
                let error = rewritten(body, &values).unwrap_err();

                assert!(matches!(
                    &error,
                    Error::RewriteWarcinfo {
                        index: 0,
                        source: WarcinfoError::MissingPart { field: found, part: found_part },
                        ..
                    } if *found == field && *found_part == part
                ));
                assert!(error.to_string().ends_with("input.warc"));
            }
        }
    }

    #[test]
    fn refuses_a_warcinfo_record_whose_block_is_not_fields() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        let mut contents = render(&core("resource", "<urn:uuid:1>"), "resource body");
        contents.extend_from_slice(&render(
            &[
                core("warcinfo", "<urn:uuid:2>").as_slice(),
                &[("Content-Type", "text/plain")],
            ]
            .concat(),
            "not fields",
        ));
        std::fs::write(&input, contents).unwrap();

        let error = warcinfo(
            &input,
            &output,
            &WarcinfoValues {
                software_name: Some("new".to_owned()),
                ..WarcinfoValues::default()
            },
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            Error::RewriteWarcinfo {
                path,
                index: 1,
                source: WarcinfoError::NotFields
            } if path == &input
        ));
        assert_eq!(
            error.to_string(),
            format!("cannot rewrite warcinfo record 1 of {}", input.display())
        );
    }

    #[test]
    fn refuses_a_value_that_cannot_be_written_as_a_field() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        let contents = render(
            &[
                core("warcinfo", "<urn:uuid:1>").as_slice(),
                &[("Content-Type", "application/warc-fields")],
            ]
            .concat(),
            WARCINFO_BODY,
        );
        std::fs::write(&input, contents).unwrap();

        let error = warcinfo(
            &input,
            &output,
            &WarcinfoValues {
                operator_name: Some("two\r\nlines".to_owned()),
                ..WarcinfoValues::default()
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            Error::RewriteWarcinfo {
                index: 0,
                source: WarcinfoError::Field(_),
                ..
            }
        ));
    }

    #[test]
    fn refuses_a_block_digest_it_cannot_compute() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        let mut headers = warcinfo_headers("<urn:uuid:1>");
        headers.push(("WARC-Block-Digest", "crc32:1c330fb2d66be8b5"));
        std::fs::write(&input, render(&headers, WARCINFO_BODY)).unwrap();

        let error = warcinfo(
            &input,
            &output,
            &WarcinfoValues {
                software_name: Some("new".to_owned()),
                ..WarcinfoValues::default()
            },
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            Error::RewriteWarcinfo {
                index: 0,
                source: WarcinfoError::UnsupportedDigestAlgorithm { label },
                ..
            } if label == "crc32"
        ));
    }
}
