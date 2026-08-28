//! Canonicalize the header fields of a WARC file.
//!
//! Standard fields are respelled as the WARC standard prints them and moved into conventional
//! order. Extension fields follow standard fields and keep their spelling and relative order.
//! Values, bodies, record order, and the relative order of repeated fields are preserved.

use std::path::Path;

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;

use crate::Result;
use crate::file::{compression, transform};

/// What was written to the canonicalized file.
#[derive(Debug)]
pub struct CanonicalizeSummary {
    /// The number of records written.
    pub records: usize,
}

/// Canonicalize every record header in `input` and write the records to `output`.
///
/// Standard field names are respelled and sorted into conventional order. Extension field names,
/// all field values, bodies, and record order are preserved. A path with a `.gz` extension names
/// a gzip-compressed file; a compressed output holds one gzip member per record. A temporary file
/// beside `output` is moved into place after the last record is written.
///
/// # Errors
///
/// Returns an error when the input and output paths are the same, a file cannot be opened, a
/// record cannot be read or written, or the output cannot be flushed or moved into place.
pub fn canonicalize(input: &Path, output: &Path) -> Result<CanonicalizeSummary> {
    let summary = transform(&[input], output, compression(output), |_, mut record| {
        canonicalize_header(&mut record.header);

        Ok(Some(record))
    })?;

    Ok(CanonicalizeSummary {
        records: summary.records,
    })
}

/// Respell standard fields and put them before extension fields in conventional order.
fn canonicalize_header(header: &mut raw::RecordHeader) {
    for (name, _) in &mut header.headers {
        if let Some(field) = Field::from_name(name) {
            field.standard_name().clone_into(name);
        }
    }

    // This stable sort keeps repeated fields and extension fields in their original relative
    // order. Extension fields all receive the same rank after every standard field.
    header
        .headers
        .sort_by_key(|(name, _)| Field::from_name(name).map_or(usize::MAX, Field::canonical_rank));
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use archivindex_test_support::warc::render;

    use super::*;
    use crate::Error;
    use crate::file::open;

    #[test]
    fn canonicalizes_every_header_without_changing_values_or_bodies() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");

        let mut contents = render(
            &[
                ("X-First", "extension one "),
                ("warc-record-id", "<urn:uuid:first> "),
                ("WARC-concurrent-TO", "<urn:uuid:a> "),
                ("warc-type", "response "),
                ("X-Second", "extension two "),
                ("warc-CONCURRENT-to", "<urn:uuid:b> "),
                ("warc-date", "not parsed by this operation "),
            ],
            "first body",
        );
        contents.extend_from_slice(&render(
            &[
                ("content-type", " application/octet-stream "),
                ("warc-type", " resource "),
            ],
            "second body",
        ));
        std::fs::write(&input, contents).unwrap();

        let summary = canonicalize(&input, &output).unwrap();

        assert_eq!(summary.records, 2);
        let records: Vec<_> = open(&output)
            .unwrap()
            .iter_raw_records()
            .records()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].body, b"first body");
        assert_eq!(
            records[0]
                .header
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            [
                "WARC-Type",
                "WARC-Date",
                "WARC-Record-ID",
                "WARC-Concurrent-To",
                "WARC-Concurrent-To",
                "Content-Length",
                "X-First",
                "X-Second",
            ]
        );
        assert_eq!(
            records[0].header.headers[1].1,
            b" not parsed by this operation "
        );
        assert_eq!(records[0].header.headers[3].1, b" <urn:uuid:a> ");
        assert_eq!(records[0].header.headers[4].1, b" <urn:uuid:b> ");
        assert_eq!(records[1].body, b"second body");
    }

    #[test]
    fn reads_and_writes_gzip_by_extension() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc.gz");
        let output = directory.path().join("output.warc.gz");
        let contents = render(&[("warc-type", " resource ")], "body");
        let mut encoder = flate2::write::GzEncoder::new(
            File::create(&input).unwrap(),
            flate2::Compression::default(),
        );
        encoder.write_all(&contents).unwrap();
        encoder.finish().unwrap();

        let summary = canonicalize(&input, &output).unwrap();

        assert_eq!(summary.records, 1);
        let records: Vec<_> = open(&output)
            .unwrap()
            .iter_raw_records()
            .records()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records[0].header.headers[0].0, "WARC-Type");
        assert_eq!(records[0].body, b"body");
    }

    #[test]
    fn refuses_to_overwrite_the_input() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let contents = render(&[("warc-type", " resource ")], "body");
        std::fs::write(&input, &contents).unwrap();

        let error = canonicalize(&input, &input).unwrap_err();

        assert!(matches!(
            &error,
            Error::SameInputAndOutput { path } if path == &input
        ));
        assert_eq!(
            error.to_string(),
            format!(
                "input and output must be different files: {}",
                input.display()
            )
        );
        assert_eq!(std::fs::read(input).unwrap(), contents);
    }
}
