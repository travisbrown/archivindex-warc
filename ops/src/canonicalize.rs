//! Canonicalize the header fields of a WARC file.
//!
//! Standard fields are respelled as the WARC standard prints them and moved into conventional
//! order. Extension fields follow standard fields and keep their spelling and relative order.
//! Values, bodies, record order, and the relative order of repeated fields are preserved.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;

use crate::files::{compression, open};
use crate::{Error, Result};

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
/// a gzip-compressed file; a compressed output holds one gzip member per record.
///
/// # Errors
///
/// Returns an error when the input and output paths are the same, a file cannot be opened, a
/// record cannot be read or written, or the output cannot be flushed.
pub fn canonicalize(input: &Path, output: &Path) -> Result<CanonicalizeSummary> {
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

    for result in open(input)?.iter_raw_records() {
        let mut record = result.map_err(|source| Error::Read {
            path: input.to_owned(),
            source,
        })?;
        canonicalize_header(&mut record.header);

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

    Ok(CanonicalizeSummary { records })
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
    use std::io::Write;

    use super::*;

    /// A WARC 1.1 record with the given fields, framed by the body's length.
    fn render(headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut record = b"WARC/1.1\r\n".to_vec();
        for (name, value) in headers {
            record.extend_from_slice(format!("{name}:{value}\r\n").as_bytes());
        }
        record.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        record.extend_from_slice(body.as_bytes());
        record.extend_from_slice(b"\r\n\r\n");

        record
    }

    #[test]
    fn canonicalizes_every_header_without_changing_values_or_bodies() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");

        let mut contents = render(
            &[
                ("X-First", " extension one "),
                ("warc-record-id", " <urn:uuid:first> "),
                ("WARC-concurrent-TO", " <urn:uuid:a> "),
                ("warc-type", " response "),
                ("X-Second", " extension two "),
                ("warc-CONCURRENT-to", " <urn:uuid:b> "),
                ("warc-date", " not parsed by this operation "),
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
