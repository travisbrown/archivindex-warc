//! Compress a WARC file record by record.
//!
//! Each record becomes its own gzip member, as the WARC standard requires of compressed files,
//! so the output can be indexed and any record decompressed without reading the ones before it.

use std::io::{BufRead, Write};
use std::path::Path;

use archivindex_warc::io::read::{self, WarcReader};
use archivindex_warc::io::write::{self, Compression, WarcWriter};

use crate::file::transform;

/// A failure while compressing a WARC file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A record could not be read from the input.
    #[error("cannot read record")]
    Read(#[from] read::Error),
    /// A record could not be written to the output.
    #[error("cannot write record")]
    Write(#[from] write::Error),
}

/// What was written to the compressed output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of compressed bytes written.
    pub bytes: u64,
}

/// Compress every record of the uncompressed WARC file in `input` into `output` at `level`.
///
/// Each record is written as an independent gzip member at compression level `level`, from 0
/// (no compression) through 9 (best compression). Records are copied byte for byte; nothing is
/// reordered, respelled, or validated beyond what reading requires. The output is flushed before
/// returning.
///
/// # Errors
///
/// Returns [`Error::Write`] carrying
/// [`write::Error::InvalidGzipCompressionLevel`] when `level` is greater than 9, before anything
/// is read, [`Error::Read`] when a record cannot be read, and [`Error::Write`] when a record
/// cannot be written or the output cannot be flushed.
pub fn compress<R: BufRead, W: Write>(
    input: R,
    level: u32,
    output: W,
) -> Result<CompressSummary, Error> {
    let compression = Compression::gzip_with_level(level)?;
    let mut writer = WarcWriter::new(output).with_compression(compression);
    let mut records = 0;

    for result in WarcReader::new(input).iter_raw_records() {
        writer.write(&result?)?;
        records += 1;
    }

    writer.flush().map_err(write::Error::from)?;

    Ok(CompressSummary {
        records,
        bytes: writer.position(),
    })
}

/// Compress the WARC file at `input` into the file at `output` at `level`.
///
/// The records are compressed as by [`compress`], but written to `<output>.partial`, which must
/// not already exist, and moved into place once the last one is written, so a failure leaves any
/// file already at `output` as it was, and an output that is a hard link or symbolic link to the
/// input leaves the input as it was.
///
/// # Errors
///
/// Returns [`crate::Error::CompressionLevel`] when `level` is greater than 9, before anything is
/// read, and otherwise the error of the step that failed: opening, reading, creating, writing,
/// flushing, or publishing.
pub fn compress_path(input: &Path, level: u32, output: &Path) -> crate::Result<CompressSummary> {
    let compression =
        Compression::gzip_with_level(level).map_err(crate::Error::CompressionLevel)?;
    let summary = transform(&[input], output, compression, |_, record| Ok(Some(record)))?;

    Ok(CompressSummary {
        records: summary.records,
        bytes: summary.bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use archivindex_test_support::warc::render;
    use archivindex_warc::parse::raw;
    use flate2::bufread::GzDecoder;

    use super::*;

    /// A WARC 1.1 resource record with the given identifier and body.
    fn resource(id: &str, body: &str) -> Vec<u8> {
        render(
            &[
                ("WARC-Type", "resource"),
                ("WARC-Record-ID", &format!("<urn:uuid:{id}>")),
                ("WARC-Date", "2024-01-01T00:00:00Z"),
            ],
            body,
        )
    }

    /// Two records, concatenated.
    fn archive() -> Vec<u8> {
        let mut bytes = resource("a", "first body");
        bytes.extend(resource("b", "second body"));
        bytes
    }

    fn records(bytes: &[u8]) -> Vec<raw::Record> {
        WarcReader::new(bytes)
            .iter_raw_records()
            .collect::<Result<_, _>>()
            .expect("every record reads")
    }

    /// The decompressed contents of each gzip member in `bytes`, in order.
    fn members(mut bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut members = Vec::new();
        while !bytes.is_empty() {
            let mut decoder = GzDecoder::new(bytes);
            let mut member = Vec::new();
            decoder
                .read_to_end(&mut member)
                .expect("the member decodes");
            members.push(member);
            bytes = decoder.into_inner();
        }
        members
    }

    #[test]
    fn each_record_becomes_its_own_gzip_member() {
        let input = archive();
        let mut output = Vec::new();

        let summary = compress(&input[..], 6, &mut output).unwrap();

        assert_eq!(
            summary,
            CompressSummary {
                records: 2,
                bytes: output.len() as u64,
            }
        );
        let members = members(&output);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0], resource("a", "first body"));
        assert_eq!(members[1], resource("b", "second body"));
    }

    #[test]
    fn the_compressed_file_reads_back_unchanged() {
        let input = archive();
        let mut output = Vec::new();

        compress(&input[..], 9, &mut output).unwrap();

        let mut decoded = Vec::new();
        flate2::bufread::MultiGzDecoder::new(&output[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(records(&decoded), records(&input));
    }

    #[test]
    fn an_empty_input_yields_an_empty_output() {
        let mut output = Vec::new();

        let summary = compress(&b""[..], 6, &mut output).unwrap();

        assert_eq!(
            summary,
            CompressSummary {
                records: 0,
                bytes: 0
            }
        );
        assert!(output.is_empty());
    }

    #[test]
    fn an_invalid_level_is_refused_before_reading() {
        let mut output = Vec::new();

        let error = compress(&b"not a warc"[..], 10, &mut output).unwrap_err();

        assert!(matches!(
            error,
            Error::Write(write::Error::InvalidGzipCompressionLevel(10))
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn an_unreadable_record_stops_compression() {
        let mut input = archive();
        input.extend_from_slice(b"WARC/1.1\r\nbroken");
        let mut output = Vec::new();

        let error = compress(&input[..], 6, &mut output).unwrap_err();

        assert!(matches!(error, Error::Read(_)));
        assert_eq!(members(&output).len(), 2);
    }

    #[test]
    fn a_path_is_compressed_into_a_readable_file() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc.gz");
        std::fs::write(&input, archive()).unwrap();

        let summary = compress_path(&input, 6, &output).unwrap();

        let compressed = std::fs::read(&output).unwrap();
        assert_eq!(
            summary,
            CompressSummary {
                records: 2,
                bytes: compressed.len() as u64,
            }
        );
        assert_eq!(members(&compressed).len(), 2);
        let read = crate::file::open(&output)
            .unwrap()
            .iter_raw_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(read, records(&archive()));
    }

    #[test]
    fn an_unreadable_record_leaves_the_previous_output_in_place() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc.gz");
        let mut broken = archive();
        broken.extend_from_slice(b"WARC/1.1\r\nbroken");
        std::fs::write(&input, broken).unwrap();
        std::fs::write(&output, b"previous").unwrap();

        let error = compress_path(&input, 6, &output).unwrap_err();

        assert!(matches!(error, crate::Error::Read { .. }));
        assert_eq!(std::fs::read(&output).unwrap(), b"previous");
        assert!(!directory.path().join("output.warc.gz.partial").exists());
    }

    #[test]
    fn an_invalid_level_for_a_path_is_refused_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("missing.warc");
        let output = directory.path().join("output.warc.gz");

        let error = compress_path(&input, 10, &output).unwrap_err();

        assert!(matches!(
            error,
            crate::Error::CompressionLevel(write::Error::InvalidGzipCompressionLevel(10))
        ));
        assert!(!output.exists());
    }
}
