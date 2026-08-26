//! Validation using the crate's raw, untyped, and semantic representations.
//!
//! Each layer reads the file independently and reports only the rules it checks.

use std::io::{self, BufRead};
use std::path::Path;

use archivindex_cli_support::plural;
use archivindex_warc::io::read::{Error, WarcReader};
use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc_ops::file::is_gzip;

use crate::model::ValidationResult;

/// A validation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Record framing and raw field syntax.
    Raw,
    /// Field-value grammar in addition to raw validation.
    Untyped,
    /// Semantic rules and declared digests in addition to untyped validation.
    Record,
}

impl Layer {
    /// The layer's report name.
    const fn name(self) -> &'static str {
        match self {
            Self::Raw => "archivindex raw",
            Self::Untyped => "archivindex untyped",
            Self::Record => "archivindex record",
        }
    }
}

pub fn run_archivindex(file: &Path, layer: Layer) -> ValidationResult {
    let name = layer.name();
    match read(file, layer) {
        Err(error) => ValidationResult::error(name, format!("could not open the file: {error}")),
        Ok(outcome) if !outcome.errors.is_empty() => ValidationResult::failed(
            name,
            format!(
                "{}, {}",
                records_read(outcome.records),
                plural(outcome.errors.len(), "error")
            ),
            outcome.errors.join("\n"),
        ),
        Ok(outcome) if outcome.records == 0 => {
            ValidationResult::failed(name, "file contains no WARC records", String::new())
        }
        Ok(outcome) => ValidationResult::passed(name, records_read(outcome.records), String::new()),
    }
}

/// Results from reading a file at one layer.
struct Outcome {
    /// Records read successfully.
    records: usize,
    /// Errors in record order.
    errors: Vec<String>,
}

fn read(file: &Path, layer: Layer) -> io::Result<Outcome> {
    if is_gzip(file) {
        Ok(tally(WarcReader::from_path_gzip(file)?, layer))
    } else {
        Ok(tally(WarcReader::from_path(file)?, layer))
    }
}

/// Read and count records at one validation layer.
///
/// Stream and framing errors stop iteration. Untyped and semantic errors do not.
fn tally<R: BufRead>(reader: WarcReader<R>, layer: Layer) -> Outcome {
    match layer {
        Layer::Raw => collect(reader.iter_raw_records()),
        Layer::Untyped => collect(reader.iter_untyped_records()),
        Layer::Record => collect(reader.iter_records::<NoExtension>().map(digest_checked)),
    }
}

/// Return a record only if its supported declared digests are valid.
///
/// Semantic reading preserves invalid digests, so validation checks them explicitly.
fn digest_checked(
    record: Result<Record<NoExtension>, Error>,
) -> Result<Record<NoExtension>, Error> {
    let record = record?;

    record
        .incorrect_block_digest()
        .or_else(|| record.incorrect_payload_digest())
        .map_or(Ok(record), |failure| Err(Error::Record(failure.into())))
}

fn collect<T>(records: impl Iterator<Item = Result<T, Error>>) -> Outcome {
    let mut outcome = Outcome {
        records: 0,
        errors: Vec::new(),
    };

    for record in records {
        match record {
            Ok(_) => outcome.records += 1,
            Err(error) => {
                let position = outcome.records + outcome.errors.len() + 1;
                outcome
                    .errors
                    .push(format!("record {position}: {}", describe(&error)));
            }
        }
    }

    outcome
}

/// Format an error, including the underlying I/O error when available.
fn describe(error: &Error) -> String {
    if let Error::Source(source) = error {
        format!("{error} ({source})")
    } else {
        error.to_string()
    }
}

fn records_read(count: usize) -> String {
    format!("{} read", plural(count, "record"))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tempfile::{Builder, NamedTempFile};

    use super::*;

    const ALL_LAYERS: [Layer; 3] = [Layer::Raw, Layer::Untyped, Layer::Record];

    const VALID_WARC: &[u8] = concat!(
        "WARC/1.1\r\n",
        "WARC-Type: resource\r\n",
        "WARC-Record-ID: <urn:uuid:12345678-1234-1234-1234-123456789abc>\r\n",
        "WARC-Date: 2026-08-14T12:00:00Z\r\n",
        "WARC-Target-URI: https://example.com/\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
        "\r\n\r\n",
    )
    .as_bytes();

    /// A syntactically valid `resource` missing its required target URI.
    const UNNAMED_RESOURCE: &[u8] = concat!(
        "WARC/1.1\r\n",
        "WARC-Type: resource\r\n",
        "WARC-Record-ID: <urn:uuid:12345678-1234-1234-1234-123456789abc>\r\n",
        "WARC-Date: 2026-08-14T12:00:00Z\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
        "\r\n\r\n",
    )
    .as_bytes();

    /// A record with an invalid `WARC-Date` value.
    const MALFORMED_DATE: &[u8] = concat!(
        "WARC/1.1\r\n",
        "WARC-Type: resource\r\n",
        "WARC-Record-ID: <urn:uuid:12345678-1234-1234-1234-123456789abc>\r\n",
        "WARC-Date: the day before yesterday\r\n",
        "WARC-Target-URI: https://example.com/\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
        "\r\n\r\n",
    )
    .as_bytes();

    fn outcome_of(contents: &[u8], layer: Layer) -> Outcome {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), contents).unwrap();
        read(file.path(), layer).unwrap()
    }

    #[test]
    fn reads_a_minimal_warc_at_every_layer() {
        for layer in ALL_LAYERS {
            let outcome = outcome_of(VALID_WARC, layer);
            assert_eq!(outcome.records, 1, "{layer:?}");
            assert!(outcome.errors.is_empty(), "{layer:?}");
        }
    }

    #[test]
    fn reads_a_minimal_gzip_warc_at_every_layer() {
        let mut file = Builder::new().suffix(".warc.gz").tempfile().unwrap();
        let mut encoder = GzEncoder::new(file.as_file_mut(), Compression::default());
        encoder.write_all(VALID_WARC).unwrap();
        encoder.finish().unwrap();

        for layer in ALL_LAYERS {
            assert_eq!(read(file.path(), layer).unwrap().records, 1, "{layer:?}");
        }
    }

    /// A record rejected only by semantic rules passes the lower layers.
    #[test]
    fn each_layer_refuses_only_what_it_checks() {
        assert!(outcome_of(UNNAMED_RESOURCE, Layer::Raw).errors.is_empty());
        assert!(
            outcome_of(UNNAMED_RESOURCE, Layer::Untyped)
                .errors
                .is_empty()
        );

        let refused = outcome_of(UNNAMED_RESOURCE, Layer::Record);
        assert_eq!(refused.records, 0);
        assert_eq!(
            refused.errors,
            ["record 1: the mandatory `warc-target-uri` field is missing".to_owned()]
        );
    }

    /// Invalid field grammar is reported by both layers that parse values.
    #[test]
    fn a_malformed_value_is_reported_with_the_field_that_carried_it() {
        assert!(outcome_of(MALFORMED_DATE, Layer::Raw).errors.is_empty());

        for layer in [Layer::Untyped, Layer::Record] {
            let refused = outcome_of(MALFORMED_DATE, layer);
            assert_eq!(refused.records, 0, "{layer:?}");
            assert!(
                refused.errors[0].contains("malformed WARC-Date field"),
                "{:?}",
                refused.errors
            );
        }
    }

    /// Reading continues after record-level errors and preserves record positions.
    #[test]
    fn errors_name_the_record_they_belong_to() {
        let mut archive = MALFORMED_DATE.to_vec();
        archive.extend_from_slice(VALID_WARC);
        archive.extend_from_slice(UNNAMED_RESOURCE);

        let refused = outcome_of(&archive, Layer::Record);

        assert_eq!(refused.records, 1);
        assert!(refused.errors[0].starts_with("record 1: "));
        assert!(refused.errors[1].starts_with("record 3: "));
    }

    #[test]
    fn rejects_an_empty_file() {
        let file = NamedTempFile::new().unwrap();
        for layer in ALL_LAYERS {
            assert!(
                !run_archivindex(file.path(), layer).is_success(),
                "{layer:?}"
            );
        }
    }

    /// A truncated stream produces one error and stops iteration.
    #[test]
    fn a_truncated_record_is_reported_once() {
        let truncated = &VALID_WARC[..VALID_WARC.len() - 6];
        let refused = outcome_of(truncated, Layer::Raw);

        assert_eq!(refused.records, 0);
        assert_eq!(refused.errors.len(), 1);
    }
}
