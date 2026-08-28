//! Payload digests recomputed the way other tools compute them.
//!
//! WARC 1.1 clause 5.9 makes the payload of an HTTP message its entity-body, which is the message
//! body with any transfer-coding removed. Several other tools digest the message body as it was
//! framed, chunk sizes and trailers included, and expect the same of the files they validate.

use std::path::Path;

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::payload;
use archivindex_warc::value::{DigestError, DigestFormat, LabelledDigest, MediaType};

use crate::Result;
use crate::file::{compression, transform};
use crate::header::{is_request, is_response};

/// What was written to the rewritten file.
#[derive(Debug)]
pub struct FramedPayloadsSummary {
    /// The number of records written.
    pub records: usize,
    /// The number of payload digests that changed.
    pub rewritten: usize,
}

/// Why a declared payload digest is kept as read.
#[derive(Debug, thiserror::Error)]
enum Kept {
    /// The declared digest does not fit the `labelled-digest` grammar.
    #[error("the payload digest is malformed: {0}")]
    Malformed(#[from] DigestError),
    /// The declared digest names an algorithm this build does not compute.
    #[error("the payload digest names the algorithm `{0}`, which this build does not compute")]
    UnsupportedAlgorithm(String),
    /// The declared digest value is in no encoding of its algorithm's digest.
    #[error("the payload digest value `{0}` is in no encoding of its algorithm's digest")]
    Undecodable(String),
    /// The HTTP message has no body to digest.
    #[error(transparent)]
    Unreadable(#[from] payload::Error),
}

/// Rewrite the payload digests of `input` over HTTP message bodies as framed, writing the records
/// to `output`.
///
/// Each `request` or `response` record with an HTTP or HTTPS target and a `Content-Type` of
/// `application/http` or none that declares `WARC-Payload-Digest` has it recomputed over the
/// message body as framed, transfer-coding included, under the algorithm and encoding it declares,
/// keeping the label as read. A segmented or truncated record, a record whose digest is malformed
/// or names an algorithm this build does not compute, and a record whose message has no end of
/// header section are copied as read, the last three with a warning. Every other record is copied
/// as read. A path with a `.gz` extension names a gzip-compressed file; a compressed output holds
/// one gzip member per record. A temporary file beside `output` is moved into place after the
/// last record is written.
///
/// # Errors
///
/// Returns an error when the input and output paths are the same, a file cannot be opened, a
/// record cannot be read or written, or the output cannot be flushed or moved into place.
pub fn framed_payloads(input: &Path, output: &Path) -> Result<FramedPayloadsSummary> {
    let mut rewritten = 0;
    let summary = transform(
        &[input],
        output,
        compression(output),
        |index, mut record| {
            if holds_http_message(&record.header)
                && let Some(position) = payload_digest_position(&record.header)
            {
                match framed_digest(&record, position) {
                    Ok(Some(digest)) => {
                        replace_trimmed(&mut record.header.headers[position].1, &digest);
                        rewritten += 1;
                    }
                    Ok(None) => {}
                    Err(kept) => log::warn!("keeping the payload digest of record {index}: {kept}"),
                }
            }

            Ok(Some(record))
        },
    )?;

    Ok(FramedPayloadsSummary {
        records: summary.records,
        rewritten,
    })
}

/// Whether a header block declares an HTTP message as its block.
///
/// The record must be a `request` or `response`, the target URI must name HTTP or HTTPS, and the
/// media type must be `application/http` or absent.
fn holds_http_message(header: &raw::RecordHeader) -> bool {
    (is_request(header) || is_response(header))
        && has_http_target(header)
        && header
            .get(Field::ContentType.standard_name())
            .is_none_or(|value| {
                MediaType::parse(value.trim_ascii())
                    .is_ok_and(|media_type| media_type.is("application", "http"))
            })
}

/// Whether a header block's target URI names HTTP or HTTPS, with or without angle brackets.
fn has_http_target(header: &raw::RecordHeader) -> bool {
    header
        .get(Field::TargetURI.standard_name())
        .is_some_and(|value| {
            let target = value.trim_ascii();
            let target = target.strip_prefix(b"<").unwrap_or(target);

            [b"http:".as_slice(), b"https:"].into_iter().any(|scheme| {
                target
                    .get(..scheme.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
            })
        })
}

/// The index of the `WARC-Payload-Digest` field in a header block, unless the record is a segment
/// or truncated, whose declared digest covers more than its block.
fn payload_digest_position(header: &raw::RecordHeader) -> Option<usize> {
    if header.get(Field::SegmentNumber.standard_name()).is_some()
        || header.get(Field::Truncated.standard_name()).is_some()
    {
        return None;
    }

    header
        .headers
        .iter()
        .position(|(name, _)| Field::from_name(name) == Some(Field::PayloadDigest))
}

/// The labelled digest of the framed message body, or `None` when the declared digest already
/// is it.
///
/// The declared label and encoding are kept.
fn framed_digest(
    record: &raw::Record,
    position: usize,
) -> std::result::Result<Option<String>, Kept> {
    let declared = LabelledDigest::parse(record.header.headers[position].1.trim_ascii())?;
    let algorithm = declared
        .algorithm()
        .ok_or_else(|| Kept::UnsupportedAlgorithm(declared.algorithm_as_read().into_owned()))?;
    let encoding = declared
        .encoding()
        .ok_or_else(|| Kept::Undecodable(declared.value().to_owned()))?;
    let digest = algorithm
        .digest(payload::message_body(&record.body)?)
        .ok_or_else(|| Kept::UnsupportedAlgorithm(declared.algorithm_as_read().into_owned()))?;

    if declared.decoded().as_deref() == Some(&*digest) {
        return Ok(None);
    }

    let format = DigestFormat {
        algorithm,
        encoding,
    };
    let value = LabelledDigest::from_digest_in(format, &digest);

    Ok(Some(format!(
        "{}:{}",
        declared.algorithm_as_read(),
        value.value()
    )))
}

/// Replace a field value with `replacement`, keeping the white space around the value as read.
fn replace_trimmed(value: &mut Vec<u8>, replacement: &str) {
    let start = value.len() - value.trim_ascii_start().len();
    let end = value.trim_ascii_end().len();

    value.splice(start..end, replacement.bytes());
}

#[cfg(test)]
mod tests {
    use archivindex_test_support::warc::render;

    use super::*;
    use crate::file::open;

    /// A chunked message whose entity-body is `hello`.
    const CHUNKED: &str =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

    /// The SHA-1 digest of `hello`.
    const ENTITY_BASE32: &str = "VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N";

    /// The SHA-1 digest of the chunked framing of `hello`.
    const FRAMED_BASE32: &str = "FPKJFAEPEIMEFSS2G2SDNSN5YKX3N5JX";

    /// The SHA-1 digest of `hello`, in Base16.
    const ENTITY_BASE16: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    /// The SHA-1 digest of the chunked framing of `hello`, in Base16.
    const FRAMED_BASE16: &str = "2bd492808f221842ca5a36a436c9bdc2afb6f537";

    /// A response record for `http://example.com/` with the given further fields.
    fn response(fields: &[(&str, &str)], body: &str) -> Vec<u8> {
        let headers = [
            &[
                ("WARC-Type", "response"),
                ("WARC-Target-URI", "http://example.com/"),
            ],
            fields,
        ]
        .concat();

        render(&headers, body)
    }

    /// Write `contents` as the input, rewrite it, and read back the output records.
    fn rewritten(contents: &[u8]) -> (FramedPayloadsSummary, Vec<raw::Record>) {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        let output = directory.path().join("output.warc");
        std::fs::write(&input, contents).unwrap();

        let summary = framed_payloads(&input, &output).unwrap();

        let records = open(&output)
            .unwrap()
            .iter_raw_records()
            .records()
            .collect::<std::result::Result<_, _>>()
            .unwrap();

        (summary, records)
    }

    /// The `WARC-Payload-Digest` value of a record, as read.
    fn payload_digest(record: &raw::Record) -> Option<&[u8]> {
        record.header.get("WARC-Payload-Digest")
    }

    #[test]
    fn digests_the_framed_body_of_a_chunked_message_in_the_declared_format() {
        let mut contents = response(
            &[("WARC-Payload-Digest", &format!("sha1:{ENTITY_BASE32}"))],
            CHUNKED,
        );
        contents.extend_from_slice(&response(
            &[("WARC-Payload-Digest", &format!("SHA-1:{ENTITY_BASE16}"))],
            CHUNKED,
        ));
        contents.extend_from_slice(&render(
            &[
                ("WARC-Type", "request"),
                ("WARC-Target-URI", "<https://example.com/>"),
                ("Content-Type", "application/http; msgtype=request"),
                ("WARC-Payload-Digest", &format!("sha1:{ENTITY_BASE32}  ")),
            ],
            CHUNKED,
        ));

        let (summary, records) = rewritten(&contents);

        assert_eq!(summary.records, 3);
        assert_eq!(summary.rewritten, 3);
        assert_eq!(
            payload_digest(&records[0]),
            Some(format!(" sha1:{FRAMED_BASE32}").as_bytes())
        );
        assert_eq!(
            payload_digest(&records[1]),
            Some(format!(" SHA-1:{FRAMED_BASE16}").as_bytes())
        );
        assert_eq!(
            payload_digest(&records[2]),
            Some(format!(" sha1:{FRAMED_BASE32}  ").as_bytes())
        );
        assert!(
            records
                .iter()
                .all(|record| record.body == CHUNKED.as_bytes())
        );
    }

    #[test]
    fn keeps_a_digest_the_framed_body_already_has() {
        let contents = response(
            &[("WARC-Payload-Digest", &format!("sha1:{ENTITY_BASE32}"))],
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        );

        let (summary, records) = rewritten(&contents);

        assert_eq!(summary.rewritten, 0);
        assert_eq!(
            payload_digest(&records[0]),
            Some(format!(" sha1:{ENTITY_BASE32}").as_bytes())
        );
    }

    #[test]
    fn copies_records_without_an_http_message_payload() {
        let digest = format!("sha1:{ENTITY_BASE32}");
        let mut contents = render(
            &[
                ("WARC-Type", "revisit"),
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Payload-Digest", &digest),
            ],
            CHUNKED,
        );
        contents.extend_from_slice(&response(
            &[
                ("Content-Type", "application/octet-stream"),
                ("WARC-Payload-Digest", &digest),
            ],
            CHUNKED,
        ));
        contents.extend_from_slice(&render(
            &[
                ("WARC-Type", "response"),
                ("WARC-Target-URI", "dns:example.com"),
                ("WARC-Payload-Digest", &digest),
            ],
            CHUNKED,
        ));
        contents.extend_from_slice(&render(
            &[
                ("WARC-Type", "resource"),
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Payload-Digest", &digest),
            ],
            CHUNKED,
        ));
        contents.extend_from_slice(&response(&[], CHUNKED));

        let (summary, records) = rewritten(&contents);

        assert_eq!(summary.records, 5);
        assert_eq!(summary.rewritten, 0);
        for record in &records[..4] {
            assert_eq!(
                payload_digest(record),
                Some(format!(" {digest}").as_bytes())
            );
        }
        assert_eq!(payload_digest(&records[4]), None);
    }

    #[test]
    fn keeps_digests_it_cannot_recompute() {
        let digest = format!("sha1:{ENTITY_BASE32}");
        let mut contents = response(
            &[
                ("WARC-Segment-Number", "1"),
                ("WARC-Payload-Digest", &digest),
            ],
            CHUNKED,
        );
        contents.extend_from_slice(&response(
            &[
                ("WARC-Truncated", "length"),
                ("WARC-Payload-Digest", &digest),
            ],
            CHUNKED,
        ));
        contents.extend_from_slice(&response(
            &[("WARC-Payload-Digest", "sha1:not-a-digest")],
            CHUNKED,
        ));
        contents.extend_from_slice(&response(
            &[(
                "WARC-Payload-Digest",
                "unheard-of:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
            )],
            CHUNKED,
        ));
        contents.extend_from_slice(&response(
            &[(
                "WARC-Payload-Digest",
                "sha1 VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
            )],
            CHUNKED,
        ));
        contents.extend_from_slice(&response(
            &[("WARC-Payload-Digest", &digest)],
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
        ));

        let (summary, records) = rewritten(&contents);

        assert_eq!(summary.records, 6);
        assert_eq!(summary.rewritten, 0);
        assert_eq!(
            records
                .iter()
                .map(|record| payload_digest(record).unwrap())
                .collect::<Vec<_>>(),
            [
                format!(" {digest}").as_bytes(),
                format!(" {digest}").as_bytes(),
                b" sha1:not-a-digest",
                b" unheard-of:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
                b" sha1 VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
                format!(" {digest}").as_bytes(),
            ]
        );
    }

    #[test]
    fn leaves_an_archive_digested_that_way_unchanged() {
        let contents = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/data/warcio/example-iana.org-chunked.warc"
        ))
        .unwrap();

        let (summary, records) = rewritten(&contents);

        assert_eq!(summary.records, 3);
        assert_eq!(summary.rewritten, 0);
        assert_eq!(
            payload_digest(&records[1]),
            Some(b" sha1:b1f949b4920c773fd9c863479ae9a788b948c7ad".as_slice())
        );
    }
}
