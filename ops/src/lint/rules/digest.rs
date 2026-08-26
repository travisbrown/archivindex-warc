//! Rules 4, 5, and 11: the digests a record declares, and what they digest.

use std::io::BufRead;

use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::{BlockError, Record};

use super::block::has_http_target;
use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<R> {
    /// Check that a record declares the digests its block calls for, and that each is the digest
    /// of what it covers.
    ///
    /// Each digest is recomputed under the algorithm the record itself names. A digest this build
    /// cannot compute, and a payload digest the record layer does not check, yield nothing.
    pub(crate) fn check_digests(&mut self, index: usize, record: &Record) {
        let record_id = record.core().record_id.clone();

        if has_payload(record)
            && record
                .payload()
                .is_some_and(|payload| payload.payload_digest.is_none())
        {
            self.report(index, &record_id, Violation::MissingPayloadDigest);
        }
        if record.core().block_digest.is_none() {
            self.report(index, &record_id, Violation::MissingBlockDigest);
        }

        match record.incorrect_block_digest() {
            Some(BlockError::BlockDigestMismatch { declared, actual }) => self.report(
                index,
                &record_id,
                Violation::BlockDigestMismatch {
                    declared: *declared,
                    computed: *actual,
                },
            ),
            Some(BlockError::MalformedBlockDigest(found)) => self.report(
                index,
                &record_id,
                Violation::MalformedDigest {
                    field: Field::BlockDigest,
                    found: *found,
                },
            ),
            // The block digest check reports no other failure.
            Some(_) | None => {}
        }

        match record.incorrect_payload_digest() {
            Some(BlockError::PayloadDigestMismatch { declared, actual }) => self.report(
                index,
                &record_id,
                Violation::PayloadDigestMismatch {
                    declared: *declared,
                    computed: *actual,
                },
            ),
            Some(BlockError::MalformedPayloadDigest(found)) => self.report(
                index,
                &record_id,
                Violation::MalformedDigest {
                    field: Field::PayloadDigest,
                    found: *found,
                },
            ),
            Some(BlockError::Payload(error)) => self.report(
                index,
                &record_id,
                Violation::UnreadablePayload {
                    reason: error.to_string(),
                },
            ),
            // The payload digest check reports no other failure.
            Some(_) | None => {}
        }
    }
}

/// Whether a record's block determines its payload, as WARC 1.1 clause 5.9 defines it.
fn has_payload(record: &Record) -> bool {
    match record {
        Record::Resource { .. } | Record::Conversion { .. } => true,
        Record::Request { .. } | Record::Response { .. } => holds_http_message(record),
        Record::Warcinfo { .. }
        | Record::Metadata { .. }
        | Record::Revisit { .. }
        | Record::Continuation { .. }
        | Record::Other { .. } => false,
    }
}

/// Whether a record declares an HTTP message as its block.
///
/// The target URI must name HTTP or HTTPS, and the media type must be `application/http` or
/// absent, which is what the record layer accepts when extracting a payload.
fn holds_http_message(record: &Record) -> bool {
    has_http_target(record)
        && record
            .core()
            .content_type
            .as_ref()
            .is_none_or(|content_type| content_type.is("application", "http"))
}

#[cfg(test)]
mod tests {
    use archivindex_warc::value::{Algorithm, LabelledDigest};

    use super::*;
    use crate::lint::fixtures::*;

    /// The digest of the empty block, which no fixture carries.
    const EMPTY_DIGEST: &str = "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";

    #[test]
    fn records_with_payloads_carry_payload_digests() {
        let mut records = capture();
        records[2] = records[2].clone().without("WARC-Payload-Digest");
        records.push(resource(OTHER_ID).without("WARC-Payload-Digest"));
        records.push(
            TestRecord::new("revisit", &other_id(1), "")
                .with("WARC-Target-URI", TARGET)
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with(
                    "WARC-Profile",
                    "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
                ),
        );

        assert_eq!(
            findings(&records),
            [
                (2, Violation::MissingPayloadDigest),
                (4, Violation::MissingPayloadDigest),
                (5, Violation::ResponseWithoutRequest),
            ]
        );
    }

    #[test]
    fn a_request_for_a_non_http_target_has_no_payload() {
        let mut records = capture();
        for record in &mut records[1..] {
            *record = record
                .clone()
                .set("WARC-Target-URI", "ftp://example.com/")
                .without("WARC-Payload-Digest");
        }

        assert_eq!(findings(&records), []);
    }

    #[test]
    fn every_record_carries_a_block_digest() {
        let mut records = capture();
        records[0] = records[0].clone().without("WARC-Block-Digest");
        records[3] = records[3].clone().without("WARC-Block-Digest");

        assert_eq!(
            findings(&records),
            [
                (0, Violation::MissingBlockDigest),
                (3, Violation::MissingBlockDigest)
            ]
        );
    }

    #[test]
    fn a_declared_digest_is_the_digest_of_what_it_covers() {
        let mut records = capture();
        records[2] = records[2]
            .clone()
            .set("WARC-Block-Digest", EMPTY_DIGEST)
            .set("WARC-Payload-Digest", EMPTY_DIGEST);

        assert_eq!(
            findings(&records),
            [
                (
                    2,
                    Violation::BlockDigestMismatch {
                        declared: labelled(EMPTY_DIGEST),
                        computed: labelled(&digest(RESPONSE_BLOCK)),
                    }
                ),
                (
                    2,
                    Violation::PayloadDigestMismatch {
                        declared: labelled(EMPTY_DIGEST),
                        computed: labelled(&digest("hello")),
                    }
                ),
            ]
        );
    }

    /// A digest is checked under the algorithm the record itself names.
    #[test]
    fn a_digest_is_checked_under_the_algorithm_it_names() {
        let mut records = capture();
        records[2] = records[2].clone().set(
            "WARC-Block-Digest",
            &LabelledDigest::compute(Algorithm::Md5, RESPONSE_BLOCK.as_bytes())
                .expect("the md5 algorithm is enabled")
                .to_string(),
        );

        assert_eq!(findings(&records), []);
    }

    /// A value the algorithm cannot have produced is reported rather than compared.
    #[test]
    fn a_digest_the_algorithm_cannot_have_produced_is_reported() {
        let mut records = capture();
        records[2] = records[2].clone().set("WARC-Block-Digest", "sha1:AAAA");

        assert_eq!(
            findings(&records),
            [(
                2,
                Violation::MalformedDigest {
                    field: Field::BlockDigest,
                    found: labelled("sha1:AAAA"),
                }
            )]
        );
    }

    /// A payload digest declared over a block that is not the HTTP message it claims to be names
    /// nothing the linter can compute.
    #[test]
    fn a_payload_digest_over_an_unreadable_block_is_reported() {
        let mut records = capture();
        records[2].body = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".to_owned();

        assert_eq!(
            findings(&records),
            [(
                2,
                Violation::UnreadablePayload {
                    reason: "the HTTP message does not end its header section with an empty line"
                        .to_owned(),
                }
            )]
        );
    }
}
