//! Rules 6 and 10: the `Content-Type` a record's block calls for, and the truncation a `revisit`
//! record's block is.

use std::io::BufRead;

use archivindex_warc::record::Record;
use archivindex_warc::record::header::RevisitProfile;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::value::MediaType;

use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<R> {
    /// Check that a `revisit` record declares the truncation its block is, and that a record with
    /// a block declares the `Content-Type` its type calls for.
    pub(crate) fn check_block(&mut self, index: usize, record: &Record) {
        let record_id = &record.core().record_id;

        if let Some(length) = undeclared_revisit_truncation(record) {
            self.report(
                index,
                record_id,
                Violation::UndeclaredRevisitTruncation { length },
            );
        }

        match &record.core().content_type {
            None => {
                if record.content_length() > 0 && !matches!(record, Record::Continuation { .. }) {
                    self.report(index, record_id, Violation::MissingContentType);
                }
            }
            Some(found) => {
                if let Some(expected) = expected_content_type(record)
                    && !fits(found, &expected)
                {
                    self.report(
                        index,
                        record_id,
                        Violation::WrongContentType {
                            expected,
                            found: found.clone(),
                        },
                    );
                }
            }
        }
    }
}

/// The length of a block a `revisit` record carries without declaring the truncation it is.
///
/// Clause 6.7.2 of the WARC 1.1 standard has a record under the identical payload digest profile
/// carry either no block or the beginning of the response it stands for, declared as
/// `WARC-Truncated: length`. No rule here applies to another profile.
fn undeclared_revisit_truncation(record: &Record) -> Option<u64> {
    let Record::Revisit { header, body } = record else {
        return None;
    };

    (!body.is_empty()
        && header.profile == RevisitProfile::IDENTICAL_PAYLOAD_DIGEST
        && !matches!(header.core.truncated, Some(TruncatedType::Length)))
    .then_some(body.len() as u64)
}

/// Whether a record captures an exchange in a protocol whose messages this crate reads.
pub fn has_http_target(record: &Record) -> bool {
    record.target_uri().is_some_and(|target_uri| {
        let scheme = target_uri.scheme().as_str();
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    })
}

/// The media type a record's type calls for, or `None` for a type this module does not constrain.
///
/// WARC 1.1 clause 5.6 contemplates captures of other protocols, whose block is a message of that
/// protocol rather than an HTTP one, so only a capture of an HTTP exchange is constrained.
fn expected_content_type(record: &Record) -> Option<MediaType> {
    match record {
        Record::Warcinfo { .. } | Record::Metadata { .. } => Some(MediaType::WARC_FIELDS),
        Record::Request { .. } => has_http_target(record).then_some(MediaType::HTTP_REQUEST),
        Record::Response { .. } | Record::Revisit { .. } => {
            has_http_target(record).then_some(MediaType::HTTP_RESPONSE)
        }
        Record::Resource { .. }
        | Record::Conversion { .. }
        | Record::Continuation { .. }
        | Record::Other { .. } => None,
    }
}

/// Whether a declared media type is the expected one.
///
/// Types and parameter values are compared without regard to case. Parameters beyond the expected
/// ones, such as a `charset`, are allowed.
fn fits(found: &MediaType, expected: &MediaType) -> bool {
    found.is(expected.type_name(), expected.subtype())
        && expected.parameters().all(|(name, value)| {
            found
                .parameter(name)
                .is_some_and(|declared| declared.as_str().eq_ignore_ascii_case(value.as_str()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    /// Clause 6.7.2 obliges the writer, so a record that omits the field is read and reported
    /// rather than refused.
    #[test]
    fn a_revisit_declares_the_truncation_its_block_is() {
        let mut records = capture();
        let mut later = copies(&capture()[1..], 1);
        later[1] = revisit_of(later[1].clone(), RESPONSE_ID).set("WARC-Truncated", "time");
        records.extend(later);

        assert_eq!(
            findings(&records),
            [(
                5,
                Violation::UndeclaredRevisitTruncation {
                    length: records[5].body.len() as u64
                }
            )]
        );
    }

    /// WARC 1.1 clause 5.6 contemplates a capture of another protocol, whose block is its own.
    #[test]
    fn a_capture_of_another_protocol_declares_its_own_media_type() {
        let mut records = capture();
        for record in &mut records[1..] {
            *record = record
                .clone()
                .set("WARC-Target-URI", "ftp://example.com/")
                .without("WARC-Payload-Digest");
        }
        for record in &mut records[1..3] {
            *record = record
                .clone()
                .set("Content-Type", "application/octet-stream");
        }

        assert_eq!(findings(&records), []);
    }

    #[test]
    fn a_record_with_a_block_carries_a_content_type() {
        let mut records = capture();
        records[2] = records[2].clone().without("Content-Type");
        records.push(
            TestRecord::new("continuation", OTHER_ID, "more")
                .with("WARC-Target-URI", TARGET)
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with("WARC-Segment-Number", "2")
                .with("WARC-Segment-Origin-ID", format!("<{RESPONSE_ID}>")),
        );
        records.push(
            TestRecord::new("revisit", &other_id(1), "")
                .with("WARC-Target-URI", TARGET)
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with("WARC-Payload-Digest", DIGEST)
                .with(
                    "WARC-Profile",
                    "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
                )
                .with("WARC-Refers-To", format!("<{RESPONSE_ID}>"))
                .with("WARC-Refers-To-Target-URI", TARGET)
                .with("WARC-Refers-To-Date", DATE),
        );

        assert_eq!(
            findings(&records),
            [
                (2, Violation::MissingContentType),
                (5, Violation::ResponseWithoutRequest),
            ]
        );
    }

    #[test]
    fn a_content_type_fits_the_record_type() {
        let mut records = capture();
        records[0] = records[0].clone().set("Content-Type", "text/plain");
        records[1] = records[1]
            .clone()
            .set("Content-Type", "application/http;msgtype=response");
        records[2] = records[2].clone().set(
            "Content-Type",
            "Application/HTTP; MsgType=Response; charset=utf-8",
        );
        records[3] = records[3].clone().set("Content-Type", "application/json");

        assert_eq!(
            findings(&records),
            [
                (0, Violation::MissingCollectionId),
                (
                    0,
                    Violation::WrongContentType {
                        expected: MediaType::WARC_FIELDS,
                        found: MediaType::TEXT_PLAIN
                    }
                ),
                (
                    1,
                    Violation::WrongContentType {
                        expected: MediaType::HTTP_REQUEST,
                        found: MediaType::HTTP_RESPONSE
                    }
                ),
                (
                    3,
                    Violation::WrongContentType {
                        expected: MediaType::WARC_FIELDS,
                        found: MediaType::JSON
                    }
                ),
                (3, Violation::MissingFetchTime),
            ]
        );
    }
}
