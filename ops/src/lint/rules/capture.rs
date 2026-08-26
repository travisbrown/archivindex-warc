//! Rule 7: a capture is a `request`, its `response` or `revisit`, and its `metadata` record, in
//! that order, each naming the one before it and repeating the request's target.

use std::io::BufRead;

use archivindex_warc::record::fields::metadata::MetadataField;
use archivindex_warc::record::{FieldsBlock, Record};
use fluent_uri::Uri;

use crate::lint::{Linter, Violation};

/// The record a capture's next record must name and agree with.
#[derive(Debug)]
pub struct Pending {
    /// The kind of record expected next.
    slot: Slot,
    /// The position of the record that set the expectation.
    index: usize,
    /// The identifier the next record must name in `WARC-Concurrent-To`.
    record_id: Uri<String>,
    /// The request's target URI, which the next record must repeat.
    target_uri: Uri<String>,
}

/// The record a capture expects next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    /// A `response` or `revisit` record following a `request`.
    Response,
    /// A `metadata` record following a `response` or `revisit`.
    Metadata,
}

impl<R: BufRead> Linter<R> {
    /// Resolve a waiting capture expectation against the record just read.
    ///
    /// Returns the expectation when this record is the kind it waited for. Otherwise the record
    /// that set the expectation gets a finding, and the expectation is dropped.
    pub(crate) fn settle(&mut self, record: &Record) -> Option<Pending> {
        let pending = self.pending.take()?;
        let met = match pending.slot {
            Slot::Response => is_response_slot(record),
            Slot::Metadata => matches!(record, Record::Metadata { .. }),
        };
        if met {
            return Some(pending);
        }

        let found = Some(record.type_name().to_owned());
        let violation = match pending.slot {
            Slot::Response => Violation::RequestWithoutResponse { found },
            Slot::Metadata => Violation::ResponseWithoutMetadata { found },
        };
        self.report(pending.index, &pending.record_id, violation);

        None
    }

    /// Check the capture sequence rule and set the expectation for the next record.
    pub(crate) fn check_capture(
        &mut self,
        index: usize,
        record: &Record,
        expected: Option<Pending>,
    ) {
        let record_id = &record.core().record_id;

        match record {
            Record::Request { header, .. } => {
                self.pending = Some(Pending {
                    slot: Slot::Response,
                    index,
                    record_id: record_id.clone(),
                    target_uri: header.target_uri.clone(),
                });
            }
            Record::Response { .. } | Record::Revisit { .. } => match expected {
                Some(pending) => {
                    self.check_links(index, record, &pending);
                    self.pending = Some(Pending {
                        slot: Slot::Metadata,
                        index,
                        record_id: record_id.clone(),
                        target_uri: pending.target_uri,
                    });
                }
                None => self.report(index, record_id, Violation::ResponseWithoutRequest),
            },
            Record::Metadata { body, .. } => {
                if let Some(pending) = expected {
                    self.check_links(index, record, &pending);
                    let has_fetch_time = match body {
                        FieldsBlock::Fields(fields) => {
                            fields.get(&MetadataField::FetchTimeMs).is_some()
                        }
                        FieldsBlock::Raw(_) => false,
                    };
                    if !has_fetch_time {
                        self.report(index, record_id, Violation::MissingFetchTime);
                    }
                }
            }
            Record::Warcinfo { .. }
            | Record::Resource { .. }
            | Record::Conversion { .. }
            | Record::Continuation { .. }
            | Record::Other { .. } => {}
        }
    }

    /// Check that a capture record names the record before it and repeats the request's target.
    fn check_links(&mut self, index: usize, record: &Record, pending: &Pending) {
        let record_id = &record.core().record_id;

        if record.concurrent_to() != std::slice::from_ref(&pending.record_id) {
            self.report(
                index,
                record_id,
                Violation::WrongConcurrentTo {
                    expected: pending.record_id.clone(),
                    found: record.concurrent_to().to_vec(),
                },
            );
        }

        if record.target_uri() != Some(&pending.target_uri) {
            self.report(
                index,
                record_id,
                Violation::WrongTargetUri {
                    expected: pending.target_uri.clone(),
                    found: record.target_uri().cloned(),
                },
            );
        }
    }

    /// Report a capture left waiting at the end of the file.
    pub(crate) fn finish_capture(&mut self) {
        if let Some(pending) = self.pending.take() {
            let violation = match pending.slot {
                Slot::Response => Violation::RequestWithoutResponse { found: None },
                Slot::Metadata => Violation::ResponseWithoutMetadata { found: None },
            };
            self.report(pending.index, &pending.record_id, violation);
        }
    }
}

/// Whether a record can stand in the response position of a capture.
const fn is_response_slot(record: &Record) -> bool {
    matches!(record, Record::Response { .. } | Record::Revisit { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    #[test]
    fn a_revisit_stands_in_for_the_response() {
        let mut records = capture();
        records[2] = records[2]
            .clone()
            .set("WARC-Type", "revisit")
            .with(
                "WARC-Profile",
                "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
            )
            .with("WARC-Truncated", "length");

        assert_eq!(findings(&records), []);
    }

    #[test]
    fn a_request_is_followed_by_its_response() {
        let mut records = capture();
        records.remove(2);

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::RequestWithoutResponse {
                    found: Some("metadata".to_owned())
                }
            )]
        );

        let records = capture()[..2].to_vec();

        assert_eq!(
            findings(&records),
            [(1, Violation::RequestWithoutResponse { found: None })]
        );
    }

    #[test]
    fn a_response_follows_a_request() {
        let mut records = capture();
        records.remove(1);

        assert_eq!(findings(&records), [(1, Violation::ResponseWithoutRequest)]);
    }

    #[test]
    fn a_response_is_followed_by_its_metadata_record() {
        let mut records = capture();
        records[3] = resource(OTHER_ID);

        assert_eq!(
            findings(&records),
            [(
                2,
                Violation::ResponseWithoutMetadata {
                    found: Some("resource".to_owned())
                }
            )]
        );

        let records = capture()[..3].to_vec();

        assert_eq!(
            findings(&records),
            [(2, Violation::ResponseWithoutMetadata { found: None })]
        );
    }

    #[test]
    fn a_second_request_breaks_the_capture_before_it() {
        let mut records = capture();
        records.insert(2, copies(&[request()], 1).remove(0));
        // The response names the request it follows, which is now the second one.
        records[3] = records[3]
            .clone()
            .set("WARC-Concurrent-To", &format!("<{REQUEST_ID}-1>"));

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::RequestWithoutResponse {
                    found: Some("request".to_owned())
                }
            )]
        );
    }

    #[test]
    fn capture_records_name_the_record_before_them_alone() {
        let mut records = capture();
        records[2] = records[2].clone().without("WARC-Concurrent-To");
        records[3] = records[3]
            .clone()
            .with("WARC-Concurrent-To", format!("<{REQUEST_ID}>"));

        assert_eq!(
            findings(&records),
            [
                (
                    2,
                    Violation::WrongConcurrentTo {
                        expected: uri(REQUEST_ID),
                        found: vec![]
                    }
                ),
                (
                    3,
                    Violation::WrongConcurrentTo {
                        expected: uri(RESPONSE_ID),
                        found: vec![uri(RESPONSE_ID), uri(REQUEST_ID)]
                    }
                ),
            ]
        );
    }

    #[test]
    fn capture_records_repeat_the_request_target() {
        let mut records = capture();
        records[2] = records[2]
            .clone()
            .set("WARC-Target-URI", "https://example.com/other");
        records[3] = records[3].clone().without("WARC-Target-URI");

        assert_eq!(
            findings(&records),
            [
                (
                    2,
                    Violation::WrongTargetUri {
                        expected: uri(TARGET),
                        found: Some(uri("https://example.com/other"))
                    }
                ),
                (
                    3,
                    Violation::WrongTargetUri {
                        expected: uri(TARGET),
                        found: None
                    }
                ),
            ]
        );
    }

    #[test]
    fn capture_metadata_carries_a_fetch_time() {
        let mut records = capture();
        records[3].body = "via: https://example.com/\r\n".to_owned();

        assert_eq!(findings(&records), [(3, Violation::MissingFetchTime)]);
    }

    #[test]
    fn metadata_outside_a_capture_is_unconstrained() {
        let mut records = capture();
        records.push(
            TestRecord::new("metadata", OTHER_ID, "via: https://example.com/\r\n")
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with("WARC-Refers-To", format!("<{RESPONSE_ID}>"))
                .with("Content-Type", "application/warc-fields"),
        );

        assert_eq!(findings(&records), []);
    }
}
