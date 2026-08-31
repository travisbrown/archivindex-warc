//! Lint a WARC file against conventions stricter than the standard.
//!
//! [`Linter`] reads a file at the semantic level and checks every record that the standard accepts
//! against these rules:
//!
//! 1. Every record of a gzip file lies in a gzip member of its own, which is what lets a record be
//!    found and decompressed without reading the ones before it. A file read without its member
//!    framing, as an uncompressed file is, is not held to this rule.
//! 2. Nothing stands between one record and the next. A record ends with the two line endings that
//!    close it, so a blank line before a record, or at the end of the file, is padding that some
//!    writers emit and that concatenating files leaves behind.
//! 3. Header fields appear in canonical order. Standard fields precede extension fields; repeated
//!    and extension fields retain their relative order.
//! 4. No two records share a `WARC-Record-ID`, which clause 5.2 of the standard requires to be
//!    globally unique. Concatenating files record by record is what usually breaks this.
//! 5. Every record is dated no earlier than the record before it.
//! 6. Every record with a block carries a `Content-Type` fitting its type: `application/warc-fields`
//!    for `warcinfo` and `metadata`, `application/http;msgtype=request` for `request`, and
//!    `application/http;msgtype=response` for `response` and for a `revisit` with a block.
//!    A `continuation` record carries no `Content-Type`, as the standard says.
//! 7. Every record carries a `WARC-Block-Digest`.
//! 8. Every record with a payload the block determines carries a `WARC-Payload-Digest`. Those are
//!    `resource` and `conversion` records, and `request` and `response` records holding HTTP
//!    messages. A `revisit` record's payload lies elsewhere, and a `continuation` record's payload
//!    is digested in its first segment, so neither is held to this rule.
//! 9. Every `WARC-Block-Digest` is the digest of the block the record carries, and every
//!    `WARC-Payload-Digest` the digest of the payload its block determines. A digest under an
//!    algorithm this build does not compute is not checked, and neither is the payload digest of a
//!    segment or of a record that declares its block truncated.
//! 10. The first record is a `warcinfo` record.
//! 11. Every other record names, in `WARC-Warcinfo-ID`, the `warcinfo` record that most closely
//!     precedes it.
//! 12. Every `warcinfo` record names its collection in an `isPartOf` field, as a host, any number
//!     of path parts, and a timestamp of digits, all joined by `-`, and its `WARC-Filename` is that
//!     identifier followed by the extension of the file it is read from: `.warc.gz` for a gzip
//!     file, and `.warc` for one read as it stands. A path part such as `en` holds no `.`, which
//!     tells it from the host.
//! 13. Every `request` record's target URI has, as its host, exactly the host of the collection
//!     identifier named by the `warcinfo` record that most closely precedes it. A request that no
//!     well-formed collection identifier governs is not held to this rule.
//! 14. A capture is written as three consecutive records: a `request`, then the `response` (or the
//!     `revisit` standing in for it) naming the request alone in `WARC-Concurrent-To`, then a
//!     `metadata` record naming the response alone. The response and the metadata record repeat
//!     the request's `WARC-Target-URI`, and the metadata record's `application/warc-fields` body
//!     carries a `fetchTimeMs` field. A `metadata` record outside a capture is not held to these
//!     rules.
//! 15. No other record names one in `WARC-Concurrent-To`: not a `request`, not a `metadata`
//!     record outside a capture, and not a record of any other type. A `response` outside a
//!     capture is reported for that alone.
//! 16. Every `revisit` record under the identical payload digest profile that carries a block
//!     declares it as `WARC-Truncated: length`, which clause 6.7.2 of the standard asks of the
//!     writer.
//! 17. Every `revisit` record names the record it revisits in `WARC-Refers-To`,
//!     `WARC-Refers-To-Target-URI`, and `WARC-Refers-To-Date`.
//! 18. Every `revisit` record's `WARC-Refers-To` names a record that precedes it in the file. A
//!     file whose revisits are of records held elsewhere breaks this rule by design.
//!
//! The rules go from the shape of the file, through what each record's header and block hold, to
//! how records relate: to the `warcinfo` record governing them, within a capture, and to the
//! record a `revisit` stands for. A record's findings come in that order.
//!
//! Each rule a record breaks is one [`Finding`]. A record that breaks none is reported by its
//! identifier alone.
//!
//! A pass also runs any rule handed to [`Linter::with_rule`], which holds a file to conventions
//! this crate does not know: a project archiving one kind of site can check the shape its captures
//! take without a pass of its own. An added rule sees every record the pass reads, in order,
//! faults a record or the file as a whole, and reports as an error or a warning. What it reports
//! joins the same results.
//!
//! The rules live in one module per family under `rules`, in that order; what they report is in
//! `report`, and what an added rule reports through is in `rule`.

mod report;
mod rule;
mod rules;

#[cfg(test)]
mod fixtures;

use std::collections::{HashMap, VecDeque};
use std::io::BufRead;

use archivindex_warc::io::read::{self, UntypedIter, WarcReader};
use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::value::WarcDate;
use fluent_uri::Uri;
pub use report::{Checked, Custom, Finding, Severity, Subject, Violation};
pub use rule::{Findings, Rule};
use rules::capture::Pending;
use rules::framing::Framing;
use rules::header::canonical_order_violation;

/// An iterator over the findings of a lint pass.
///
/// Read errors come through as they are reported by the reader. A stream or framing error ends
/// iteration, as it does for the reader. A record the standard refuses is reported and skipped:
/// it takes a position in the file but is checked against no rule, and a capture waiting on it is
/// forgotten without a finding.
pub struct Linter<'a, R> {
    records: UntypedIter<R>,
    /// Whether the records are read from a gzip stream, which the file is named for.
    gzip: bool,
    /// The rules added to the pass, run after the rules this module defines.
    rules: Vec<Box<dyn Rule + 'a>>,
    /// The position of the next record read.
    index: usize,
    /// The position of the record the gzip member being read holds first.
    member_first: usize,
    /// The position and identifier of the record read last, if it read.
    last_record: Option<(usize, Uri<String>)>,
    /// Where each identifier the file has used was used first.
    record_ids: HashMap<Uri<String>, usize>,
    /// The position and date of the record read last, if one has.
    previous_date: Option<(usize, WarcDate)>,
    /// The identifier of the most recent `warcinfo` record.
    warcinfo_id: Option<Uri<String>>,
    /// The host of the collection identifier the most recent `warcinfo` record names, if it
    /// names a well-formed one.
    collection_host: Option<String>,
    /// The capture record expected next, if a capture is under way.
    pending: Option<Pending>,
    /// The preceding record, if it broke no rule and the record after it may still fault it.
    clean: Option<Uri<String>>,
    /// Results not yet yielded, since one record can produce several.
    queue: VecDeque<Checked>,
    /// A read error to yield once the results queued before it have been.
    deferred: Option<read::Error>,
    /// Whether the end of the file has been settled.
    finished: bool,
}

impl<'a, R: BufRead> Linter<'a, R> {
    /// Lint the WARC records `reader` reads.
    ///
    /// The gzip framing of the file is checked when the reader places its records, as one made
    /// by [`WarcReader::from_gzip`] does.
    pub fn new(reader: WarcReader<R>) -> Self {
        let records = reader.iter_untyped_records();

        Self {
            gzip: records.is_gzip(),
            records,
            rules: Vec::new(),
            index: 0,
            member_first: 0,
            last_record: None,
            record_ids: HashMap::new(),
            previous_date: None,
            warcinfo_id: None,
            collection_host: None,
            pending: None,
            clean: None,
            queue: VecDeque::new(),
            deferred: None,
            finished: false,
        }
    }

    /// Check every record against `rule` as well, after the rules this module defines.
    ///
    /// A rule added by mutable reference is borrowed for the life of the pass, so one that
    /// gathers a summary beside its findings can be read once the pass is done with.
    #[must_use]
    pub fn with_rule(mut self, rule: impl Rule + 'a) -> Self {
        self.rules.push(Box::new(rule));

        self
    }

    /// The number of records consumed so far, counting unreadable ones.
    ///
    /// After a read error is yielded, the unreadable record's index is one less than this.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.index
    }

    /// Check one record against every rule, in the order the rules are listed, and queue what it
    /// yields.
    fn check(&mut self, record: &Record, order_violation: Option<Violation>, framing: Framing) {
        let index = self.index;
        self.index += 1;

        let mark = self.queue.len();
        let expected = self.settle(record);
        // The preceding record is only clean once this one has failed to fault it.
        self.settle_clean(mark);

        let mark = self.queue.len();
        self.check_framing(index, record, framing);
        self.check_header(index, record, order_violation);
        self.check_block(index, record);
        self.check_digests(index, record);
        self.check_warcinfo(index, record);
        self.check_capture(index, record, expected);
        self.check_revisit(index, record);
        self.check_rules(index, record);
        self.last_record = Some((index, record.core().record_id.clone()));
        if self.queue.len() == mark {
            self.clean = Some(record.core().record_id.clone());
        }
    }

    /// Run the rules added to the pass over the record at `index`.
    fn check_rules(&mut self, index: usize, record: &Record) {
        for rule in &mut self.rules {
            rule.check(index, record, &mut Findings::new(&mut self.queue));
        }
    }

    /// Queue the held `Ok`, or drop it if a finding was queued past `mark`.
    fn settle_clean(&mut self, mark: usize) {
        if self.queue.len() == mark {
            self.release_clean();
        } else {
            self.clean = None;
        }
    }

    /// Queue the held `Ok`, now that nothing can fault the record it belongs to.
    fn release_clean(&mut self) {
        if let Some(record_id) = self.clean.take() {
            self.queue.push_back(Ok(record_id));
        }
    }

    /// Report a capture left waiting at the end of the file, and the blank lines it ends with.
    ///
    /// The iterator polls the records again once they run out, so this returns without reporting
    /// after the first call: an added rule may report in [`Rule::finish`] whenever it is asked.
    fn finish(&mut self) {
        if std::mem::replace(&mut self.finished, true) {
            return;
        }

        let mark = self.queue.len();
        self.finish_capture();
        self.finish_framing();
        self.settle_clean(mark);
        for rule in &mut self.rules {
            rule.finish(&mut Findings::new(&mut self.queue));
        }
    }

    /// Take a record that cannot be checked out of the file, keeping its position.
    ///
    /// The capture expectation it might have met is forgotten without a finding, so the record
    /// before it can no longer be faulted.
    fn skip(&mut self, error: read::Error) {
        for rule in &mut self.rules {
            rule.skip(self.index);
        }
        self.index += 1;
        self.pending = None;
        self.last_record = None;
        self.release_clean();
        self.deferred = Some(error);
    }

    /// Queue a finding against the record being checked.
    fn fault(&mut self, index: usize, record: &Record, violation: Violation) {
        self.report(index, &record.core().record_id, violation);
    }

    /// Queue a finding against a record by its position and identifier.
    fn report(&mut self, index: usize, record_id: &Uri<String>, violation: Violation) {
        self.queue.push_back(Err(Box::new(Finding {
            subject: Some(Subject {
                index,
                record_id: record_id.clone(),
            }),
            violation,
        })));
    }
}

impl<R: BufRead> Iterator for Linter<'_, R> {
    type Item = Result<Checked, read::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(checked) = self.queue.pop_front() {
                return Some(Ok(checked));
            }
            if let Some(error) = self.deferred.take() {
                return Some(Err(error));
            }

            let Some(located) = self.records.next() else {
                self.finish();
                if self.queue.is_empty() {
                    return None;
                }
                continue;
            };
            let framing = self.framing(&located);
            match located.value {
                Ok(untyped) => {
                    let order_violation = canonical_order_violation(&untyped.header);
                    match Record::<NoExtension>::try_from(untyped) {
                        Ok(record) => self.check(&record, order_violation, framing),
                        Err(error) => self.skip(error.into()),
                    }
                }
                Err(error) => self.skip(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn a_clean_capture_yields_every_record_id_in_order() {
        assert_eq!(
            lint(&capture()),
            [WARCINFO_ID, REQUEST_ID, RESPONSE_ID, METADATA_ID]
                .map(|id| Ok(uri(id)))
                .to_vec()
        );
    }

    /// A record is reported clean only once the record after it has failed to fault it.
    #[test]
    fn a_record_the_next_record_faults_yields_no_ok() {
        let records = [warcinfo(), request(), resource(OTHER_ID)];

        assert_eq!(
            lint(&records),
            [
                Ok(uri(WARCINFO_ID)),
                fault(
                    1,
                    REQUEST_ID,
                    Violation::RequestWithoutResponse {
                        found: Some("resource".to_owned()),
                    },
                ),
                Ok(uri(OTHER_ID)),
            ]
        );
    }

    /// A capture left waiting at the end of the file faults the record that opened it.
    #[test]
    fn a_record_the_end_of_the_file_faults_yields_no_ok() {
        let records = [warcinfo(), request()];

        assert_eq!(
            lint(&records),
            [
                Ok(uri(WARCINFO_ID)),
                fault(
                    1,
                    REQUEST_ID,
                    Violation::RequestWithoutResponse { found: None },
                ),
            ]
        );
    }

    #[test]
    fn an_unreadable_record_is_passed_through_and_forgets_the_capture() {
        let mut records = capture();
        records[2] = records[2].clone().set("WARC-Date", "yesterday");

        let items: Vec<_> = Linter::new(WarcReader::new(&render(&records)[..])).collect();

        assert_eq!(items.len(), 4);
        assert!(matches!(&items[0], Ok(Ok(id)) if id == &uri(WARCINFO_ID)));
        assert!(matches!(&items[1], Ok(Ok(id)) if id == &uri(REQUEST_ID)));
        assert!(matches!(items[2], Err(read::Error::Untyped(_))));
        // The metadata record is outside a capture now, so its link is out of place.
        assert!(matches!(
            &items[3],
            Ok(Err(finding))
                if finding.subject.as_ref().is_some_and(|subject| subject.index == 3)
                    && matches!(finding.violation, Violation::UnexpectedConcurrentTo { .. })
        ));
    }

    #[test]
    fn a_stream_error_ends_iteration() {
        let mut bytes = render(&capture());
        bytes.truncate(bytes.len() - 10);

        let items: Vec<_> = Linter::new(WarcReader::new(&bytes[..])).collect();

        assert_eq!(items.len(), 4);
        assert!(matches!(items[3], Err(read::Error::UnexpectedEndOfBody)));
    }

    /// A rule that faults every metadata record and reports how long the file was.
    #[derive(Default)]
    struct Counting {
        records: usize,
        skipped: Vec<usize>,
    }

    impl Rule for Counting {
        fn check(&mut self, index: usize, record: &Record, findings: &mut Findings<'_>) {
            self.records += 1;
            if matches!(record, Record::Metadata { .. }) {
                findings.fault(
                    index,
                    &record.core().record_id,
                    Custom::warning("metadata_record", "the record is a metadata record"),
                );
            }
        }

        fn finish(&mut self, findings: &mut Findings<'_>) {
            findings.fault_file(Custom::error(
                "record_count",
                format!("the file holds {} records", self.records),
            ));
        }

        fn skip(&mut self, index: usize) {
            self.skipped.push(index);
        }
    }

    /// An added rule faults a record the built-in rules pass, and reports against the file once
    /// every record has been read.
    #[test]
    fn an_added_rule_reports_beside_the_built_in_rules() {
        let mut rule = Counting::default();

        let checked: Vec<Checked> = Linter::new(WarcReader::new(&render(&capture())[..]))
            .with_rule(&mut rule)
            .collect::<Result<_, _>>()
            .expect("every record reads");

        assert_eq!(
            checked,
            [
                Ok(uri(WARCINFO_ID)),
                Ok(uri(REQUEST_ID)),
                Ok(uri(RESPONSE_ID)),
                fault(
                    3,
                    METADATA_ID,
                    Custom::warning("metadata_record", "the record is a metadata record").into(),
                ),
                Err(Box::new(Finding {
                    subject: None,
                    violation: Custom::error("record_count", "the file holds 4 records").into(),
                })),
            ]
        );
        assert_eq!(rule.records, 4);
        assert!(rule.skipped.is_empty());
    }

    /// The end of the file settles once, however often an exhausted pass is polled, so a rule
    /// reporting in `finish` reports there once rather than on every poll.
    #[test]
    fn an_added_rule_settles_the_end_of_the_file_once() {
        let bytes = render(&capture());
        let mut rule = Counting::default();
        let mut linter = Linter::new(WarcReader::new(&bytes[..])).with_rule(&mut rule);

        // Bounded, so a pass that reports forever fails here instead of running out of memory.
        let checked = linter.by_ref().take(64).count();

        assert_eq!(checked, 5);
        assert!(linter.next().is_none());
        assert!(linter.next().is_none());
    }

    /// A record the pass cannot read is checked against no added rule either.
    #[test]
    fn an_added_rule_is_told_of_a_record_that_cannot_be_read() {
        let mut records = capture();
        records[2] = records[2].clone().set("WARC-Date", "yesterday");
        let mut rule = Counting::default();

        let items: Vec<_> = Linter::new(WarcReader::new(&render(&records)[..]))
            .with_rule(&mut rule)
            .collect();

        // The two records that read, the read error, the finding against the metadata record,
        // and the added rule's findings against that record and against the file.
        assert_eq!(items.len(), 6);
        assert!(matches!(items[2], Err(read::Error::Untyped(_))));
        assert_eq!(rule.records, 3);
        assert_eq!(rule.skipped, [2]);
    }

    #[test]
    fn lints_a_real_archive() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/data/warcio/example-iana.org-chunked.warc"
        ))
        .expect("the fixture is present");

        let checked: Vec<Checked> = Linter::new(WarcReader::new(&bytes[..]))
            .collect::<Result<_, _>>()
            .expect("every record reads");

        assert!(checked.iter().all(Result::is_err));
        assert_eq!(
            checked
                .into_iter()
                .filter_map(Result::err)
                .map(|finding| {
                    let subject = finding.subject.expect("the finding is against a record");

                    (subject.index, finding.violation)
                })
                .collect::<Vec<_>>(),
            [
                (
                    0,
                    Violation::NonCanonicalHeaderOrder {
                        preceding: "WARC-Record-ID".to_owned(),
                        following: "WARC-Type".to_owned(),
                    }
                ),
                (0, Violation::MissingBlockDigest),
                (0, Violation::MissingCollectionId),
                (
                    1,
                    Violation::NonCanonicalHeaderOrder {
                        preceding: "WARC-Record-ID".to_owned(),
                        following: "WARC-Date".to_owned(),
                    }
                ),
                // The writer digested the message body as it was framed, where clause 5.9 has the
                // payload be the entity-body, which is that body dechunked.
                (
                    1,
                    Violation::PayloadDigestMismatch {
                        declared: labelled("sha1:b1f949b4920c773fd9c863479ae9a788b948c7ad"),
                        computed: labelled("sha1:RBDPEPHJIOR3OAEJ7BRUKYTHPDGZH4I6"),
                    }
                ),
                (1, Violation::MissingWarcinfoId),
                (1, Violation::ResponseWithoutRequest),
                (
                    2,
                    Violation::NonCanonicalHeaderOrder {
                        preceding: "WARC-Record-ID".to_owned(),
                        following: "WARC-Date".to_owned(),
                    }
                ),
                (2, Violation::MissingPayloadDigest),
                (2, Violation::MissingWarcinfoId),
                // The writer linked the request to its response, not the response to its request.
                (
                    2,
                    Violation::UnexpectedConcurrentTo {
                        found: vec![uri("urn:uuid:a96ae1a5-931d-4c45-96f3-98576d155f8b")]
                    }
                ),
                (2, Violation::RequestWithoutResponse { found: None }),
            ]
        );
    }
}
