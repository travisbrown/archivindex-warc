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
    assert!(rule.skipped.is_empty(), "{:?}", rule.skipped);
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

    // The two records that read, the read error, the finding against the metadata record, and
    // the added rule's findings against that record and against the file.
    assert_eq!(items.len(), 6);
    assert!(matches!(items[2], Err(read::Error::Untyped(_))));
    assert_eq!(rule.records, 3);
    assert_eq!(rule.skipped, [2]);
}

#[test]
fn lints_a_real_archive() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/data/warcio/example-iana.org-chunked.warc"
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
