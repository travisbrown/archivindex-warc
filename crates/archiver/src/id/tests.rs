use archivindex_test_support::warc::render;
use archivindex_warc::version::WarcVersion;
use chrono::DateTime;

use super::*;

fn raw(fields: &[(&str, &str)], block: &str) -> raw::Record {
    let bytes = render(fields, block);
    archivindex_warc::io::read::WarcReader::new(std::io::Cursor::new(bytes))
        .iter_raw_records()
        .records()
        .next()
        .unwrap()
        .unwrap()
}

fn record(date: &str, fields: &[(&str, &str)]) -> raw::Record {
    raw(
        &[
            &[("WARC-Type", "response"), ("WARC-Date", date)][..],
            fields,
        ]
        .concat(),
        "abc",
    )
}

fn id(record: &raw::Record) -> Uri<String> {
    raw_record_id(record).unwrap()
}

/// Fixed vectors also check agreement with the typed adapter and the reidentify command.
#[test]
fn fixed_vectors() {
    assert_eq!(
        id(&record(
            "1970-01-01T00:00:01.234Z",
            &[("WARC-Target-URI", "https://example.org/a%2Fb?q=1")]
        ))
        .as_str(),
        "https://archivindex.org/record/9054bd499b56c7c96dfd5beb9ad3635490a65ac3e82bd32bf63846ed6dd43f98"
    );
    assert_eq!(
        id(&raw(
            &[
                ("WARC-Type", "warcinfo"),
                ("WARC-Date", "1970-01-01T00:00:00Z")
            ],
            ""
        ))
        .as_str(),
        "https://archivindex.org/record/1279f996e64d8d1678bf94a32349447c4685351027d9b62d29018b35809ed92f"
    );
}

/// The archiver records microseconds. Finer precision in input files is deliberately truncated to
/// that resolution, and date spelling is not identity.
#[test]
fn dates_use_archiver_precision() {
    for second in ["1970-01-01T00:00:00", "2026-01-01T00:00:00"] {
        let first = id(&record(&format!("{second}.123001Z"), &[]));
        assert_ne!(first, id(&record(&format!("{second}.123999Z"), &[])));
        assert_eq!(first, id(&record(&format!("{second}.123001999Z"), &[])));
        assert_eq!(first, id(&record(&format!("{second}.123001000Z"), &[])));
    }
    assert_eq!(
        id(&record("2026-01-01T00:00:00Z", &[])),
        id(&record("2026-01-01T00:00:00.000000Z", &[]))
    );
    for date in ["1970-01-01T00:00:00Z", "9999-12-31T23:59:59.999999Z"] {
        assert!(raw_record_id(&record(date, &[])).is_ok());
    }
}

/// Dates are unsigned Unix microseconds, since the archiver never writes a date before 1970.
#[test]
fn rejects_dates_before_1970() {
    for date in ["1969-12-31T23:59:59.999999Z", "0000-01-01T00:00:00Z"] {
        assert!(matches!(
            raw_record_id(&record(date, &[])),
            Err(Error::InvalidField(Field::Date))
        ));
        assert!(matches!(
            raw_record_id(&record(
                "2026-01-01T00:00:00Z",
                &[("WARC-Refers-To-Date", date)]
            )),
            Err(Error::InvalidField(Field::RefersToDate))
        ));
    }
}

/// Every included optional field distinguishes otherwise equal blocks. Changing a field's value
/// also changes identity; role tags prevent one reference kind being mistaken for another.
#[test]
fn context_fields_distinguish_records() {
    let base = id(&record("2026-01-01T00:00:00Z", &[]));
    let mut ids = vec![base];
    for (field, first, second) in [
        (
            "WARC-Target-URI",
            "https://example.org/a",
            "https://example.org/b",
        ),
        (
            "WARC-Profile",
            "https://example.org/a",
            "https://example.org/b",
        ),
        (
            "WARC-Refers-To-Target-URI",
            "https://example.org/a",
            "https://example.org/b",
        ),
        (
            "WARC-Refers-To-Date",
            "2026-01-01T00:00:00.123001Z",
            "2026-01-01T00:00:00.123002Z",
        ),
    ] {
        for value in [first, second] {
            let next = id(&record("2026-01-01T00:00:00Z", &[(field, value)]));
            assert!(!ids.contains(&next), "{field}: {value}");
            ids.push(next);
        }
    }
}

/// Header name case, header order, and URI brackets are incidental, and all header values remain
/// unchanged in stored records.
#[test]
fn normalizes_only_incidental_spelling() {
    let first = record(
        "2026-01-01T00:00:00Z",
        &[
            ("WARC-Refers-To-Target-URI", "https://example.org/original"),
            ("WARC-Target-URI", "https://example.org/"),
        ],
    );
    let second = record(
        "2026-01-01T00:00:00Z",
        &[
            ("warc-target-uri", "<https://example.org/>"),
            (
                "warc-refers-to-target-uri",
                "<https://example.org/original>",
            ),
        ],
    );
    assert_eq!(id(&first), id(&second));
}

/// The source record ID, packaging, and digest configuration do not identify a capture. Neither
/// do references to other records, so an ID never waits on another record's ID, and rewriting a
/// file under a new `warcinfo` record keeps its IDs.
#[test]
fn ignores_fields_outside_archivindex_identity() {
    assert_eq!(
        id(&record("2026-01-01T00:00:00Z", &[])),
        id(&record(
            "2026-01-01T00:00:00Z",
            &[
                ("WARC-Record-ID", "urn:uuid:1"),
                ("WARC-Filename", "another.warc"),
                ("WARC-Block-Digest", "sha1:AAAA"),
                ("WARC-Payload-Digest", "sha256:BBBB"),
                ("WARC-IP-Address", "127.0.0.1"),
                ("WARC-Warcinfo-ID", "urn:uuid:2"),
                ("WARC-Refers-To", "urn:uuid:5"),
                ("WARC-Concurrent-To", "urn:uuid:3"),
                ("WARC-Concurrent-To", "urn:uuid:4"),
                ("X-Annotation", "one"),
            ]
        ))
    );
}

/// Malformed and repeated identity fields must not silently disappear from the preimage.
#[test]
fn rejects_unreadable_identity_fields() {
    for (field, value) in [
        ("WARC-Target-URI", "not a uri"),
        ("WARC-Refers-To-Date", "yesterday"),
    ] {
        assert!(raw_record_id(&record("2026-01-01T00:00:00Z", &[(field, value)])).is_err());
    }
    assert!(matches!(
        raw_record_id(&record(
            "2026-01-01T00:00:00Z",
            &[
                ("WARC-Target-URI", "https://example.org/a"),
                ("WARC-Target-URI", "https://example.org/b"),
            ]
        )),
        Err(Error::RepeatedField(Field::TargetURI))
    ));
    for record_type in ["resource", "conversion", "continuation", "extension"] {
        assert!(matches!(
            raw_record_id(&raw(
                &[
                    ("WARC-Type", record_type),
                    ("WARC-Date", "2026-01-01T00:00:00Z")
                ],
                ""
            )),
            Err(Error::UnsupportedRecordType(_))
        ));
    }
}

/// Segmented records are not identified, so any segment field refuses the record, including the
/// segment number that marks the first segment of a record.
#[test]
fn rejects_segmented_records() {
    for (field, name, value) in [
        (Field::SegmentNumber, "WARC-Segment-Number", "1"),
        (
            Field::SegmentOriginID,
            "WARC-Segment-Origin-ID",
            "urn:uuid:1",
        ),
        (Field::SegmentTotalLength, "warc-segment-total-length", "3"),
    ] {
        assert!(matches!(
            raw_record_id(&record("2026-01-01T00:00:00Z", &[(name, value)])),
            Err(Error::Segmented(found)) if found == field
        ));
    }
    let date = WarcDate::from(DateTime::UNIX_EPOCH);
    let record = Record::response("https://example.org/", date)
        .unwrap()
        .segment_origin()
        .body(b"abc".to_vec())
        .unwrap();
    assert!(matches!(
        record_id(&record),
        Err(Error::Segmented(Field::SegmentNumber))
    ));
}

/// Typed capture properties and their serialized representation must give the same ID.
#[test]
fn typed_and_raw_records_agree() {
    let date = WarcDate::from(DateTime::from_timestamp_micros(1_234_001).unwrap());
    let record = Record::response("https://example.org/", date)
        .unwrap()
        .warcinfo_id(Uri::parse("urn:uuid:info".to_owned()).unwrap())
        .concurrent_to(Uri::parse("urn:uuid:request".to_owned()).unwrap())
        .body(b"abc".to_vec())
        .unwrap();
    let typed = record_id(&record).unwrap();
    assert_eq!(typed, id(&record.into_raw().unwrap()));
    assert_eq!(
        WarcDate::parse("2026-01-01T00:00:00Z", WarcVersion::V1_0),
        WarcDate::parse("2026-01-01T00:00:00Z", WarcVersion::V1_1)
    );
}

/// This vector fixes the context tags, numeric encodings, and reference suffix. The expected
/// digest was computed independently with Python's hashlib and big-endian struct packing.
#[test]
fn context_fixed_vector() {
    let revisit = raw(
        &[
            ("WARC-Type", "revisit"),
            ("WARC-Date", "1970-01-01T00:00:01.234001Z"),
            ("WARC-Target-URI", "https://example.org/"),
            (
                "WARC-Profile",
                "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
            ),
            ("WARC-Refers-To-Target-URI", "https://example.org/original"),
            ("WARC-Refers-To-Date", "1970-01-01T00:00:00.000001Z"),
            ("WARC-Refers-To", "urn:uuid:original"),
        ],
        "abc",
    );
    assert_eq!(
        id(&revisit).as_str(),
        "https://archivindex.org/record/4602eb3148722334faa2aad12bc9b5f51dc21c1eeaaa08eaad0ab4c1eec392cf"
    );
}

/// Type and stored block remain identity inputs even when the contextual fields are identical.
#[test]
fn type_and_block_distinguish_records() {
    let original = record("2026-01-01T00:00:00Z", &[]);
    let mut changed = original.clone();
    changed.body.push(b'!');
    assert_ne!(id(&original), id(&changed));
    let mut changed = original.clone();
    changed
        .header
        .headers
        .iter_mut()
        .find(|(name, _)| name == "WARC-Type")
        .unwrap()
        .1 = b" request".to_vec();
    assert_ne!(id(&original), id(&changed));
}
