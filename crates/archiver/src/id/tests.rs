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
    Identity::from_raw(record).unwrap().record_id()
}

/// Fixed vectors also check agreement with the typed adapter and the reidentify command.
#[test]
fn fixed_vectors() {
    assert_eq!(
        id(&record(
            "1969-12-31T23:59:58.766Z",
            &[("WARC-Target-URI", "https://example.org/a%2Fb?q=1")]
        ))
        .as_str(),
        "https://archivindex.org/record/c70e0fa2a227bc36cbdb869f44904ad134ded72475c117ddf0e2e19fdc822bc7"
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

/// The archiver records microseconds, including before the Unix epoch. Finer precision in input
/// files is deliberately truncated to that resolution, and date spelling is not identity.
#[test]
fn dates_use_archiver_precision() {
    for second in ["1969-12-31T23:59:59", "2026-01-01T00:00:00"] {
        let first = id(&record(&format!("{second}.123001Z"), &[]));
        assert_ne!(first, id(&record(&format!("{second}.123999Z"), &[])));
        assert_eq!(first, id(&record(&format!("{second}.123001999Z"), &[])));
        assert_eq!(first, id(&record(&format!("{second}.123001000Z"), &[])));
    }
    assert_eq!(
        id(&record("2026-01-01T00:00:00Z", &[])),
        id(&record("2026-01-01T00:00:00.000000Z", &[]))
    );
    for date in ["0000-01-01T00:00:00Z", "9999-12-31T23:59:59.999999Z"] {
        assert!(Identity::from_raw(&record(date, &[])).is_ok());
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
        ("WARC-Warcinfo-ID", "urn:uuid:1", "urn:uuid:2"),
        ("WARC-Concurrent-To", "urn:uuid:1", "urn:uuid:2"),
        ("WARC-Refers-To", "urn:uuid:1", "urn:uuid:2"),
        ("WARC-Segment-Origin-ID", "urn:uuid:1", "urn:uuid:2"),
        ("WARC-Segment-Number", "1", "2"),
        ("WARC-Segment-Total-Length", "12", "13"),
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

/// Header order, URI brackets, decimal padding, and concurrent-reference order are incidental.
/// Duplicate references still count, and all header values remain unchanged in stored records.
#[test]
fn normalizes_only_incidental_spelling() {
    let first = record(
        "2026-01-01T00:00:00Z",
        &[
            ("WARC-Concurrent-To", "urn:uuid:1"),
            ("WARC-Concurrent-To", "urn:uuid:2"),
            ("WARC-Segment-Number", "2"),
        ],
    );
    let second = record(
        "2026-01-01T00:00:00Z",
        &[
            ("warc-segment-number", "002"),
            ("warc-concurrent-to", "<urn:uuid:2>"),
            ("WARC-Concurrent-To", "<urn:uuid:1>"),
        ],
    );
    assert_eq!(id(&first), id(&second));
    let mut duplicate = first.clone();
    duplicate
        .header
        .headers
        .push(("WARC-Concurrent-To".to_owned(), b" urn:uuid:1".to_vec()));
    assert_ne!(id(&first), id(&duplicate));
}

/// The source record ID, packaging, and digest configuration do not identify a capture.
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
                ("X-Annotation", "one"),
            ]
        ))
    );
}

/// Malformed and repeated identity fields must not silently disappear from the preimage.
#[test]
fn rejects_unreadable_identity_fields() {
    for (field, value) in [
        ("WARC-Refers-To", "not a uri"),
        ("WARC-Segment-Number", "+2"),
        ("WARC-Segment-Number", "0"),
        ("WARC-Segment-Total-Length", "18446744073709551616"),
        ("WARC-Refers-To-Date", "yesterday"),
    ] {
        assert!(Identity::from_raw(&record("2026-01-01T00:00:00Z", &[(field, value)])).is_err());
    }
    assert!(matches!(
        Identity::from_raw(&record(
            "2026-01-01T00:00:00Z",
            &[
                ("WARC-Refers-To", "urn:uuid:1"),
                ("WARC-Refers-To", "urn:uuid:2"),
            ]
        )),
        Err(Error::RepeatedField(Field::RefersTo))
    ));
    assert!(matches!(
        Identity::from_raw(&raw(
            &[
                ("WARC-Type", "extension"),
                ("WARC-Date", "2026-01-01T00:00:00Z")
            ],
            ""
        )),
        Err(Error::UnknownRecordType(_))
    ));
}

/// Typed capture properties and their serialized representation must give the same ID.
#[test]
fn typed_and_raw_records_agree() {
    let date = WarcDate::from(DateTime::from_timestamp_micros(-1_234_001).unwrap());
    let records = [
        Record::response("https://example.org/", date)
            .unwrap()
            .warcinfo_id(Uri::parse("urn:uuid:info".to_owned()).unwrap())
            .concurrent_to(Uri::parse("urn:uuid:request".to_owned()).unwrap())
            .segment_origin()
            .body(b"abc".to_vec())
            .unwrap(),
        Record::continuation(
            "https://example.org/",
            date,
            2,
            Uri::parse("urn:uuid:origin".to_owned()).unwrap(),
        )
        .unwrap()
        .segment_total_length(6)
        .body(b"abc".to_vec())
        .unwrap(),
    ];
    for record in records {
        let typed = Identity::from_record(&record).unwrap().record_id();
        assert_eq!(typed, id(&record.into_raw().unwrap()));
    }
    assert_eq!(
        WarcDate::parse("2026-01-01T00:00:00Z", WarcVersion::V1_0),
        WarcDate::parse("2026-01-01T00:00:00Z", WarcVersion::V1_1)
    );
}

/// These vectors fix the context tags, numeric encodings, and sorted reference suffix. Expected
/// digests were computed independently with Python's hashlib and big-endian struct packing.
#[test]
fn context_fixed_vectors() {
    let revisit = raw(
        &[
            ("WARC-Type", "revisit"),
            ("WARC-Date", "1969-12-31T23:59:58.765999Z"),
            ("WARC-Target-URI", "https://example.org/"),
            ("WARC-Segment-Number", "1"),
            (
                "WARC-Profile",
                "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
            ),
            ("WARC-Refers-To-Target-URI", "https://example.org/original"),
            ("WARC-Refers-To-Date", "1970-01-01T00:00:00.000001Z"),
            ("WARC-Warcinfo-ID", "urn:uuid:info"),
            ("WARC-Concurrent-To", "urn:uuid:b"),
            ("WARC-Concurrent-To", "urn:uuid:a"),
            ("WARC-Refers-To", "urn:uuid:original"),
        ],
        "abc",
    );
    assert_eq!(
        id(&revisit).as_str(),
        "https://archivindex.org/record/74797072597e5581af529dafcce67039ad15a95f6c5a9b5ba493ad7f6fc87ff5"
    );
    let continuation = raw(
        &[
            ("WARC-Type", "continuation"),
            ("WARC-Date", "1969-12-31T23:59:58.765999Z"),
            ("WARC-Target-URI", "https://example.org/"),
            ("WARC-Segment-Number", "2"),
            ("WARC-Segment-Total-Length", "6"),
            ("WARC-Warcinfo-ID", "urn:uuid:info"),
            ("WARC-Segment-Origin-ID", "urn:uuid:origin"),
        ],
        "abc",
    );
    assert_eq!(
        id(&continuation).as_str(),
        "https://archivindex.org/record/ba96471768f0657d785b41feadbdad9b9994fc4dc5a4d96e448d8b4ce08dfefd"
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
