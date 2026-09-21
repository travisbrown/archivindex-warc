use archivindex_test_support::warc::render;
use archivindex_warc_ops::file::open;

use super::*;

/// The derived identifier of the scheme's fixed test vector, which the archiver assigns to a
/// `response` record with this date, target URI, and content block.
const FIXED_VECTOR: &str = "https://archivindex.org/record/c70e0fa2a227bc36cbdb869f44904ad134ded72475c117ddf0e2e19fdc822bc7";

/// A record of the given type and identifier, with the given further fields.
fn record(record_type: &str, id: &str, fields: &[(&str, &str)], body: &str) -> Vec<u8> {
    let headers = [
        &[
            ("WARC-Type", record_type),
            ("WARC-Record-ID", id),
            ("WARC-Date", "2026-01-01T00:00:00Z"),
        ][..],
        fields,
    ]
    .concat();

    render(&headers, body)
}

/// The field names of a raw record's header, in order.
fn names(record: &raw::Record) -> Vec<&str> {
    record
        .header
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect()
}

/// A record's `WARC-Record-ID` as written.
fn id_of(record: &raw::Record) -> &str {
    std::str::from_utf8(record.header.get("WARC-Record-ID").unwrap()).unwrap()
}

/// The value of a record's field, as written.
fn field(record: &raw::Record, name: &str) -> String {
    String::from_utf8(record.header.get(name).unwrap().to_vec()).unwrap()
}

/// Read back the records of a file.
fn records(path: &Path) -> Vec<raw::Record> {
    open(path)
        .unwrap()
        .iter_raw_records()
        .records()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

/// Write `contents` as the input, reidentify it, and read back the records of both files.
fn reidentified(contents: &[u8]) -> Result<(Summary, Vec<raw::Record>, Vec<raw::Record>)> {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.warc");
    let output = directory.path().join("output.warc");
    std::fs::write(&input, contents).unwrap();

    let summary = record_ids(&input, &output)?;

    Ok((summary, records(&input), records(&output)))
}

/// The identifier a record receives is the one the scheme's own vector fixes, so a record read
/// from a file is identified exactly as the archiver identifies the record it wrote.
#[test]
fn derives_the_identifier_the_scheme_fixes() {
    let contents = render(
        &[
            ("WARC-Type", "response"),
            ("WARC-Record-ID", "<urn:uuid:1>"),
            ("WARC-Date", "1969-12-31T23:59:58.766Z"),
            ("WARC-Target-URI", "https://example.org/a%2Fb?q=1"),
        ],
        "abc",
    );

    let (summary, _, output) = reidentified(&contents).unwrap();

    assert_eq!(summary.reidentified, 1);
    assert_eq!(id_of(&output[0]), format!(" <{FIXED_VECTOR}>"));
}

/// A WARC 1.0 file brackets its target URI, which is not part of the URI the scheme hashes, so
/// the same capture written either way derives the same identifier.
#[test]
fn reads_a_bracketed_target_uri_as_the_uri_it_spells() {
    let contents = [
        b"WARC/1.0\r\nWARC-Type: response\r\nWARC-Record-ID: <urn:uuid:1>\r\n".to_vec(),
        b"WARC-Date: 1969-12-31T23:59:58Z\r\n".to_vec(),
        b"WARC-Target-URI: <https://example.org/a%2Fb?q=1>\r\nContent-Length: 3\r\n\r\n".to_vec(),
        b"abc\r\n\r\n".to_vec(),
    ]
    .concat();

    let (_, _, output) = reidentified(&contents).unwrap();

    // WARC 1.0 writes dates at second precision, so this is not the fixed vector's instant.
    assert!(id_of(&output[0]).starts_with(" <https://archivindex.org/record/"));
    assert_eq!(
        field(&output[0], "WARC-Target-URI"),
        " <https://example.org/a%2Fb?q=1>"
    );
}

/// Every reference to a reidentified record follows it to its new identifier, and a reference
/// to a record the file does not hold is left as read.
#[test]
fn redirects_every_reference_to_a_reidentified_record() {
    let contents = [
        record("warcinfo", "<urn:uuid:1>", &[], "software: test"),
        record(
            "request",
            "<urn:uuid:2>",
            &[
                ("WARC-Warcinfo-ID", "<urn:uuid:1>"),
                ("WARC-Target-URI", "https://example.org/"),
            ],
            "GET / HTTP/1.1\r\n\r\n",
        ),
        record(
            "response",
            "<urn:uuid:3>",
            &[
                ("WARC-Warcinfo-ID", "<urn:uuid:1>"),
                ("WARC-Concurrent-To", "urn:uuid:2"),
                ("WARC-Target-URI", "https://example.org/"),
            ],
            "HTTP/1.1 200 OK\r\n\r\nbody",
        ),
        record(
            "revisit",
            "<urn:uuid:4>",
            &[
                ("WARC-Refers-To", "<urn:uuid:3>"),
                ("WARC-Segment-Origin-ID", "<urn:uuid:9>"),
                ("WARC-Target-URI", "https://example.org/again"),
            ],
            "",
        ),
    ]
    .concat();

    let (summary, input, output) = reidentified(&contents).unwrap();

    assert_eq!(summary.records, 4);
    assert_eq!(summary.reidentified, 4);
    assert_eq!(summary.unidentifiable, 0);
    for record in &output {
        assert!(id_of(record).starts_with(" <https://archivindex.org/record/"));
    }
    assert_eq!(field(&output[1], "WARC-Warcinfo-ID"), id_of(&output[0]));
    assert_eq!(field(&output[2], "WARC-Warcinfo-ID"), id_of(&output[0]));
    assert_eq!(field(&output[2], "WARC-Concurrent-To"), id_of(&output[1]));
    assert_eq!(field(&output[3], "WARC-Refers-To"), id_of(&output[2]));
    // Nothing in the file is written with this identifier, so it is left as read.
    assert_eq!(field(&output[3], "WARC-Segment-Origin-ID"), " <urn:uuid:9>");
    // Only the identifier and the references change.
    for (read, written) in input.iter().zip(&output) {
        assert_eq!(names(read), names(written));
        assert_eq!(read.body, written.body);
        assert_eq!(field(read, "WARC-Date"), field(written, "WARC-Date"));
    }
}

/// Fields outside the hashed sequence do not identify a record, so two records differing only
/// in them derive the same identifier, which is a collision the operation refuses to write.
#[test]
fn refuses_records_with_different_identifiers_that_derive_the_same_one() {
    let contents = [
        record(
            "response",
            "<urn:uuid:1>",
            &[("WARC-Target-URI", "https://example.org/")],
            "HTTP/1.1 200 OK\r\n\r\nbody",
        ),
        record(
            "response",
            "<urn:uuid:2>",
            &[
                ("WARC-Target-URI", "https://example.org/"),
                ("WARC-Block-Digest", "sha1:AAAA"),
            ],
            "HTTP/1.1 200 OK\r\n\r\nbody",
        ),
    ]
    .concat();

    let error = reidentified(&contents).unwrap_err();

    assert!(
        matches!(&error, Error::CollidingRecordIds { id } if id.starts_with(
            "https://archivindex.org/record/"
        ))
    );
}

/// A reference to an identifier two records share names neither once they are told apart, so
/// the operation refuses rather than redirecting it to one of them.
#[test]
fn refuses_records_sharing_an_identifier_that_derive_different_ones() {
    let contents = [
        record(
            "response",
            "<urn:uuid:1>",
            &[("WARC-Target-URI", "https://example.org/")],
            "HTTP/1.1 200 OK\r\n\r\nfirst",
        ),
        record(
            "response",
            "<urn:uuid:1>",
            &[("WARC-Target-URI", "https://example.org/")],
            "HTTP/1.1 200 OK\r\n\r\nsecond",
        ),
    ]
    .concat();

    let error = reidentified(&contents).unwrap_err();

    assert!(matches!(&error, Error::RepeatedRecordId { id } if id == "urn:uuid:1"));
}

/// A retained ID must not be redirected to another record, whichever record is read first.
#[test]
fn refuses_a_shared_identifier_when_one_record_keeps_it() {
    let identified = record("resource", "<urn:uuid:1>", &[], "body");
    let retained = record("extension", "<urn:uuid:1>", &[], "body");

    for contents in [
        [identified.clone(), retained.clone()].concat(),
        [retained, identified].concat(),
    ] {
        assert!(matches!(
            reidentified(&contents).unwrap_err(),
            Error::RepeatedRecordId { id } if id == "urn:uuid:1"
        ));
    }
}

/// A new identifier must not collide with one a record the scheme cannot identify retains.
#[test]
fn refuses_a_derived_identifier_that_another_record_retains() {
    let identified = record("resource", "<urn:uuid:1>", &[], "body");
    let (_, _, output) = reidentified(&identified).unwrap();
    let retained = record("extension", id_of(&output[0]).trim(), &[], "body");

    for contents in [
        [identified.clone(), retained.clone()].concat(),
        [retained, identified].concat(),
    ] {
        assert!(matches!(
            reidentified(&contents).unwrap_err(),
            Error::CollidingRecordIds { .. }
        ));
    }
}

/// Two unnamed records have no shared input identity that would justify assigning one ID.
#[test]
fn refuses_colliding_records_without_identifiers() {
    let anonymous = render(
        &[
            ("WARC-Type", "resource"),
            ("WARC-Date", "2026-01-01T00:00:00Z"),
        ],
        "body",
    );

    assert!(matches!(
        reidentified(&anonymous.repeat(2)).unwrap_err(),
        Error::CollidingRecordIds { .. }
    ));
}

/// An unidentifiable record keeps its ID but still follows references to changed IDs.
#[test]
fn redirects_references_in_an_unidentifiable_record() {
    let contents = [
        record("resource", "<urn:uuid:1>", &[], "body"),
        record(
            "extension",
            "<urn:uuid:2>",
            &[("WARC-Refers-To", "<urn:uuid:1>")],
            "note",
        ),
    ]
    .concat();

    let (_, input, output) = reidentified(&contents).unwrap();

    assert_eq!(id_of(&input[1]), id_of(&output[1]));
    assert_eq!(field(&output[1], "WARC-Refers-To"), id_of(&output[0]));
}

/// Refusing an ambiguous output leaves an existing output and the input intact.
#[test]
fn collision_leaves_existing_files_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.warc");
    let output = directory.path().join("output.warc");
    let contents = [
        record("resource", "<urn:uuid:1>", &[], "body"),
        record("extension", "<urn:uuid:1>", &[], "body"),
    ]
    .concat();
    std::fs::write(&input, &contents).unwrap();
    std::fs::write(&output, b"previous output").unwrap();

    assert!(record_ids(&input, &output).is_err());
    assert_eq!(std::fs::read(&input).unwrap(), contents);
    assert_eq!(std::fs::read(&output).unwrap(), b"previous output");
    assert!(!directory.path().join("output.warc.partial").exists());
}

/// The standard requires every record to carry an identifier, so one that does not is given
/// the identifier its properties derive, in conventional header order.
#[test]
fn gives_a_record_without_an_identifier_one() {
    let contents = render(
        &[
            ("WARC-Type", "resource"),
            ("WARC-Target-URI", "https://example.org/"),
            ("WARC-Date", "2026-01-01T00:00:00Z"),
        ],
        "body",
    );

    let (summary, _, output) = reidentified(&contents).unwrap();

    assert_eq!(summary.reidentified, 1);
    assert_eq!(
        names(&output[0]),
        [
            "WARC-Type",
            "WARC-Target-URI",
            "WARC-Date",
            "WARC-Record-ID",
            "Content-Length"
        ]
    );
    assert!(id_of(&output[0]).starts_with(" <https://archivindex.org/record/"));
}

/// A record the scheme cannot identify keeps the identifier references already name, so the
/// file's relationships survive even where it cannot be reidentified.
#[test]
fn copies_a_record_it_cannot_identify_and_keeps_references_to_it() {
    let contents = [
        // The scheme gives every type it does not define the same type byte.
        record(
            "extension",
            "<urn:uuid:1>",
            &[("WARC-Target-URI", "https://example.org/")],
            "body",
        ),
        // A date outside the grammar cannot be read.
        render(
            &[
                ("WARC-Type", "resource"),
                ("WARC-Record-ID", "<urn:uuid:2>"),
                ("WARC-Date", "yesterday"),
            ],
            "body",
        ),
        // A target URI that is not a URI cannot be read.
        record(
            "resource",
            "<urn:uuid:3>",
            &[("WARC-Target-URI", "not a uri")],
            "body",
        ),
        record(
            "metadata",
            "<urn:uuid:4>",
            &[
                ("WARC-Refers-To", "<urn:uuid:1>"),
                ("WARC-Concurrent-To", "<urn:uuid:2>"),
                ("WARC-Target-URI", "https://example.org/"),
            ],
            "note: kept",
        ),
    ]
    .concat();

    let (summary, input, output) = reidentified(&contents).unwrap();

    assert_eq!(summary.records, 4);
    assert_eq!(summary.reidentified, 1);
    assert_eq!(summary.unidentifiable, 3);
    assert_eq!(output[..3], input[..3]);
    assert!(id_of(&output[3]).starts_with(" <https://archivindex.org/record/"));
    assert_eq!(field(&output[3], "WARC-Refers-To"), " <urn:uuid:1>");
    assert_eq!(field(&output[3], "WARC-Concurrent-To"), " <urn:uuid:2>");
}

/// Identifiers are determined by the records themselves, so reidentifying an already
/// reidentified file rewrites nothing.
#[test]
fn is_idempotent() {
    let contents = [
        record("warcinfo", "<urn:uuid:1>", &[], "software: test"),
        record(
            "response",
            "<urn:uuid:2>",
            &[
                ("WARC-Warcinfo-ID", "<urn:uuid:1>"),
                ("WARC-Target-URI", "https://example.org/"),
            ],
            "HTTP/1.1 200 OK\r\n\r\nbody",
        ),
    ]
    .concat();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.warc");
    let once = directory.path().join("once.warc");
    let twice = directory.path().join("twice.warc");
    std::fs::write(&input, &contents).unwrap();

    record_ids(&input, &once).unwrap();
    record_ids(&once, &twice).unwrap();

    assert_eq!(
        std::fs::read(&once).unwrap(),
        std::fs::read(&twice).unwrap()
    );
}

/// Standard input cannot serve both passes, so it is refused before either.
#[test]
fn refuses_standard_input() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("output.warc");

    let error = record_ids(Path::new("-"), &output).unwrap_err();

    assert!(matches!(
        error,
        Error::File(archivindex_warc_ops::Error::StandardInputReadTwice)
    ));
    assert!(!output.exists());
}

/// Forward references are resolved to final IDs without changing record order. Two records whose
/// bodies agree but whose originals differ must no longer collide.
#[test]
fn resolves_forward_references_before_deriving_dependent_ids() {
    let contents = [
        record(
            "metadata",
            "urn:uuid:meta1",
            &[("WARC-Refers-To", "urn:uuid:first")],
            "note",
        ),
        record(
            "metadata",
            "urn:uuid:meta2",
            &[("WARC-Refers-To", "urn:uuid:second")],
            "note",
        ),
        record(
            "response",
            "urn:uuid:first",
            &[("WARC-Concurrent-To", "urn:uuid:request")],
            "first",
        ),
        record(
            "response",
            "urn:uuid:second",
            &[("WARC-Concurrent-To", "urn:uuid:request")],
            "second",
        ),
        record(
            "request",
            "urn:uuid:request",
            &[("WARC-Warcinfo-ID", "urn:uuid:info")],
            "GET /",
        ),
        record("warcinfo", "urn:uuid:info", &[], "info"),
    ]
    .concat();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.warc");
    let once = directory.path().join("once.warc.gz");
    let twice = directory.path().join("twice.warc");
    std::fs::write(&input, contents).unwrap();
    record_ids(&input, &once).unwrap();
    record_ids(&once, &twice).unwrap();
    let output = records(&once);
    assert_eq!(output, records(&twice));
    assert_ne!(id_of(&output[0]), id_of(&output[1]));
    assert_eq!(field(&output[0], "WARC-Refers-To"), id_of(&output[2]));
    assert_eq!(field(&output[1], "WARC-Refers-To"), id_of(&output[3]));
    assert_eq!(field(&output[2], "WARC-Concurrent-To"), id_of(&output[4]));
    assert_eq!(field(&output[4], "WARC-Warcinfo-ID"), id_of(&output[5]));
    for record in output {
        assert_eq!(
            id_of(&record).trim(),
            format!("<{}>", Identity::from_raw(&record).unwrap().record_id())
        );
    }
}

/// Local source labels are only lookup keys; changing them must not change final identity.
#[test]
fn source_identifier_spelling_does_not_affect_final_ids() {
    let contents = |first: &str, second: &str| {
        [
            record("metadata", first, &[("WARC-Refers-To", second)], "note"),
            record("resource", second, &[], "body"),
        ]
        .concat()
    };
    let (_, _, left) = reidentified(&contents("urn:uuid:1", "urn:uuid:2")).unwrap();
    let (_, _, right) = reidentified(&contents("urn:uuid:3", "urn:uuid:4")).unwrap();
    assert_eq!(left, right);
}

/// Both the number and the origin distinguish segments holding the same bytes.
#[test]
fn distinguishes_segments_with_identical_blocks() {
    let contents = [
        record(
            "continuation",
            "urn:uuid:1",
            &[
                ("WARC-Segment-Number", "2"),
                ("WARC-Segment-Origin-ID", "urn:uuid:origin1"),
            ],
            "same",
        ),
        record(
            "continuation",
            "urn:uuid:2",
            &[
                ("WARC-Segment-Number", "3"),
                ("WARC-Segment-Origin-ID", "urn:uuid:origin1"),
            ],
            "same",
        ),
        record(
            "continuation",
            "urn:uuid:3",
            &[
                ("WARC-Segment-Number", "2"),
                ("WARC-Segment-Origin-ID", "urn:uuid:origin2"),
            ],
            "same",
        ),
    ]
    .concat();
    let (_, _, output) = reidentified(&contents).unwrap();
    for (index, record) in output.iter().enumerate() {
        assert!(
            output[..index]
                .iter()
                .all(|other| id_of(record) != id_of(other))
        );
    }
}

/// A cycle has no starting point for content-derived references. Refuse it before publication,
/// including a self-reference, rather than emitting IDs that change on the next run.
#[test]
fn refuses_reference_cycles_without_touching_output() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.warc");
    let output = directory.path().join("output.warc");
    for contents in [
        record(
            "metadata",
            "urn:uuid:1",
            &[("WARC-Refers-To", "urn:uuid:1")],
            "note",
        ),
        [
            record(
                "request",
                "urn:uuid:1",
                &[("WARC-Concurrent-To", "urn:uuid:2")],
                "request",
            ),
            record(
                "response",
                "urn:uuid:2",
                &[("WARC-Concurrent-To", "urn:uuid:1")],
                "response",
            ),
        ]
        .concat(),
    ] {
        std::fs::write(&input, &contents).unwrap();
        std::fs::write(&output, b"previous").unwrap();
        assert!(matches!(
            record_ids(&input, &output),
            Err(Error::CyclicReferences { .. })
        ));
        assert_eq!(std::fs::read(&input).unwrap(), contents);
        assert_eq!(std::fs::read(&output).unwrap(), b"previous");
        assert!(!directory.path().join("output.warc.partial").exists());
    }
}

/// References to records whose IDs are retained are fixed inputs to dependent identities, even
/// when those records point back. Repeated links must not prevent dependency resolution.
#[test]
fn retained_ids_are_fixed_reference_targets() {
    let contents = [
        record(
            "metadata",
            "urn:uuid:1",
            &[
                ("WARC-Refers-To", "urn:uuid:2"),
                ("WARC-Concurrent-To", "urn:uuid:2"),
                ("WARC-Concurrent-To", "urn:uuid:2"),
            ],
            "note",
        ),
        record(
            "extension",
            "urn:uuid:2",
            &[("WARC-Refers-To", "urn:uuid:1")],
            "body",
        ),
    ]
    .concat();
    let (_, _, output) = reidentified(&contents).unwrap();
    assert_eq!(id_of(&output[1]), " urn:uuid:2");
    assert_eq!(field(&output[1], "WARC-Refers-To"), id_of(&output[0]));
    assert_eq!(
        id_of(&output[0]).trim(),
        format!("<{}>", Identity::from_raw(&output[0]).unwrap().record_id())
    );
}
