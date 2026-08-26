//! Fixture checks over the archives pywb's indexing tests exercise.

#![cfg(feature = "gzip")]

mod support;

use support::{DigestStatus, FixtureSet, header, record_types};

const FIXTURES: FixtureSet = FixtureSet::new("pywb");

// These sequences mirror the archive kinds exercised by pywb's indexing tests.
#[test]
fn valid_archives_have_the_expected_record_types() {
    for (name, expected) in [
        (
            "example.warc.gz",
            &[
                "warcinfo", "response", "request", "revisit", "request", "response",
            ][..],
        ),
        (
            "example-wget-1-14.warc.gz",
            &[
                "warcinfo", "request", "response", "resource", "resource", "resource",
            ][..],
        ),
        (
            "example-wpull.warc.gz",
            &["warcinfo", "request", "response", "resource"][..],
        ),
        (
            "post-test.warc.gz",
            &[
                "response", "request", "response", "request", "response", "request",
            ][..],
        ),
        ("example2.warc.gz", &["warcinfo", "response", "request"][..]),
        ("httpbin-resource.warc.gz", &["resource"][..]),
    ] {
        let records = FIXTURES
            .read(name)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(record_types(&records), expected, "{name}");
    }
}

// Pywb's indexing and resource-loading tests assert these values from example.warc.gz.
#[test]
fn indexed_headers_and_payload_match_pywb_expectations() {
    let records = FIXTURES.read("example.warc.gz").unwrap();
    let response = &records[1];
    assert_eq!(
        header(response, "WARC-Target-URI"),
        Some("http://example.com?example=1")
    );
    assert_eq!(header(response, "WARC-Date"), Some("2014-01-03T03:03:21Z"));
    assert_eq!(
        header(response, "WARC-Payload-Digest"),
        Some("sha1:B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A")
    );
    assert!(
        response
            .body
            .windows(b"Example Domain".len())
            .any(|window| window == b"Example Domain")
    );

    let revisit = &records[3];
    assert_eq!(
        header(revisit, "WARC-Target-URI"),
        Some("http://example.com?example=1")
    );
    assert_eq!(header(revisit, "WARC-Date"), Some("2014-01-03T03:03:41Z"));

    let iana_response = &records[5];
    assert_eq!(
        header(iana_response, "WARC-Target-URI"),
        Some("http://www.iana.org/domains/example")
    );
    assert_eq!(
        header(iana_response, "WARC-Payload-Digest"),
        Some("sha1:JZ622UA23G5ZU6Y3XAKH4LINONUEICEG")
    );
}

// This covers pywb's larger duplicate and IANA indexing samples without embedding CDX output.
#[test]
fn large_archives_have_the_expected_shape() {
    let duplicate_records = FIXTURES.read("dupes.warc.gz").unwrap();
    let duplicate_types = record_types(&duplicate_records);
    assert_eq!(duplicate_types.len(), 25);
    assert_eq!(
        duplicate_types
            .iter()
            .filter(|&&kind| kind == "warcinfo")
            .count(),
        1
    );
    assert_eq!(
        duplicate_types
            .iter()
            .filter(|&&kind| kind == "response")
            .count(),
        3
    );
    assert_eq!(
        duplicate_types
            .iter()
            .filter(|&&kind| kind == "request")
            .count(),
        12
    );
    assert_eq!(
        duplicate_types
            .iter()
            .filter(|&&kind| kind == "revisit")
            .count(),
        9
    );

    let iana_records = FIXTURES.read("iana.warc.gz").unwrap();
    assert_eq!(iana_records.len(), 343);
    assert_eq!(header(&iana_records[0], "WARC-Type"), Some("warcinfo"));
}

// Pywb indexes these as valid samples; all declared SHA-1 digests must verify here as well.
#[test]
fn valid_examples_have_no_digest_failures() {
    for name in [
        "dupes.warc.gz",
        "example-wget-1-14.warc.gz",
        "example-wpull.warc.gz",
        "example.warc.gz",
        "example2.warc.gz",
        "httpbin-resource.warc.gz",
        "iana.warc.gz",
        "post-test.warc.gz",
    ] {
        assert!(
            !FIXTURES
                .digest_statuses(name)
                .contains(&DigestStatus::Failed),
            "{name}"
        );
    }
}

// The valid compressed samples use the independently compressed record convention.
#[test]
fn valid_compressed_examples_have_one_record_per_gzip_member() {
    for (name, expected_members) in [
        ("dupes.warc.gz", 25),
        ("example-wget-1-14.warc.gz", 6),
        ("example-wpull.warc.gz", 4),
        ("example.warc.gz", 6),
        ("example2.warc.gz", 3),
        ("httpbin-resource.warc.gz", 1),
        ("iana.warc.gz", 343),
        ("post-test.warc.gz", 6),
    ] {
        assert_eq!(
            FIXTURES.validate_gzip_members(name),
            Ok(expected_members),
            "{name}"
        );
    }
}

// Pywb rejects this deliberately non-chunked compressed archive when validation is enabled.
#[test]
fn malformed_compressed_example_is_rejected() {
    assert!(
        FIXTURES
            .validate_gzip_members("example-bad.warc.gz.bad")
            .is_err()
    );
}

// Pywb uses or tolerates these examples to test lenient HTTP and WARC handling. This crate
// intentionally enforces strict WARC record framing and reports their structural defects.
#[test]
fn nonconforming_examples_report_framing_errors() {
    for (name, expected_error) in [
        ("example-extra.warc", "Malformed record terminator."),
        (
            "example-url-agnostic-orig.warc.gz",
            "Malformed record terminator.",
        ),
        (
            "example-url-agnostic-revisit.warc.gz",
            "Malformed record terminator.",
        ),
        ("example.warc", "Malformed record terminator."),
        (
            "missing-status-text.warc",
            "Unexpected end of header block.",
        ),
    ] {
        assert_eq!(FIXTURES.read(name).unwrap_err(), expected_error, "{name}");
    }
}
