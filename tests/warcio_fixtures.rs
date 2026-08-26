//! Fixture checks over the archives warcio's own tests exercise.

#![cfg(feature = "gzip")]

mod support;

use support::{DigestStatus, FixtureSet, record_types};

const FIXTURES: FixtureSet = FixtureSet::new("warcio");

// These record sequences come from warcio's TestArchiveIterator examples.
#[test]
fn valid_archives_have_the_expected_record_types() {
    for (name, expected) in [
        (
            "example.warc",
            &[
                "warcinfo", "warcinfo", "response", "request", "revisit", "request",
            ][..],
        ),
        (
            "example.warc.gz",
            &[
                "warcinfo", "warcinfo", "response", "request", "revisit", "request",
            ][..],
        ),
        (
            "example-iana.org-chunked.warc",
            &["warcinfo", "response", "request"][..],
        ),
        (
            "example-resource.warc.gz",
            &["warcinfo", "warcinfo", "resource"][..],
        ),
    ] {
        let records = FIXTURES
            .read(name)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(record_types(&records), expected, "{name}");
    }
}

// This ports warcio's valid digest-check example for the plain and gzip archives.
#[test]
fn valid_example_digests_pass() {
    let statuses: Vec<_> = ["example.warc", "example.warc.gz"]
        .into_iter()
        .flat_map(|name| FIXTURES.digest_statuses(name))
        .collect();

    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == DigestStatus::Passed)
            .count(),
        4
    );
    assert!(!statuses.contains(&DigestStatus::Failed));
}

// This ports warcio's deliberately invalid digest example, including RFC 3548 encodings.
#[test]
fn invalid_example_digest_is_detected() {
    let statuses = FIXTURES.digest_statuses("example-digest.warc");
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == DigestStatus::Passed)
            .count(),
        3
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == DigestStatus::Failed)
            .count(),
        1
    );
}

// This ports warcio's chunked HTTP digest-check example.
#[test]
fn valid_chunked_example_digests_pass() {
    let statuses = FIXTURES.digest_statuses("example-iana.org-chunked.warc");
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == DigestStatus::Passed)
            .count(),
        2
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == DigestStatus::NoDigest)
            .count(),
        1
    );
    assert!(!statuses.contains(&DigestStatus::Failed));
}

// This matches warcio's parameterized check over every other non-malformed WARC fixture.
#[test]
fn remaining_valid_examples_have_no_digest_failures() {
    for name in [
        "example-resource.warc.gz",
        "example-space-in-target-uri.warc.gz",
        "example-wget-bad-target-uri.warc.gz",
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

// Warcio requires each record in a compressed WARC to occupy one gzip member.
#[test]
fn valid_compressed_examples_have_one_record_per_gzip_member() {
    for (name, expected_members) in [
        ("example.warc.gz", 6),
        ("example-resource.warc.gz", 3),
        ("example-space-in-target-uri.warc.gz", 2),
        ("example-wget-bad-target-uri.warc.gz", 6),
        ("post-test.warc.gz", 6),
    ] {
        assert_eq!(
            FIXTURES.validate_gzip_members(name),
            Ok(expected_members),
            "{name}"
        );
    }
}

// These are the malformed compression examples rejected by warcio's iterator and CLI tests.
#[test]
fn malformed_compressed_examples_are_rejected() {
    for name in [
        "example-bad-non-chunked.warc.gz",
        "example-bad.warc.gz.bad",
        "example-wrong-chunks.warc.gz",
    ] {
        assert!(FIXTURES.validate_gzip_members(name).is_err(), "{name}");
    }
}

// Warcio reports one archive-iteration error for this deliberately truncated fixture.
#[test]
fn truncated_example_is_rejected() {
    assert!(FIXTURES.read("example-trunc.warc").is_err());
}
