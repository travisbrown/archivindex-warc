#![cfg(feature = "gzip")]

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};

use archivindex_warc::{RawRecordHeader, WarcHeader, WarcReader};
use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL, HEXLOWER};
use flate2::bufread::GzDecoder;
use sha1::{Digest, Sha1};

type RawRecord = (RawRecordHeader, Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DigestStatus {
    NoDigest,
    Passed,
    Failed,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/warcio")
        .join(name)
}

fn collect_records<R: BufRead>(reader: WarcReader<R>) -> Result<Vec<RawRecord>, String> {
    reader
        .iter_raw_records()
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())
}

fn read_fixture(name: &str) -> Result<Vec<RawRecord>, String> {
    let path = fixture(name);
    if name.ends_with(".gz") || name.ends_with(".gz.bad") {
        collect_records(WarcReader::from_path_gzip(path).map_err(|error| error.to_string())?)
    } else {
        collect_records(WarcReader::from_path(path).map_err(|error| error.to_string())?)
    }
}

fn header<'a>(record: &'a RawRecord, name: &WarcHeader) -> Option<&'a str> {
    record
        .0
        .headers
        .get(name)
        .map(|value| std::str::from_utf8(value).unwrap())
}

fn record_types(records: &[RawRecord]) -> Vec<&str> {
    records
        .iter()
        .map(|record| header(record, &WarcHeader::WarcType).unwrap())
        .collect()
}

fn digest_matches(data: &[u8], expected: &str) -> bool {
    let Some((algorithm, expected)) = expected.split_once(':') else {
        return false;
    };
    if !algorithm.eq_ignore_ascii_case("sha1") {
        return false;
    }

    let digest = Sha1::digest(data);
    match expected.len().cmp(&32) {
        std::cmp::Ordering::Equal => BASE32_NOPAD.encode(&digest) == expected,
        std::cmp::Ordering::Greater => HEXLOWER.encode(&digest).eq_ignore_ascii_case(expected),
        std::cmp::Ordering::Less => {
            BASE64.encode(&digest) == expected || BASE64URL.encode(&digest) == expected
        }
    }
}

fn digest_status(record: &RawRecord) -> DigestStatus {
    // This matches warcio: revisit digests are present for reference only and are not checked.
    if header(record, &WarcHeader::WarcType) == Some("revisit") {
        return DigestStatus::NoDigest;
    }

    let block_digest = header(record, &WarcHeader::BlockDigest);
    let payload_digest = header(record, &WarcHeader::PayloadDigest);
    if block_digest.is_none() && payload_digest.is_none() {
        return DigestStatus::NoDigest;
    }

    let body = record.1.as_slice();
    let block_passed = block_digest.is_none_or(|expected| digest_matches(body, expected));
    let payload_passed = payload_digest.is_none_or(|expected| {
        let payload = if header(record, &WarcHeader::ContentType)
            .is_some_and(|value| value.starts_with("application/http"))
        {
            body.windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map_or(body, |index| &body[index + 4..])
        } else {
            body
        };
        digest_matches(payload, expected)
    });

    if block_passed && payload_passed {
        DigestStatus::Passed
    } else {
        DigestStatus::Failed
    }
}

fn digest_statuses(name: &str) -> Vec<DigestStatus> {
    read_fixture(name)
        .unwrap_or_else(|error| panic!("failed to read {name}: {error}"))
        .iter()
        .map(digest_status)
        .collect()
}

fn validate_gzip_members(name: &str) -> Result<usize, String> {
    let mut source = BufReader::new(File::open(fixture(name)).map_err(|error| error.to_string())?);
    let mut member_count = 0;

    while !source
        .fill_buf()
        .map_err(|error| error.to_string())?
        .is_empty()
    {
        let mut decoder = GzDecoder::new(source);
        let mut member = Vec::new();
        decoder
            .read_to_end(&mut member)
            .map_err(|error| error.to_string())?;
        source = decoder.into_inner();

        let records = collect_records(WarcReader::new(BufReader::new(Cursor::new(member))))?;
        if records.len() != 1 {
            return Err(format!(
                "gzip member {} contains {} WARC records",
                member_count + 1,
                records.len()
            ));
        }
        member_count += 1;
    }

    Ok(member_count)
}

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
        let records = read_fixture(name).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(record_types(&records), expected, "{name}");
    }
}

// This ports warcio's valid digest-check example for the plain and gzip archives.
#[test]
fn valid_example_digests_pass() {
    let statuses: Vec<_> = ["example.warc", "example.warc.gz"]
        .into_iter()
        .flat_map(digest_statuses)
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
    let statuses = digest_statuses("example-digest.warc");
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
    let statuses = digest_statuses("example-iana.org-chunked.warc");
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
            !digest_statuses(name).contains(&DigestStatus::Failed),
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
        assert_eq!(validate_gzip_members(name), Ok(expected_members), "{name}");
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
        assert!(validate_gzip_members(name).is_err(), "{name}");
    }
}

// Warcio reports one archive-iteration error for this deliberately truncated fixture.
#[test]
fn truncated_example_is_rejected() {
    assert!(read_fixture("example-trunc.warc").is_err());
}
