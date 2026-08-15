// Each integration test binary compiles this module separately and uses only the helpers it
// needs, so items unused by one binary are still live in another.
#![allow(dead_code)]

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};

use archivindex_warc::{RawRecordHeader, WarcHeader, WarcReader, WarcWriter};
use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL, HEXLOWER};
use flate2::bufread::{GzDecoder, MultiGzDecoder};
use sha1::{Digest, Sha1};

pub type RawRecord = (RawRecordHeader, Vec<u8>);

/// Resolve the path of a fixture within one of the `tests/data` fixture sets.
fn fixture_path(set: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(set)
        .join(name)
}

/// Read a fixture into memory, decompressing it if it is gzip-compressed.
///
/// This is what the round-trip suites compare over: reading the bytes directly keeps a
/// crate's path constructors and gzip backend out of a comparison that is about WARC
/// handling.
pub fn fixture_bytes(set: &str, name: &str) -> Result<Vec<u8>, String> {
    let path = fixture_path(set, name);
    let mut source = BufReader::new(File::open(path).map_err(|error| error.to_string())?);
    let mut bytes = Vec::new();

    if name.ends_with(".gz") {
        MultiGzDecoder::new(source)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
    } else {
        source
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
    }

    Ok(bytes)
}

/// Read every raw record of an uncompressed archive and write them straight back out.
pub fn roundtrip(source: &[u8]) -> Result<Vec<u8>, String> {
    let mut writer = WarcWriter::new(Vec::new());
    for record in WarcReader::new(source).iter_raw_records() {
        let (headers, body) = record.map_err(|error| error.to_string())?;
        writer
            .write_raw(&headers, &body)
            .map_err(|error| error.to_string())?;
    }

    Ok(writer.into_inner())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestStatus {
    NoDigest,
    Passed,
    Failed,
}

#[derive(Clone, Copy)]
pub struct FixtureSet(&'static str);

impl FixtureSet {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    fn path(self, name: &str) -> PathBuf {
        fixture_path(self.0, name)
    }

    pub fn read(self, name: &str) -> Result<Vec<RawRecord>, String> {
        let path = self.path(name);
        if name.ends_with(".gz") || name.ends_with(".gz.bad") {
            collect_records(WarcReader::from_path_gzip(path).map_err(|error| error.to_string())?)
        } else {
            collect_records(WarcReader::from_path(path).map_err(|error| error.to_string())?)
        }
    }

    pub fn digest_statuses(self, name: &str) -> Vec<DigestStatus> {
        self.read(name)
            .unwrap_or_else(|error| panic!("failed to read {name}: {error}"))
            .iter()
            .map(digest_status)
            .collect()
    }

    pub fn validate_gzip_members(self, name: &str) -> Result<usize, String> {
        let mut source =
            BufReader::new(File::open(self.path(name)).map_err(|error| error.to_string())?);
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
}

fn collect_records<R: BufRead>(reader: WarcReader<R>) -> Result<Vec<RawRecord>, String> {
    reader
        .iter_raw_records()
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())
}

pub fn header<'a>(record: &'a RawRecord, name: &WarcHeader) -> Option<&'a str> {
    record
        .0
        .headers
        .get(name)
        .map(|value| std::str::from_utf8(value).unwrap())
}

pub fn record_types(records: &[RawRecord]) -> Vec<&str> {
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
    // Warcio treats revisit digests as references and does not validate them.
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
