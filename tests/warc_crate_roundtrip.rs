//! Cross-implementation comparison against the `warc` crate, version 0.4.0, from which this
//! crate is derived.
//!
//! Every valid pywb and warcio fixture is round-tripped (read every record, write every
//! record back out) through both implementations, and the two outputs are required to encode
//! the same records up to the order and case of the header names. Upstream keeps a record's
//! header block in a `HashMap`, so it emits header lines in hash order while this crate
//! preserves their order of appearance; that difference is what the tolerance covers.
//! Everything else — the record count, the WARC version, every header name and value, and
//! every body byte — has to match exactly.
//!
//! Both implementations are handed the same uncompressed bytes rather than a path, so that
//! the comparison measures WARC handling alone. Reading through each crate's own path
//! constructors would instead measure their gzip backends, and would not get as far as a
//! comparison at all: upstream's `from_path` opens files with `create` but without write or
//! append access, which `std` rejects outright, and its `from_path_gzip` decompresses
//! through `libflate`, which fails on `pywb/example-wget-1-14.warc.gz`. Neither defect is in
//! upstream's reader, which parses every fixture here once it is given the bytes.

#![cfg(feature = "gzip")]

mod support;

use std::io::BufWriter;

use archivindex_warc::{WarcHeader, WarcVersion};
use support::{fixture_bytes, roundtrip};

/// The number of bytes of a header value shown when a comparison fails.
const VALUE_CONTEXT: usize = 64;

/// A written record reduced to the form the comparison is defined over.
#[derive(Debug, Eq, PartialEq)]
struct NormalizedRecord {
    version: WarcVersion,
    /// Every header as a lower-cased name and its value, sorted into a canonical order.
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

/// Round-trip every raw record of an uncompressed archive through the `warc` crate.
fn roundtrip_upstream(source: &[u8]) -> Result<Vec<u8>, String> {
    // Unlike this crate's writer, the upstream writer only exposes its inner writer when that
    // writer is a `BufWriter`, so the output buffer is wrapped in one to recover it.
    let mut writer = warc::WarcWriter::new(BufWriter::new(Vec::new()));
    for record in warc::WarcReader::new(source).iter_raw_records() {
        let (headers, body) = record.map_err(|error| error.to_string())?;
        // The upstream writer takes the header block by value.
        writer
            .write_raw(headers, &body)
            .map_err(|error| error.to_string())?;
    }

    writer
        .into_inner()
        .map_err(|error| std::io::IntoInnerError::into_error(error).to_string())
}

/// Reduce a written archive to the records it encodes, discarding header order and case.
///
/// Both outputs are parsed by this crate's reader, so any surviving difference is a
/// difference in the records the bytes encode rather than in their layout. Lower-casing the
/// names and sorting the block is the whole of the tolerance.
fn normalize(output: &[u8]) -> Result<Vec<NormalizedRecord>, String> {
    archivindex_warc::WarcReader::new(output)
        .iter_raw_records()
        .map(|record| {
            let (header, body) = record.map_err(|error| error.to_string())?;
            // `WARC-Concurrent-To` is repeatable and so is held apart from the other fields;
            // each of its values is one more header for comparison purposes.
            let concurrent_to = header
                .concurrent_to
                .iter()
                .map(|value| (WarcHeader::ConcurrentTo.name().to_owned(), value.clone()));
            let mut headers = header
                .headers
                .iter()
                .map(|(name, value)| (name.name().to_ascii_lowercase(), value.clone()))
                .chain(concurrent_to)
                .collect::<Vec<_>>();
            headers.sort_unstable();

            Ok(NormalizedRecord {
                version: header.version,
                headers,
                body,
            })
        })
        .collect()
}

/// Render a header for a failure message, truncating a long value.
fn describe_header((name, value): &(String, Vec<u8>)) -> String {
    let shown = String::from_utf8_lossy(&value[..value.len().min(VALUE_CONTEXT)]);

    format!("{name}: {}", shown.escape_debug())
}

/// List the headers present in `headers` but not in `other`, for a failure message.
fn headers_only_in(headers: &[(String, Vec<u8>)], other: &[(String, Vec<u8>)]) -> String {
    let missing = headers
        .iter()
        .filter(|header| !other.contains(header))
        .map(describe_header)
        .collect::<Vec<_>>();

    if missing.is_empty() {
        "(none)".to_owned()
    } else {
        missing.join(", ")
    }
}

/// Describe the first difference between two normalized archives, or `None` if they encode
/// the same records.
///
/// Bodies run to megabytes, so a differing body is reported by length and by the offset of
/// its first differing byte rather than as a full dump.
fn describe_difference(
    archivindex: &[NormalizedRecord],
    upstream: &[NormalizedRecord],
) -> Option<String> {
    if archivindex.len() != upstream.len() {
        return Some(format!(
            "archivindex-warc wrote {} records, warc 0.4.0 wrote {}",
            archivindex.len(),
            upstream.len()
        ));
    }

    archivindex
        .iter()
        .zip(upstream)
        .enumerate()
        .find_map(|(index, (left, right))| {
            if left.version != right.version {
                return Some(format!(
                    "record {index}: WARC version {:?} here, {:?} upstream",
                    left.version, right.version
                ));
            }

            if left.headers != right.headers {
                return Some(format!(
                    "record {index}: header blocks differ\n  \
                     only in archivindex-warc: {}\n  only in warc 0.4.0:       {}",
                    headers_only_in(&left.headers, &right.headers),
                    headers_only_in(&right.headers, &left.headers)
                ));
            }

            if left.body != right.body {
                let offset = left
                    .body
                    .iter()
                    .zip(&right.body)
                    .position(|(one, other)| one != other)
                    .unwrap_or_else(|| left.body.len().min(right.body.len()));

                return Some(format!(
                    "record {index}: bodies differ at byte {offset} ({} bytes here, {} upstream)",
                    left.body.len(),
                    right.body.len()
                ));
            }

            None
        })
}

/// Assert that both implementations round-trip a fixture to the same records.
fn assert_roundtrips_match(set: &str, name: &str) {
    let source = fixture_bytes(set, name).unwrap_or_else(|error| panic!("{set}/{name}: {error}"));

    let archivindex = roundtrip(&source)
        .and_then(|output| normalize(&output))
        .unwrap_or_else(|error| panic!("{set}/{name}: archivindex-warc: {error}"));
    let upstream = roundtrip_upstream(&source)
        .and_then(|output| normalize(&output))
        .unwrap_or_else(|error| panic!("{set}/{name}: warc 0.4.0: {error}"));

    assert!(!archivindex.is_empty(), "{set}/{name}: no records compared");

    if let Some(difference) = describe_difference(&archivindex, &upstream) {
        panic!("{set}/{name}: {difference}");
    }
}

/// Define one test per fixture, so that each fixture's outcome is reported on its own.
macro_rules! roundtrip_tests {
    ($set:literal, $($test_name:ident: $fixture:literal,)+) => {
        $(
            #[test]
            fn $test_name() {
                assert_roundtrips_match($set, $fixture);
            }
        )+
    };
}

// The fixtures pywb treats as valid archives: the same set the pywb digest and gzip-member
// tests cover. The remaining pywb fixtures are deliberately malformed or non-conforming and
// have no round trip to compare.
roundtrip_tests!(
    "pywb",
    pywb_dupes: "dupes.warc.gz",
    pywb_example: "example.warc.gz",
    pywb_example2: "example2.warc.gz",
    pywb_example_wget_1_14: "example-wget-1-14.warc.gz",
    pywb_example_wpull: "example-wpull.warc.gz",
    pywb_httpbin_resource: "httpbin-resource.warc.gz",
    pywb_iana: "iana.warc.gz",
    pywb_post_test: "post-test.warc.gz",
);

// The fixtures warcio treats as valid archives. `example-digest.warc` is included because
// only one of its declared digests is wrong: the records themselves are well-formed. The
// truncated and deliberately mis-compressed fixtures are excluded.
roundtrip_tests!(
    "warcio",
    warcio_example: "example.warc",
    warcio_example_gzip: "example.warc.gz",
    warcio_example_digest: "example-digest.warc",
    warcio_example_iana_chunked: "example-iana.org-chunked.warc",
    warcio_example_resource: "example-resource.warc.gz",
    warcio_example_space_in_target_uri: "example-space-in-target-uri.warc.gz",
    warcio_example_wget_bad_target_uri: "example-wget-bad-target-uri.warc.gz",
    warcio_post_test: "post-test.warc.gz",
);
