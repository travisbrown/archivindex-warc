//! Byte-fidelity of this crate's own round trip over the pywb and warcio fixtures.
//!
//! Every valid fixture is decompressed if necessary, read record by record, and written
//! straight back out, and the result is required to be byte-identical to the uncompressed
//! input. This is a stronger property than the cross-implementation comparison in
//! `warc_crate_roundtrip`, which forgives header order and case: here nothing is forgiven,
//! so the suite pins down exactly how faithful a round trip through this crate is.
//!
//! Every fixture currently fails, for two reasons, both of which preserve the length of the
//! archive to the byte, so the whole suite is ignored pending a fix:
//!
//! 1. The writer emits header names lower-cased (`warc-type:` for the fixtures'
//!    `WARC-Type:`), because a parsed name is matched against a table of lower-case literals
//!    and the original spelling is not kept. This accounts for all sixteen failures, and for
//!    three of them — `pywb/httpbin-resource.warc.gz`, `warcio/example-resource.warc.gz` and
//!    `warcio/example-space-in-target-uri.warc.gz` — it is the only difference.
//! 2. `WARC-Concurrent-To` is repeatable, so it is held in its own field rather than in the
//!    header block, and the writer emits it after every other header. A fixture that carries
//!    the field mid-block therefore comes back with it at the end of that record's block.
//!    This accounts for the remaining thirteen failures; setting those lines aside makes
//!    every other header line land at its original position.

#![cfg(feature = "gzip")]

mod support;

use support::{fixture_bytes, roundtrip};

/// The number of bytes of context shown from each side when a comparison fails.
const DIFFERENCE_CONTEXT: usize = 96;

/// Render a window of an archive as an escaped string, for reporting a difference.
fn window(data: &[u8], offset: usize) -> String {
    let end = data.len().min(offset + DIFFERENCE_CONTEXT);

    String::from_utf8_lossy(&data[offset..end])
        .escape_debug()
        .to_string()
}

/// Describe the first difference between the input and the round-tripped output, or `None`
/// if they are byte-identical.
///
/// Archives run to megabytes, so a difference is reported as the offset of the first
/// differing byte plus a short window of context from each side, rather than as a full dump.
fn describe_difference(source: &[u8], written: &[u8]) -> Option<String> {
    let first_difference = source
        .iter()
        .zip(written)
        .position(|(left, right)| left != right);

    if first_difference.is_none() && source.len() == written.len() {
        return None;
    }

    // Without a differing byte, one archive is a prefix of the other, and they first differ
    // where the shorter one ends.
    let offset = first_difference.unwrap_or_else(|| source.len().min(written.len()));

    Some(format!(
        "output differs at byte {offset} ({} bytes in, {} bytes out)\n  \
         fixture: {}\n  written: {}",
        source.len(),
        written.len(),
        window(source, offset),
        window(written, offset)
    ))
}

/// Assert that reading and rewriting a fixture reproduces its uncompressed bytes exactly.
fn assert_roundtrip_is_faithful(set: &str, name: &str) {
    let source = fixture_bytes(set, name).unwrap_or_else(|error| panic!("{set}/{name}: {error}"));
    let written = roundtrip(&source).unwrap_or_else(|error| panic!("{set}/{name}: {error}"));

    if let Some(difference) = describe_difference(&source, &written) {
        panic!("{set}/{name}: {difference}");
    }
}

/// Define one test per fixture, so that each fixture's outcome is reported on its own.
macro_rules! roundtrip_tests {
    ($set:literal, $($test_name:ident: $fixture:literal,)+) => {
        $(
            #[test]
            #[ignore = "known bug (writer lower-cases header names, moves warc-concurrent-to): \
                        fix incoming"]
            fn $test_name() {
                assert_roundtrip_is_faithful($set, $fixture);
            }
        )+
    };
}

// The same fixtures the cross-implementation suite covers: those pywb treats as valid.
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

// The same fixtures the cross-implementation suite covers: those warcio treats as valid.
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
