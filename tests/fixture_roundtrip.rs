//! Byte fidelity of this crate's round trips over the pywb and warcio fixtures.
//!
//! Each valid fixture is read and written through the two representations that preserve bytes:
//!
//! 1. [`raw::Record`](archivindex_warc::parse::raw::Record), which preserves raw field names and
//!    values.
//! 2. [`untyped::Record`](archivindex_warc::parse::untyped::Record), which also parses each value.
//!
//! Both must reproduce the uncompressed fixture exactly. The semantic representation instead
//! renders fields canonically, so its records are rendered, parsed again, and compared by value.
//!
//! `UNREADABLE` lists the fixtures each representation is expected to reject.

#![cfg(feature = "gzip")]

mod support;

use support::{fixture_bytes, roundtrip, roundtrip_records, roundtrip_semantic_meaning};

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

/// The fixtures a layer cannot read, as `(layer, set, name)`, with the reason each is here.
///
/// A grammar record refuses a value the rule its name selects does not admit, which one of the
/// warcio fixtures was collected for: it writes a space into a `WARC-Target-URI`, and a space is
/// not a character any URI may spell. Nothing a grammar record refuses can reach the semantic
/// layer, so that fixture is listed for both. Lifting refuses more: a field the record's type
/// does not permit, and a field named for the first time in WARC 1.1 under a record declaring
/// WARC 1.0, which is what stops the other fixtures listed there.
const UNREADABLE: &[(&str, &str, &str)] = &[
    (
        "grammar records",
        "warcio",
        "example-space-in-target-uri.warc.gz",
    ),
    (
        "semantic records",
        "warcio",
        "example-space-in-target-uri.warc.gz",
    ),
    ("semantic records", "pywb", "dupes.warc.gz"),
    ("semantic records", "pywb", "example.warc.gz"),
    ("semantic records", "pywb", "example-wpull.warc.gz"),
    ("semantic records", "pywb", "iana.warc.gz"),
    ("semantic records", "warcio", "example.warc"),
    ("semantic records", "warcio", "example.warc.gz"),
];

/// Assert that reading and rewriting a fixture reproduces its uncompressed bytes exactly, at
/// every layer that promises as much and can read it, that a fixture the semantic layer can read
/// says the same thing after being rendered and read again, and that the fixtures a layer cannot
/// read are exactly those listed.
fn assert_roundtrip_is_faithful(set: &str, name: &str) {
    let source = fixture_bytes(set, name).unwrap_or_else(|error| panic!("{set}/{name}: {error}"));

    for (layer, written) in [
        ("raw records", roundtrip(&source)),
        ("grammar records", roundtrip_records(&source)),
    ] {
        let listed = UNREADABLE.contains(&(layer, set, name));
        match written {
            Ok(written) => {
                assert!(
                    !listed,
                    "{set}/{name}: now reads as {layer}, so drop it from UNREADABLE"
                );
                if let Some(difference) = describe_difference(&source, &written) {
                    panic!("{set}/{name} as {layer}: {difference}");
                }
            }
            Err(error) => assert!(listed, "{set}/{name} as {layer}: {error}"),
        }
    }

    // The semantic layer renders a block from what a record means rather than from how it was
    // written, so what is asked of it is that the rendering say what was read rather than that it
    // spell it the same way.
    let listed = UNREADABLE.contains(&("semantic records", set, name));
    match roundtrip_semantic_meaning(&source) {
        Ok(()) => assert!(
            !listed,
            "{set}/{name}: now reads as semantic records, so drop it from UNREADABLE"
        ),
        Err(error) => assert!(listed, "{set}/{name} as semantic records: {error}"),
    }
}

/// Define one test per fixture, so that each fixture's outcome is reported on its own.
macro_rules! roundtrip_tests {
    ($set:literal, $($test_name:ident: $fixture:literal,)+) => {
        $(
            #[test]
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
