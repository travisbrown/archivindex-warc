#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(clippy::missing_errors_doc)]
#![forbid(unsafe_code)]
//! A WARC (Web ARChive) library

const MB: usize = 1_048_576;

/// Whether a byte may appear in a header name, per the specification's token grammar: ASCII,
/// excluding control characters, separators, and space. Shared by the parser and the
/// write-path validation so that acceptance on write matches acceptance on read.
fn is_header_token_char(chr: u8) -> bool {
    !matches!(chr, 0..=31
        | 127..=255
        | b'('
        | b')'
        | b'<'
        | b'>'
        | b'@'
        | b','
        | b';'
        | b':'
        | b'"'
        | b'/'
        | b'['
        | b']'
        | b'?'
        | b'='
        | b'{'
        | b'}'
        | b' '
        | b'\\')
}

/// Whether a version string names a WARC version this crate supports.
///
/// The crate implements WARC 1.0 and 1.1; a record claiming conformance to anything else
/// cannot be read as either, so it is rejected rather than read as though it were. Shared by
/// the parser and the write-path validation so that acceptance on write matches acceptance
/// on read.
fn is_supported_version(version: &str) -> bool {
    matches!(version, "1.0" | "1.1")
}

mod error;
pub use error::Error;

/// Parse a `Content-Length` value per the specification's `1*DIGIT` grammar.
///
/// The field grammar permits linear whitespace around the digits, so surrounding spaces and
/// tabs are stripped; the digits themselves admit no sign, internal whitespace, or any other
/// character. `None` also covers values beyond the unsigned 64-bit range, which could never
/// frame a real record. Shared by the parser and the record entry points so that both accept
/// exactly the same values.
fn parse_content_length(value: &str) -> Option<u64> {
    let digits = value.trim_matches(|chr| chr == ' ' || chr == '\t');

    // `parse` accepts exactly the `1*DIGIT` grammar plus an optional leading `+`, which is
    // therefore the one deviation to reject.
    if digits.starts_with('+') {
        None
    } else {
        digits.parse().ok()
    }
}

mod warc_reader;
pub use warc_reader::*;
mod warc_writer;
pub use warc_writer::*;

mod header;
pub use header::WarcHeader;

/// Core functions for parsing. Not recommended for direct use.
pub mod parser;

mod record;
pub use record::{BufferedBody, EmptyBody, RawRecordHeader, Record, RecordBuilder, StreamingBody};

mod record_type;
pub use record_type::RecordType;

mod truncated_type;
pub use truncated_type::TruncatedType;
