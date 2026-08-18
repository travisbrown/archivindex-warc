#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(clippy::missing_errors_doc)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! A [WARC][warc] ("Web ARChive") library, originally forked from [`warc`][warc-crate].
//!
//! A WARC file is a sequence of WARC records. This library provides three record representations:
//!
//! 1. [`parse::raw::Record`] preserves the version, field lines, white space, and content block. It
//!    performs only the validation needed to frame a record and supports byte-exact round-tripping.
//! 2. [`parse::untyped::Record`] parses each field value according to the union of the WARC 1.0 and
//!    1.1 grammars. It includes practical changes from the [annotated WARC 1.1 standard][annotated]
//!    but does not check values against the record's declared version.
//! 3. [`record::Record`] applies the semantic rules for the declared version and record type. It
//!    checks whether fields are allowed, required, or repeatable, and whether their values are
//!    semantically valid. Its extension mechanism can weaken these guarantees, so rendering may
//!    still return a [`record::RenderError`].
//!
//! [`io::read::WarcReader`] reads any of these representations and can skip content blocks after
//! inspecting their headers. [`io::read::WarcReader`] and [`io::write::WarcWriter`] both support
//! gzip-compressed WARC files.
//!
//! Errors are reported at the level that finds them. [`value::Error`] reports violations of field
//! value grammars, while [`parse::untyped::Error`] adds the field that carried the value.
//! [`record::Error`] reports semantic violations, including forbidden or repeated fields and
//! values that are invalid for the declared version or record type. [`record::RenderError`] catches
//! invalid states introduced through extensions or direct mutation, such as duplicate standard
//! fields, fields unavailable in the declared version, and names or values that cannot form a
//! valid header line. [`io::read::Error`] and [`io::write::Error`] add stream failures.
//!
//! [annotated]:
//!   https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/
//! [warc-crate]: https://crates.io/crates/warc
//! [warc]: https://en.wikipedia.org/wiki/WARC_(file_format)

const MB: usize = 1_048_576;

/// Whether a byte may appear in a header name, per the specification's token grammar: ASCII,
/// excluding control characters, separators, and space. Shared by the parser and the
/// write-path validation so that acceptance on write matches acceptance on read.
const fn is_header_token_char(chr: u8) -> bool {
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
pub use header::{FieldName, WarcHeader};

/// Core functions for parsing. Not recommended for direct use.
pub mod parser;

mod record;
pub use record::{BufferedBody, EmptyBody, RawRecordHeader, Record, RecordBuilder, StreamingBody};

mod record_type;
pub use record_type::RecordType;

mod truncated_type;
pub use truncated_type::TruncatedType;

mod version;
pub use version::WarcVersion;

mod parsing;

pub mod value;

pub mod fields;
