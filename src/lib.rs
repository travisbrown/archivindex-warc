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
//! Errors are reported at the level that finds them. [`value::Error`] reports field-value grammar
//! violations through [`value::TextError`], [`value::MediaTypeError`], and
//! [`value::DigestError`]. [`parse::untyped::Error`] adds the field that carried the value.
//! [`record::Error`] reports semantic violations, including forbidden or repeated fields and
//! values that are invalid for the declared version or record type. [`record::RenderError`] catches
//! invalid states introduced through extensions or direct mutation, such as duplicate standard
//! fields, fields unavailable in the declared version, and names or values that cannot form a
//! valid header line. [`io::read::Error`] and [`io::write::Error`] add stream failures.
//!
//! Field values are read and written as they are spelled. Clause 4 of the WARC 1.1 standard admits
//! non-ASCII characters in a field value only as the encoded words of RFC 2047, a mechanism the
//! [annotated standard][annotated] finds underspecified for WARC, rarely implemented, and
//! obsoleted by Unicode. Its community recommendation #67 is not to implement it, and this crate
//! follows that: an encoded word reaches the caller as it was read, and a value is written as it
//! was given.
//!
//! WARC 1.0 and 1.1 are the versions read and written. A record declaring any other version is
//! a stream failure rather than a record-level error: the reader frames a record by the
//! `Content-Length` in its header block, which it does not parse under a version it does not
//! know, so it cannot skip to the next record and iteration ends there.
//!
//! [annotated]:
//!   https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/
//! [warc-crate]: https://crates.io/crates/warc
//! [warc]: https://en.wikipedia.org/wiki/WARC_(file_format)

mod parsing;

pub mod io;
pub mod parse;
pub mod record;
#[cfg(feature = "recorder")]
pub mod recorder;
pub mod value;
pub mod version;
