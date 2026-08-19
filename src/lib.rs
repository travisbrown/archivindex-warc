#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(clippy::missing_errors_doc)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! A [WARC][warc] ("Web ARChive") library, originally forked from [`warc`][warc-crate].
//!
//! A WARC file is a sequence of WARC records. This library provides three record representations:
//!
//! 1. [`parse::raw::Record`] preserves version, field lines, whitespace, and content block. It
//!    validates record framing and supports byte-exact round-tripping.
//! 2. [`parse::untyped::Record`] parses values using the combined WARC 1.0 and 1.1 grammars,
//!    including selected changes from the [annotated standard][annotated].
//! 3. [`record::Record`] validates fields against the declared version and record type, including
//!    required fields, repetition, and allowed values. Direct mutation and extension fields can
//!    still cause rendering to fail.
//!
//! [`io::read::WarcReader`] reads any of these representations and can skip content blocks after
//! inspecting their headers. [`io::read::WarcReader`] and [`io::write::WarcWriter`] both support
//! gzip-compressed WARC files.
//!
//! Errors are reported at the level that finds them. [`value::Error`] reports field-value grammar
//! violations through [`value::TextError`], [`value::MediaTypeError`], and [`value::DigestError`].
//! [`parse::untyped::Error`] adds the field that carried the value. [`record::Error`] reports
//! semantic violations, including forbidden or repeated fields and values that are invalid for the
//! declared version or record type. [`record::RenderError`] catches invalid states introduced
//! through extensions or direct mutation, such as duplicate standard fields, fields unavailable in
//! the declared version, and names or values that cannot form a valid header line.
//! [`io::read::Error`] and [`io::write::Error`] add stream failures.
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
