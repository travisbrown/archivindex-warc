#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(clippy::missing_errors_doc)]
#![forbid(unsafe_code)]
//! A WARC ("Web Archive") library

mod parsing;

pub mod fields;
pub mod io;
pub mod parse;
pub mod value;
pub mod version;

mod record_type;
pub use record_type::RecordType;

mod truncated_type;
pub use truncated_type::TruncatedType;
