#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(clippy::missing_errors_doc)]
#![forbid(unsafe_code)]
//! Higher-level operations for WARC files.

pub mod canonicalize;
mod error;
pub mod merge;

pub use error::{Error, Result};
