#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(clippy::missing_errors_doc)]
//! Higher-level operations for WARC files.

pub mod canonicalize;
pub mod compress;
mod error;
mod files;
pub mod lint;
pub mod merge;
pub mod rewrite;

pub use error::{Error, Result};
