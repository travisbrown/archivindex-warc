//! Higher-level operations for WARC files.

pub mod canonicalize;
pub mod compress;
mod error;
pub mod file;
pub mod lint;
pub mod merge;
pub mod rewrite;

pub use error::{Error, Result};
