//! Higher-level operations for WARC files.

pub mod canonicalize;
pub mod compress;
mod error;
pub mod file;
pub mod gzip;
pub mod header;
pub mod lint;
pub mod merge;
pub mod propagate;
pub mod remove;
pub mod rewrite;

pub use error::{Error, Result};
