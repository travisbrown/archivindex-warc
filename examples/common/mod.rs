//! Helpers shared by the examples.
//!
//! This file lives in a subdirectory so that Cargo does not pick it up as an
//! example of its own: only `examples/*.rs` and `examples/*/main.rs` are
//! built as examples.

use std::io;
use std::path::{Path, PathBuf};

/// Directory holding the WARC files that the examples write and read.
///
/// `env!` reads an environment variable at compile time rather than at run
/// time, and Cargo sets `CARGO_MANIFEST_DIR` to the crate root, so this path
/// does not depend on the directory an example is run from.
const TMP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/tmp");

/// Resolve `name` inside `examples/tmp`, creating that directory if it does
/// not exist yet.
///
/// # Arguments
///
/// * `name` - File name to resolve, or an absolute path to use as-is
///
/// # Returns
///
/// The path to use for the file
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the directory cannot be created
pub fn tmp_path<P: AsRef<Path>>(name: P) -> io::Result<PathBuf> {
    std::fs::create_dir_all(TMP_DIR)?;

    // `join` replaces the base entirely when given an absolute path, so an
    // example that takes a path on the command line still accepts one that
    // points outside of this directory.
    Ok(Path::new(TMP_DIR).join(name))
}
