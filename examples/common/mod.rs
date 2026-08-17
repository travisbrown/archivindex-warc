//! Helpers shared by the examples.
//!
//! This file lives in a subdirectory so that Cargo does not treat it as an example of its own.

use std::io;
use std::path::{Path, PathBuf};

/// Directory holding the WARC files that the examples write and read.
///
/// Cargo sets `CARGO_MANIFEST_DIR` to the crate root, so this path does not depend on the current
/// directory.
const TMP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/tmp");

/// Resolve `name` inside `examples/tmp`, creating the directory if needed.
///
/// # Arguments
///
/// * `name`: File name to resolve, or an absolute path to use as is.
///
/// # Returns
///
/// The path to use for the file.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the directory cannot be created.
pub fn tmp_path<P: AsRef<Path>>(name: P) -> io::Result<PathBuf> {
    std::fs::create_dir_all(TMP_DIR)?;

    // `join` replaces the base when given an absolute path.
    Ok(Path::new(TMP_DIR).join(name))
}
