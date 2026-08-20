//! Errors from higher-level WARC operations.

use std::io;
use std::path::PathBuf;

use archivindex_warc::io::{read, write};

/// A failure while performing a higher-level WARC operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An input file could not be opened.
    #[error("cannot open {}", path.display())]
    Open {
        /// The input path.
        path: PathBuf,
        /// The file-system failure.
        #[source]
        source: io::Error,
    },

    /// An output file could not be created.
    #[error("cannot create {}", path.display())]
    Create {
        /// The output path.
        path: PathBuf,
        /// The file-system failure.
        #[source]
        source: io::Error,
    },

    /// A record could not be read from an input file.
    #[error("cannot read {}", path.display())]
    Read {
        /// The input path.
        path: PathBuf,
        /// The WARC reading failure.
        #[source]
        source: read::Error,
    },

    /// A record could not be written to an output file.
    #[error("cannot write to {}", path.display())]
    Write {
        /// The output path.
        path: PathBuf,
        /// The WARC writing failure.
        #[source]
        source: write::Error,
    },

    /// Buffered output could not be flushed.
    #[error("cannot write to {}", path.display())]
    Flush {
        /// The output path.
        path: PathBuf,
        /// The file-system failure.
        #[source]
        source: io::Error,
    },

    /// An operation was asked to overwrite its input file.
    #[error("input and output must be different files: {}", path.display())]
    SameInputAndOutput {
        /// The path used for both input and output.
        path: PathBuf,
    },

    /// A kept warcinfo record had no identifier for redirecting references.
    #[error("cannot redirect references: a merged warcinfo record has no WARC-Record-ID")]
    MissingWarcinfoRecordId,

    /// The input's warcinfo records differed between the planning and writing passes.
    #[error("warcinfo records changed between reads")]
    WarcinfoRecordsChanged,
}

/// A result returned by a higher-level WARC operation.
pub type Result<T, E = Error> = std::result::Result<T, E>;
