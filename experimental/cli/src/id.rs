//! Rewrite the records of a WARC file to use content-derived identifiers.
//!
//! References are resolved before IDs are derived, so each ID describes the relationships written
//! to the output. Records remain in input order; only their IDs and record references change.

use std::path::Path;

use archivindex_archiver::id::Identity;
use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc_ops::file::{compression, is_stdin, transform};
use archivindex_warc_ops::header::{insert_field, redirect_references};
use fluent_uri::Uri;

mod plan;

/// A failure while rewriting the identifiers of a file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file could not be read or written.
    #[error(transparent)]
    File(#[from] archivindex_warc_ops::Error),

    /// Separate input identities would share an output identifier.
    #[error("separate input identities would share the output identifier {id}")]
    CollidingRecordIds {
        /// The output identifier both records would share.
        id: String,
    },

    /// An input identifier does not name exactly one record.
    #[error("more than one input record uses identifier {id}")]
    RepeatedRecordId {
        /// The identifier the records are written with.
        id: String,
    },

    /// References among identifiable records form a cycle.
    #[error(
        "cannot derive IDs for cyclic references (record {record} is in or depends on a cycle)"
    )]
    CyclicReferences {
        /// The zero-based index of an unresolved record.
        record: usize,
    },
}

/// A result of rewriting the identifiers of a file.
type Result<T> = std::result::Result<T, Error>;

/// What was written to the output file.
#[derive(Debug)]
pub struct Summary {
    /// The number of records written.
    pub records: usize,
    /// The number of records given a derived identifier.
    pub reidentified: usize,
    /// The number of records whose identifiers were retained because derivation failed.
    pub unidentifiable: usize,
}

/// Give each record of `input` the identifier the content-derived scheme assigns it, and write
/// every record to `output`.
///
/// References to records in the input use their final IDs, including forward references. External
/// references retain their IDs. Records with an unknown type or unreadable identity fields keep
/// their own IDs with a warning; their references are still updated. All other fields and blocks
/// are preserved, in input order.
///
/// The input must remain unchanged across both passes. A `.gz` path selects gzip; compressed
/// output holds one member per record. Output is published only after every record is written.
///
/// # Errors
///
/// Refuses duplicate input IDs, colliding output IDs, and cyclic dependencies among identifiable
/// records before creating output. Also fails for standard input, identical input and output paths,
/// or an error reading, writing, or publishing a file.
pub fn record_ids(input: &Path, output: &Path) -> Result<Summary> {
    if is_stdin(input) {
        return Err(archivindex_warc_ops::Error::StandardInputReadTwice.into());
    }

    let redirects = plan::redirects(input)?;
    let mut reidentified = 0;
    let mut unidentifiable = 0;
    let summary = transform(
        &[input],
        output,
        compression(output),
        |index, mut record| {
            redirect_references(&mut record.header, &redirects);
            match Identity::from_raw(&record) {
                Ok(identity) => {
                    let id = identity.record_id();
                    set_record_id(&mut record.header, &id);
                    reidentified += 1;
                }
                Err(reason) => {
                    log::warn!("retaining the identifier of record {index}: {reason}");
                    unidentifiable += 1;
                }
            }
            Ok(Some(record))
        },
    )?;

    Ok(Summary {
        records: summary.records,
        reidentified,
        unidentifiable,
    })
}

/// The `WARC-Record-ID` value naming a derived identifier.
///
/// The standard writes this field, and every field naming another record, inside angle brackets.
fn record_id_value(id: &Uri<String>) -> Vec<u8> {
    format!(" <{id}>").into_bytes()
}

/// Give a header a derived identifier, adding the field when the record declares none.
fn set_record_id(header: &mut raw::RecordHeader, id: &Uri<String>) {
    let value = record_id_value(id);
    let mut replaced = false;

    for (name, existing) in &mut header.headers {
        if name.eq_ignore_ascii_case(Field::RecordID.standard_name()) {
            existing.clone_from(&value);
            replaced = true;
        }
    }

    if !replaced {
        insert_field(header, Field::RecordID, value);
    }
}

#[cfg(test)]
mod tests;
