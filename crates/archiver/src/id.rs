//! Content-derived record IDs.
//!
//! Version 1 hashes the record type, date at microsecond precision, target URI, and SHA-256 of the
//! stored block, followed for a revisit by the date and target URI of its original capture. An ID
//! depends only on its own record. See the crate README for the byte format and the fields
//! intentionally excluded from identity.

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::Record;
use archivindex_warc::record::record_type::RecordType;
use archivindex_warc::value::WarcDate;
use fluent_uri::Uri;
use sha2::{Digest, Sha256};

mod read;

/// The version of the scheme this crate derives IDs under.
pub const VERSION: u8 = 1;

/// A record could not be identified under this scheme.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// Record types the archiver never writes have no assigned type byte.
    #[error("record type {0} has no type byte in version {VERSION} of the scheme")]
    UnsupportedRecordType(String),
    /// A required identity field is absent, an identity field cannot be parsed, or an identity date
    /// is before 1970.
    #[error("missing or invalid {0}")]
    InvalidField(Field),
    /// An identity field appears more than once.
    #[error("repeated {0}")]
    RepeatedField(Field),
    /// The record is part of a segmented record, which the scheme does not identify.
    #[error("segmented records are not supported, but the record has {0}")]
    Segmented(Field),
}

/// Derive the ID of a typed record.
///
/// # Errors
///
/// Fails for an unsupported record type, a segment number, a date before 1970, or a revisit
/// without its original's date and target URI.
pub fn record_id(record: &Record) -> Result<Uri<String>, Error> {
    if record.segment_number().is_some() {
        return Err(Error::Segmented(Field::SegmentNumber));
    }
    let original = match record {
        Record::Revisit { header, .. } => Some(Original {
            date: header.refers_to_date,
            target_uri: header.refers_to_target_uri.as_ref().map(Uri::as_str),
        }),
        _ => None,
    };
    derive(
        &record.record_type(),
        record.core().date,
        record.target_uri().map(Uri::as_str),
        &record.body_bytes(),
        original,
    )
}

/// Derive the ID of a raw record without validating unrelated header fields.
///
/// URI brackets and surrounding whitespace are not part of identity.
///
/// # Errors
///
/// Fails for an unsupported type, a segment field, a missing type or date, a malformed or repeated
/// identity field, or a revisit without its original's date and target URI.
pub fn raw_record_id(record: &raw::Record) -> Result<Uri<String>, Error> {
    read::record_id(record)
}

/// A revisit's original capture, as its `WARC-Refers-To-Date` and `WARC-Refers-To-Target-URI`.
struct Original<'a> {
    date: Option<WarcDate>,
    target_uri: Option<&'a str>,
}

/// Hash the pre-image of a record, where `original` is present exactly when it is a revisit.
fn derive(
    record_type: &RecordType,
    date: WarcDate,
    target_uri: Option<&str>,
    block: &[u8],
    original: Option<Original<'_>>,
) -> Result<Uri<String>, Error> {
    if !matches!(
        record_type,
        RecordType::Warcinfo
            | RecordType::Request
            | RecordType::Response
            | RecordType::Metadata
            | RecordType::Revisit
    ) {
        return Err(Error::UnsupportedRecordType(record_type.to_string()));
    }
    let mut hash = Sha256::new();
    hash.update([VERSION, record_type.canonical_rank() + 1]);
    hash.update(date_bytes(date, Field::Date)?);
    length_prefixed(&mut hash, target_uri.unwrap_or_default());
    hash.update(Sha256::digest(block));
    if let Some(original) = original {
        let date = original
            .date
            .ok_or(Error::InvalidField(Field::RefersToDate))?;
        hash.update(date_bytes(date, Field::RefersToDate)?);
        let target_uri = original
            .target_uri
            .ok_or(Error::InvalidField(Field::RefersToTargetURI))?;
        length_prefixed(&mut hash, target_uri);
    }
    Ok(Uri::parse(format!(
        "https://archivindex.org/record/{}",
        data_encoding::HEXLOWER.encode(&hash.finalize())
    ))
    .expect("the record ID is a valid HTTPS URI"))
}

fn length_prefixed(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

/// Encode a date as unsigned Unix microseconds, refusing dates before 1970.
fn date_bytes(date: WarcDate, field: Field) -> Result<[u8; 8], Error> {
    u64::try_from(date.date_time().timestamp_micros())
        .map(u64::to_be_bytes)
        .map_err(|_| Error::InvalidField(field))
}

#[cfg(test)]
mod tests;
