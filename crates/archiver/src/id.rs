//! Content-derived record IDs.
//!
//! Version 1 hashes the record type, date at microsecond precision, SHA-256 of its stored block,
//! target URI, and a revisit's profile and original capture coordinates. An ID depends only on its
//! own record. See the crate README for the byte format and the fields intentionally excluded from
//! identity.

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
/// Fails for an unsupported record type, a segment number, or a date before 1970.
pub fn record_id(record: &Record) -> Result<Uri<String>, Error> {
    if record.segment_number().is_some() {
        return Err(Error::Segmented(Field::SegmentNumber));
    }
    let mut preimage = Preimage::new(
        &record.record_type(),
        record.core().date,
        &record.body_bytes(),
    )?;
    preimage.optional(1, record.target_uri().map(|uri| uri.as_str().as_bytes()));
    if let Record::Revisit { header, .. } = record {
        preimage.field(2, header.profile.to_string().as_bytes());
        preimage.optional(
            3,
            header
                .refers_to_target_uri
                .as_ref()
                .map(|uri| uri.as_str().as_bytes()),
        );
        preimage.optional(
            4,
            header
                .refers_to_date
                .map(|date| date_bytes(date, Field::RefersToDate))
                .transpose()?,
        );
    }
    Ok(preimage.finish())
}

/// Derive the ID of a raw record without validating unrelated header fields.
///
/// URI brackets and surrounding whitespace are not part of identity.
///
/// # Errors
///
/// Fails for an unsupported type, a segment field, a missing type or date, or a malformed or
/// repeated identity field.
pub fn raw_record_id(record: &raw::Record) -> Result<Uri<String>, Error> {
    read::record_id(record)
}

/// The hash of a record's identity properties, fed in the order the scheme defines.
struct Preimage(Sha256);

impl Preimage {
    fn new(record_type: &RecordType, date: WarcDate, block: &[u8]) -> Result<Self, Error> {
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
        hash.update(Sha256::digest(block));
        Ok(Self(hash))
    }

    fn field(&mut self, tag: u8, value: &[u8]) {
        field(&mut self.0, tag, value);
    }

    fn optional(&mut self, tag: u8, value: Option<impl AsRef<[u8]>>) {
        if let Some(value) = value {
            self.field(tag, value.as_ref());
        }
    }

    fn finish(self) -> Uri<String> {
        Uri::parse(format!(
            "https://archivindex.org/record/{}",
            data_encoding::HEXLOWER.encode(&self.0.finalize())
        ))
        .expect("the record ID is a valid HTTPS URI")
    }
}

fn field(hash: &mut Sha256, tag: u8, value: &[u8]) {
    hash.update([tag]);
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
