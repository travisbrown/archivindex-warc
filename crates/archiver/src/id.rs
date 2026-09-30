//! Content-derived record IDs.
//!
//! Version 1 hashes the record type, date at microsecond precision, SHA-256 of its stored block,
//! target URI, revisit profile and original capture coordinates, and the `WARC-Refers-To`
//! reference, which must name its final identifier. See the crate README for the byte format and
//! the fields intentionally excluded from identity.

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

/// A record's identity properties, retaining its block hash rather than its block.
///
/// This permits planning reference updates without keeping content blocks in memory. Construct
/// from a typed or raw record, then derive its identifier after the referenced IDs are known.
#[derive(Clone, Debug)]
pub struct Identity {
    hash: Sha256,
    refers_to: Option<String>,
}

impl Identity {
    /// Read identity properties from a raw record without validating unrelated header fields.
    ///
    /// Returns an error for an unsupported type, a segment field, a missing type or date, or a
    /// malformed or repeated identity field. URI brackets and surrounding whitespace are not part
    /// of identity.
    pub fn from_raw(record: &raw::Record) -> Result<Self, Error> {
        read::identity(record)
    }

    /// Read identity properties from a typed record without copying its content block.
    ///
    /// Returns an error for an unsupported record type or a segment number.
    pub fn from_record(record: &Record) -> Result<Self, Error> {
        if record.segment_number().is_some() {
            return Err(Error::Segmented(Field::SegmentNumber));
        }
        let mut identity = Self::new(
            &record.record_type(),
            record.core().date,
            &record.body_bytes(),
        )?;
        identity.optional(1, record.target_uri().map(|uri| uri.as_str().as_bytes()));
        if let Record::Revisit { header, .. } = record {
            identity.field(2, header.profile.to_string().as_bytes());
            identity.optional(
                3,
                header
                    .refers_to_target_uri
                    .as_ref()
                    .map(|uri| uri.as_str().as_bytes()),
            );
            identity.optional(
                4,
                header
                    .refers_to_date
                    .map(|date| date_bytes(date, Field::RefersToDate))
                    .transpose()?,
            );
        }
        identity.refers_to = record.refers_to().map(|uri| uri.as_str().to_owned());
        Ok(identity)
    }

    /// The IDs this record's identity depends on.
    pub fn references(&self) -> impl Iterator<Item = &str> {
        self.refers_to.as_deref().into_iter()
    }

    /// Derive an ID using the references as read.
    #[must_use]
    pub fn record_id(&self) -> Uri<String> {
        self.record_id_with_references(|_| None)
    }

    /// Derive an ID using final reference IDs supplied by `resolve`.
    ///
    /// Returning `None` keeps a reference as read, for example when its target is in another file.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the ID is a hex path under a fixed HTTPS prefix"
    )]
    pub fn record_id_with_references<'a>(
        &self,
        mut resolve: impl FnMut(&str) -> Option<&'a str>,
    ) -> Uri<String> {
        let mut hash = self.hash.clone();
        if let Some(id) = &self.refers_to {
            field(&mut hash, 5, resolve(id).unwrap_or(id).as_bytes());
        }
        Uri::parse(format!(
            "https://archivindex.org/record/{}",
            data_encoding::HEXLOWER.encode(&hash.finalize())
        ))
        .expect("the record ID is a valid HTTPS URI")
    }

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
        Ok(Self {
            hash,
            refers_to: None,
        })
    }

    fn field(&mut self, tag: u8, value: &[u8]) {
        field(&mut self.hash, tag, value);
    }

    fn optional(&mut self, tag: u8, value: Option<impl AsRef<[u8]>>) {
        if let Some(value) = value {
            self.field(tag, value.as_ref());
        }
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
