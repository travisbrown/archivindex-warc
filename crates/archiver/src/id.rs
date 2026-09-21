//! Content-derived record IDs, including capture relationships and segment identity.
//!
//! Version 1 hashes the record type, date at microsecond precision, SHA-256 of its stored block,
//! target URI, segment fields, revisit profile and original capture coordinates, and all four
//! standard record-reference fields. References must name their final identifiers. See the crate
//! README for the byte format and the fields intentionally excluded from identity.

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
    /// Extension record types have no assigned type byte.
    #[error("record type {0} has no type byte in version {VERSION} of the scheme")]
    UnknownRecordType(String),
    /// A required identity field is absent or an identity field cannot be parsed.
    #[error("missing or invalid {0}")]
    InvalidField(Field),
    /// An identity field other than `WARC-Concurrent-To` appears more than once.
    #[error("repeated {0}")]
    RepeatedField(Field),
}

/// A record's identity properties, retaining its block hash rather than its block.
///
/// This permits planning reference updates without keeping content blocks in memory. Construct
/// from a typed or raw record, then derive its identifier after the referenced IDs are known.
#[derive(Clone, Debug)]
pub struct Identity {
    hash: Sha256,
    references: Vec<(u8, String)>,
}

impl Identity {
    /// Read identity properties from a raw record without validating unrelated header fields.
    ///
    /// Returns an error for an unknown type, a missing type or date, or a malformed or repeated
    /// identity field. URI brackets and surrounding whitespace are not part of identity.
    pub fn from_raw(record: &raw::Record) -> Result<Self, Error> {
        read::identity(record)
    }

    /// Read identity properties from a typed record without copying its content block.
    ///
    /// Returns an error for an unknown record type.
    pub fn from_record(record: &Record) -> Result<Self, Error> {
        let mut identity = Self::new(
            &record.record_type(),
            record.core().date,
            &record.body_bytes(),
        )?;
        identity.optional(1, record.target_uri().map(|uri| uri.as_str().as_bytes()));
        identity.optional(2, record.segment_number().map(u64::to_be_bytes));
        if let Record::Continuation { header, .. } = record {
            identity.optional(3, header.segment_total_length.map(u64::to_be_bytes));
            identity.reference(10, header.segment_origin_id.as_str());
        }
        if let Record::Revisit { header, .. } = record {
            identity.field(4, header.profile.to_string().as_bytes());
            identity.optional(
                5,
                header
                    .refers_to_target_uri
                    .as_ref()
                    .map(|uri| uri.as_str().as_bytes()),
            );
            identity.optional(6, header.refers_to_date.map(date_bytes));
        }
        if let Some(uri) = record.warcinfo_id() {
            identity.reference(7, uri.as_str());
        }
        for uri in record.concurrent_to() {
            identity.reference(8, uri.as_str());
        }
        if let Some(uri) = record.refers_to() {
            identity.reference(9, uri.as_str());
        }
        Ok(identity)
    }

    /// The IDs this record names, including repeated references.
    pub fn references(&self) -> impl Iterator<Item = &str> {
        self.references.iter().map(|(_, id)| id.as_str())
    }

    /// Derive an ID using the references as read.
    #[must_use]
    pub fn record_id(&self) -> Uri<String> {
        self.record_id_with_references(|_| None)
    }

    /// Derive an ID using final reference IDs supplied by `resolve`.
    ///
    /// Returning `None` keeps a reference as read, for example when its target is in another file.
    /// Reference order does not affect identity, but field roles and duplicate counts do.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the ID is a hex path under a fixed HTTPS prefix"
    )]
    pub fn record_id_with_references<'a>(
        &self,
        mut resolve: impl FnMut(&str) -> Option<&'a str>,
    ) -> Uri<String> {
        let mut references = self
            .references
            .iter()
            .map(|(tag, id)| (*tag, resolve(id).unwrap_or(id)))
            .collect::<Vec<_>>();
        references.sort_unstable();
        let mut hash = self.hash.clone();
        for (tag, id) in references {
            field(&mut hash, tag, id.as_bytes());
        }
        Uri::parse(format!(
            "https://archivindex.org/record/{}",
            data_encoding::HEXLOWER.encode(&hash.finalize())
        ))
        .expect("the record ID is a valid HTTPS URI")
    }

    fn new(record_type: &RecordType, date: WarcDate, block: &[u8]) -> Result<Self, Error> {
        if let RecordType::Unknown(name) = record_type {
            return Err(Error::UnknownRecordType(name.clone()));
        }
        let mut hash = Sha256::new();
        hash.update([VERSION, record_type.canonical_rank() + 1]);
        hash.update(date_bytes(date));
        hash.update(Sha256::digest(block));
        Ok(Self {
            hash,
            references: Vec::new(),
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

    fn reference(&mut self, tag: u8, value: &str) {
        self.references.push((tag, value.to_owned()));
    }
}

fn field(hash: &mut Sha256, tag: u8, value: &[u8]) {
    hash.update([tag]);
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

const fn date_bytes(date: WarcDate) -> [u8; 8] {
    date.date_time().timestamp_micros().to_be_bytes()
}

#[cfg(test)]
mod tests;
