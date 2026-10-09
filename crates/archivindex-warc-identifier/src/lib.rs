//! Content-derived WARC record identifiers under the Archivindex identity scheme.
//!
//! [`IdentityV1`] borrows identity fields from a record and provides its version 1 preimage and
//! URI. See the crate README for the byte format and the fields intentionally excluded from identity.

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::Record;
use archivindex_warc::record::record_type::RecordType;
use archivindex_warc::value::WarcDate;
use fluent_uri::Uri;
use sha2::{Digest, Sha256};

mod read;

/// The prefix of every identifier under the scheme. The hash follows it in lowercase hexadecimal.
pub const RECORD_ID_PREFIX: &str = "https://archivindex.org/record/";

/// A record could not be identified under this scheme.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// Record types the archiver never writes have no assigned type byte.
    #[error("record type {0} has no type byte in version 1 of the scheme")]
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

/// Derive a raw record's URI under version 1 of the Archivindex identity scheme.
///
/// Equivalent to constructing an [`IdentityV1`] and calling [`IdentityV1::uri`].
///
/// # Errors
///
/// Returns the same errors as [`IdentityV1::new`].
pub fn record_id(record: &raw::Record) -> Result<Uri<String>, Error> {
    IdentityV1::new(record).map(|identity| identity.uri())
}

/// A validated version 1 identity, borrowing URI text from its source record.
///
/// Construction hashes the stored block once and validates the identity fields. Unrelated header
/// fields are ignored. The source record must outlive the identity.
#[derive(Clone, Debug)]
pub struct IdentityV1<'a> {
    record_type: u8,
    date: [u8; 8],
    target_uri: Option<&'a str>,
    block_hash: [u8; 32],
    original: Option<Original<'a>>,
}

#[derive(Clone, Debug)]
struct Original<'a> {
    date: [u8; 8],
    target_uri: &'a str,
}

impl<'a> IdentityV1<'a> {
    /// Construct an identity from a typed record without copying its content block.
    ///
    /// Fields blocks are rendered as they would be when written to a WARC file.
    ///
    /// # Errors
    ///
    /// Fails for an unsupported record type, a segment number, a date before 1970, or a revisit
    /// without its original's date and target URI.
    pub fn from_record(record: &'a Record) -> Result<Self, Error> {
        if record.segment_number().is_some() {
            return Err(Error::Segmented(Field::SegmentNumber));
        }
        let original = match record {
            Record::Revisit { header, .. } => Some(Original {
                date: date_bytes(
                    header
                        .refers_to_date
                        .ok_or(Error::InvalidField(Field::RefersToDate))?,
                    Field::RefersToDate,
                )?,
                target_uri: header
                    .refers_to_target_uri
                    .as_ref()
                    .map(Uri::as_str)
                    .ok_or(Error::InvalidField(Field::RefersToTargetURI))?,
            }),
            _ => None,
        };
        Self::from_parts(
            &record.record_type(),
            record.core().date,
            record.target_uri().map(Uri::as_str),
            &record.body_bytes(),
            original,
        )
    }

    /// Return the exact bytes hashed to produce this identity's URI.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode_preimage(|part| bytes.extend_from_slice(part));
        bytes
    }

    /// Return `https://archivindex.org/record/<hash>`, using the lowercase SHA-256 of the preimage.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "a fixed HTTPS prefix followed by hexadecimal digits is always a valid URI"
    )]
    pub fn uri(&self) -> Uri<String> {
        let mut hash = Sha256::new();
        self.encode_preimage(|part| hash.update(part));
        Uri::parse(format!(
            "{RECORD_ID_PREFIX}{}",
            data_encoding::HEXLOWER.encode(&hash.finalize())
        ))
        .expect("the record ID is a valid HTTPS URI")
    }

    fn encode_preimage(&self, mut write: impl FnMut(&[u8])) {
        write(&[1, self.record_type]);
        write(&self.date);
        length_prefixed(&mut write, self.target_uri.unwrap_or_default());
        write(&self.block_hash);
        if let Some(original) = &self.original {
            write(&original.date);
            length_prefixed(&mut write, original.target_uri);
        }
    }

    fn from_parts(
        record_type: &RecordType,
        date: WarcDate,
        target_uri: Option<&'a str>,
        block: &[u8],
        original: Option<Original<'a>>,
    ) -> Result<Self, Error> {
        let record_type = match record_type {
            RecordType::Warcinfo => 1,
            RecordType::Request => 2,
            RecordType::Response => 3,
            RecordType::Metadata => 4,
            RecordType::Revisit => 5,
            _ => return Err(Error::UnsupportedRecordType(record_type.to_string())),
        };
        Ok(Self {
            record_type,
            date: date_bytes(date, Field::Date)?,
            target_uri,
            block_hash: Sha256::digest(block).into(),
            original,
        })
    }
}

fn length_prefixed(write: &mut impl FnMut(&[u8]), value: &str) {
    write(&(value.len() as u64).to_be_bytes());
    write(value.as_bytes());
}

/// Encode a date as unsigned Unix microseconds, refusing dates before 1970.
fn date_bytes(date: WarcDate, field: Field) -> Result<[u8; 8], Error> {
    u64::try_from(date.date_time().timestamp_micros())
        .map(u64::to_be_bytes)
        .map_err(|_| Error::InvalidField(field))
}

#[cfg(test)]
mod tests;
