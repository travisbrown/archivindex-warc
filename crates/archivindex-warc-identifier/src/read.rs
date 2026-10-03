//! Parse the identity fields while leaving unrelated raw headers alone.

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::record_type::RecordType;
use archivindex_warc::value::WarcDate;
use fluent_uri::Uri;

use super::{Error, IdentityV1, Original, date_bytes};

impl<'a> IdentityV1<'a> {
    /// Construct an identity from a raw record without validating unrelated header fields.
    ///
    /// URI brackets and surrounding whitespace are not part of identity.
    ///
    /// # Errors
    ///
    /// Fails for an unsupported type, a segment field, a missing type or date, a malformed or
    /// repeated identity field, or a revisit without its original's date and target URI.
    pub fn new(record: &'a raw::Record) -> Result<Self, Error> {
        let header = &record.header;
        let record_type = RecordType::from(
            text(header, Field::WarcType)?.ok_or(Error::InvalidField(Field::WarcType))?,
        );
        let record_date = date(header, Field::Date)?.ok_or(Error::InvalidField(Field::Date))?;
        if let Some(field) = [
            Field::SegmentNumber,
            Field::SegmentOriginID,
            Field::SegmentTotalLength,
        ]
        .into_iter()
        .find(|field| {
            header
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(field.standard_name()))
        }) {
            return Err(Error::Segmented(field));
        }
        let original = if matches!(record_type, RecordType::Revisit) {
            Some(Original {
                date: date_bytes(
                    date(header, Field::RefersToDate)?
                        .ok_or(Error::InvalidField(Field::RefersToDate))?,
                    Field::RefersToDate,
                )?,
                target_uri: uri(header, Field::RefersToTargetURI)?
                    .ok_or(Error::InvalidField(Field::RefersToTargetURI))?,
            })
        } else {
            None
        };
        Self::from_parts(
            &record_type,
            record_date,
            uri(header, Field::TargetURI)?,
            &record.body,
            original,
        )
    }
}

fn value(header: &raw::RecordHeader, field: Field) -> Result<Option<&[u8]>, Error> {
    let mut values = header
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(field.standard_name()));
    let first = values.next().map(|(_, value)| value.as_slice());
    if values.next().is_some() {
        return Err(Error::RepeatedField(field));
    }
    Ok(first)
}

fn text(header: &raw::RecordHeader, field: Field) -> Result<Option<&str>, Error> {
    value(header, field)?
        .map(|value| {
            std::str::from_utf8(value.trim_ascii()).map_err(|_| Error::InvalidField(field))
        })
        .transpose()
}

fn date(header: &raw::RecordHeader, field: Field) -> Result<Option<WarcDate>, Error> {
    text(header, field)?
        .map(|value| WarcDate::parse(value, header.version).ok_or(Error::InvalidField(field)))
        .transpose()
}

fn uri(header: &raw::RecordHeader, field: Field) -> Result<Option<&str>, Error> {
    value(header, field)?
        .map(|value| {
            let value = value.trim_ascii();
            let value = value
                .strip_prefix(b"<")
                .and_then(|value| value.strip_suffix(b">"))
                .unwrap_or(value);
            let value = std::str::from_utf8(value).map_err(|_| Error::InvalidField(field))?;
            Uri::parse(value).map_err(|_| Error::InvalidField(field))?;
            Ok(value)
        })
        .transpose()
}
