//! Parse the identity fields while leaving unrelated raw headers alone.

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::record_type::RecordType;
use archivindex_warc::value::WarcDate;
use fluent_uri::Uri;

use super::{Error, Identity, date_bytes};

pub(super) fn identity(record: &raw::Record) -> Result<Identity, Error> {
    let header = &record.header;
    let record_type = text(header, Field::WarcType)?.ok_or(Error::InvalidField(Field::WarcType))?;
    let record_date = date(header, Field::Date)?.ok_or(Error::InvalidField(Field::Date))?;
    let mut identity = Identity::new(&RecordType::from(record_type), record_date, &record.body)?;
    identity.optional(1, uri(header, Field::TargetURI)?.map(str::as_bytes));
    for (tag, field) in [(2, Field::SegmentNumber), (3, Field::SegmentTotalLength)] {
        if let Some(value) = text(header, field)? {
            let number = value
                .parse::<u64>()
                .ok()
                .filter(|_| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                .filter(|number| field != Field::SegmentNumber || *number > 0)
                .ok_or(Error::InvalidField(field))?;
            identity.field(tag, &number.to_be_bytes());
        }
    }
    identity.optional(4, uri(header, Field::Profile)?.map(str::as_bytes));
    identity.optional(5, uri(header, Field::RefersToTargetURI)?.map(str::as_bytes));
    identity.optional(6, date(header, Field::RefersToDate)?.map(date_bytes));
    for (tag, field) in [
        (7, Field::WarcinfoID),
        (9, Field::RefersTo),
        (10, Field::SegmentOriginID),
    ] {
        if let Some(value) = uri(header, field)? {
            identity.reference(tag, value);
        }
    }
    for (_, value) in header
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(Field::ConcurrentTo.standard_name()))
    {
        identity.reference(8, parse_uri(value, Field::ConcurrentTo)?);
    }
    Ok(identity)
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
        .map(|value| parse_uri(value, field))
        .transpose()
}

fn parse_uri(value: &[u8], field: Field) -> Result<&str, Error> {
    let value = value.trim_ascii();
    let value = value
        .strip_prefix(b"<")
        .and_then(|value| value.strip_suffix(b">"))
        .unwrap_or(value);
    let value = std::str::from_utf8(value).map_err(|_| Error::InvalidField(field))?;
    Uri::parse(value).map_err(|_| Error::InvalidField(field))?;
    Ok(value)
}
