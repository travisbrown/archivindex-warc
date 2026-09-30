//! Header fields read by more than one operation.

use std::collections::HashMap;
use std::path::Path;

use archivindex_warc::parse::raw;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::value::{Text, WarcDate};

/// Fields whose values are the identifiers of other records.
pub const REFERENCE_FIELDS: [&str; 4] = [
    "WARC-Warcinfo-ID",
    "WARC-Refers-To",
    "WARC-Concurrent-To",
    "WARC-Segment-Origin-ID",
];

/// Whether a header block declares the `warcinfo` record type.
#[must_use]
pub fn is_warcinfo(header: &raw::RecordHeader) -> bool {
    declares_type(header, b"warcinfo")
}

/// Whether a header block declares the `request` record type.
#[must_use]
pub fn is_request(header: &raw::RecordHeader) -> bool {
    declares_type(header, b"request")
}

/// Whether a header block declares the `response` record type.
#[must_use]
pub fn is_response(header: &raw::RecordHeader) -> bool {
    declares_type(header, b"response")
}

/// Whether a header block declares the `revisit` record type.
#[must_use]
pub fn is_revisit(header: &raw::RecordHeader) -> bool {
    declares_type(header, b"revisit")
}

/// Whether a header block's `WARC-Type` is `record_type`, ignoring case and surrounding space.
fn declares_type(header: &raw::RecordHeader, record_type: &[u8]) -> bool {
    header
        .get("WARC-Type")
        .is_some_and(|value| value.trim_ascii().eq_ignore_ascii_case(record_type))
}

/// A record identifier without its surrounding white space and angle brackets, for comparison.
#[must_use]
pub fn normalize_id(value: &[u8]) -> &[u8] {
    let value = value.trim_ascii();

    value
        .strip_prefix(b"<")
        .and_then(|inner| inner.strip_suffix(b">"))
        .unwrap_or(value)
}

/// The `WARC-Filename` value naming `output`, when its name can be written as one.
///
/// A name that is not valid UTF-8, or that no `TEXT` value can spell, has no accurate field value.
pub(crate) fn output_filename(output: &Path) -> Option<Vec<u8>> {
    let name = output.file_name()?.to_str()?;
    let spelled = Text::parse(name.as_bytes()).ok()?;
    let spelled = spelled.to_bytes();
    let mut value = Vec::with_capacity(spelled.len() + 1);
    value.push(b' ');
    value.extend_from_slice(&spelled);

    Some(value)
}

/// Name the file a warcinfo record is now in, dropping the field when it cannot be named.
///
/// WARC 1.1 clause 5.17 defines `WARC-Filename` as the name of the containing file, so a record
/// written into a different output cannot keep the name of the file it was read from.
pub(crate) fn set_filename(header: &mut raw::RecordHeader, filename: Option<&[u8]>) {
    header.headers.retain_mut(|(name, value)| {
        if !name.eq_ignore_ascii_case("WARC-Filename") {
            return true;
        }
        let Some(filename) = filename else {
            return false;
        };
        value.clear();
        value.extend_from_slice(filename);

        true
    });
}

/// Add `field` to a header block before the first field that follows it in conventional order.
///
/// A header whose fields are already in that order stays in it. Extension fields follow every
/// standard field.
pub fn insert_field(header: &mut raw::RecordHeader, field: Field, value: Vec<u8>) {
    let rank = field.canonical_rank();
    let position = header
        .headers
        .iter()
        .position(|(name, _)| {
            Field::from_name(name).is_none_or(|existing| existing.canonical_rank() > rank)
        })
        .unwrap_or(header.headers.len());

    header
        .headers
        .insert(position, (field.standard_name().to_owned(), value));
}

/// Replace each reference to a record named in `redirects` with the value it maps to.
///
/// Keys are normalized identifiers, as [`normalize_id`] writes them, and values are complete field
/// values, written as read. A reference to a record `redirects` does not name is left as it is.
pub fn redirect_references<S: std::hash::BuildHasher>(
    header: &mut raw::RecordHeader,
    redirects: &HashMap<Vec<u8>, Vec<u8>, S>,
) {
    if redirects.is_empty() {
        return;
    }

    for (name, value) in &mut header.headers {
        if REFERENCE_FIELDS
            .iter()
            .any(|field| name.eq_ignore_ascii_case(field))
            && let Some(replacement) = redirects.get(normalize_id(value))
        {
            value.clone_from(replacement);
        }
    }
}

/// The instant a record's `WARC-Date` declares, read under the version its header declares, when it
/// can be read.
#[must_use]
pub fn record_date(header: &raw::RecordHeader) -> Option<WarcDate> {
    let value = header.get("WARC-Date")?;
    let value = std::str::from_utf8(value.trim_ascii()).ok()?;

    WarcDate::parse(value, header.version)
}

#[cfg(test)]
mod tests {
    use archivindex_warc::parse::raw;

    use super::{Field, insert_field, is_response, is_revisit, is_warcinfo, normalize_id};

    #[test]
    fn strips_brackets_and_white_space() {
        assert_eq!(normalize_id(b" <urn:uuid:a> "), b"urn:uuid:a");
        assert_eq!(normalize_id(b"urn:uuid:a>"), b"urn:uuid:a>");
    }

    #[test]
    fn recognizes_warcinfo_by_type_ignoring_case_and_space() {
        let header = raw::RecordHeader::parse(
            b"WARC/1.1\r\nwarc-type:  WarcInfo \r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap()
        .0;

        assert!(is_warcinfo(&header));
        assert!(!is_response(&header));
        assert!(!is_revisit(&header));
    }

    #[test]
    fn places_the_field_before_the_first_that_follows_it_in_conventional_order() {
        let mut header = raw::RecordHeader::parse(
            b"WARC/1.1\r\nContent-Length: 0\r\nWARC-Type: revisit\r\n\
              WARC-Refers-To: <urn:uuid:1>\r\n\r\n",
        )
        .unwrap()
        .0;

        insert_field(
            &mut header,
            Field::IdentifiedPayloadType,
            b" text/plain".to_vec(),
        );

        assert_eq!(
            header
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            [
                "WARC-Identified-Payload-Type",
                "Content-Length",
                "WARC-Type",
                "WARC-Refers-To",
            ]
        );
    }
}
