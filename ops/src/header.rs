//! Header fields read by more than one operation.

use archivindex_warc::parse::raw;

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

#[cfg(test)]
mod tests {
    use archivindex_warc::parse::raw;

    use super::{is_response, is_revisit, is_warcinfo, normalize_id};

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
}
