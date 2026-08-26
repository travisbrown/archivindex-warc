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
    header
        .get("WARC-Type")
        .is_some_and(|value| value.trim_ascii().eq_ignore_ascii_case(b"warcinfo"))
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

    use super::{is_warcinfo, normalize_id};

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
    }
}
