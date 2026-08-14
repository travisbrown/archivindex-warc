use std::fmt::Display;

#[cfg(feature = "with_serde")]
use serde::{Deserialize, Serialize};
/// Represents a WARC header defined by the standard.
///
/// All headers are camel-case versions of the standard names, with the hyphens removed.
#[allow(missing_docs)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "with_serde", serde(into = "String"))]
#[cfg_attr(feature = "with_serde", serde(from = "String"))]
pub enum WarcHeader {
    ContentLength,
    ContentType,
    BlockDigest,
    ConcurrentTo,
    Date,
    Filename,
    IdentifiedPayloadType,
    IPAddress,
    PayloadDigest,
    Profile,
    RecordID,
    RefersTo,
    SegmentNumber,
    SegmentOriginID,
    SegmentTotalLength,
    TargetURI,
    Truncated,
    WarcType,
    WarcInfoID,
    Unknown(String),
}

impl From<WarcHeader> for String {
    fn from(header: WarcHeader) -> Self {
        header.to_string()
    }
}

impl WarcHeader {
    /// Fold an `Unknown` spelling of a well-known field name (in any case) into that field's
    /// variant, and lower-case genuinely unknown names, exactly as parsing does. This keeps
    /// `Unknown("warc-date")` from bypassing the lookups and interception keyed on the
    /// well-known variants.
    pub fn normalized(self) -> Self {
        match self {
            WarcHeader::Unknown(name) => WarcHeader::from(name.as_str()),
            header => header,
        }
    }
}

impl Display for WarcHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stringified = match self {
            WarcHeader::ContentLength => "content-length",
            WarcHeader::ContentType => "content-type",
            WarcHeader::BlockDigest => "warc-block-digest",
            WarcHeader::ConcurrentTo => "warc-concurrent-to",
            WarcHeader::Date => "warc-date",
            WarcHeader::Filename => "warc-filename",
            WarcHeader::IdentifiedPayloadType => "warc-identified-payload-type",
            WarcHeader::IPAddress => "warc-ip-address",
            WarcHeader::PayloadDigest => "warc-payload-digest",
            WarcHeader::Profile => "warc-profile",
            WarcHeader::RecordID => "warc-record-id",
            WarcHeader::RefersTo => "warc-refers-to",
            WarcHeader::SegmentNumber => "warc-segment-number",
            WarcHeader::SegmentOriginID => "warc-segment-origin-id",
            WarcHeader::SegmentTotalLength => "warc-segment-total-length",
            WarcHeader::TargetURI => "warc-target-uri",
            WarcHeader::Truncated => "warc-truncated",
            WarcHeader::WarcType => "warc-type",
            WarcHeader::WarcInfoID => "warc-warcinfo-id",
            WarcHeader::Unknown(string) => string,
        };
        write!(f, "{}", stringified)
    }
}

const KNOWN_HEADERS: [(&str, WarcHeader); 19] = [
    ("content-length", WarcHeader::ContentLength),
    ("content-type", WarcHeader::ContentType),
    ("warc-block-digest", WarcHeader::BlockDigest),
    ("warc-concurrent-to", WarcHeader::ConcurrentTo),
    ("warc-date", WarcHeader::Date),
    ("warc-filename", WarcHeader::Filename),
    (
        "warc-identified-payload-type",
        WarcHeader::IdentifiedPayloadType,
    ),
    ("warc-ip-address", WarcHeader::IPAddress),
    ("warc-payload-digest", WarcHeader::PayloadDigest),
    ("warc-profile", WarcHeader::Profile),
    ("warc-record-id", WarcHeader::RecordID),
    ("warc-refers-to", WarcHeader::RefersTo),
    ("warc-segment-number", WarcHeader::SegmentNumber),
    ("warc-segment-origin-id", WarcHeader::SegmentOriginID),
    ("warc-segment-total-length", WarcHeader::SegmentTotalLength),
    ("warc-target-uri", WarcHeader::TargetURI),
    ("warc-truncated", WarcHeader::Truncated),
    ("warc-type", WarcHeader::WarcType),
    ("warc-warcinfo-id", WarcHeader::WarcInfoID),
];

impl<S: AsRef<str>> From<S> for WarcHeader {
    fn from(string: S) -> Self {
        let string = string.as_ref();
        KNOWN_HEADERS
            .iter()
            .find(|(name, _)| string.eq_ignore_ascii_case(name))
            .map(|(_, header)| header.clone())
            .unwrap_or_else(|| WarcHeader::Unknown(string.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    /// The `with_serde` derives round-trip headers through their string names.
    #[cfg(feature = "with_serde")]
    #[test]
    fn serde_round_trip() {
        use super::WarcHeader;

        for header in [
            WarcHeader::ContentLength,
            WarcHeader::TargetURI,
            WarcHeader::Unknown("x-custom".to_string()),
        ] {
            let encoded = serde_json::to_string(&header).unwrap();
            assert_eq!(encoded, format!("\"{header}\""));
            assert_eq!(
                serde_json::from_str::<WarcHeader>(&encoded).unwrap(),
                header
            );
        }

        // Deserialization goes through `From<String>`, so names are normalized like any
        // other header-name conversion.
        assert_eq!(
            serde_json::from_str::<WarcHeader>("\"WARC-Type\"").unwrap(),
            WarcHeader::WarcType
        );
    }
}
