use std::fmt::Display;

/// Represents a WARC header defined by the standard.
///
/// All headers are camel-case versions of the standard names, with the hyphens removed.
#[allow(missing_docs)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "String"))]
#[cfg_attr(feature = "serde", serde(from = "String"))]
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
    RefersToDate,
    RefersToTargetURI,
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
    #[must_use]
    pub fn normalized(self) -> Self {
        match self {
            Self::Unknown(name) => Self::from(name.as_str()),
            header => header,
        }
    }

    /// The header's serialized field name: the standard lower-case name for known headers,
    /// or the stored name for unknown ones. Borrowing this beats `to_string` on hot write
    /// paths, which would otherwise allocate per header line.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::ContentLength => "content-length",
            Self::ContentType => "content-type",
            Self::BlockDigest => "warc-block-digest",
            Self::ConcurrentTo => "warc-concurrent-to",
            Self::Date => "warc-date",
            Self::Filename => "warc-filename",
            Self::IdentifiedPayloadType => "warc-identified-payload-type",
            Self::IPAddress => "warc-ip-address",
            Self::PayloadDigest => "warc-payload-digest",
            Self::Profile => "warc-profile",
            Self::RecordID => "warc-record-id",
            Self::RefersTo => "warc-refers-to",
            Self::RefersToDate => "warc-refers-to-date",
            Self::RefersToTargetURI => "warc-refers-to-target-uri",
            Self::SegmentNumber => "warc-segment-number",
            Self::SegmentOriginID => "warc-segment-origin-id",
            Self::SegmentTotalLength => "warc-segment-total-length",
            Self::TargetURI => "warc-target-uri",
            Self::Truncated => "warc-truncated",
            Self::WarcType => "warc-type",
            Self::WarcInfoID => "warc-warcinfo-id",
            Self::Unknown(string) => string,
        }
    }
}

impl Display for WarcHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

const KNOWN_HEADERS: [(&str, WarcHeader); 21] = [
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
    ("warc-refers-to-date", WarcHeader::RefersToDate),
    ("warc-refers-to-target-uri", WarcHeader::RefersToTargetURI),
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
            .map_or_else(
                || Self::Unknown(string.to_lowercase()),
                |(_, header)| header.clone(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::WarcHeader;

    /// The `serde` derives round-trip headers through their string names.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip() {
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

    /// The named fields added in WARC 1.1 map in both directions.
    #[test]
    fn warc_1_1_headers_round_trip() {
        for (name, header) in [
            ("warc-refers-to-date", WarcHeader::RefersToDate),
            ("warc-refers-to-target-uri", WarcHeader::RefersToTargetURI),
        ] {
            assert_eq!(WarcHeader::from(name), header);
            assert_eq!(WarcHeader::from(name.to_uppercase().as_str()), header);
            assert_eq!(header.to_string(), name);
        }
    }
}
