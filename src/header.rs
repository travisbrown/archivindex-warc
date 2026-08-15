use std::fmt::Display;

use crate::WarcVersion;

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
    /// The header's serialized field name: the standard name lower-cased for known headers,
    /// or the stored name for unknown ones. Borrowing this beats `to_string` on hot write
    /// paths, which would otherwise allocate per header line.
    #[must_use]
    pub fn name(&self) -> &str {
        self.names().0
    }

    /// The header's field name as the standard itself prints it, which is the spelling
    /// archives overwhelmingly use. An unknown name has only the spelling it was parsed
    /// with, which is already lower-cased.
    #[must_use]
    pub fn standard_name(&self) -> &str {
        self.names().1
    }

    /// Both spellings of the field name, as `(lower-case, standard)`. Keeping them in one
    /// table is what stops them from drifting apart.
    fn names(&self) -> (&str, &str) {
        match self {
            Self::ContentLength => ("content-length", "Content-Length"),
            Self::ContentType => ("content-type", "Content-Type"),
            Self::BlockDigest => ("warc-block-digest", "WARC-Block-Digest"),
            Self::ConcurrentTo => ("warc-concurrent-to", "WARC-Concurrent-To"),
            Self::Date => ("warc-date", "WARC-Date"),
            Self::Filename => ("warc-filename", "WARC-Filename"),
            Self::IdentifiedPayloadType => (
                "warc-identified-payload-type",
                "WARC-Identified-Payload-Type",
            ),
            Self::IPAddress => ("warc-ip-address", "WARC-IP-Address"),
            Self::PayloadDigest => ("warc-payload-digest", "WARC-Payload-Digest"),
            Self::Profile => ("warc-profile", "WARC-Profile"),
            Self::RecordID => ("warc-record-id", "WARC-Record-ID"),
            Self::RefersTo => ("warc-refers-to", "WARC-Refers-To"),
            Self::RefersToDate => ("warc-refers-to-date", "WARC-Refers-To-Date"),
            Self::RefersToTargetURI => ("warc-refers-to-target-uri", "WARC-Refers-To-Target-URI"),
            Self::SegmentNumber => ("warc-segment-number", "WARC-Segment-Number"),
            Self::SegmentOriginID => ("warc-segment-origin-id", "WARC-Segment-Origin-ID"),
            Self::SegmentTotalLength => ("warc-segment-total-length", "WARC-Segment-Total-Length"),
            Self::TargetURI => ("warc-target-uri", "WARC-Target-URI"),
            Self::Truncated => ("warc-truncated", "WARC-Truncated"),
            Self::WarcType => ("warc-type", "WARC-Type"),
            Self::WarcInfoID => ("warc-warcinfo-id", "WARC-Warcinfo-ID"),
            Self::Unknown(string) => (string, string),
        }
    }

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

    /// This field's position in the conventional ordering of a header block, which
    /// [`RawRecordHeader::canonical_order`](crate::RawRecordHeader::canonical_order) sorts
    /// into. Every field the standard does not name shares the one rank past the last of
    /// those it does, so extension fields sort after them and among themselves not at all.
    pub(crate) fn canonical_rank(&self) -> usize {
        KNOWN_HEADERS
            .iter()
            .position(|header| header == self)
            .unwrap_or(KNOWN_HEADERS.len())
    }

    /// Return whether this field name is permitted by the given WARC version.
    ///
    /// WARC 1.0 permits extension fields, so unknown names are accepted. The two fields
    /// standardized for the first time in WARC 1.1 are rejected only when recognized as
    /// their well-known variants.
    pub(crate) const fn is_allowed_in(&self, version: WarcVersion) -> bool {
        !matches!(
            (version, self),
            (
                WarcVersion::V1_0,
                Self::RefersToDate | Self::RefersToTargetURI
            )
        )
    }
}

impl Display for WarcHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Every field the standard names, in the order a header block conventionally prints them:
/// what the record is and what it describes first, the segmentation and integrity fields
/// next, and the fields describing the block itself last.
///
/// This is both the table `From<S>` looks a name up in and the ordering
/// [`WarcHeader::canonical_rank`] reports, so the two cannot drift apart. The names
/// themselves live on `WarcHeader::names`, so this list carries only the variants.
const KNOWN_HEADERS: [WarcHeader; 21] = [
    WarcHeader::WarcType,
    WarcHeader::TargetURI,
    WarcHeader::Date,
    WarcHeader::Profile,
    WarcHeader::RecordID,
    WarcHeader::WarcInfoID,
    WarcHeader::Filename,
    WarcHeader::RefersTo,
    WarcHeader::RefersToTargetURI,
    WarcHeader::RefersToDate,
    WarcHeader::BlockDigest,
    WarcHeader::PayloadDigest,
    WarcHeader::SegmentNumber,
    WarcHeader::SegmentOriginID,
    WarcHeader::SegmentTotalLength,
    WarcHeader::IPAddress,
    WarcHeader::ConcurrentTo,
    WarcHeader::ContentType,
    WarcHeader::IdentifiedPayloadType,
    WarcHeader::ContentLength,
    WarcHeader::Truncated,
];

impl<S: AsRef<str>> From<S> for WarcHeader {
    fn from(string: S) -> Self {
        let string = string.as_ref();
        KNOWN_HEADERS
            .iter()
            .find(|header| string.eq_ignore_ascii_case(header.name()))
            .map_or_else(|| Self::Unknown(string.to_lowercase()), Clone::clone)
    }
}

/// How a field name was spelled in the record it was read from.
///
/// The two spellings archives actually use are held as tags rather than strings, so reading a
/// record allocates nothing for its field names.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Spelling {
    /// The lower-case name, as [`WarcHeader::name`] renders it.
    Lower,
    /// The name as the standard prints it, as [`WarcHeader::standard_name`] renders it.
    Standard,
    /// Any other mixture of cases, held as it was read.
    Other(Box<str>),
}

/// A field name as it appeared in a record's header block.
///
/// WARC field names are case-insensitive, so a name is identified by the field it denotes:
/// two names that differ only in spelling are equal. The spelling is carried alongside so
/// that a record read from an archive can be written back out with its field names unchanged.
///
/// ```
/// use archivindex_warc::{FieldName, WarcHeader};
///
/// let as_read = FieldName::as_read("WARC-Target-URI");
/// assert_eq!(as_read.header(), &WarcHeader::TargetURI);
/// assert_eq!(as_read.name(), "WARC-Target-URI");
///
/// // The two spell the same field, so they are the same name.
/// assert_eq!(as_read, FieldName::new(WarcHeader::TargetURI));
/// assert_eq!(FieldName::new(WarcHeader::TargetURI).name(), "warc-target-uri");
/// ```
#[derive(Clone, Debug, Eq)]
pub struct FieldName {
    header: WarcHeader,
    spelling: Spelling,
}

impl FieldName {
    /// A field name in its lower-case spelling.
    #[must_use]
    pub const fn new(header: WarcHeader) -> Self {
        Self {
            header,
            spelling: Spelling::Lower,
        }
    }

    /// A field name spelled as it appeared in an archive.
    #[must_use]
    pub fn as_read(name: &str) -> Self {
        let header = WarcHeader::from(name);
        let (lower, standard) = header.names();
        let spelling = if name == lower {
            Spelling::Lower
        } else if name == standard {
            Spelling::Standard
        } else {
            Spelling::Other(Box::from(name))
        };

        Self { header, spelling }
    }

    /// The field this name denotes.
    #[must_use]
    pub const fn header(&self) -> &WarcHeader {
        &self.header
    }

    /// The name as it will be serialized: the spelling it was read with, or the lower-case
    /// name for a field named by its variant.
    #[must_use]
    pub fn name(&self) -> &str {
        match &self.spelling {
            Spelling::Lower => self.header.name(),
            Spelling::Standard => self.header.standard_name(),
            Spelling::Other(name) => name,
        }
    }

    /// Consume this name, returning the field it denotes.
    #[must_use]
    pub fn into_header(self) -> WarcHeader {
        self.header
    }

    /// Fold an `Unknown` spelling of a well-known field name into that field's variant,
    /// keeping the name as it would be serialized. See [`WarcHeader::normalized`].
    pub fn normalize(&mut self) {
        if matches!(self.header, WarcHeader::Unknown(_)) {
            *self = Self::as_read(self.name());
        }
    }
}

/// Names are compared by the field they denote, since WARC field names are case-insensitive.
impl PartialEq for FieldName {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
    }
}

impl From<WarcHeader> for FieldName {
    fn from(header: WarcHeader) -> Self {
        Self::new(header)
    }
}

impl Display for FieldName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldName, WarcHeader};
    use crate::WarcVersion;

    /// A name is written back out with the spelling it was read with, whichever of the three
    /// forms that spelling takes.
    #[test]
    fn field_name_keeps_the_spelling_it_was_read_with() {
        for name in [
            "warc-target-uri",
            "WARC-Target-URI",
            "Warc-Target-Uri",
            "WARC-TARGET-URI",
        ] {
            let field_name = FieldName::as_read(name);
            assert_eq!(field_name.name(), name);
            assert_eq!(field_name.header(), &WarcHeader::TargetURI);
        }
    }

    /// Field names are case-insensitive, so names that differ only in spelling are equal,
    /// while a name built from its variant serializes lower-case.
    #[test]
    fn field_names_are_equal_whatever_their_spelling() {
        assert_eq!(
            FieldName::as_read("Warc-Type"),
            FieldName::new(WarcHeader::WarcType)
        );
        assert_eq!(FieldName::new(WarcHeader::WarcType).name(), "warc-type");
    }

    /// An unrecognized name is kept as it was spelled but denotes the lower-cased field, so
    /// two spellings of one extension field are still the same field.
    #[test]
    fn unknown_field_names_are_matched_case_insensitively() {
        let field_name = FieldName::as_read("X-Extension");
        assert_eq!(field_name.name(), "X-Extension");
        assert_eq!(
            field_name.header(),
            &WarcHeader::Unknown("x-extension".to_string())
        );
        assert_eq!(field_name, FieldName::as_read("x-extension"));
    }

    /// Normalizing folds a hand-built `Unknown` spelling of a well-known field into that
    /// field's variant, leaving the spelling alone.
    #[test]
    fn normalizing_a_field_name_folds_unknown_spellings() {
        let mut field_name = FieldName::new(WarcHeader::Unknown("WARC-Target-URI".to_string()));
        field_name.normalize();

        assert_eq!(field_name.header(), &WarcHeader::TargetURI);
        assert_eq!(field_name.name(), "WARC-Target-URI");
    }

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

    /// The fields added in WARC 1.1 are version-specific, while WARC 1.0 extension fields
    /// remain permitted.
    #[test]
    fn warc_1_1_headers_are_not_allowed_in_warc_1_0() {
        for header in [WarcHeader::RefersToDate, WarcHeader::RefersToTargetURI] {
            assert!(!header.is_allowed_in(WarcVersion::V1_0));
            assert!(header.is_allowed_in(WarcVersion::V1_1));
        }

        let extension = WarcHeader::Unknown("x-extension".to_string());
        assert!(extension.is_allowed_in(WarcVersion::V1_0));
        assert!(extension.is_allowed_in(WarcVersion::V1_1));
    }
}
