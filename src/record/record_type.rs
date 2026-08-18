//! Record types defined by the WARC standard or an extension.

use std::fmt::Display;

/// The value of a record's `WARC-Type` field.
///
/// Names are compared without regard to case. Unknown names are normalized to lowercase and
/// preserved in [`Self::Unknown`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// A description of the records that follow it, up to the next `warcinfo` record or the
    /// end of the file.
    Warcinfo,
    /// A complete scheme-specific response, including protocol information where the scheme
    /// has any.
    Response,
    /// A resource captured without the protocol information a `response` carries.
    Resource,
    /// A complete scheme-specific request, including protocol information.
    Request,
    /// Content describing another record, in a way no other record type covers.
    Metadata,
    /// A record standing in for content found to duplicate content already archived.
    Revisit,
    /// An alternative version of another record's content, produced by an archival process.
    Conversion,
    /// A later segment of a block too large to be held in one record.
    Continuation,
    /// A type the standard does not define, held under the name it was written with,
    /// lower-cased.
    Unknown(String),
}

impl RecordType {
    /// The name used to serialize this value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Warcinfo => "warcinfo",
            Self::Response => "response",
            Self::Resource => "resource",
            Self::Request => "request",
            Self::Metadata => "metadata",
            Self::Revisit => "revisit",
            Self::Conversion => "conversion",
            Self::Continuation => "continuation",
            Self::Unknown(val) => val,
        }
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The record types defined by the standard.
const KNOWN_TYPES: [(&str, RecordType); 8] = [
    ("warcinfo", RecordType::Warcinfo),
    ("response", RecordType::Response),
    ("resource", RecordType::Resource),
    ("request", RecordType::Request),
    ("metadata", RecordType::Metadata),
    ("revisit", RecordType::Revisit),
    ("conversion", RecordType::Conversion),
    ("continuation", RecordType::Continuation),
];

/// Parse a record type without regard to case.
impl<S: AsRef<str>> From<S> for RecordType {
    fn from(string: S) -> Self {
        let string = string.as_ref();
        KNOWN_TYPES
            .iter()
            .find(|(name, _)| string.eq_ignore_ascii_case(name))
            .map_or_else(
                || Self::Unknown(string.to_lowercase()),
                |(_, record_type)| record_type.clone(),
            )
    }
}
