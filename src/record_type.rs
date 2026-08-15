#![allow(missing_docs)]

use std::fmt::Display;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordType {
    Warcinfo,
    Response,
    Resource,
    Request,
    Metadata,
    Revisit,
    Conversion,
    Continuation,
    Unknown(String),
}

impl RecordType {
    /// The serialized form of this value, borrowing rather than allocating.
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
