#![allow(missing_docs)]

use std::fmt::Display;
#[derive(Clone, Debug, PartialEq)]
pub enum RecordType {
    WarcInfo,
    Response,
    Resource,
    Request,
    Metadata,
    Revisit,
    Conversion,
    Continuation,
    Unknown(String),
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stringified = match *self {
            RecordType::WarcInfo => "warcinfo",
            RecordType::Response => "response",
            RecordType::Resource => "resource",
            RecordType::Request => "request",
            RecordType::Metadata => "metadata",
            RecordType::Revisit => "revisit",
            RecordType::Conversion => "conversion",
            RecordType::Continuation => "continuation",
            RecordType::Unknown(ref val) => val.as_ref(),
        };
        f.write_str(stringified)
    }
}

const KNOWN_TYPES: [(&str, RecordType); 8] = [
    ("warcinfo", RecordType::WarcInfo),
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
            .map(|(_, record_type)| record_type.clone())
            .unwrap_or_else(|| RecordType::Unknown(string.to_lowercase()))
    }
}
