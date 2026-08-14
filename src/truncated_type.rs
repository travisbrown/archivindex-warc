#![allow(missing_docs)]

use std::fmt::Display;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TruncatedType {
    Length,
    Time,
    Disconnect,
    Unspecified,
    Unknown(String),
}

impl Display for TruncatedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stringified = match *self {
            Self::Length => "length",
            Self::Time => "time",
            Self::Disconnect => "disconnect",
            Self::Unspecified => "unspecified",
            Self::Unknown(ref val) => val.as_ref(),
        };
        f.write_str(stringified)
    }
}

const KNOWN_TYPES: [(&str, TruncatedType); 4] = [
    ("length", TruncatedType::Length),
    ("time", TruncatedType::Time),
    ("disconnect", TruncatedType::Disconnect),
    ("unspecified", TruncatedType::Unspecified),
];

impl<S: AsRef<str>> From<S> for TruncatedType {
    fn from(string: S) -> Self {
        let string = string.as_ref();
        KNOWN_TYPES
            .iter()
            .find(|(name, _)| string.eq_ignore_ascii_case(name))
            .map_or_else(
                || Self::Unknown(string.to_lowercase()),
                |(_, truncated_type)| truncated_type.clone(),
            )
    }
}
