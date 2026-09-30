//! Record types defined by the WARC standard or an extension.

use std::fmt::Display;

/// The value of a record's `WARC-Type` field.
///
/// Names are compared without regard to case. Unknown names are normalized to lowercase and
/// preserved in [`Self::Unknown`].
///
/// The canonical order is warcinfo, request, response, metadata, revisit, resource, conversion,
/// continuation, then unknown types ordered by name. This order classifies record types; it does
/// not require records in a WARC file to be sorted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordType {
    /// A description of the records that follow it, up to the next `warcinfo` record or the end of
    /// the file.
    Warcinfo,
    /// A complete scheme-specific request, including protocol information.
    Request,
    /// A complete scheme-specific response, including protocol information where the scheme has
    /// any.
    Response,
    /// Content describing another record, in a way no other record type covers.
    Metadata,
    /// A record standing in for content found to duplicate content already archived.
    Revisit,
    /// A resource captured without the protocol information a `response` carries.
    Resource,
    /// An alternative version of another record's content, produced by an archival process.
    Conversion,
    /// A later segment of a block too large to be held in one record.
    Continuation,
    /// A type the standard does not define, held under the name it was written with, lower-cased.
    Unknown(String),
}

impl RecordType {
    /// The zero-based position in the canonical record-type order.
    ///
    /// Standard types have stable ranks from 0 through 7. All unknown types have rank 8;
    /// [`Ord`] additionally compares their names. The archiver uses the rank plus one as the
    /// type byte in its record ID scheme.
    #[must_use]
    pub const fn canonical_rank(&self) -> u8 {
        match self {
            Self::Warcinfo => 0,
            Self::Request => 1,
            Self::Response => 2,
            Self::Metadata => 3,
            Self::Revisit => 4,
            Self::Resource => 5,
            Self::Conversion => 6,
            Self::Continuation => 7,
            Self::Unknown(_) => 8,
        }
    }

    /// The name used to serialize this value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Warcinfo => "warcinfo",
            Self::Request => "request",
            Self::Response => "response",
            Self::Metadata => "metadata",
            Self::Revisit => "revisit",
            Self::Resource => "resource",
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
    ("request", RecordType::Request),
    ("response", RecordType::Response),
    ("metadata", RecordType::Metadata),
    ("revisit", RecordType::Revisit),
    ("resource", RecordType::Resource),
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

#[cfg(test)]
mod tests {
    use super::RecordType;

    #[test]
    fn canonical_order_and_stable_ranks() {
        let names = [
            "warcinfo",
            "request",
            "response",
            "metadata",
            "revisit",
            "resource",
            "conversion",
            "continuation",
            "x-first",
            "x-last",
        ];
        let expected = names.map(RecordType::from);
        let mut sorted = expected.clone();
        sorted.reverse();
        sorted.sort();
        assert_eq!(sorted, expected);
        for (record_type, rank) in expected.iter().zip([0, 1, 2, 3, 4, 5, 6, 7, 8, 8]) {
            assert_eq!(record_type.canonical_rank(), rank);
        }
    }
}
