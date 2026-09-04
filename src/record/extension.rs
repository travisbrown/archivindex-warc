//! Support for WARC extensions.
//!
//! The WARC standard allows extensions to define record types, header fields, and truncation
//! reasons. [`Extension`] describes such a vocabulary at compile time. Use [`NoExtension`] for
//! the core format alone.

use std::fmt::Debug;

/// A vocabulary of record types and named fields layered on top of the core WARC format.
///
/// Implementations are marker types. Each associated field type contains the fields added to one
/// core record type. Use `()` where the extension adds no fields.
pub trait Extension: Clone + Debug + Eq {
    /// The record types the extension defines.
    ///
    /// Use [`Never`] if it defines none. Fields on extension record types remain untyped in
    /// [`CoreHeaders::unrecognized`](crate::record::header::CoreHeaders::unrecognized).
    type Types: ExtensionRecordType;

    /// The truncation reasons the extension defines.
    ///
    /// Use [`Never`] if it defines none.
    type TruncatedReasons: ExtensionTruncatedReason;

    /// The fields the extension adds to a `warcinfo` record.
    type WarcinfoFields: ExtensionFields;

    /// The fields the extension adds to a `response` record.
    type ResponseFields: ExtensionFields;

    /// The fields the extension adds to a `resource` record.
    type ResourceFields: ExtensionFields;

    /// The fields the extension adds to a `request` record.
    type RequestFields: ExtensionFields;

    /// The fields the extension adds to a `metadata` record.
    type MetadataFields: ExtensionFields;

    /// The fields the extension adds to a `revisit` record.
    type RevisitFields: ExtensionFields;

    /// The fields the extension adds to a `conversion` record.
    type ConversionFields: ExtensionFields;

    /// The fields the extension adds to a `continuation` record.
    type ContinuationFields: ExtensionFields;
}

/// The fields an extension adds to one of the core record types.
///
/// During reading, an extension claims its fields from the lines not recognized by the standard.
/// Unclaimed fields remain in
/// [`CoreHeaders::unrecognized`](crate::record::header::CoreHeaders::unrecognized). During
/// writing, the extension appends its field lines. The `()` implementation claims and appends
/// nothing.
pub trait ExtensionFields: Clone + Debug + Eq {
    /// Claim and parse the extension's fields from the remaining header lines.
    ///
    /// Lines left unclaimed remain in
    /// [`CoreHeaders::unrecognized`](crate::record::header::CoreHeaders::unrecognized).
    ///
    /// # Errors
    ///
    /// Returns a [`crate::record::Error`] for a malformed or missing extension field.
    fn from_unclaimed(fields: &mut Unclaimed<'_>) -> Result<Self, crate::record::Error>;

    /// Append these fields as header lines, in their desired order.
    ///
    /// These lines are rendered after the fields defined by the standard.
    fn append_to(&self, fields: &mut Vec<(String, String)>);
}

impl ExtensionFields for () {
    fn from_unclaimed(_fields: &mut Unclaimed<'_>) -> Result<Self, crate::record::Error> {
        Ok(())
    }

    fn append_to(&self, _fields: &mut Vec<(String, String)>) {}
}

/// The header lines of a record that no vocabulary has claimed yet.
#[derive(Debug)]
pub struct Unclaimed<'a> {
    /// The remaining `(name, value)` lines, in order and with their original names.
    fields: &'a mut Vec<(String, String)>,
}

impl<'a> Unclaimed<'a> {
    /// Create a view over the remaining header lines.
    pub(crate) const fn new(fields: &'a mut Vec<(String, String)>) -> Self {
        Self { fields }
    }

    /// Remove every field with this name and return its values in order.
    ///
    /// Names are compared without regard to case. All occurrences are removed, so the extension
    /// decides whether repetition is valid. An empty result means the field is absent.
    pub fn claim(&mut self, name: &str) -> Vec<String> {
        let mut claimed = Vec::new();
        // Move each value out of its line to avoid cloning it.
        self.fields.retain_mut(|(stored, value)| {
            if stored.eq_ignore_ascii_case(name) {
                claimed.push(std::mem::take(value));
                false
            } else {
                true
            }
        });

        claimed
    }

    /// Return the values for this name in order without claiming them.
    #[must_use]
    pub fn get(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(stored, _)| stored.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Iterate over the remaining names in order, yielding repeated names only once.
    ///
    /// Names are compared without regard to case. The spelling comes from the first occurrence.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.fields
            .iter()
            .enumerate()
            .filter(|(index, (name, _))| {
                self.fields[..*index]
                    .iter()
                    .all(|(earlier, _)| !earlier.eq_ignore_ascii_case(name))
            })
            .map(|(_, (name, _))| name.as_str())
    }
}

/// A record type defined by an extension.
pub trait ExtensionRecordType: Clone + Debug + Eq {
    /// The value this record's `WARC-Type` field carries.
    ///
    /// This is the spelling used when writing. It must not name a standard record type.
    fn type_name(&self) -> &str;

    /// Parse an extension record type, or return `None` if the name is not recognized.
    ///
    /// The name is lowercase. Standard record types are handled before this method is called.
    fn from_type_name(name: &str) -> Option<Self>;
}

/// A truncation reason defined by an extension.
pub trait ExtensionTruncatedReason: Clone + Debug + Eq {
    /// The token this reason's `WARC-Truncated` field carries.
    fn reason_token(&self) -> &str;

    /// Parse an extension truncation reason, or return `None` if it is not recognized.
    ///
    /// Standard reasons are handled before this method is called. Tokens are case-insensitive.
    fn from_reason_token(token: &str) -> Option<Self>;
}

/// An uninhabited type for extensions that define no values of an associated type.
///
/// This stands in for `!`, which is not yet stable as an ordinary type.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum Never {}

impl ExtensionRecordType for Never {
    #[expect(
        clippy::uninhabited_references,
        reason = "dereferencing proves the method unreachable, since `Never` has no values"
    )]
    fn type_name(&self) -> &str {
        match *self {}
    }

    fn from_type_name(_name: &str) -> Option<Self> {
        None
    }
}

impl ExtensionTruncatedReason for Never {
    #[expect(
        clippy::uninhabited_references,
        reason = "dereferencing proves the method unreachable, since `Never` has no values"
    )]
    fn reason_token(&self) -> &str {
        match *self {}
    }

    fn from_reason_token(_token: &str) -> Option<Self> {
        None
    }
}

/// The extension that adds nothing: the core WARC format on its own.
#[derive(Clone, Copy, Debug, Default, Hash, Eq, PartialEq)]
pub struct NoExtension;

impl Extension for NoExtension {
    type Types = Never;
    type TruncatedReasons = Never;
    type WarcinfoFields = ();
    type ResponseFields = ();
    type ResourceFields = ();
    type RequestFields = ();
    type MetadataFields = ();
    type RevisitFields = ();
    type ConversionFields = ();
    type ContinuationFields = ();
}

#[cfg(test)]
mod unclaimed_tests {
    use super::Unclaimed;

    /// Header lines with one field repeated under two spellings.
    fn lines() -> Vec<(String, String)> {
        [
            ("X-Crawl-Id", "crawl-7"),
            ("X-Other", "kept"),
            ("x-crawl-id", "crawl-8"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    #[test]
    fn claiming_takes_every_line_naming_the_field() {
        let mut lines = lines();
        let mut unclaimed = Unclaimed::new(&mut lines);

        assert_eq!(unclaimed.claim("X-CRAWL-ID"), ["crawl-7", "crawl-8"]);
        assert_eq!(unclaimed.claim("x-crawl-id"), Vec::<String>::new());

        assert_eq!(lines, [("X-Other".to_owned(), "kept".to_owned())]);
    }

    #[test]
    fn getting_leaves_every_line_where_it_is() {
        let mut lines = lines();
        let unclaimed = Unclaimed::new(&mut lines);

        assert_eq!(unclaimed.get("x-crawl-id"), ["crawl-7", "crawl-8"]);
        assert_eq!(unclaimed.get("x-absent"), Vec::<&str>::new());

        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn iterating_names_a_repeated_field_once() {
        let mut lines = lines();
        let mut unclaimed = Unclaimed::new(&mut lines);

        assert_eq!(
            unclaimed.iter().collect::<Vec<_>>(),
            ["X-Crawl-Id", "X-Other"]
        );

        unclaimed.claim("x-crawl-id");
        assert_eq!(unclaimed.iter().collect::<Vec<_>>(), ["X-Other"]);
    }
}
