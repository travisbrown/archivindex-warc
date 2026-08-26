//! Parsed values for WARC header fields.

mod date;
mod media_type;
mod text;

pub use archivindex_warc_digest as digest;
pub use date::{WarcDate, WarcDatePrecision};
pub use digest::algorithm::marker::{self, Supported};
pub use digest::algorithm::{self, Algorithm, Hasher};
pub use digest::{Encoding, Error as DigestError, LabelledDigest};
pub use media_type::{Error as MediaTypeError, MediaType, ParameterValue};
pub use text::{Error as TextError, Text};

pub use crate::parsing::QuotedStringError;

/// The rule a value did not match.
///
/// Variants name grammar rules because several fields can use the same rule.
/// [`parse::untyped::Error`](crate::parse::untyped::Error) adds the name of the field that carried
/// the value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A value is not the `1*DIGIT` its field's grammar calls for, or names a number beyond the
    /// unsigned 64-bit range.
    #[error("not a number: {0}")]
    Digits(String),
    /// A value is not a `token`: it is empty, or holds a control character or a separator.
    #[error("not a token: {0}")]
    Token(String),
    /// A value is not the `URI` of RFC 3986, or its angle brackets are unbalanced.
    #[error("not a URI: {0}")]
    Uri(String),
    /// A value is not a `labelled-digest` (an algorithm and a value separated by a colon).
    #[error(transparent)]
    Digest(#[from] DigestError),
    /// A value is not a `media-type`.
    #[error(transparent)]
    MediaType(#[from] MediaTypeError),
    /// A value is not an IPv4 or IPv6 address.
    #[error("not an IP address: {0}")]
    IpAddress(String),
    /// A value is not a `w3c-iso8601` timestamp.
    #[error("not a timestamp: {0}")]
    Date(String),
    /// A value is neither `TEXT` nor a `quoted-string`.
    #[error(transparent)]
    Text(#[from] TextError),
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::{Algorithm, DigestError, Error, MediaTypeError, TextError, digest};
    use crate::parsing::QuotedStringError;

    /// The digest crate remains available under the value-layer path.
    #[test]
    fn digest_crate_is_reexported() {
        assert_eq!(digest::algorithm::Algorithm::Sha1, Algorithm::Sha1);
    }

    /// A rule is named without the field whose value failed it, since the same rule serves
    /// several fields and [`crate::parse::untyped::Error`] is what supplies the name.
    #[test]
    fn each_error_names_the_rule_it_failed() {
        let expectations = [
            (Error::Digits("12 34".to_owned()), "not a number: 12 34"),
            (
                Error::Token("two words".to_owned()),
                "not a token: two words",
            ),
            (Error::Uri("not a uri".to_owned()), "not a URI: not a uri"),
            (
                Error::Digest(DigestError::MalformedValue {
                    digest: "sha1".to_owned(),
                }),
                "not a labelled digest: `sha1` is not a digest value",
            ),
            (
                Error::MediaType(MediaTypeError::NoSubtype {
                    value: "text".to_owned(),
                }),
                "not a media type: no `/` separating type from subtype in `text`",
            ),
            (
                Error::IpAddress("::garbage".to_owned()),
                "not an IP address: ::garbage",
            ),
            (
                Error::Date("yesterday".to_owned()),
                "not a timestamp: yesterday",
            ),
            (
                Error::Text(TextError::ControlCharacter {
                    value: "with\u{7}bell".to_owned(),
                    index: 4,
                }),
                "not text: a control character is written at byte 4 of `with\u{7}bell`",
            ),
        ];

        for (error, message) in expectations {
            assert_eq!(error.to_string(), message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    /// A value read against a rule written in terms of another reports that rule as its source.
    #[test]
    fn a_nested_rule_is_reported_as_a_source() {
        let error = Error::Text(TextError::QuotedString {
            value: "\"unterminated".to_owned(),
            source: QuotedStringError::Unterminated,
        });

        assert_eq!(
            error.to_string(),
            "not text: `\"unterminated` is not a quoted string, \
             since it does not open and close with a quote"
        );
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some("it does not open and close with a quote")
        );
    }
}
