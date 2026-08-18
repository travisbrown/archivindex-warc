//! Parsed values for WARC header fields.

mod date;
mod digest;
mod media_type;
mod text;

pub use date::{WarcDate, WarcDatePrecision};
pub use digest::{DigestAlgorithm, DigestEncoding, LabelledDigest};
pub use media_type::{MediaType, ParameterValue};
pub use text::Text;

/// The rule a value did not match.
///
/// Variants name grammar rules because several fields can use the same rule.
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
    #[error("not a labelled digest: {0}")]
    Digest(String),
    /// A value is not a `media-type`.
    #[error("not a media type: {0}")]
    MediaType(String),
    /// A value is not an IPv4 or IPv6 address.
    #[error("not an IP address: {0}")]
    IpAddress(String),
    /// A value is not a `w3c-iso8601` timestamp.
    #[error("not a timestamp: {0}")]
    Date(String),
    /// A value is neither `TEXT` nor a `quoted-string`.
    #[error("not text: {0}")]
    Text(String),
}

/// Convert bytes already validated as ASCII into a string.
fn from_ascii(bytes: &[u8]) -> Box<str> {
    std::str::from_utf8(bytes)
        .expect("invariant violation: grammar admitted a non-ASCII byte")
        .into()
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::Error;

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
                Error::Digest("sha1".to_owned()),
                "not a labelled digest: sha1",
            ),
            (
                Error::MediaType("text".to_owned()),
                "not a media type: text",
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
                Error::Text("with\u{7}bell".to_owned()),
                "not text: with\u{7}bell",
            ),
        ];

        for (error, message) in expectations {
            assert_eq!(error.to_string(), message);
            assert!(error.source().is_none(), "{message}");
        }
    }
}
