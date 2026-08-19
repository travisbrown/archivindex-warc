//! The `TEXT` value carried by `WARC-Filename`.

use std::borrow::Cow;
use std::fmt::Display;

use crate::parsing::{QuotedStringError, is_text_char, lossy, unquote};

/// A `WARC-Filename` value, which the grammar writes either bare or in quotes.
///
/// ```text
/// WARC-Filename = "WARC-Filename" ":" ( TEXT | quoted-string )
/// TEXT          = <any OCTET except CTLs, but including LWS>
/// ```
///
/// `TEXT` admits any octet, and a file name is not necessarily valid UTF-8, so the content is held
/// as bytes rather than as text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Text {
    content: Box<[u8]>,
    quoted: bool,
}

/// The rule a `TEXT` or `quoted-string` value did not match.
///
/// Offsets are byte positions in the value as it was read, counting any opening quote.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The value holds a control character, which `TEXT` excludes unless it is linear white
    /// space.
    #[error("not text: a control character is written at byte {index} of `{value}`")]
    ControlCharacter {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
        /// Where the control character is written.
        index: usize,
    },
    /// The value opens with a quote and is not a well-formed `quoted-string`.
    #[error("not text: `{value}` is not a quoted string, since {source}")]
    QuotedString {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
        /// The rule the quoted string broke.
        source: QuotedStringError,
    },
}

impl Text {
    /// Read a `TEXT` or `quoted-string` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ControlCharacter`] when the value holds a control character other than
    /// linear white space, and [`Error::QuotedString`] when a value opening with a quote is not a
    /// well-formed `quoted-string`.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        if value.first() == Some(&b'"') {
            let content = unquote(value).map_err(|source| Error::QuotedString {
                value: lossy(value),
                source,
            })?;

            return Ok(Self {
                content: content.into_boxed_slice(),
                quoted: true,
            });
        }

        if let Some(index) = value.iter().position(|&byte| !is_text_char(byte)) {
            return Err(Error::ControlCharacter {
                value: lossy(value),
                index,
            });
        }

        Ok(Self {
            content: Box::from(value),
            quoted: false,
        })
    }

    /// The content, with any quoting removed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.content
    }

    /// The content as text, when it happens to be valid UTF-8.
    #[must_use]
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.content).ok()
    }

    /// The content as text, replacing any octet that is not valid UTF-8.
    ///
    /// Where [`Display`] spells the whole value, quoting included, this is the content alone.
    #[must_use]
    pub fn to_str_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.content)
    }

    /// Whether the value was written as a quoted string.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        self.quoted
    }

    /// The octets that spell this value, quoted and escaped when it was read that way.
    ///
    /// This is what a field carrying the value is written with. [`Display`] spells the same
    /// value, but replaces any octet that is not valid UTF-8.
    #[must_use]
    pub fn to_bytes(&self) -> Cow<'_, [u8]> {
        if !self.quoted {
            return Cow::Borrowed(&self.content);
        }

        // Two quotes, plus a backslash before each octet that needs one.
        let mut spelled = Vec::with_capacity(self.content.len() + 2);
        spelled.push(b'"');
        for &byte in &self.content {
            if byte == b'"' || byte == b'\\' {
                spelled.push(b'\\');
            }
            spelled.push(byte);
        }
        spelled.push(b'"');

        Cow::Owned(spelled)
    }
}

impl Display for Text {
    /// Write the value as text, replacing any octet that is not valid UTF-8.
    ///
    /// A file name is not necessarily valid UTF-8, so [`Text::to_bytes`] is what writes one back.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, QuotedStringError, Text};

    #[test]
    fn parses_text_and_quoted_strings() {
        let plain = Text::parse(b"example.warc.gz").unwrap();
        assert_eq!(plain.as_bytes(), b"example.warc.gz");
        assert_eq!(plain.to_str(), Some("example.warc.gz"));
        assert_eq!(plain.to_str_lossy(), "example.warc.gz");
        assert!(!plain.is_quoted());
        assert_eq!(plain.to_string(), "example.warc.gz");

        let quoted = Text::parse(br#""with \"quotes\" and ; punctuation""#).unwrap();
        assert_eq!(quoted.as_bytes(), br#"with "quotes" and ; punctuation"#);
        assert_eq!(quoted.to_str_lossy(), r#"with "quotes" and ; punctuation"#);
        assert!(quoted.is_quoted());
        assert_eq!(quoted.to_string(), r#""with \"quotes\" and ; punctuation""#);
        assert_eq!(
            quoted.to_bytes().as_ref(),
            br#""with \"quotes\" and ; punctuation""#
        );

        // `TEXT` admits any octet, so a name that is not UTF-8 still parses, and is spelled
        // with the octets it was read as rather than with what they say as text.
        let bytes = Text::parse(b"caf\xe9.warc").unwrap();
        assert_eq!(bytes.as_bytes(), b"caf\xe9.warc");
        assert_eq!(bytes.to_str(), None);
        assert_eq!(bytes.to_str_lossy(), "caf\u{fffd}.warc");
        assert_eq!(bytes.to_bytes().as_ref(), b"caf\xe9.warc");
        assert_eq!(bytes.to_string(), "caf\u{fffd}.warc");
    }

    /// `TEXT` includes linear white space, so a tab is not one of the control characters it
    /// excludes, however it is written.
    #[test]
    fn keeps_a_tab() {
        for value in [
            b"with\ttab.warc".as_slice(),
            b"\"with\\\ttab.warc\"".as_slice(),
        ] {
            let text = Text::parse(value).expect("parsed");
            assert_eq!(text.as_bytes(), b"with\ttab.warc");
        }
    }

    #[test]
    fn rejects_malformed_text() {
        for (value, expected) in [
            (
                b"with\x01control".as_slice(),
                Error::ControlCharacter {
                    value: "with\u{1}control".to_owned(),
                    index: 4,
                },
            ),
            (
                b"\"with\x01control\"".as_slice(),
                Error::QuotedString {
                    value: "\"with\u{1}control\"".to_owned(),
                    source: QuotedStringError::ControlCharacter { index: 5 },
                },
            ),
            // An escape does not make a control character text.
            (
                b"\"with\\\x01control\"".as_slice(),
                Error::QuotedString {
                    value: "\"with\\\u{1}control\"".to_owned(),
                    source: QuotedStringError::ControlCharacter { index: 6 },
                },
            ),
            (
                br#""unterminated"#.as_slice(),
                Error::QuotedString {
                    value: "\"unterminated".to_owned(),
                    source: QuotedStringError::Unterminated,
                },
            ),
            (
                br#""with"gap""#.as_slice(),
                Error::QuotedString {
                    value: "\"with\"gap\"".to_owned(),
                    source: QuotedStringError::UnescapedQuote { index: 5 },
                },
            ),
        ] {
            assert_eq!(Text::parse(value), Err(expected), "{value:?}");
        }
    }
}
