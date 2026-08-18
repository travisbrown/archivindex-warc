//! The `TEXT` value carried by `WARC-Filename`.

use std::borrow::Cow;
use std::fmt::Display;

use crate::parsing::lossy;
use crate::value::Error;

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

impl Text {
    /// Read a `TEXT` or `quoted-string` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Text`] when the value holds a control character, or when it opens with a
    /// quote it does not close.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        let error = || Error::Text(lossy(value));

        if value.first() == Some(&b'"') {
            let content = unquote_bytes(value).ok_or_else(error)?;
            if content.iter().any(|&byte| is_ctl(byte)) {
                return Err(error());
            }

            return Ok(Self {
                content: content.into_boxed_slice(),
                quoted: true,
            });
        }

        if value.iter().any(|&byte| is_ctl(byte)) {
            return Err(error());
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

/// Resolve a `quoted-string` into the octets it stands for.
///
/// The escaping is the same as for a media type parameter value, but the result is bytes rather
/// than text.
fn unquote_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let inner = input.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    let mut unquoted = Vec::with_capacity(inner.len());
    let mut index = 0;
    while index < inner.len() {
        match inner[index] {
            b'\\' => {
                unquoted.push(*inner.get(index + 1)?);
                index += 2;
            }
            b'"' => return None,
            byte => {
                unquoted.push(byte);
                index += 1;
            }
        }
    }

    Some(unquoted)
}

/// Whether a byte is a control character, which `TEXT` excludes.
const fn is_ctl(byte: u8) -> bool {
    byte < 32 || byte == 127
}

#[cfg(test)]
mod tests {
    use super::{Error, Text};

    #[test]
    fn parses_text_and_quoted_strings() {
        let plain = Text::parse(b"example.warc.gz").unwrap();
        assert_eq!(plain.as_bytes(), b"example.warc.gz");
        assert_eq!(plain.to_str(), Some("example.warc.gz"));
        assert!(!plain.is_quoted());
        assert_eq!(plain.to_string(), "example.warc.gz");

        let quoted = Text::parse(br#""with \"quotes\" and ; punctuation""#).unwrap();
        assert_eq!(quoted.as_bytes(), br#"with "quotes" and ; punctuation"#);
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
        assert_eq!(bytes.to_bytes().as_ref(), b"caf\xe9.warc");
        assert_eq!(bytes.to_string(), "caf\u{fffd}.warc");
    }

    #[test]
    fn rejects_malformed_text() {
        for value in [
            b"with\x01control".as_slice(),
            br#""unterminated"#.as_slice(),
            br#""with"gap""#.as_slice(),
        ] {
            assert!(
                matches!(Text::parse(value), Err(Error::Text(_))),
                "{value:?}"
            );
        }
    }
}
