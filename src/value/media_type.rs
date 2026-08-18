//! The `media-type` value carried by `Content-Type` and `WARC-Identified-Payload-Type`.

use std::fmt::Display;

use super::from_ascii;
use crate::parsing::{is_token, lossy};
use crate::value::Error;

/// A `media-type` value.
///
/// ```text
/// media-type = type "/" subtype *( OWS ";" OWS parameter )
/// type       = token
/// subtype    = token
/// parameter  = attribute "=" value
/// attribute  = token
/// value      = token | quoted-string
/// OWS        = *( SP / HTAB )
/// ```
///
/// The published grammar has no `OWS`, and so forbids the spaces around `;` that the standard's own
/// examples use. Errata #38 of the WARC 1.1 annotated specification supplies the rule above, which
/// is what we implement.
///
/// Type, subtype, and attribute names are case-insensitive; they are kept as written, and
/// [`is`](Self::is) compares without regard to case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaType {
    type_name: Box<str>,
    subtype: Box<str>,
    parameters: Box<[(Box<str>, ParameterValue)]>,
}

/// A media type parameter's value, which the grammar writes either bare or in quotes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParameterValue {
    /// A bare `token`.
    Token(Box<str>),
    /// A `quoted-string`, held with its quotes removed and its `\` escapes resolved.
    Quoted(Box<str>),
}

impl ParameterValue {
    /// The value itself, with any quoting removed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Token(value) | Self::Quoted(value) => value,
        }
    }
}

impl Display for ParameterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(value) => f.write_str(value),
            Self::Quoted(value) => {
                f.write_str("\"")?;
                for character in value.chars() {
                    if character == '"' || character == '\\' {
                        f.write_str("\\")?;
                    }
                    write!(f, "{character}")?;
                }
                f.write_str("\"")
            }
        }
    }
}

impl MediaType {
    /// Read a media type.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MediaType`] when the value does not match the grammar above, or when a
    /// quoted parameter value is not valid UTF-8. This is stricter than the `TEXT` rule, which
    /// admits any octet, because media types are represented as text here.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        let error = || Error::MediaType(lossy(value));

        let essence_end = value
            .iter()
            .position(|&byte| byte == b';')
            .unwrap_or(value.len());
        let essence = trim_ows(&value[..essence_end]);
        let slash = essence
            .iter()
            .position(|&byte| byte == b'/')
            .ok_or_else(error)?;
        let (type_name, subtype) = (&essence[..slash], &essence[slash + 1..]);
        if !is_token(type_name) || !is_token(subtype) {
            return Err(error());
        }

        let mut parameters = Vec::new();
        let mut rest = &value[essence_end..];
        while let Some(remainder) = rest.strip_prefix(b";") {
            let (parameter, tail) = split_parameter(trim_ows_start(remainder));
            parameters.push(parse_parameter(parameter).ok_or_else(error)?);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(error());
        }

        Ok(Self {
            type_name: from_ascii(type_name),
            subtype: from_ascii(subtype),
            parameters: parameters.into_boxed_slice(),
        })
    }

    /// The type, as it was written.
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// The subtype, as it was written.
    #[must_use]
    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    /// The parameters, in the order they were written.
    pub fn parameters(&self) -> impl Iterator<Item = (&str, &ParameterValue)> {
        self.parameters
            .iter()
            .map(|(name, value)| (name.as_ref(), value))
    }

    /// The first parameter with the given name, compared case-insensitively.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&ParameterValue> {
        self.parameters
            .iter()
            .find(|(parameter, _)| parameter.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Whether this is the given type and subtype, compared case-insensitively and ignoring any
    /// parameters.
    #[must_use]
    pub fn is(&self, type_name: &str, subtype: &str) -> bool {
        self.type_name.eq_ignore_ascii_case(type_name) && self.subtype.eq_ignore_ascii_case(subtype)
    }
}

impl Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.type_name, self.subtype)?;
        for (name, value) in &self.parameters {
            write!(f, "; {name}={value}")?;
        }

        Ok(())
    }
}

/// Split off the next parameter, which ends at the `;` that is not inside a quoted string.
fn split_parameter(input: &[u8]) -> (&[u8], &[u8]) {
    let mut index = 0;
    let mut quoted = false;
    while index < input.len() {
        match input[index] {
            b'"' => {
                quoted = !quoted;
                index += 1;
            }
            // Inside a quoted string a backslash escapes whatever follows, including a quote, so
            // the pair is skipped whole.
            b'\\' if quoted => index += 2,
            b';' if !quoted => return (&input[..index], &input[index..]),
            _ => index += 1,
        }
    }

    (input, &[])
}

/// Read one `attribute "=" value`.
fn parse_parameter(input: &[u8]) -> Option<(Box<str>, ParameterValue)> {
    let input = trim_ows(input);
    let equals = input.iter().position(|&byte| byte == b'=')?;
    let (attribute, value) = (&input[..equals], &input[equals + 1..]);
    if !is_token(attribute) {
        return None;
    }

    let value = if value.first() == Some(&b'"') {
        ParameterValue::Quoted(unquote(value)?)
    } else if is_token(value) {
        ParameterValue::Token(from_ascii(value))
    } else {
        return None;
    };

    Some((from_ascii(attribute), value))
}

/// Resolve a `quoted-string` into the text it stands for.
///
/// ```text
/// quoted-string = ( <"> *( qdtext | quoted-pair ) <"> )
/// qdtext        = <any TEXT except <">>
/// quoted-pair   = "\" CHAR
/// ```
fn unquote(input: &[u8]) -> Option<Box<str>> {
    let inner = input.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    let mut unquoted = Vec::with_capacity(inner.len());
    let mut index = 0;
    while index < inner.len() {
        match inner[index] {
            b'\\' => {
                unquoted.push(*inner.get(index + 1)?);
                index += 2;
            }
            // An unescaped quote would have ended the string, so the bounds are wrong.
            b'"' => return None,
            byte => {
                unquoted.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(unquoted).ok().map(String::into_boxed_str)
}

/// Strip `OWS` from both ends, per errata #38.
fn trim_ows(input: &[u8]) -> &[u8] {
    trim_ows_end(trim_ows_start(input))
}

fn trim_ows_start(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|&byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(input.len());

    &input[start..]
}

fn trim_ows_end(input: &[u8]) -> &[u8] {
    let end = input
        .iter()
        .rposition(|&byte| !matches!(byte, b' ' | b'\t'))
        .map_or(0, |index| index + 1);

    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::{Error, MediaType, ParameterValue};

    #[test]
    fn parses_a_bare_media_type() {
        let media_type = MediaType::parse(b"application/warc-fields").unwrap();

        assert_eq!(media_type.type_name(), "application");
        assert_eq!(media_type.subtype(), "warc-fields");
        assert!(media_type.is("APPLICATION", "WARC-Fields"));
        assert!(!media_type.is("application", "http"));
        assert_eq!(media_type.parameters().count(), 0);
    }

    /// Errata #38 adds the `OWS` the standard's own examples use and the published grammar forbids.
    #[test]
    fn accepts_the_whitespace_errata_38_allows() {
        for value in [
            b"application/http;msgtype=response".as_slice(),
            b"application/http; msgtype=response".as_slice(),
            b"application/http ;  msgtype=response".as_slice(),
            b"application/http\t;\tmsgtype=response".as_slice(),
        ] {
            let media_type = MediaType::parse(value).unwrap_or_else(|_| panic!("{value:?}"));
            assert!(media_type.is("application", "http"));
            assert_eq!(
                media_type.parameter("msgtype").map(ParameterValue::as_str),
                Some("response")
            );
        }
    }

    #[test]
    fn parses_quoted_and_repeated_parameters() {
        let media_type = MediaType::parse(br#"text/plain; charset="utf-8"; x="a;b\"c""#).unwrap();

        assert_eq!(
            media_type.parameter("CHARSET").map(ParameterValue::as_str),
            Some("utf-8")
        );
        // A `;` inside a quoted string does not start a new parameter.
        assert_eq!(
            media_type.parameter("x").map(ParameterValue::as_str),
            Some(r#"a;b"c"#)
        );
        assert_eq!(media_type.parameters().count(), 2);
        assert_eq!(
            media_type.to_string(),
            r#"text/plain; charset="utf-8"; x="a;b\"c""#
        );
    }

    #[test]
    fn rejects_malformed_media_types() {
        for value in [
            b"application".as_slice(),
            b"/warc-fields".as_slice(),
            b"application/".as_slice(),
            b"application/warc fields".as_slice(),
            b"text/plain; noequals".as_slice(),
            b"text/plain; =value".as_slice(),
            br#"text/plain; x="unterminated"#.as_slice(),
        ] {
            assert!(
                matches!(MediaType::parse(value), Err(Error::MediaType(_))),
                "{value:?}"
            );
        }
    }
}
