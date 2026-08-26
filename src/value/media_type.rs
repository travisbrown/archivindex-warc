//! The `media-type` value carried by `Content-Type` and `WARC-Identified-Payload-Type`.

use std::borrow::Cow;
use std::fmt::Display;

use crate::parsing::{QuotedStringError, is_lws, is_token, lossy, unquote};

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
/// [`is`](Self::is) compares without regard to case. The `OWS` around each `;` is kept as
/// written too, so a value renders as it was read.
///
/// The types WARC records most often declare are available as constants, such as
/// [`HTTP_RESPONSE`](Self::HTTP_RESPONSE).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaType {
    type_name: Cow<'static, str>,
    subtype: Cow<'static, str>,
    parameters: Cow<'static, [Parameter]>,
}

/// One `OWS ";" OWS parameter` of a media type.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Parameter {
    /// The `OWS ";" OWS` introducing the parameter, as written.
    separator: Cow<'static, str>,
    name: Cow<'static, str>,
    value: ParameterValue,
}

/// The rule a `media-type` value did not match.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The value has no `/` separating the type from the subtype.
    #[error("not a media type: no `/` separating type from subtype in `{value}`")]
    NoSubtype {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
    },
    /// The type or the subtype is not a `token`.
    #[error("not a media type: the type or subtype of `{value}` is not a token")]
    MalformedEssence {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
    },
    /// A parameter is not an `attribute "=" value` the grammar admits.
    #[error("not a media type: `{parameter}` is not a parameter, in `{value}`")]
    MalformedParameter {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
        /// The parameter that does not match, as it was read.
        parameter: String,
    },
    /// A parameter's value opens with a quote and is not a well-formed `quoted-string`.
    #[error("not a media type: the value of `{parameter}` is not a quoted string, since {source}")]
    MalformedQuotedValue {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
        /// The parameter whose value does not match, as it was read.
        parameter: String,
        /// The rule the quoted string broke.
        source: QuotedStringError,
    },
    /// A parameter's quoted value is not valid UTF-8, which this representation requires.
    #[error("not a media type: the value of `{parameter}` is not valid UTF-8")]
    NonUtf8ParameterValue {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
        /// The parameter whose value is not text, as it was read.
        parameter: String,
    },
}

/// The rule a parameter broke, before the value that carried it is known.
enum ParameterFailure {
    /// The parameter is not an `attribute "=" value`.
    Malformed,
    /// The parameter's value is not a well-formed `quoted-string`.
    Quoted(QuotedStringError),
    /// The parameter's quoted value is not valid UTF-8.
    NonUtf8,
}

/// A media type parameter's value, which the grammar writes either bare or in quotes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParameterValue {
    /// A bare `token`.
    Token(Cow<'static, str>),
    /// A `quoted-string`, held with its quotes removed and its `\` escapes resolved.
    Quoted(Cow<'static, str>),
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
    /// `application/http`: an archived HTTP message.
    pub const HTTP: Self = Self::constant("application", "http", &[]);
    /// `application/http;msgtype=request`: an archived HTTP request, which a `request` record
    /// carries.
    pub const HTTP_REQUEST: Self = Self::constant("application", "http", &Self::REQUEST);
    /// `application/http;msgtype=response`: an archived HTTP response, which a `response` record
    /// carries.
    pub const HTTP_RESPONSE: Self = Self::constant("application", "http", &Self::RESPONSE);
    /// `application/warc-fields`: the field lines a `warcinfo` or `metadata` record carries.
    pub const WARC_FIELDS: Self = Self::constant("application", "warc-fields", &[]);
    /// `application/octet-stream`: octets the archive does not type further.
    pub const OCTET_STREAM: Self = Self::constant("application", "octet-stream", &[]);
    /// `application/json`: a JSON document.
    pub const JSON: Self = Self::constant("application", "json", &[]);
    /// `text/plain`: a block of text.
    pub const TEXT_PLAIN: Self = Self::constant("text", "plain", &[]);
    /// `text/dns`: a DNS lookup, which archives record as a `resource` record.
    pub const TEXT_DNS: Self = Self::constant("text", "dns", &[]);

    /// `application/http; msgtype=request`, the spelling with the white space errata #38 admits.
    /// Archives write it often, so it is read without allocating, but nothing here writes it.
    const HTTP_REQUEST_SPACE: Self = Self::constant("application", "http", &Self::REQUEST_SPACE);
    /// `application/http; msgtype=response`, the spelling with the white space errata #38 admits.
    /// Archives write it often, so it is read without allocating, but nothing here writes it.
    const HTTP_RESPONSE_SPACE: Self = Self::constant("application", "http", &Self::RESPONSE_SPACE);

    /// `;msgtype=request`, written without the optional white space errata #38 admits.
    const REQUEST: [Parameter; 1] = [Parameter {
        separator: Cow::Borrowed(";"),
        name: Cow::Borrowed("msgtype"),
        value: ParameterValue::Token(Cow::Borrowed("request")),
    }];
    /// `;msgtype=response`, written without the optional white space errata #38 admits.
    const RESPONSE: [Parameter; 1] = [Parameter {
        separator: Cow::Borrowed(";"),
        name: Cow::Borrowed("msgtype"),
        value: ParameterValue::Token(Cow::Borrowed("response")),
    }];
    /// `; msgtype=request`, written with the white space.
    const REQUEST_SPACE: [Parameter; 1] = [Parameter {
        separator: Cow::Borrowed("; "),
        name: Cow::Borrowed("msgtype"),
        value: ParameterValue::Token(Cow::Borrowed("request")),
    }];
    /// `; msgtype=response`, written with the white space.
    const RESPONSE_SPACE: [Parameter; 1] = [Parameter {
        separator: Cow::Borrowed("; "),
        name: Cow::Borrowed("msgtype"),
        value: ParameterValue::Token(Cow::Borrowed("response")),
    }];

    /// A media type whose parts are known to match the grammar.
    const fn constant(
        type_name: &'static str,
        subtype: &'static str,
        parameters: &'static [Parameter],
    ) -> Self {
        Self {
            type_name: Cow::Borrowed(type_name),
            subtype: Cow::Borrowed(subtype),
            parameters: Cow::Borrowed(parameters),
        }
    }

    /// Read a media type.
    ///
    /// A value spelled exactly as one of this type's constants is that constant, and so is read
    /// without allocating. The same spellings with white space around the `;` are read without
    /// allocating too, and keep that white space.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] naming the rule the value broke against the grammar above, including
    /// [`Error::NonUtf8ParameterValue`] when a quoted parameter value is not valid UTF-8. That is
    /// stricter than the `TEXT` rule, which admits any octet, because media types are represented
    /// as text here.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        if let Some(constant) = constant_for(value) {
            return Ok(constant);
        }

        let essence_end = value
            .iter()
            .position(|&byte| byte == b';')
            .unwrap_or(value.len());
        let essence = trim_ows(&value[..essence_end]);
        let slash = essence
            .iter()
            .position(|&byte| byte == b'/')
            .ok_or_else(|| Error::NoSubtype {
                value: lossy(value),
            })?;
        let (type_name, subtype) = (&essence[..slash], &essence[slash + 1..]);
        if !is_token(type_name) || !is_token(subtype) {
            return Err(Error::MalformedEssence {
                value: lossy(value),
            });
        }

        let mut parameters = Vec::new();
        // A separator runs from the end of the element before it to the parameter it introduces,
        // so it starts at the white space that element was trimmed of rather than at the `;`.
        let mut separator_start = essence_end - trailing_ows(&value[..essence_end]);
        let mut index = essence_end;

        // `index` sits on a `;` whenever there is one left, since `split_parameter` stops there.
        while index < value.len() {
            let after_semicolon = index + 1;
            let content_start = after_semicolon + leading_ows(&value[after_semicolon..]);
            let (chunk, rest) = split_parameter(&value[content_start..]);
            // Trailing `OWS` belongs to the separator that follows, not to this parameter.
            let content = trim_ows_end(chunk);
            let (name, parameter_value) =
                parse_parameter(content).map_err(|failure| failure.against(value, content))?;

            parameters.push(Parameter {
                separator: owned_ascii(&value[separator_start..content_start]),
                name,
                value: parameter_value,
            });

            separator_start = content_start + content.len();
            index = value.len() - rest.len();
        }

        Ok(Self {
            type_name: owned_ascii(type_name),
            subtype: owned_ascii(subtype),
            parameters: Cow::Owned(parameters),
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
            .map(|parameter| (parameter.name.as_ref(), &parameter.value))
    }

    /// The first parameter with the given name, compared case-insensitively.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&ParameterValue> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
            .map(|parameter| &parameter.value)
    }

    /// Whether this is the given type and subtype, compared case-insensitively and ignoring any
    /// parameters.
    #[must_use]
    pub fn is(&self, type_name: &str, subtype: &str) -> bool {
        self.type_name.eq_ignore_ascii_case(type_name) && self.subtype.eq_ignore_ascii_case(subtype)
    }
}

impl Display for MediaType {
    /// Write the type and its parameters, each spelled with the `OWS` it was read with.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.type_name, self.subtype)?;
        for Parameter {
            separator,
            name,
            value,
        } in self.parameters.iter()
        {
            write!(f, "{separator}{name}={value}")?;
        }

        Ok(())
    }
}

/// The constant these bytes are the rendering of, if they are one.
const fn constant_for(value: &[u8]) -> Option<MediaType> {
    match value {
        b"application/http;msgtype=request" => Some(MediaType::HTTP_REQUEST),
        b"application/http;msgtype=response" => Some(MediaType::HTTP_RESPONSE),
        b"application/warc-fields" => Some(MediaType::WARC_FIELDS),
        b"application/octet-stream" => Some(MediaType::OCTET_STREAM),
        b"application/json" => Some(MediaType::JSON),
        b"application/http; msgtype=request" => Some(MediaType::HTTP_REQUEST_SPACE),
        b"application/http; msgtype=response" => Some(MediaType::HTTP_RESPONSE_SPACE),
        b"application/http" => Some(MediaType::HTTP),
        b"text/plain" => Some(MediaType::TEXT_PLAIN),
        b"text/dns" => Some(MediaType::TEXT_DNS),
        _ => None,
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

impl ParameterFailure {
    /// Name the rule against the value and the parameter it was read from.
    fn against(self, value: &[u8], parameter: &[u8]) -> Error {
        let (value, parameter) = (lossy(value), lossy(parameter));
        match self {
            Self::Malformed => Error::MalformedParameter { value, parameter },
            Self::Quoted(source) => Error::MalformedQuotedValue {
                value,
                parameter,
                source,
            },
            Self::NonUtf8 => Error::NonUtf8ParameterValue { value, parameter },
        }
    }
}

/// Read one `attribute "=" value`, given the content without its surrounding `OWS`.
fn parse_parameter(input: &[u8]) -> Result<(Cow<'static, str>, ParameterValue), ParameterFailure> {
    let equals = input
        .iter()
        .position(|&byte| byte == b'=')
        .ok_or(ParameterFailure::Malformed)?;
    let (attribute, value) = (&input[..equals], &input[equals + 1..]);
    if !is_token(attribute) {
        return Err(ParameterFailure::Malformed);
    }

    let value = if value.first() == Some(&b'"') {
        let unquoted = unquote(value).map_err(ParameterFailure::Quoted)?;
        let unquoted = String::from_utf8(unquoted).map_err(|_| ParameterFailure::NonUtf8)?;
        ParameterValue::Quoted(Cow::Owned(unquoted))
    } else if is_token(value) {
        ParameterValue::Token(owned_ascii(value))
    } else {
        return Err(ParameterFailure::Malformed);
    };

    Ok((owned_ascii(attribute), value))
}

/// Take ownership of bytes already validated as ASCII.
fn owned_ascii(bytes: &[u8]) -> Cow<'static, str> {
    Cow::Owned(
        String::from_utf8(bytes.to_vec())
            .expect("invariant violation: grammar admitted a non-ASCII byte"),
    )
}

/// The length of the `OWS` a value opens with.
fn leading_ows(input: &[u8]) -> usize {
    input
        .iter()
        .position(|&byte| !is_lws(byte))
        .unwrap_or(input.len())
}

/// The length of the `OWS` a value closes with.
fn trailing_ows(input: &[u8]) -> usize {
    input.len()
        - input
            .iter()
            .rposition(|&byte| !is_lws(byte))
            .map_or(0, |index| index + 1)
}

/// Strip `OWS` from both ends, per errata #38.
fn trim_ows(input: &[u8]) -> &[u8] {
    trim_ows_end(&input[leading_ows(input)..])
}

fn trim_ows_end(input: &[u8]) -> &[u8] {
    &input[..input.len() - trailing_ows(input)]
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_strategy::proptest;

    use super::{Cow, Error, MediaType, ParameterValue, QuotedStringError};
    use crate::strategies;

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
            // The `OWS` is kept as read, so each spelling writes back as itself.
            assert_eq!(media_type.to_string().as_bytes(), value);
        }
    }

    /// Each separator is the white space around its own `;`, so spellings that differ from one
    /// parameter to the next are each kept.
    #[test]
    fn keeps_the_whitespace_of_each_parameter_separately() {
        let value = b"text/plain ;a=1;\tb=\"x ; y\" ;  c=3".as_slice();
        let media_type = MediaType::parse(value).unwrap();

        assert_eq!(media_type.parameters().count(), 3);
        assert_eq!(
            media_type.parameter("b").map(ParameterValue::as_str),
            Some("x ; y")
        );
        assert_eq!(media_type.to_string().as_bytes(), value);
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

    /// Whether a value holds nothing of its own, which the constants and only the constants do.
    fn is_borrowed(media_type: &MediaType) -> bool {
        matches!(media_type.type_name, Cow::Borrowed(_))
            && matches!(media_type.subtype, Cow::Borrowed(_))
            && matches!(media_type.parameters, Cow::Borrowed(_))
    }

    /// Each constant is the media type it is documented as, and reading that spelling gives the
    /// constant back rather than a value that only equals it.
    #[test]
    fn the_constants_are_the_types_they_are_written_as() {
        for (constant, spelling) in [
            (MediaType::HTTP, "application/http"),
            (MediaType::HTTP_REQUEST, "application/http;msgtype=request"),
            (
                MediaType::HTTP_RESPONSE,
                "application/http;msgtype=response",
            ),
            (MediaType::WARC_FIELDS, "application/warc-fields"),
            (MediaType::OCTET_STREAM, "application/octet-stream"),
            (MediaType::JSON, "application/json"),
            (MediaType::TEXT_PLAIN, "text/plain"),
            (MediaType::TEXT_DNS, "text/dns"),
        ] {
            assert_eq!(constant.to_string(), spelling);

            let parsed = MediaType::parse(spelling.as_bytes()).expect("a media type");

            assert_eq!(parsed, constant);
            assert!(is_borrowed(&parsed), "{spelling}");
        }
    }

    /// The spelling with white space around the `;` is what archives most often write, so it is
    /// read without allocating as well, and it is written back as it was read.
    #[test]
    fn the_spelling_archives_write_is_read_without_allocating() {
        for spelling in [
            "application/http; msgtype=request",
            "application/http; msgtype=response",
        ] {
            let media_type = MediaType::parse(spelling.as_bytes()).expect("a media type");

            assert!(is_borrowed(&media_type), "{spelling}");
            assert!(media_type.is("application", "http"));
            assert_eq!(media_type.to_string(), spelling);
        }
    }

    /// A media type spelled otherwise than a constant is read as it was written, since a value
    /// keeps the white space it was read with.
    #[test]
    fn a_constant_spelled_another_way_keeps_its_own_spelling() {
        let media_type = MediaType::parse(b"application/http ;msgtype=response").unwrap();

        assert_ne!(media_type, MediaType::HTTP_RESPONSE);
        assert!(!is_borrowed(&media_type));
        assert!(media_type.is("application", "http"));
        assert_eq!(
            media_type.parameter("msgtype").map(ParameterValue::as_str),
            Some("response")
        );
        assert_eq!(media_type.to_string(), "application/http ;msgtype=response");
    }

    #[test]
    fn rejects_malformed_media_types() {
        for (value, expected) in [
            (
                b"application".as_slice(),
                Error::NoSubtype {
                    value: "application".to_owned(),
                },
            ),
            (
                b"/warc-fields".as_slice(),
                Error::MalformedEssence {
                    value: "/warc-fields".to_owned(),
                },
            ),
            (
                b"application/".as_slice(),
                Error::MalformedEssence {
                    value: "application/".to_owned(),
                },
            ),
            (
                b"application/warc fields".as_slice(),
                Error::MalformedEssence {
                    value: "application/warc fields".to_owned(),
                },
            ),
            (
                b"text/plain; noequals".as_slice(),
                Error::MalformedParameter {
                    value: "text/plain; noequals".to_owned(),
                    parameter: "noequals".to_owned(),
                },
            ),
            (
                b"text/plain; =value".as_slice(),
                Error::MalformedParameter {
                    value: "text/plain; =value".to_owned(),
                    parameter: "=value".to_owned(),
                },
            ),
            (
                br#"text/plain; x="unterminated"#.as_slice(),
                Error::MalformedQuotedValue {
                    value: "text/plain; x=\"unterminated".to_owned(),
                    parameter: "x=\"unterminated".to_owned(),
                    source: QuotedStringError::Unterminated,
                },
            ),
        ] {
            assert_eq!(MediaType::parse(value), Err(expected), "{value:?}");
        }
    }

    /// A quoted parameter value is made of `qdtext` and `quoted-pair`, and a control character is
    /// neither: `quoted-pair` escapes an octet, so a backslash does not admit one.
    #[test]
    fn rejects_controls_in_a_quoted_parameter() {
        // Each offset counts from the quote opening the parameter's value.
        for (value, offset) in [
            (b"text/plain; x=\"a\0b\"".as_slice(), 2),
            (b"text/plain; x=\"a\x7fb\"".as_slice(), 2),
            (b"text/plain; x=\"a\\\0b\"".as_slice(), 3),
            (b"text/plain; x=\"a\\\x7fb\"".as_slice(), 3),
        ] {
            assert!(
                matches!(
                    MediaType::parse(value),
                    Err(Error::MalformedQuotedValue {
                        source: QuotedStringError::ControlCharacter { index },
                        ..
                    }) if index == offset
                ),
                "{value:?}"
            );
        }
    }

    /// A media type reads back as written, parameters and their white space included.
    #[proptest]
    fn round_trips_a_media_type(#[strategy(strategies::media_type())] media_type: MediaType) {
        let written = media_type.to_string();

        prop_assert_eq!(MediaType::parse(written.as_bytes()), Ok(media_type));
    }
}
