//! Field values, read against the grammar their field's name selects.
//!
//! A [`HeaderValue`] preserves its source bytes and stores their parsed form when the field has a
//! standard grammar.

use std::net::IpAddr;

use fluent_uri::Uri;

use super::name::Field;
use crate::parsing::{is_text, is_token, lossy, parse_content_length, unfold};
use crate::value::{Error, LabelledDigest, MediaType, Text, WarcDate};
use crate::version::WarcVersion;

/// The parsed form of a field value.
///
/// Variants represent grammar rules, which several fields can share. This type accepts the union
/// of the WARC 1.0 and 1.1 grammars. The semantic representation checks the declared version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueForm {
    /// A URI, and whether it was written inside the angle brackets of the `"<" uri ">"` rule.
    ///
    /// WARC 1.0 brackets every URI-valued field; WARC 1.1 brackets only the five fields whose
    /// value is a record identifier. Both spellings parse here, and `bracketed` records which one
    /// was read so that the semantic level can check it against the record's version.
    Uri {
        /// The URI itself, with the brackets removed.
        uri: Uri<String>,
        /// Whether the value was written as `"<" uri ">"`.
        bracketed: bool,
    },
    /// A `w3c-iso8601` timestamp, at the precision it was written with.
    ///
    /// Read with the WARC 1.1 grammar, which admits every precision WARC 1.0 does and more.
    Date(WarcDate),
    /// A `1*DIGIT` count.
    Digits(u64),
    /// A bare `token`, as the record type and the truncation reason are written.
    Token(Box<str>),
    /// A `labelled-digest`.
    Digest(LabelledDigest),
    /// A `media-type`.
    MediaType(MediaType),
    /// A `TEXT` or `quoted-string` value.
    Text(Text),
    /// An IPv4 or IPv6 address.
    IpAddress(IpAddr),
}

impl ValueForm {
    /// Append the octets that spell this form.
    fn write_to(&self, out: &mut Vec<u8>) {
        match self {
            // Text is the one form held as octets, since `TEXT` admits any of them, so it is
            // written from those rather than through the lossy `Display` every other form has.
            Self::Text(text) => out.extend_from_slice(&text.to_bytes()),
            form => out.extend_from_slice(form.to_string().as_bytes()),
        }
    }
}

impl std::fmt::Display for ValueForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uri { uri, bracketed } => {
                if *bracketed {
                    write!(f, "<{}>", uri.as_str())
                } else {
                    f.write_str(uri.as_str())
                }
            }
            // A date renders at its own precision, which is the WARC 1.1 spelling. Rendering it
            // for a record's version is the semantic level's business.
            Self::Date(date) => write!(f, "{date}"),
            Self::Digits(digits) => write!(f, "{digits}"),
            Self::Token(token) => f.write_str(token),
            Self::Digest(digest) => write!(f, "{digest}"),
            Self::MediaType(media_type) => write!(f, "{media_type}"),
            Self::Text(text) => write!(f, "{text}"),
            Self::IpAddress(address) => write!(f, "{address}"),
        }
    }
}

/// The grammar a field's value is read against.
///
/// A field the standard does not define has no grammar, so its value is kept as written.
const fn form_of(field: Field) -> FormKind {
    match field {
        Field::ContentLength | Field::SegmentNumber | Field::SegmentTotalLength => FormKind::Digits,
        Field::ContentType | Field::IdentifiedPayloadType => FormKind::MediaType,
        Field::BlockDigest | Field::PayloadDigest => FormKind::Digest,
        Field::ConcurrentTo
        | Field::Profile
        | Field::RecordID
        | Field::RefersTo
        | Field::RefersToTargetURI
        | Field::SegmentOriginID
        | Field::TargetURI
        | Field::WarcinfoID => FormKind::Uri,
        Field::Date | Field::RefersToDate => FormKind::Date,
        Field::Filename => FormKind::Text,
        Field::IPAddress => FormKind::IpAddress,
        Field::Truncated | Field::WarcType => FormKind::Token,
    }
}

/// Which of the grammars in [`ValueForm`] applies, before one has been read.
#[derive(Clone, Copy)]
enum FormKind {
    Uri,
    Date,
    Digits,
    Token,
    Digest,
    MediaType,
    Text,
    IpAddress,
}

/// A field value as written and, when defined, its parsed form.
///
/// The bytes are kept verbatim, leading and trailing white space and folded continuation lines
/// included, to support byte-exact round-tripping. The form is parsed from the value's content:
/// the bytes with folds resolved to single spaces and surrounding white space removed, as
/// `field-value = *( field-content | LWS )` prescribes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderValue {
    raw: Box<[u8]>,
    form: Option<ValueForm>,
}

impl HeaderValue {
    /// Read a value written for the given field.
    ///
    /// A field the standard does not define carries no grammar, so its value is only checked for
    /// the control characters `TEXT` excludes.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] of the grammar the field selects.
    pub fn parse(field: Option<Field>, raw: &[u8]) -> Result<Self, Error> {
        let content = unfold(raw);
        let form = if let Some(kind) = field.map(form_of) {
            Some(parse_form(kind, &content)?)
        } else {
            if !is_text(&content) {
                return Err(Error::Text(lossy(&content)));
            }
            None
        };

        Ok(Self {
            raw: Box::from(raw),
            form,
        })
    }

    /// The value as it was written, with all of its white space.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The value as it was written, taking ownership of the bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.raw.into_vec()
    }

    /// The parsed form of the value, when its field has a grammar.
    #[must_use]
    pub const fn form(&self) -> Option<&ValueForm> {
        self.form.as_ref()
    }

    /// Take the parsed form and discard the source bytes.
    #[must_use]
    pub fn into_form(self) -> Option<ValueForm> {
        self.form
    }

    /// The value as text, when the bytes happen to be valid UTF-8.
    ///
    /// This is the whole value, white space included, not the content its grammar applies to.
    #[must_use]
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.raw).ok()
    }
}

impl From<ValueForm> for HeaderValue {
    /// Render a form into the bytes that spell it.
    ///
    /// The bytes open with the conventional single space after the colon, which
    /// `field-value = *( field-content | LWS )` admits as leading `LWS` and which every example in
    /// the standard writes.
    fn from(form: ValueForm) -> Self {
        let mut raw = vec![b' '];
        form.write_to(&mut raw);

        Self {
            raw: raw.into_boxed_slice(),
            form: Some(form),
        }
    }
}

/// Read a value's content against one grammar.
fn parse_form(kind: FormKind, content: &[u8]) -> Result<ValueForm, Error> {
    match kind {
        FormKind::Uri => parse_uri(content),
        FormKind::Date => {
            let text = std::str::from_utf8(content).map_err(|_| Error::Date(lossy(content)))?;
            // The 1.1 grammar admits the one spelling 1.0 has and several more. Whether the
            // record's version allows the one read is settled a level up.
            WarcDate::parse(text, WarcVersion::V1_1)
                .map(ValueForm::Date)
                .ok_or_else(|| Error::Date(text.to_owned()))
        }
        FormKind::Digits => parse_content_length(
            std::str::from_utf8(content).map_err(|_| Error::Digits(lossy(content)))?,
        )
        .map(ValueForm::Digits)
        .ok_or_else(|| Error::Digits(lossy(content))),
        FormKind::Token => {
            if is_token(content) {
                Ok(ValueForm::Token(lossy(content).into()))
            } else {
                Err(Error::Token(lossy(content)))
            }
        }
        FormKind::Digest => LabelledDigest::parse(content).map(ValueForm::Digest),
        FormKind::MediaType => MediaType::parse(content).map(ValueForm::MediaType),
        FormKind::Text => Text::parse(content).map(ValueForm::Text),
        FormKind::IpAddress => std::str::from_utf8(content)
            .ok()
            .and_then(|text| text.parse().ok())
            .map(ValueForm::IpAddress)
            .ok_or_else(|| Error::IpAddress(lossy(content))),
    }
}

/// Read a URI, with or without the angle brackets of the `"<" uri ">"` rule.
fn parse_uri(content: &[u8]) -> Result<ValueForm, Error> {
    let error = || Error::Uri(lossy(content));

    let bracketed = content.first() == Some(&b'<');
    let inner = if bracketed {
        content
            .strip_prefix(b"<")
            .and_then(|rest| rest.strip_suffix(b">"))
            .ok_or_else(error)?
    } else {
        // A closing bracket with no opening one is as unbalanced as the reverse.
        if content.last() == Some(&b'>') {
            return Err(error());
        }
        content
    };

    let text = std::str::from_utf8(inner).map_err(|_| error())?;
    let uri = Uri::parse(text).map_err(|_| error())?.to_owned();

    Ok(ValueForm::Uri { uri, bracketed })
}

#[cfg(test)]
mod tests {
    use super::{Error, Field, HeaderValue, ValueForm};

    /// A value keeps every byte it was written with, whatever its grammar makes of them.
    #[test]
    fn preserves_the_bytes_as_written() {
        let value = HeaderValue::parse(Some(Field::ContentLength), b"  1234\t").unwrap();

        assert_eq!(value.as_bytes(), b"  1234\t");
        assert_eq!(value.form(), Some(&ValueForm::Digits(1234)));
    }

    /// A folded value reads as though the fold were a single space.
    #[test]
    fn reads_through_a_fold() {
        let value = HeaderValue::parse(Some(Field::ContentType), b" text/plain;\r\n x=1").unwrap();

        assert_eq!(value.as_bytes(), b" text/plain;\r\n x=1");
        let Some(ValueForm::MediaType(media_type)) = value.form() else {
            panic!("{value:?}")
        };
        assert!(media_type.is("text", "plain"));
    }

    /// Both spellings of a URI-valued field parse, and which was written is remembered.
    #[test]
    fn reads_bracketed_and_bare_uris() {
        let bracketed = HeaderValue::parse(Some(Field::RecordID), b"<urn:uuid:abc>").unwrap();
        let bare = HeaderValue::parse(Some(Field::TargetURI), b"http://example.com/").unwrap();

        let Some(ValueForm::Uri {
            uri,
            bracketed: is_bracketed,
        }) = bracketed.form()
        else {
            panic!("{bracketed:?}")
        };
        assert_eq!(uri.as_str(), "urn:uuid:abc");
        assert!(is_bracketed);

        let Some(ValueForm::Uri {
            uri,
            bracketed: is_bracketed,
        }) = bare.form()
        else {
            panic!("{bare:?}")
        };
        assert_eq!(uri.as_str(), "http://example.com/");
        assert!(!is_bracketed);
    }

    #[test]
    fn rejects_malformed_uris() {
        for value in [
            b"<http://example.com/".as_slice(),
            b"http://example.com/>".as_slice(),
            b"not a uri".as_slice(),
            // RFC 3986's `URI` rule requires a scheme, so a relative reference is not one.
            b"/relative/path".as_slice(),
        ] {
            assert!(
                matches!(
                    HeaderValue::parse(Some(Field::TargetURI), value),
                    Err(Error::Uri(_))
                ),
                "{value:?}"
            );
        }
    }

    /// The union admits every precision WARC 1.1 does, whatever version declared the record.
    #[test]
    fn reads_dates_at_any_precision() {
        for value in [
            b"2020-01-01T00:00:00Z".as_slice(),
            b"2020-01-01T00:00:00.123456Z".as_slice(),
            b"2020-01".as_slice(),
        ] {
            assert!(
                matches!(
                    HeaderValue::parse(Some(Field::Date), value),
                    Ok(HeaderValue {
                        form: Some(ValueForm::Date(_)),
                        ..
                    })
                ),
                "{value:?}"
            );
        }

        assert!(matches!(
            HeaderValue::parse(Some(Field::Date), b"yesterday"),
            Err(Error::Date(_))
        ));
    }

    /// A field the standard does not define has no grammar to fail.
    #[test]
    fn keeps_an_extension_value_as_written() {
        let value = HeaderValue::parse(None, b" anything at all; <>: \"").unwrap();

        assert_eq!(value.as_bytes(), b" anything at all; <>: \"");
        assert_eq!(value.form(), None);

        // A control character is outside `TEXT`, so it is refused even without a grammar.
        assert!(matches!(
            HeaderValue::parse(None, b"with\x07bell"),
            Err(Error::Text(_))
        ));

        // `TEXT` includes linear white space, so a tab inside a value is not one of them.
        let tabbed = HeaderValue::parse(None, b" with\ttab").unwrap();
        assert_eq!(tabbed.as_bytes(), b" with\ttab");
    }

    /// Bytes that are not UTF-8 fail every grammar that reads a value as text, and are kept
    /// where the grammar is `TEXT`, which admits any octet, or where there is no grammar.
    #[test]
    fn a_value_that_is_not_utf8_fails_the_grammars_that_read_text() {
        let cases: [(Field, &[u8], &str); 7] = [
            (Field::ContentLength, b"12\xff34", "not a number"),
            (Field::WarcType, b"resp\xffonse", "not a token"),
            (Field::RecordID, b"<urn:uuid:\xff>", "not a URI"),
            (Field::Date, b"2020-01-01T00:00:0\xffZ", "not a timestamp"),
            (Field::IPAddress, b"127.0.0.\xff", "not an IP address"),
            (Field::BlockDigest, b"sha1:AB\xffC", "not a labelled digest"),
            (Field::ContentType, b"text/pl\xffain", "not a media type"),
        ];

        for (field, value, rule) in cases {
            let error = HeaderValue::parse(Some(field), value).expect_err("not UTF-8");
            assert!(error.to_string().starts_with(rule), "{error}");
        }

        for field in [Some(Field::Filename), None] {
            let value = HeaderValue::parse(field, b"caf\xe9.warc").unwrap();

            assert_eq!(value.as_bytes(), b"caf\xe9.warc");
            assert_eq!(value.to_str(), None);
        }
    }

    /// Rendering a form and reading the result back gives the same form.
    #[test]
    fn rendering_round_trips() {
        let forms = [
            ValueForm::Digits(0),
            ValueForm::Token("response".into()),
            ValueForm::IpAddress("2001:db8::1".parse().unwrap()),
        ];
        let fields = [Field::ContentLength, Field::WarcType, Field::IPAddress];

        for (form, field) in forms.into_iter().zip(fields) {
            let value = HeaderValue::from(form.clone());
            assert_eq!(
                HeaderValue::parse(Some(field), value.as_bytes()).unwrap(),
                value
            );
            assert_eq!(value.form(), Some(&form));
        }
    }
}
