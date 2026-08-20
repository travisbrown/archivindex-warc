//! Record bodies written as `application/warc-fields`.
//!
//! [`warcinfo`] describes a WARC file or crawl, while [`metadata`] describes another record. Both
//! use optional, repeatable named fields drawn from the [DCMI Metadata Terms], fields defined by
//! the record type, and extension fields. [`Body`] provides their shared representation. With the
//! `serde` feature, the `serde` module converts between bodies and caller-defined types.
//!
//! [DCMI Metadata Terms]: https://www.dublincore.org/specifications/dublin-core/dcmi-terms/

mod parser;

pub mod dcmi;
pub mod metadata;
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde;
pub mod warcinfo;

use std::fmt::Display;
use std::str;

use crate::parsing::{is_text, is_token};
use crate::record::fields::dcmi::DcmiTerm;

/// An error returned by reading a record body written as `application/warc-fields`.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The block contains something other than a named field at the given byte offset.
    #[error("Not a named field at byte {offset} of the block.")]
    NotANamedField {
        /// Where in the block reading stopped.
        offset: usize,
    },
    /// A field's value is not valid UTF-8, which is the only encoding the standard permits.
    #[error("The value of the `{name}` field is not valid UTF-8.")]
    InvalidValue {
        /// The name of the field, as it was spelled in the block.
        name: String,
    },
    /// A field carries a name or a value that cannot be written as a valid field line.
    #[error("The `{name}` field cannot be written: {reason}.")]
    UnwritableField {
        /// The field's name, as it was given.
        name: String,
        /// What about the field cannot be written.
        reason: String,
    },
}

/// A named field of a record body written as `application/warc-fields`.
///
/// Implementations combine DCMI terms, fields defined by the record type, and extension fields.
///
/// This trait must be in scope to call [`name`](Self::name). Field types also implement [`Display`]
/// and `From<S: AsRef<str>>`.
pub trait Field: Sized + Clone + Eq + 'static {
    /// The fields the record type defines for itself, beyond the DCMI vocabulary.
    ///
    /// [`from_name`](Self::from_name) checks these before the DCMI vocabulary.
    const KNOWN: &'static [Self];

    /// The field's name in its canonical spelling.
    ///
    /// This may differ from the source spelling. Unchanged bodies retain their source block.
    fn name(&self) -> &str;

    /// The field holding a term of the DCMI vocabulary.
    fn dcmi(term: DcmiTerm) -> Self;

    /// The field holding a name belonging to neither vocabulary, given lower-cased.
    fn other(name: String) -> Self;

    /// Read a name as the field it names, ignoring case as the standard requires.
    ///
    /// Names outside the known vocabularies become extension fields normalized to lowercase.
    fn from_name(name: &str) -> Self {
        Self::KNOWN
            .iter()
            .find(|field| name.eq_ignore_ascii_case(field.name()))
            .cloned()
            .unwrap_or_else(|| {
                DcmiTerm::from_name(name)
                    .map_or_else(|| Self::other(name.to_lowercase()), Self::dcmi)
            })
    }
}

/// A record body written as `application/warc-fields`.
///
/// Fields retain their order and may repeat. [`get`](Self::get) returns the first value, while
/// [`get_all`](Self::get_all) returns every value.
///
/// A parsed body keeps its source block for byte-exact round-tripping. Changing the body discards
/// the source, after which the fields are rendered canonically. See [`source`](Self::source).
///
/// A field of a body is one the grammar can write back: [`push`](Self::push) refuses a name that
/// is not a token or a value that is not `TEXT`, and a parsed block holds nothing else.
#[derive(Clone, Debug)]
pub struct Body<F> {
    fields: Vec<(F, String)>,
    /// The block this body was read from, held until the body is changed.
    source: Option<Box<str>>,
}

impl<F> Body<F> {
    /// An empty body.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fields: Vec::new(),
            source: None,
        }
    }

    /// The block this body was read from, exactly as it was read.
    ///
    /// This is `None` for a new or modified body, which is rendered canonically. A caller that
    /// needs to preserve an existing block digest can use this to check whether the original bytes
    /// are still available.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Every field of the body, in the order they appeared.
    pub fn iter(&self) -> impl Iterator<Item = (&F, &str)> {
        self.fields
            .iter()
            .map(|(field, value)| (field, value.as_str()))
    }

    /// The number of field lines in the body, counting a repeated name once per appearance.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the body has no fields.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl<F: Field> Body<F> {
    /// Add a field to the end of the body, whether or not it already appears.
    ///
    /// This releases the retained source block, so the body is written canonically from here on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnwritableField`] if the field's name is not a token or its value is not
    /// `TEXT`. A value holding a line break would be read back as a field of its own, and a name
    /// outside the token grammar would not be read back as a field at all.
    pub fn push(&mut self, field: impl Into<F>, value: impl Into<String>) -> Result<(), Error> {
        let field = field.into();
        let value = value.into();
        check_writable(&field, &value)?;

        self.fields.push((field, value));
        self.source = None;

        Ok(())
    }

    /// Give a field one value, in place of every value it already has.
    ///
    /// A field the body does not carry is added at the end. One it carries already keeps the
    /// position of its first appearance and loses any other.
    ///
    /// This releases the retained source block, so the body is written canonically from here on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnwritableField`] under the same conditions as [`push`](Self::push).
    pub fn set(&mut self, field: impl Into<F>, value: impl Into<String>) -> Result<(), Error> {
        let field = field.into();
        let value = value.into();
        check_writable(&field, &value)?;

        if let Some(first) = self.fields.iter().position(|(name, _)| *name == field) {
            self.fields[first].1 = value;

            let mut index = 0;
            self.fields.retain(|(name, _)| {
                let keep = index <= first || *name != field;
                index += 1;
                keep
            });
        } else {
            self.fields.push((field, value));
        }
        self.source = None;

        Ok(())
    }

    /// The number of octets the body renders as, which is the `Content-Length` of a record
    /// carrying it.
    ///
    /// Computed without building the block. A body still holding the block it was read from
    /// reports that block's length.
    #[must_use]
    pub fn rendered_len(&self) -> usize {
        self.source.as_ref().map_or_else(
            || {
                self.fields
                    .iter()
                    // Each line is `name`, `": "`, `value`, and the closing `CRLF`.
                    .map(|(field, value)| field.name().len() + value.len() + 4)
                    .sum()
            },
            |source| source.len(),
        )
    }

    /// Parse a record body.
    ///
    /// Values must be UTF-8. Folds become single spaces. The final field may end with `CRLF` or at
    /// the end of the block.
    ///
    /// The block is kept alongside the fields it was read as, so that writing the body back out
    /// reproduces it byte for byte. See [`source`](Self::source).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotANamedField`] if the block holds anything that is not a named
    /// field, or [`Error::InvalidValue`] if a field's value is not valid UTF-8.
    ///
    /// # Panics
    ///
    /// If a block that parsed as named fields is not UTF-8 taken as a whole, which cannot happen:
    /// every value in it has been decoded by then, and the rest of the grammar is ASCII.
    pub fn parse(block: &[u8]) -> Result<Self, Error> {
        // Supplying the missing terminator allows an unterminated last line; the copy is made
        // only for a block that lacks one.
        let mut body = if block.last().is_some_and(|byte| *byte != b'\n') {
            let mut terminated = Vec::with_capacity(block.len() + 2);
            terminated.extend_from_slice(block);
            terminated.extend_from_slice(b"\r\n");

            Self::parse_terminated(&terminated)?
        } else {
            Self::parse_terminated(block)?
        };

        // Every value has just been decoded as UTF-8, everything the grammar writes around a
        // value is ASCII, and folds are joined at a space, so a block that parsed is valid UTF-8.
        // We keep the caller's block rather than the terminated copy, so that a body written back
        // out is the bytes that were read.
        let source = str::from_utf8(block)
            .expect("invariant violation: a parsed warc-fields block is not UTF-8");
        body.source = Some(source.into());

        Ok(body)
    }

    /// Read a block whose last field line is known to be terminated.
    fn parse_terminated(block: &[u8]) -> Result<Self, Error> {
        // The parser stops at the first line that is not a named field rather than failing, so a
        // malformed block is reported at the offset of whatever was left unread.
        let (rest, parsed) = parser::fields(block);

        // The grammar closes a block with one bare CRLF, which carries no field of its own.
        let rest = rest
            .strip_prefix(b"\r\n")
            .or_else(|| rest.strip_prefix(b"\n"))
            .unwrap_or(rest);

        if !rest.is_empty() {
            return Err(Error::NotANamedField {
                offset: block.len() - rest.len(),
            });
        }

        let mut fields = Vec::with_capacity(parsed.len());
        for (name, value) in parsed {
            let value = str::from_utf8(&value).map_err(|_| Error::InvalidValue {
                name: name.to_string(),
            })?;

            fields.push((F::from_name(name), value.to_string()));
        }

        Ok(Self {
            fields,
            source: None,
        })
    }

    /// The first value written for a field, if it appears at all.
    #[must_use]
    pub fn get(&self, field: &F) -> Option<&str> {
        // Written out rather than as `get_all(field).next()`, so that the value borrows the body
        // alone and the field need not outlive the borrow.
        self.fields
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value.as_str())
    }

    /// Every value written for a field, in the order they appeared.
    pub fn get_all<'a>(&'a self, field: &'a F) -> impl Iterator<Item = &'a str> {
        self.fields
            .iter()
            .filter(move |(name, _)| name == field)
            .map(|(_, value)| value.as_str())
    }
}

/// Check that a field can be written back as a field line before it is added to a body.
fn check_writable<F: Field>(field: &F, value: &str) -> Result<(), Error> {
    if !is_token(field.name().as_bytes()) {
        return Err(Error::UnwritableField {
            name: field.name().to_owned(),
            reason: "the name is not a token".to_owned(),
        });
    }
    // A value is held here with its folds already resolved, so a line break in one is a field
    // line the caller wrote into it rather than a fold.
    if !is_text(value.as_bytes()) {
        return Err(Error::UnwritableField {
            name: field.name().to_owned(),
            reason: "the value holds a control character".to_owned(),
        });
    }

    Ok(())
}

impl<F> Default for Body<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare parsed fields and values, ignoring the retained source block.
impl<F: PartialEq> PartialEq for Body<F> {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
    }
}

impl<F: Eq> Eq for Body<F> {}

/// Write the source block if unchanged, or render one canonical `CRLF` terminated line per field.
/// The record framing, not this formatter, adds the final blank line.
impl<F: Field> Display for Body<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(source) = &self.source {
            return f.write_str(source);
        }

        for (field, value) in &self.fields {
            write!(f, "{}: {value}\r\n", field.name())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::warcinfo::{WarcinfoBody, WarcinfoField};
    use super::{Error, Field};
    use crate::record::fields::dcmi::DcmiTerm;

    /// Writing a body out and reading it back gives the same body, and the rendering is the
    /// named fields of the block in the order they were added.
    #[test]
    fn a_body_round_trips_through_its_rendering() -> Result<(), Error> {
        let mut body = WarcinfoBody::new();
        assert!(body.is_empty());

        body.push(WarcinfoField::Software, "archivindex/0.1.0")?;
        body.push(WarcinfoField::Dcmi(DcmiTerm::IsPartOf), "a-crawl")?;
        body.push("x-custom", "a value")?;

        assert_eq!(
            body.to_string(),
            "software: archivindex/0.1.0\r\nisPartOf: a-crawl\r\nx-custom: a value\r\n"
        );
        assert_eq!(WarcinfoBody::parse(body.to_string().as_bytes())?, body);

        Ok(())
    }

    /// Setting a field gives it the value in place of every one it had, at the position its
    /// first appearance held, and adds it at the end when the body did not carry it at all.
    #[test]
    fn setting_a_field_replaces_every_value_it_had() -> Result<(), Error> {
        let mut body = WarcinfoBody::new();

        body.push(WarcinfoField::Software, "one")?;
        body.push(WarcinfoField::Hostname, "a-host")?;
        body.push(WarcinfoField::Software, "two")?;

        body.set(WarcinfoField::Software, "three")?;
        body.set(WarcinfoField::Operator, "an-operator")?;

        assert_eq!(
            body.to_string(),
            "software: three\r\nhostname: a-host\r\noperator: an-operator\r\n"
        );
        assert_eq!(body.get_all(&WarcinfoField::Software).count(), 1);

        Ok(())
    }

    /// The length a body reports is the length of what it writes, whether that is the block it
    /// was read from or the canonical rendering it falls back to once it has been changed.
    #[test]
    fn a_body_reports_the_length_it_writes() -> Result<(), Error> {
        for block in [
            &b"SOFTWARE:  one\r\nIsPartOf:\r\n\ttwo\r\nX-Custom: three\r\n\r\n"[..],
            &b"software: one"[..],
            &b""[..],
        ] {
            let mut body = WarcinfoBody::parse(block)?;
            assert_eq!(body.rendered_len(), block.len(), "{block:?}");

            body.push(WarcinfoField::Hostname, "crawler.example.com")?;
            assert_eq!(body.rendered_len(), body.to_string().len(), "{block:?}");
        }

        Ok(())
    }

    /// A body that has not been changed is written back out as the block it was read from,
    /// down to the spelling of each name, the folding of each value, the space after each
    /// colon, and the way the block ends.
    #[test]
    fn an_unmodified_body_is_written_as_it_was_read() {
        for block in [
            &b"SOFTWARE:  one\r\nIsPartOf:\r\n\ttwo\r\nX-Custom: three\r\n\r\n"[..],
            &b"software: one"[..],
            &b""[..],
        ] {
            let body = WarcinfoBody::parse(block).expect("block");
            let written = body.to_string();

            assert_eq!(written.as_bytes(), block, "{block:?}");
            assert_eq!(body.source(), Some(written.as_str()), "{block:?}");
        }
    }

    /// Once a body has been changed it is written canonically rather than from the block it was
    /// read from.
    #[test]
    fn a_modified_body_is_written_canonically() -> Result<(), Error> {
        let mut body = WarcinfoBody::parse(b"SOFTWARE:  one\r\nX-Custom: two\r\n")?;
        assert!(body.source().is_some());

        body.push(WarcinfoField::Robots, "classic")?;

        assert_eq!(body.source(), None);
        assert_eq!(
            body.to_string(),
            "software: one\r\nx-custom: two\r\nrobots: classic\r\n"
        );

        Ok(())
    }

    /// A body read from a block and a body built by hand are equal when their fields match.
    #[test]
    fn equality_ignores_the_block_the_body_was_read_from() -> Result<(), Error> {
        let read = WarcinfoBody::parse(b"SOFTWARE:  one\r\nIsPartOf:\r\n two\r\n")?;

        let mut built = WarcinfoBody::new();
        built.push(WarcinfoField::Software, "one")?;
        built.push(WarcinfoField::Dcmi(DcmiTerm::IsPartOf), "two")?;

        assert_eq!(read, built);
        assert!(read.source().is_some());
        assert_eq!(built.source(), None);

        Ok(())
    }

    /// A repeated field keeps every value it was given, in order, and reports the first as its
    /// value.
    #[test]
    fn repeated_fields_keep_every_value() {
        let body = WarcinfoBody::parse(b"subject: one\r\ndescription: two\r\nsubject: three\r\n")
            .expect("repeated fields");

        let subject = WarcinfoField::Dcmi(DcmiTerm::Subject);
        assert_eq!(body.get(&subject), Some("one"));
        assert_eq!(body.get_all(&subject).collect::<Vec<_>>(), ["one", "three"]);
        assert_eq!(body.len(), 3);
    }

    /// A block may close with the bare CRLF of the grammar, may stop at the last character of
    /// its last value, and may be empty, all reading as the same fields.
    #[test]
    fn a_block_may_be_terminated_any_of_the_ways_it_is_written() {
        for block in [
            &b"software: one\r\n"[..],
            &b"software: one\r\n\r\n"[..],
            &b"software: one"[..],
        ] {
            let body = WarcinfoBody::parse(block).expect("terminator");
            assert_eq!(body.software(), Some("one"));
            assert_eq!(body.len(), 1);
        }

        for block in [&b""[..], &b"\r\n"[..]] {
            assert!(WarcinfoBody::parse(block).expect("empty block").is_empty());
        }
    }

    /// Anything in the block that is not a named field is an error rather than a field quietly
    /// dropped.
    #[test]
    fn a_block_that_is_not_named_fields_is_rejected() {
        // The offset is where reading stopped, which is the start of the block when nothing in
        // it was a field at all.
        for (block, offset) in [
            (&b"not a named field\r\n"[..], 0),
            (&b"software: one\r\nthen some prose\r\n"[..], 15),
            (&b"software: one\r\n\r\nsoftware: two\r\n"[..], 17),
        ] {
            assert_eq!(
                WarcinfoBody::parse(block),
                Err(Error::NotANamedField { offset }),
                "{block:?}"
            );
        }

        // Values are UTF-8, so a lone continuation byte is not one.
        assert_eq!(
            WarcinfoBody::parse(b"description: \xff\r\n"),
            Err(Error::InvalidValue {
                name: "description".to_string()
            })
        );
    }

    /// A value holding a line break would be written as further field lines, so it is refused
    /// rather than written.
    #[test]
    fn a_value_that_would_be_written_as_another_field_is_refused() {
        let mut body = WarcinfoBody::new();

        for value in ["one\r\ninjected: two", "one\rtwo", "one\ntwo"] {
            assert_eq!(
                body.push(WarcinfoField::Software, value),
                Err(Error::UnwritableField {
                    name: "software".to_string(),
                    reason: "the value holds a control character".to_string()
                }),
                "{value:?}"
            );
        }

        assert!(body.is_empty());
    }

    /// A value is `TEXT`, which admits the white space a field line is written with and no other
    /// control character.
    #[test]
    fn a_value_holds_text_alone() -> Result<(), Error> {
        let mut body = WarcinfoBody::new();

        for value in ["\x00", "\x7f", "\x1b[0m"] {
            assert!(body.push("x-custom", value).is_err(), "{value:?}");
        }

        body.push("x-custom", "one\ttwo three")?;
        assert_eq!(body.to_string(), "x-custom: one\ttwo three\r\n");

        Ok(())
    }

    /// A name is a token, so one holding the punctuation that separates a field from its value
    /// or from the next field is refused.
    #[test]
    fn a_name_that_is_not_a_token_is_refused() {
        let mut body = WarcinfoBody::new();

        for name in ["x-custom: injected\r\nevil", "x custom", "x:custom", ""] {
            assert_eq!(
                body.push(name, "a value"),
                Err(Error::UnwritableField {
                    name: name.to_lowercase(),
                    reason: "the name is not a token".to_string()
                }),
                "{name:?}"
            );
        }

        assert!(body.is_empty());
    }

    /// A name outside both vocabularies is an extension field under its lower-cased spelling.
    #[test]
    fn a_name_in_neither_vocabulary_is_an_extension_field() {
        assert_eq!(
            WarcinfoField::from_name("X-Custom"),
            WarcinfoField::Other("x-custom".to_string())
        );
    }
}
