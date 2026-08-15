//! Record bodies written as `application/warc-fields`.
//!
//! Two record types describe something in named fields rather than carrying a payload:
//! [`warcinfo`] describes the WARC file or the crawl that produced it, and [`metadata`]
//! describes another record. The standard gives them the same shape: allowable fields include
//! all of the [DCMI Metadata Terms] plus a few the record type names itself, every field is
//! optional, and none is forbidden to repeat.
//!
//! [`Body`] is that shape, parameterized by the [`Field`] vocabulary of the record type it
//! belongs to, and [`warcinfo::WarcinfoBody`] and [`metadata::MetadataBody`] are the two it is
//! used at.
//!
//! [DCMI Metadata Terms]: https://www.dublincore.org/specifications/dublin-core/dcmi-terms/

pub mod dcmi;
pub mod metadata;
pub mod warcinfo;

use std::fmt::Display;
use std::str;

use crate::fields::dcmi::DcmiTerm;
use crate::parser;

/// An error returned by reading a record body written as `application/warc-fields`.
///
/// A body is read on its own, after the record framing has already given up its bytes, so
/// nothing here overlaps with [`crate::Error`]: these are the two ways a block of bytes fails
/// to be a run of named fields.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The block holds something other than a named field, at the given byte offset from its
    /// start. Reading stops there rather than dropping the rest, since a body silently read as
    /// empty would misdescribe what it belongs to.
    #[error("Not a named field at byte {offset} of the block.")]
    NotANamedField {
        /// Where in the block reading stopped.
        offset: usize,
    },
    /// A field's value is not valid UTF-8, which is the only encoding the standard permits a
    /// field value to be written in.
    #[error("The value of the `{name}` field is not valid UTF-8.")]
    InvalidValue {
        /// The name of the field, as it was spelled in the block.
        name: String,
    },
}

/// A named field of a record body written as `application/warc-fields`.
///
/// The vocabulary of such a body is open: it is the DCMI terms, plus the handful of fields the
/// record type defines for itself, plus whatever else a writer saw fit to add. An implementor
/// supplies the middle part and the two ways of holding the rest, and [`from_name`](Self::from_name)
/// puts them together the same way for every record type.
///
/// This trait must be in scope to name a field with [`name`](Self::name). Each field type also
/// implements [`Display`] and `From<S: AsRef<str>>`, which cover the same ground without it.
pub trait Field: Sized + Clone + Eq + 'static {
    /// The fields the record type defines for itself, beyond the DCMI vocabulary.
    ///
    /// This is the table [`from_name`](Self::from_name) looks a name up in before falling back
    /// to [`DcmiTerm::from_name`]. The names themselves live on [`name`](Self::name), so the
    /// table carries only the variants and the two cannot drift apart.
    const KNOWN: &'static [Self];

    /// The field's name as it is written in the record.
    ///
    /// Borrowing rather than allocating, so that naming a field on a write path costs nothing.
    /// This is the canonical spelling of the field rather than the spelling it was read with,
    /// which loses nothing: a body that has not been changed is written back out as the block
    /// it was read from, spellings included. See [`Body::source`].
    fn name(&self) -> &str;

    /// The field holding a term of the DCMI vocabulary, all of which are allowed in such a
    /// body.
    fn dcmi(term: DcmiTerm) -> Self;

    /// The field holding a name belonging to neither vocabulary, given lower-cased.
    fn other(name: String) -> Self;

    /// Read a name as the field it names, ignoring case as the standard requires.
    ///
    /// Unlike [`DcmiTerm::from_name`] this cannot fail, since the vocabulary is open. A name
    /// in neither vocabulary is kept lower-cased, so that two spellings of one extension field
    /// are still the same field.
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
/// The fields are kept in the order they appeared, and a name may appear more than once: DCMI
/// properties such as `subject` and `description` are repeatable by design, and the standard
/// places no restriction on repetition here. [`get`](Self::get) therefore reports the first
/// value of a field and [`get_all`](Self::get_all) reports every one.
///
/// A parsed body also keeps the block it was read from, so that a record read and written
/// again is unchanged and any digest taken over its block still verifies. Reading a body is
/// lossy on its own (names take their canonical spelling, folded values are joined onto one
/// line, and the space after a colon is normalized), and the retained block is what covers
/// that. Changing the body discards it, since it no longer describes what the body says.
#[derive(Clone, Debug)]
pub struct Body<F> {
    fields: Vec<(F, String)>,
    /// The block this body was read from, held until the body is changed.
    source: Option<Box<str>>,
}

impl<F> Body<F> {
    /// An empty body, describing nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fields: Vec::new(),
            source: None,
        }
    }

    /// Add a field to the end of the body, whether or not it already appears.
    ///
    /// The body no longer says what the block it was read from says, so that block is
    /// released and the body is written canonically from here on.
    pub fn push(&mut self, field: impl Into<F>, value: impl Into<String>) {
        self.fields.push((field.into(), value.into()));
        self.source = None;
    }

    /// The block this body was read from, exactly as it was read.
    ///
    /// This is `None` for a body that was built rather than read, and for one that has been
    /// changed since it was read; either way the body is written canonically instead. A
    /// caller that must leave an existing block digest verifiable can ask here which of the
    /// two writing the body will give.
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
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the body describes nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl<F: Field> Body<F> {
    /// Read a record's body.
    ///
    /// Values are decoded as UTF-8, which is what the standard permits them to contain, and a
    /// value folded over several lines is joined with a single space per fold. The block may
    /// end with the bare `CRLF` the grammar closes it with, and, since a block copied out of a
    /// record by hand often stops at the last character of the last value, it need not end
    /// with a line ending at all.
    ///
    /// The block is kept alongside the fields it was read as, so that writing the body back
    /// out reproduces it byte for byte. See [`source`](Self::source).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotANamedField`] if the block holds anything that is not a named
    /// field, or [`Error::InvalidValue`] if a field's value is not valid UTF-8.
    ///
    /// # Panics
    ///
    /// If a block that parsed as named fields is not UTF-8 taken as a whole, which cannot
    /// happen: every value in it has been decoded by then, and everything the grammar writes
    /// around a value is ASCII.
    pub fn parse(block: &[u8]) -> Result<Self, Error> {
        // Supplying the missing terminator is what allows an unterminated last line, and the
        // copy that costs is made only for a block that lacks one.
        let mut body = if block.last().is_some_and(|byte| *byte != b'\n') {
            let mut terminated = Vec::with_capacity(block.len() + 2);
            terminated.extend_from_slice(block);
            terminated.extend_from_slice(b"\r\n");

            Self::parse_terminated(&terminated)?
        } else {
            Self::parse_terminated(block)?
        };

        // Every value has just been decoded as UTF-8, everything the grammar writes around a
        // value is ASCII, and the pieces of a folded value are joined at a space, which is a
        // character boundary. A block that parsed is therefore text. What is kept is the
        // caller's block rather than the terminated copy, so that a body written back out is
        // the bytes that were read.
        let source = str::from_utf8(block)
            .expect("invariant violation: a parsed warc-fields block is not UTF-8");
        body.source = Some(source.into());

        Ok(body)
    }

    /// Read a block whose last field line is known to be terminated.
    fn parse_terminated(block: &[u8]) -> Result<Self, Error> {
        // The parser stops at the first line that is not a named field rather than failing, so
        // what it did not consume is where a malformed block is reported from. Reading nothing
        // at all is that same report with the whole block left over.
        let (rest, parsed) = parser::fields(block).unwrap_or((block, Vec::new()));

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
        // Written out rather than as `get_all(field).next()`, so that the value borrows the
        // body alone and the field it names need not outlive the borrow.
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

impl<F> Default for Body<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Two bodies are equal when they describe the same thing in the same order, whatever
/// spellings and line breaks each was written with. The block a body was read from is a record
/// of how it arrived rather than part of what it says, so it is not compared.
impl<F: PartialEq> PartialEq for Body<F> {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
    }
}

impl<F: Eq> Eq for Body<F> {}

/// Writes the block the body was read from, if it still stands for what the body says, and
/// otherwise renders the body as `application/warc-fields`: one `CRLF`-terminated line per
/// field, under the canonical spelling of each name, with no blank line closing the block. The
/// record framing writes the blank line that follows a body, and [`Body::parse`] accepts a
/// block written either way, so this round-trips.
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
    use crate::fields::dcmi::DcmiTerm;

    /// Writing a body out and reading it back gives the same body, and the rendering is the
    /// named fields of the block in the order they were added.
    #[test]
    fn a_body_round_trips_through_its_rendering() {
        let mut body = WarcinfoBody::new();
        assert!(body.is_empty());

        body.push(WarcinfoField::Software, "archivindex/0.1.0");
        body.push(WarcinfoField::Dcmi(DcmiTerm::IsPartOf), "a-crawl");
        body.push("x-custom", "a value");

        assert_eq!(
            body.to_string(),
            "software: archivindex/0.1.0\r\nisPartOf: a-crawl\r\nx-custom: a value\r\n"
        );
        assert_eq!(
            WarcinfoBody::parse(body.to_string().as_bytes()).expect("round trip"),
            body
        );
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

    /// Once a body has been changed it no longer says what the block it was read from says,
    /// so it is written canonically instead.
    #[test]
    fn a_modified_body_is_written_canonically() {
        let mut body = WarcinfoBody::parse(b"SOFTWARE:  one\r\nX-Custom: two\r\n").expect("block");
        assert!(body.source().is_some());

        body.push(WarcinfoField::Robots, "classic");

        assert_eq!(body.source(), None);
        assert_eq!(
            body.to_string(),
            "software: one\r\nx-custom: two\r\nrobots: classic\r\n"
        );
    }

    /// The block a body was read from is not part of what it says, so a body read from one
    /// and a body built by hand are equal when they describe the same thing.
    #[test]
    fn equality_ignores_the_block_the_body_was_read_from() {
        let read = WarcinfoBody::parse(b"SOFTWARE:  one\r\nIsPartOf:\r\n two\r\n").expect("block");

        let mut built = WarcinfoBody::new();
        built.push(WarcinfoField::Software, "one");
        built.push(WarcinfoField::Dcmi(DcmiTerm::IsPartOf), "two");

        assert_eq!(read, built);
        assert!(read.source().is_some());
        assert_eq!(built.source(), None);
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
    /// dropped, since a body read as empty would misdescribe what it belongs to.
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

    /// A name outside both vocabularies is an extension field under its lower-cased spelling,
    /// whichever record type's vocabulary it was read against.
    #[test]
    fn a_name_in_neither_vocabulary_is_an_extension_field() {
        assert_eq!(
            WarcinfoField::from_name("X-Custom"),
            WarcinfoField::Other("x-custom".to_string())
        );
    }
}
