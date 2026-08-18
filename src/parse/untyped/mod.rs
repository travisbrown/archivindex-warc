//! Records with field values parsed according to their grammar.
//!
//! This representation sits above [`crate::parse::raw::Record`]. It uses the union of the WARC
//! 1.0 and 1.1 grammars, but does not check values or repeated fields against the declared
//! version and record type.

pub mod name;
pub mod value;

use name::{Field, HeaderName};
use value::HeaderValue;

use crate::parse::{self, raw};

/// A field whose value does not match the grammar its name selects.
///
/// This pairs a [`value::Error`](crate::value::Error) with the field that caused it.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Malformed {name} field: {source}")]
pub struct Error {
    /// The field's name, as it was written.
    pub name: String,
    /// The grammar rule the value failed.
    #[source]
    pub source: crate::value::Error,
}

/// A header block whose field names and values have been read against the grammar.
///
/// Each name keeps the spelling it was written with, and each value keeps its original bytes
/// alongside its parsed form, so a block read here writes back as it was read.
pub type RecordHeader = parse::RecordHeader<HeaderName, HeaderValue>;

impl RecordHeader {
    /// The first value written for a defined field.
    #[must_use]
    pub fn get(&self, field: Field) -> Option<&HeaderValue> {
        self.get_all(field).next()
    }

    /// Every value written for a defined field, in the order they were written.
    ///
    /// Only `WARC-Concurrent-To` may repeat under the standard, but repetition is not enforced at
    /// this level, so this reports every value present.
    pub fn get_all(&self, field: Field) -> impl Iterator<Item = &HeaderValue> {
        self.find_all(move |name| name.field() == Some(field))
    }

    /// The first value written for a field of the given name, compared case-insensitively.
    ///
    /// This reaches extension fields, which have no [`Field`] to name them.
    #[must_use]
    pub fn get_named(&self, name: &str) -> Option<&HeaderValue> {
        let sought = HeaderName::as_read(name);

        self.find(move |name| *name == sought)
    }

    /// Convert this header block back to its raw representation.
    ///
    /// This cannot fail: every name is a token, and every value is bytes that some grammar
    /// accepted.
    #[must_use]
    pub fn into_raw(self) -> raw::RecordHeader {
        raw::RecordHeader {
            version: self.version,
            headers: self
                .headers
                .into_iter()
                .map(|(name, value)| (name.into_name(), value.into_bytes()))
                .collect(),
        }
    }
}

impl TryFrom<raw::RecordHeader> for RecordHeader {
    type Error = Error;

    /// Read a raw header block's fields against the grammar.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] for the first field whose value does not match the grammar its name
    /// selects.
    fn try_from(header: raw::RecordHeader) -> Result<Self, Error> {
        let headers = header
            .headers
            .into_iter()
            .map(|(name, value)| {
                let name = HeaderName::as_read(&name);
                let value = HeaderValue::parse(name.field(), &value).map_err(|source| Error {
                    name: name.name().to_owned(),
                    source,
                })?;

                Ok((name, value))
            })
            .collect::<Result<_, Error>>()?;

        Ok(Self {
            version: header.version,
            headers,
        })
    }
}

/// A record whose field names and values have been read against the grammar.
pub type Record = parse::Record<HeaderName, HeaderValue>;

impl Record {
    /// Convert this record back to its raw representation.
    ///
    /// This cannot fail; see [`RecordHeader::into_raw`].
    #[must_use]
    pub fn into_raw(self) -> raw::Record {
        raw::Record {
            header: self.header.into_raw(),
            body: self.body,
        }
    }
}

impl TryFrom<raw::Record> for Record {
    type Error = Error;

    /// Read a raw record's fields against the grammar.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] for the first field whose value does not match the grammar its name
    /// selects.
    fn try_from(record: raw::Record) -> Result<Self, Error> {
        Ok(Self {
            header: RecordHeader::try_from(record.header)?,
            body: record.body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::value::ValueForm;
    use super::{Error, Field, Record};
    use crate::parse::raw;
    use crate::version::WarcVersion;

    fn raw(fields: &[(&str, &str)]) -> raw::Record {
        raw::RecordHeader {
            version: WarcVersion::V1_0,
            headers: fields
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.as_bytes().to_vec()))
                .collect(),
        }
        .with_body(Vec::new())
    }

    #[test]
    fn reads_fields_against_their_grammars() {
        let record = Record::try_from(raw(&[
            ("WARC-Type", "response"),
            ("Content-Length", "0"),
            ("WARC-Block-Digest", "sha1:ABC"),
            ("X-Custom", "whatever it likes"),
        ]))
        .unwrap();

        assert!(matches!(
            record.header.get(Field::WarcType).and_then(super::HeaderValue::form),
            Some(ValueForm::Token(token)) if &**token == "response"
        ));
        assert!(matches!(
            record
                .header
                .get(Field::BlockDigest)
                .and_then(super::HeaderValue::form),
            Some(ValueForm::Digest(_))
        ));
        // An extension field has no grammar, so it has no form.
        assert_eq!(
            record
                .header
                .get_named("x-custom")
                .map(super::HeaderValue::form),
            Some(None)
        );
        assert_eq!(record.header.get_named("nothing"), None);
    }

    /// Repetition is a semantic question, so the grammar layer keeps every field it is given.
    #[test]
    fn keeps_repeated_fields_in_order() {
        let record = Record::try_from(raw(&[
            ("Content-Length", "0"),
            ("WARC-Concurrent-To", "<urn:uuid:one>"),
            ("WARC-Concurrent-To", "<urn:uuid:two>"),
            ("WARC-Date", "2020-01-01T00:00:00Z"),
            ("WARC-Date", "2021-01-01T00:00:00Z"),
        ]))
        .unwrap();

        assert_eq!(record.header.get_all(Field::ConcurrentTo).count(), 2);
        assert_eq!(record.header.get_all(Field::Date).count(), 2);
    }

    #[test]
    fn reports_the_field_that_failed() {
        let error = Record::try_from(raw(&[
            ("Content-Length", "0"),
            ("WARC-IP-Address", "not-an-address"),
        ]))
        .unwrap_err();

        assert!(
            matches!(&error, Error { name, .. } if name == "WARC-IP-Address"),
            "{error}"
        );
    }

    /// A control character breaks no framing, so the raw layer keeps it. It is outside `TEXT`, so
    /// it is refused here, where the grammar is applied.
    #[test]
    fn refuses_a_control_character_the_raw_layer_kept() {
        let fields = [("Content-Length", "0"), ("X-Custom", "a\u{1}b")];
        assert!(raw(&fields).header.validate().is_ok());

        let error = Record::try_from(raw(&fields)).unwrap_err();
        assert!(
            matches!(&error, Error { name, .. } if name == "X-Custom"),
            "{error}"
        );
    }

    /// Reading and rendering are inverses when the bytes are the ones a grammar would write.
    #[test]
    fn renders_back_the_bytes_it_read() {
        let fields = [
            ("WARC-Type", "warcinfo"),
            ("content-length", "  0 "),
            ("WARC-Filename", "\"example.warc.gz\""),
            ("X-Custom", "kept\r\n\tfolded"),
        ];
        let before = raw(&fields);
        let after = Record::try_from(before.clone()).unwrap().into_raw();

        assert_eq!(after, before);
    }

    /// The one fault of this layer names the field that carried the value and carries the rule
    /// the value failed as its source, which names no field of its own.
    #[test]
    fn the_error_names_the_field_and_carries_the_rule() {
        let error = Error {
            name: "WARC-Date".to_owned(),
            source: crate::value::Error::Date("yesterday".to_owned()),
        };

        assert_eq!(
            error.to_string(),
            "Malformed WARC-Date field: not a timestamp: yesterday"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("not a timestamp: yesterday".to_owned())
        );
    }
}
