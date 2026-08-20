//! Serde support for `application/warc-fields` bodies.
//!
//! [`from_body`] deserializes a [`Body`] into a caller-defined type, and [`to_body`] serializes a
//! value into a body. This provides typed schemas for `warcinfo` and `metadata` records without
//! using the accessors on [`WarcinfoBody`](super::warcinfo::WarcinfoBody) or
//! [`MetadataBody`](super::metadata::MetadataBody).
//!
//! The mapping:
//!
//! - Bodies map to flat structs or maps. Values may be text, types parsed from text, or sequences
//!   representing repeated fields.
//! - Field names match case-insensitively. Use `#[serde(rename_all = "camelCase")]` for DCMI names
//!   such as `isPartOf`, and `#[serde(rename = "...")]` for names that need individual handling.
//! - An absent required field is an error. An absent `Option` is `None`; an optional sequence needs
//!   `#[serde(default)]`.
//! - A repeated field must deserialize as a sequence.
//! - Unknown fields are ignored unless the type uses `#[serde(deny_unknown_fields)]`.
//! - Serialization writes fields in serialization order, omits `None`, writes one line per
//!   sequence element, and validates each line with [`Body::push`].
//!
//! [`Body`] remains the lossless representation: it preserves unknown fields, repetition, order,
//! and the original bytes. Deserialization projects that data into a type; serialization creates
//! a new canonical body.
//!
//! ```
//! use archivindex_warc::record::fields::serde::{from_body, to_body};
//! use archivindex_warc::record::fields::warcinfo::WarcinfoBody;
//!
//! #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
//! #[serde(rename_all = "camelCase")]
//! struct CrawlInfo {
//!     software: String,
//!     is_part_of: String,
//!     #[serde(default)]
//!     subject: Vec<String>,
//!     operator: Option<String>,
//! }
//!
//! let body = WarcinfoBody::parse(
//!     b"software: mycrawler/1.0\r\n\
//!       isPartOf: crawl-2026-08\r\n\
//!       subject: one\r\n\
//!       subject: two\r\n",
//! )?;
//!
//! let info: CrawlInfo = from_body(&body)?;
//! assert_eq!(info.software, "mycrawler/1.0");
//! assert_eq!(info.subject, ["one", "two"]);
//! assert_eq!(info.operator, None);
//!
//! let rebuilt: WarcinfoBody = to_body(&info)?;
//! assert_eq!(
//!     rebuilt.to_string(),
//!     "software: mycrawler/1.0\r\nisPartOf: crawl-2026-08\r\nsubject: one\r\nsubject: two\r\n"
//! );
//! # Ok::<(), archivindex_warc::record::fields::serde::Error>(())
//! ```

use std::fmt::Display;
use std::marker::PhantomData;
use std::str;

use serde::de::value::BorrowedStrDeserializer;
use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};
use serde::forward_to_deserialize_any;
use serde::ser::{self, Impossible, Serialize};

use crate::record::fields::{self, Body, Field};

/// An error from deserializing or serializing a body.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A field cannot be written as a field line. See [`fields::Error::UnwritableField`].
    #[error(transparent)]
    Field(#[from] fields::Error),
    /// A repeated field was deserialized as a single value instead of a sequence.
    #[error("The `{name}` field appears {count} times where one value is expected.")]
    RepeatedField {
        /// The requested field name.
        name: String,
        /// How many times the field appears in the body.
        count: usize,
    },
    /// A field's text cannot be parsed as the requested type.
    #[error("The `{name}` field cannot be read as {expected}.")]
    UnreadableValue {
        /// The requested field name.
        name: String,
        /// What the value was expected to parse as.
        expected: &'static str,
    },
    /// A value has no representation as flat, named text fields.
    #[error("Unsupported for warc-fields: {0}.")]
    Unsupported(&'static str),
    /// Another Serde error, such as a missing required field.
    #[error("{0}")]
    Message(String),
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }
}

/// Deserialize a body into a caller-defined type.
///
/// Values borrow from the body, so a struct of `&str` fields reads without copying.
///
/// # Errors
///
/// Returns errors from the type's `Deserialize` implementation, or [`Error::RepeatedField`] and
/// [`Error::UnreadableValue`] when the body does not match the requested shape.
pub fn from_body<'de, F: Field, T: de::Deserialize<'de>>(body: &'de Body<F>) -> Result<T, Error> {
    T::deserialize(BodyDeserializer { body })
}

/// Serialize a value as a body.
///
/// The type must serialize as a struct or map. Fields are written in the order they are
/// serialized, `None` fields are omitted, and a sequence writes one field line per element.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] for an unsupported shape, or [`Error::Field`] when
/// [`Body::push`] rejects a name or value.
pub fn to_body<F: Field, T: Serialize + ?Sized>(value: &T) -> Result<Body<F>, Error> {
    value.serialize(BodySerializer { field: PhantomData })
}

impl<F: Field> Body<F> {
    /// Deserialize the body. This is equivalent to [`from_body`].
    pub fn deserialize<'de, T: de::Deserialize<'de>>(&'de self) -> Result<T, Error> {
        from_body(self)
    }
}

/// Group field lines by name in first-appearance order.
///
/// When an expected name matches case-insensitively, use its spelling.
fn grouped<'de, F: Field>(
    body: &'de Body<F>,
    expected: &'static [&'static str],
) -> Vec<(&'de str, Vec<&'de str>)> {
    let mut entries: Vec<(&'de str, Vec<&'de str>)> = Vec::new();

    for (field, value) in body.iter() {
        let name = field.name();
        let name = expected
            .iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(name))
            .copied()
            .unwrap_or(name);

        if let Some((_, values)) = entries
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            values.push(value);
        } else {
            entries.push((name, vec![value]));
        }
    }

    entries
}

/// Deserializes a body as a map of grouped fields.
struct BodyDeserializer<'de, F> {
    body: &'de Body<F>,
}

impl<'de, F: Field> Deserializer<'de> for BodyDeserializer<'de, F> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_map(GroupedFields::new(grouped(self.body, &[])))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_map(GroupedFields::new(grouped(self.body, fields)))
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
        ignored_any
    }
}

/// A body's grouped fields, exposed as one map entry per name.
struct GroupedFields<'de> {
    entries: std::vec::IntoIter<(&'de str, Vec<&'de str>)>,
    /// The entry awaiting a value read.
    pending: Option<(&'de str, Vec<&'de str>)>,
}

impl<'de> GroupedFields<'de> {
    fn new(entries: Vec<(&'de str, Vec<&'de str>)>) -> Self {
        Self {
            entries: entries.into_iter(),
            pending: None,
        }
    }
}

impl<'de> MapAccess<'de> for GroupedFields<'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        self.entries.next().map_or(Ok(None), |entry| {
            let name = entry.0;
            self.pending = Some(entry);

            seed.deserialize(BorrowedStrDeserializer::new(name))
                .map(Some)
        })
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let (name, values) = self
            .pending
            .take()
            .expect("invariant violation: a map value was read before its key");

        seed.deserialize(FieldValues { name, values })
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

/// Implement scalar deserialization by parsing a field's text.
macro_rules! parse_single {
    ($($method:ident($ty:ty) => $visit:ident, $expected:literal;)*) => {
        $(
            fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
                let parsed: $ty = self.single()?.parse().map_err(|_| Error::UnreadableValue {
                    name: self.name.to_string(),
                    expected: $expected,
                })?;

                visitor.$visit(parsed)
            }
        )*
    };
}

/// All values for one field name.
struct FieldValues<'de> {
    name: &'de str,
    /// Values in field-line order. Never empty.
    values: Vec<&'de str>,
}

impl<'de> FieldValues<'de> {
    /// Return the sole value, or an error if the field repeats.
    fn single(&self) -> Result<&'de str, Error> {
        match self.values.as_slice() {
            &[value] => Ok(value),
            values => Err(Error::RepeatedField {
                name: self.name.to_string(),
                count: values.len(),
            }),
        }
    }
}

impl<'de> Deserializer<'de> for FieldValues<'de> {
    type Error = Error;

    /// Expose one value as text and repeated values as a sequence.
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.values.len() > 1 {
            self.deserialize_seq(visitor)
        } else {
            visitor.visit_borrowed_str(self.single()?)
        }
    }

    parse_single! {
        deserialize_bool(bool) => visit_bool, "a boolean";
        deserialize_i8(i8) => visit_i8, "an integer";
        deserialize_i16(i16) => visit_i16, "an integer";
        deserialize_i32(i32) => visit_i32, "an integer";
        deserialize_i64(i64) => visit_i64, "an integer";
        deserialize_i128(i128) => visit_i128, "an integer";
        deserialize_u8(u8) => visit_u8, "an integer";
        deserialize_u16(u16) => visit_u16, "an integer";
        deserialize_u32(u32) => visit_u32, "an integer";
        deserialize_u64(u64) => visit_u64, "an integer";
        deserialize_u128(u128) => visit_u128, "an integer";
        deserialize_f32(f32) => visit_f32, "a floating-point number";
        deserialize_f64(f64) => visit_f64, "a floating-point number";
        deserialize_char(char) => visit_char, "a character";
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_borrowed_str(self.single()?)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_borrowed_bytes(self.single()?.as_bytes())
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_bytes(visitor)
    }

    /// A present field is always `Some`; Serde handles absent fields before this point.
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::Unsupported("a field's value read as a unit"))
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(Error::Unsupported("a field's value read as a unit struct"))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_seq(FieldValuesSeq {
            name: self.name,
            values: self.values.into_iter(),
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::Unsupported("a field's value read as a nested map"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(Error::Unsupported(
            "a field's value read as a nested struct",
        ))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_enum(UnitVariant {
            value: self.single()?,
        })
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_any(visitor)
    }
}

/// A repeated field exposed as a sequence.
struct FieldValuesSeq<'de> {
    name: &'de str,
    values: std::vec::IntoIter<&'de str>,
}

impl<'de> SeqAccess<'de> for FieldValuesSeq<'de> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.values
            .next()
            .map(|value| {
                seed.deserialize(FieldValues {
                    name: self.name,
                    values: vec![value],
                })
            })
            .transpose()
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.values.len())
    }
}

/// Deserializes a field value as a unit variant name.
struct UnitVariant<'de> {
    value: &'de str,
}

impl<'de> EnumAccess<'de> for UnitVariant<'de> {
    type Error = Error;
    type Variant = UnitOnly;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, UnitOnly), Error> {
        Ok((
            seed.deserialize(BorrowedStrDeserializer::<Error>::new(self.value))?,
            UnitOnly,
        ))
    }
}

/// Rejects data attached to a unit variant.
struct UnitOnly;

impl<'de> VariantAccess<'de> for UnitOnly {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, _seed: T) -> Result<T::Value, Error> {
        Err(Error::Unsupported("an enum variant carrying data"))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::Unsupported("an enum variant carrying data"))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(Error::Unsupported("an enum variant carrying data"))
    }
}

/// Error for a top-level value that is not a struct or map.
const NOT_A_BODY: &str = "only a struct or map serializes as a warc-fields body";

/// Error for a value that cannot fit in one field line.
const NOT_A_VALUE: &str = "a field's value must serialize as text, a number, or a sequence of them";

/// Error for a non-string field name.
const NOT_A_NAME: &str = "a field's name must serialize as a string";

/// Implement unsupported serializer methods with one error.
macro_rules! unsupported {
    ($message:expr => $($method:ident($($ty:ty),*);)*) => {
        $(
            fn $method(self $(, _: $ty)*) -> Result<Self::Ok, Self::Error> {
                Err(Error::Unsupported($message))
            }
        )*
    };
}

/// Serializes a struct or map as a body.
struct BodySerializer<F> {
    field: PhantomData<F>,
}

impl<F: Field> ser::Serializer for BodySerializer<F> {
    type Ok = Body<F>;
    type Error = Error;
    type SerializeSeq = Impossible<Body<F>, Error>;
    type SerializeTuple = Impossible<Body<F>, Error>;
    type SerializeTupleStruct = Impossible<Body<F>, Error>;
    type SerializeTupleVariant = Impossible<Body<F>, Error>;
    type SerializeMap = FieldsWriter<F>;
    type SerializeStruct = FieldsWriter<F>;
    type SerializeStructVariant = Impossible<Body<F>, Error>;

    unsupported! { NOT_A_BODY =>
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_i128(i128);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_u128(u128);
        serialize_f32(f32);
        serialize_f64(f64);
        serialize_char(char);
        serialize_str(&str);
        serialize_bytes(&[u8]);
        serialize_unit();
        serialize_unit_struct(&'static str);
        serialize_unit_variant(&'static str, u32, &'static str);
    }

    /// A top-level `None` produces an empty body.
    fn serialize_none(self) -> Result<Body<F>, Error> {
        Ok(Body::new())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Body<F>, Error> {
        value.serialize(self)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Body<F>, Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Body<F>, Error> {
        Err(Error::Unsupported(NOT_A_BODY))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(Error::Unsupported(NOT_A_BODY))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(Error::Unsupported(NOT_A_BODY))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(Error::Unsupported(NOT_A_BODY))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::Unsupported(NOT_A_BODY))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Ok(FieldsWriter::new())
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Ok(FieldsWriter::new())
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::Unsupported(NOT_A_BODY))
    }
}

/// Builds a body from struct fields or map entries.
struct FieldsWriter<F> {
    body: Body<F>,
    /// The map key awaiting its value.
    key: Option<String>,
}

impl<F> FieldsWriter<F> {
    const fn new() -> Self {
        Self {
            body: Body::new(),
            key: None,
        }
    }
}

impl<F: Field> ser::SerializeStruct for FieldsWriter<F> {
    type Ok = Body<F>;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(FieldValueSerializer {
            body: &mut self.body,
            name: key,
            in_seq: false,
        })
    }

    fn end(self) -> Result<Body<F>, Error> {
        Ok(self.body)
    }
}

impl<F: Field> ser::SerializeMap for FieldsWriter<F> {
    type Ok = Body<F>;
    type Error = Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        self.key = Some(key.serialize(NameSerializer)?);

        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let name = self
            .key
            .take()
            .expect("invariant violation: a map value was written before its key");

        value.serialize(FieldValueSerializer {
            body: &mut self.body,
            name: &name,
            in_seq: false,
        })
    }

    fn end(self) -> Result<Body<F>, Error> {
        Ok(self.body)
    }
}

/// Serialize displayable scalars as text.
macro_rules! push_display {
    ($($method:ident($ty:ty);)*) => {
        $(
            fn $method(self, value: $ty) -> Result<(), Error> {
                self.push(value.to_string())
            }
        )*
    };
}

/// Serializes one named field or map entry.
struct FieldValueSerializer<'a, F> {
    body: &'a mut Body<F>,
    name: &'a str,
    /// Whether this value is inside a sequence, which may not nest.
    in_seq: bool,
}

impl<F: Field> FieldValueSerializer<'_, F> {
    /// Add a field line through [`Body::push`].
    fn push(self, value: impl Into<String>) -> Result<(), Error> {
        Ok(self.body.push(F::from_name(self.name), value)?)
    }
}

impl<'a, F: Field> ser::Serializer for FieldValueSerializer<'a, F> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = RepeatedField<'a, F>;
    type SerializeTuple = RepeatedField<'a, F>;
    type SerializeTupleStruct = RepeatedField<'a, F>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    push_display! {
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_i128(i128);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_u128(u128);
        serialize_f32(f32);
        serialize_f64(f64);
        serialize_char(char);
    }

    fn serialize_str(self, value: &str) -> Result<(), Error> {
        self.push(value)
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), Error> {
        let value = str::from_utf8(value)
            .map_err(|_| Error::Unsupported("bytes that are not UTF-8 text"))?;

        self.push(value)
    }

    /// Omit an absent field.
    fn serialize_none(self) -> Result<(), Error> {
        Ok(())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }

    /// Write a unit variant as its name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.push(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        if self.in_seq {
            return Err(Error::Unsupported("a sequence nested in a sequence"));
        }

        Ok(RepeatedField {
            body: self.body,
            name: self.name,
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::Unsupported(NOT_A_VALUE))
    }
}

/// Writes each sequence element as a separate line under one name.
struct RepeatedField<'a, F> {
    body: &'a mut Body<F>,
    name: &'a str,
}

impl<F: Field> ser::SerializeSeq for RepeatedField<'_, F> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(FieldValueSerializer {
            body: &mut *self.body,
            name: self.name,
            in_seq: true,
        })
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<F: Field> ser::SerializeTuple for RepeatedField<'_, F> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<F: Field> ser::SerializeTupleStruct for RepeatedField<'_, F> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

/// Serializes a string map key as a field name.
struct NameSerializer;

impl ser::Serializer for NameSerializer {
    type Ok = String;
    type Error = Error;
    type SerializeSeq = Impossible<String, Error>;
    type SerializeTuple = Impossible<String, Error>;
    type SerializeTupleStruct = Impossible<String, Error>;
    type SerializeTupleVariant = Impossible<String, Error>;
    type SerializeMap = Impossible<String, Error>;
    type SerializeStruct = Impossible<String, Error>;
    type SerializeStructVariant = Impossible<String, Error>;

    unsupported! { NOT_A_NAME =>
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_i128(i128);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_u128(u128);
        serialize_f32(f32);
        serialize_f64(f64);
        serialize_char(char);
        serialize_bytes(&[u8]);
        serialize_none();
        serialize_unit();
        serialize_unit_struct(&'static str);
        serialize_unit_variant(&'static str, u32, &'static str);
    }

    fn serialize_str(self, value: &str) -> Result<String, Error> {
        Ok(value.to_owned())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::Unsupported(NOT_A_NAME))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use serde::ser::Serialize;

    use super::{Error, from_body, to_body};
    use crate::record::fields::metadata::MetadataBody;
    use crate::record::fields::warcinfo::WarcinfoBody;

    /// A crawler-specific schema with required, optional, repeated, and typed fields.
    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CrawlInfo {
        software: String,
        is_part_of: String,
        #[serde(default)]
        subject: Vec<String>,
        operator: Option<String>,
        ip: Option<IpAddr>,
    }

    /// Required, optional, repeated, and typed fields deserialize as expected, while unknown
    /// fields are ignored.
    #[test]
    fn an_opinionated_struct_reads_from_a_body() -> Result<(), Error> {
        let body = WarcinfoBody::parse(
            b"software: mycrawler/1.0\r\n\
              isPartOf: crawl-2026-08\r\n\
              ip: 203.0.113.7\r\n\
              subject: one\r\n\
              x-unrelated: noise\r\n\
              subject: two\r\n",
        )?;

        let info: CrawlInfo = from_body(&body)?;

        assert_eq!(
            info,
            CrawlInfo {
                software: "mycrawler/1.0".to_string(),
                is_part_of: "crawl-2026-08".to_string(),
                subject: vec!["one".to_string(), "two".to_string()],
                operator: None,
                ip: "203.0.113.7".parse().ok(),
            }
        );

        Ok(())
    }

    /// Omitting a required field reports its name instead of supplying a default.
    #[test]
    fn a_missing_required_field_is_an_error() -> Result<(), Error> {
        let body = WarcinfoBody::parse(b"isPartOf: crawl-2026-08\r\n")?;

        match from_body::<_, CrawlInfo>(&body) {
            Err(Error::Message(message)) => assert!(message.contains("missing field `software`")),
            other => panic!("expected a missing field error, got {other:?}"),
        }

        Ok(())
    }

    /// A repeated field must be read as a sequence; reading it as one value is an error.
    #[test]
    fn a_repeated_field_reads_as_a_sequence_and_not_as_one_value() -> Result<(), Error> {
        #[derive(Debug, serde::Deserialize)]
        struct OneSubject {
            #[expect(dead_code, reason = "read only to force the single-value path")]
            subject: String,
        }

        #[derive(Debug, serde::Deserialize)]
        struct ManySubjects {
            subject: Vec<String>,
        }

        let body = WarcinfoBody::parse(b"subject: one\r\nsubject: two\r\n")?;

        assert_eq!(
            from_body::<_, OneSubject>(&body).map(|_| ()),
            Err(Error::RepeatedField {
                name: "subject".to_string(),
                count: 2,
            })
        );
        assert_eq!(from_body::<_, ManySubjects>(&body)?.subject, ["one", "two"]);

        Ok(())
    }

    /// Typed values are parsed individually, and an invalid value reports its field and expected
    /// type.
    #[test]
    fn typed_values_parse_or_report_the_field() -> Result<(), Error> {
        #[derive(Debug, serde::Deserialize)]
        struct Timings {
            #[serde(rename = "fetchTimeMs")]
            fetch_time_ms: Vec<u64>,
        }

        let body = MetadataBody::parse(b"fetchTimeMs: 565\r\nfetchTimeMs: 32\r\n")?;
        assert_eq!(from_body::<_, Timings>(&body)?.fetch_time_ms, [565, 32]);

        let unreadable = MetadataBody::parse(b"fetchTimeMs: quick\r\n")?;
        assert_eq!(
            from_body::<_, Timings>(&unreadable).map(|_| ()),
            Err(Error::UnreadableValue {
                name: "fetchTimeMs".to_string(),
                expected: "an integer",
            })
        );

        Ok(())
    }

    /// The scalar representations supported by warc-fields read from and write to text.
    #[test]
    fn scalar_kinds_round_trip_through_text() -> Result<(), Error> {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Scalars {
            enabled: bool,
            i8_value: i8,
            i16_value: i16,
            i32_value: i32,
            i64_value: i64,
            i128_value: i128,
            u8_value: u8,
            u16_value: u16,
            u32_value: u32,
            u64_value: u64,
            u128_value: u128,
            f32_value: f32,
            f64_value: f64,
            initial: char,
        }

        let body = MetadataBody::parse(
            b"enabled: true\r\n\
              i8_value: -8\r\n\
              i16_value: -16\r\n\
              i32_value: -32\r\n\
              i64_value: -64\r\n\
              i128_value: -128\r\n\
              u8_value: 8\r\n\
              u16_value: 16\r\n\
              u32_value: 32\r\n\
              u64_value: 64\r\n\
              u128_value: 128\r\n\
              f32_value: 1.5\r\n\
              f64_value: 1.25\r\n\
              initial: W\r\n",
        )?;
        let scalars: Scalars = from_body(&body)?;

        assert_eq!(
            scalars,
            Scalars {
                enabled: true,
                i8_value: -8,
                i16_value: -16,
                i32_value: -32,
                i64_value: -64,
                i128_value: -128,
                u8_value: 8,
                u16_value: 16,
                u32_value: 32,
                u64_value: 64,
                u128_value: 128,
                f32_value: 1.5,
                f64_value: 1.25,
                initial: 'W',
            }
        );

        let rebuilt: MetadataBody = to_body(&scalars)?;
        assert_eq!(rebuilt.to_string(), body.to_string());

        Ok(())
    }

    /// Newtypes and both tuple forms use the same textual and repeated-field representations as
    /// their underlying values.
    #[test]
    fn newtypes_and_fixed_sequences_round_trip() -> Result<(), Error> {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Count(u16);

        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Bounds(i8, i8);

        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Values {
            count: Count,
            bounds: Bounds,
            pair: (u8, u8),
        }

        let body = MetadataBody::parse(
            b"count: 3\r\n\
              bounds: -2\r\n\
              bounds: 7\r\n\
              pair: 4\r\n\
              pair: 9\r\n",
        )?;
        let values: Values = from_body(&body)?;

        assert_eq!(
            values,
            Values {
                count: Count(3),
                bounds: Bounds(-2, 7),
                pair: (4, 9),
            }
        );

        let rebuilt: MetadataBody = to_body(&values)?;
        assert_eq!(rebuilt.to_string(), body.to_string());

        Ok(())
    }

    /// Struct field names match body field names case-insensitively.
    #[test]
    fn names_match_case_insensitively() -> Result<(), Error> {
        #[derive(Debug, serde::Deserialize)]
        struct Custom {
            #[serde(rename = "X-Custom")]
            x_custom: String,
            #[serde(rename = "HOPSFROMSEED")]
            hops_from_seed: String,
        }

        // Exercise a lowercased extension name and a canonicalized standard name.
        let body = MetadataBody::parse(b"X-CUSTOM: one\r\nhopsfromseed: LE\r\n")?;
        let custom: Custom = from_body(&body)?;

        assert_eq!(custom.x_custom, "one");
        assert_eq!(custom.hops_from_seed, "LE");

        Ok(())
    }

    /// `deny_unknown_fields` rejects an unrecognized body field and reports its name.
    #[test]
    fn unknown_fields_can_be_denied() -> Result<(), Error> {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            #[expect(
                dead_code,
                reason = "read only to prove the unknown field is the error"
            )]
            software: String,
        }

        let body = WarcinfoBody::parse(b"software: one\r\nx-custom: two\r\n")?;

        match from_body::<_, Strict>(&body) {
            Err(Error::Message(message)) => assert!(message.contains("x-custom")),
            other => panic!("expected an unknown field error, got {other:?}"),
        }

        Ok(())
    }

    /// A unit enum variant round-trips through its field value.
    #[test]
    fn a_unit_enum_variant_round_trips_through_its_name() -> Result<(), Error> {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        #[serde(rename_all = "lowercase")]
        enum Robots {
            Classic,
            Ignore,
        }

        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Policy {
            robots: Robots,
        }

        let body = WarcinfoBody::parse(b"robots: classic\r\n")?;
        let policy: Policy = from_body(&body)?;
        assert_eq!(policy.robots, Robots::Classic);

        let rebuilt: WarcinfoBody = to_body(&Policy {
            robots: Robots::Ignore,
        })?;
        assert_eq!(rebuilt.to_string(), "robots: ignore\r\n");

        Ok(())
    }

    /// Serialization preserves declaration order, omits `None`, emits one line per sequence
    /// element, and round-trips through deserialization.
    #[test]
    fn a_struct_round_trips_through_a_body() -> Result<(), Error> {
        let info = CrawlInfo {
            software: "mycrawler/1.0".to_string(),
            is_part_of: "crawl-2026-08".to_string(),
            subject: vec!["one".to_string(), "two".to_string()],
            operator: None,
            ip: "203.0.113.7".parse().ok(),
        };

        let body: WarcinfoBody = to_body(&info)?;

        assert_eq!(
            body.to_string(),
            "software: mycrawler/1.0\r\n\
             isPartOf: crawl-2026-08\r\n\
             subject: one\r\n\
             subject: two\r\n\
             ip: 203.0.113.7\r\n"
        );
        assert_eq!(from_body::<_, CrawlInfo>(&body)?, info);

        Ok(())
    }

    /// Values rejected by the field grammar remain errors during serialization.
    #[test]
    fn writing_a_value_the_grammar_refuses_is_an_error() {
        #[derive(Debug, serde::Serialize)]
        struct Injection {
            software: String,
        }

        let result: Result<WarcinfoBody, Error> = to_body(&Injection {
            software: "one\r\ninjected: two".to_string(),
        });

        assert!(matches!(result, Err(Error::Field(_))));
    }

    /// A top-level value must be a struct or map to serialize as a body.
    #[test]
    fn only_a_struct_or_map_writes_as_a_body() {
        let result: Result<WarcinfoBody, Error> = to_body("just some text");

        assert!(matches!(result, Err(Error::Unsupported(_))));
    }

    /// A string map supports fields that are not fixed at compile time.
    #[test]
    fn a_map_reads_and_writes() -> Result<(), Error> {
        let body = WarcinfoBody::parse(b"software: one\r\nhostname: a-host\r\n")?;
        let map: BTreeMap<String, String> = from_body(&body)?;

        assert_eq!(map["software"], "one");
        assert_eq!(map["hostname"], "a-host");

        let rebuilt: WarcinfoBody = to_body(&map)?;
        assert_eq!(rebuilt.to_string(), "hostname: a-host\r\nsoftware: one\r\n");

        Ok(())
    }

    /// Dynamic maps retain repeated values, including a field that appears only once.
    #[test]
    fn a_map_can_hold_repeated_fields() -> Result<(), Error> {
        let body = WarcinfoBody::parse(
            b"subject: one\r\n\
              subject: two\r\n\
              software: crawler/1.0\r\n",
        )?;
        let map: BTreeMap<String, Vec<String>> = from_body(&body)?;

        assert_eq!(map["subject"], ["one", "two"]);
        assert_eq!(map["software"], ["crawler/1.0"]);

        let rebuilt: WarcinfoBody = to_body(&map)?;
        assert_eq!(
            rebuilt.to_string(),
            "software: crawler/1.0\r\nsubject: one\r\nsubject: two\r\n"
        );

        Ok(())
    }

    /// Map keys must provide field names as strings.
    #[test]
    fn a_non_string_map_key_is_rejected() {
        let map = BTreeMap::from([(1_u8, "one")]);
        let result: Result<WarcinfoBody, Error> = to_body(&map);

        assert_eq!(
            result,
            Err(Error::Unsupported(
                "a field's name must serialize as a string"
            ))
        );
    }

    /// Borrowed fields deserialize without copying their values from the body.
    #[test]
    fn a_struct_can_borrow_from_the_body() -> Result<(), Error> {
        #[derive(Debug, serde::Deserialize)]
        struct View<'a> {
            software: &'a str,
        }

        let body = WarcinfoBody::parse(b"software: one\r\n")?;
        let view: View<'_> = body.deserialize()?;

        assert_eq!(view.software, "one");

        Ok(())
    }

    /// Optional and newtype wrappers around a body retain the body's top-level representation.
    #[test]
    fn top_level_wrappers_serialize_as_bodies() -> Result<(), Error> {
        #[derive(serde::Serialize)]
        struct Fields {
            software: &'static str,
        }

        #[derive(serde::Serialize)]
        struct Wrapped(Fields);

        let absent: WarcinfoBody = to_body(&Option::<Fields>::None)?;
        assert!(absent.is_empty());

        let present: WarcinfoBody = to_body(&Some(Fields { software: "one" }))?;
        assert_eq!(present.to_string(), "software: one\r\n");

        let wrapped: WarcinfoBody = to_body(&Wrapped(Fields { software: "two" }))?;
        assert_eq!(wrapped.to_string(), "software: two\r\n");

        Ok(())
    }

    /// Every compound top-level shape other than a struct or map is rejected consistently.
    #[test]
    fn compound_top_level_values_are_rejected() {
        #[derive(serde::Serialize)]
        struct Tuple(u8, u8);

        #[derive(serde::Serialize)]
        enum Choice {
            Newtype(u8),
            Tuple(u8, u8),
            Struct { value: u8 },
        }

        fn rejected<T: Serialize + ?Sized>(value: &T) {
            let result: Result<WarcinfoBody, Error> = to_body(value);
            assert!(matches!(result, Err(Error::Unsupported(_))));
        }

        rejected(&vec![1_u8, 2]);
        rejected(&(1_u8, 2_u8));
        rejected(&Tuple(1, 2));
        rejected(&Choice::Newtype(1));
        rejected(&Choice::Tuple(1, 2));
        rejected(&Choice::Struct { value: 1 });
    }

    /// A field value is flat: units, nested containers, and data-carrying variants do not fit.
    #[test]
    fn nested_non_scalar_values_are_rejected() {
        #[derive(serde::Serialize)]
        struct Unit;

        #[derive(serde::Serialize)]
        struct Inner {
            value: u8,
        }

        #[derive(serde::Serialize)]
        enum Choice {
            Newtype(u8),
            Tuple(u8, u8),
            Struct { value: u8 },
        }

        #[derive(serde::Serialize)]
        struct Field<T> {
            field: T,
        }

        fn rejected<T: Serialize>(field: T) {
            let result: Result<WarcinfoBody, Error> = to_body(&Field { field });
            assert!(matches!(result, Err(Error::Unsupported(_))));
        }

        rejected(());
        rejected(Unit);
        rejected(Choice::Newtype(1));
        rejected(Choice::Tuple(1, 2));
        rejected(Choice::Struct { value: 1 });
        rejected(BTreeMap::from([("nested", "value")]));
        rejected(Inner { value: 1 });
        rejected(vec![vec![1_u8]]);
    }

    /// Byte values use their UTF-8 text representation; arbitrary binary data is not a field.
    #[test]
    fn utf_8_bytes_round_trip_as_text() -> Result<(), Error> {
        #[derive(Debug, Eq, PartialEq)]
        struct Bytes(Vec<u8>);

        impl Serialize for Bytes {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for Bytes {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct BytesVisitor;

                impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                    type Value = Bytes;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("UTF-8 field text")
                    }

                    fn visit_borrowed_bytes<E: serde::de::Error>(
                        self,
                        value: &'de [u8],
                    ) -> Result<Bytes, E> {
                        Ok(Bytes(value.to_vec()))
                    }
                }

                deserializer.deserialize_byte_buf(BytesVisitor)
            }
        }

        #[derive(Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Field {
            value: Bytes,
        }

        let body = WarcinfoBody::parse(b"value: some text\r\n")?;
        let field: Field = from_body(&body)?;
        assert_eq!(field.value, Bytes(b"some text".to_vec()));

        let rebuilt: WarcinfoBody = to_body(&field)?;
        assert_eq!(rebuilt.to_string(), body.to_string());

        let binary = Field {
            value: Bytes(vec![0xff]),
        };
        assert!(matches!(
            to_body::<crate::record::fields::warcinfo::WarcinfoField, _>(&binary),
            Err(Error::Unsupported(_))
        ));

        Ok(())
    }

    /// Dynamic map keys accept strings and string newtypes, and reject every compound shape.
    #[test]
    fn dynamic_map_keys_must_flatten_to_strings() -> Result<(), Error> {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
        struct StringKey(&'static str);

        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
        struct TupleKey(u8, u8);

        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
        struct StructKey {
            value: u8,
        }

        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
        enum ChoiceKey {
            Newtype(u8),
            Tuple(u8, u8),
            Struct { value: u8 },
        }

        fn rejected<K: Ord + Serialize>(key: K) {
            let result: Result<WarcinfoBody, Error> = to_body(&BTreeMap::from([(key, "value")]));
            assert!(matches!(result, Err(Error::Unsupported(_))));
        }

        let body: WarcinfoBody = to_body(&BTreeMap::from([(StringKey("software"), "one")]))?;
        assert_eq!(body.to_string(), "software: one\r\n");

        rejected(Some("name"));
        rejected(vec![1_u8]);
        rejected((1_u8, 2_u8));
        rejected(TupleKey(1, 2));
        rejected(BTreeMap::from([(1_u8, 2_u8)]));
        rejected(StructKey { value: 1 });
        rejected(ChoiceKey::Newtype(1));
        rejected(ChoiceKey::Tuple(1, 2));
        rejected(ChoiceKey::Struct { value: 1 });

        Ok(())
    }

    /// Nested deserialization shapes fail at the field boundary with the documented error.
    #[test]
    fn nested_deserialization_shapes_are_rejected() -> Result<(), Error> {
        #[derive(Debug, serde::Deserialize)]
        struct Unit;

        #[derive(Debug, serde::Deserialize)]
        struct Inner {
            #[expect(dead_code, reason = "only the rejection path is under test")]
            value: String,
        }

        #[derive(Debug, serde::Deserialize)]
        enum Choice {
            Newtype(#[expect(dead_code)] String),
            Tuple(#[expect(dead_code)] String, #[expect(dead_code)] String),
            Struct {
                #[expect(dead_code)]
                value: String,
            },
        }

        #[derive(Debug, serde::Deserialize)]
        struct Field<T> {
            #[expect(dead_code, reason = "only the rejection path is under test")]
            field: T,
        }

        fn rejected<T: for<'de> serde::Deserialize<'de>>(body: &WarcinfoBody) {
            assert!(matches!(
                from_body::<_, Field<T>>(body),
                Err(Error::Unsupported(_))
            ));
        }

        let unit = WarcinfoBody::parse(b"field: value\r\n")?;
        rejected::<()>(&unit);
        rejected::<Unit>(&unit);
        rejected::<BTreeMap<String, String>>(&unit);
        rejected::<Inner>(&unit);

        let newtype = WarcinfoBody::parse(b"field: Newtype\r\n")?;
        rejected::<Choice>(&newtype);
        let tuple = WarcinfoBody::parse(b"field: Tuple\r\n")?;
        rejected::<Choice>(&tuple);
        let structure = WarcinfoBody::parse(b"field: Struct\r\n")?;
        rejected::<Choice>(&structure);

        Ok(())
    }
}
