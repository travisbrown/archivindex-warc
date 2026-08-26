//! Reading the header fields of a record into its semantic representation.

use std::net::IpAddr;

use fluent_uri::Uri;

use super::{Error, date_fits_version, repeated_field};
use crate::parse::untyped::name::{Field, HeaderName};
use crate::parse::untyped::value::{HeaderValue, ValueForm};
use crate::parsing::unfold;
use crate::record::extension::{ExtensionFields, Unclaimed};
use crate::record::header::{PayloadHeaders, SegmentNumber};
use crate::value::{LabelledDigest, MediaType, Text, WarcDate};
use crate::version::WarcVersion;

/// The unclaimed fields of a record being lifted.
pub(super) struct Lifter {
    pub(super) version: WarcVersion,
    pub(super) fields: Vec<(HeaderName, HeaderValue)>,
}

/// Take a field whose grammar maps to one [`ValueForm`] variant.
macro_rules! take_form {
    ($name:ident, $variant:ident, $value:ty, $rule:literal) => {
        #[doc = concat!("Remove `field`, whose value is ", $rule, ".")]
        pub(super) fn $name(&mut self, field: Field) -> Option<$value> {
            match self.take_form(field)? {
                ValueForm::$variant(value) => Some(value),
                form => unreachable!("invariant violation: {field} was read as {form:?}"),
            }
        }
    };
}

impl Lifter {
    take_form!(take_digest, Digest, LabelledDigest, "a labelled digest");
    take_form!(take_media_type, MediaType, MediaType, "a media type");
    take_form!(take_text, Text, Text, "text");
    take_form!(take_token, Token, Box<str>, "a token");
    take_form!(take_digits, Digits, u64, "a count");

    /// Reject a nonrepeatable standard field written more than once.
    pub(super) fn check_repetition(&self) -> Result<(), Error> {
        repeated_field(self.fields.iter().map(|(name, _)| name))
            .map_or(Ok(()), |field| Err(Error::RepeatedField(field)))
    }

    /// Reject a standard field the declared version does not define.
    ///
    /// The grammar admits the union of the two versions' fields, so this is where a record is
    /// held to the version it declares. Rendering checks the same rule, since a record can also
    /// be assembled or edited after it is read.
    pub(super) fn check_version(&self) -> Result<(), Error> {
        if let Some(field) = self
            .fields
            .iter()
            .filter_map(|(name, _)| name.field())
            .find(|field| !field.defined_in(self.version))
        {
            return Err(Error::FieldNotInVersion {
                field,
                version: self.version,
            });
        }

        Ok(())
    }

    /// Remove and return the first value for `field`.
    fn take_form(&mut self, field: Field) -> Option<ValueForm> {
        let position = self
            .fields
            .iter()
            .position(|(name, _)| name.field() == Some(field))?;

        Some(
            self.fields
                .remove(position)
                .1
                .into_form()
                .expect("invariant violation: a defined field was read without its form"),
        )
    }

    /// Remove `field`, whose value is a URI.
    pub(super) fn take_uri(&mut self, field: Field) -> Option<Uri<String>> {
        match self.take_form(field)? {
            // Whether the URI was written in the angle brackets of the `"<" uri ">"` rule is
            // the grammar's record of how it arrived. It is written back as the declared
            // version requires rather than as it was read, so it is dropped here.
            ValueForm::Uri { uri, .. } => Some(uri),
            form => unreachable!("invariant violation: {field} was read as {form:?}"),
        }
    }

    /// Remove `field`, whose presence the record's type makes mandatory, as a URI.
    pub(super) fn take_required_uri(&mut self, field: Field) -> Result<Uri<String>, Error> {
        self.take_uri(field).ok_or(Error::MissingField(field))
    }

    /// Remove `field`, whose presence the record's type makes mandatory, as a token.
    pub(super) fn take_required_token(&mut self, field: Field) -> Result<Box<str>, Error> {
        self.take_token(field).ok_or(Error::MissingField(field))
    }

    /// Remove `WARC-IP-Address`.
    pub(super) fn take_ip_address(&mut self) -> Option<IpAddr> {
        match self.take_form(Field::IPAddress)? {
            ValueForm::IpAddress(address) => Some(address),
            form => unreachable!("invariant violation: WARC-IP-Address was read as {form:?}"),
        }
    }

    /// Remove `field` and validate its date against the declared WARC version.
    pub(super) fn take_date(&mut self, field: Field) -> Result<Option<WarcDate>, Error> {
        let Some(form) = self.take_form(field) else {
            return Ok(None);
        };
        let ValueForm::Date(date) = form else {
            unreachable!("invariant violation: {field} was read as {form:?}")
        };

        if !date_fits_version(date, self.version) {
            return Err(Error::MalformedField {
                field,
                value: date.to_string(),
            });
        }

        Ok(Some(date))
    }

    /// Remove every `WARC-Concurrent-To` line, in order.
    pub(super) fn take_concurrent_to(&mut self) -> Vec<Uri<String>> {
        let mut concurrent_to = Vec::new();
        while let Some(uri) = self.take_uri(Field::ConcurrentTo) {
            concurrent_to.push(uri);
        }

        concurrent_to
    }

    /// Remove the fields describing the record's payload.
    pub(super) fn take_payload(&mut self) -> PayloadHeaders {
        PayloadHeaders {
            payload_digest: self.take_digest(Field::PayloadDigest),
            identified_payload_type: self.take_media_type(Field::IdentifiedPayloadType),
        }
    }

    /// Remove and validate `WARC-Segment-Number` from an origin record.
    pub(super) fn take_segment_origin(&mut self) -> Result<bool, Error> {
        match self.take_digits(Field::SegmentNumber) {
            None => Ok(false),
            Some(1) => Ok(true),
            Some(number) => Err(Error::MalformedField {
                field: Field::SegmentNumber,
                value: number.to_string(),
            }),
        }
    }

    /// Remove and validate the required segment number of a continuation.
    pub(super) fn take_segment_number(&mut self) -> Result<SegmentNumber, Error> {
        let number = self
            .take_digits(Field::SegmentNumber)
            .ok_or(Error::MissingField(Field::SegmentNumber))?;

        SegmentNumber::new(number).ok_or_else(|| Error::MalformedField {
            field: Field::SegmentNumber,
            value: number.to_string(),
        })
    }

    /// Reject remaining standard fields, then offer the rest to the extension.
    pub(super) fn finish<F: ExtensionFields>(
        self,
        record_type: &'static str,
    ) -> Result<(F, Vec<(String, String)>), Error> {
        if let Some(field) = self.fields.iter().find_map(|(name, _)| name.field()) {
            return Err(Error::ForbiddenField { record_type, field });
        }

        let mut unclaimed = self.finish_unconstrained()?;
        let other = F::from_unclaimed(&mut Unclaimed::new(&mut unclaimed))?;
        Ok((other, unclaimed))
    }

    /// Keep every remaining field for an extension record type.
    ///
    /// Values are kept as text, with folds resolved and surrounding white space removed.
    pub(super) fn finish_unconstrained(self) -> Result<Vec<(String, String)>, Error> {
        self.fields
            .into_iter()
            .map(|(name, value)| {
                let content = unfold(value.as_bytes()).into_owned();
                let content = String::from_utf8(content)
                    .map_err(|_| Error::NonUtf8Field(name.name().to_owned()))?;

                Ok((name.into_name(), content))
            })
            .collect()
    }
}
