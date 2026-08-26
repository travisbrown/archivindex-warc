//! Writing a record's semantic representation back into header fields.

use std::borrow::Cow;
use std::net::IpAddr;

use fluent_uri::Uri;

use super::{RenderError, date_fits_version, repeated_field};
use crate::parse::untyped::name::{Field, HeaderName};
use crate::parse::untyped::value::{HeaderValue, ValueForm};
use crate::parsing::is_token;
use crate::record::extension::ExtensionFields;
use crate::record::header::{PayloadHeaders, RevisitProfile};
use crate::value::{LabelledDigest, MediaType, Text, WarcDate};
use crate::version::WarcVersion;

/// Fields being rendered under a declared WARC version.
pub(super) struct Renderer {
    version: WarcVersion,
    /// Whether the record's type is one no version of the standard defines.
    ///
    /// Such a record is under no constraint about which fields it carries, so it keeps standard
    /// names as read rather than being held to what the standard says about them.
    unconstrained: bool,
    pub(super) headers: Vec<(HeaderName, HeaderValue)>,
}

/// Push required or optional fields represented by one [`ValueForm`] variant.
macro_rules! push_form {
    ($push:ident, $push_optional:ident, $variant:ident, $value:ty) => {
        pub(super) fn $push(&mut self, field: Field, value: $value) -> Result<(), RenderError> {
            self.push(field, ValueForm::$variant(value))
        }

        pub(super) fn $push_optional(
            &mut self,
            field: Field,
            value: Option<$value>,
        ) -> Result<(), RenderError> {
            value.map_or(Ok(()), |value| self.$push(field, value))
        }
    };
}

impl Renderer {
    push_form!(push_digest, push_optional_digest, Digest, LabelledDigest);
    push_form!(
        push_media_type,
        push_optional_media_type,
        MediaType,
        MediaType
    );
    push_form!(push_text, push_optional_text, Text, Text);
    push_form!(push_digits, push_optional_digits, Digits, u64);

    /// An empty block declaring `version`.
    pub(super) const fn new(version: WarcVersion, unconstrained: bool) -> Self {
        Self {
            version,
            unconstrained,
            headers: Vec::new(),
        }
    }

    /// Reject a field the declared version does not define.
    const fn check_version(&self, field: Field) -> Result<(), RenderError> {
        if field.defined_in(self.version) {
            Ok(())
        } else {
            Err(RenderError::FieldNotInVersion {
                field,
                version: self.version,
            })
        }
    }

    /// Append a field holding the given form.
    fn push(&mut self, field: Field, form: ValueForm) -> Result<(), RenderError> {
        self.check_version(field)?;
        self.headers
            .push((HeaderName::new(field), HeaderValue::from(form)));

        Ok(())
    }

    /// Whether the declared version writes `field` inside URI angle brackets.
    ///
    /// WARC 1.0 brackets every URI-valued field. WARC 1.1 brackets only the five whose value is a
    /// record identifier, and writes the rest bare.
    const fn brackets(&self, field: Field) -> bool {
        matches!(self.version, WarcVersion::V1_0)
            || matches!(
                field,
                Field::ConcurrentTo
                    | Field::RecordID
                    | Field::RefersTo
                    | Field::SegmentOriginID
                    | Field::WarcinfoID
            )
    }

    /// Append a URI-valued field, bracketed or bare as the declared version requires.
    pub(super) fn push_uri(&mut self, field: Field, uri: Uri<String>) -> Result<(), RenderError> {
        let bracketed = self.brackets(field);
        self.push(field, ValueForm::Uri { uri, bracketed })
    }

    /// Append a URI-valued field when the record carries one.
    pub(super) fn push_optional_uri(
        &mut self,
        field: Field,
        uri: Option<Uri<String>>,
    ) -> Result<(), RenderError> {
        uri.map_or(Ok(()), |uri| self.push_uri(field, uri))
    }

    /// Append a date, refusing one the declared version has no spelling for.
    pub(super) fn push_date(&mut self, field: Field, date: WarcDate) -> Result<(), RenderError> {
        if !date_fits_version(date, self.version) {
            return Err(RenderError::ValueNotInVersion {
                field,
                version: self.version,
                value: date.to_string(),
            });
        }

        self.push(field, ValueForm::Date(date))
    }

    /// Append a token-valued field, rejecting a token an extension spelled in a way the
    /// grammar does not admit.
    pub(super) fn push_token(&mut self, field: Field, token: &str) -> Result<(), RenderError> {
        if !is_token(token.as_bytes()) {
            return Err(RenderError::UnwritableField {
                name: field.name().to_owned(),
                reason: format!("`{token}` is not a token"),
            });
        }

        self.push(field, ValueForm::Token(token.into()))
    }

    /// Append `WARC-Profile`, validating custom profile URIs.
    pub(super) fn push_profile(&mut self, profile: &RevisitProfile) -> Result<(), RenderError> {
        let uri = Uri::parse(profile.as_str())
            .map_err(|error| RenderError::UnwritableField {
                name: Field::Profile.name().to_owned(),
                reason: error.to_string(),
            })?
            .to_owned();

        self.push_uri(Field::Profile, uri)
    }

    /// Append the fields describing the record's payload.
    pub(super) fn push_payload(&mut self, payload: PayloadHeaders) -> Result<(), RenderError> {
        self.push_optional_digest(Field::PayloadDigest, payload.payload_digest)?;
        self.push_optional_media_type(
            Field::IdentifiedPayloadType,
            payload.identified_payload_type,
        )
    }

    /// Append `WARC-IP-Address` when the record carries one.
    pub(super) fn push_ip_address(
        &mut self,
        ip_address: Option<IpAddr>,
    ) -> Result<(), RenderError> {
        ip_address.map_or(Ok(()), |address| {
            self.push(Field::IPAddress, ValueForm::IpAddress(address))
        })
    }

    /// Append one `WARC-Concurrent-To` line per referenced record.
    pub(super) fn push_concurrent_to(
        &mut self,
        concurrent_to: Vec<Uri<String>>,
    ) -> Result<(), RenderError> {
        for record_id in concurrent_to {
            self.push_uri(Field::ConcurrentTo, record_id)?;
        }

        Ok(())
    }

    /// Append `WARC-Segment-Number` with the value `1`, the only value the standard permits on
    /// a record that is not a `continuation`, when the record is the origin of a series.
    pub(super) fn push_segment_origin(&mut self, segment_origin: bool) -> Result<(), RenderError> {
        if segment_origin {
            self.push_digits(Field::SegmentNumber, 1)?;
        }

        Ok(())
    }

    /// Append a field after validating that its name and value can be read back.
    ///
    /// A record of a type the standard defines writes every standard field from the value its own
    /// header holds, so a name the standard defines is refused here rather than written beside
    /// the field it names.
    pub(super) fn push_as_read(&mut self, name: &str, value: &str) -> Result<(), RenderError> {
        if !is_token(name.as_bytes()) {
            return Err(RenderError::UnwritableField {
                name: name.to_owned(),
                reason: "the name is not a token".to_owned(),
            });
        }
        // A value is held here with its folds already resolved, so a line break in one is a
        // header line the caller wrote into it rather than a fold, and would be read back as a
        // field of its own.
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(RenderError::UnwritableField {
                name: name.to_owned(),
                reason: "the value holds a line break".to_owned(),
            });
        }

        let name = HeaderName::as_read(name);
        if let Some(field) = name.field() {
            if !self.unconstrained {
                return Err(RenderError::ReservedField(field));
            }
            self.check_version(field)?;
        }
        // A value is written after the colon exactly as it is given, so one that does not open
        // with the linear white space the convention puts there is given a single space.
        let spelled = match value.as_bytes().first() {
            Some(b' ' | b'\t') => Cow::Borrowed(value),
            _ => Cow::Owned(format!(" {value}")),
        };
        let value = HeaderValue::parse(name.field(), spelled.as_bytes()).map_err(|error| {
            RenderError::UnwritableField {
                name: name.name().to_owned(),
                reason: error.to_string(),
            }
        })?;

        self.headers.push((name, value));
        Ok(())
    }

    /// Reject a nonrepeatable standard field written more than once.
    ///
    /// A block is checked once it is complete: the fields every record carries are written after
    /// the fields of its own type, so one written by the extension or kept as read can only be
    /// seen to repeat one of them at the end.
    pub(super) fn check_repetition(&self) -> Result<(), RenderError> {
        repeated_field(self.headers.iter().map(|(name, _)| name))
            .map_or(Ok(()), |field| Err(RenderError::RepeatedField(field)))
    }

    /// Append and validate the extension's fields.
    pub(super) fn push_extension<F: ExtensionFields>(
        &mut self,
        other: &F,
    ) -> Result<(), RenderError> {
        let mut fields = Vec::new();
        other.append_to(&mut fields);
        for (name, value) in fields {
            self.push_as_read(&name, &value)?;
        }

        Ok(())
    }

    /// Put standard fields in conventional order, followed by extension fields.
    pub(super) fn canonical_order(&mut self) {
        self.headers
            .sort_by_key(|(name, _)| name.field().map_or(usize::MAX, Field::canonical_rank));
    }
}
