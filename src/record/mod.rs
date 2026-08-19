//! A semantic representation of WARC records.
//!
//! [`Record`] pairs each record type with its corresponding [`header`] and content block.
//! [`TryFrom`] converts an [`untyped::Record`] by checking its fields against the declared version
//! and record type. [`Record::into_raw`] converts it back to a [`raw::Record`]. [`RecordHeader`]
//! provides the same validation without reading a content block.
//!
//! This representation is strict, and some real archives do not conform. The `warcinfo` records
//! wpull writes, for example, carry `WARC-Warcinfo-ID`, which clause 5.16 of the WARC 1.1 standard
//! permits on every record type but that one, and are refused here. So is a record declaring
//! WARC 1.0 that carries one of the two fields WARC 1.1 added. Read uncertain input as
//! [`raw::Record`] first, then convert records when semantic validation is needed.
//!
//! Semantic records preserve values, but normalize header order, field spelling, white space, and
//! URI brackets when rendered. A declared `Content-Length` is checked whenever a header and body
//! are paired, and again when the record is rendered.
//!
//! Declared digests are preserved when a record is read. Use
//! [`Record::incorrect_block_digest`] and [`Record::incorrect_payload_digest`] to inspect them.
//! Rendering validates declared digests and adds missing digests when possible.
//!
//! Payload digests follow WARC 1.1 clause 5.10. For `application/http`, this means the HTTP
//! entity-body after transfer-coding has been removed. Some widely used tools digest the message
//! body instead, so their chunked records read but cannot be rendered.
//!
//! Use [`builder`] to create new records.

pub mod builder;
mod digest;
pub mod extension;
pub mod fields;
pub mod header;
pub mod payload;
pub mod record_type;

use std::borrow::Cow;
use std::net::IpAddr;

use fluent_uri::Uri;
use fluent_uri::component::Scheme;

use crate::parse::untyped::name::{Field, HeaderName};
use crate::parse::untyped::value::{HeaderValue, ValueForm};
use crate::parse::{raw, untyped};
use crate::parsing::{is_token, unfold};
use crate::record::digest::{check_block_digest, check_payload_digest, verify_block_digest};
use crate::record::extension::{
    Extension, ExtensionFields, ExtensionRecordType, NoExtension, Unclaimed,
};
use crate::record::fields::metadata::MetadataField;
use crate::record::fields::warcinfo::WarcinfoField;
use crate::record::header::truncated_type::TruncatedType;
use crate::record::header::{
    ContinuationHeader, ConversionHeader, CoreHeaders, MetadataHeader, OtherHeader, PayloadHeaders,
    RequestHeader, ResourceHeader, ResponseHeader, RevisitHeader, RevisitProfile, SegmentNumber,
    WarcinfoHeader,
};
use crate::record::record_type::RecordType;
use crate::value::{LabelledDigest, MediaType, Text, WarcDate, WarcDatePrecision};
use crate::version::WarcVersion;

/// The ways a header block and its content block can fail to go together.
///
/// [`Error::Block`] wraps these failures while reading, and [`RenderError::Block`] wraps them while
/// rendering. Digest errors are reported during rendering or by the digest inspection methods on
/// [`Record`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockError {
    /// The record declares a `Content-Length` that is not the length of the block it carries.
    #[error("`Content-Length` declares {declared} octets, but the block is {actual}.")]
    ContentLengthMismatch {
        /// The length the record declares.
        declared: u64,
        /// The length of the block it carries.
        actual: u64,
    },
    /// The block digest is invalid for its declared algorithm, which this crate computes.
    #[error("The block digest `{0}` is not a digest the algorithm it names can have produced.")]
    MalformedBlockDigest(Box<LabelledDigest>),
    /// The record's block digest does not match the block it carries.
    #[error(
        "The record declares the block digest `{declared}`, but its block digests as `{actual}`."
    )]
    BlockDigestMismatch {
        /// The digest the record declares.
        declared: Box<LabelledDigest>,
        /// The digest of the block it carries.
        actual: Box<LabelledDigest>,
    },
    /// The payload digest is invalid for its declared algorithm, which this crate computes.
    #[error("The payload digest `{0}` is not a digest the algorithm it names can have produced.")]
    MalformedPayloadDigest(Box<LabelledDigest>),
    /// The record's payload digest does not match the payload its block carries.
    #[error(
        "The record declares the payload digest `{declared}`, but its payload digests as \
         `{actual}`."
    )]
    PayloadDigestMismatch {
        /// The digest the record declares.
        declared: Box<LabelledDigest>,
        /// The digest of the payload it carries.
        actual: Box<LabelledDigest>,
    },
    /// The declared payload digest cannot be checked because the HTTP message is malformed.
    #[error("The record's payload cannot be read from its block: {0}")]
    Payload(#[from] payload::Error),
    /// A `revisit` record under the identical payload digest profile carries a block without
    /// declaring the truncation such a block is.
    #[error(
        "A `revisit` record under the identical payload digest profile carries a block of {0} \
         octets without declaring `WARC-Truncated: length`."
    )]
    UndeclaredRevisitTruncation(u64),
    /// The block could not be read as the `application/warc-fields` its record's `Content-Type`
    /// declares.
    #[error("The record's body is not what its `Content-Type` declares: {0}")]
    Fields(#[from] fields::Error),
}

/// The ways a grammatical record can break the standard's rules for its type and its declared
/// version.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A field the standard makes mandatory for the record's type is missing.
    #[error("The mandatory `{0}` field is missing.")]
    MissingField(Field),
    /// A field the standard names is present on a record type it is not permitted for.
    #[error("The `{field}` field is not permitted on a `{record_type}` record.")]
    ForbiddenField {
        /// The standard record type carrying the field.
        record_type: &'static str,
        /// The field the standard does not permit that type.
        field: Field,
    },
    /// A field the standard names is present on a record declaring a version that does not
    /// define it.
    #[error("The `{field}` field is not defined in WARC {version}.")]
    FieldNotInVersion {
        /// The field the declared version does not define.
        field: Field,
        /// The version the record declares.
        version: WarcVersion,
    },
    /// A nonrepeatable standard field is written more than once.
    ///
    /// `WARC-Concurrent-To` is the only repeatable standard field.
    #[error("The `{0}` field is written more than once.")]
    RepeatedField(Field),
    /// A field's value is well-formed under its field's grammar but says something the standard
    /// does not permit, such as a `continuation` numbered below `2` or a WARC 1.0 date written
    /// at a precision only WARC 1.1 defines.
    #[error("The value of the `{field}` field is not permitted: `{value}`.")]
    MalformedField {
        /// The field whose value the standard does not permit.
        field: Field,
        /// The value as it was read.
        value: String,
    },
    /// A value given to a builder for a URI-valued field is not a URI.
    #[error("The value given for the `{field}` field is not a URI: {source}")]
    NotAUri {
        /// The field the value was given for.
        field: Field,
        /// The RFC 3986 violation.
        source: fluent_uri::ParseError,
    },
    /// An unrecognized field has a value that cannot be preserved as UTF-8 text.
    #[error("The value of the `{0}` field is not valid UTF-8.")]
    NonUtf8Field(String),
    /// `WARC-Type` names a type defined by neither the standard nor the extension.
    #[error("The `{0}` record type is defined by no vocabulary in force.")]
    UnknownRecordType(String),
    /// The extension attempts to redefine a standard record type.
    #[error("The `{0}` record type is defined by the standard and cannot be redefined.")]
    RedefinedRecordType(String),
    /// The extension could not parse the fields it claims.
    #[error("The extension in force could not read the record: {0}")]
    Extension(String),
    /// The header block does not go with the block it was given.
    #[error(transparent)]
    Block(#[from] BlockError),
}

/// The ways a semantic record can fail to render as a raw record.
///
/// These checks apply both to records assembled by hand and to records read from an archive and
/// then edited.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RenderError {
    /// The record's declared version does not define a field it contains.
    #[error("The `{field}` field is not defined in WARC {version}.")]
    FieldNotInVersion {
        /// The field the declared version does not define.
        field: Field,
        /// The version the record declares.
        version: WarcVersion,
    },
    /// The record's declared version has no spelling for a value the record carries.
    #[error("The `{field}` value `{value}` cannot be written in WARC {version}.")]
    ValueNotInVersion {
        /// The field carrying the value.
        field: Field,
        /// The version the record declares.
        version: WarcVersion,
        /// The value, spelled as WARC 1.1 writes it.
        value: String,
    },
    /// A field carries a name or a value that cannot be written as a valid header line.
    #[error("The `{name}` field cannot be written: {reason}.")]
    UnwritableField {
        /// The field's name, as it was given.
        name: String,
        /// What about the field cannot be written.
        reason: String,
    },
    /// A standard field would be written more than once.
    ///
    /// A record of a type no version of the standard defines keeps every field as read, so it is
    /// where a name the standard defines can be written twice.
    #[error("The `{0}` field would be written more than once.")]
    RepeatedField(Field),
    /// A field the record's revisit profile requires is not present.
    #[error("The `{0}` field is required by the record's revisit profile.")]
    MissingProfileField(Field),
    /// An extension or unrecognized field names a field the standard defines.
    ///
    /// A record of a standard type writes each standard field from the value its own header
    /// holds, so a field of that name carried beside it would be read back as the standard field
    /// rather than as what it was.
    #[error("The `{0}` field is defined by the standard and cannot be written as read.")]
    ReservedField(Field),
    /// The record does not go with the block it carries.
    #[error(transparent)]
    Block(#[from] BlockError),
}

/// The first nonrepeatable standard field written more than once, if a block has one.
///
/// `WARC-Concurrent-To` is the one standard field a record may repeat. A name no version of the
/// standard defines is the extension's business rather than this crate's, so it is not compared.
fn repeated_field<'a>(names: impl Iterator<Item = &'a HeaderName>) -> Option<Field> {
    // A block holds at most one line per field before it repeats one, so this scan compares at
    // most the twenty-one the standard defines.
    let mut seen = Vec::new();
    for field in names.filter_map(HeaderName::field) {
        if field == Field::ConcurrentTo {
            continue;
        }
        if seen.contains(&field) {
            return Some(field);
        }
        seen.push(field);
    }

    None
}

/// Whether a WARC version has a spelling for a date at the precision it carries.
///
/// WARC 1.0 spells a date one way, so a value at any other precision says more than that version
/// can write. WARC 1.1 spells every precision.
const fn date_fits_version(date: WarcDate, version: WarcVersion) -> bool {
    !matches!(version, WarcVersion::V1_0) || matches!(date.precision(), WarcDatePrecision::Second)
}

/// Check the length a record declares against the length of the block it carries.
///
/// A record with no declared length always passes.
const fn check_declared_length(declared: Option<u64>, actual: u64) -> Result<(), BlockError> {
    match declared {
        Some(declared) if declared != actual => {
            Err(BlockError::ContentLengthMismatch { declared, actual })
        }
        _ => Ok(()),
    }
}

/// Check what the block of a `revisit` record says against the profile the record names.
///
/// Clause 6.7.2 of the WARC 1.1 standard has a record under the identical payload digest profile
/// carry either no block or the beginning of the response it stands for, which is a truncation
/// the record declares as `WARC-Truncated: length`. No rule here applies to another profile.
const fn check_revisit_block<E: Extension>(
    header: &RevisitHeader<E>,
    content_length: u64,
) -> Result<(), BlockError> {
    if content_length > 0
        && matches!(header.profile, RevisitProfile::IdenticalPayloadDigest(_))
        && !matches!(header.core.truncated, Some(TruncatedType::Length))
    {
        return Err(BlockError::UndeclaredRevisitTruncation(content_length));
    }

    Ok(())
}

/// The body of a record type the standard recommends be written as `application/warc-fields`.
///
/// A block declared as `application/warc-fields` is parsed into fields. Other blocks remain raw.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldsBlock<F> {
    /// A block declared and read as `application/warc-fields`.
    Fields(fields::Body<F>),
    /// A block of any other declared type, kept as read.
    Raw(Vec<u8>),
}

impl<F: fields::Field> FieldsBlock<F> {
    /// Consume the block and return its rendered bytes.
    ///
    /// Unmodified parsed fields reproduce their source bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Fields(body) => body.to_string().into_bytes(),
            Self::Raw(bytes) => bytes,
        }
    }

    /// Return the block bytes, borrowing raw blocks and rendering parsed fields.
    ///
    /// Use [`into_bytes`](Self::into_bytes) to take ownership.
    #[must_use]
    pub fn as_bytes(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Fields(body) => Cow::Owned(body.to_string().into_bytes()),
            Self::Raw(bytes) => Cow::Borrowed(bytes),
        }
    }

    /// The number of octets the block renders as.
    fn rendered_len(&self) -> usize {
        match self {
            Self::Fields(body) => body.rendered_len(),
            Self::Raw(bytes) => bytes.len(),
        }
    }

    /// Read a record's block as its fields when its `Content-Type` declares them, and keep it
    /// as the bytes it arrived as otherwise.
    fn read(content_type: Option<&MediaType>, body: Vec<u8>) -> Result<Self, BlockError> {
        if content_type.is_some_and(|media_type| media_type.is("application", "warc-fields")) {
            Ok(Self::Fields(fields::Body::parse(&body)?))
        } else {
            Ok(Self::Raw(body))
        }
    }
}

/// A WARC record in its semantic representation.
///
/// The type parameter selects an extension vocabulary and defaults to [`NoExtension`]. Extensions
/// can add record types, truncation reasons, and fields on standard record types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record<E: Extension = NoExtension> {
    /// A `warcinfo` record: a description of the web crawl that produced the records
    /// following it.
    Warcinfo {
        /// The record's header block.
        header: WarcinfoHeader<E>,
        /// The record's block, recommended to be `application/warc-fields`.
        body: FieldsBlock<WarcinfoField>,
    },
    /// A `response` record: a complete scheme-specific response to a request.
    Response {
        /// The record's header block.
        header: ResponseHeader<E>,
        /// The record's block, the captured response as its scheme defines it.
        body: Vec<u8>,
    },
    /// A `resource` record: a resource captured without full protocol information.
    Resource {
        /// The record's header block.
        header: ResourceHeader<E>,
        /// The record's block, the captured resource itself.
        body: Vec<u8>,
    },
    /// A `request` record: a complete scheme-specific request.
    Request {
        /// The record's header block.
        header: RequestHeader<E>,
        /// The record's block, the captured request as its scheme defines it.
        body: Vec<u8>,
    },
    /// A `metadata` record: content created to further describe another record.
    Metadata {
        /// The record's header block.
        header: MetadataHeader<E>,
        /// The record's block, recommended to be `application/warc-fields`.
        body: FieldsBlock<MetadataField>,
    },
    /// A `revisit` record: a revisitation of content already archived.
    Revisit {
        /// The record's header block.
        header: RevisitHeader<E>,
        /// The record's block, whose shape the revisit profile governs.
        body: Vec<u8>,
    },
    /// A `conversion` record: an alternative version of another record's content.
    Conversion {
        /// The record's header block.
        header: ConversionHeader<E>,
        /// The record's block, the converted content.
        body: Vec<u8>,
    },
    /// A `continuation` record: the continuation of a block segmented across records.
    Continuation {
        /// The record's header block.
        header: ContinuationHeader<E>,
        /// The record's block, the next segment of the origin record's block.
        body: Vec<u8>,
    },
    /// A record of a type defined by the extension in force rather than the standard. Its fields
    /// remain untyped in [`CoreHeaders::unrecognized`].
    Other {
        /// The record's header block.
        header: OtherHeader<E>,
        /// The record's block, whose shape the extension governs.
        body: Vec<u8>,
    },
}

/// A WARC record header in its semantic representation.
///
/// This validates an [`untyped::RecordHeader`] without reading its body. Use
/// [`with_body`](Self::with_body) to attach a content block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordHeader<E: Extension = NoExtension> {
    /// The header of a `warcinfo` record.
    Warcinfo(WarcinfoHeader<E>),
    /// The header of a `response` record.
    Response(ResponseHeader<E>),
    /// The header of a `resource` record.
    Resource(ResourceHeader<E>),
    /// The header of a `request` record.
    Request(RequestHeader<E>),
    /// The header of a `metadata` record.
    Metadata(MetadataHeader<E>),
    /// The header of a `revisit` record.
    Revisit(RevisitHeader<E>),
    /// The header of a `conversion` record.
    Conversion(ConversionHeader<E>),
    /// The header of a `continuation` record.
    Continuation(ContinuationHeader<E>),
    /// The header of a record of a type the extension in force defines.
    Other(OtherHeader<E>),
}

/// Generate accessors shared by [`Record`] and [`RecordHeader`].
///
/// The binding name comes before the accessor list because the bodies are written at the call site,
/// where a name bound inside the macro would not be visible.
macro_rules! header_accessors {
    // A `const` accessor taking `&self`.
    (@methods $field:tt, $binding:ident,
        $(#[$meta:meta])*
        pub const fn $name:ident(&self) -> $return_type:ty {
            $( $( $variant:ident )|+ => $answer:expr ),+ $(,)?
        }
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        #[must_use]
        #[allow(unused_variables)]
        pub const fn $name(&self) -> $return_type {
            match self {
                $($( Self::$variant { $field: $binding, .. } => $answer, )+)+
            }
        }

        header_accessors!(@methods $field, $binding, $($rest)*);
    };

    // A `const` accessor taking `&mut self`, handing out a reference to be written through.
    (@methods $field:tt, $binding:ident,
        $(#[$meta:meta])*
        pub const fn $name:ident(&mut self) -> $return_type:ty {
            $( $( $variant:ident )|+ => $answer:expr ),+ $(,)?
        }
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        #[allow(unused_variables)]
        pub const fn $name(&mut self) -> $return_type {
            match self {
                $($( Self::$variant { $field: $binding, .. } => $answer, )+)+
            }
        }

        header_accessors!(@methods $field, $binding, $($rest)*);
    };

    // An accessor whose body cannot be `const`.
    (@methods $field:tt, $binding:ident,
        $(#[$meta:meta])*
        pub fn $name:ident(&self) -> $return_type:ty {
            $( $( $variant:ident )|+ => $answer:expr ),+ $(,)?
        }
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        #[must_use]
        #[allow(unused_variables)]
        pub fn $name(&self) -> $return_type {
            match self {
                $($( Self::$variant { $field: $binding, .. } => $answer, )+)+
            }
        }

        header_accessors!(@methods $field, $binding, $($rest)*);
    };

    (@methods $field:tt, $binding:ident,) => {};

    // The whole list, given to each of the two types in turn. This rule is written last so the
    // recursive calls above, which it would otherwise also match, reach their own rules first.
    ($binding:ident; $($accessors:tt)*) => {
        impl<E: Extension> Record<E> {
            header_accessors!(@methods header, $binding, $($accessors)*);
        }

        impl<E: Extension> RecordHeader<E> {
            header_accessors!(@methods 0, $binding, $($accessors)*);
        }
    };
}

header_accessors! {
    header;

    /// The value the record's `WARC-Type` field carries.
    pub fn type_name(&self) -> &str {
        Warcinfo => "warcinfo",
        Response => "response",
        Resource => "resource",
        Request => "request",
        Metadata => "metadata",
        Revisit => "revisit",
        Conversion => "conversion",
        Continuation => "continuation",
        Other => header.extension.type_name(),
    }

    /// The WARC version declared by this record.
    pub const fn version(&self) -> WarcVersion {
        Warcinfo | Response | Resource | Request | Metadata | Revisit | Conversion
            | Continuation | Other => header.version,
    }

    /// Mutably access the WARC version declared by this record.
    pub const fn version_mut(&mut self) -> &mut WarcVersion {
        Warcinfo | Response | Resource | Request | Metadata | Revisit | Conversion
            | Continuation | Other => &mut header.version,
    }

    /// The fields shared by every record type.
    pub const fn core(&self) -> &CoreHeaders<E> {
        Warcinfo | Response | Resource | Request | Metadata | Revisit | Conversion
            | Continuation | Other => &header.core,
    }

    /// The fields every record carries, mutably.
    pub const fn core_mut(&mut self) -> &mut CoreHeaders<E> {
        Warcinfo | Response | Resource | Request | Metadata | Revisit | Conversion
            | Continuation | Other => &mut header.core,
    }

    /// The payload fields, or `None` if this record type has no payload.
    pub const fn payload(&self) -> Option<&PayloadHeaders> {
        Response | Resource | Request | Revisit | Conversion
            | Continuation => Some(&header.payload),
        Warcinfo | Metadata | Other => None,
    }

    /// The payload fields, mutably, or `None` if this record type has no payload.
    pub const fn payload_mut(&mut self) -> Option<&mut PayloadHeaders> {
        Response | Resource | Request | Revisit | Conversion
            | Continuation => Some(&mut header.payload),
        Warcinfo | Metadata | Other => None,
    }

    /// `WARC-Target-URI`: the URI the record's content came from.
    ///
    /// Returns `None` when the field is forbidden or absent.
    pub const fn target_uri(&self) -> Option<&Uri<String>> {
        Response | Resource | Request | Revisit | Conversion
            | Continuation => Some(&header.target_uri),
        Metadata => header.target_uri.as_ref(),
        Warcinfo | Other => None,
    }

    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub const fn warcinfo_id(&self) -> Option<&Uri<String>> {
        Response | Resource | Request | Metadata | Revisit | Conversion
            | Continuation => header.warcinfo_id.as_ref(),
        Warcinfo | Other => None,
    }

    /// `WARC-IP-Address`: the address from which the content was retrieved.
    pub const fn ip_address(&self) -> Option<IpAddr> {
        Response | Resource | Request | Metadata | Revisit => header.ip_address,
        Warcinfo | Conversion | Continuation | Other => None,
    }

    /// `WARC-Concurrent-To`: the other records of this record's capture event, in the order
    /// they were given. Empty for the record types forbidden the field.
    pub fn concurrent_to(&self) -> &[Uri<String>] {
        Response | Resource | Request | Metadata | Revisit => &header.concurrent_to,
        Warcinfo | Conversion | Continuation | Other => &[],
    }

    /// `WARC-Refers-To`: the record this one describes or derives from.
    pub const fn refers_to(&self) -> Option<&Uri<String>> {
        Metadata | Revisit | Conversion => header.refers_to.as_ref(),
        Warcinfo | Response | Resource | Request | Continuation | Other => None,
    }

    /// `WARC-Segment-Number`: this record's position in a segmented series.
    ///
    /// Returns `1` for an origin record and the declared number for a continuation. `None` means
    /// the record is not segmented.
    pub const fn segment_number(&self) -> Option<u64> {
        Continuation => Some(header.segment_number.get()),
        Warcinfo | Response | Resource | Request | Metadata | Revisit | Conversion
            | Other => if header.segment_origin { Some(1) } else { None },
    }
}

/// Generate lifting and rendering for `response`, `resource`, and `request` records.
///
/// These three carry the same six fields, but their header structs are distinct types sharing only
/// field names, which a macro can reach across and a function cannot.
macro_rules! capture_record {
    (lift $lift:ident, $header:ident, $variant:ident, $type_name:literal) => {
        #[doc = concat!("Lift the header block of a `", $type_name, "` record.")]
        fn $lift(mut lifter: Lifter, mut core: CoreHeaders<E>) -> Result<Self, Error> {
            let version = lifter.version;
            let payload = lifter.take_payload();
            let target_uri = lifter.take_required_uri(Field::TargetURI)?;
            let warcinfo_id = lifter.take_uri(Field::WarcinfoID);
            let ip_address = lifter.take_ip_address();
            let concurrent_to = lifter.take_concurrent_to();
            let segment_origin = lifter.take_segment_origin()?;
            let (other, unrecognized) = lifter.finish($type_name)?;
            core.unrecognized = unrecognized;

            Ok(Self::$variant($header {
                version,
                core,
                payload,
                target_uri,
                warcinfo_id,
                ip_address,
                concurrent_to,
                segment_origin,
                other,
            }))
        }
    };

    (store $store:ident, $header:ident, $type_name:literal) => {
        #[doc = concat!("Push the fields of a `", $type_name, "` record's header into the \
                         renderer, giving up the fields every record carries.")]
        fn $store(
            renderer: &mut Renderer,
            header: $header<E>,
        ) -> Result<CoreHeaders<E>, RenderError> {
            renderer.push_payload(header.payload)?;
            renderer.push_uri(Field::TargetURI, header.target_uri)?;
            renderer.push_optional_uri(Field::WarcinfoID, header.warcinfo_id)?;
            renderer.push_ip_address(header.ip_address)?;
            renderer.push_concurrent_to(header.concurrent_to)?;
            renderer.push_segment_origin(header.segment_origin)?;
            renderer.push_extension(&header.other)?;
            Ok(header.core)
        }
    };
}

impl<E: Extension> Record<E> {
    capture_record!(store store_response, ResponseHeader, "response");
    capture_record!(store store_resource, ResourceHeader, "resource");
    capture_record!(store store_request, RequestHeader, "request");

    /// Convert this variant to its raw record type while preserving extension type spelling.
    fn record_type(&self) -> RecordType {
        match self {
            Self::Warcinfo { .. } => RecordType::Warcinfo,
            Self::Response { .. } => RecordType::Response,
            Self::Resource { .. } => RecordType::Resource,
            Self::Request { .. } => RecordType::Request,
            Self::Metadata { .. } => RecordType::Metadata,
            Self::Revisit { .. } => RecordType::Revisit,
            Self::Conversion { .. } => RecordType::Conversion,
            Self::Continuation { .. } => RecordType::Continuation,
            Self::Other { header, .. } => {
                RecordType::Unknown(header.extension.type_name().to_owned())
            }
        }
    }

    /// `Content-Length`: the rendered length of this record's content block.
    ///
    /// This measures the current block. [`into_raw`](Self::into_raw) rejects a conflicting value
    /// in [`CoreHeaders::content_length`].
    #[must_use]
    pub fn content_length(&self) -> u64 {
        let length = match self {
            Self::Warcinfo { body, .. } => body.rendered_len(),
            Self::Metadata { body, .. } => body.rendered_len(),
            Self::Response { body, .. }
            | Self::Resource { body, .. }
            | Self::Request { body, .. }
            | Self::Revisit { body, .. }
            | Self::Conversion { body, .. }
            | Self::Continuation { body, .. }
            | Self::Other { body, .. } => body.len(),
        };

        // A block is held in memory, so its length is a `usize` that fits a `u64` on every
        // platform this crate builds for.
        length as u64
    }

    /// This record's rendered content block.
    ///
    /// A block read as `application/warc-fields` is rendered on demand and comes back owned;
    /// every other block is the bytes the record arrived with and is borrowed.
    #[must_use]
    pub fn body_bytes(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Warcinfo { body, .. } => body.as_bytes(),
            Self::Metadata { body, .. } => body.as_bytes(),
            Self::Response { body, .. }
            | Self::Resource { body, .. }
            | Self::Request { body, .. }
            | Self::Revisit { body, .. }
            | Self::Conversion { body, .. }
            | Self::Continuation { body, .. }
            | Self::Other { body, .. } => Cow::Borrowed(body),
        }
    }

    /// Return this record's payload as defined by WARC 1.1 clause 5.10.
    ///
    /// A `resource` or `conversion` payload is the complete block. For an HTTP `response` or
    /// `request`, it is the entity-body extracted by [`payload::entity_body`].
    ///
    /// Returns `None` for records without a locally determinable payload, including revisits,
    /// continuations, and non-HTTP captures.
    ///
    /// # Errors
    ///
    /// Returns an error if an HTTP block cannot be parsed far enough to extract its entity-body.
    pub fn payload_bytes(&self) -> Result<Option<Cow<'_, [u8]>>, payload::Error> {
        match self {
            Self::Resource { body, .. } | Self::Conversion { body, .. } => {
                Ok(Some(Cow::Borrowed(body)))
            }
            Self::Response { body, .. } | Self::Request { body, .. } => {
                if self.holds_http_message() {
                    payload::entity_body(body).map(Some)
                } else {
                    Ok(None)
                }
            }
            Self::Warcinfo { .. }
            | Self::Metadata { .. }
            | Self::Revisit { .. }
            | Self::Continuation { .. }
            | Self::Other { .. } => Ok(None),
        }
    }

    /// Check the declared block digest and return its failure, if any.
    ///
    /// Returns `None` for a valid digest, no digest, or an unsupported algorithm. The current block
    /// is digested on every call.
    #[must_use]
    pub fn incorrect_block_digest(&self) -> Option<BlockError> {
        let declared = self.core().block_digest.as_ref()?;

        verify_block_digest(declared, &self.body_bytes()).err()
    }

    /// Check the declared payload digest and return its failure, if any.
    ///
    /// Returns `None` for a segment or truncated record, for a payload
    /// [`payload_bytes`](Self::payload_bytes) does not determine, and when no supported digest can
    /// be checked. A malformed HTTP message is reported where a digest is declared over it. The
    /// payload is recomputed on every call.
    #[must_use]
    pub fn incorrect_payload_digest(&self) -> Option<BlockError> {
        check_payload_digest(self).err()
    }

    /// Whether rendering should add a missing payload digest.
    const fn takes_added_payload_digest(&self) -> bool {
        matches!(self, Self::Response { .. } | Self::Request { .. })
    }

    /// Whether this record declares an HTTP message as its block.
    ///
    /// A missing media type is accepted when the target URI uses HTTP or HTTPS.
    fn holds_http_message(&self) -> bool {
        const HTTP: &Scheme = Scheme::new_or_panic("http");
        const HTTPS: &Scheme = Scheme::new_or_panic("https");

        self.target_uri().is_some_and(|target_uri| {
            let scheme = target_uri.scheme();
            scheme == HTTP || scheme == HTTPS
        }) && self
            .core()
            .content_type
            .as_ref()
            .is_none_or(|content_type| content_type.is("application", "http"))
    }

    /// Consume this record and render it as a raw record.
    ///
    /// Fields use their conventional order and standard spelling. Unrecognized fields preserve
    /// their names. URI brackets follow the declared WARC version.
    ///
    /// `Content-Length` comes from the rendered body. If the header also declares a length, the
    /// two must match. Clear or update the declaration after editing a body.
    ///
    /// `WARC-Block-Digest` is checked against the rendered body, and a record that declares none
    /// is given one under SHA-256. A digest naming an algorithm this crate does not compute is
    /// written as read and is not checked.
    ///
    /// `WARC-Payload-Digest` is checked against [`payload_bytes`](Self::payload_bytes). Missing
    /// digests are added to HTTP `response` and `request` records that are neither segments nor
    /// truncated.
    ///
    /// Clone the record first if it must be retained.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::ContentLengthMismatch`] if the record declares a length its block
    /// does not have, [`BlockError::MalformedBlockDigest`] if it declares a digest its algorithm
    /// cannot have produced, [`BlockError::BlockDigestMismatch`] if it declares a digest its block
    /// does not have, [`BlockError::UndeclaredRevisitTruncation`] if a `revisit` record under the
    /// identical payload digest profile carries a block without declaring it truncated,
    /// [`RenderError::MissingProfileField`] if a `revisit` record does not carry a
    /// field its profile requires, [`RenderError::FieldNotInVersion`] if a field named for the
    /// first time in a later version of the standard than the declared one is present,
    /// [`RenderError::ValueNotInVersion`] if the declared version has no spelling for a value the
    /// record carries, and [`RenderError::UnwritableField`] if a field kept as read or written by
    /// the extension carries a name or a value that would not be read back as intended. Returns
    /// [`RenderError::ReservedField`] if such a field names one the standard defines, or
    /// [`RenderError::RepeatedField`] if a record of an extension type names one twice. Returns
    /// [`BlockError::MalformedPayloadDigest`], [`BlockError::PayloadDigestMismatch`], or
    /// [`BlockError::Payload`] where the payload digest fails as the block digest does.
    pub fn into_raw(mut self) -> Result<raw::Record, RenderError> {
        // Resolve the payload digest before rendering the header fields.
        if let Some(added) = check_payload_digest(&self)? {
            if let Some(headers) = self.payload_mut() {
                headers.payload_digest = Some(added);
            }
        }

        // Read before the record is consumed, since the version and the record type come from
        // the header block and the variant rather than from the core headers.
        let version = self.version();
        let record_type = self.record_type();
        let mut renderer = Renderer::new(version, matches!(record_type, RecordType::Unknown(_)));
        let (core, body) = self.into_stored(&mut renderer)?;

        // A block is held in memory, so its length is a `usize` that fits a `u64` on every
        // platform this crate builds for.
        let content_length = body.len() as u64;
        // A record can also be assembled directly by naming its variant, so the declared length
        // is checked here as well as where a header block and a body are paired.
        check_declared_length(core.content_length, content_length)?;
        let block_digest = check_block_digest(core.block_digest, &body)?;

        renderer.push_token(Field::WarcType, record_type.as_str())?;
        renderer.push_uri(Field::RecordID, core.record_id)?;
        renderer.push_date(Field::Date, core.date)?;
        renderer.push_digits(Field::ContentLength, content_length)?;
        renderer.push_digest(Field::BlockDigest, block_digest)?;
        renderer.push_optional_media_type(Field::ContentType, core.content_type)?;
        if let Some(truncated) = &core.truncated {
            renderer.push_token(Field::Truncated, truncated.as_str())?;
        }
        for (name, value) in core.unrecognized {
            renderer.push_as_read(&name, &value)?;
        }
        renderer.check_repetition()?;
        renderer.canonical_order();

        // Every value here was rendered from its typed form, so this conversion cannot fail.
        Ok(untyped::RecordHeader {
            version,
            headers: renderer.headers,
        }
        .with_body(body)
        .into_raw())
    }

    /// Render type-specific fields and return the core fields and body.
    fn into_stored(
        self,
        renderer: &mut Renderer,
    ) -> Result<(CoreHeaders<E>, Vec<u8>), RenderError> {
        match self {
            Self::Warcinfo { header, body } => {
                renderer.push_optional_text(Field::Filename, header.filename)?;
                renderer.push_segment_origin(header.segment_origin)?;
                renderer.push_extension(&header.other)?;
                Ok((header.core, body.into_bytes()))
            }
            Self::Response { header, body } => Ok((Self::store_response(renderer, header)?, body)),
            Self::Resource { header, body } => Ok((Self::store_resource(renderer, header)?, body)),
            Self::Request { header, body } => Ok((Self::store_request(renderer, header)?, body)),
            Self::Metadata { header, body } => {
                renderer.push_optional_uri(Field::TargetURI, header.target_uri)?;
                renderer.push_optional_uri(Field::WarcinfoID, header.warcinfo_id)?;
                renderer.push_ip_address(header.ip_address)?;
                renderer.push_concurrent_to(header.concurrent_to)?;
                renderer.push_optional_uri(Field::RefersTo, header.refers_to)?;
                renderer.push_segment_origin(header.segment_origin)?;
                renderer.push_extension(&header.other)?;
                Ok((header.core, body.into_bytes()))
            }
            Self::Revisit { header, body } => {
                // The digest is what a record under this profile asserts, per clause 6.7.2 of
                // the WARC 1.1 standard, so a record without one says nothing and is refused
                // here as it is when read.
                if matches!(header.profile, RevisitProfile::IdenticalPayloadDigest(_))
                    && header.payload.payload_digest.is_none()
                {
                    return Err(RenderError::MissingProfileField(Field::PayloadDigest));
                }
                // A block is held in memory, so its length is a `usize` that fits a `u64` on
                // every platform this crate builds for.
                check_revisit_block(&header, body.len() as u64)?;
                renderer.push_payload(header.payload)?;
                renderer.push_uri(Field::TargetURI, header.target_uri)?;
                renderer.push_optional_uri(Field::WarcinfoID, header.warcinfo_id)?;
                renderer.push_profile(&header.profile)?;
                renderer.push_ip_address(header.ip_address)?;
                renderer.push_concurrent_to(header.concurrent_to)?;
                renderer.push_optional_uri(Field::RefersTo, header.refers_to)?;
                renderer
                    .push_optional_uri(Field::RefersToTargetURI, header.refers_to_target_uri)?;
                if let Some(refers_to_date) = header.refers_to_date {
                    renderer.push_date(Field::RefersToDate, refers_to_date)?;
                }
                renderer.push_segment_origin(header.segment_origin)?;
                renderer.push_extension(&header.other)?;
                Ok((header.core, body))
            }
            Self::Conversion { header, body } => {
                renderer.push_payload(header.payload)?;
                renderer.push_uri(Field::TargetURI, header.target_uri)?;
                renderer.push_optional_uri(Field::WarcinfoID, header.warcinfo_id)?;
                renderer.push_optional_uri(Field::RefersTo, header.refers_to)?;
                renderer.push_segment_origin(header.segment_origin)?;
                renderer.push_extension(&header.other)?;
                Ok((header.core, body))
            }
            Self::Continuation { header, body } => {
                renderer.push_payload(header.payload)?;
                renderer.push_uri(Field::TargetURI, header.target_uri)?;
                renderer.push_optional_uri(Field::WarcinfoID, header.warcinfo_id)?;
                renderer.push_digits(Field::SegmentNumber, header.segment_number.get())?;
                renderer.push_uri(Field::SegmentOriginID, header.segment_origin_id)?;
                renderer
                    .push_optional_digits(Field::SegmentTotalLength, header.segment_total_length)?;
                renderer.push_extension(&header.other)?;
                Ok((header.core, body))
            }
            Self::Other { header, body } => {
                renderer.push_segment_origin(header.segment_origin)?;
                Ok((header.core, body))
            }
        }
    }
}

impl<E: Extension> RecordHeader<E> {
    capture_record!(lift lift_response, ResponseHeader, Response, "response");
    capture_record!(lift lift_resource, ResourceHeader, Resource, "resource");
    capture_record!(lift lift_request, RequestHeader, Request, "request");

    /// Pair this header with a content block to create a record.
    ///
    /// A `warcinfo` or `metadata` block declared as `application/warc-fields` is parsed into
    /// fields. Other blocks remain raw.
    ///
    /// A declared `Content-Length` must match the block. The resulting record stores its actual
    /// length.
    ///
    /// Declared digests are preserved without validation. They can be inspected on the resulting
    /// [`Record`] and are validated when it is rendered. Missing digests are also added during
    /// rendering.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::ContentLengthMismatch`] if the header block declares a
    /// `Content-Length` the given block does not have, [`BlockError::Fields`] if the block is
    /// declared `application/warc-fields` and is not, and
    /// [`BlockError::UndeclaredRevisitTruncation`] if a `revisit` record under the identical
    /// payload digest profile carries a block without declaring it truncated.
    pub fn with_body(mut self, body: Vec<u8>) -> Result<Record<E>, BlockError> {
        // A block is held in memory, so its length is a `usize` that fits a `u64` on every
        // platform this crate builds for.
        let content_length = body.len() as u64;
        check_declared_length(self.core().content_length, content_length)?;
        self.core_mut().content_length = Some(content_length);
        if let Self::Revisit(header) = &self {
            check_revisit_block(header, content_length)?;
        }

        let record = match self {
            Self::Warcinfo(header) => {
                let body = FieldsBlock::read(header.core.content_type.as_ref(), body)?;
                Record::Warcinfo { header, body }
            }
            Self::Metadata(header) => {
                let body = FieldsBlock::read(header.core.content_type.as_ref(), body)?;
                Record::Metadata { header, body }
            }
            Self::Response(header) => Record::Response { header, body },
            Self::Resource(header) => Record::Resource { header, body },
            Self::Request(header) => Record::Request { header, body },
            Self::Revisit(header) => Record::Revisit { header, body },
            Self::Conversion(header) => Record::Conversion { header, body },
            Self::Continuation(header) => Record::Continuation { header, body },
            Self::Other(header) => Record::Other { header, body },
        };

        Ok(record)
    }

    /// Lift the header of a `warcinfo` record.
    fn lift_warcinfo(mut lifter: Lifter, mut core: CoreHeaders<E>) -> Result<Self, Error> {
        let version = lifter.version;
        let filename = lifter.take_text(Field::Filename);
        let segment_origin = lifter.take_segment_origin()?;
        let (other, unrecognized) = lifter.finish("warcinfo")?;
        core.unrecognized = unrecognized;

        Ok(Self::Warcinfo(WarcinfoHeader {
            version,
            core,
            filename,
            segment_origin,
            other,
        }))
    }

    /// Lift the header block of a `metadata` record.
    fn lift_metadata(mut lifter: Lifter, mut core: CoreHeaders<E>) -> Result<Self, Error> {
        let version = lifter.version;
        let target_uri = lifter.take_uri(Field::TargetURI);
        let warcinfo_id = lifter.take_uri(Field::WarcinfoID);
        let ip_address = lifter.take_ip_address();
        let concurrent_to = lifter.take_concurrent_to();
        let refers_to = lifter.take_uri(Field::RefersTo);
        let segment_origin = lifter.take_segment_origin()?;
        let (other, unrecognized) = lifter.finish("metadata")?;
        core.unrecognized = unrecognized;

        Ok(Self::Metadata(MetadataHeader {
            version,
            core,
            target_uri,
            warcinfo_id,
            ip_address,
            concurrent_to,
            refers_to,
            segment_origin,
            other,
        }))
    }

    /// Lift the header of a `revisit` record and apply its profile requirements.
    fn lift_revisit(mut lifter: Lifter, mut core: CoreHeaders<E>) -> Result<Self, Error> {
        let version = lifter.version;
        let payload = lifter.take_payload();
        let target_uri = lifter.take_required_uri(Field::TargetURI)?;
        let warcinfo_id = lifter.take_uri(Field::WarcinfoID);
        let profile = RevisitProfile::from(
            lifter
                .take_uri(Field::Profile)
                .ok_or(Error::MissingField(Field::Profile))?
                .as_str(),
        );
        // A record under this profile shall carry the digest that was compared, per clause 6.7.2
        // of the WARC 1.1 standard.
        if matches!(profile, RevisitProfile::IdenticalPayloadDigest(_))
            && payload.payload_digest.is_none()
        {
            return Err(Error::MissingField(Field::PayloadDigest));
        }
        let ip_address = lifter.take_ip_address();
        let concurrent_to = lifter.take_concurrent_to();
        let refers_to = lifter.take_uri(Field::RefersTo);
        let refers_to_target_uri = lifter.take_uri(Field::RefersToTargetURI);
        let refers_to_date = lifter.take_date(Field::RefersToDate)?;
        let segment_origin = lifter.take_segment_origin()?;
        let (other, unrecognized) = lifter.finish("revisit")?;
        core.unrecognized = unrecognized;

        Ok(Self::Revisit(RevisitHeader {
            version,
            core,
            payload,
            target_uri,
            warcinfo_id,
            profile,
            ip_address,
            concurrent_to,
            refers_to,
            refers_to_target_uri,
            refers_to_date,
            segment_origin,
            other,
        }))
    }

    /// Lift the header block of a `conversion` record.
    fn lift_conversion(mut lifter: Lifter, mut core: CoreHeaders<E>) -> Result<Self, Error> {
        let version = lifter.version;
        let payload = lifter.take_payload();
        let target_uri = lifter.take_required_uri(Field::TargetURI)?;
        let warcinfo_id = lifter.take_uri(Field::WarcinfoID);
        let refers_to = lifter.take_uri(Field::RefersTo);
        let segment_origin = lifter.take_segment_origin()?;
        let (other, unrecognized) = lifter.finish("conversion")?;
        core.unrecognized = unrecognized;

        Ok(Self::Conversion(ConversionHeader {
            version,
            core,
            payload,
            target_uri,
            warcinfo_id,
            refers_to,
            segment_origin,
            other,
        }))
    }

    /// Lift the header of a `continuation` record.
    fn lift_continuation(mut lifter: Lifter, mut core: CoreHeaders<E>) -> Result<Self, Error> {
        let version = lifter.version;
        let payload = lifter.take_payload();
        let target_uri = lifter.take_required_uri(Field::TargetURI)?;
        let warcinfo_id = lifter.take_uri(Field::WarcinfoID);
        let segment_number = lifter.take_segment_number()?;
        let segment_origin_id = lifter.take_required_uri(Field::SegmentOriginID)?;
        let segment_total_length = lifter.take_digits(Field::SegmentTotalLength);
        let (other, unrecognized) = lifter.finish("continuation")?;
        core.unrecognized = unrecognized;

        Ok(Self::Continuation(ContinuationHeader {
            version,
            core,
            payload,
            target_uri,
            warcinfo_id,
            segment_number,
            segment_origin_id,
            segment_total_length,
            other,
        }))
    }

    /// Lift a record type defined by the extension.
    fn lift_other(
        mut lifter: Lifter,
        mut core: CoreHeaders<E>,
        name: String,
    ) -> Result<Self, Error> {
        let version = lifter.version;
        let Some(extension) = E::Types::from_type_name(&name) else {
            return Err(Error::UnknownRecordType(name));
        };
        // The record is written back under the name the extension type gives itself. A name the
        // standard defines would be written back as a record of that type, so a type claiming
        // one is refused here rather than silently becoming a standard record on the way out.
        let claimed = extension.type_name();
        if !matches!(RecordType::from(claimed), RecordType::Unknown(_)) {
            return Err(Error::RedefinedRecordType(claimed.to_owned()));
        }

        let segment_origin = lifter.take_segment_origin()?;
        // The standard does not constrain a record type it does not define, so every remaining
        // field, known names included, is preserved as read.
        core.unrecognized = lifter.finish_unconstrained()?;

        Ok(Self::Other(OtherHeader {
            version,
            core,
            segment_origin,
            extension,
        }))
    }
}

impl<E: Extension> TryFrom<untyped::RecordHeader> for RecordHeader<E> {
    type Error = Error;

    /// Convert an untyped header to its semantic representation.
    ///
    /// # Errors
    ///
    /// Returns the first semantic rule the header violates.
    fn try_from(header: untyped::RecordHeader) -> Result<Self, Error> {
        let mut lifter = Lifter {
            version: header.version,
            fields: header.headers,
        };
        lifter.check_repetition()?;
        lifter.check_version()?;

        let record_type = RecordType::from(&*lifter.take_required_token(Field::WarcType)?);
        let core = CoreHeaders {
            record_id: lifter.take_required_uri(Field::RecordID)?,
            date: lifter
                .take_date(Field::Date)?
                .ok_or(Error::MissingField(Field::Date))?,
            // The field is kept as declared rather than required here: the level that reads a
            // record from its bytes has already refused one that declares no length.
            content_length: lifter.take_digits(Field::ContentLength),
            block_digest: lifter.take_digest(Field::BlockDigest),
            content_type: lifter.take_media_type(Field::ContentType),
            truncated: lifter
                .take_token(Field::Truncated)
                .map(|reason| TruncatedType::from(&*reason)),
            unrecognized: Vec::new(),
        };

        match record_type {
            RecordType::Warcinfo => Self::lift_warcinfo(lifter, core),
            RecordType::Response => Self::lift_response(lifter, core),
            RecordType::Resource => Self::lift_resource(lifter, core),
            RecordType::Request => Self::lift_request(lifter, core),
            RecordType::Metadata => Self::lift_metadata(lifter, core),
            RecordType::Revisit => Self::lift_revisit(lifter, core),
            RecordType::Conversion => Self::lift_conversion(lifter, core),
            RecordType::Continuation => Self::lift_continuation(lifter, core),
            RecordType::Unknown(name) => Self::lift_other(lifter, core, name),
        }
    }
}

impl<E: Extension> TryFrom<untyped::Record> for Record<E> {
    type Error = Error;

    /// Convert an untyped record to its semantic representation.
    ///
    /// # Errors
    ///
    /// Returns the first semantic rule the record violates.
    fn try_from(record: untyped::Record) -> Result<Self, Error> {
        Ok(RecordHeader::try_from(record.header)?.with_body(record.body)?)
    }
}

/// The unclaimed fields of a record being lifted.
struct Lifter {
    version: WarcVersion,
    fields: Vec<(HeaderName, HeaderValue)>,
}

/// Take a field whose grammar maps to one [`ValueForm`] variant.
macro_rules! take_form {
    ($name:ident, $variant:ident, $value:ty, $rule:literal) => {
        #[doc = concat!("Remove `field`, whose value is ", $rule, ".")]
        fn $name(&mut self, field: Field) -> Option<$value> {
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
    fn check_repetition(&self) -> Result<(), Error> {
        repeated_field(self.fields.iter().map(|(name, _)| name))
            .map_or(Ok(()), |field| Err(Error::RepeatedField(field)))
    }

    /// Reject a standard field the declared version does not define.
    ///
    /// The grammar admits the union of the two versions' fields, so this is where a record is
    /// held to the version it declares. Rendering checks the same rule, since a record can also
    /// be assembled or edited after it is read.
    fn check_version(&self) -> Result<(), Error> {
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
    fn take_uri(&mut self, field: Field) -> Option<Uri<String>> {
        match self.take_form(field)? {
            // Whether the URI was written in the angle brackets of the `"<" uri ">"` rule is
            // the grammar's record of how it arrived. It is written back as the declared
            // version requires rather than as it was read, so it is dropped here.
            ValueForm::Uri { uri, .. } => Some(uri),
            form => unreachable!("invariant violation: {field} was read as {form:?}"),
        }
    }

    /// Remove `field`, whose presence the record's type makes mandatory, as a URI.
    fn take_required_uri(&mut self, field: Field) -> Result<Uri<String>, Error> {
        self.take_uri(field).ok_or(Error::MissingField(field))
    }

    /// Remove `field`, whose presence the record's type makes mandatory, as a token.
    fn take_required_token(&mut self, field: Field) -> Result<Box<str>, Error> {
        self.take_token(field).ok_or(Error::MissingField(field))
    }

    /// Remove `WARC-IP-Address`.
    fn take_ip_address(&mut self) -> Option<IpAddr> {
        match self.take_form(Field::IPAddress)? {
            ValueForm::IpAddress(address) => Some(address),
            form => unreachable!("invariant violation: WARC-IP-Address was read as {form:?}"),
        }
    }

    /// Remove `field` and validate its date against the declared WARC version.
    fn take_date(&mut self, field: Field) -> Result<Option<WarcDate>, Error> {
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
    fn take_concurrent_to(&mut self) -> Vec<Uri<String>> {
        let mut concurrent_to = Vec::new();
        while let Some(uri) = self.take_uri(Field::ConcurrentTo) {
            concurrent_to.push(uri);
        }

        concurrent_to
    }

    /// Remove the fields describing the record's payload.
    fn take_payload(&mut self) -> PayloadHeaders {
        PayloadHeaders {
            payload_digest: self.take_digest(Field::PayloadDigest),
            identified_payload_type: self.take_media_type(Field::IdentifiedPayloadType),
        }
    }

    /// Remove and validate `WARC-Segment-Number` from an origin record.
    fn take_segment_origin(&mut self) -> Result<bool, Error> {
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
    fn take_segment_number(&mut self) -> Result<SegmentNumber, Error> {
        let number = self
            .take_digits(Field::SegmentNumber)
            .ok_or(Error::MissingField(Field::SegmentNumber))?;

        SegmentNumber::new(number).ok_or_else(|| Error::MalformedField {
            field: Field::SegmentNumber,
            value: number.to_string(),
        })
    }

    /// Reject remaining standard fields, then offer the rest to the extension.
    fn finish<F: ExtensionFields>(
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
    fn finish_unconstrained(self) -> Result<Vec<(String, String)>, Error> {
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

/// Fields being rendered under a declared WARC version.
struct Renderer {
    version: WarcVersion,
    /// Whether the record's type is one no version of the standard defines.
    ///
    /// Such a record is under no constraint about which fields it carries, so it keeps standard
    /// names as read rather than being held to what the standard says about them.
    unconstrained: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Push required or optional fields represented by one [`ValueForm`] variant.
macro_rules! push_form {
    ($push:ident, $push_optional:ident, $variant:ident, $value:ty) => {
        fn $push(&mut self, field: Field, value: $value) -> Result<(), RenderError> {
            self.push(field, ValueForm::$variant(value))
        }

        fn $push_optional(
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
    const fn new(version: WarcVersion, unconstrained: bool) -> Self {
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
    fn push_uri(&mut self, field: Field, uri: Uri<String>) -> Result<(), RenderError> {
        let bracketed = self.brackets(field);
        self.push(field, ValueForm::Uri { uri, bracketed })
    }

    /// Append a URI-valued field when the record carries one.
    fn push_optional_uri(
        &mut self,
        field: Field,
        uri: Option<Uri<String>>,
    ) -> Result<(), RenderError> {
        uri.map_or(Ok(()), |uri| self.push_uri(field, uri))
    }

    /// Append a date, refusing one the declared version has no spelling for.
    fn push_date(&mut self, field: Field, date: WarcDate) -> Result<(), RenderError> {
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
    fn push_token(&mut self, field: Field, token: &str) -> Result<(), RenderError> {
        if !is_token(token.as_bytes()) {
            return Err(RenderError::UnwritableField {
                name: field.name().to_owned(),
                reason: format!("`{token}` is not a token"),
            });
        }

        self.push(field, ValueForm::Token(token.into()))
    }

    /// Append `WARC-Profile`, validating custom profile URIs.
    fn push_profile(&mut self, profile: &RevisitProfile) -> Result<(), RenderError> {
        let uri = Uri::parse(profile.as_str())
            .map_err(|error| RenderError::UnwritableField {
                name: Field::Profile.name().to_owned(),
                reason: error.to_string(),
            })?
            .to_owned();

        self.push_uri(Field::Profile, uri)
    }

    /// Append the fields describing the record's payload.
    fn push_payload(&mut self, payload: PayloadHeaders) -> Result<(), RenderError> {
        self.push_optional_digest(Field::PayloadDigest, payload.payload_digest)?;
        self.push_optional_media_type(
            Field::IdentifiedPayloadType,
            payload.identified_payload_type,
        )
    }

    /// Append `WARC-IP-Address` when the record carries one.
    fn push_ip_address(&mut self, ip_address: Option<IpAddr>) -> Result<(), RenderError> {
        ip_address.map_or(Ok(()), |address| {
            self.push(Field::IPAddress, ValueForm::IpAddress(address))
        })
    }

    /// Append one `WARC-Concurrent-To` line per referenced record.
    fn push_concurrent_to(&mut self, concurrent_to: Vec<Uri<String>>) -> Result<(), RenderError> {
        for record_id in concurrent_to {
            self.push_uri(Field::ConcurrentTo, record_id)?;
        }

        Ok(())
    }

    /// Append `WARC-Segment-Number` with the value `1`, the only value the standard permits on
    /// a record that is not a `continuation`, when the record is the origin of a series.
    fn push_segment_origin(&mut self, segment_origin: bool) -> Result<(), RenderError> {
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
    fn push_as_read(&mut self, name: &str, value: &str) -> Result<(), RenderError> {
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
    fn check_repetition(&self) -> Result<(), RenderError> {
        repeated_field(self.headers.iter().map(|(name, _)| name))
            .map_or(Ok(()), |field| Err(RenderError::RepeatedField(field)))
    }

    /// Append and validate the extension's fields.
    fn push_extension<F: ExtensionFields>(&mut self, other: &F) -> Result<(), RenderError> {
        let mut fields = Vec::new();
        other.append_to(&mut fields);
        for (name, value) in fields {
            self.push_as_read(&name, &value)?;
        }

        Ok(())
    }

    /// Put standard fields in conventional order, followed by extension fields.
    fn canonical_order(&mut self) {
        self.headers
            .sort_by_key(|(name, _)| name.field().map_or(usize::MAX, Field::canonical_rank));
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::record::extension::{ExtensionTruncatedReason, Never};

    const RECORD_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";
    const DATE: &str = "2020-07-08T02:52:55Z";

    /// The block the block-digest tests declare digests of.
    const DIGESTED_BLOCK: &[u8] = b"hello";

    /// Read the field lines a record would be written with as the grammatical record they
    /// spell, which is the only way in to the semantic one.
    ///
    /// The three fields every record carries come first, so that each test writes only the
    /// lines its own record type adds to them.
    fn grammar_of(
        version: WarcVersion,
        record_type: &str,
        lines: &[(&str, &str)],
        body: &[u8],
    ) -> untyped::Record {
        let record_id = format!("<{RECORD_ID}>");
        let mut all = vec![
            ("WARC-Type", record_type),
            ("WARC-Record-ID", record_id.as_str()),
            ("WARC-Date", DATE),
        ];
        all.extend_from_slice(lines);

        untyped::Record::try_from(crate::io::test_record(version, &all, body))
            .expect("field lines matching the grammars their names select")
    }

    /// A WARC 1.1 record of the given type, carrying the given lines and no block.
    fn grammar(record_type: &str, lines: &[(&str, &str)]) -> untyped::Record {
        grammar_of(WarcVersion::V1_1, record_type, lines, b"")
    }

    /// Lift a grammatical record under the core vocabulary alone, which is what the tests here
    /// mean by `Record` unless they name an extension.
    fn lift_grammar(grammar: untyped::Record) -> Result<Record, Error> {
        Record::try_from(grammar)
    }

    /// Lift a WARC 1.1 record of the given type under the core vocabulary alone.
    fn lift(record_type: &str, lines: &[(&str, &str)]) -> Result<Record, Error> {
        lift_grammar(grammar(record_type, lines))
    }

    /// Lift the header block of a WARC 1.1 record of the given type, framing the given block.
    ///
    /// The block itself is dropped, since a header block is what is wanted here, but the length
    /// it is framed by is what the header block declares.
    fn lift_header(
        record_type: &str,
        lines: &[(&str, &str)],
        body: &[u8],
    ) -> Result<RecordHeader, Error> {
        RecordHeader::try_from(grammar_of(WarcVersion::V1_1, record_type, lines, body).header)
    }

    /// The value a rendered record writes for the named field, as text.
    fn written(record: &raw::Record, name: &str) -> Option<String> {
        record
            .header
            .get(name)
            .map(|value| String::from_utf8_lossy(value).trim().to_owned())
    }

    /// Update a record with the digests rendering would add.
    ///
    /// Used when comparing a value before and after a rendering round trip.
    pub(super) fn as_rendered<E: Extension>(mut record: Record<E>) -> Record<E> {
        if record.core().block_digest.is_none() {
            let digest = crate::record::digest::added_digest(&record.body_bytes());
            record.core_mut().block_digest = Some(digest);
        }

        if let Ok(Some(digest)) = check_payload_digest(&record) {
            if let Some(headers) = record.payload_mut() {
                headers.payload_digest = Some(digest);
            }
        }

        record
    }

    /// The names a rendered record's block is written with, in order.
    fn written_names(record: &raw::Record) -> Vec<&str> {
        record
            .header
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// A vocabulary standing in for a small archiving extension: one record type of its own,
    /// one truncation reason, and one field it adds to `warcinfo` records.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Sitemaps;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SitemapType {
        /// A type of the extension's own, spelled with a capital to pin down that a record is
        /// written under the name its type gives itself rather than the one it was read with.
        Sitemap,
        /// A type that answers to a name of its own and then names one the standard defines,
        /// which is what a record must not be lifted as.
        Impostor,
    }

    impl ExtensionRecordType for SitemapType {
        fn type_name(&self) -> &str {
            match self {
                Self::Sitemap => "Sitemap",
                Self::Impostor => "response",
            }
        }

        fn from_type_name(name: &str) -> Option<Self> {
            match name {
                "sitemap" => Some(Self::Sitemap),
                "impostor" => Some(Self::Impostor),
                _ => None,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Refused {
        Robots,
    }

    impl ExtensionTruncatedReason for Refused {
        fn reason_token(&self) -> &str {
            match self {
                Self::Robots => "robots",
            }
        }

        fn from_reason_token(token: &str) -> Option<Self> {
            token.eq_ignore_ascii_case("robots").then_some(Self::Robots)
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CrawlFields {
        crawl_id: Option<String>,
    }

    impl ExtensionFields for CrawlFields {
        fn from_unclaimed(fields: &mut Unclaimed<'_>) -> Result<Self, Error> {
            Ok(Self {
                crawl_id: fields.claim("x-crawl-id").into_iter().next(),
            })
        }

        fn append_to(&self, fields: &mut Vec<(String, String)>) {
            if let Some(crawl_id) = &self.crawl_id {
                fields.push(("x-crawl-id".to_owned(), crawl_id.clone()));
            }
        }
    }

    /// A vocabulary whose one field spells the name of a field the standard defines, which is
    /// what no record may be written with twice.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Impersonating;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SecondRecordId;

    impl ExtensionFields for SecondRecordId {
        fn from_unclaimed(_fields: &mut Unclaimed<'_>) -> Result<Self, Error> {
            Ok(Self)
        }

        fn append_to(&self, fields: &mut Vec<(String, String)>) {
            fields.push((
                Field::RecordID.standard_name().to_owned(),
                format!("<{RECORD_ID}>"),
            ));
        }
    }

    /// A vocabulary whose one field spells the name of a field the standard defines for the
    /// record type it is attached to, which is what no record may be written with twice.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Renaming;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileNamer;

    impl ExtensionFields for FileNamer {
        fn from_unclaimed(_fields: &mut Unclaimed<'_>) -> Result<Self, Error> {
            Ok(Self)
        }

        fn append_to(&self, fields: &mut Vec<(String, String)>) {
            fields.push((
                Field::Filename.standard_name().to_owned(),
                "example.warc".to_owned(),
            ));
        }
    }

    impl Extension for Renaming {
        type Types = Never;
        type TruncatedReasons = Never;
        type WarcinfoFields = FileNamer;
        type ResponseFields = ();
        type ResourceFields = ();
        type RequestFields = ();
        type MetadataFields = ();
        type RevisitFields = ();
        type ConversionFields = ();
        type ContinuationFields = ();
    }

    impl Extension for Impersonating {
        type Types = Never;
        type TruncatedReasons = Never;
        type WarcinfoFields = SecondRecordId;
        type ResponseFields = ();
        type ResourceFields = ();
        type RequestFields = ();
        type MetadataFields = ();
        type RevisitFields = ();
        type ConversionFields = ();
        type ContinuationFields = ();
    }

    impl Extension for Sitemaps {
        type Types = SitemapType;
        type TruncatedReasons = Refused;
        type WarcinfoFields = CrawlFields;
        type ResponseFields = ();
        type ResourceFields = ();
        type RequestFields = ();
        type MetadataFields = ();
        type RevisitFields = ();
        type ConversionFields = ();
        type ContinuationFields = ();
    }

    /// The HTTP response used by the payload and digest tests.
    const RESPONSE_BLOCK: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nhello";

    #[test]
    fn a_response_lifts_its_fields() {
        let record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "response",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-IP-Address", "93.184.216.34"),
                (
                    "WARC-Payload-Digest",
                    "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
                ),
                ("Content-Type", "application/http; msgtype=response"),
                ("WARC-Concurrent-To", "<urn:uuid:request>"),
            ],
            RESPONSE_BLOCK,
        ))
        .expect("liftable record");

        let Record::Response { header, body } = record else {
            panic!("not a response");
        };
        assert_eq!(header.target_uri, "http://example.com/");
        assert_eq!(header.ip_address, "93.184.216.34".parse().ok());
        assert_eq!(
            header
                .payload
                .payload_digest
                .map(|digest| digest.to_string()),
            Some("sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N".to_owned())
        );
        assert_eq!(header.concurrent_to, ["urn:uuid:request"]);
        assert_eq!(header.core.record_id, RECORD_ID);
        assert!(header.core.unrecognized.is_empty());
        assert_eq!(body, RESPONSE_BLOCK);
    }

    const WARCINFO_BLOCK: &[u8] = b"SOFTWARE:  archivindex/0.1.0\r\nisPartOf: a-crawl\r\n";

    #[test]
    fn a_warcinfo_body_reads_as_fields_and_round_trips() {
        let record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "warcinfo",
            &[
                ("Content-Type", "application/warc-fields"),
                ("WARC-Filename", "example.warc"),
            ],
            WARCINFO_BLOCK,
        ))
        .expect("liftable record");

        let Record::Warcinfo { header, body } = &record else {
            panic!("not a warcinfo");
        };
        assert_eq!(
            header.filename.as_ref().and_then(Text::to_str),
            Some("example.warc")
        );
        let FieldsBlock::Fields(fields) = body else {
            panic!("not read as fields");
        };
        assert_eq!(fields.software(), Some("archivindex/0.1.0"));

        let raw = record.clone().into_raw().expect("renderable record");
        assert_eq!(raw.body, WARCINFO_BLOCK);
        assert_eq!(
            written(&raw, "WARC-Record-ID").as_deref(),
            Some("<urn:uuid:00000000-0000-0000-0000-000000000001>")
        );

        let again = Record::try_from(untyped::Record::try_from(raw).expect("readable record"))
            .expect("liftable record");
        assert_eq!(again, as_rendered(record));
    }

    /// A header block is read without the block its record frames, and answers about its fields
    /// exactly as the record it heads does.
    #[test]
    fn a_header_block_lifts_and_answers_on_its_own() {
        let header = lift_header(
            "response",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-IP-Address", "93.184.216.34"),
                ("WARC-Concurrent-To", "<urn:uuid:request>"),
            ],
            b"hello",
        )
        .expect("liftable header block");

        assert_eq!(header.type_name(), "response");
        assert_eq!(header.version(), WarcVersion::V1_1);
        assert_eq!(header.core().record_id, RECORD_ID);
        assert_eq!(
            *header.target_uri().expect("a response's target URI"),
            "http://example.com/"
        );
        assert_eq!(header.ip_address(), "93.184.216.34".parse().ok());
        assert_eq!(header.concurrent_to(), ["urn:uuid:request"]);
        assert_eq!(header.segment_number(), None);
        assert!(header.payload().is_some());

        let record = header
            .clone()
            .with_body(b"hello".to_vec())
            .expect("a block a response frames");
        assert_eq!(record.type_name(), header.type_name());
        assert_eq!(record.core(), header.core());
        assert_eq!(record.target_uri(), header.target_uri());
        assert_eq!(record.concurrent_to(), header.concurrent_to());
        assert_eq!(record.payload(), header.payload());
    }

    /// A grammatical record read in two steps, its header block and then the block that block
    /// frames, is the record read in one.
    #[test]
    fn a_header_block_paired_with_a_block_is_the_record() {
        for grammar in [
            grammar_of(
                WarcVersion::V1_1,
                "warcinfo",
                &[("Content-Type", "application/warc-fields")],
                WARCINFO_BLOCK,
            ),
            grammar_of(
                WarcVersion::V1_1,
                "response",
                &[("WARC-Target-URI", "http://example.com/")],
                b"hello",
            ),
        ] {
            let at_once = lift_grammar(grammar.clone()).expect("liftable record");
            let in_two_steps = RecordHeader::try_from(grammar.header)
                .expect("liftable header block")
                .with_body(grammar.body)
                .expect("a block its header describes");

            assert_eq!(in_two_steps, at_once);
        }
    }

    /// The length of a record's block is measured when it is asked for, so it follows a block
    /// that is edited, and it is the length the record renders under.
    #[test]
    fn content_length_is_measured_from_the_block() {
        let mut record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "warcinfo",
            &[("Content-Type", "application/warc-fields")],
            WARCINFO_BLOCK,
        ))
        .expect("liftable record");
        // The block is held as it was read, two spaces after `SOFTWARE:` and all.
        assert_eq!(record.content_length(), WARCINFO_BLOCK.len() as u64);

        let Record::Warcinfo {
            body: FieldsBlock::Fields(fields),
            ..
        } = &mut record
        else {
            panic!("not a warcinfo read as fields");
        };
        fields
            .push(WarcinfoField::Hostname, "crawler.example.com")
            .expect("a writable field");

        // Changing the body releases the block it was read from, so the record now renders
        // canonically and is longer than the block by that one line, not by that line and the
        // space the original block wasted. The length the record was read declaring is the
        // length of a block it no longer carries, so it is cleared for the block to answer.
        record.core_mut().content_length = None;

        let length = record.content_length();
        let raw = record.into_raw().expect("renderable record");
        assert_eq!(raw.body.len() as u64, length);
        assert_eq!(raw.content_length(), length);
    }

    /// The length a record was framed by is the length it declares, whether it was read whole
    /// or as the header block alone, which is where the declaration is all there is to say how
    /// long the block it frames is.
    #[test]
    fn a_declared_length_is_kept_as_it_was_read() {
        let lines = [("WARC-Target-URI", "http://example.com/")];

        let record = lift_grammar(grammar_of(WarcVersion::V1_1, "response", &lines, b"hello"))
            .expect("liftable record");
        assert_eq!(record.core().content_length, Some(5));

        let header = lift_header("response", &lines, b"hello").expect("liftable header block");
        assert_eq!(header.core().content_length, Some(5));
    }

    /// A header block read framing one block is paired only with a block of that length, and
    /// the record the pairing makes declares the length of the block it was given.
    #[test]
    fn a_header_block_refuses_a_block_of_another_length() {
        let header = lift_header(
            "response",
            &[("WARC-Target-URI", "http://example.com/")],
            b"hello",
        )
        .expect("liftable header block");

        assert_eq!(
            header.clone().with_body(b"good day".to_vec()),
            Err(BlockError::ContentLengthMismatch {
                declared: 5,
                actual: 8,
            })
        );
        assert_eq!(
            header
                .with_body(b"world".to_vec())
                .expect("a block the header block frames")
                .core()
                .content_length,
            Some(5)
        );
    }

    /// A block paired with a header block declaring `warc-fields` is read as those fields, so
    /// octets that are not them are what the pairing fails on.
    #[test]
    fn a_header_block_declaring_fields_refuses_a_block_that_is_not_them() {
        const BLOCK: &[u8] = b"this line names no field\r\n";

        let header = lift_header(
            "warcinfo",
            &[("Content-Type", "application/warc-fields")],
            BLOCK,
        )
        .expect("liftable header block");

        assert_eq!(
            header.with_body(BLOCK.to_vec()),
            Err(BlockError::Fields(fields::Error::NotANamedField {
                offset: 0
            }))
        );

        // The same octets under any other content type are the record's as they stand.
        let header = lift_header("warcinfo", &[("Content-Type", "text/plain")], BLOCK)
            .expect("liftable header block");
        let record = header
            .with_body(BLOCK.to_vec())
            .expect("a block that is not read as fields cannot fail to be read as them");

        assert_eq!(record.body_bytes().as_ref(), BLOCK);
    }

    /// A record is also assembled by naming its variant, where nothing holds its declaration to
    /// its block, so writing asks again rather than writing what no reader would read back.
    #[test]
    fn a_record_declaring_a_length_its_block_does_not_have_is_not_written() {
        let mut record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "response",
            &[("WARC-Target-URI", "http://example.com/")],
            b"hello",
        ))
        .expect("liftable record");

        let Record::Response { body, .. } = &mut record else {
            panic!("not a response");
        };
        body.extend_from_slice(b", world");

        assert_eq!(
            record.clone().into_raw(),
            Err(RenderError::Block(BlockError::ContentLengthMismatch {
                declared: 5,
                actual: 12,
            }))
        );

        // The block the record now carries is written by declaring the length it has.
        record.core_mut().content_length = Some(12);
        assert_eq!(
            record.into_raw().expect("renderable record").body,
            b"hello, world"
        );
    }

    /// Build an untyped response with the given block digest.
    fn grammar_declaring_digest(value: &str) -> untyped::Record {
        grammar_of(
            WarcVersion::V1_1,
            "response",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Block-Digest", value),
            ],
            DIGESTED_BLOCK,
        )
    }

    /// Build a semantic response with the given block digest.
    fn declaring_digest(value: &str) -> Record {
        lift_grammar(grammar_declaring_digest(value)).expect("liftable record")
    }

    /// Parse a digest used by these tests.
    fn digest(value: &str) -> LabelledDigest {
        LabelledDigest::parse(value.as_bytes()).expect("a labelled digest")
    }

    /// Rendering adds a SHA-256 block digest when none is declared.
    #[test]
    fn a_record_declaring_no_block_digest_is_given_one() {
        let raw = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "response",
            &[("WARC-Target-URI", "http://example.com/")],
            DIGESTED_BLOCK,
        ))
        .expect("liftable record")
        .into_raw()
        .expect("renderable record");

        assert_eq!(
            written(&raw, "WARC-Block-Digest").as_deref(),
            Some("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }

    /// Valid block digests are checked in their declared format and preserved as read.
    #[test]
    fn a_block_digest_the_block_has_is_written_as_read() {
        for value in [
            "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
            "sha1:vl2mmho4yxukfwv63yhtwsbm3gxksq2n",
            "SHA-1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "sha1:qvTGHdzF6KLavt4PO0gs2a6pQ00=",
            "md5:5d41402abc4b2a76b9719d911017c592",
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ] {
            let raw = declaring_digest(value)
                .into_raw()
                .expect("renderable record");

            assert_eq!(
                written(&raw, "WARC-Block-Digest").as_deref(),
                Some(value),
                "{value}"
            );
        }
    }

    /// A malformed value is reported without preventing the record from being read.
    #[test]
    fn a_block_digest_its_algorithm_cannot_have_produced_is_reported() {
        for value in [
            // Invalid encoding, wrong length, and the length of another algorithm.
            "sha1:not-a-digest",
            "sha1:aaf4c61d",
            "md5:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
        ] {
            let record = declaring_digest(value);

            assert_eq!(
                record.incorrect_block_digest(),
                Some(BlockError::MalformedBlockDigest(Box::new(digest(value)))),
                "{value}"
            );
        }
    }

    /// A mismatched digest reports both the declared and computed values.
    #[test]
    fn a_block_digest_the_block_does_not_have_is_reported() {
        for (value, actual) in [
            (
                "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
                "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
            ),
            (
                "md5:7d793037a0760186574b0282f2f435e7",
                "md5:5d41402abc4b2a76b9719d911017c592",
            ),
        ] {
            let record = declaring_digest(value);

            assert_eq!(
                record.incorrect_block_digest(),
                Some(BlockError::BlockDigestMismatch {
                    declared: Box::new(digest(value)),
                    actual: Box::new(digest(actual)),
                }),
                "{value}"
            );
        }
    }

    /// Invalid declared digests are readable but prevent rendering.
    #[test]
    fn a_record_declaring_a_digest_it_does_not_have_is_read_and_not_written() {
        // SHA-1 of an empty block.
        let of_nothing = "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";
        let record = declaring_digest(of_nothing);

        assert_eq!(record.body_bytes().as_ref(), DIGESTED_BLOCK);
        assert_eq!(
            record.into_raw(),
            Err(RenderError::Block(BlockError::BlockDigestMismatch {
                declared: Box::new(digest(of_nothing)),
                actual: Box::new(digest("sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N")),
            }))
        );

        let record = payload_record(
            "response",
            &[("WARC-Payload-Digest", of_nothing)],
            RESPONSE_BLOCK,
        );

        assert_eq!(record.body_bytes().as_ref(), RESPONSE_BLOCK);
        assert!(matches!(
            record.into_raw(),
            Err(RenderError::Block(BlockError::PayloadDigestMismatch { .. }))
        ));
    }

    /// Valid, absent, and unsupported digests do not report a failure.
    #[test]
    fn a_record_declaring_a_digest_it_has_reports_nothing() {
        for value in [
            "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
            "md5:5d41402abc4b2a76b9719d911017c592",
            "xxh3:1c330fb2d66be8b5",
            "blake3:not-a-digest",
        ] {
            let record = declaring_digest(value);

            assert_eq!(record.incorrect_block_digest(), None, "{value}");
            assert_eq!(record.incorrect_payload_digest(), None, "{value}");
        }

        let record = payload_record("response", &[], RESPONSE_BLOCK);

        assert_eq!(record.incorrect_block_digest(), None);
        assert_eq!(record.incorrect_payload_digest(), None);
    }

    /// Digests using unsupported algorithms are preserved without validation.
    #[test]
    fn a_block_digest_under_an_unknown_algorithm_is_not_checked() {
        for value in ["xxh3:1c330fb2d66be8b5", "blake3:not-a-digest"] {
            let raw = declaring_digest(value)
                .into_raw()
                .expect("renderable record");

            assert_eq!(
                written(&raw, "WARC-Block-Digest").as_deref(),
                Some(value),
                "{value}"
            );
        }
    }

    /// [`RESPONSE_BLOCK`] with a chunked entity-body.
    const CHUNKED_RESPONSE_BLOCK: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

    /// The default digest of the entity-body in the HTTP test blocks.
    const ADDED_PAYLOAD_DIGEST: &str =
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    /// Build a record with an HTTP target and the supplied fields and body.
    fn payload_record(record_type: &str, lines: &[(&str, &str)], body: &[u8]) -> Record {
        let mut all = vec![("WARC-Target-URI", "http://example.com/")];
        all.extend_from_slice(lines);

        lift_grammar(grammar_of(WarcVersion::V1_1, record_type, &all, body))
            .expect("liftable record")
    }

    /// Payload extraction follows WARC rules for each record type.
    #[test]
    fn the_payload_of_a_record_is_what_the_standard_says_it_is() {
        for (record_type, block, payload) in [
            ("response", RESPONSE_BLOCK, Some(DIGESTED_BLOCK)),
            ("response", CHUNKED_RESPONSE_BLOCK, Some(DIGESTED_BLOCK)),
            ("request", RESPONSE_BLOCK, Some(DIGESTED_BLOCK)),
            ("resource", DIGESTED_BLOCK, Some(DIGESTED_BLOCK)),
            ("conversion", DIGESTED_BLOCK, Some(DIGESTED_BLOCK)),
            ("metadata", DIGESTED_BLOCK, None),
        ] {
            let record = payload_record(record_type, &[], block);

            assert_eq!(
                record
                    .payload_bytes()
                    .expect("a block framing a payload")
                    .as_deref(),
                payload,
                "{record_type}"
            );
        }
    }

    /// Rendering adds payload digests to requests and responses, but not whole-block payloads.
    #[test]
    fn a_record_declaring_no_payload_digest_is_given_one() {
        for (record_type, block, digest) in [
            ("response", RESPONSE_BLOCK, Some(ADDED_PAYLOAD_DIGEST)),
            ("request", RESPONSE_BLOCK, Some(ADDED_PAYLOAD_DIGEST)),
            ("resource", DIGESTED_BLOCK, None),
        ] {
            let raw = payload_record(record_type, &[], block)
                .into_raw()
                .expect("renderable record");

            assert_eq!(
                written(&raw, "WARC-Payload-Digest").as_deref(),
                digest,
                "{record_type}"
            );
        }
    }

    /// Payload digests are checked against the payload rather than the enclosing block.
    #[test]
    fn a_payload_digest_the_payload_does_not_have_is_reported() {
        let malformed = "sha1:not-a-digest";
        let of_another_payload = "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";
        // SHA-1 of the entity-body, not the enclosing HTTP block.
        let of_the_payload = "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N";

        for (value, expected) in [
            (
                malformed,
                BlockError::MalformedPayloadDigest(Box::new(digest(malformed))),
            ),
            (
                of_another_payload,
                BlockError::PayloadDigestMismatch {
                    declared: Box::new(digest(of_another_payload)),
                    actual: Box::new(digest(of_the_payload)),
                },
            ),
        ] {
            let record = payload_record(
                "response",
                &[("WARC-Payload-Digest", value)],
                RESPONSE_BLOCK,
            );

            assert_eq!(record.incorrect_payload_digest(), Some(expected), "{value}");
        }
    }

    /// A declared digest makes an unparseable HTTP payload an error.
    #[test]
    fn a_payload_digest_over_a_block_framing_no_payload_is_reported() {
        let record = payload_record(
            "response",
            &[(
                "WARC-Payload-Digest",
                "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
            )],
            DIGESTED_BLOCK,
        );

        assert_eq!(
            record.incorrect_payload_digest(),
            Some(BlockError::Payload(payload::Error::UnterminatedHeaders))
        );

        let raw = payload_record("response", &[], DIGESTED_BLOCK)
            .into_raw()
            .expect("renderable record");

        assert_eq!(written(&raw, "WARC-Payload-Digest"), None);
    }

    /// Partial records preserve declared payload digests and do not receive new ones.
    #[test]
    fn the_payload_digest_of_a_partial_record_is_left_alone() {
        for line in [("WARC-Segment-Number", "1"), ("WARC-Truncated", "length")] {
            let declared = "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";
            let raw = payload_record(
                "response",
                &[line, ("WARC-Payload-Digest", declared)],
                RESPONSE_BLOCK,
            )
            .into_raw()
            .expect("renderable record");

            assert_eq!(
                written(&raw, "WARC-Payload-Digest").as_deref(),
                Some(declared),
                "{line:?}"
            );

            let raw = payload_record("response", &[line], RESPONSE_BLOCK)
                .into_raw()
                .expect("renderable record");

            assert_eq!(written(&raw, "WARC-Payload-Digest"), None, "{line:?}");
        }
    }

    /// A payload using an unsupported transfer-coding cannot be checked and is preserved.
    #[test]
    fn a_payload_digest_over_a_coding_this_crate_cannot_remove_is_not_checked() {
        let declared = "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";
        let block = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nhello";
        let raw = payload_record(
            "response",
            &[("WARC-Payload-Digest", declared)],
            block.as_slice(),
        )
        .into_raw()
        .expect("renderable record");

        assert_eq!(
            written(&raw, "WARC-Payload-Digest").as_deref(),
            Some(declared)
        );
    }

    /// Every record type keeps its block somewhere different, and the one accessor reads any
    /// of them: a block read as fields renders as the bytes it was read from, and one kept as
    /// read is handed out rather than copied.
    #[test]
    fn the_block_is_read_through_one_accessor() {
        let warcinfo = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "warcinfo",
            &[("Content-Type", "application/warc-fields")],
            WARCINFO_BLOCK,
        ))
        .expect("liftable record");
        assert_eq!(warcinfo.body_bytes().as_ref(), WARCINFO_BLOCK);
        assert_eq!(
            warcinfo.body_bytes().len() as u64,
            warcinfo.content_length()
        );

        let response = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "response",
            &[("WARC-Target-URI", "http://example.com/")],
            b"hello",
        ))
        .expect("liftable record");
        assert!(matches!(response.body_bytes(), Cow::Borrowed(b"hello")));
    }

    #[test]
    fn the_warc_fields_content_type_is_matched_by_media_type() {
        for content_type in [
            "application/warc-fields",
            "Application/WARC-Fields; charset=utf-8",
        ] {
            let record = lift_grammar(grammar_of(
                WarcVersion::V1_1,
                "warcinfo",
                &[("Content-Type", content_type)],
                WARCINFO_BLOCK,
            ))
            .expect("liftable record");
            assert!(
                matches!(
                    record,
                    Record::Warcinfo {
                        body: FieldsBlock::Fields(_),
                        ..
                    }
                ),
                "`{content_type}` was not read as fields"
            );
        }

        let record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "warcinfo",
            &[("Content-Type", "application/json")],
            b"{}",
        ))
        .expect("liftable record");
        let Record::Warcinfo { body, .. } = record else {
            panic!("not a warcinfo");
        };
        assert_eq!(body, FieldsBlock::Raw(b"{}".to_vec()));
    }

    #[test]
    fn a_malformed_warc_fields_body_is_an_error() {
        let record = Record::<NoExtension>::try_from(grammar_of(
            WarcVersion::V1_1,
            "warcinfo",
            &[("Content-Type", "application/warc-fields")],
            b"not a field\r\n",
        ));
        assert_eq!(
            record,
            Err(Error::Block(BlockError::Fields(
                fields::Error::NotANamedField { offset: 0 }
            )))
        );
    }

    /// A URI is held as the URI it names, and written back in the brackets the declared
    /// version calls for: WARC 1.0 brackets every one of them, and WARC 1.1 only the five
    /// whose value is a record identifier.
    #[test]
    fn a_uri_is_written_bracketed_as_the_version_requires() {
        let mut record = lift_grammar(grammar_of(
            WarcVersion::V1_0,
            "request",
            &[
                ("WARC-Target-URI", "<http://example.com/>"),
                ("WARC-Warcinfo-ID", "<urn:uuid:warcinfo>"),
            ],
            b"",
        ))
        .expect("liftable record");

        let Record::Request { header, .. } = &record else {
            panic!("not a request");
        };
        assert_eq!(header.target_uri, "http://example.com/");

        // The record was read as a WARC 1.0 record and says so, so it is written as one
        // without being told.
        assert_eq!(record.version(), WarcVersion::V1_0);
        let raw = record.clone().into_raw().expect("renderable record");
        assert_eq!(raw.header.version, WarcVersion::V1_0);
        assert_eq!(
            written(&raw, "WARC-Target-URI").as_deref(),
            Some("<http://example.com/>")
        );
        assert_eq!(
            written(&raw, "WARC-Warcinfo-ID").as_deref(),
            Some("<urn:uuid:warcinfo>")
        );

        // Writing it as the other version is a change to what the record declares.
        *record.version_mut() = WarcVersion::V1_1;
        let raw = record.into_raw().expect("renderable record");
        assert_eq!(
            written(&raw, "WARC-Target-URI").as_deref(),
            Some("http://example.com/")
        );
        // A record identifier keeps its brackets under either version.
        assert_eq!(
            written(&raw, "WARC-Warcinfo-ID").as_deref(),
            Some("<urn:uuid:warcinfo>")
        );
    }

    /// A profile URI in angle brackets names the profile it spells, rather than reading as one
    /// the standard does not define, and carries that profile's requirements with it.
    #[test]
    fn a_bracketed_profile_names_the_profile_it_spells() {
        let profile = RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_0);
        let bracketed = format!("<{}>", profile.as_str());
        let record = lift_grammar(grammar_of(
            WarcVersion::V1_0,
            "revisit",
            &[
                ("WARC-Target-URI", "<http://example.com/>"),
                ("WARC-Profile", bracketed.as_str()),
                ("WARC-Payload-Digest", "sha1:AAAA"),
            ],
            b"",
        ))
        .expect("liftable record");

        let Record::Revisit { header, .. } = &record else {
            panic!("not a revisit");
        };
        assert_eq!(header.profile, profile);

        let raw = record.into_raw().expect("renderable record");
        assert_eq!(
            written(&raw, "WARC-Profile").as_deref(),
            Some(bracketed.as_str())
        );
    }

    #[test]
    fn a_field_the_type_does_not_permit_is_an_error() {
        assert_eq!(
            lift(
                "response",
                &[
                    ("WARC-Target-URI", "http://example.com/"),
                    ("WARC-Filename", "example.warc"),
                ]
            ),
            Err(Error::ForbiddenField {
                record_type: "response",
                field: Field::Filename,
            })
        );
    }

    #[test]
    fn a_missing_mandatory_field_is_an_error() {
        assert_eq!(
            lift("response", &[]),
            Err(Error::MissingField(Field::TargetURI))
        );
    }

    /// The standard names one repeatable field, so any other field written twice is a record
    /// that says two things where it may say one. The grammar keeps both lines, and this is
    /// where they are refused.
    #[test]
    fn a_repeated_field_is_an_error() {
        assert_eq!(
            lift(
                "response",
                &[
                    ("WARC-Target-URI", "http://example.com/first"),
                    ("WARC-Target-URI", "http://example.com/second"),
                ]
            ),
            Err(Error::RepeatedField(Field::TargetURI))
        );

        // The one field that may repeat does, and is lifted in the order it was written.
        let record = lift(
            "response",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Concurrent-To", "<urn:uuid:first>"),
                ("WARC-Concurrent-To", "<urn:uuid:second>"),
            ],
        )
        .expect("liftable record");
        assert_eq!(
            record.concurrent_to(),
            ["urn:uuid:first", "urn:uuid:second"]
        );
    }

    /// WARC 1.0 gives a date one spelling. The grammar reads every precision WARC 1.1 defines
    /// whatever the record declares, so a record declaring 1.0 and carrying a 1.1 date is
    /// refused here.
    #[test]
    fn a_warc_1_0_date_is_held_to_the_second() {
        let sub_second = "2020-07-08T02:52:55.123456Z";
        let mut lines = vec![
            ("WARC-Type", "resource"),
            ("WARC-Record-ID", "<urn:uuid:a>"),
        ];
        lines.push(("WARC-Date", sub_second));
        lines.push(("WARC-Target-URI", "<http://example.com/>"));
        let grammar =
            untyped::Record::try_from(crate::io::test_record(WarcVersion::V1_0, &lines, b""))
                .expect("readable record");

        assert_eq!(
            Record::<NoExtension>::try_from(grammar),
            Err(Error::MalformedField {
                field: Field::Date,
                value: sub_second.to_owned(),
            })
        );
    }

    /// WARC 1.1 names two fields WARC 1.0 does not, and the grammar reads both whatever version
    /// a record declares. A record declaring 1.0 and carrying one of them is refused here, where
    /// the version it declares is what its fields are read against, rather than only when it is
    /// written back out.
    #[test]
    fn a_warc_1_0_record_refuses_a_field_only_warc_1_1_names() {
        for (field, value) in [
            (Field::RefersToDate, "2019-01-01T00:00:00Z"),
            (Field::RefersToTargetURI, "<http://example.com/original>"),
        ] {
            let lines = [
                ("WARC-Type", "revisit"),
                ("WARC-Record-ID", "<urn:uuid:a>"),
                ("WARC-Date", DATE),
                ("WARC-Target-URI", "<http://example.com/>"),
                (
                    "WARC-Profile",
                    "<http://netpreserve.org/warc/1.0/revisit/server-not-modified>",
                ),
                (field.standard_name(), value),
            ];
            let grammar =
                untyped::Record::try_from(crate::io::test_record(WarcVersion::V1_0, &lines, b""))
                    .expect("readable record");

            assert_eq!(
                Record::<NoExtension>::try_from(grammar),
                Err(Error::FieldNotInVersion {
                    field,
                    version: WarcVersion::V1_0,
                })
            );
        }
    }

    #[test]
    fn unrecognized_fields_are_kept_as_read_in_order() {
        let record = lift(
            "resource",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("X-First", "one"),
                ("x-second", "two"),
            ],
        )
        .expect("liftable record");
        assert_eq!(
            record.core().unrecognized,
            [
                ("X-First".to_owned(), "one".to_owned()),
                ("x-second".to_owned(), "two".to_owned()),
            ]
        );

        let raw = record.into_raw().expect("renderable record");
        assert_eq!(
            written_names(&raw),
            [
                "WARC-Type",
                "WARC-Target-URI",
                "WARC-Date",
                "WARC-Record-ID",
                "WARC-Block-Digest",
                "Content-Length",
                "X-First",
                "x-second",
            ]
        );
    }

    /// A record is written in the conventional order and the standard's own spelling, whatever
    /// order and spelling it was read with, since a record here holds what it says rather than
    /// how it was written.
    #[test]
    fn a_record_is_written_in_the_conventional_order() {
        let grammar = untyped::Record::try_from(crate::io::test_record(
            WarcVersion::V1_1,
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("warc-type", "resource"),
                ("WaRc-DaTe", DATE),
                ("WARC-RECORD-ID", "<urn:uuid:a>"),
            ],
            b"",
        ))
        .expect("readable record");

        let raw = Record::<NoExtension>::try_from(grammar)
            .expect("liftable record")
            .into_raw()
            .expect("renderable record");

        assert_eq!(
            written_names(&raw),
            [
                "WARC-Type",
                "WARC-Target-URI",
                "WARC-Date",
                "WARC-Record-ID",
                "WARC-Block-Digest",
                "Content-Length",
            ]
        );
    }

    /// `TEXT` admits any octet, and the name of the file a `warcinfo` record describes is not
    /// necessarily valid UTF-8, so a name is written back as the octets it was read as. The
    /// quoted spelling is rendered as it was read too, since the quotes are the grammar's and
    /// not the name's.
    #[test]
    fn a_file_name_is_written_as_the_octets_it_was_read_as() {
        for (spelled, name) in [
            (b" caf\xe9.warc".as_slice(), b"caf\xe9.warc".as_slice()),
            (
                b" \"caf\xe9 archive.warc\"".as_slice(),
                b"caf\xe9 archive.warc".as_slice(),
            ),
        ] {
            let raw = raw::RecordHeader {
                version: WarcVersion::V1_1,
                headers: vec![
                    ("WARC-Type".to_owned(), b" warcinfo".to_vec()),
                    (
                        "WARC-Record-ID".to_owned(),
                        format!(" <{RECORD_ID}>").into_bytes(),
                    ),
                    ("WARC-Date".to_owned(), format!(" {DATE}").into_bytes()),
                    ("WARC-Filename".to_owned(), spelled.to_vec()),
                    ("Content-Length".to_owned(), b" 0".to_vec()),
                ],
            }
            .with_body(Vec::new());
            let grammar = untyped::Record::try_from(raw).expect("readable record");
            let record = Record::<NoExtension>::try_from(grammar).expect("liftable record");

            let Record::Warcinfo { header, .. } = &record else {
                panic!("not a warcinfo");
            };
            assert_eq!(header.filename.as_ref().map(Text::as_bytes), Some(name));

            let written = record.into_raw().expect("renderable record");
            assert_eq!(written.header.get("WARC-Filename"), Some(spelled));
        }
    }

    /// A field kept as read is written under the name it carries, so a record given a name or a
    /// value the header grammar does not admit is rejected where it is rendered, rather than
    /// reaching the writer and failing there as an I/O error.
    #[test]
    fn a_field_kept_as_read_is_checked_when_it_is_rendered() {
        for (name, value, reason) in [
            ("X Spaces", "one", "the name is not a token"),
            (
                "X-Break",
                "one\r\nWARC-Type: response",
                "the value holds a line break",
            ),
        ] {
            let mut record = lift("resource", &[("WARC-Target-URI", "http://example.com/")])
                .expect("liftable record");
            record
                .core_mut()
                .unrecognized
                .push((name.to_owned(), value.to_owned()));

            assert_eq!(
                record.into_raw(),
                Err(RenderError::UnwritableField {
                    name: name.to_owned(),
                    reason: reason.to_owned(),
                })
            );
        }
    }

    /// A field kept as read under the name of a field the standard names is the field it names,
    /// and a record of a type the standard defines writes that field from its own header, so it
    /// is refused here whether or not the record has anything else to say for it.
    #[test]
    fn a_field_kept_as_read_cannot_name_a_standard_field() {
        for (name, value, field) in [
            (
                "WARC-Refers-To-Date",
                "2019-01-01T00:00:00Z",
                Field::RefersToDate,
            ),
            (
                "WARC-Target-URI",
                "http://example.com/other",
                Field::TargetURI,
            ),
            // A name is the field it names however it is spelled.
            (
                "warc-target-uri",
                "http://example.com/other",
                Field::TargetURI,
            ),
        ] {
            let mut record = lift("resource", &[("WARC-Target-URI", "http://example.com/")])
                .expect("liftable record");
            record
                .core_mut()
                .unrecognized
                .push((name.to_owned(), value.to_owned()));

            assert_eq!(
                record.into_raw(),
                Err(RenderError::ReservedField(field)),
                "{name}"
            );
        }
    }

    /// A record of a type no version of the standard defines carries what fields it likes, so a
    /// standard name is kept as read there and is held to the version the record renders under
    /// just as a typed field is.
    #[test]
    fn a_field_kept_as_read_is_the_field_it_names() {
        let mut record = Record::<Sitemaps>::try_from(grammar(
            "sitemap",
            &[("WARC-Refers-To-Date", "2019-01-01T00:00:00Z")],
        ))
        .expect("liftable record");
        assert_survives_rendering(&record);

        *record.version_mut() = WarcVersion::V1_0;
        assert_eq!(
            record.into_raw(),
            Err(RenderError::FieldNotInVersion {
                field: Field::RefersToDate,
                version: WarcVersion::V1_0,
            })
        );
    }

    /// A record of a type no version of the standard defines keeps every field as read, so it is
    /// the one record that can come to say a field the standard defines twice.
    #[test]
    fn a_record_of_an_extension_type_cannot_repeat_a_standard_field() {
        let mut record =
            Record::<Sitemaps>::try_from(grammar("sitemap", &[])).expect("liftable record");
        record.core_mut().unrecognized.extend([
            (
                "WARC-Target-URI".to_owned(),
                "http://example.com/".to_owned(),
            ),
            (
                "WARC-Target-URI".to_owned(),
                "http://example.com/other".to_owned(),
            ),
        ]);

        assert_eq!(
            record.into_raw(),
            Err(RenderError::RepeatedField(Field::TargetURI))
        );
    }

    /// Assert that a record either refuses to render or reads back as the record it was.
    ///
    /// This is the whole of what the checks applied while lifting and the checks applied while
    /// rendering have to agree on. A record that renders into something no reader accepts, or
    /// into something a reader accepts as a different record, is one they disagree about.
    fn assert_survives_rendering<E: Extension>(record: &Record<E>) {
        let Ok(raw) = record.clone().into_raw() else {
            return;
        };
        let grammar = untyped::Record::try_from(raw).expect("a rendered record is grammatical");

        assert_eq!(
            Record::<E>::try_from(grammar).ok(),
            Some(as_rendered(record.clone()))
        );
    }

    /// Records read from an archive and then edited through their public fields, which is the
    /// one way a record comes to say something no record read from an archive says.
    fn edited_records() -> Vec<Record> {
        let target = ("WARC-Target-URI", "http://example.com/");

        let mut response = lift("response", &[target]).expect("liftable record");
        response.core_mut().content_type = MediaType::parse(b"application/http").ok();
        response
            .core_mut()
            .unrecognized
            .push(("X-Kept".to_owned(), "as read".to_owned()));
        let Record::Response { header, .. } = &mut response else {
            panic!("not a response");
        };
        header.concurrent_to.push(uri("urn:uuid:request"));
        header.segment_origin = true;

        // A record declaring WARC 1.0 writes its URI-valued fields bracketed, and carries a date
        // at the one precision that version spells.
        let mut resource = lift("resource", &[target]).expect("liftable record");
        *resource.version_mut() = WarcVersion::V1_0;

        let mut warcinfo = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "warcinfo",
            &[("Content-Type", "application/warc-fields")],
            WARCINFO_BLOCK,
        ))
        .expect("liftable record");
        let Record::Warcinfo {
            body: FieldsBlock::Fields(fields),
            ..
        } = &mut warcinfo
        else {
            panic!("not a warcinfo read as fields");
        };
        fields
            .push(WarcinfoField::Hostname, "crawler.example.com")
            .expect("a writable field");
        let length = warcinfo.content_length();
        warcinfo.core_mut().content_length = Some(length);

        let mut revisit = lift(
            "revisit",
            &[
                target,
                (
                    "WARC-Profile",
                    RevisitProfile::ServerNotModified(WarcVersion::V1_1).as_str(),
                ),
            ],
        )
        .expect("liftable record");
        let Record::Revisit { header, .. } = &mut revisit else {
            panic!("not a revisit");
        };
        header.refers_to_date = WarcDate::parse("2019-01-01T00:00:00.5Z", WarcVersion::V1_1);

        let continuation = lift(
            "continuation",
            &[
                target,
                ("WARC-Segment-Number", "2"),
                ("WARC-Segment-Origin-ID", "<urn:uuid:origin>"),
                ("WARC-Segment-Total-Length", "1024"),
            ],
        )
        .expect("liftable record");

        vec![response, resource, warcinfo, revisit, continuation]
    }

    /// A record renders only as itself: whatever it was edited to say, writing it and reading it
    /// back gives the record that was written.
    #[test]
    fn a_rendered_record_reads_back_as_itself() {
        for record in edited_records() {
            assert_survives_rendering(&record);
        }

        // A record of a type no version of the standard defines is under no constraint about
        // which fields it carries, so it keeps standard names as read and writes them back.
        let sitemap = Record::<Sitemaps>::try_from(grammar(
            "sitemap",
            &[("WARC-Target-URI", "http://example.com/")],
        ))
        .expect("liftable record");
        assert_eq!(sitemap.core().unrecognized.len(), 1);
        assert_survives_rendering(&sitemap);
    }

    /// WARC 1.0 spells a date one way, so a record declaring that version cannot carry a date at
    /// a precision only WARC 1.1 spells: writing it would drop what its extra digits say.
    #[test]
    fn a_date_the_declared_version_cannot_spell_is_not_written() {
        let mut record = lift("response", &[("WARC-Target-URI", "http://example.com/")])
            .expect("liftable record");
        record.core_mut().date =
            WarcDate::parse("2020-07-08T02:52:55.123456Z", WarcVersion::V1_1).expect("a date");
        *record.version_mut() = WarcVersion::V1_0;

        assert_eq!(
            record.into_raw(),
            Err(RenderError::ValueNotInVersion {
                field: Field::Date,
                version: WarcVersion::V1_0,
                value: "2020-07-08T02:52:55.123456Z".to_owned(),
            })
        );
    }

    /// A series is numbered from the origin record's `1`, so a `continuation` numbered below `2`
    /// claims a position that is not a continuation of anything, which is a number the type its
    /// header holds it as does not have.
    #[test]
    fn a_number_below_two_is_not_a_segment_number() {
        assert_eq!(SegmentNumber::new(0), None);
        assert_eq!(SegmentNumber::new(1), None);
        assert_eq!(SegmentNumber::new(2).map(SegmentNumber::get), Some(2));
    }

    #[test]
    fn a_record_type_no_vocabulary_defines_cannot_be_lifted() {
        assert_eq!(
            lift("sitemap", &[]),
            Err(Error::UnknownRecordType("sitemap".to_owned()))
        );
    }

    #[test]
    fn an_extension_defines_record_types_the_standard_does_not_constrain() {
        let record = Record::<Sitemaps>::try_from(grammar(
            "sitemap",
            &[("WARC-Target-URI", "http://example.com/sitemap.xml")],
        ))
        .expect("liftable record");

        let Record::Other { header, .. } = &record else {
            panic!("not an extension record");
        };
        assert_eq!(header.extension, SitemapType::Sitemap);
        // A type the standard does not define is one it does not constrain, so the known
        // field is preserved rather than rejected.
        assert_eq!(
            header.core.unrecognized,
            [(
                "WARC-Target-URI".to_owned(),
                "http://example.com/sitemap.xml".to_owned(),
            )]
        );
        assert_eq!(record.type_name(), "Sitemap");
    }

    /// A record of an extension type is written under the name its type gives itself, rather
    /// than under that name read back through the eight the standard defines, which would
    /// lower-case it.
    #[test]
    fn an_extension_record_type_keeps_its_own_spelling() {
        let raw = Record::<Sitemaps>::try_from(grammar("sitemap", &[]))
            .expect("liftable record")
            .into_raw()
            .expect("renderable record");

        assert_eq!(written(&raw, "WARC-Type").as_deref(), Some("Sitemap"));
    }

    /// An extension may not redefine the types the standard defines, so a type that names one
    /// of them is refused as it is read rather than being written back as a standard record.
    #[test]
    fn an_extension_type_naming_a_standard_type_is_refused() {
        assert_eq!(
            Record::<Sitemaps>::try_from(grammar("impostor", &[])),
            Err(Error::RedefinedRecordType("response".to_owned()))
        );
    }

    #[test]
    fn an_extension_claims_its_fields_and_writes_them_back() {
        let record = Record::<Sitemaps>::try_from(grammar(
            "warcinfo",
            &[("x-crawl-id", "crawl-7"), ("x-other", "kept")],
        ))
        .expect("liftable record");

        let Record::Warcinfo { header, .. } = &record else {
            panic!("not a warcinfo");
        };
        assert_eq!(
            header.other,
            CrawlFields {
                crawl_id: Some("crawl-7".to_owned()),
            }
        );
        assert_eq!(
            header.core.unrecognized,
            [("x-other".to_owned(), "kept".to_owned())]
        );

        let raw = record.into_raw().expect("renderable record");
        assert_eq!(written(&raw, "x-crawl-id").as_deref(), Some("crawl-7"));
        assert_eq!(written(&raw, "x-other").as_deref(), Some("kept"));
    }

    /// What an extension writes is held to the same rule as a field kept as read, whether it
    /// names a field the record already carries or one its type is forbidden.
    #[test]
    fn an_extension_cannot_name_a_field_the_standard_defines() {
        let record =
            Record::<Impersonating>::try_from(grammar("warcinfo", &[])).expect("liftable record");
        assert_eq!(
            record.into_raw(),
            Err(RenderError::ReservedField(Field::RecordID))
        );

        let record =
            Record::<Renaming>::try_from(grammar("warcinfo", &[])).expect("liftable record");
        assert_eq!(
            record.into_raw(),
            Err(RenderError::ReservedField(Field::Filename))
        );
    }

    #[test]
    fn a_truncation_reason_the_extension_defines_is_lifted() {
        let record = Record::<Sitemaps>::try_from(grammar(
            "resource",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Truncated", "robots"),
            ],
        ))
        .expect("liftable record");
        assert_eq!(
            record.core().truncated,
            Some(TruncatedType::Extension(Refused::Robots))
        );

        let raw = record.into_raw().expect("renderable record");
        assert_eq!(written(&raw, "WARC-Truncated").as_deref(), Some("robots"));
    }

    #[test]
    fn a_revisit_lifts_its_profile_and_references() {
        let mut record = lift(
            "revisit",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                (
                    "WARC-Profile",
                    "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
                ),
                ("WARC-Refers-To", "<urn:uuid:original>"),
                ("WARC-Refers-To-Date", "2019-01-01T00:00:00Z"),
                ("WARC-Payload-Digest", "sha1:AAAA"),
            ],
        )
        .expect("liftable record");

        let Record::Revisit { header, .. } = &record else {
            panic!("not a revisit");
        };
        assert_eq!(
            header.profile,
            RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_1)
        );
        assert_eq!(
            header.refers_to.as_ref().map(Uri::as_str),
            Some("urn:uuid:original")
        );
        assert_eq!(
            header.refers_to_date,
            WarcDate::parse("2019-01-01T00:00:00Z", WarcVersion::V1_1)
        );

        // The reference fields are new in WARC 1.1, so the record cannot render under 1.0.
        *record.version_mut() = WarcVersion::V1_0;
        assert_eq!(
            record.into_raw(),
            Err(RenderError::FieldNotInVersion {
                field: Field::RefersToDate,
                version: WarcVersion::V1_0,
            })
        );
    }

    /// The digest is what the identical-payload-digest profile asserts, so a record naming
    /// that profile without one is rejected, under either version's spelling of the URI.
    #[test]
    fn an_identical_payload_digest_revisit_carries_the_digest() {
        for version in [WarcVersion::V1_0, WarcVersion::V1_1] {
            let profile = RevisitProfile::IdenticalPayloadDigest(version);
            assert_eq!(
                lift(
                    "revisit",
                    &[
                        ("WARC-Target-URI", "http://example.com/"),
                        ("WARC-Profile", profile.as_str()),
                        ("WARC-Refers-To", "<urn:uuid:original>"),
                    ]
                ),
                Err(Error::MissingField(Field::PayloadDigest))
            );
        }
    }

    /// A record read with the digest and then stripped of it is not written, since a record this
    /// crate writes is one it reads back, and the header fields are the caller's to edit.
    #[test]
    fn an_identical_payload_digest_revisit_without_the_digest_is_not_written() {
        for version in [WarcVersion::V1_0, WarcVersion::V1_1] {
            let mut record = lift(
                "revisit",
                &[
                    ("WARC-Target-URI", "http://example.com/"),
                    (
                        "WARC-Profile",
                        RevisitProfile::IdenticalPayloadDigest(version).as_str(),
                    ),
                    ("WARC-Payload-Digest", "sha1:AAAA"),
                ],
            )
            .expect("liftable record");

            let Record::Revisit { header, .. } = &mut record else {
                panic!("not a revisit");
            };
            header.payload.payload_digest = None;

            assert_eq!(
                record.into_raw(),
                Err(RenderError::MissingProfileField(Field::PayloadDigest))
            );
        }
    }

    /// A `revisit` record under the identical payload digest profile, carrying the digest that
    /// profile requires and whatever else the test adds to it.
    fn identical_payload_digest_revisit(lines: &[(&str, &str)], body: &[u8]) -> untyped::Record {
        let mut all = vec![
            ("WARC-Target-URI", "http://example.com/"),
            (
                "WARC-Profile",
                "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
            ),
            ("WARC-Payload-Digest", "sha1:AAAA"),
        ];
        all.extend_from_slice(lines);

        grammar_of(WarcVersion::V1_1, "revisit", &all, body)
    }

    /// A block under this profile is the beginning of the response the record stands for, so a
    /// record carrying one and not saying it is truncated is not read.
    #[test]
    fn an_identical_payload_digest_revisit_declares_the_truncation_its_block_is() {
        let refused = lift_grammar(identical_payload_digest_revisit(&[], b"HTTP/1.1 200 OK"));

        assert_eq!(
            refused,
            Err(Error::Block(BlockError::UndeclaredRevisitTruncation(15)))
        );

        // Another reason says the block is something other than the truncation this profile
        // has it be.
        let refused = lift_grammar(identical_payload_digest_revisit(
            &[("WARC-Truncated", "time")],
            b"HTTP/1.1 200 OK",
        ));

        assert_eq!(
            refused,
            Err(Error::Block(BlockError::UndeclaredRevisitTruncation(15)))
        );
    }

    /// A record that declares the truncation, and one that carries no block at all, are both
    /// what the profile describes.
    #[test]
    fn an_identical_payload_digest_revisit_carries_a_truncated_block_or_none() {
        for (lines, body) in [
            (&[("WARC-Truncated", "length")][..], &b"HTTP/1.1 200 OK"[..]),
            (&[], b""),
        ] {
            let record = lift_grammar(identical_payload_digest_revisit(lines, body))
                .expect("liftable record");

            assert_survives_rendering(&record);
            assert!(record.into_raw().is_ok());
        }
    }

    /// A record read with the truncation and then stripped of it is not written, for the same
    /// reason it would not be read.
    #[test]
    fn a_revisit_stripped_of_its_truncation_is_not_written() {
        let mut record = lift_grammar(identical_payload_digest_revisit(
            &[("WARC-Truncated", "length")],
            b"HTTP/1.1 200 OK",
        ))
        .expect("liftable record");
        record.core_mut().truncated = None;

        assert_eq!(
            record.into_raw(),
            Err(RenderError::Block(BlockError::UndeclaredRevisitTruncation(
                15
            )))
        );
    }

    /// A record under another profile carries whatever block it was written with, since the
    /// truncation rule belongs to the profile that has the block stand for a response.
    #[test]
    fn a_revisit_under_another_profile_carries_any_block() {
        let record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "revisit",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                (
                    "WARC-Profile",
                    "http://netpreserve.org/warc/0.18/revisit/identical-payload-digest",
                ),
            ],
            b"HTTP/1.1 200 OK",
        ))
        .expect("liftable record");

        assert_survives_rendering(&record);
        assert!(record.into_raw().is_ok());
    }

    /// A record under another profile is written without a digest, since no rule here asks one
    /// of it.
    #[test]
    fn a_revisit_under_another_profile_is_written_without_a_digest() {
        let record = lift(
            "revisit",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                (
                    "WARC-Profile",
                    RevisitProfile::ServerNotModified(WarcVersion::V1_1).as_str(),
                ),
            ],
        )
        .expect("liftable record");

        assert_survives_rendering(&record);
        assert!(record.into_raw().is_ok());
    }

    /// No other profile carries the requirement: the server's assertion stands on its own,
    /// and a profile the standard does not define is not this crate's to interpret.
    #[test]
    fn another_profile_needs_no_digest() {
        for profile in [
            RevisitProfile::ServerNotModified(WarcVersion::V1_1).as_str(),
            "http://netpreserve.org/warc/0.18/revisit/identical-payload-digest",
        ] {
            lift(
                "revisit",
                &[
                    ("WARC-Target-URI", "http://example.com/"),
                    ("WARC-Profile", profile),
                ],
            )
            .expect("liftable record");
        }
    }

    #[test]
    fn segment_fields_lift_for_origins_and_continuations() {
        let record = lift(
            "response",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Segment-Number", "1"),
            ],
        )
        .expect("liftable record");
        let Record::Response { header, .. } = record else {
            panic!("not a response");
        };
        assert!(header.segment_origin);

        let record = lift(
            "continuation",
            &[
                ("WARC-Target-URI", "http://example.com/"),
                ("WARC-Segment-Number", "2"),
                ("WARC-Segment-Origin-ID", "<urn:uuid:origin>"),
                ("WARC-Segment-Total-Length", "1024"),
            ],
        )
        .expect("liftable record");
        let Record::Continuation { header, .. } = record else {
            panic!("not a continuation");
        };
        assert_eq!(header.segment_number.get(), 2);
        assert_eq!(header.segment_origin_id, "urn:uuid:origin");
        assert_eq!(header.segment_total_length, Some(1024));

        // On a record that is not a continuation the field can only mark the origin.
        assert_eq!(
            lift(
                "response",
                &[
                    ("WARC-Target-URI", "http://example.com/"),
                    ("WARC-Segment-Number", "2"),
                ]
            ),
            Err(Error::MalformedField {
                field: Field::SegmentNumber,
                value: "2".to_owned(),
            })
        );
    }

    /// A series is numbered from the origin record's `1`, so a `continuation` numbering
    /// itself `0` or `1` claims a position that is not a continuation of anything.
    #[test]
    fn a_continuation_numbers_itself_from_two() {
        for value in ["0", "1"] {
            assert_eq!(
                lift(
                    "continuation",
                    &[
                        ("WARC-Target-URI", "http://example.com/"),
                        ("WARC-Segment-Number", value),
                        ("WARC-Segment-Origin-ID", "<urn:uuid:origin>"),
                    ]
                ),
                Err(Error::MalformedField {
                    field: Field::SegmentNumber,
                    value: value.to_owned(),
                })
            );
        }
    }

    #[test]
    fn a_metadata_body_reads_as_its_fields() {
        let record = lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "metadata",
            &[
                ("Content-Type", "application/warc-fields"),
                ("WARC-Refers-To", "<urn:uuid:original>"),
            ],
            b"via: http://example.com/\r\n",
        ))
        .expect("liftable record");

        let Record::Metadata { header, body } = record else {
            panic!("not a metadata record");
        };
        assert_eq!(
            header.refers_to.as_ref().map(Uri::as_str),
            Some("urn:uuid:original")
        );
        let FieldsBlock::Fields(fields) = body else {
            panic!("not read as fields");
        };
        assert_eq!(fields.via(), Some("http://example.com/"));
    }

    /// A URI for a record built here rather than lifted from an archive.
    fn uri(value: &str) -> Uri<String> {
        Uri::parse(value).expect("well-formed URI").to_owned()
    }

    /// The fields every record carries, for a record built here rather than lifted from one.
    fn core() -> CoreHeaders {
        CoreHeaders {
            record_id: uri(RECORD_ID),
            date: WarcDate::parse(DATE, WarcVersion::V1_1).expect("well-formed date"),
            content_length: None,
            block_digest: None,
            content_type: MediaType::parse(b"application/http; msgtype=response").ok(),
            truncated: None,
            unrecognized: Vec::new(),
        }
    }

    /// A `response` record carrying one of each field its type permits.
    fn response() -> Record {
        Record::Response {
            header: ResponseHeader {
                version: WarcVersion::V1_1,
                core: core(),
                payload: PayloadHeaders::default(),
                target_uri: uri("http://example.com/"),
                warcinfo_id: Some(uri("urn:uuid:warcinfo")),
                ip_address: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                concurrent_to: vec![uri("urn:uuid:request")],
                segment_origin: false,
                other: (),
            },
            body: Vec::new(),
        }
    }

    /// A `warcinfo` record, the type forbidden the most of the cross-type fields.
    fn warcinfo() -> Record {
        Record::Warcinfo {
            header: WarcinfoHeader {
                version: WarcVersion::V1_1,
                core: core(),
                filename: Text::parse(b"example.warc.gz").ok(),
                segment_origin: false,
                other: (),
            },
            body: FieldsBlock::Raw(Vec::new()),
        }
    }

    /// A record type's name is its variant, not a field, so every variant reports one.
    #[test]
    fn each_record_type_names_itself() {
        assert_eq!(response().type_name(), "response");
        assert_eq!(warcinfo().type_name(), "warcinfo");
    }

    /// The accessors read the fields a variant carries and report nothing for the fields the
    /// standard forbids its record type.
    #[test]
    fn accessors_report_only_the_permitted_fields() {
        let response = response();
        assert_eq!(
            response.target_uri().map(Uri::as_str),
            Some("http://example.com/")
        );
        assert_eq!(
            response.warcinfo_id().map(Uri::as_str),
            Some("urn:uuid:warcinfo")
        );
        assert_eq!(response.concurrent_to(), ["urn:uuid:request"]);
        assert!(response.payload().is_some());
        // A `response` record is forbidden `WARC-Refers-To`.
        assert!(response.refers_to().is_none());

        // A `warcinfo` record is forbidden a target URI, an address, and a capture event, and
        // has no payload to describe.
        let warcinfo = warcinfo();
        assert!(warcinfo.target_uri().is_none());
        assert!(warcinfo.ip_address().is_none());
        assert!(warcinfo.concurrent_to().is_empty());
        assert!(warcinfo.payload().is_none());
    }

    /// The origin of a series and its continuations report their segment number through the
    /// one accessor, however the header stores it.
    #[test]
    fn segment_number_reads_both_spellings() {
        assert_eq!(response().segment_number(), None);

        let Record::Response { header, body } = response() else {
            unreachable!("built as a response")
        };
        let target_uri = header.target_uri.clone();
        let origin = Record::Response {
            header: ResponseHeader {
                segment_origin: true,
                ..header
            },
            body,
        };
        assert_eq!(origin.segment_number(), Some(1));

        let continuation = Record::Continuation {
            header: ContinuationHeader {
                version: WarcVersion::V1_1,
                core: core(),
                payload: PayloadHeaders::default(),
                target_uri,
                warcinfo_id: None,
                segment_number: SegmentNumber::new(2).expect("a segment number"),
                segment_origin_id: uri("urn:uuid:origin"),
                segment_total_length: Some(1024),
                other: (),
            },
            body: Vec::new(),
        };
        assert_eq!(continuation.segment_number(), Some(2));
    }
}
