//! A semantic representation of WARC records.
//!
//! [`Record`] pairs each record type with its corresponding [`header`] and content block.
//! [`TryFrom`] converts an [`untyped::Record`] by checking its fields against the declared version
//! and record type. [`Record::into_raw`] converts it back to a [`raw::Record`]. [`RecordHeader`]
//! provides the same validation without reading a content block.
//!
//! This representation is strict, and some real archives do not conform. The `warcinfo` records
//! wpull writes, for example, carry `WARC-Warcinfo-ID`, which clause 5.16 of the WARC 1.1 standard
//! permits on every record type but that one, and are refused here. Records declaring WARC 1.0 are
//! also refused if they carry either field added in WARC 1.1. Read uncertain input as
//! [`raw::Record`] first, then convert records when semantic validation is needed.
//!
//! Semantic records preserve values, but normalize header order, field spelling, white space, and
//! URI brackets when rendered. A declared `Content-Length` is checked whenever a header and body
//! are paired, and again when the record is rendered.
//!
//! Declared digests are preserved when a record is read. Use [`Record::incorrect_block_digest`] and
//! [`Record::incorrect_payload_digest`] to inspect them. Rendering validates declared digests.
//! [`Record::into_raw_with_digests`] and [`Record::into_raw_with_digests_in`] add the digests a
//! record does not declare.
//!
//! Payload digests follow WARC 1.1 clause 5.9. For `application/http`, this means the HTTP
//! entity-body after transfer-coding has been removed. Some widely used tools digest the message
//! body instead, so their chunked records read but cannot be rendered.
//!
//! Use [`builder`] to create new records.

pub mod builder;
pub mod capture;
mod digest;
pub mod extension;
pub mod fields;
pub mod header;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod http;
#[cfg(feature = "payload-identification")]
#[cfg_attr(docsrs, doc(cfg(feature = "payload-identification")))]
pub mod identify;
mod lift;
pub mod payload;
pub mod record_type;
mod render;

use std::borrow::Cow;
use std::net::IpAddr;

use fluent_uri::Uri;
use fluent_uri::component::Scheme;

use crate::parse::untyped::name::{Field, HeaderName};
use crate::parse::{raw, untyped};
use crate::record::digest::{check_block_digest, check_payload_digest, verify_block_digest};
use crate::record::extension::{Extension, ExtensionRecordType, NoExtension};
use crate::record::fields::metadata::MetadataField;
use crate::record::fields::warcinfo::WarcinfoField;
use crate::record::header::truncated_type::TruncatedType;
use crate::record::header::{
    ContinuationHeader, ConversionHeader, CoreHeaders, MetadataHeader, OtherHeader, PayloadHeaders,
    RequestHeader, ResourceHeader, ResponseHeader, RevisitHeader, RevisitProfile, WarcinfoHeader,
};
use crate::record::lift::Lifter;
use crate::record::record_type::RecordType;
use crate::record::render::Renderer;
use crate::value::{
    Algorithm, DigestFormat, LabelledDigest, MediaType, Supported, WarcDate, WarcDatePrecision,
};
use crate::version::WarcVersion;

/// Errors in a record's content block or its relationship to the header.
///
/// [`Error::Block`] wraps these failures while reading, and [`RenderError::Block`] wraps them while
/// rendering. Digest errors are reported during rendering or by the digest inspection methods on
/// [`Record`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockError {
    /// The record declares a `Content-Length` that is not the length of the block it carries.
    #[error("`Content-Length` declares {declared} octets, but the block is {actual}")]
    ContentLengthMismatch {
        /// The length the record declares.
        declared: u64,
        /// The length of the block it carries.
        actual: u64,
    },
    /// The block digest is invalid for its declared algorithm, which this crate computes.
    #[error("the block digest `{0}` is not a digest the algorithm it names can have produced")]
    MalformedBlockDigest(Box<LabelledDigest>),
    /// The record's block digest does not match the block it carries.
    #[error(
        "the record declares the block digest `{declared}`, but its block digests as `{actual}`"
    )]
    BlockDigestMismatch {
        /// The digest the record declares.
        declared: Box<LabelledDigest>,
        /// The digest of the block it carries.
        actual: Box<LabelledDigest>,
    },
    /// The payload digest is invalid for its declared algorithm, which this crate computes.
    #[error("the payload digest `{0}` is not a digest the algorithm it names can have produced")]
    MalformedPayloadDigest(Box<LabelledDigest>),
    /// The record's payload digest does not match the payload its block carries.
    #[error(
        "the record declares the payload digest `{declared}`, but its payload digests as \
         `{actual}`"
    )]
    PayloadDigestMismatch {
        /// The digest the record declares.
        declared: Box<LabelledDigest>,
        /// The digest of the payload it carries.
        actual: Box<LabelledDigest>,
    },
    /// The declared payload digest cannot be checked because the HTTP message is malformed.
    #[error("the record's payload cannot be read from its block: {0}")]
    Payload(#[from] payload::Error),
    /// A nonempty identical-payload-digest revisit block lacks `WARC-Truncated: length`.
    #[error(
        "a `revisit` record under the identical payload digest profile carries a block of {0} \
         octets without declaring `WARC-Truncated: length`"
    )]
    UndeclaredRevisitTruncation(u64),
    /// The block could not be read as the `application/warc-fields` its record's `Content-Type`
    /// declares.
    #[error("the record's body is not what its `Content-Type` declares: {0}")]
    Fields(#[from] fields::Error),
}

/// Semantic validation errors for a record's type and declared WARC version.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A field the standard makes mandatory for the record's type is missing.
    #[error("the mandatory `{0}` field is missing")]
    MissingField(Field),
    /// A field the standard names is present on a record type it is not permitted for.
    #[error("the `{field}` field is not permitted on a `{record_type}` record")]
    ForbiddenField {
        /// The standard record type carrying the field.
        record_type: &'static str,
        /// The field the standard does not permit that type.
        field: Field,
    },
    /// A field the standard names is present on a record declaring a version that does not define
    /// it.
    #[error("the `{field}` field is not defined in WARC {version}")]
    FieldNotInVersion {
        /// The field the declared version does not define.
        field: Field,
        /// The version the record declares.
        version: WarcVersion,
    },
    /// A nonrepeatable standard field is written more than once.
    ///
    /// `WARC-Concurrent-To` is the only repeatable standard field.
    #[error("the `{0}` field is written more than once")]
    RepeatedField(Field),
    /// A field's value is well-formed under its field's grammar but says something the standard
    /// does not permit, such as a `continuation` numbered below `2` or a WARC 1.0 date written at a
    /// precision only WARC 1.1 defines.
    #[error("the value of the `{field}` field is not permitted: `{value}`")]
    MalformedField {
        /// The field whose value the standard does not permit.
        field: Field,
        /// The value as it was read.
        value: String,
    },
    /// A value given to a builder for a URI-valued field is not a URI.
    #[error("the value given for the `{field}` field is not a URI: {source}")]
    NotAUri {
        /// The field the value was given for.
        field: Field,
        /// The RFC 3986 violation.
        source: fluent_uri::ParseError,
    },
    /// An unrecognized field has a value that cannot be preserved as UTF-8 text.
    #[error("the value of the `{0}` field is not valid UTF-8")]
    NonUtf8Field(String),
    /// `WARC-Type` names a type defined by neither the standard nor the extension.
    #[error("the `{0}` record type is defined by no vocabulary in force")]
    UnknownRecordType(String),
    /// The extension attempts to redefine a standard record type.
    #[error("the `{0}` record type is defined by the standard and cannot be redefined")]
    RedefinedRecordType(String),
    /// The extension could not parse the fields it claims.
    #[error("the extension in force could not read the record: {0}")]
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
    #[error("the `{field}` field is not defined in WARC {version}")]
    FieldNotInVersion {
        /// The field the declared version does not define.
        field: Field,
        /// The version the record declares.
        version: WarcVersion,
    },
    /// The record's declared version has no spelling for a value the record carries.
    #[error("the `{field}` value `{value}` cannot be written in WARC {version}")]
    ValueNotInVersion {
        /// The field carrying the value.
        field: Field,
        /// The version the record declares.
        version: WarcVersion,
        /// The value, spelled as WARC 1.1 writes it.
        value: String,
    },
    /// A field carries a name or a value that cannot be written as a valid header line.
    #[error("the `{name}` field cannot be written: {reason}")]
    UnwritableField {
        /// The field's name, as it was given.
        name: String,
        /// What about the field cannot be written.
        reason: String,
    },
    /// A standard field would be written more than once.
    ///
    /// Extension records may retain additional standard fields; rendering rejects nonrepeatable
    /// duplicates.
    #[error("the `{0}` field would be written more than once")]
    RepeatedField(Field),
    /// A field the record's revisit profile requires is not present.
    #[error("the `{0}` field is required by the record's revisit profile")]
    MissingProfileField(Field),
    /// An extension or unrecognized field names a field the standard defines.
    ///
    /// Standard fields on standard record types must come from the typed header. An extension or
    /// unrecognized field cannot use a reserved name, even if the typed field is absent.
    #[error("the `{0}` field is defined by the standard and cannot be written as read")]
    ReservedField(Field),
    /// The record does not go with the block it carries.
    #[error(transparent)]
    Block(#[from] BlockError),
    /// A digest was to be added with an algorithm this build does not enable.
    #[error("digest algorithm {0} is not enabled in this build")]
    UnsupportedDigestAlgorithm(Algorithm),
}

/// The first nonrepeatable standard field written more than once, if a block has one.
///
/// `WARC-Concurrent-To` is the one standard field a record may repeat. A name no version of the
/// standard defines is the extension's business rather than this crate's, so it is not compared.
fn repeated_field<'a>(names: impl Iterator<Item = &'a HeaderName>) -> Option<Field> {
    // A block holds at most one line per field before it repeats one, so this scan compares at most
    // the twenty-one the standard defines.
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
/// WARC 1.0 requires second precision; WARC 1.1 supports every precision this type represents.
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
/// For the identical-payload-digest profile, WARC 1.1 clause 6.7.2 requires a nonempty block to be
/// an initial portion of the response, marked `WARC-Truncated: length`. Other profiles are not
/// checked here.
///
/// The clause obliges the writer, so this is checked when a record is written and not when one is
/// read. A record read from a writer that omits the field is reported by the `lint` operation.
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

    /// Read a record's block as its fields when its `Content-Type` declares them, and keep it as
    /// the bytes it arrived as otherwise.
    ///
    /// A block the record declares truncated is not a complete entity, so one that does not parse
    /// is kept as the bytes it arrived as rather than refused.
    fn read(
        content_type: Option<&MediaType>,
        truncated: bool,
        body: Vec<u8>,
    ) -> Result<Self, BlockError> {
        if !content_type.is_some_and(|media_type| media_type.is("application", "warc-fields")) {
            return Ok(Self::Raw(body));
        }

        match fields::Body::parse(&body) {
            Ok(fields) => Ok(Self::Fields(fields)),
            Err(_) if truncated => Ok(Self::Raw(body)),
            Err(error) => Err(error.into()),
        }
    }
}

/// A WARC record in its semantic representation.
///
/// The type parameter selects an extension vocabulary and defaults to [`NoExtension`]. Extensions
/// can add record types, truncation reasons, and fields on standard record types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record<E: Extension = NoExtension> {
    /// A `warcinfo` record: metadata about a WARC file or the process that produced it.
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
        #[allow(unused_variables, reason = "an answer need not read the binding")]
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
        #[allow(unused_variables, reason = "an answer need not read the binding")]
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
        #[allow(unused_variables, reason = "an answer need not read the binding")]
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

    /// `WARC-Concurrent-To`: the other records of this record's capture event, in the order they
    /// were given. Empty for the record types forbidden the field.
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
    /// This measures the current block. [`into_raw`](Self::into_raw) rejects a conflicting value in
    /// [`CoreHeaders::content_length`].
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

        // A block is held in memory, so its length is a `usize` that fits a `u64` on every platform
        // this crate builds for.
        length as u64
    }

    /// This record's rendered content block.
    ///
    /// A block read as `application/warc-fields` is rendered on demand and comes back owned; every
    /// other block is the bytes the record arrived with and is borrowed.
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

    /// Return this record's payload as defined by WARC 1.1 clause 5.9.
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
        check_payload_digest(self, None).err()
    }

    /// Whether this record declares an HTTP message as its block.
    ///
    /// The target URI must name HTTP or HTTPS, and the media type must be `application/http` or
    /// absent.
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
    /// `Content-Length` comes from the rendered body. If the header also declares a length, the two
    /// must match. Clear or update the declaration after editing a body.
    ///
    /// `WARC-Block-Digest` is checked against the rendered body. A digest naming an algorithm this
    /// crate does not compute is written as read and is not checked.
    ///
    /// `WARC-Payload-Digest` is checked when the complete payload and algorithm are supported; see
    /// [`incorrect_payload_digest`](Self::incorrect_payload_digest). Missing digests are not added.
    /// Use [`into_raw_with_digests`](Self::into_raw_with_digests) to add them.
    ///
    /// Clone the record first if it must be retained.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError::Block`] wrapping:
    ///
    /// - [`BlockError::ContentLengthMismatch`] if the record declares a length its block does not
    ///   have.
    /// - [`BlockError::MalformedBlockDigest`] or [`BlockError::MalformedPayloadDigest`] if a
    ///   declared digest is one its algorithm cannot have produced.
    /// - [`BlockError::BlockDigestMismatch`] or [`BlockError::PayloadDigestMismatch`] if a declared
    ///   digest is not the digest of what it covers.
    /// - [`BlockError::Payload`] if the payload cannot be read from the block.
    /// - [`BlockError::UndeclaredRevisitTruncation`] if a `revisit` record under the identical
    ///   payload digest profile carries a block without declaring it truncated.
    ///
    /// Otherwise returns:
    ///
    /// - [`RenderError::MissingProfileField`] if a `revisit` record does not carry a field its
    ///   profile requires.
    /// - [`RenderError::FieldNotInVersion`] or [`RenderError::ValueNotInVersion`] if the declared
    ///   version has no spelling for a field or a value the record carries.
    /// - [`RenderError::UnwritableField`] if a field kept as read or written by the extension
    ///   carries a name or a value that would not be read back as intended.
    /// - [`RenderError::ReservedField`] if such a field names one the standard defines.
    /// - [`RenderError::RepeatedField`] if a record of an extension type names a nonrepeatable
    ///   standard field twice.
    pub fn into_raw(self) -> Result<raw::Record, RenderError> {
        self.into_raw_added(None, None)
    }

    /// Render as [`into_raw`](Self::into_raw), adding the digests the record does not declare.
    ///
    /// A record declaring no `WARC-Block-Digest` is given one, and a `WARC-Payload-Digest` is added
    /// to a record whose payload [`payload_bytes`](Self::payload_bytes) determines, unless it is a
    /// segment or truncated. The algorithm is chosen at the type level ([`Supported`]), so an
    /// algorithm this build cannot compute is a compile error. Declared digests are checked exactly
    /// as [`into_raw`](Self::into_raw) checks them.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`into_raw`](Self::into_raw).
    pub fn into_raw_with_digests<A: Supported>(
        self,
        _algorithm: A,
    ) -> Result<raw::Record, RenderError> {
        let format = DigestFormat::recommended(A::ALGORITHM);

        self.into_raw_added(Some(format), Some(format))
    }

    /// Render, adding block and payload digests in the given formats where none is declared.
    ///
    /// The formats are chosen at run time, so an algorithm this build cannot compute is an error.
    /// Declared digests are checked exactly as [`into_raw`](Self::into_raw) checks them.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError::UnsupportedDigestAlgorithm`] if either format's algorithm is not
    /// enabled in this build, and otherwise the same errors as [`into_raw`](Self::into_raw).
    pub fn into_raw_with_digests_in(
        self,
        block: DigestFormat,
        payload: DigestFormat,
    ) -> Result<raw::Record, RenderError> {
        if let Some(unsupported) = [block, payload]
            .into_iter()
            .map(|format| format.algorithm)
            .find(|algorithm| !algorithm.is_supported())
        {
            return Err(RenderError::UnsupportedDigestAlgorithm(unsupported));
        }

        self.into_raw_added(Some(block), Some(payload))
    }

    /// Render, optionally adding block and payload digests.
    fn into_raw_added(
        mut self,
        block: Option<DigestFormat>,
        payload: Option<DigestFormat>,
    ) -> Result<raw::Record, RenderError> {
        // Resolve the payload digest before rendering the header fields.
        if let Some(digest) = check_payload_digest(&self, payload)?
            && let Some(headers) = self.payload_mut()
        {
            headers.payload_digest = Some(digest);
        }

        // Read before the record is consumed, since the version and the record type come from the
        // header block and the variant rather than from the core headers.
        let version = self.version();
        let record_type = self.record_type();
        let mut renderer = Renderer::new(version, matches!(record_type, RecordType::Unknown(_)));
        let (core, body) = self.into_stored(&mut renderer)?;

        // A block is held in memory, so its length is a `usize` that fits a `u64` on every platform
        // this crate builds for.
        let content_length = body.len() as u64;
        // A record can also be assembled directly by naming its variant, so the declared length is
        // checked here as well as where a header block and a body are paired.
        check_declared_length(core.content_length, content_length)?;
        let block_digest = check_block_digest(core.block_digest, &body, block)?;

        renderer.push_token(Field::WarcType, record_type.as_str())?;
        renderer.push_uri(Field::RecordID, core.record_id)?;
        renderer.push_date(Field::Date, core.date)?;
        renderer.push_digits(Field::ContentLength, content_length)?;
        if let Some(block_digest) = block_digest {
            renderer.push_digest(Field::BlockDigest, block_digest)?;
        }
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
                // The digest is what a record under this profile asserts, per clause 6.7.2 of the
                // WARC 1.1 standard, so a record without one says nothing and is refused here as it
                // is when read.
                if matches!(header.profile, RevisitProfile::IdenticalPayloadDigest(_))
                    && header.payload.payload_digest.is_none()
                {
                    return Err(RenderError::MissingProfileField(Field::PayloadDigest));
                }
                // A block is held in memory, so its length is a `usize` that fits a `u64` on every
                // platform this crate builds for.
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
    /// fields. Other blocks remain raw, as does such a block that does not parse when the record
    /// declares it truncated.
    ///
    /// A declared `Content-Length` must match the block. The resulting record stores its actual
    /// length.
    ///
    /// Declared digests are preserved without validation. Inspect them on the resulting [`Record`],
    /// or validate them during rendering. Missing digests are added only by the
    /// `into_raw_with_digests` methods.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::ContentLengthMismatch`] if the header block declares a
    /// `Content-Length` the given block does not have, and [`BlockError::Fields`] if the block is
    /// declared `application/warc-fields`, is not, and is not declared truncated.
    pub fn with_body(mut self, body: Vec<u8>) -> Result<Record<E>, BlockError> {
        // A block is held in memory, so its length is a `usize` that fits a `u64` on every platform
        // this crate builds for.
        let content_length = body.len() as u64;
        check_declared_length(self.core().content_length, content_length)?;
        self.core_mut().content_length = Some(content_length);

        let record = match self {
            Self::Warcinfo(header) => {
                let body = FieldsBlock::read(
                    header.core.content_type.as_ref(),
                    header.core.truncated.is_some(),
                    body,
                )?;
                Record::Warcinfo { header, body }
            }
            Self::Metadata(header) => {
                let body = FieldsBlock::read(
                    header.core.content_type.as_ref(),
                    header.core.truncated.is_some(),
                    body,
                )?;
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
        // A record under this profile shall carry the digest that was compared, per clause 6.7.2 of
        // the WARC 1.1 standard.
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
        // standard defines would be written back as a record of that type, so a type claiming one
        // is refused here rather than silently becoming a standard record on the way out.
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

#[cfg(test)]
mod tests;
