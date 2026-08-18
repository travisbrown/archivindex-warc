//! Builders for records and record headers.
//!
//! Each entry point selects a record type and requires its mandatory fields. The returned builder
//! exposes only the optional fields allowed for that type.
//!
//! [`build`](ResponseBuilder::build) returns a header block, while
//! [`body`](ResponseBuilder::body) attaches a content block and returns a record:
//!
//! ```
//! use archivindex_warc::record::{Record, RecordHeader};
//! use archivindex_warc::value::MediaType;
//! use chrono::Utc;
//! use fluent_uri::Uri;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let target_uri = Uri::parse("https://example.com/")?.to_owned();
//!
//! let record: Record = Record::response(Utc::now(), target_uri.clone())
//!     .content_type(MediaType::parse(b"application/http")?)
//!     .body("HTTP/1.1 200 OK\r\n\r\nhello")?;
//!
//! let header: RecordHeader = Record::response(Utc::now(), target_uri).build();
//!
//! assert_eq!(header.type_name(), record.type_name());
//! # Ok(())
//! # }
//! ```
//!
//! Builders generate a fresh `urn:uuid` record identifier unless
//! [`record_id`](ResponseBuilder::record_id) provides one.
//!
//! Builders restrict which fields can be set, but they do not validate every relationship between
//! values. For example, they do not require the payload digest associated with a particular
//! revisit profile. Those semantic checks are applied when records are read.
//! [`Record::continuation`] is the exception: it returns a result, since a segment number below
//! `2` would build a record that could never be read back.
//!
//! Attaching a body can fail if a declared `Content-Length` does not match, or if a `warcinfo` or
//! `metadata` body declared as `application/warc-fields` cannot be parsed. Use
//! [`fields`](WarcinfoBuilder::fields) to attach an already parsed fields body.
//!
//! A record is given a SHA-256 `WARC-Block-Digest` when it is written. Use
//! [`sha_1_block_digest`](ResponseBuilder::sha_1_block_digest) to digest the block with SHA-1 as
//! it is attached instead.
//!
//! Records default to WARC 1.1. Use [`version`](ResponseBuilder::version) to select WARC 1.0.
//! Revisit records use separate entry points because WARC 1.1 adds two fields:
//! [`Record::revisit`] and [`Record::revisit_1_0`].
//!
//! The extension defaults to [`NoExtension`]. Use `Record::<MyExtension>::response(..)` to select
//! another extension.

use std::marker::PhantomData;
use std::net::IpAddr;

use fluent_uri::Uri;
use uuid::Uuid;

use crate::parse::untyped::name::Field;
use crate::record::digest::add_sha_1_block_digest;
use crate::record::extension::{Extension, NoExtension};
use crate::record::fields::metadata::MetadataField;
use crate::record::fields::warcinfo::WarcinfoField;
use crate::record::header::truncated_type::TruncatedType;
use crate::record::header::{
    ContinuationHeader, ConversionHeader, CoreHeaders, MetadataHeader, OtherHeader, PayloadHeaders,
    RequestHeader, ResourceHeader, ResponseHeader, RevisitHeader, RevisitProfile, SegmentNumber,
    WarcinfoHeader,
};
use crate::record::{
    BlockError, Error, FieldsBlock, Record, RecordHeader, check_declared_length, fields,
};
use crate::value::{LabelledDigest, MediaType, Text, WarcDate};
use crate::version::{WarcVersion, marker};

/// Generate a version 4 UUID using the `urn:uuid` scheme.
fn generated_record_id() -> Uri<String> {
    // The buffer is sized by `uuid` for its longest rendering, which is this one.
    let mut buffer = Uuid::encode_buffer();
    let urn = Uuid::new_v4().urn().encode_lower(&mut buffer);

    Uri::parse(&*urn)
        .expect("invariant violation: a UUID URN is not a URI")
        .to_owned()
}

/// The fields every record carries, with only the two universally mandatory ones populated.
fn core_headers<E: Extension>(date: WarcDate) -> CoreHeaders<E> {
    CoreHeaders {
        record_id: generated_record_id(),
        date,
        content_length: None,
        block_digest: None,
        content_type: None,
        truncated: None,
        unrecognized: Vec::new(),
    }
}

/// The media type a block written as `warc-fields` declares itself with.
fn warc_fields() -> MediaType {
    MediaType::parse(b"application/warc-fields")
        .expect("invariant violation: `application/warc-fields` is not a media type")
}

/// Generate setters shared by several record types.
macro_rules! shared_setters {
    () => {};

    // The version the record declares, which the header block says rather than a field of it.
    (version, $($rest:tt)*) => {
        /// Set the WARC version this record declares and uses when written.
        #[must_use]
        pub const fn version(mut self, version: WarcVersion) -> Self {
            self.header.version = version;
            self
        }

        shared_setters!($($rest)*);
    };

    // The optional fields every record carries, whatever its type.
    (core, $($rest:tt)*) => {
        /// `WARC-Record-ID`: replace the generated identifier for this record.
        #[must_use]
        pub fn record_id(mut self, record_id: Uri<String>) -> Self {
            self.header.core.record_id = record_id;
            self
        }

        /// `Content-Length`: declare the expected length of the content block.
        ///
        /// Attaching a block of another length returns [`BlockError::ContentLengthMismatch`].
        /// Building only a header stores the declaration without checking it against a block.
        #[must_use]
        pub const fn content_length(mut self, content_length: u64) -> Self {
            self.header.core.content_length = Some(content_length);
            self
        }

        /// `WARC-Block-Digest`: set a digest over the complete content block.
        ///
        /// The builder writes the provided digest but does not compute it.
        #[must_use]
        pub fn block_digest(mut self, digest: LabelledDigest) -> Self {
            self.header.core.block_digest = Some(digest);
            self
        }

        /// `WARC-Block-Digest`: digest the content block with SHA-1 rather than SHA-256.
        ///
        /// The digest is written in unpadded upper-case Base32, which is what most tools in this
        /// space write. It is computed when a content block is attached, so a header built
        /// without one carries no digest, and a digest set by
        /// [`block_digest`](Self::block_digest) is left alone.
        #[must_use]
        pub const fn sha_1_block_digest(mut self) -> Self {
            self.sha_1_block_digest = true;
            self
        }

        /// `Content-Type`: the media type of the record's block, which for an archived HTTP
        /// message is `application/http` rather than the type that message declares.
        #[must_use]
        pub fn content_type(mut self, content_type: MediaType) -> Self {
            self.header.core.content_type = Some(content_type);
            self
        }

        /// `WARC-Truncated`: why the record's block holds less than what was captured.
        #[must_use]
        pub fn truncated(mut self, reason: TruncatedType<E::TruncatedReasons>) -> Self {
            self.header.core.truncated = Some(reason);
            self
        }

        shared_setters!($($rest)*);
    };

    // The fields describing a payload, which the record types that have one carry.
    (payload, $($rest:tt)*) => {
        /// `WARC-Payload-Digest`: a digest over the record's payload, which need not be present
        /// in this record's block.
        #[must_use]
        pub fn payload_digest(mut self, digest: LabelledDigest) -> Self {
            self.header.payload.payload_digest = Some(digest);
            self
        }

        /// `WARC-Identified-Payload-Type`: the media type of the payload as determined by
        /// inspecting it, never by promoting a type declared inside the block.
        #[must_use]
        pub fn identified_payload_type(mut self, media_type: MediaType) -> Self {
            self.header.payload.identified_payload_type = Some(media_type);
            self
        }

        shared_setters!($($rest)*);
    };

    // `WARC-Target-URI` where the record type leaves it optional, which is `metadata` alone.
    (target_uri, $($rest:tt)*) => {
        /// `WARC-Target-URI`: a copy of the target URI of the record this one describes.
        #[must_use]
        pub fn target_uri(mut self, target_uri: Uri<String>) -> Self {
            self.header.target_uri = Some(target_uri);
            self
        }

        shared_setters!($($rest)*);
    };

    (warcinfo_id, $($rest:tt)*) => {
        /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one, overriding whichever
        /// `warcinfo` record precedes it in the file.
        #[must_use]
        pub fn warcinfo_id(mut self, record_id: Uri<String>) -> Self {
            self.header.warcinfo_id = Some(record_id);
            self
        }

        shared_setters!($($rest)*);
    };

    (ip_address, $($rest:tt)*) => {
        /// `WARC-IP-Address`: the address the record's content was retrieved from.
        #[must_use]
        pub const fn ip_address(mut self, ip_address: IpAddr) -> Self {
            self.header.ip_address = Some(ip_address);
            self
        }

        shared_setters!($($rest)*);
    };

    (concurrent_to, $($rest:tt)*) => {
        /// `WARC-Concurrent-To`: another record produced by this record's capture event.
        ///
        /// Each call appends another value because this field may repeat.
        #[must_use]
        pub fn concurrent_to(mut self, record_id: Uri<String>) -> Self {
            self.header.concurrent_to.push(record_id);
            self
        }

        shared_setters!($($rest)*);
    };

    (refers_to, $($rest:tt)*) => {
        /// `WARC-Refers-To`: the record this one describes or was derived from.
        #[must_use]
        pub fn refers_to(mut self, record_id: Uri<String>) -> Self {
            self.header.refers_to = Some(record_id);
            self
        }

        shared_setters!($($rest)*);
    };

    (segment_origin, $($rest:tt)*) => {
        /// `WARC-Segment-Number` with the value `1`: mark this record as the first segment of a
        /// series continued by `continuation` records.
        ///
        /// It takes no value because `1` is the only value the standard permits the field on a
        /// record that is not itself a `continuation`.
        #[must_use]
        pub const fn segment_origin(mut self) -> Self {
            self.header.segment_origin = true;
            self
        }

        shared_setters!($($rest)*);
    };

    // The fields the extension in force adds to this record type, named by its associated type.
    (extension($fields:ident), $($rest:tt)*) => {
        /// Replace the extension fields for this record.
        #[must_use]
        pub fn extension(mut self, fields: E::$fields) -> Self {
            self.header.other = fields;
            self
        }

        shared_setters!($($rest)*);
    };
}

/// Generate methods that finish a builder as a header or complete record.
macro_rules! builder_end {
    ($builder:ident as $variant:ident $(, fields $field:ty)?) => {
        impl<E: Extension> $builder<E> {
            /// Build the record header without a content block.
            #[must_use]
            pub fn build(self) -> RecordHeader<E> {
                RecordHeader::$variant(self.header)
            }

            /// Build a record with the given content block.
            ///
            /// # Errors
            ///
            /// Returns [`BlockError::ContentLengthMismatch`] if the builder was told a
            /// `Content-Length` this block does not have, and [`BlockError::Fields`] if the
            /// block is declared `application/warc-fields` and is not those fields, which only
            /// a `warcinfo` or `metadata` record can be.
            pub fn body(self, body: impl Into<Vec<u8>>) -> Result<Record<E>, BlockError> {
                let sha_1_block_digest = self.sha_1_block_digest;
                let mut record = self.build().with_body(body.into())?;

                if sha_1_block_digest {
                    add_sha_1_block_digest(&mut record);
                }

                Ok(record)
            }

            $(
                /// Build a record with an already parsed `warc-fields` body.
                ///
                /// Sets `Content-Type` to `application/warc-fields` unless one was already set.
                ///
                /// # Errors
                ///
                /// Returns [`BlockError::ContentLengthMismatch`] if the rendered fields do not
                /// match the declared `Content-Length`.
                pub fn fields(
                    mut self,
                    fields: fields::Body<$field>,
                ) -> Result<Record<E>, BlockError> {
                    // A block is held in memory, so its length is a `usize` that fits a `u64`
                    // on every platform this crate builds for.
                    let rendered_len = fields.rendered_len() as u64;
                    check_declared_length(self.header.core.content_length, rendered_len)?;
                    self.header.core.content_length = Some(rendered_len);

                    if self.header.core.content_type.is_none() {
                        self.header.core.content_type = Some(warc_fields());
                    }

                    let mut record = Record::$variant {
                        header: self.header,
                        body: FieldsBlock::Fields(fields),
                    };

                    if self.sha_1_block_digest {
                        add_sha_1_block_digest(&mut record);
                    }

                    Ok(record)
                }
            )?
        }
    };
}

/// Generate builders for `response`, `resource`, and `request` records.
macro_rules! capture_builder {
    ($builder:ident, $header:ident, $fields:ident, $type_name:literal) => {
        impl<E: Extension> $builder<E> {
            #[doc = concat!("A builder for a `", $type_name, "` record, given the fields the \
                             standard makes mandatory for one.")]
            #[must_use]
            pub fn new(date: impl Into<WarcDate>, target_uri: Uri<String>) -> Self
            where
                E::$fields: Default,
            {
                Self {
                    header: $header {
                        version: WarcVersion::V1_1,
                        core: core_headers(date.into()),
                        payload: PayloadHeaders::default(),
                        target_uri,
                        warcinfo_id: None,
                        ip_address: None,
                        concurrent_to: Vec::new(),
                        segment_origin: false,
                        other: Default::default(),
                    },
                    sha_1_block_digest: false,
                }
            }

            shared_setters!(
                version,
                core,
                payload,
                warcinfo_id,
                ip_address,
                concurrent_to,
                segment_origin,
                extension($fields),
            );
        }
    };
}

/// A builder for a `warcinfo` record, which describes the records that follow it.
#[derive(Clone, Debug)]
pub struct WarcinfoBuilder<E: Extension = NoExtension> {
    header: WarcinfoHeader<E>,
    sha_1_block_digest: bool,
}

impl<E: Extension> WarcinfoBuilder<E> {
    /// Create a `warcinfo` builder with its required fields.
    #[must_use]
    pub fn new(date: impl Into<WarcDate>) -> Self
    where
        E::WarcinfoFields: Default,
    {
        Self {
            header: WarcinfoHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into()),
                filename: None,
                segment_origin: false,
                other: Default::default(),
            },
            sha_1_block_digest: false,
        }
    }
}

impl<E: Extension> WarcinfoBuilder<E> {
    shared_setters!(version, core, segment_origin, extension(WarcinfoFields),);

    /// `WARC-Filename`: the name of the file holding this record, which no other record type
    /// may carry.
    #[must_use]
    pub fn filename(mut self, filename: Text) -> Self {
        self.header.filename = Some(filename);
        self
    }
}

builder_end!(WarcinfoBuilder as Warcinfo, fields WarcinfoField);

/// A builder for a `response` record, which holds a complete scheme-specific response.
#[derive(Clone, Debug)]
pub struct ResponseBuilder<E: Extension = NoExtension> {
    header: ResponseHeader<E>,
    sha_1_block_digest: bool,
}

capture_builder!(ResponseBuilder, ResponseHeader, ResponseFields, "response");
builder_end!(ResponseBuilder as Response);

/// A builder for a `resource` record, which holds a resource without protocol information.
#[derive(Clone, Debug)]
pub struct ResourceBuilder<E: Extension = NoExtension> {
    header: ResourceHeader<E>,
    sha_1_block_digest: bool,
}

capture_builder!(ResourceBuilder, ResourceHeader, ResourceFields, "resource");
builder_end!(ResourceBuilder as Resource);

/// A builder for a `request` record, which holds a complete scheme-specific request.
#[derive(Clone, Debug)]
pub struct RequestBuilder<E: Extension = NoExtension> {
    header: RequestHeader<E>,
    sha_1_block_digest: bool,
}

capture_builder!(RequestBuilder, RequestHeader, RequestFields, "request");
builder_end!(RequestBuilder as Request);

/// A builder for a `metadata` record, which describes another record.
#[derive(Clone, Debug)]
pub struct MetadataBuilder<E: Extension = NoExtension> {
    header: MetadataHeader<E>,
    sha_1_block_digest: bool,
}

impl<E: Extension> MetadataBuilder<E> {
    /// Create a `metadata` builder with its required fields.
    #[must_use]
    pub fn new(date: impl Into<WarcDate>) -> Self
    where
        E::MetadataFields: Default,
    {
        Self {
            header: MetadataHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into()),
                target_uri: None,
                warcinfo_id: None,
                ip_address: None,
                concurrent_to: Vec::new(),
                refers_to: None,
                segment_origin: false,
                other: Default::default(),
            },
            sha_1_block_digest: false,
        }
    }
}

impl<E: Extension> MetadataBuilder<E> {
    shared_setters!(
        version,
        core,
        target_uri,
        warcinfo_id,
        ip_address,
        concurrent_to,
        refers_to,
        segment_origin,
        extension(MetadataFields),
    );
}

builder_end!(MetadataBuilder as Metadata, fields MetadataField);

/// A builder for a `revisit` record, which stands in for content already archived.
///
/// The type parameter selects the WARC version. Only a [`marker::V1_1`] builder exposes the two
/// fields introduced in WARC 1.1.
///
/// ```
/// # use archivindex_warc::record::{Record, extension::NoExtension};
/// # use chrono::Utc;
/// # use fluent_uri::Uri;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let target_uri = Uri::parse("https://example.com/")?.to_owned();
/// let profile = "http://netpreserve.org/warc/1.1/revisit/server-not-modified";
///
/// let builder = Record::<NoExtension>::revisit(Utc::now(), target_uri, profile)
///     .refers_to_date(Utc::now());
///
/// assert_eq!(builder.build().type_name(), "revisit");
/// # Ok(())
/// # }
/// ```
///
/// The same call does not compile on the WARC 1.0 builder:
///
/// ```compile_fail
/// # use archivindex_warc::record::{Record, extension::NoExtension};
/// # use chrono::Utc;
/// # use fluent_uri::Uri;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let target_uri = Uri::parse("https://example.com/")?.to_owned();
/// let profile = "http://netpreserve.org/warc/1.0/revisit/server-not-modified";
///
/// let builder = Record::<NoExtension>::revisit_1_0(Utc::now(), target_uri, profile)
///     .refers_to_date(Utc::now());
///
/// assert_eq!(builder.build().type_name(), "revisit");
/// # Ok(())
/// # }
/// ```
///
/// The type parameter also determines the version declared by the record.
#[derive(Clone, Debug)]
pub struct RevisitBuilder<E: Extension = NoExtension, V: marker::WarcVersion = marker::V1_1> {
    header: RevisitHeader<E>,
    sha_1_block_digest: bool,
    version: PhantomData<fn() -> V>,
}

impl<E: Extension, V: marker::WarcVersion> RevisitBuilder<E, V> {
    /// Create a `revisit` builder for the version named by `V`.
    fn start(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        profile: impl Into<RevisitProfile>,
    ) -> Self
    where
        E::RevisitFields: Default,
    {
        Self {
            header: RevisitHeader {
                version: V::VALUE,
                core: core_headers(date.into()),
                payload: PayloadHeaders::default(),
                target_uri,
                warcinfo_id: None,
                profile: profile.into(),
                ip_address: None,
                concurrent_to: Vec::new(),
                refers_to: None,
                refers_to_target_uri: None,
                refers_to_date: None,
                segment_origin: false,
                other: Default::default(),
            },
            sha_1_block_digest: false,
            version: PhantomData,
        }
    }

    /// Build the record header without a content block.
    #[must_use]
    pub fn build(self) -> RecordHeader<E> {
        RecordHeader::Revisit(self.header)
    }

    /// Build a record with the given content block.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::ContentLengthMismatch`] if the block does not match the declared
    /// `Content-Length`.
    pub fn body(self, body: impl Into<Vec<u8>>) -> Result<Record<E>, BlockError> {
        self.build().with_body(body.into())
    }

    shared_setters!(
        core,
        payload,
        warcinfo_id,
        ip_address,
        concurrent_to,
        refers_to,
        segment_origin,
        extension(RevisitFields),
    );
}

impl<E: Extension> RevisitBuilder<E, marker::V1_1> {
    /// Create a WARC 1.1 `revisit` builder with its required fields.
    ///
    /// The profile URI describes how the record should be interpreted. Its embedded version may
    /// differ from the version declared by the record.
    #[must_use]
    pub fn new(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        profile: impl Into<RevisitProfile>,
    ) -> Self
    where
        E::RevisitFields: Default,
    {
        Self::start(date, target_uri, profile)
    }

    /// `WARC-Refers-To-Target-URI`: the target URI of the record this one revisits, which need
    /// not be this record's own. Named by WARC 1.1.
    #[must_use]
    pub fn refers_to_target_uri(mut self, target_uri: Uri<String>) -> Self {
        self.header.refers_to_target_uri = Some(target_uri);
        self
    }

    /// `WARC-Refers-To-Date`: the date of the record this one revisits. Named by WARC 1.1.
    #[must_use]
    pub fn refers_to_date(mut self, date: impl Into<WarcDate>) -> Self {
        self.header.refers_to_date = Some(date.into());
        self
    }
}

impl<E: Extension> RevisitBuilder<E, marker::V1_0> {
    /// Create a WARC 1.0 `revisit` builder.
    #[must_use]
    pub fn new_1_0(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        profile: impl Into<RevisitProfile>,
    ) -> Self
    where
        E::RevisitFields: Default,
    {
        Self::start(date, target_uri, profile)
    }
}

/// A builder for a `conversion` record, which holds another record's content converted.
#[derive(Clone, Debug)]
pub struct ConversionBuilder<E: Extension = NoExtension> {
    header: ConversionHeader<E>,
    sha_1_block_digest: bool,
}

impl<E: Extension> ConversionBuilder<E> {
    /// Create a `conversion` builder with its required fields.
    #[must_use]
    pub fn new(date: impl Into<WarcDate>, target_uri: Uri<String>) -> Self
    where
        E::ConversionFields: Default,
    {
        Self {
            header: ConversionHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into()),
                payload: PayloadHeaders::default(),
                target_uri,
                warcinfo_id: None,
                refers_to: None,
                segment_origin: false,
                other: Default::default(),
            },
            sha_1_block_digest: false,
        }
    }
}

impl<E: Extension> ConversionBuilder<E> {
    shared_setters!(
        version,
        core,
        payload,
        warcinfo_id,
        refers_to,
        segment_origin,
        extension(ConversionFields),
    );
}

builder_end!(ConversionBuilder as Conversion);

/// A builder for a `continuation` record, which holds a later segment of a block.
#[derive(Clone, Debug)]
pub struct ContinuationBuilder<E: Extension = NoExtension> {
    header: ContinuationHeader<E>,
    sha_1_block_digest: bool,
}

impl<E: Extension> ContinuationBuilder<E> {
    /// Create a `continuation` builder with its required fields.
    ///
    /// The origin record is segment `1`, so the first continuation is segment `2`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedField`] when the segment number is below `2`.
    pub fn new(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        segment_number: u64,
        segment_origin_id: Uri<String>,
    ) -> Result<Self, Error>
    where
        E::ContinuationFields: Default,
    {
        let segment_number =
            SegmentNumber::new(segment_number).ok_or_else(|| Error::MalformedField {
                field: Field::SegmentNumber,
                value: segment_number.to_string(),
            })?;

        Ok(Self {
            header: ContinuationHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into()),
                payload: PayloadHeaders::default(),
                target_uri,
                warcinfo_id: None,
                segment_number,
                segment_origin_id,
                segment_total_length: None,
                other: Default::default(),
            },
            sha_1_block_digest: false,
        })
    }
}

impl<E: Extension> ContinuationBuilder<E> {
    shared_setters!(
        version,
        core,
        payload,
        warcinfo_id,
        extension(ContinuationFields),
    );

    /// `WARC-Segment-Total-Length`: the length of every segment's block once reassembled,
    /// which the last `continuation` of a series carries and no other record does.
    #[must_use]
    pub const fn segment_total_length(mut self, length: u64) -> Self {
        self.header.segment_total_length = Some(length);
        self
    }
}

builder_end!(ContinuationBuilder as Continuation);

/// A builder for a record of a type the extension in force defines.
#[derive(Clone, Debug)]
pub struct OtherBuilder<E: Extension = NoExtension> {
    header: OtherHeader<E>,
    sha_1_block_digest: bool,
}

impl<E: Extension> OtherBuilder<E> {
    /// Create a builder for the given extension record type.
    ///
    /// Only the fields required for every record are populated.
    #[must_use]
    pub fn new(date: impl Into<WarcDate>, extension: E::Types) -> Self {
        Self {
            header: OtherHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into()),
                segment_origin: false,
                extension,
            },
            sha_1_block_digest: false,
        }
    }
}

impl<E: Extension> OtherBuilder<E> {
    shared_setters!(version, core, segment_origin,);
}

builder_end!(OtherBuilder as Other);

/// Entry points for building each record type.
impl<E: Extension> Record<E> {
    /// A builder for a `warcinfo` record, which describes the records that follow it.
    #[must_use]
    pub fn warcinfo(date: impl Into<WarcDate>) -> WarcinfoBuilder<E>
    where
        E::WarcinfoFields: Default,
    {
        WarcinfoBuilder::new(date)
    }

    /// A builder for a `response` record, which holds a complete scheme-specific response.
    #[must_use]
    pub fn response(date: impl Into<WarcDate>, target_uri: Uri<String>) -> ResponseBuilder<E>
    where
        E::ResponseFields: Default,
    {
        ResponseBuilder::new(date, target_uri)
    }

    /// A builder for a `resource` record, which holds a resource without protocol information.
    #[must_use]
    pub fn resource(date: impl Into<WarcDate>, target_uri: Uri<String>) -> ResourceBuilder<E>
    where
        E::ResourceFields: Default,
    {
        ResourceBuilder::new(date, target_uri)
    }

    /// A builder for a `request` record, which holds a complete scheme-specific request.
    #[must_use]
    pub fn request(date: impl Into<WarcDate>, target_uri: Uri<String>) -> RequestBuilder<E>
    where
        E::RequestFields: Default,
    {
        RequestBuilder::new(date, target_uri)
    }

    /// A builder for a `metadata` record, which describes another record.
    #[must_use]
    pub fn metadata(date: impl Into<WarcDate>) -> MetadataBuilder<E>
    where
        E::MetadataFields: Default,
    {
        MetadataBuilder::new(date)
    }

    /// A builder for a WARC 1.1 `revisit` record, which stands in for content already archived.
    #[must_use]
    pub fn revisit(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        profile: impl Into<RevisitProfile>,
    ) -> RevisitBuilder<E>
    where
        E::RevisitFields: Default,
    {
        RevisitBuilder::new(date, target_uri, profile)
    }

    /// A builder for a WARC 1.0 `revisit` record.
    #[must_use]
    pub fn revisit_1_0(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        profile: impl Into<RevisitProfile>,
    ) -> RevisitBuilder<E, marker::V1_0>
    where
        E::RevisitFields: Default,
    {
        RevisitBuilder::new_1_0(date, target_uri, profile)
    }

    /// A builder for a `conversion` record, which holds another record's content converted.
    #[must_use]
    pub fn conversion(date: impl Into<WarcDate>, target_uri: Uri<String>) -> ConversionBuilder<E>
    where
        E::ConversionFields: Default,
    {
        ConversionBuilder::new(date, target_uri)
    }

    /// A builder for a `continuation` record, which holds a later segment of a block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedField`] when the segment number is below `2`.
    pub fn continuation(
        date: impl Into<WarcDate>,
        target_uri: Uri<String>,
        segment_number: u64,
        segment_origin_id: Uri<String>,
    ) -> Result<ContinuationBuilder<E>, Error>
    where
        E::ContinuationFields: Default,
    {
        ContinuationBuilder::new(date, target_uri, segment_number, segment_origin_id)
    }

    /// A builder for a record type defined by the extension.
    ///
    /// This is unavailable under [`NoExtension`] because its
    /// [`Never`](crate::record::extension::Never) type has no values.
    #[must_use]
    pub fn other(date: impl Into<WarcDate>, extension: E::Types) -> OtherBuilder<E> {
        OtherBuilder::new(date, extension)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{raw, untyped};
    use crate::record::digest::added_block_digest;
    use crate::record::extension::{ExtensionRecordType, Never};
    use crate::record::tests::as_rendered;

    const RECORD_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";
    const OTHER_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000002";
    const TARGET_URI: &str = "https://example.com/index.html";
    const DATE: &str = "2020-07-08T02:52:55Z";

    fn uri(value: &str) -> Uri<String> {
        Uri::parse(value).expect("well-formed URI").to_owned()
    }

    fn date() -> WarcDate {
        WarcDate::parse(DATE, WarcVersion::V1_1).expect("a date at the second precision")
    }

    /// A block whose digest a fixture declares, which a record is written with only when the
    /// digest it declares is the digest of the block it carries.
    const RESPONSE_BLOCK: &str = "HTTP/1.1 200 OK\r\n\r\nhello";

    fn digest() -> LabelledDigest {
        LabelledDigest::new("sha1", "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ").expect("a labelled digest")
    }

    /// The value a written record carries for the named field, as text.
    fn written(record: &raw::Record, name: &str) -> Option<String> {
        record
            .header
            .get(name)
            .map(|value| String::from_utf8_lossy(value).trim().to_owned())
    }

    /// Write a built record and read it back, which is the check that every field the builder
    /// set is a field the standard permits the record type and that the record says the same
    /// thing at either end.
    fn round_trip(record: &Record) -> Record {
        let raw = record
            .clone()
            .into_raw()
            .expect("a record built here is writable");
        let grammar = untyped::Record::try_from(raw).expect("a written record reads as grammar");

        Record::try_from(grammar).expect("a written record reads as itself")
    }

    /// One record of each type the standard defines, built with the fields its builder offers.
    fn records() -> Result<Vec<Record>, Error> {
        Ok(vec![
            Record::warcinfo(date())
                .filename(Text::parse(b"example.warc").expect("a file name"))
                .segment_origin()
                .body("software: archivindex-warc\r\n")?,
            Record::response(date(), uri(TARGET_URI))
                .block_digest(added_block_digest(RESPONSE_BLOCK.as_bytes()))
                .payload_digest(digest())
                .ip_address("192.0.2.1".parse().expect("an address"))
                .concurrent_to(uri(OTHER_ID))
                .warcinfo_id(uri(OTHER_ID))
                .body(RESPONSE_BLOCK)?,
            Record::resource(date(), uri(TARGET_URI))
                .truncated(TruncatedType::Length)
                .body("hello")?,
            Record::request(date(), uri(TARGET_URI))
                .identified_payload_type(MediaType::parse(b"text/html").expect("a media type"))
                .body("GET / HTTP/1.1\r\n\r\n")?,
            Record::metadata(date())
                .target_uri(uri(TARGET_URI))
                .refers_to(uri(OTHER_ID))
                .body("via: https://example.com/\r\n")?,
            Record::revisit(
                date(),
                uri(TARGET_URI),
                RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_1),
            )
            .payload_digest(digest())
            .refers_to(uri(OTHER_ID))
            .refers_to_target_uri(uri(TARGET_URI))
            .refers_to_date(date())
            .body("")?,
            Record::conversion(date(), uri(TARGET_URI))
                .refers_to(uri(OTHER_ID))
                .body("converted")?,
            Record::continuation(date(), uri(TARGET_URI), 2, uri(OTHER_ID))?
                .segment_total_length(14)
                .body("second segment")?,
        ])
    }

    /// Every record a builder builds is a record the standard permits, which is what reading
    /// back what it is written as establishes.
    #[test]
    fn a_built_record_reads_back_as_itself() -> Result<(), Error> {
        for record in records()? {
            assert_eq!(round_trip(&record), as_rendered(record));
        }

        Ok(())
    }

    /// A continuation is numbered from `2`, since the origin record is segment `1`.
    #[test]
    fn a_continuation_is_numbered_from_two() {
        for segment_number in [0, 1] {
            let refused = Record::<NoExtension>::continuation(
                date(),
                uri(TARGET_URI),
                segment_number,
                uri(OTHER_ID),
            );

            assert_eq!(
                refused.err(),
                Some(Error::MalformedField {
                    field: Field::SegmentNumber,
                    value: segment_number.to_string(),
                })
            );
        }
    }

    /// A record must carry an identifier, so a builder not told one names the record itself:
    /// each record built without one is built under a fresh `urn:uuid` name.
    #[test]
    fn a_builder_not_told_an_identifier_names_the_record_itself() -> Result<(), BlockError> {
        let record: Record = Record::response(date(), uri(TARGET_URI)).body("")?;
        let another: Record = Record::response(date(), uri(TARGET_URI)).body("")?;

        assert!(record.core().record_id.as_str().starts_with("urn:uuid:"));
        assert_ne!(record.core().record_id, another.core().record_id);
        assert_eq!(round_trip(&record), as_rendered(record));

        Ok(())
    }

    /// A caller whose identifiers are its own says so, and the identifier it gives is the one
    /// the record is written under.
    #[test]
    fn an_identifier_the_caller_gave_is_the_one_written() -> Result<(), BlockError> {
        let record: Record = Record::response(date(), uri(TARGET_URI))
            .record_id(uri(RECORD_ID))
            .body("")?;

        assert_eq!(record.core().record_id, RECORD_ID);

        let raw = record.into_raw().expect("a record built here is writable");

        assert_eq!(
            written(&raw, "WARC-Record-ID"),
            Some(format!("<{RECORD_ID}>"))
        );

        Ok(())
    }

    /// A builder told to use SHA-1 digests the block it is given with it, rather than leaving
    /// the record to be given a SHA-256 digest when it is written.
    #[test]
    fn a_builder_told_to_use_sha_1_writes_a_sha_1_digest() -> Result<(), BlockError> {
        let record: Record = Record::response(date(), uri(TARGET_URI))
            .sha_1_block_digest()
            .body("hello")?;
        let written = record.core().block_digest.as_ref().map(ToString::to_string);

        assert_eq!(
            written.as_deref(),
            Some("sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N")
        );
        assert_eq!(round_trip(&record), record);

        Ok(())
    }

    /// A record given an already parsed body is digested over the block those fields are
    /// written as.
    #[test]
    fn a_fields_body_is_digested_as_it_is_written() -> Result<(), BlockError> {
        let fields = fields::Body::parse(b"software: archivindex-warc\r\n")?;
        let record: Record = Record::warcinfo(date())
            .sha_1_block_digest()
            .fields(fields)?;
        let written = record.core().block_digest.as_ref().map(ToString::to_string);

        assert_eq!(
            written.as_deref(),
            Some("sha1:K3BHB7RNS422KCX4ORM7HYYH6RNAGKOI")
        );
        assert_eq!(round_trip(&record), record);

        Ok(())
    }

    /// A digest the caller gave is the digest written, whatever the builder was told to compute.
    #[test]
    fn a_digest_the_caller_gave_outranks_the_sha_1_option() -> Result<(), BlockError> {
        let record: Record = Record::response(date(), uri(TARGET_URI))
            .sha_1_block_digest()
            .block_digest(added_block_digest(b"hello"))
            .body("hello")?;

        assert_eq!(
            record.core().block_digest,
            Some(added_block_digest(b"hello"))
        );

        Ok(())
    }

    /// A builder ended with `build` builds the header block alone, which says what the record
    /// ended with `body` says, since the record is that same header block around a block.
    #[test]
    fn a_builder_ended_with_build_builds_the_header_block_alone() -> Result<(), BlockError> {
        // The two are built separately, so the one field a builder would otherwise settle for
        // itself is settled here, leaving nothing that could differ but what is being tested.
        let header: RecordHeader = Record::response(date(), uri(TARGET_URI))
            .record_id(uri(RECORD_ID))
            .block_digest(digest())
            // A record declares the length of the block it was given, so a header block saying
            // what that record says is one told the same length.
            .content_length(5)
            .build();
        let record: Record = Record::response(date(), uri(TARGET_URI))
            .record_id(uri(RECORD_ID))
            .block_digest(digest())
            .body("hello")?;

        assert_eq!(header.type_name(), "response");
        assert_eq!(header.core(), record.core());
        assert_eq!(record.body_bytes().as_ref(), b"hello");

        Ok(())
    }

    /// A block given as `warc-fields` is declared as those fields, so that the record it is
    /// written into reads back as the fields it was built from rather than as octets.
    #[test]
    fn a_block_given_as_fields_declares_itself_as_them() {
        let mut body = fields::Body::new();
        body.push(WarcinfoField::Software, "archivindex-warc")
            .expect("a writable field");

        let record: Record = Record::warcinfo(date())
            .fields(body)
            .expect("a block of the declared length");

        assert!(
            record
                .core()
                .content_type
                .as_ref()
                .is_some_and(|content_type| content_type.is("application", "warc-fields"))
        );
        assert_eq!(round_trip(&record), as_rendered(record.clone()));
        assert!(matches!(
            record,
            Record::Warcinfo {
                body: FieldsBlock::Fields(_),
                ..
            }
        ));
    }

    /// A content type the caller set stands, since the standard recommends the format for these
    /// blocks rather than requiring it and a caller naming another one means it.
    #[test]
    fn a_content_type_the_caller_set_stands() {
        let record: Record = Record::metadata(date())
            .content_type(MediaType::parse(b"text/plain").expect("a media type"))
            .fields(fields::Body::new())
            .expect("a block of the declared length");

        assert!(
            record
                .core()
                .content_type
                .as_ref()
                .is_some_and(|content_type| content_type.is("text", "plain"))
        );
    }

    /// A block of octets declared `warc-fields` is read as those fields, so octets that are not
    /// them are what ending a builder with a block can fail on.
    #[test]
    fn a_block_that_is_not_the_fields_it_is_declared_to_be_is_an_error() {
        let record: Result<Record, BlockError> = Record::warcinfo(date())
            .content_type(warc_fields())
            .body("this line names no field\r\n");

        assert!(matches!(
            record,
            Err(BlockError::Fields(fields::Error::NotANamedField {
                offset: 0
            }))
        ));

        // The same octets under any other content type are the record's as they stand.
        let record: Record = Record::warcinfo(date())
            .content_type(MediaType::parse(b"text/plain").expect("a media type"))
            .body("this line names no field\r\n")
            .expect("a block that is not read as fields cannot fail to be read as them");

        assert_eq!(
            record.body_bytes().as_ref(),
            b"this line names no field\r\n"
        );
    }

    /// A builder told a `Content-Length` ends at a record only where the block it is given is
    /// that length, so a declaration made here cannot be made to disagree with the block it
    /// describes.
    #[test]
    fn a_builder_told_a_content_length_refuses_a_block_of_another_length() {
        let mismatched: Result<Record, BlockError> = Record::response(date(), uri(TARGET_URI))
            .content_length(5)
            .body("good day");

        assert_eq!(
            mismatched,
            Err(BlockError::ContentLengthMismatch {
                declared: 5,
                actual: 8,
            })
        );

        let record: Record = Record::response(date(), uri(TARGET_URI))
            .content_length(5)
            .body("hello")
            .expect("a block of the declared length");

        assert_eq!(record.core().content_length, Some(5));
        assert_eq!(round_trip(&record), as_rendered(record));
    }

    /// A block given as fields is held to the declaration by what it renders as, since that is
    /// what the record carrying it is written under.
    #[test]
    fn a_block_given_as_fields_is_measured_by_what_it_renders_as() {
        let mut body = fields::Body::new();
        body.push(WarcinfoField::Software, "archivindex-warc")
            .expect("a writable field");
        let rendered_len = body.rendered_len() as u64;

        let mismatched: Result<Record, BlockError> = Record::warcinfo(date())
            .content_length(rendered_len + 1)
            .fields(body.clone());

        assert_eq!(
            mismatched,
            Err(BlockError::ContentLengthMismatch {
                declared: rendered_len + 1,
                actual: rendered_len,
            })
        );

        let record: Record = Record::warcinfo(date())
            .content_length(rendered_len)
            .fields(body)
            .expect("a block of the declared length");

        assert_eq!(record.core().content_length, Some(rendered_len));
        assert_eq!(record.content_length(), rendered_len);
    }

    /// A `revisit` record built for WARC 1.0 carries no field WARC 1.0 does not define, so it
    /// is written as a WARC 1.0 record without anything being refused.
    #[test]
    fn a_revisit_built_for_warc_1_0_is_written_as_warc_1_0() -> Result<(), BlockError> {
        let record: Record = Record::revisit_1_0(
            date(),
            uri(TARGET_URI),
            RevisitProfile::ServerNotModified(WarcVersion::V1_0),
        )
        .body("")?;

        // The version the builder was built for is the version the record declares, so the
        // record is written as WARC 1.0 without anything else being said.
        assert_eq!(record.version(), WarcVersion::V1_0);

        let raw = record
            .into_raw()
            .expect("a record built for WARC 1.0 is writable as one");

        assert_eq!(raw.header.version, WarcVersion::V1_0);
        assert_eq!(
            written(&raw, "WARC-Profile").as_deref(),
            Some("<http://netpreserve.org/warc/1.0/revisit/server-not-modified>")
        );

        Ok(())
    }

    /// Every other builder is told its version rather than built for one, and the record it
    /// builds is written as the version it declares: WARC 1.0 brackets every URI-valued field
    /// where WARC 1.1 brackets only the five naming a record.
    #[test]
    fn a_record_is_written_as_the_version_its_builder_declared() -> Result<(), BlockError> {
        let record: Record = Record::response(date(), uri(TARGET_URI))
            .version(WarcVersion::V1_0)
            .body("HTTP/1.1 200 OK\r\n\r\n")?;

        assert_eq!(record.version(), WarcVersion::V1_0);
        assert_eq!(round_trip(&record), as_rendered(record.clone()));

        let raw = record.into_raw().expect("a record built here is writable");

        assert_eq!(raw.header.version, WarcVersion::V1_0);
        assert_eq!(
            written(&raw, "WARC-Target-URI"),
            Some(format!("<{TARGET_URI}>"))
        );

        Ok(())
    }

    /// A vocabulary standing in for a small archiving extension, which defines one record type
    /// and adds nothing to the types the standard defines.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Sitemaps;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SitemapType;

    impl ExtensionRecordType for SitemapType {
        fn type_name(&self) -> &'static str {
            "sitemap"
        }

        fn from_type_name(name: &str) -> Option<Self> {
            (name == "sitemap").then_some(Self)
        }
    }

    impl Extension for Sitemaps {
        type Types = SitemapType;
        type TruncatedReasons = Never;
        type WarcinfoFields = ();
        type ResponseFields = ();
        type ResourceFields = ();
        type RequestFields = ();
        type MetadataFields = ();
        type RevisitFields = ();
        type ConversionFields = ();
        type ContinuationFields = ();
    }

    /// A record under an extension is built the same way, through the record it is a record of,
    /// and one of a type the extension defines is written under the name that type gives itself.
    #[test]
    fn a_record_of_an_extension_type_is_built_under_the_name_its_type_gives_itself()
    -> Result<(), BlockError> {
        let record = Record::<Sitemaps>::other(date(), SitemapType)
            .segment_origin()
            .body("<urlset></urlset>")?;

        assert_eq!(record.type_name(), "sitemap");
        assert_eq!(record.segment_number(), Some(1));

        let raw = record
            .clone()
            .into_raw()
            .expect("a record built here is writable");
        let grammar = untyped::Record::try_from(raw).expect("a written record reads as grammar");

        assert_eq!(
            Record::<Sitemaps>::try_from(grammar).expect("a written record reads as itself"),
            as_rendered(record)
        );

        let response = Record::<Sitemaps>::response(date(), uri(TARGET_URI))
            .body("HTTP/1.1 200 OK\r\n\r\n")?;

        assert_eq!(response.type_name(), "response");

        Ok(())
    }
}
