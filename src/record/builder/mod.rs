//! Builders for records and record headers.
//!
//! Each entry point selects a record type and requires its mandatory fields. The returned builder
//! exposes only the optional fields allowed for that type.
//!
//! For builders that accept an arbitrary content block, [`build`](ResponseBuilder::build) returns
//! a header and [`body`](ResponseBuilder::body) attaches the block and returns a record:
//!
//! ```
//! use archivindex_warc::record::{Record, RecordHeader};
//! use archivindex_warc::value::MediaType;
//! use chrono::Utc;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let record: Record = Record::response("https://example.com/", Utc::now())?
//!     .content_type(MediaType::HTTP)
//!     .body("HTTP/1.1 200 OK\r\n\r\nhello")?;
//!
//! let header: RecordHeader = Record::response("https://example.com/", Utc::now())?.build();
//!
//! assert_eq!(header.type_name(), record.type_name());
//! # Ok(())
//! # }
//! ```
//!
//! Builders generate a fresh `urn:uuid` record identifier unless
//! [`record_id`](ResponseBuilder::record_id) provides one.
//!
//! Builders restrict which fields can be set, but some relationships between values are checked
//! only when records are read. For example, a revisit profile may require a particular digest.
//! Segment numbers below `2` are rejected immediately because they can never form a valid
//! `continuation` record.
//!
//! Record types whose block has a customary media type declare it: `application/http` with the
//! matching `msgtype` for `request` and `response` records, and `application/warc-fields` for
//! `warcinfo` and `metadata` records. [`content_type`](ResponseBuilder::content_type) replaces it
//! on the builders that are given a block. Attaching a body fails if a declared `Content-Length`
//! does not match it.
//!
//! The `warcinfo` and `metadata` builders construct their own `warc-fields` bodies, so
//! [`build`](WarcinfoBuilder::build) returns a complete record. A `warcinfo` body begins with
//! fields identifying the declared WARC version; a `metadata` body begins empty. Construct a
//! record directly if either type must carry another kind of block.
//!
//! Rendering adds SHA-256 block and payload digests when possible.
//! [`digests`](ResponseBuilder::digests) selects another algorithm.
//!
//! Records declare WARC 1.1. The [`v1_0`] module mirrors every entry point here for an archive
//! that has to be written as WARC 1.0.
//!
//! The extension defaults to [`NoExtension`]. Use `Record::<MyExtension>::response(..)` to select
//! another extension.

use std::net::IpAddr;
use std::time::Duration;

use fluent_uri::{ParseError, Uri};
use uuid::Uuid;

use crate::parse::untyped::name::Field;
use crate::record::digest::{add_block_digest, add_payload_digest};
use crate::record::extension::{Extension, NoExtension};
use crate::record::fields::dcmi::DcmiTerm;
use crate::record::fields::metadata::{HopsFromSeed, MetadataBody, MetadataField};
use crate::record::fields::warcinfo::{WarcinfoBody, WarcinfoField};
use crate::record::header::truncated_type::TruncatedType;
use crate::record::header::{
    ContinuationHeader, ConversionHeader, CoreHeaders, MetadataHeader, OtherHeader, PayloadHeaders,
    RequestHeader, ResourceHeader, ResponseHeader, RevisitHeader, RevisitProfile, SegmentNumber,
    WarcinfoHeader,
};
use crate::record::{BlockError, Error, FieldsBlock, Record, RecordHeader, fields};
use crate::value::{Algorithm, LabelledDigest, MediaType, Text, TextError, WarcDate};
use crate::version::WarcVersion;

/// Generate a version 4 UUID using the `urn:uuid` scheme.
fn generated_record_id() -> Uri<String> {
    // The buffer is sized by `uuid` for its longest rendering, which is this one.
    let mut buffer = Uuid::encode_buffer();
    let urn = Uuid::new_v4().urn().encode_lower(&mut buffer);

    Uri::parse(&*urn)
        .expect("invariant violation: a UUID URN is not a URI")
        .to_owned()
}

/// Read the URI a record type requires as its `WARC-Target-URI`.
fn parse_target_uri(value: &str) -> Result<Uri<String>, ParseError> {
    Uri::parse(value).map(|uri| uri.to_owned())
}

/// The fields every record carries, with the two universally mandatory ones and the media type
/// customary for the record type populated.
fn core_headers<E: Extension>(date: WarcDate, content_type: Option<MediaType>) -> CoreHeaders<E> {
    CoreHeaders {
        record_id: generated_record_id(),
        date,
        content_length: None,
        block_digest: None,
        content_type,
        truncated: None,
        unrecognized: Vec::new(),
    }
}

/// Add the requested digests.
fn add_digests<E: Extension>(record: &mut Record<E>, digests: Option<Algorithm>) {
    if let Some(algorithm) = digests {
        add_block_digest(record, algorithm);
        add_payload_digest(record, algorithm);
    }
}

/// Where the specification a WARC file of the given version conforms to is published.
const fn specification_uri(version: WarcVersion) -> &'static str {
    match version {
        WarcVersion::V1_0 => {
            "http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.0/"
        }
        WarcVersion::V1_1 => {
            "http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/"
        }
    }
}

/// Write a field of a record body from a value this crate rendered, which is always writable.
fn set_rendered<F: fields::Field>(body: &mut fields::Body<F>, field: F, value: impl Into<String>) {
    body.set(field, value)
        .expect("invariant violation: a value rendered here is not a writable field value");
}

/// Write what a `warcinfo` record says about the version of the file it opens, in the two
/// fields Annex B.1 of the standard writes it in.
fn describe_version(body: &mut WarcinfoBody, version: WarcVersion) {
    set_rendered(
        body,
        WarcinfoField::Dcmi(DcmiTerm::Format),
        format!("WARC file version {version}"),
    );
    set_rendered(
        body,
        WarcinfoField::Dcmi(DcmiTerm::ConformsTo),
        specification_uri(version),
    );
}

/// Generate setters for the fields of a record body written as `warc-fields`.
macro_rules! body_setters {
    ($body:ty; $($setter:ident: $field:expr, $name:literal, $description:literal;)*) => {
        /// Write a field the setters here do not name, such as one outside the vocabulary the
        /// standard fixes for this record type.
        ///
        /// Each call appends a value. The named setters replace their field's existing value.
        ///
        /// # Errors
        ///
        /// Returns [`fields::Error::UnwritableField`] if the name is not a token or the value
        /// holds a control character, neither of which a field line can be written from.
        pub fn field(mut self, field: $body, value: &str) -> Result<Self, fields::Error> {
            self.body.push(field, value)?;

            Ok(self)
        }

        $(
            #[doc = concat!("`", $name, "`: ", $description)]
            ///
            /// This replaces any value the field already carries.
            ///
            /// # Errors
            ///
            /// Returns [`fields::Error::UnwritableField`] if the value holds a control
            /// character, which the `TEXT` rule a field value is written under does not admit.
            pub fn $setter(mut self, value: &str) -> Result<Self, fields::Error> {
                self.body.set($field, value)?;

                Ok(self)
            }
        )*
    };
}

/// Generate setters shared by several record types.
macro_rules! shared_setters {
    () => {};

    // The version the record declares, which the header block says rather than a field of it.
    // Only the `v1_0` entry points declare anything but WARC 1.1, so this stays private.
    (v1_0, $($rest:tt)*) => {
        /// Declare this record as WARC 1.0.
        #[must_use]
        const fn into_v1_0(mut self) -> Self {
            self.header.version = WarcVersion::V1_0;
            self
        }

        shared_setters!($($rest)*);
    };

    // The optional fields every record carries whose block the builder is given.
    (core, $($rest:tt)*) => {
        shared_setters!(record_id, digests, block, truncated, $($rest)*);
    };

    (record_id, $($rest:tt)*) => {
        /// `WARC-Record-ID`: replace the generated identifier for this record.
        #[must_use]
        pub fn record_id(mut self, record_id: Uri<String>) -> Self {
            self.header.core.record_id = record_id;
            self
        }

        shared_setters!($($rest)*);
    };

    (digests, $($rest:tt)*) => {
        /// Add block and payload digests computed with the given algorithm.
        ///
        /// Digests use the algorithm's recommended label and encoding. Existing digests are
        /// preserved, and a header built without a block gets none. The algorithm is chosen at
        /// the type level ([`Supported`](crate::value::Supported)), so an algorithm this build
        /// cannot compute is a compile error.
        #[must_use]
        pub fn digests<A: crate::value::Supported>(mut self, _algorithm: A) -> Self {
            self.digests = Some(A::ALGORITHM);
            self
        }

        shared_setters!($($rest)*);
    };

    // What a record says about a block it is given, which a record type whose block the builder
    // writes has no use for.
    (block, $($rest:tt)*) => {
        /// `Content-Length`: declare the expected length of the content block.
        ///
        /// The declaration is checked against the block when one is attached, so it is
        /// [`body`](Self::body) that reports [`BlockError::ContentLengthMismatch`] when the
        /// block is of another length. Building only a header stores the declaration without
        /// checking it against a block.
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

        /// `Content-Type`: the media type of the record's block, which for an archived HTTP
        /// message is `application/http` rather than the type that message declares.
        ///
        /// This replaces the type the record type is built with.
        #[must_use]
        pub fn content_type(mut self, content_type: MediaType) -> Self {
            self.header.core.content_type = Some(content_type);
            self
        }

        shared_setters!($($rest)*);
    };

    (truncated, $($rest:tt)*) => {
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
    // The record types whose block is written as `warc-fields`, which the builder writes
    // rather than is given, so that building one finishes a record and cannot fail.
    ($builder:ident as $variant:ident, fields) => {
        impl<E: Extension> $builder<E> {
            /// Build the record from the fields the builder was told.
            ///
            /// A block these fields cannot express is written by constructing the record
            /// directly.
            #[must_use]
            pub fn build(self) -> Record<E> {
                let Self {
                    mut header,
                    body,
                    digests,
                } = self;

                // A block is held in memory, so its length is a `usize` that fits a `u64`
                // on every platform this crate builds for.
                header.core.content_length = Some(body.rendered_len() as u64);

                let mut record = Record::$variant {
                    header,
                    body: FieldsBlock::Fields(body),
                };
                add_digests(&mut record, digests);

                record
            }
        }
    };

    ($builder:ident as $variant:ident) => {
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
            /// `Content-Length` this block does not have. A `revisit` record under the identical
            /// payload digest profile that carries a block without declaring it truncated is
            /// refused when it is written.
            pub fn body(self, body: impl Into<Vec<u8>>) -> Result<Record<E>, BlockError> {
                let digests = self.digests;
                let mut record = RecordHeader::$variant(self.header).with_body(body.into())?;
                add_digests(&mut record, digests);

                Ok(record)
            }
        }
    };
}

/// Generate builders for `response`, `resource`, and `request` records.
macro_rules! capture_builder {
    ($builder:ident, $header:ident, $fields:ident, $type_name:literal, $content_type:expr) => {
        impl<E: Extension> $builder<E> {
            #[doc = concat!("A builder for a `", $type_name, "` record, given the fields the \
                             standard makes mandatory for one.")]
            ///
            /// # Errors
            ///
            /// Returns [`ParseError`] if the target URI is not a URI.
            pub fn new(target_uri: &str, date: impl Into<WarcDate>) -> Result<Self, ParseError>
            where
                E::$fields: Default,
            {
                Ok(Self {
                    header: $header {
                        version: WarcVersion::V1_1,
                        core: core_headers(date.into(), $content_type),
                        payload: PayloadHeaders::default(),
                        target_uri: parse_target_uri(target_uri)?,
                        warcinfo_id: None,
                        ip_address: None,
                        concurrent_to: Vec::new(),
                        segment_origin: false,
                        other: Default::default(),
                    },
                    digests: None,
                })
            }

            shared_setters!(
                v1_0,
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
///
/// The setters write the record's `warc-fields` body, which starts by identifying the WARC
/// version of the file:
///
/// ```
/// # use archivindex_warc::record::{Record, extension::NoExtension};
/// # use chrono::Utc;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let record = Record::<NoExtension>::warcinfo(Utc::now())
///     .hostname("crawling017.archive.org")?
///     .build();
///
/// assert_eq!(record.type_name(), "warcinfo");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct WarcinfoBuilder<E: Extension = NoExtension> {
    header: WarcinfoHeader<E>,
    body: WarcinfoBody,
    digests: Option<Algorithm>,
}

impl<E: Extension> WarcinfoBuilder<E> {
    /// Create a `warcinfo` builder with its required fields.
    ///
    /// The body starts with `format` and `conformsTo` fields for the declared WARC version.
    /// Their setters replace these defaults.
    #[must_use]
    pub fn new(date: impl Into<WarcDate>) -> Self
    where
        E::WarcinfoFields: Default,
    {
        let mut body = WarcinfoBody::new();
        describe_version(&mut body, WarcVersion::V1_1);

        Self {
            header: WarcinfoHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into(), Some(MediaType::WARC_FIELDS)),
                filename: None,
                segment_origin: false,
                other: Default::default(),
            },
            body,
            digests: None,
        }
    }

    /// Declare this record, and the file it describes, as WARC 1.0.
    ///
    /// Only the `v1_0` entry points declare anything but WARC 1.1, so this stays private.
    #[must_use]
    fn into_v1_0(mut self) -> Self {
        self.header.version = WarcVersion::V1_0;
        describe_version(&mut self.body, WarcVersion::V1_0);

        self
    }
}

impl<E: Extension> WarcinfoBuilder<E> {
    shared_setters!(record_id, digests, extension(WarcinfoFields),);

    body_setters!(
        WarcinfoField;
        robots: WarcinfoField::Robots, "robots",
            "the robots policy followed by the harvester creating this WARC resource.";
        hostname: WarcinfoField::Hostname, "hostname",
            "the hostname of the machine that created this WARC resource.";
        http_header_user_agent: WarcinfoField::HttpHeaderUserAgent, "http-header-user-agent",
            "the HTTP `user-agent` header the harvester usually sent with each request.";
        http_header_from: WarcinfoField::HttpHeaderFrom, "http-header-from",
            "the HTTP `from` header the harvester usually sent with each request.";
        description: WarcinfoField::Dcmi(DcmiTerm::Description), "description",
            "an account of the crawl or the file this record describes.";
        is_part_of: WarcinfoField::Dcmi(DcmiTerm::IsPartOf), "isPartOf",
            "the crawl or collection this file belongs to.";
        format: WarcinfoField::Dcmi(DcmiTerm::Format), "format",
            "the format of the file this record opens, such as `WARC file version 1.1`.";
        conforms_to: WarcinfoField::Dcmi(DcmiTerm::ConformsTo), "conformsTo",
            "the specification this file conforms to, named by its URI.";
    );

    /// Set `operator` to the creator's `name` or, when given, `name <email>`.
    ///
    /// Replaces any existing value.
    ///
    /// # Errors
    ///
    /// Returns [`fields::Error::UnwritableField`] if `name` or `email` contains a control
    /// character, which the field-value grammar forbids.
    pub fn operator(mut self, name: &str, email: Option<&str>) -> Result<Self, fields::Error> {
        match email {
            Some(email) => self
                .body
                .set(WarcinfoField::Operator, format!("{name} <{email}>"))?,
            None => self.body.set(WarcinfoField::Operator, name)?,
        }

        Ok(self)
    }

    /// Set `software` to the creating software's `name/version`.
    ///
    /// Replaces any existing value.
    ///
    /// # Errors
    ///
    /// Returns [`fields::Error::UnwritableField`] if `name` or `version` contains a control
    /// character, which the field-value grammar forbids.
    pub fn software(mut self, name: &str, version: &str) -> Result<Self, fields::Error> {
        self.body
            .set(WarcinfoField::Software, format!("{name}/{version}"))?;

        Ok(self)
    }

    /// `ip`: the IP address of the machine that created this WARC resource.
    ///
    /// This replaces any value the field already carries.
    #[must_use]
    pub fn ip(mut self, ip_address: IpAddr) -> Self {
        set_rendered(&mut self.body, WarcinfoField::Ip, ip_address.to_string());

        self
    }

    /// `WARC-Filename`: the name of the file holding this record, which no other record type
    /// may carry.
    ///
    /// # Errors
    ///
    /// Returns [`TextError`] if the name holds a control character, which the `TEXT` rule the
    /// field is written under does not admit.
    pub fn filename(mut self, filename: &str) -> Result<Self, TextError> {
        self.header.filename = Some(Text::parse(filename.as_bytes())?);

        Ok(self)
    }
}

builder_end!(WarcinfoBuilder as Warcinfo, fields);

/// A builder for a `response` record, which holds a complete scheme-specific response.
#[derive(Clone, Debug)]
pub struct ResponseBuilder<E: Extension = NoExtension> {
    header: ResponseHeader<E>,
    digests: Option<Algorithm>,
}

capture_builder!(
    ResponseBuilder,
    ResponseHeader,
    ResponseFields,
    "response",
    Some(MediaType::HTTP_RESPONSE)
);
builder_end!(ResponseBuilder as Response);

/// A builder for a `resource` record, which holds a resource without protocol information.
#[derive(Clone, Debug)]
pub struct ResourceBuilder<E: Extension = NoExtension> {
    header: ResourceHeader<E>,
    digests: Option<Algorithm>,
}

capture_builder!(
    ResourceBuilder,
    ResourceHeader,
    ResourceFields,
    "resource",
    None
);
builder_end!(ResourceBuilder as Resource);

/// A builder for a `request` record, which holds a complete scheme-specific request.
#[derive(Clone, Debug)]
pub struct RequestBuilder<E: Extension = NoExtension> {
    header: RequestHeader<E>,
    digests: Option<Algorithm>,
}

capture_builder!(
    RequestBuilder,
    RequestHeader,
    RequestFields,
    "request",
    Some(MediaType::HTTP_REQUEST)
);
builder_end!(RequestBuilder as Request);

/// A builder for a `metadata` record, which describes another record.
///
/// The setters here write the record's `warc-fields` body, which starts empty.
#[derive(Clone, Debug)]
pub struct MetadataBuilder<E: Extension = NoExtension> {
    header: MetadataHeader<E>,
    body: MetadataBody,
    digests: Option<Algorithm>,
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
                core: core_headers(date.into(), Some(MediaType::WARC_FIELDS)),
                target_uri: None,
                warcinfo_id: None,
                ip_address: None,
                concurrent_to: Vec::new(),
                refers_to: None,
                segment_origin: false,
                other: Default::default(),
            },
            body: MetadataBody::new(),
            digests: None,
        }
    }
}

impl<E: Extension> MetadataBuilder<E> {
    shared_setters!(
        v1_0,
        record_id,
        digests,
        target_uri,
        warcinfo_id,
        ip_address,
        concurrent_to,
        refers_to,
        extension(MetadataFields),
    );

    body_setters!(
        MetadataField;
        via: MetadataField::Via, "via",
            "the referring URI from which the archived URI was discovered.";
    );

    /// `hopsFromSeed`: the type of each hop from a starting seed URI to the archived one, which
    /// is the empty path for a seed itself.
    ///
    /// This replaces any value the field already carries. The standard fixes no alphabet for the
    /// value, so a path spelled outside the one [`Hop`](fields::metadata::Hop) recommends is
    /// written through [`field`](Self::field).
    #[must_use]
    pub fn hops_from_seed(mut self, hops: &HopsFromSeed) -> Self {
        set_rendered(
            &mut self.body,
            MetadataField::HopsFromSeed,
            hops.to_string(),
        );

        self
    }

    /// `fetchTimeMs`: the time from initiating network traffic to completing the capture.
    ///
    /// The duration is written in whole milliseconds. This replaces any existing value.
    #[must_use]
    pub fn fetch_time_ms(mut self, fetch_time: Duration) -> Self {
        set_rendered(
            &mut self.body,
            MetadataField::FetchTimeMs,
            fetch_time.as_millis().to_string(),
        );

        self
    }
}

builder_end!(MetadataBuilder as Metadata, fields);

/// Generate a `revisit` builder for one WARC version.
macro_rules! revisit_builder {
    ($builder:ident, $version:expr, $version_name:literal) => {
        impl<E: Extension> $builder<E> {
            #[doc = concat!("Create a WARC ", $version_name, " `revisit` builder with its \
                             required fields.")]
            ///
            /// The profile describes how the record should be interpreted. The version its URI
            /// names may differ from the version declared by the record.
            ///
            /// # Errors
            ///
            /// Returns [`ParseError`] if the target URI is not a URI.
            pub fn new(
                target_uri: &str,
                date: impl Into<WarcDate>,
                profile: RevisitProfile,
            ) -> Result<Self, ParseError>
            where
                E::RevisitFields: Default,
            {
                Ok(Self {
                    header: RevisitHeader {
                        version: $version,
                        core: core_headers(date.into(), None),
                        payload: PayloadHeaders::default(),
                        target_uri: parse_target_uri(target_uri)?,
                        warcinfo_id: None,
                        profile,
                        ip_address: None,
                        concurrent_to: Vec::new(),
                        refers_to: None,
                        refers_to_target_uri: None,
                        refers_to_date: None,
                        segment_origin: false,
                        other: Default::default(),
                    },
                    digests: None,
                })
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
    };
}

/// A builder for a `revisit` record, which stands in for content already archived.
///
/// ```
/// # use archivindex_warc::record::{Record, extension::NoExtension, header::RevisitProfile};
/// # use chrono::Utc;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let profile = RevisitProfile::SERVER_NOT_MODIFIED;
///
/// let builder = Record::<NoExtension>::revisit("https://example.com/", Utc::now(), profile)?
///     .refers_to_date(Utc::now());
///
/// assert_eq!(builder.build().type_name(), "revisit");
/// # Ok(())
/// # }
/// ```
///
/// [`v1_0::RevisitBuilder`] is the same builder for a WARC 1.0 record.
#[derive(Clone, Debug)]
pub struct RevisitBuilder<E: Extension = NoExtension> {
    header: RevisitHeader<E>,
    digests: Option<Algorithm>,
}

revisit_builder!(RevisitBuilder, WarcVersion::V1_1, "1.1");

impl<E: Extension> RevisitBuilder<E> {
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

builder_end!(RevisitBuilder as Revisit);

/// A builder for a `conversion` record, which holds another record's content converted.
#[derive(Clone, Debug)]
pub struct ConversionBuilder<E: Extension = NoExtension> {
    header: ConversionHeader<E>,
    digests: Option<Algorithm>,
}

impl<E: Extension> ConversionBuilder<E> {
    /// Create a `conversion` builder with its required fields.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the target URI is not a URI.
    pub fn new(target_uri: &str, date: impl Into<WarcDate>) -> Result<Self, ParseError>
    where
        E::ConversionFields: Default,
    {
        Ok(Self {
            header: ConversionHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into(), None),
                payload: PayloadHeaders::default(),
                target_uri: parse_target_uri(target_uri)?,
                warcinfo_id: None,
                refers_to: None,
                segment_origin: false,
                other: Default::default(),
            },
            digests: None,
        })
    }
}

impl<E: Extension> ConversionBuilder<E> {
    shared_setters!(
        v1_0,
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
    digests: Option<Algorithm>,
}

impl<E: Extension> ContinuationBuilder<E> {
    /// Create a `continuation` builder with its required fields.
    ///
    /// The origin record is segment `1`, so the first continuation is segment `2`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAUri`] if the target URI is not a URI, and
    /// [`Error::MalformedField`] when the segment number is below `2`.
    pub fn new(
        target_uri: &str,
        date: impl Into<WarcDate>,
        segment_number: u64,
        segment_origin_id: Uri<String>,
    ) -> Result<Self, Error>
    where
        E::ContinuationFields: Default,
    {
        let target_uri = parse_target_uri(target_uri).map_err(|source| Error::NotAUri {
            field: Field::TargetURI,
            source,
        })?;
        let segment_number =
            SegmentNumber::new(segment_number).ok_or_else(|| Error::MalformedField {
                field: Field::SegmentNumber,
                value: segment_number.to_string(),
            })?;

        Ok(Self {
            header: ContinuationHeader {
                version: WarcVersion::V1_1,
                core: core_headers(date.into(), None),
                payload: PayloadHeaders::default(),
                target_uri,
                warcinfo_id: None,
                segment_number,
                segment_origin_id,
                segment_total_length: None,
                other: Default::default(),
            },
            digests: None,
        })
    }
}

impl<E: Extension> ContinuationBuilder<E> {
    shared_setters!(
        v1_0,
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
    digests: Option<Algorithm>,
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
                core: core_headers(date.into(), None),
                segment_origin: false,
                extension,
            },
            digests: None,
        }
    }
}

impl<E: Extension> OtherBuilder<E> {
    shared_setters!(v1_0, core, segment_origin,);
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
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the target URI is not a URI.
    pub fn response(
        target_uri: &str,
        date: impl Into<WarcDate>,
    ) -> Result<ResponseBuilder<E>, ParseError>
    where
        E::ResponseFields: Default,
    {
        ResponseBuilder::new(target_uri, date)
    }

    /// A builder for a `resource` record, which holds a resource without protocol information.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the target URI is not a URI.
    pub fn resource(
        target_uri: &str,
        date: impl Into<WarcDate>,
    ) -> Result<ResourceBuilder<E>, ParseError>
    where
        E::ResourceFields: Default,
    {
        ResourceBuilder::new(target_uri, date)
    }

    /// A builder for a `request` record, which holds a complete scheme-specific request.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the target URI is not a URI.
    pub fn request(
        target_uri: &str,
        date: impl Into<WarcDate>,
    ) -> Result<RequestBuilder<E>, ParseError>
    where
        E::RequestFields: Default,
    {
        RequestBuilder::new(target_uri, date)
    }

    /// A builder for a `metadata` record, which describes another record.
    #[must_use]
    pub fn metadata(date: impl Into<WarcDate>) -> MetadataBuilder<E>
    where
        E::MetadataFields: Default,
    {
        MetadataBuilder::new(date)
    }

    /// A builder for a `revisit` record, which stands in for content already archived.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the target URI is not a URI.
    pub fn revisit(
        target_uri: &str,
        date: impl Into<WarcDate>,
        profile: RevisitProfile,
    ) -> Result<RevisitBuilder<E>, ParseError>
    where
        E::RevisitFields: Default,
    {
        RevisitBuilder::new(target_uri, date, profile)
    }

    /// A builder for a `conversion` record, which holds another record's content converted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the target URI is not a URI.
    pub fn conversion(
        target_uri: &str,
        date: impl Into<WarcDate>,
    ) -> Result<ConversionBuilder<E>, ParseError>
    where
        E::ConversionFields: Default,
    {
        ConversionBuilder::new(target_uri, date)
    }

    /// A builder for a `continuation` record, which holds a later segment of a block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAUri`] if the target URI is not a URI, and
    /// [`Error::MalformedField`] when the segment number is below `2`.
    pub fn continuation(
        target_uri: &str,
        date: impl Into<WarcDate>,
        segment_number: u64,
        segment_origin_id: Uri<String>,
    ) -> Result<ContinuationBuilder<E>, Error>
    where
        E::ContinuationFields: Default,
    {
        ContinuationBuilder::new(target_uri, date, segment_number, segment_origin_id)
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

// Declared here because it uses the macros defined above.
pub mod v1_0;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{raw, untyped};
    use crate::record::digest::added_digest;
    use crate::record::extension::{ExtensionRecordType, Never};
    use crate::record::tests::as_rendered;
    use crate::value::marker;

    const RECORD_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";
    pub(super) const OTHER_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000002";
    pub(super) const TARGET_URI: &str = "https://example.com/index.html";
    const DATE: &str = "2020-07-08T02:52:55Z";

    pub(super) fn uri(value: &str) -> Uri<String> {
        Uri::parse(value).expect("well-formed URI").to_owned()
    }

    pub(super) fn date() -> WarcDate {
        WarcDate::parse(DATE, WarcVersion::V1_1).expect("a date at the second precision")
    }

    /// The HTTP block used by the digest tests.
    const RESPONSE_BLOCK: &str = "HTTP/1.1 200 OK\r\n\r\nhello";

    /// The entity-body of [`RESPONSE_BLOCK`].
    const RESPONSE_PAYLOAD: &str = "hello";

    fn digest() -> LabelledDigest {
        LabelledDigest::new("sha1", "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ").expect("a labelled digest")
    }

    /// The value a written record carries for the named field, as text.
    pub(super) fn written(record: &raw::Record, name: &str) -> Option<String> {
        record
            .header
            .get(name)
            .map(|value| String::from_utf8_lossy(value).trim().to_owned())
    }

    /// Write a built record and read it back, which is the check that every field the builder
    /// set is a field the standard permits the record type and that the record says the same
    /// thing at either end.
    pub(super) fn round_trip(record: &Record) -> Record {
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
                .filename("example.warc")
                .expect("a file name")
                .software("archivindex-warc", "0.1.0")
                .expect("a writable field")
                .build(),
            Record::response(TARGET_URI, date())
                .expect("a well-formed target URI")
                .block_digest(added_digest(
                    Algorithm::Sha256.into(),
                    RESPONSE_BLOCK.as_bytes(),
                ))
                .payload_digest(added_digest(
                    Algorithm::Sha1.into(),
                    RESPONSE_PAYLOAD.as_bytes(),
                ))
                .ip_address("192.0.2.1".parse().expect("an address"))
                .concurrent_to(uri(OTHER_ID))
                .warcinfo_id(uri(OTHER_ID))
                .body(RESPONSE_BLOCK)?,
            Record::resource(TARGET_URI, date())
                .expect("a well-formed target URI")
                .truncated(TruncatedType::Length)
                .body("hello")?,
            Record::request(TARGET_URI, date())
                .expect("a well-formed target URI")
                .identified_payload_type(MediaType::TEXT_PLAIN)
                .body("GET / HTTP/1.1\r\n\r\n")?,
            Record::metadata(date())
                .target_uri(uri(TARGET_URI))
                .refers_to(uri(OTHER_ID))
                .via("https://example.com/")
                .expect("a writable field")
                .build(),
            Record::revisit(TARGET_URI, date(), RevisitProfile::IDENTICAL_PAYLOAD_DIGEST)
                .expect("a well-formed target URI")
                .payload_digest(digest())
                .refers_to(uri(OTHER_ID))
                .refers_to_target_uri(uri(TARGET_URI))
                .refers_to_date(date())
                .body("")?,
            Record::conversion(TARGET_URI, date())
                .expect("a well-formed target URI")
                .refers_to(uri(OTHER_ID))
                .body("converted")?,
            Record::continuation(TARGET_URI, date(), 2, uri(OTHER_ID))?
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
                TARGET_URI,
                date(),
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
        let record: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .body("")?;
        let another: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .body("")?;

        assert!(record.core().record_id.as_str().starts_with("urn:uuid:"));
        assert_ne!(record.core().record_id, another.core().record_id);
        assert_eq!(round_trip(&record), as_rendered(record));

        Ok(())
    }

    /// A caller whose identifiers are its own says so, and the identifier it gives is the one
    /// the record is written under.
    #[test]
    fn an_identifier_the_caller_gave_is_the_one_written() -> Result<(), BlockError> {
        let record: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
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

    /// The `digests` option selects the algorithm used for added digests.
    #[test]
    fn a_builder_told_an_algorithm_writes_its_digests() -> Result<(), BlockError> {
        let record: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .digests(marker::Sha1)
            .body(RESPONSE_BLOCK)?;
        let block_digest = record.core().block_digest.as_ref().map(ToString::to_string);
        let payload_digest = record
            .payload()
            .and_then(|headers| headers.payload_digest.as_ref())
            .map(ToString::to_string);

        assert_eq!(
            block_digest.as_deref(),
            Some("sha1:IORUMWLIBUO53GZZJS7FEOU3IDD3AFBH")
        );
        assert_eq!(
            payload_digest.as_deref(),
            Some("sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N")
        );
        assert_eq!(round_trip(&record), record);

        Ok(())
    }

    /// A body the builder wrote is digested in its rendered form.
    #[test]
    fn a_fields_body_is_digested_as_it_is_written() -> Result<(), fields::Error> {
        let record: Record = Record::metadata(date())
            .digests(marker::Sha1)
            .via("http://www.archive.org/")?
            .build();
        let written = record.core().block_digest.as_ref().map(ToString::to_string);

        assert_eq!(
            written.as_deref(),
            Some("sha1:LIXK6ZKWZ7NJHZ2PLYGDQEZJJH4QM4IB")
        );
        assert_eq!(round_trip(&record), record);

        Ok(())
    }

    /// A caller-provided digest takes precedence over the `digests` option.
    #[test]
    fn a_digest_the_caller_gave_outranks_the_digests_option() -> Result<(), BlockError> {
        let record: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .digests(marker::Sha1)
            .block_digest(added_digest(Algorithm::Sha256.into(), b"hello"))
            .body("hello")?;

        assert_eq!(
            record.core().block_digest,
            Some(added_digest(Algorithm::Sha256.into(), b"hello"))
        );

        Ok(())
    }

    /// `build` returns the same header that `body` uses to create a record.
    #[test]
    fn a_builder_ended_with_build_builds_the_header_block_alone() -> Result<(), BlockError> {
        let block_digest = added_digest(Algorithm::Sha1.into(), b"hello");
        // Set body-dependent fields explicitly so the header and record are comparable.
        let header: RecordHeader = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .record_id(uri(RECORD_ID))
            .block_digest(block_digest.clone())
            .content_length(5)
            .build();
        let record: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .record_id(uri(RECORD_ID))
            .block_digest(block_digest)
            .body("hello")?;

        assert_eq!(header.type_name(), "response");
        assert_eq!(header.core(), record.core());
        assert_eq!(record.body_bytes().as_ref(), b"hello");

        Ok(())
    }

    /// A block written as `warc-fields` is declared as those fields, so that the record it is
    /// written into reads back as the fields it was built from rather than as octets.
    #[test]
    fn a_block_written_as_fields_declares_itself_as_them() {
        let record: Record = Record::warcinfo(date())
            .software("archivindex-warc", "0.1.0")
            .expect("a writable field")
            .build();

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

    /// A `warcinfo` body starts by identifying its WARC version, and `build` writes those fields
    /// as the record block.
    #[test]
    fn a_warcinfo_body_opens_describing_the_standard() {
        let record: Record = Record::warcinfo(date()).build();

        assert_eq!(
            String::from_utf8_lossy(&record.body_bytes()),
            format!(
                "format: WARC file version 1.1\r\n\
                 conformsTo: {}\r\n",
                specification_uri(WarcVersion::V1_1)
            )
        );
        assert_eq!(round_trip(&record), as_rendered(record.clone()));
    }

    /// An `operator` includes the email address only when provided.
    #[test]
    fn an_operator_is_written_with_its_optional_email_address() -> Result<(), fields::Error> {
        let with_email: Record = Record::warcinfo(date())
            .operator("A. N. Operator", Some("operator@example.com"))?
            .build();
        let without_email: Record = Record::warcinfo(date())
            .operator("A. N. Operator", None)?
            .build();

        assert!(
            String::from_utf8_lossy(&with_email.body_bytes())
                .contains("operator: A. N. Operator <operator@example.com>\r\n")
        );
        assert!(
            String::from_utf8_lossy(&without_email.body_bytes())
                .contains("operator: A. N. Operator\r\n")
        );

        Ok(())
    }

    /// Setting a field again replaces its value without moving it or creating a duplicate.
    #[test]
    fn a_warcinfo_setter_replaces_the_value_the_body_already_carries() -> Result<(), fields::Error>
    {
        let record: Record = Record::warcinfo(date())
            .software("wget", "1.21")?
            .hostname("crawling017.archive.org")?
            .software("heritrix", "3.4.0")?
            .ip("207.241.227.234".parse().expect("an address"))
            .is_part_of("testcrawl-20050708")?
            .build();

        assert_eq!(
            String::from_utf8_lossy(&record.body_bytes()),
            format!(
                "format: WARC file version 1.1\r\n\
                 conformsTo: {}\r\n\
                 software: heritrix/3.4.0\r\n\
                 hostname: crawling017.archive.org\r\n\
                 ip: 207.241.227.234\r\n\
                 isPartOf: testcrawl-20050708\r\n",
                specification_uri(WarcVersion::V1_1)
            )
        );
        assert_eq!(round_trip(&record), as_rendered(record.clone()));

        Ok(())
    }

    /// A `metadata` body opens empty, so a record built from one holds only what its setters
    /// were told.
    #[test]
    fn a_metadata_body_holds_only_what_its_setters_were_told() -> Result<(), fields::Error> {
        let empty: Record = Record::metadata(date()).build();

        assert_eq!(empty.body_bytes().as_ref(), b"");

        let record: Record = Record::metadata(date())
            .via("http://www.archive.org/")?
            .hops_from_seed(&"E".parse().expect("a path"))
            .fetch_time_ms(Duration::from_millis(565))
            .build();

        assert_eq!(
            String::from_utf8_lossy(&record.body_bytes()),
            "via: http://www.archive.org/\r\nhopsFromSeed: E\r\nfetchTimeMs: 565\r\n"
        );
        assert_eq!(round_trip(&record), as_rendered(record.clone()));

        Ok(())
    }

    /// A field the setters do not name is written by name, and each call adds a value rather
    /// than replacing the one before it, since a `warc-fields` body may repeat a field.
    #[test]
    fn a_field_written_by_name_adds_a_value_rather_than_replacing_one() -> Result<(), fields::Error>
    {
        let record: Record = Record::metadata(date())
            .field(MetadataField::Other("x-note".to_owned()), "first")?
            .field(MetadataField::Other("x-note".to_owned()), "second")?
            .build();

        assert_eq!(
            String::from_utf8_lossy(&record.body_bytes()),
            "x-note: first\r\nx-note: second\r\n"
        );
        assert_eq!(round_trip(&record), as_rendered(record.clone()));

        Ok(())
    }

    /// A record type whose block has a customary media type is built declaring it, and the
    /// declaration is written as the standard spells it.
    #[test]
    fn a_record_type_with_a_customary_media_type_declares_it() -> Result<(), Error> {
        let declared = |header: RecordHeader| header.core().content_type.clone();

        // The two types whose block is `warc-fields` are built as records rather than headers.
        assert_eq!(
            Record::<NoExtension>::warcinfo(date())
                .build()
                .core()
                .content_type,
            Some(MediaType::WARC_FIELDS)
        );
        assert_eq!(
            Record::<NoExtension>::metadata(date())
                .build()
                .core()
                .content_type,
            Some(MediaType::WARC_FIELDS)
        );
        assert_eq!(
            declared(
                Record::request(TARGET_URI, date())
                    .expect("a well-formed target URI")
                    .build()
            ),
            Some(MediaType::HTTP_REQUEST)
        );
        assert_eq!(
            declared(
                Record::response(TARGET_URI, date())
                    .expect("a well-formed target URI")
                    .build()
            ),
            Some(MediaType::HTTP_RESPONSE)
        );

        // Every other type holds whatever the record it was made from held, so its builder
        // declares nothing.
        assert_eq!(
            declared(
                Record::resource(TARGET_URI, date())
                    .expect("a well-formed target URI")
                    .build()
            ),
            None
        );
        assert_eq!(
            declared(
                Record::conversion(TARGET_URI, date())
                    .expect("a well-formed target URI")
                    .build()
            ),
            None
        );
        assert_eq!(
            declared(
                Record::revisit(TARGET_URI, date(), RevisitProfile::IDENTICAL_PAYLOAD_DIGEST)
                    .expect("a well-formed target URI")
                    .build()
            ),
            None
        );
        assert_eq!(
            declared(Record::continuation(TARGET_URI, date(), 2, uri(OTHER_ID))?.build()),
            None
        );

        let record: Record = Record::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .body(RESPONSE_BLOCK)?;
        let raw = record.into_raw().expect("a record built here is writable");

        assert_eq!(
            written(&raw, "Content-Type").as_deref(),
            Some("application/http;msgtype=response")
        );

        Ok(())
    }

    /// A file name is written under the `TEXT` rule, so a name that is not text is refused where
    /// it is given rather than where the record is written.
    #[test]
    fn a_file_name_that_is_not_text_is_refused() {
        let refused = Record::<NoExtension>::warcinfo(date()).filename("example\n.warc");

        assert_eq!(
            refused.err(),
            Some(TextError::ControlCharacter {
                value: "example\n.warc".to_owned(),
                index: 7,
            })
        );
    }

    /// A target URI is read where it is given, so a value that is not a URI is refused there
    /// rather than where the record is written.
    #[test]
    fn a_target_uri_that_is_not_a_uri_is_refused() {
        let refused = Record::<NoExtension>::response("not a URI", date());

        assert_eq!(
            refused.err(),
            Some(Uri::parse("not a URI").expect_err("not a URI"))
        );
    }

    /// A `continuation` builder reports both of the values it can be given that no record could
    /// carry, so the target URI it refuses names the field it was given for.
    #[test]
    fn a_continuation_target_uri_that_is_not_a_uri_is_refused() {
        let refused = Record::<NoExtension>::continuation("not a URI", date(), 2, uri(OTHER_ID));

        assert_eq!(
            refused.err(),
            Some(Error::NotAUri {
                field: Field::TargetURI,
                source: Uri::parse("not a URI").expect_err("not a URI"),
            })
        );
    }

    /// A body the builder writes declares what it renders as, since that is what the record
    /// carrying it is written under.
    #[test]
    fn a_fields_body_declares_the_length_it_renders_as() {
        let record: Record = Record::warcinfo(date())
            .software("archivindex-warc", "0.1.0")
            .expect("a writable field")
            .build();

        assert_eq!(record.core().content_length, Some(record.content_length()));
        assert_eq!(record.content_length(), record.body_bytes().len() as u64);
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

        let response = Record::<Sitemaps>::response(TARGET_URI, date())
            .expect("a well-formed target URI")
            .body("HTTP/1.1 200 OK\r\n\r\n")?;

        assert_eq!(response.type_name(), "response");

        Ok(())
    }
}
