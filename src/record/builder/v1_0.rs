//! Builders for WARC 1.0 records.
//!
//! Each function here mirrors the entry point of the same name on [`Record`] and declares the
//! record it builds as WARC 1.0. A `revisit` record has its own [`RevisitBuilder`], since a
//! WARC 1.0 record cannot carry the two fields WARC 1.1 named for that type.
//!
//! ```
//! use archivindex_warc::record::Record;
//! use archivindex_warc::record::builder::v1_0;
//! use archivindex_warc::version::WarcVersion;
//! use chrono::Utc;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let record: Record = v1_0::response("https://example.com/", Utc::now())?
//!     .body("HTTP/1.1 200 OK\r\n\r\nhello")?;
//!
//! assert_eq!(record.version(), WarcVersion::V1_0);
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;

use fluent_uri::{ParseError, Uri};

use super::{
    ContinuationBuilder, ConversionBuilder, MetadataBuilder, OtherBuilder, RequestBuilder,
    ResourceBuilder, ResponseBuilder, WarcinfoBuilder, add_sha_1_digests, core_headers,
    parse_target_uri,
};
use crate::record::extension::{Extension, NoExtension};
use crate::record::header::truncated_type::TruncatedType;
use crate::record::header::{PayloadHeaders, RevisitHeader, RevisitProfile};
use crate::record::{BlockError, Error, Record, RecordHeader};
use crate::value::{LabelledDigest, MediaType, WarcDate};
use crate::version::WarcVersion;

/// A builder for a `revisit` record, which stands in for content already archived.
///
/// It is [`super::RevisitBuilder`] without `WARC-Refers-To-Target-URI` and
/// `WARC-Refers-To-Date`, which WARC 1.1 named and a WARC 1.0 record cannot carry:
///
/// ```compile_fail
/// # use archivindex_warc::record::builder::v1_0;
/// # use archivindex_warc::record::extension::NoExtension;
/// # use archivindex_warc::record::header::RevisitProfile;
/// # use archivindex_warc::version::WarcVersion;
/// # use chrono::Utc;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let profile = RevisitProfile::ServerNotModified(WarcVersion::V1_0);
///
/// let builder = v1_0::revisit::<NoExtension>("https://example.com/", Utc::now(), profile)?
///     .refers_to_date(Utc::now());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct RevisitBuilder<E: Extension = NoExtension> {
    header: RevisitHeader<E>,
    sha_1: bool,
}

revisit_builder!(RevisitBuilder, WarcVersion::V1_0, "1.0");

builder_end!(RevisitBuilder as Revisit);

/// A builder for a `warcinfo` record, which describes the records that follow it.
#[must_use]
pub fn warcinfo<E: Extension>(date: impl Into<WarcDate>) -> WarcinfoBuilder<E>
where
    E::WarcinfoFields: Default,
{
    WarcinfoBuilder::new(date).into_v1_0()
}

/// A builder for a `response` record, which holds a complete scheme-specific response.
///
/// # Errors
///
/// Returns [`ParseError`] if the target URI is not a URI.
pub fn response<E: Extension>(
    target_uri: &str,
    date: impl Into<WarcDate>,
) -> Result<ResponseBuilder<E>, ParseError>
where
    E::ResponseFields: Default,
{
    ResponseBuilder::new(target_uri, date).map(ResponseBuilder::into_v1_0)
}

/// A builder for a `resource` record, which holds a resource without protocol information.
///
/// # Errors
///
/// Returns [`ParseError`] if the target URI is not a URI.
pub fn resource<E: Extension>(
    target_uri: &str,
    date: impl Into<WarcDate>,
) -> Result<ResourceBuilder<E>, ParseError>
where
    E::ResourceFields: Default,
{
    ResourceBuilder::new(target_uri, date).map(ResourceBuilder::into_v1_0)
}

/// A builder for a `request` record, which holds a complete scheme-specific request.
///
/// # Errors
///
/// Returns [`ParseError`] if the target URI is not a URI.
pub fn request<E: Extension>(
    target_uri: &str,
    date: impl Into<WarcDate>,
) -> Result<RequestBuilder<E>, ParseError>
where
    E::RequestFields: Default,
{
    RequestBuilder::new(target_uri, date).map(RequestBuilder::into_v1_0)
}

/// A builder for a `metadata` record, which describes another record.
#[must_use]
pub fn metadata<E: Extension>(date: impl Into<WarcDate>) -> MetadataBuilder<E>
where
    E::MetadataFields: Default,
{
    MetadataBuilder::new(date).into_v1_0()
}

/// A builder for a `revisit` record, which stands in for content already archived.
///
/// # Errors
///
/// Returns [`ParseError`] if the target URI is not a URI.
pub fn revisit<E: Extension>(
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
pub fn conversion<E: Extension>(
    target_uri: &str,
    date: impl Into<WarcDate>,
) -> Result<ConversionBuilder<E>, ParseError>
where
    E::ConversionFields: Default,
{
    ConversionBuilder::new(target_uri, date).map(ConversionBuilder::into_v1_0)
}

/// A builder for a `continuation` record, which holds a later segment of a block.
///
/// # Errors
///
/// Returns [`Error::NotAUri`] if the target URI is not a URI, and
/// [`Error::MalformedField`] when the segment number is below `2`.
pub fn continuation<E: Extension>(
    target_uri: &str,
    date: impl Into<WarcDate>,
    segment_number: u64,
    segment_origin_id: Uri<String>,
) -> Result<ContinuationBuilder<E>, Error>
where
    E::ContinuationFields: Default,
{
    ContinuationBuilder::new(target_uri, date, segment_number, segment_origin_id)
        .map(ContinuationBuilder::into_v1_0)
}

/// A builder for a record type defined by the extension.
///
/// This is unavailable under [`NoExtension`] because its
/// [`Never`](crate::record::extension::Never) type has no values.
#[must_use]
pub fn other<E: Extension>(date: impl Into<WarcDate>, extension: E::Types) -> OtherBuilder<E> {
    OtherBuilder::new(date, extension).into_v1_0()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::builder::tests::{OTHER_ID, TARGET_URI, date, round_trip, uri, written};
    use crate::record::builder::{specification_uri, v1_0};
    use crate::record::tests::as_rendered;

    /// Every entry point in [`v1_0`] declares WARC 1.0, which is the whole of what the module
    /// adds over the entry points on [`Record`].
    #[test]
    fn every_warc_1_0_entry_point_declares_warc_1_0() -> Result<(), Error> {
        const TARGET: &str = "a well-formed target URI";

        let headers: Vec<RecordHeader> = vec![
            v1_0::response(TARGET_URI, date()).expect(TARGET).build(),
            v1_0::resource(TARGET_URI, date()).expect(TARGET).build(),
            v1_0::request(TARGET_URI, date()).expect(TARGET).build(),
            v1_0::revisit(
                TARGET_URI,
                date(),
                RevisitProfile::ServerNotModified(WarcVersion::V1_0),
            )
            .expect(TARGET)
            .build(),
            v1_0::conversion(TARGET_URI, date()).expect(TARGET).build(),
            v1_0::continuation(TARGET_URI, date(), 2, uri(OTHER_ID))?.build(),
        ];

        for header in headers {
            assert_eq!(header.version(), WarcVersion::V1_0);
        }

        // The two types whose block is `warc-fields` are built as records rather than headers.
        assert_eq!(
            v1_0::warcinfo::<NoExtension>(date()).build().version(),
            WarcVersion::V1_0
        );
        assert_eq!(
            v1_0::metadata::<NoExtension>(date()).build().version(),
            WarcVersion::V1_0
        );

        Ok(())
    }

    /// A `warcinfo` record built for WARC 1.0 says so in the body it opens with, since the
    /// fields that name the standard are the ones the file's version selects.
    #[test]
    fn a_warcinfo_built_for_warc_1_0_describes_warc_1_0() {
        let record: Record = v1_0::warcinfo(date()).build();

        assert_eq!(
            String::from_utf8_lossy(&record.body_bytes()),
            format!(
                "format: WARC file version 1.0\r\n\
                 conformsTo: {}\r\n",
                specification_uri(WarcVersion::V1_0)
            )
        );
        assert_eq!(round_trip(&record), as_rendered(record.clone()));
    }

    /// A `revisit` record built for WARC 1.0 carries no field WARC 1.0 does not define, so it
    /// is written as a WARC 1.0 record without anything being refused.
    #[test]
    fn a_revisit_built_for_warc_1_0_is_written_as_warc_1_0() -> Result<(), BlockError> {
        let record: Record = v1_0::revisit(
            TARGET_URI,
            date(),
            RevisitProfile::ServerNotModified(WarcVersion::V1_0),
        )
        .expect("a well-formed target URI")
        .body("")?;

        // The builder declares the version, so the record is written as WARC 1.0 without
        // anything else being said.
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

    /// A record built by a [`v1_0`] entry point is written as the version it declares: WARC 1.0
    /// brackets every URI-valued field where WARC 1.1 brackets only the five naming a record.
    #[test]
    fn a_record_is_written_as_the_version_its_builder_declared() -> Result<(), BlockError> {
        let record: Record = v1_0::response(TARGET_URI, date())
            .expect("a well-formed target URI")
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
}
