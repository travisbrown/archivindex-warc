//! A semantic representation of a WARC record's header block.
//!
//! Each record type has its own header struct. Required fields are plain values, optional fields
//! use [`Option`], and forbidden fields are absent. The record variant supplies `WARC-Type`, while
//! each header stores the WARC version declared by its version line.
//!
//! These structs encode clauses 5 and 6 of the WARC 1.1 standard. Where the two versions differ,
//! the 1.1 reading is taken, since it only ever widens what 1.0 allowed.
//!
//! Every header except [`ContinuationHeader`] has a `segment_origin` flag. It represents a
//! `WARC-Segment-Number` of `1`. Continuation headers store their required segment number directly.
//!
//! The type parameter provides record types, fields, and truncation reasons defined by an
//! extension. See [`crate::record::extension`].

pub mod truncated_type;

use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use fluent_uri::Uri;

use crate::record::extension::{Extension, NoExtension};
use crate::record::header::truncated_type::TruncatedType;
use crate::value::{LabelledDigest, MediaType, Text, WarcDate};
use crate::version::WarcVersion;

/// The kind of analysis a `revisit` record reports, named by its `WARC-Profile` URI.
///
/// Unknown profiles are preserved as [`Self::Other`]. Each standard profile stores the version
/// named in its URI, which may differ from the record's declared version.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum RevisitProfile {
    /// The payload is identical to one already archived, as established by a strong digest.
    ///
    /// A record using this profile must carry the matching `WARC-Payload-Digest`. Its block is
    /// either empty or the beginning of the response it stands for, which the record declares as
    /// `WARC-Truncated: length`.
    ///
    /// Both rules apply only to the standard profile URIs. They are checked when a record is read
    /// and again when one is written, so a record assembled or edited directly is checked before
    /// it reaches a file.
    IdenticalPayloadDigest(WarcVersion),
    /// The server asserted the content had not changed, as with an HTTP `304 Not Modified`.
    ///
    /// A record under this profile may have an empty block.
    ServerNotModified(WarcVersion),
    /// A profile defined outside the standard, held as the URI it was written with.
    Other(String),
}

impl RevisitProfile {
    /// The profile URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::IdenticalPayloadDigest(WarcVersion::V1_0) => {
                "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest"
            }
            Self::IdenticalPayloadDigest(WarcVersion::V1_1) => {
                "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest"
            }
            Self::ServerNotModified(WarcVersion::V1_0) => {
                "http://netpreserve.org/warc/1.0/revisit/server-not-modified"
            }
            Self::ServerNotModified(WarcVersion::V1_1) => {
                "http://netpreserve.org/warc/1.1/revisit/server-not-modified"
            }
            Self::Other(uri) => uri,
        }
    }
}

impl Display for RevisitProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Every profile URI defined by the two supported WARC versions.
const KNOWN_PROFILES: [RevisitProfile; 4] = [
    RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_0),
    RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_1),
    RevisitProfile::ServerNotModified(WarcVersion::V1_0),
    RevisitProfile::ServerNotModified(WarcVersion::V1_1),
];

/// Profile URIs are case-sensitive and preserved as written.
impl<S: AsRef<str>> From<S> for RevisitProfile {
    fn from(string: S) -> Self {
        let string = string.as_ref();
        KNOWN_PROFILES
            .iter()
            .find(|profile| profile.as_str() == string)
            .map_or_else(|| Self::Other(string.to_owned()), Clone::clone)
    }
}

/// The named fields every record carries, whatever its type.
///
/// `WARC-Type` comes from the record variant, and the version comes from the containing header.
/// The type parameter supplies extension truncation reasons.
#[derive(Clone, Debug)]
pub struct CoreHeaders<E: Extension = NoExtension> {
    /// `WARC-Record-ID`: this record's required identifier.
    pub record_id: Uri<String>,
    /// `WARC-Date`: the required start time of the capture event.
    pub date: WarcDate,
    /// `Content-Length`: the declared length of the record's block.
    ///
    /// `None` lets the block supply its own length. A declared length must match the block when the
    /// record is rendered.
    pub content_length: Option<u64>,
    /// `WARC-Block-Digest`: `algorithm ":" value` over the whole of the record's block.
    ///
    /// Rendering adds a SHA-256 digest when this is `None`. Supported algorithms are validated;
    /// unsupported algorithms are preserved without validation.
    pub block_digest: Option<LabelledDigest>,
    /// `Content-Type`: the media type of the block itself.
    ///
    /// For an archived HTTP message, this describes the WARC block, not the enclosed HTTP entity.
    /// Every record with a nonempty block except a `continuation` should carry this field.
    pub content_type: Option<MediaType>,
    /// `WARC-Truncated`: why the block holds less than the resource that was captured.
    /// [`Record::content_length`](crate::record::Record::content_length) still reports the
    /// truncated length.
    pub truncated: Option<TruncatedType<E::TruncatedReasons>>,
    /// Fields claimed by neither the standard nor the extension.
    ///
    /// Their order and name spelling are preserved. Values are stored as unfolded UTF-8 text.
    pub unrecognized: Vec<(String, String)>,
}

/// Compare field values without requiring another bound on the extension type.
impl<E: Extension> PartialEq for CoreHeaders<E> {
    fn eq(&self, other: &Self) -> bool {
        self.record_id == other.record_id
            && self.date == other.date
            && self.content_length == other.content_length
            && self.block_digest == other.block_digest
            && self.content_type == other.content_type
            && self.truncated == other.truncated
            && self.unrecognized == other.unrecognized
    }
}

impl<E: Extension> Eq for CoreHeaders<E> {}

/// The named fields describing a record's payload, as opposed to its block.
///
/// A payload may be part of the block, such as an HTTP message body, or content referenced by a
/// `revisit` record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PayloadHeaders {
    /// `WARC-Payload-Digest`: `algorithm ":" value` over the payload, which need not be
    /// present in this record's block. A segmented record records it in its first segment,
    /// where it covers the payload of the reassembled logical record.
    pub payload_digest: Option<LabelledDigest>,
    /// `WARC-Identified-Payload-Type`: the media type of the payload as determined by
    /// inspecting it, never by promoting a declared `Content-Type` out of the block.
    pub identified_payload_type: Option<MediaType>,
}

/// The header of a `warcinfo` record, which describes the records that follow it up to the
/// next `warcinfo` record or the end of the file.
///
/// It describes a file rather than a capture, so it has no target URI, no IP address, and no
/// association with either a `warcinfo` record or a capture event. It has no payload, so it
/// carries no payload fields either.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WarcinfoHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// `WARC-Filename`: the name of the file holding this record. Permitted on no other
    /// record type.
    pub filename: Option<Text>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    ///
    /// No other value is permitted on a record that is not itself a `continuation`.
    pub segment_origin: bool,
    /// The fields the extension adds to a `warcinfo` record.
    pub other: E::WarcinfoFields,
}

/// The header of a `response` record, which holds a complete scheme-specific response
/// including protocol information. For `http` and `https` that is the full response message
/// with its headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// The fields describing the payload, which for an HTTP response is its entity-body.
    pub payload: PayloadHeaders,
    /// `WARC-Target-URI`: the URI whose capture produced this record. Mandatory.
    pub target_uri: Uri<String>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one, overriding whichever
    /// `warcinfo` record precedes it in the file.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-IP-Address`: the address the response was received from.
    pub ip_address: Option<IpAddr>,
    /// `WARC-Concurrent-To`: the records produced by the same capture event, typically the
    /// matching `request`. The one field the standard allows to repeat.
    pub concurrent_to: Vec<Uri<String>>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    pub segment_origin: bool,
    /// The fields the extension adds to a `response` record.
    pub other: E::ResponseFields,
}

/// The header of a `resource` record, which holds a resource without the protocol information
/// a `response` would carry. Its payload is its block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// The fields describing the payload, which for a `resource` is the block itself.
    pub payload: PayloadHeaders,
    /// `WARC-Target-URI`: the URI whose capture produced this record. Mandatory.
    pub target_uri: Uri<String>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-IP-Address`: the address the resource was retrieved from.
    pub ip_address: Option<IpAddr>,
    /// `WARC-Concurrent-To`: the records produced by the same capture event.
    pub concurrent_to: Vec<Uri<String>>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    pub segment_origin: bool,
    /// The fields the extension adds to a `resource` record.
    pub other: E::ResourceFields,
}

/// The header of a `request` record, which holds a complete scheme-specific request including
/// protocol information. For `http` and `https` that is the full request message with its
/// headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// The fields describing the payload, which for an HTTP request is its entity-body.
    pub payload: PayloadHeaders,
    /// `WARC-Target-URI`: the URI this request was directed at. Mandatory.
    pub target_uri: Uri<String>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-IP-Address`: the address the request was directed to.
    pub ip_address: Option<IpAddr>,
    /// `WARC-Concurrent-To`: the records produced by the same capture event, typically the
    /// matching `response`.
    pub concurrent_to: Vec<Uri<String>>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    pub segment_origin: bool,
    /// The fields the extension adds to a `request` record.
    pub other: E::RequestFields,
}

/// The header of a `metadata` record, which describes or accompanies another record in a way
/// no other record type covers.
///
/// It has no payload, so it carries no payload fields, and its target URI is optional: a
/// metadata record describes a record rather than a capture, and names what it describes with
/// `refers_to`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// `WARC-Target-URI`: a copy of the target URI of the record this one describes.
    /// Optional here, unlike on the record types that describe a capture directly.
    pub target_uri: Option<Uri<String>>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-IP-Address`: the address the described material was retrieved from.
    pub ip_address: Option<IpAddr>,
    /// `WARC-Concurrent-To`: the records produced by the same capture event.
    pub concurrent_to: Vec<Uri<String>>,
    /// `WARC-Refers-To`: the record this one describes, which may be of any type,
    /// `metadata` included.
    pub refers_to: Option<Uri<String>>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    pub segment_origin: bool,
    /// The fields the extension adds to a `metadata` record.
    pub other: E::MetadataFields,
}

/// The header of a `revisit` record, which stands in for a `response` or `resource` whose
/// content was found to duplicate content already archived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisitHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// The fields describing the unchanged original payload. The
    /// [`RevisitProfile::IdenticalPayloadDigest`] profile requires its digest.
    pub payload: PayloadHeaders,
    /// `WARC-Target-URI`: the URI this retrieval was directed at. Mandatory.
    pub target_uri: Uri<String>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-Profile`: why the revisit was created and how it is interpreted. Mandatory on a
    /// `revisit` and defined for no other record type.
    pub profile: RevisitProfile,
    /// `WARC-IP-Address`: the address the revisited resource was retrieved from.
    pub ip_address: Option<IpAddr>,
    /// `WARC-Concurrent-To`: the records produced by the same capture event.
    pub concurrent_to: Vec<Uri<String>>,
    /// `WARC-Refers-To`: the earlier record holding the content this one duplicates. Recommended
    /// to identify the referenced record unambiguously.
    pub refers_to: Option<Uri<String>>,
    /// `WARC-Refers-To-Target-URI`: the target URI of the record this one revisits, which
    /// need not equal `target_uri`. Named by WARC 1.1; permitted on no other record type.
    pub refers_to_target_uri: Option<Uri<String>>,
    /// `WARC-Refers-To-Date`: the date of the record this one revisits. Named by WARC 1.1;
    /// permitted on no other record type.
    pub refers_to_date: Option<WarcDate>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    pub segment_origin: bool,
    /// The fields the extension adds to a `revisit` record.
    pub other: E::RevisitFields,
}

/// The header of a `conversion` record, which holds an alternative version of another
/// record's content produced by an archival process. Its payload is its block.
///
/// It is the product of a transformation rather than of a capture, so it carries neither an
/// IP address nor an association with a capture event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// The fields describing the payload, which for a `conversion` is the block itself.
    pub payload: PayloadHeaders,
    /// `WARC-Target-URI`: a copy of the target URI of the record that was converted.
    /// Mandatory.
    pub target_uri: Uri<String>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-Refers-To`: the record whose content was converted. Recommended wherever it
    /// is practical to record it.
    pub refers_to: Option<Uri<String>>,
    /// Whether `WARC-Segment-Number` is present with the value `1`, marking this record as
    /// the first segment of a series continued by `continuation` records.
    pub segment_origin: bool,
    /// The fields the extension adds to a `conversion` record.
    pub other: E::ConversionFields,
}

/// The position of a `continuation` record in its series.
///
/// Under clause 5.20 of the WARC 1.1 standard a segmented record's series is numbered from the
/// origin record's `1`, so a `continuation` is numbered from `2`: the record numbered `1` is the
/// origin rather than a continuation of it. This type holds only numbers a `continuation` can
/// carry, which is what keeps one that cannot be read back from being written.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentNumber(u64);

impl SegmentNumber {
    /// The position of a segment, or `None` for a number below `2`.
    #[must_use]
    pub const fn new(number: u64) -> Option<Self> {
        if number > 1 { Some(Self(number)) } else { None }
    }

    /// The position as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The header of a `continuation` record, which holds a later segment of a block too large
/// for one file.
///
/// Its block is appended to those of the earlier segments to rebuild the logical record, so
/// it describes no capture of its own: it carries no IP address, no association with a
/// capture event, and no `WARC-Refers-To`. The standard recommends against the remaining
/// optional fields here as well, apart from a `WARC-Block-Digest` over this segment's own
/// block and, on the last segment of a series, `WARC-Segment-Total-Length` and
/// `WARC-Truncated`. It recommends rather than forbids, so the rest are admitted here, and a
/// builder leaves every one of them empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// The fields describing the payload of the logical record this segment continues.
    pub payload: PayloadHeaders,
    /// `WARC-Target-URI`: the target URI of the logical record, identical across every
    /// segment of the series. Mandatory.
    pub target_uri: Uri<String>,
    /// `WARC-Warcinfo-ID`: the `warcinfo` record describing this one.
    pub warcinfo_id: Option<Uri<String>>,
    /// `WARC-Segment-Number`: this segment's position in the series, counting from the
    /// origin record's `1`. Mandatory on a `continuation`.
    pub segment_number: SegmentNumber,
    /// `WARC-Segment-Origin-ID`: the record holding the first segment of the series.
    /// Mandatory on a `continuation` and permitted on no other record type.
    pub segment_origin_id: Uri<String>,
    /// `WARC-Segment-Total-Length`: the total length of every segment's block once
    /// reassembled. Present exactly on the last `continuation` of a series, so its
    /// presence is what marks the series as complete.
    pub segment_total_length: Option<u64>,
    /// The fields the extension adds to a `continuation` record.
    pub other: E::ContinuationFields,
}

/// The header of a record whose `WARC-Type` the extension defines.
///
/// It carries the fields every record has and the type itself. The standard does not constrain
/// other fields on extension record types, so they remain in
/// [`core.unrecognized`](CoreHeaders::unrecognized) rather than being lifted into typed fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherHeader<E: Extension = NoExtension> {
    /// The WARC version declared by this record.
    pub version: WarcVersion,
    /// The fields every record carries.
    pub core: CoreHeaders<E>,
    /// Whether `WARC-Segment-Number` is present with the value `1`. Segmentation applies
    /// to any record type but `continuation`, extension types included.
    pub segment_origin: bool,
    /// The extension's record type, which names itself and nothing else. Its untyped fields remain
    /// in [`core.unrecognized`](CoreHeaders::unrecognized).
    pub extension: E::Types,
}

#[cfg(test)]
mod tests {
    use super::RevisitProfile;
    use crate::version::WarcVersion;

    /// Both versions' spellings of both standard profiles are recognized, and anything else is
    /// kept exactly as written.
    #[test]
    fn revisit_profiles_round_trip() {
        for profile in [
            RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_0),
            RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_1),
            RevisitProfile::ServerNotModified(WarcVersion::V1_0),
            RevisitProfile::ServerNotModified(WarcVersion::V1_1),
        ] {
            assert_eq!(RevisitProfile::from(profile.as_str()), profile);
        }

        assert_eq!(
            RevisitProfile::from("http://example.com/Profile"),
            RevisitProfile::Other("http://example.com/Profile".to_owned())
        );
    }

    /// A profile URI names the version that defined it, which is not necessarily the version
    /// the record declares, so the two spellings are distinct values.
    #[test]
    fn revisit_profile_versions_are_distinct() {
        assert_ne!(
            RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_0),
            RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_1)
        );
        assert!(
            RevisitProfile::IdenticalPayloadDigest(WarcVersion::V1_1)
                .as_str()
                .contains("/1.1/")
        );
    }
}
