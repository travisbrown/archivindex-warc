//! What a lint pass reports: the rule a record breaks, and its text and JSON renderings.

use std::fmt::{self, Display, Formatter};

use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::value::{LabelledDigest, MediaType, Text, WarcDate};
use fluent_uri::Uri;

/// A rule a record breaks.
///
/// The module documentation lists the rules. The fields carry what the rule expected and what the
/// record had, where that is not obvious from the variant.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, thiserror::Error)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum Violation {
    /// A record is not alone in its gzip member.
    #[error("the record shares its gzip member with record {first}")]
    SharedGzipMember {
        /// The position of the other record in the member.
        first: usize,
    },
    /// A record's octets are spread over several gzip members.
    #[error("the record is spread over {members} gzip members")]
    SplitGzipMember {
        /// The number of members the record lies in.
        members: usize,
    },
    /// Blank lines stand before a record.
    #[error("the record is preceded by {}", blank_lines(*lines))]
    BlankLinesBefore {
        /// The number of blank lines standing before the record.
        lines: usize,
    },
    /// Blank lines stand after the last record of the file.
    #[error("{} follow the record, at the end of the file", blank_lines(*lines))]
    TrailingBlankLines {
        /// The number of blank lines the file ends with.
        lines: usize,
    },
    /// Two adjacent fields appear in the opposite of canonical order.
    #[error("`{following}` should appear before `{preceding}`")]
    NonCanonicalHeaderOrder {
        /// The earlier field, whose canonical rank is later.
        preceding: String,
        /// The later field, whose canonical rank is earlier.
        following: String,
    },
    /// A record's `WARC-Record-ID` is one an earlier record already used.
    #[error("`WARC-Record-ID` is the identifier of record {first}")]
    DuplicateRecordId {
        /// The position of the record that used the identifier first.
        first: usize,
    },
    /// A record is dated earlier than the record before it.
    #[error("`WARC-Date` is {found}, which precedes the {expected} of record {preceding}")]
    DateOutOfOrder {
        /// The position of the record before this one.
        preceding: usize,
        /// The date of the record before this one.
        #[serde(serialize_with = "serialize_display")]
        expected: WarcDate,
        /// The date of this record.
        #[serde(serialize_with = "serialize_display")]
        found: WarcDate,
    },
    /// A record with a block carries no `Content-Type`.
    #[error("the record has a block but carries no `Content-Type`")]
    MissingContentType,
    /// A record's `Content-Type` is not the one its type calls for.
    #[error("`Content-Type` should be `{expected}`, but is `{found}`")]
    WrongContentType {
        /// The media type the record's type calls for.
        #[serde(serialize_with = "serialize_display")]
        expected: MediaType,
        /// The media type the record declares.
        #[serde(serialize_with = "serialize_display")]
        found: MediaType,
    },
    /// A record carries no `WARC-Block-Digest`.
    #[error("the record carries no `WARC-Block-Digest`")]
    MissingBlockDigest,
    /// A record whose block determines its payload carries no `WARC-Payload-Digest`.
    #[error("the record has a payload but carries no `WARC-Payload-Digest`")]
    MissingPayloadDigest,
    /// A record's `WARC-Block-Digest` is not the digest of the block it carries.
    #[error("`WARC-Block-Digest` is `{declared}`, but the block digests as `{computed}`")]
    BlockDigestMismatch {
        /// The digest the record declares.
        #[serde(serialize_with = "serialize_display")]
        declared: LabelledDigest,
        /// The digest of the block it carries.
        #[serde(serialize_with = "serialize_display")]
        computed: LabelledDigest,
    },
    /// A record's `WARC-Payload-Digest` is not the digest of the payload its block determines.
    #[error("`WARC-Payload-Digest` is `{declared}`, but the payload digests as `{computed}`")]
    PayloadDigestMismatch {
        /// The digest the record declares.
        #[serde(serialize_with = "serialize_display")]
        declared: LabelledDigest,
        /// The digest of the payload its block determines.
        #[serde(serialize_with = "serialize_display")]
        computed: LabelledDigest,
    },
    /// A record declares a digest the algorithm it names cannot have produced.
    #[error("`{field}` is `{found}`, which the algorithm it names cannot have produced")]
    MalformedDigest {
        /// The field the digest is declared in.
        #[serde(serialize_with = "serialize_display")]
        field: Field,
        /// The digest the record declares.
        #[serde(serialize_with = "serialize_display")]
        found: LabelledDigest,
    },
    /// A record declares a `WARC-Payload-Digest` over a block whose payload cannot be read.
    #[error("the payload the declared digest covers cannot be read: {reason}")]
    UnreadablePayload {
        /// Why the block does not yield a payload.
        reason: String,
    },
    /// The first record of the file is not a `warcinfo` record.
    #[error("the first record is a `{found}` record, not a `warcinfo` record")]
    FirstRecordNotWarcinfo {
        /// The type of the first record.
        found: String,
    },
    /// A record other than a `warcinfo` record carries no `WARC-Warcinfo-ID`.
    #[error("the record carries no `WARC-Warcinfo-ID`")]
    MissingWarcinfoId,
    /// A record's `WARC-Warcinfo-ID` does not name the `warcinfo` record that most closely
    /// precedes it.
    #[error("`WARC-Warcinfo-ID` names {found}, but {}", preceding_warcinfo(expected.as_ref()))]
    WrongWarcinfoId {
        /// The `warcinfo` record that most closely precedes this one, or `None` if none does.
        #[serde(serialize_with = "serialize_optional_display")]
        expected: Option<Uri<String>>,
        /// The record the field names.
        #[serde(serialize_with = "serialize_display")]
        found: Uri<String>,
    },
    /// A `warcinfo` record carries no `isPartOf` field.
    #[error("the warcinfo record carries no `isPartOf` field")]
    MissingCollectionId,
    /// A `warcinfo` record's `isPartOf` is not a host, path parts, and a timestamp joined by `-`.
    #[error(
        "`isPartOf` should be a host, path parts, and a timestamp joined by `-`, but is `{found}`"
    )]
    MalformedCollectionId {
        /// The collection identifier the record names.
        found: String,
    },
    /// A `warcinfo` record's `WARC-Filename` is not its collection identifier followed by
    /// `.warc.gz`.
    #[error("`WARC-Filename` should be `{expected}`, but {}", filename(found.as_ref()))]
    WrongFilename {
        /// The file name the collection identifier calls for.
        expected: String,
        /// The record's file name, or `None` if it carries none.
        #[serde(serialize_with = "serialize_optional_display")]
        found: Option<Text>,
    },
    /// A `request` record's target URI does not have the collection's host as its host.
    #[error("the target URI's host should be `{expected}`, but {}", host(found.as_deref()))]
    WrongRequestHost {
        /// The host of the collection identifier the `warcinfo` record names.
        expected: String,
        /// The target URI's host, or `None` if it has none.
        found: Option<String>,
    },
    /// A `request` record is not immediately followed by its `response` or `revisit` record.
    #[error("the request is not followed by its response: {}", next_record(found.as_deref()))]
    RequestWithoutResponse {
        /// The type of the record that follows, or `None` at the end of the file.
        found: Option<String>,
    },
    /// A `response` or `revisit` record does not immediately follow a `request` record.
    #[error("the response does not follow a request record")]
    ResponseWithoutRequest,
    /// A `response` or `revisit` record is not immediately followed by its `metadata` record.
    #[error("the response is not followed by its metadata record: {}", next_record(found.as_deref()))]
    ResponseWithoutMetadata {
        /// The type of the record that follows, or `None` at the end of the file.
        found: Option<String>,
    },
    /// A capture record's `WARC-Concurrent-To` does not name exactly the record before it.
    #[error(
        "`WARC-Concurrent-To` should name {expected} alone, but names {}",
        listed(found)
    )]
    WrongConcurrentTo {
        /// The record the field should name.
        #[serde(serialize_with = "serialize_display")]
        expected: Uri<String>,
        /// The records the field names.
        #[serde(serialize_with = "serialize_display_sequence")]
        found: Vec<Uri<String>>,
    },
    /// A capture record's `WARC-Target-URI` is not the request's.
    #[error("`WARC-Target-URI` should be {expected}, but {}", target_uri(found.as_ref()))]
    WrongTargetUri {
        /// The request's target URI.
        #[serde(serialize_with = "serialize_display")]
        expected: Uri<String>,
        /// The record's target URI, or `None` if it carries none.
        #[serde(serialize_with = "serialize_optional_display")]
        found: Option<Uri<String>>,
    },
    /// A capture's `metadata` record carries no `fetchTimeMs` field.
    #[error("the capture's metadata record carries no `fetchTimeMs` field")]
    MissingFetchTime,
    /// A `revisit` record carries a block it does not declare truncated.
    #[error("the revisit carries a block of {length} octets without declaring it truncated")]
    UndeclaredRevisitTruncation {
        /// The length of the block the record carries.
        length: u64,
    },
    /// A `revisit` record lacks a `WARC-Refers-To` field.
    #[error("the revisit carries no {}", fields(missing))]
    MissingRefersToFields {
        /// The fields the record lacks, in conventional order.
        #[serde(serialize_with = "serialize_field_names")]
        missing: Vec<Field>,
    },
    /// A `revisit` record's `WARC-Refers-To` names no record that precedes it.
    #[error("`WARC-Refers-To` names {found}, which is the identifier of no preceding record")]
    RefersToUnknownRecord {
        /// The record the field names.
        #[serde(serialize_with = "serialize_display")]
        found: Uri<String>,
    },
}

impl Violation {
    /// The name of the rule this breaks, as the serialized form writes it.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::SharedGzipMember { .. } => "shared_gzip_member",
            Self::SplitGzipMember { .. } => "split_gzip_member",
            Self::BlankLinesBefore { .. } => "blank_lines_before",
            Self::TrailingBlankLines { .. } => "trailing_blank_lines",
            Self::NonCanonicalHeaderOrder { .. } => "non_canonical_header_order",
            Self::DuplicateRecordId { .. } => "duplicate_record_id",
            Self::DateOutOfOrder { .. } => "date_out_of_order",
            Self::MissingContentType => "missing_content_type",
            Self::WrongContentType { .. } => "wrong_content_type",
            Self::MissingBlockDigest => "missing_block_digest",
            Self::MissingPayloadDigest => "missing_payload_digest",
            Self::BlockDigestMismatch { .. } => "block_digest_mismatch",
            Self::PayloadDigestMismatch { .. } => "payload_digest_mismatch",
            Self::MalformedDigest { .. } => "malformed_digest",
            Self::UnreadablePayload { .. } => "unreadable_payload",
            Self::FirstRecordNotWarcinfo { .. } => "first_record_not_warcinfo",
            Self::MissingWarcinfoId => "missing_warcinfo_id",
            Self::WrongWarcinfoId { .. } => "wrong_warcinfo_id",
            Self::MissingCollectionId => "missing_collection_id",
            Self::MalformedCollectionId { .. } => "malformed_collection_id",
            Self::WrongFilename { .. } => "wrong_filename",
            Self::WrongRequestHost { .. } => "wrong_request_host",
            Self::RequestWithoutResponse { .. } => "request_without_response",
            Self::ResponseWithoutRequest => "response_without_request",
            Self::ResponseWithoutMetadata { .. } => "response_without_metadata",
            Self::WrongConcurrentTo { .. } => "wrong_concurrent_to",
            Self::WrongTargetUri { .. } => "wrong_target_uri",
            Self::MissingFetchTime => "missing_fetch_time",
            Self::UndeclaredRevisitTruncation { .. } => "undeclared_revisit_truncation",
            Self::MissingRefersToFields { .. } => "missing_refers_to_fields",
            Self::RefersToUnknownRecord { .. } => "refers_to_unknown_record",
        }
    }
}

/// A value serialized as its printed form.
struct AsDisplay<'a, T>(&'a T);

impl<T: Display> serde::Serialize for AsDisplay<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}

/// Serialize a value as its printed form.
fn serialize_display<T: Display, S: serde::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

/// Serialize a value that may be absent as its printed form.
// `serialize_with` hands the field over as it is declared, so this takes a reference to the option.
#[allow(clippy::ref_option)]
fn serialize_optional_display<T: Display, S: serde::Serializer>(
    value: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.collect_str(value),
        None => serializer.serialize_none(),
    }
}

/// Serialize values as a sequence of their printed forms.
fn serialize_display_sequence<T: Display, S: serde::Serializer>(
    values: &[T],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(AsDisplay))
}

/// Describe the `warcinfo` record a record should have named.
fn preceding_warcinfo(expected: Option<&Uri<String>>) -> String {
    expected.map_or_else(
        || "no warcinfo record precedes it".to_owned(),
        |uri| format!("the closest preceding warcinfo record is {uri}"),
    )
}

/// Describe the record following one that expected a particular successor.
fn next_record(found: Option<&str>) -> String {
    found.map_or_else(
        || "it is the last record".to_owned(),
        |type_name| format!("the next record is a `{type_name}` record"),
    )
}

/// List record identifiers in a message.
fn listed(uris: &[Uri<String>]) -> String {
    if uris.is_empty() {
        return "nothing".to_owned();
    }

    uris.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Describe a record's target URI in a message.
fn target_uri(found: Option<&Uri<String>>) -> String {
    found.map_or_else(
        || "the record carries none".to_owned(),
        |uri| format!("is {uri}"),
    )
}

/// Describe a record's file name in a message.
fn filename(found: Option<&Text>) -> String {
    found.map_or_else(
        || "the record carries none".to_owned(),
        |name| format!("is `{name}`"),
    )
}

/// Describe a number of blank lines in a message.
fn blank_lines(lines: usize) -> String {
    if lines == 1 {
        "1 blank line".to_owned()
    } else {
        format!("{lines} blank lines")
    }
}

/// List header fields in a message, by their standard names.
fn fields(fields: &[Field]) -> String {
    fields
        .iter()
        .map(|field| format!("`{}`", field.standard_name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Serialize header fields by their standard names.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_field_names<S: serde::ser::Serializer>(
    fields: &[Field],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(fields.iter().map(|field| field.standard_name()))
}

/// Describe a target URI's host in a message.
fn host(found: Option<&str>) -> String {
    found.map_or_else(
        || "the URI has none".to_owned(),
        |host| format!("is `{host}`"),
    )
}

/// One rule one record breaks.
///
/// The serialized form is one flat object: the position, the identifier, the rule's name, and
/// whatever the rule reports.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, thiserror::Error)]
pub struct Finding {
    /// The record's zero-based position in the file, counting records that failed to read.
    pub index: usize,
    /// The record's `WARC-Record-ID`.
    #[serde(serialize_with = "serialize_display")]
    pub record_id: Uri<String>,
    /// The rule the record breaks.
    #[serde(flatten)]
    #[source]
    pub violation: Violation,
}

impl Display for Finding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "record {} ({}): {}",
            self.index, self.record_id, self.violation
        )
    }
}

/// What a lint pass says about one record, or one rule one record breaks.
///
/// `Ok` carries the identifier of a record that breaks no rule. A record breaking several rules
/// yields one `Err` per rule and no `Ok`. Since a record can be faulted by the record that follows
/// it, a record's result is only settled once the next one has been read. The finding is boxed to
/// keep the common case small.
pub type Checked = Result<Uri<String>, Box<Finding>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    #[test]
    fn a_finding_states_its_record_and_rule() {
        let finding = Finding {
            index: 2,
            record_id: uri(RESPONSE_ID),
            violation: Violation::WrongConcurrentTo {
                expected: uri(REQUEST_ID),
                found: vec![],
            },
        };

        assert_eq!(
            finding.to_string(),
            format!(
                "record 2 ({RESPONSE_ID}): `WARC-Concurrent-To` should name {REQUEST_ID} alone, \
                 but names nothing"
            )
        );
        assert_eq!(
            Violation::WrongWarcinfoId {
                expected: None,
                found: uri(WARCINFO_ID)
            }
            .to_string(),
            format!("`WARC-Warcinfo-ID` names {WARCINFO_ID}, but no warcinfo record precedes it")
        );
        assert_eq!(
            Violation::ResponseWithoutMetadata { found: None }.to_string(),
            "the response is not followed by its metadata record: it is the last record"
        );
        assert_eq!(
            Violation::WrongTargetUri {
                expected: uri(TARGET),
                found: None
            }
            .to_string(),
            format!("`WARC-Target-URI` should be {TARGET}, but the record carries none")
        );
        assert_eq!(
            Violation::WrongFilename {
                expected: FILENAME.to_owned(),
                found: Text::parse(b"other.warc").ok()
            }
            .to_string(),
            format!("`WARC-Filename` should be `{FILENAME}`, but is `other.warc`")
        );
        assert_eq!(
            Violation::WrongRequestHost {
                expected: HOST.to_owned(),
                found: None
            }
            .to_string(),
            format!("the target URI's host should be `{HOST}`, but the URI has none")
        );
        assert_eq!(
            Violation::DateOutOfOrder {
                preceding: 1,
                expected: date(DATE),
                found: date("2024-04-01T11:59:59Z"),
            }
            .to_string(),
            format!("`WARC-Date` is 2024-04-01T11:59:59Z, which precedes the {DATE} of record 1")
        );
        assert_eq!(
            Violation::MissingRefersToFields {
                missing: vec![Field::RefersToTargetURI, Field::RefersToDate],
            }
            .to_string(),
            "the revisit carries no `WARC-Refers-To-Target-URI`, `WARC-Refers-To-Date`"
        );
    }

    /// A finding serializes as one flat object naming the rule it reports.
    #[test]
    fn serializes_a_finding_as_a_flat_object() {
        let finding = Finding {
            index: 2,
            record_id: uri(RESPONSE_ID),
            violation: Violation::WrongTargetUri {
                expected: uri(TARGET),
                found: None,
            },
        };

        assert_eq!(
            serde_json::to_string(&finding).expect("a finding serializes"),
            format!(
                r#"{{"index":2,"record_id":"{RESPONSE_ID}","rule":"wrong_target_uri","expected":"{TARGET}","found":null}}"#
            )
        );
    }
}
