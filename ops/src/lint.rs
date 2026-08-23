//! Lint a WARC file against conventions stricter than the standard.
//!
//! [`Linter`] reads a file at the semantic level and checks every record that the standard accepts
//! against these rules:
//!
//! 1. Header fields appear in canonical order. Standard fields precede extension fields; repeated
//!    and extension fields retain their relative order.
//! 2. The first record is a `warcinfo` record.
//! 3. Every other record names, in `WARC-Warcinfo-ID`, the `warcinfo` record that most closely
//!    precedes it.
//! 4. Every record with a payload the block determines carries a `WARC-Payload-Digest`. Those are
//!    `resource` and `conversion` records, and `request` and `response` records holding HTTP
//!    messages. A `revisit` record's payload lies elsewhere, and a `continuation` record's payload
//!    is digested in its first segment, so neither is held to this rule.
//! 5. Every record carries a `WARC-Block-Digest`.
//! 6. Every record with a block carries a `Content-Type` fitting its type: `application/warc-fields`
//!    for `warcinfo` and `metadata`, `application/http;msgtype=request` for `request`, and
//!    `application/http;msgtype=response` for `response` and for a `revisit` with a block.
//!    A `continuation` record carries no `Content-Type`, as the standard says.
//! 7. A capture is written as three consecutive records: a `request`, then the `response` (or the
//!    `revisit` standing in for it) naming the request alone in `WARC-Concurrent-To`, then a
//!    `metadata` record naming the response alone. The response and the metadata record repeat the
//!    request's `WARC-Target-URI`, and the metadata record's `application/warc-fields` body carries
//!    a `fetchTimeMs` field. A `metadata` record outside a capture is not held to these rules.
//! 8. Every `warcinfo` record names its collection in an `isPartOf` field, as a host, any number of
//!    path parts, and a timestamp of digits, all joined by `-`, and its `WARC-Filename` is that
//!    identifier followed by `.warc.gz`. A path part such as `en` holds no `.`, which tells it from
//!    the host.
//! 9. Every `request` record's target URI has, as its host, exactly the host of the collection
//!    identifier named by the `warcinfo` record that most closely precedes it. A request that no
//!    well-formed collection identifier governs is not held to this rule.
//!
//! Each rule a record breaks is one [`Finding`]. A record that breaks none is reported by its
//! identifier alone.

use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::io::BufRead;

use archivindex_warc::io::read::{self, UntypedIter, WarcReader};
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::parse::untyped::{self};
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::fields::dcmi::DcmiTerm;
use archivindex_warc::record::fields::metadata::MetadataField;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::record::header::WarcinfoHeader;
use archivindex_warc::record::{FieldsBlock, Record};
use archivindex_warc::value::{MediaType, Text};
use fluent_uri::Uri;

/// A rule a record breaks.
///
/// The module documentation lists the rules. The fields carry what the rule expected and what the
/// record had, where that is not obvious from the variant.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Violation {
    /// Two adjacent fields appear in the opposite of canonical order.
    #[error("`{following}` should appear before `{preceding}`")]
    NonCanonicalHeaderOrder {
        /// The earlier field, whose canonical rank is later.
        preceding: String,
        /// The later field, whose canonical rank is earlier.
        following: String,
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
        expected: Option<Uri<String>>,
        /// The record the field names.
        found: Uri<String>,
    },
    /// A record whose block determines its payload carries no `WARC-Payload-Digest`.
    #[error("the record has a payload but carries no `WARC-Payload-Digest`")]
    MissingPayloadDigest,
    /// A record carries no `WARC-Block-Digest`.
    #[error("the record carries no `WARC-Block-Digest`")]
    MissingBlockDigest,
    /// A record with a block carries no `Content-Type`.
    #[error("the record has a block but carries no `Content-Type`")]
    MissingContentType,
    /// A record's `Content-Type` is not the one its type calls for.
    #[error("`Content-Type` should be `{expected}`, but is `{found}`")]
    WrongContentType {
        /// The media type the record's type calls for.
        expected: MediaType,
        /// The media type the record declares.
        found: MediaType,
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
        expected: Uri<String>,
        /// The records the field names.
        found: Vec<Uri<String>>,
    },
    /// A capture record's `WARC-Target-URI` is not the request's.
    #[error("`WARC-Target-URI` should be {expected}, but {}", target_uri(found.as_ref()))]
    WrongTargetUri {
        /// The request's target URI.
        expected: Uri<String>,
        /// The record's target URI, or `None` if it carries none.
        found: Option<Uri<String>>,
    },
    /// A capture's `metadata` record carries no `fetchTimeMs` field.
    #[error("the capture's metadata record carries no `fetchTimeMs` field")]
    MissingFetchTime,
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

/// Describe a target URI's host in a message.
fn host(found: Option<&str>) -> String {
    found.map_or_else(
        || "the URI has none".to_owned(),
        |host| format!("is `{host}`"),
    )
}

/// One rule one record breaks.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub struct Finding {
    /// The record's zero-based position in the file, counting records that failed to read.
    pub index: usize,
    /// The record's `WARC-Record-ID`.
    pub record_id: Uri<String>,
    /// The rule the record breaks.
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
/// yields one `Err` per rule and no `Ok`. The finding is boxed to keep the common case small.
pub type Checked = Result<Uri<String>, Box<Finding>>;

/// The record a capture's next record must name and agree with.
#[derive(Debug)]
struct Pending {
    /// The kind of record expected next.
    slot: Slot,
    /// The position of the record that set the expectation.
    index: usize,
    /// The identifier the next record must name in `WARC-Concurrent-To`.
    record_id: Uri<String>,
    /// The request's target URI, which the next record must repeat.
    target_uri: Uri<String>,
}

/// The record a capture expects next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    /// A `response` or `revisit` record following a `request`.
    Response,
    /// A `metadata` record following a `response` or `revisit`.
    Metadata,
}

/// An iterator over the findings of a lint pass.
///
/// Read errors come through as they are reported by the reader. A stream or framing error ends
/// iteration, as it does for the reader. A record the standard refuses is reported and skipped:
/// it takes a position in the file but is checked against no rule, and a capture waiting on it is
/// forgotten without a finding.
pub struct Linter<R> {
    records: UntypedIter<R>,
    /// The position of the next record read.
    index: usize,
    /// The identifier of the most recent `warcinfo` record.
    warcinfo_id: Option<Uri<String>>,
    /// The host of the collection identifier the most recent `warcinfo` record names, if it
    /// names a well-formed one.
    collection_host: Option<String>,
    /// The capture record expected next, if a capture is under way.
    pending: Option<Pending>,
    /// Results not yet yielded, since one record can produce several.
    queue: VecDeque<Checked>,
}

impl<R: BufRead> Linter<R> {
    /// Lint the WARC records read from `reader`, which must already be decompressed.
    pub fn new(reader: R) -> Self {
        Self {
            records: WarcReader::new(reader).iter_untyped_records(),
            index: 0,
            warcinfo_id: None,
            collection_host: None,
            pending: None,
            queue: VecDeque::new(),
        }
    }

    /// The number of records consumed so far, counting unreadable ones.
    ///
    /// After a read error is yielded, the unreadable record's index is one less than this.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.index
    }

    /// Check one record against every rule and queue what it yields.
    fn check(&mut self, record: &Record, order_violation: Option<Violation>) {
        let index = self.index;
        self.index += 1;

        let expected = self.settle(record);
        let mark = self.queue.len();
        if let Some(violation) = order_violation {
            self.report(index, &record.core().record_id, violation);
        }
        self.check_record(index, record);
        self.check_capture(index, record, expected);
        if self.queue.len() == mark {
            self.queue.push_back(Ok(record.core().record_id.clone()));
        }
    }

    /// Resolve a waiting capture expectation against the record just read.
    ///
    /// Returns the expectation when this record is the kind it waited for. Otherwise the record
    /// that set the expectation gets a finding, and the expectation is dropped.
    fn settle(&mut self, record: &Record) -> Option<Pending> {
        let pending = self.pending.take()?;
        let met = match pending.slot {
            Slot::Response => is_response_slot(record),
            Slot::Metadata => matches!(record, Record::Metadata { .. }),
        };
        if met {
            return Some(pending);
        }

        let found = Some(record.type_name().to_owned());
        let violation = match pending.slot {
            Slot::Response => Violation::RequestWithoutResponse { found },
            Slot::Metadata => Violation::ResponseWithoutMetadata { found },
        };
        self.report(pending.index, &pending.record_id, violation);

        None
    }

    /// Check the rules that look at one record at a time.
    fn check_record(&mut self, index: usize, record: &Record) {
        let record_id = &record.core().record_id;

        if index == 0 && !matches!(record, Record::Warcinfo { .. }) {
            self.report(
                index,
                record_id,
                Violation::FirstRecordNotWarcinfo {
                    found: record.type_name().to_owned(),
                },
            );
        }

        if let Record::Warcinfo { header, body } = record {
            self.warcinfo_id = Some(record_id.clone());
            self.check_collection(index, header, body);
        } else {
            match record.warcinfo_id() {
                None => self.report(index, record_id, Violation::MissingWarcinfoId),
                Some(found) if Some(found) != self.warcinfo_id.as_ref() => self.report(
                    index,
                    record_id,
                    Violation::WrongWarcinfoId {
                        expected: self.warcinfo_id.clone(),
                        found: found.clone(),
                    },
                ),
                Some(_) => {}
            }
        }

        if let Record::Request { header, .. } = record
            && let Some(violation) = self
                .collection_host
                .as_deref()
                .and_then(|expected| wrong_host(expected, &header.target_uri))
        {
            self.report(index, record_id, violation);
        }

        if has_payload(record)
            && record
                .payload()
                .is_some_and(|payload| payload.payload_digest.is_none())
        {
            self.report(index, record_id, Violation::MissingPayloadDigest);
        }

        if record.core().block_digest.is_none() {
            self.report(index, record_id, Violation::MissingBlockDigest);
        }

        match &record.core().content_type {
            None => {
                if record.content_length() > 0 && !matches!(record, Record::Continuation { .. }) {
                    self.report(index, record_id, Violation::MissingContentType);
                }
            }
            Some(found) => {
                if let Some(expected) = expected_content_type(record)
                    && !fits(found, &expected)
                {
                    self.report(
                        index,
                        record_id,
                        Violation::WrongContentType {
                            expected,
                            found: found.clone(),
                        },
                    );
                }
            }
        }
    }

    /// Check that a `warcinfo` record names a well-formed collection and is in the file named for
    /// it, and remember the collection's host for the requests that follow.
    fn check_collection(
        &mut self,
        index: usize,
        header: &WarcinfoHeader,
        body: &FieldsBlock<WarcinfoField>,
    ) {
        let collection = match body {
            FieldsBlock::Fields(fields) => fields.get(&WarcinfoField::Dcmi(DcmiTerm::IsPartOf)),
            FieldsBlock::Raw(_) => None,
        };
        self.collection_host = None;
        let Some(collection) = collection else {
            self.report(
                index,
                &header.core.record_id,
                Violation::MissingCollectionId,
            );
            return;
        };

        match collection_host(collection) {
            Some(host) => self.collection_host = Some(host.to_owned()),
            None => self.report(
                index,
                &header.core.record_id,
                Violation::MalformedCollectionId {
                    found: collection.to_owned(),
                },
            ),
        }

        let named_for_collection = header
            .filename
            .as_ref()
            .and_then(Text::to_str)
            .and_then(|name| name.strip_suffix(".warc.gz"))
            == Some(collection);
        if !named_for_collection {
            self.report(
                index,
                &header.core.record_id,
                Violation::WrongFilename {
                    expected: format!("{collection}.warc.gz"),
                    found: header.filename.clone(),
                },
            );
        }
    }

    /// Check the capture sequence rule and set the expectation for the next record.
    fn check_capture(&mut self, index: usize, record: &Record, expected: Option<Pending>) {
        let record_id = &record.core().record_id;

        match record {
            Record::Request { header, .. } => {
                self.pending = Some(Pending {
                    slot: Slot::Response,
                    index,
                    record_id: record_id.clone(),
                    target_uri: header.target_uri.clone(),
                });
            }
            Record::Response { .. } | Record::Revisit { .. } => match expected {
                Some(pending) => {
                    self.check_links(index, record, &pending);
                    self.pending = Some(Pending {
                        slot: Slot::Metadata,
                        index,
                        record_id: record_id.clone(),
                        target_uri: pending.target_uri,
                    });
                }
                None => self.report(index, record_id, Violation::ResponseWithoutRequest),
            },
            Record::Metadata { body, .. } => {
                if let Some(pending) = expected {
                    self.check_links(index, record, &pending);
                    let has_fetch_time = match body {
                        FieldsBlock::Fields(fields) => {
                            fields.get(&MetadataField::FetchTimeMs).is_some()
                        }
                        FieldsBlock::Raw(_) => false,
                    };
                    if !has_fetch_time {
                        self.report(index, record_id, Violation::MissingFetchTime);
                    }
                }
            }
            Record::Warcinfo { .. }
            | Record::Resource { .. }
            | Record::Conversion { .. }
            | Record::Continuation { .. }
            | Record::Other { .. } => {}
        }
    }

    /// Check that a capture record names the record before it and repeats the request's target.
    fn check_links(&mut self, index: usize, record: &Record, pending: &Pending) {
        let record_id = &record.core().record_id;

        if record.concurrent_to() != std::slice::from_ref(&pending.record_id) {
            self.report(
                index,
                record_id,
                Violation::WrongConcurrentTo {
                    expected: pending.record_id.clone(),
                    found: record.concurrent_to().to_vec(),
                },
            );
        }

        if record.target_uri() != Some(&pending.target_uri) {
            self.report(
                index,
                record_id,
                Violation::WrongTargetUri {
                    expected: pending.target_uri.clone(),
                    found: record.target_uri().cloned(),
                },
            );
        }
    }

    /// Report a capture left waiting at the end of the file.
    fn finish(&mut self) {
        if let Some(pending) = self.pending.take() {
            let violation = match pending.slot {
                Slot::Response => Violation::RequestWithoutResponse { found: None },
                Slot::Metadata => Violation::ResponseWithoutMetadata { found: None },
            };
            self.report(pending.index, &pending.record_id, violation);
        }
    }

    /// Queue a finding.
    fn report(&mut self, index: usize, record_id: &Uri<String>, violation: Violation) {
        self.queue.push_back(Err(Box::new(Finding {
            index,
            record_id: record_id.clone(),
            violation,
        })));
    }
}

impl<R: BufRead> Iterator for Linter<R> {
    type Item = Result<Checked, read::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(checked) = self.queue.pop_front() {
                return Some(Ok(checked));
            }

            match self.records.next() {
                Some(Ok(untyped)) => {
                    let order_violation = canonical_order_violation(&untyped.header);
                    match Record::<NoExtension>::try_from(untyped) {
                        Ok(record) => self.check(&record, order_violation),
                        Err(error) => {
                            self.index += 1;
                            self.pending = None;
                            return Some(Err(error.into()));
                        }
                    }
                }
                Some(Err(error)) => {
                    self.index += 1;
                    self.pending = None;
                    return Some(Err(error));
                }
                None => {
                    self.finish();
                    if self.queue.is_empty() {
                        return None;
                    }
                }
            }
        }
    }
}

/// Report the first adjacent pair whose ranks descend.
fn canonical_order_violation(header: &untyped::RecordHeader) -> Option<Violation> {
    header.headers.windows(2).find_map(|pair| {
        let preceding = &pair[0].0;
        let following = &pair[1].0;
        let rank = |field: Option<Field>| field.map_or(usize::MAX, Field::canonical_rank);
        (rank(preceding.field()) > rank(following.field())).then(|| {
            Violation::NonCanonicalHeaderOrder {
                preceding: preceding.name().to_owned(),
                following: following.name().to_owned(),
            }
        })
    })
}

/// The host of a collection identifier, which is a host, any number of path parts, and a timestamp
/// of digits, all joined by `-`.
///
/// A path part holds no `.`, which tells it from the host. Returns `None` for an identifier not of
/// that form.
fn collection_host(collection: &str) -> Option<&str> {
    let (mut host, timestamp) = collection.rsplit_once('-')?;
    if timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    while let Some((head, part)) = host.rsplit_once('-')
        && !part.contains('.')
    {
        if part.is_empty() {
            return None;
        }
        host = head;
    }

    (!host.is_empty()).then_some(host)
}

/// Report a target URI whose host is not exactly the expected one.
fn wrong_host(expected: &str, target_uri: &Uri<String>) -> Option<Violation> {
    let host = target_uri.authority().map(|authority| authority.host());
    (host != Some(expected)).then(|| Violation::WrongRequestHost {
        expected: expected.to_owned(),
        found: host.map(ToOwned::to_owned),
    })
}

/// Whether a record can stand in the response position of a capture.
const fn is_response_slot(record: &Record) -> bool {
    matches!(record, Record::Response { .. } | Record::Revisit { .. })
}

/// Whether a record's block determines its payload, as WARC 1.1 clause 5.10 defines it.
fn has_payload(record: &Record) -> bool {
    match record {
        Record::Resource { .. } | Record::Conversion { .. } => true,
        Record::Request { .. } | Record::Response { .. } => holds_http_message(record),
        Record::Warcinfo { .. }
        | Record::Metadata { .. }
        | Record::Revisit { .. }
        | Record::Continuation { .. }
        | Record::Other { .. } => false,
    }
}

/// Whether a record declares an HTTP message as its block.
///
/// A missing media type is accepted when the target URI uses HTTP or HTTPS, as the record layer
/// accepts it when extracting a payload.
fn holds_http_message(record: &Record) -> bool {
    record.target_uri().is_some_and(|target_uri| {
        let scheme = target_uri.scheme().as_str();
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    }) && record
        .core()
        .content_type
        .as_ref()
        .is_none_or(|content_type| content_type.is("application", "http"))
}

/// The media type a record's type calls for, or `None` for a type this module does not constrain.
const fn expected_content_type(record: &Record) -> Option<MediaType> {
    match record {
        Record::Warcinfo { .. } | Record::Metadata { .. } => Some(MediaType::WARC_FIELDS),
        Record::Request { .. } => Some(MediaType::HTTP_REQUEST),
        Record::Response { .. } | Record::Revisit { .. } => Some(MediaType::HTTP_RESPONSE),
        Record::Resource { .. }
        | Record::Conversion { .. }
        | Record::Continuation { .. }
        | Record::Other { .. } => None,
    }
}

/// Whether a declared media type is the expected one.
///
/// Types and parameter values are compared without regard to case. Parameters beyond the expected
/// ones, such as a `charset`, are allowed.
fn fits(found: &MediaType, expected: &MediaType) -> bool {
    found.is(expected.type_name(), expected.subtype())
        && expected.parameters().all(|(name, value)| {
            found
                .parameter(name)
                .is_some_and(|declared| declared.as_str().eq_ignore_ascii_case(value.as_str()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WARCINFO_ID: &str = "urn:uuid:aaaaaaaa-0000-4000-8000-000000000000";
    const REQUEST_ID: &str = "urn:uuid:bbbbbbbb-0000-4000-8000-000000000000";
    const RESPONSE_ID: &str = "urn:uuid:cccccccc-0000-4000-8000-000000000000";
    const METADATA_ID: &str = "urn:uuid:dddddddd-0000-4000-8000-000000000000";
    const OTHER_ID: &str = "urn:uuid:eeeeeeee-0000-4000-8000-000000000000";
    const HOST: &str = "example.com";
    const COLLECTION: &str = "example.com-20240401120000";
    const FILENAME: &str = "example.com-20240401120000.warc.gz";
    const TARGET: &str = "https://example.com/";
    const DATE: &str = "2024-04-01T12:00:00Z";
    /// The record layer keeps declared digests without checking them, so one value serves all.
    const DIGEST: &str = "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";
    const REQUEST_BLOCK: &str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const RESPONSE_BLOCK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    /// A record's header fields and block, before rendering.
    #[derive(Clone)]
    struct TestRecord {
        headers: Vec<(&'static str, String)>,
        body: String,
        preserve_header_order: bool,
    }

    impl TestRecord {
        fn new(record_type: &str, id: &str, body: &str) -> Self {
            Self {
                headers: vec![
                    ("WARC-Type", record_type.to_owned()),
                    ("WARC-Record-ID", format!("<{id}>")),
                    ("WARC-Date", DATE.to_owned()),
                    ("WARC-Block-Digest", DIGEST.to_owned()),
                ],
                body: body.to_owned(),
                preserve_header_order: false,
            }
        }

        fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.headers.push((name, value.into()));

            self
        }

        fn set(mut self, name: &str, value: &str) -> Self {
            let (_, current) = self
                .headers
                .iter_mut()
                .find(|(header, _)| *header == name)
                .expect("the field is present");
            *current = value.to_owned();

            self
        }

        fn without(mut self, name: &str) -> Self {
            self.headers.retain(|(header, _)| *header != name);

            self
        }

        fn in_written_order(mut self) -> Self {
            self.preserve_header_order = true;

            self
        }

        /// A WARC 1.1 record, framed by the body's length.
        fn render(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(b"WARC/1.1\r\n");
            let mut headers = self.headers.iter().collect::<Vec<_>>();
            if !self.preserve_header_order {
                headers.sort_by_key(|(name, _)| {
                    Field::from_name(name).map_or(usize::MAX, Field::canonical_rank)
                });
            }
            for (name, value) in headers {
                out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            out.extend_from_slice(
                format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes(),
            );
            out.extend_from_slice(self.body.as_bytes());
            out.extend_from_slice(b"\r\n\r\n");
        }
    }

    fn warcinfo() -> TestRecord {
        warcinfo_with_id(WARCINFO_ID)
    }

    /// A `warcinfo` record naming the collection, in the file named for it.
    fn warcinfo_with_id(id: &str) -> TestRecord {
        TestRecord::new(
            "warcinfo",
            id,
            &format!("software: test\r\nisPartOf: {COLLECTION}\r\n"),
        )
        .with("WARC-Filename", FILENAME)
        .with("Content-Type", "application/warc-fields")
    }

    fn request() -> TestRecord {
        TestRecord::new("request", REQUEST_ID, REQUEST_BLOCK)
            .with("WARC-Target-URI", TARGET)
            .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
            .with("WARC-Payload-Digest", DIGEST)
            .with("Content-Type", "application/http;msgtype=request")
    }

    fn response() -> TestRecord {
        TestRecord::new("response", RESPONSE_ID, RESPONSE_BLOCK)
            .with("WARC-Target-URI", TARGET)
            .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
            .with("WARC-Concurrent-To", format!("<{REQUEST_ID}>"))
            .with("WARC-Payload-Digest", DIGEST)
            .with("Content-Type", "application/http;msgtype=response")
    }

    fn metadata() -> TestRecord {
        TestRecord::new("metadata", METADATA_ID, "fetchTimeMs: 12\r\n")
            .with("WARC-Target-URI", TARGET)
            .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
            .with("WARC-Concurrent-To", format!("<{RESPONSE_ID}>"))
            .with("Content-Type", "application/warc-fields")
    }

    fn resource(id: &str) -> TestRecord {
        TestRecord::new("resource", id, "hello")
            .with("WARC-Target-URI", "https://example.com/resource")
            .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
            .with("WARC-Payload-Digest", DIGEST)
            .with("Content-Type", "text/plain")
    }

    /// A clean capture: a warcinfo record followed by a request, response, metadata triple.
    fn capture() -> Vec<TestRecord> {
        vec![warcinfo(), request(), response(), metadata()]
    }

    fn render(records: &[TestRecord]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            record.render(&mut out);
        }

        out
    }

    fn uri(value: &str) -> Uri<String> {
        Uri::parse(value.to_owned()).expect("a valid URI")
    }

    /// Every item of a lint pass, which must hold no read errors.
    fn lint(records: &[TestRecord]) -> Vec<Checked> {
        Linter::new(&render(records)[..])
            .collect::<Result<_, _>>()
            .expect("every record reads")
    }

    /// The findings of a lint pass, by position.
    fn findings(records: &[TestRecord]) -> Vec<(usize, Violation)> {
        lint(records)
            .into_iter()
            .filter_map(Result::err)
            .map(|finding| (finding.index, finding.violation))
            .collect()
    }

    #[test]
    fn a_clean_capture_yields_every_record_id_in_order() {
        assert_eq!(
            lint(&capture()),
            [WARCINFO_ID, REQUEST_ID, RESPONSE_ID, METADATA_ID]
                .map(|id| Ok(uri(id)))
                .to_vec()
        );
    }

    #[test]
    fn header_fields_are_in_canonical_order() {
        let records = [warcinfo(), resource(OTHER_ID).in_written_order()];

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::NonCanonicalHeaderOrder {
                    preceding: "WARC-Record-ID".to_owned(),
                    following: "WARC-Date".to_owned(),
                }
            )]
        );
    }

    #[test]
    fn a_revisit_stands_in_for_the_response() {
        let mut records = capture();
        records[2] = records[2]
            .clone()
            .set("WARC-Type", "revisit")
            .with(
                "WARC-Profile",
                "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
            )
            .with("WARC-Truncated", "length");

        assert_eq!(findings(&records), []);
    }

    #[test]
    fn the_first_record_must_be_a_warcinfo_record() {
        let records = capture()[1..].to_vec();

        assert_eq!(
            findings(&records),
            [
                (
                    0,
                    Violation::FirstRecordNotWarcinfo {
                        found: "request".to_owned()
                    }
                ),
                (
                    0,
                    Violation::WrongWarcinfoId {
                        expected: None,
                        found: uri(WARCINFO_ID)
                    }
                ),
                (
                    1,
                    Violation::WrongWarcinfoId {
                        expected: None,
                        found: uri(WARCINFO_ID)
                    }
                ),
                (
                    2,
                    Violation::WrongWarcinfoId {
                        expected: None,
                        found: uri(WARCINFO_ID)
                    }
                ),
            ]
        );
    }

    #[test]
    fn every_record_names_the_closest_preceding_warcinfo_record() {
        let mut records = capture();
        records[1] = records[1].clone().without("WARC-Warcinfo-ID");
        records[2] = records[2]
            .clone()
            .set("WARC-Warcinfo-ID", &format!("<{OTHER_ID}>"));
        records.push(warcinfo_with_id(OTHER_ID));
        records.push(resource(RESPONSE_ID));

        assert_eq!(
            findings(&records),
            [
                (1, Violation::MissingWarcinfoId),
                (
                    2,
                    Violation::WrongWarcinfoId {
                        expected: Some(uri(WARCINFO_ID)),
                        found: uri(OTHER_ID)
                    }
                ),
                (
                    5,
                    Violation::WrongWarcinfoId {
                        expected: Some(uri(OTHER_ID)),
                        found: uri(WARCINFO_ID)
                    }
                ),
            ]
        );
    }

    #[test]
    fn records_with_payloads_carry_payload_digests() {
        let mut records = capture();
        records[2] = records[2].clone().without("WARC-Payload-Digest");
        records.push(resource(OTHER_ID).without("WARC-Payload-Digest"));
        records.push(
            TestRecord::new("revisit", OTHER_ID, "")
                .with("WARC-Target-URI", TARGET)
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with(
                    "WARC-Profile",
                    "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
                ),
        );

        assert_eq!(
            findings(&records),
            [
                (2, Violation::MissingPayloadDigest),
                (4, Violation::MissingPayloadDigest),
                (5, Violation::ResponseWithoutRequest),
            ]
        );
    }

    #[test]
    fn a_request_for_a_non_http_target_has_no_payload() {
        let mut records = capture();
        for record in &mut records[1..] {
            *record = record
                .clone()
                .set("WARC-Target-URI", "ftp://example.com/")
                .without("WARC-Payload-Digest");
        }

        assert_eq!(findings(&records), []);
    }

    #[test]
    fn every_record_carries_a_block_digest() {
        let mut records = capture();
        records[0] = records[0].clone().without("WARC-Block-Digest");
        records[3] = records[3].clone().without("WARC-Block-Digest");

        assert_eq!(
            findings(&records),
            [
                (0, Violation::MissingBlockDigest),
                (3, Violation::MissingBlockDigest)
            ]
        );
    }

    #[test]
    fn a_record_with_a_block_carries_a_content_type() {
        let mut records = capture();
        records[2] = records[2].clone().without("Content-Type");
        records.push(
            TestRecord::new("continuation", OTHER_ID, "more")
                .with("WARC-Target-URI", TARGET)
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with("WARC-Segment-Number", "2")
                .with("WARC-Segment-Origin-ID", format!("<{RESPONSE_ID}>")),
        );
        records.push(
            TestRecord::new("revisit", OTHER_ID, "")
                .with("WARC-Target-URI", TARGET)
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with("WARC-Payload-Digest", DIGEST)
                .with(
                    "WARC-Profile",
                    "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
                ),
        );

        assert_eq!(
            findings(&records),
            [
                (2, Violation::MissingContentType),
                (5, Violation::ResponseWithoutRequest),
            ]
        );
    }

    #[test]
    fn a_content_type_fits_the_record_type() {
        let mut records = capture();
        records[0] = records[0].clone().set("Content-Type", "text/plain");
        records[1] = records[1]
            .clone()
            .set("Content-Type", "application/http;msgtype=response");
        records[2] = records[2].clone().set(
            "Content-Type",
            "Application/HTTP; MsgType=Response; charset=utf-8",
        );
        records[3] = records[3].clone().set("Content-Type", "application/json");

        assert_eq!(
            findings(&records),
            [
                (0, Violation::MissingCollectionId),
                (
                    0,
                    Violation::WrongContentType {
                        expected: MediaType::WARC_FIELDS,
                        found: MediaType::TEXT_PLAIN
                    }
                ),
                (
                    1,
                    Violation::WrongContentType {
                        expected: MediaType::HTTP_REQUEST,
                        found: MediaType::HTTP_RESPONSE
                    }
                ),
                (
                    3,
                    Violation::WrongContentType {
                        expected: MediaType::WARC_FIELDS,
                        found: MediaType::JSON
                    }
                ),
                (3, Violation::MissingFetchTime),
            ]
        );
    }

    #[test]
    fn a_request_is_followed_by_its_response() {
        let mut records = capture();
        records.remove(2);

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::RequestWithoutResponse {
                    found: Some("metadata".to_owned())
                }
            )]
        );

        let records = capture()[..2].to_vec();

        assert_eq!(
            findings(&records),
            [(1, Violation::RequestWithoutResponse { found: None })]
        );
    }

    #[test]
    fn a_response_follows_a_request() {
        let mut records = capture();
        records.remove(1);

        assert_eq!(findings(&records), [(1, Violation::ResponseWithoutRequest)]);
    }

    #[test]
    fn a_response_is_followed_by_its_metadata_record() {
        let mut records = capture();
        records[3] = resource(OTHER_ID);

        assert_eq!(
            findings(&records),
            [(
                2,
                Violation::ResponseWithoutMetadata {
                    found: Some("resource".to_owned())
                }
            )]
        );

        let records = capture()[..3].to_vec();

        assert_eq!(
            findings(&records),
            [(2, Violation::ResponseWithoutMetadata { found: None })]
        );
    }

    #[test]
    fn a_second_request_breaks_the_capture_before_it() {
        let mut records = capture();
        records.insert(2, request());

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::RequestWithoutResponse {
                    found: Some("request".to_owned())
                }
            )]
        );
    }

    #[test]
    fn capture_records_name_the_record_before_them_alone() {
        let mut records = capture();
        records[2] = records[2].clone().without("WARC-Concurrent-To");
        records[3] = records[3]
            .clone()
            .with("WARC-Concurrent-To", format!("<{REQUEST_ID}>"));

        assert_eq!(
            findings(&records),
            [
                (
                    2,
                    Violation::WrongConcurrentTo {
                        expected: uri(REQUEST_ID),
                        found: vec![]
                    }
                ),
                (
                    3,
                    Violation::WrongConcurrentTo {
                        expected: uri(RESPONSE_ID),
                        found: vec![uri(RESPONSE_ID), uri(REQUEST_ID)]
                    }
                ),
            ]
        );
    }

    #[test]
    fn capture_records_repeat_the_request_target() {
        let mut records = capture();
        records[2] = records[2]
            .clone()
            .set("WARC-Target-URI", "https://example.com/other");
        records[3] = records[3].clone().without("WARC-Target-URI");

        assert_eq!(
            findings(&records),
            [
                (
                    2,
                    Violation::WrongTargetUri {
                        expected: uri(TARGET),
                        found: Some(uri("https://example.com/other"))
                    }
                ),
                (
                    3,
                    Violation::WrongTargetUri {
                        expected: uri(TARGET),
                        found: None
                    }
                ),
            ]
        );
    }

    #[test]
    fn capture_metadata_carries_a_fetch_time() {
        let mut records = capture();
        records[3].body = "via: https://example.com/\r\n".to_owned();

        assert_eq!(findings(&records), [(3, Violation::MissingFetchTime)]);
    }

    #[test]
    fn a_warcinfo_record_names_its_collection_and_its_file() {
        let mut records = capture();
        records[0].body = "software: test\r\n".to_owned();
        records.push(warcinfo_with_id(OTHER_ID).without("WARC-Filename"));
        records.push(warcinfo_with_id(OTHER_ID).set("WARC-Filename", "other.warc"));

        assert_eq!(
            findings(&records),
            [
                (0, Violation::MissingCollectionId),
                (
                    4,
                    Violation::WrongFilename {
                        expected: FILENAME.to_owned(),
                        found: None
                    }
                ),
                (
                    5,
                    Violation::WrongFilename {
                        expected: FILENAME.to_owned(),
                        found: Text::parse(b"other.warc").ok()
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_collection_id_is_a_host_path_parts_and_a_timestamp() {
        for (collection, host) in [
            ("example.com-en-20240401120000", Some("example.com")),
            ("example.com-en-mobile-20240401120000", Some("example.com")),
            ("my-site.com-en-20240401120000", Some("my-site.com")),
            ("localhost-20240401120000", Some("localhost")),
            ("example.com--20240401120000", None),
            ("-en-20240401120000", None),
        ] {
            assert_eq!(collection_host(collection), host, "{collection}");
        }

        let malformed = [HOST, "example.com-", "-20240401120000", "example.com-today"];
        let mut records = capture();
        for (index, collection) in malformed.into_iter().enumerate() {
            let mut warcinfo = warcinfo_with_id(OTHER_ID);
            warcinfo.body = format!("software: test\r\nisPartOf: {collection}\r\n");
            records.push(warcinfo.set("WARC-Filename", &format!("{collection}.warc.gz")));
            if index == 0 {
                records.extend(capture()[1..].iter().map(|record| {
                    record
                        .clone()
                        .set("WARC-Warcinfo-ID", &format!("<{OTHER_ID}>"))
                        .set("WARC-Target-URI", "https://www.example.com/")
                }));
            }
        }

        assert_eq!(
            findings(&records),
            [4, 8, 9, 10]
                .into_iter()
                .zip(malformed)
                .map(|(index, found)| {
                    (
                        index,
                        Violation::MalformedCollectionId {
                            found: found.to_owned(),
                        },
                    )
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn requests_target_the_collection_host() {
        let mut records = capture();
        records[1] = records[1]
            .clone()
            .set("WARC-Target-URI", "https://Example.COM/");
        let mut other = capture()[1..].to_vec();
        for record in &mut other {
            *record = record
                .clone()
                .set("WARC-Target-URI", "https://www.example.com/");
        }
        records.extend(other);
        let mut hostless = capture()[1..].to_vec();
        for record in &mut hostless {
            *record = record
                .clone()
                .set("WARC-Target-URI", "urn:isbn:0451450523")
                .without("WARC-Payload-Digest");
        }
        records.extend(hostless);

        assert_eq!(
            findings(&records),
            [
                (
                    1,
                    Violation::WrongRequestHost {
                        expected: HOST.to_owned(),
                        found: Some("Example.COM".to_owned())
                    }
                ),
                (
                    2,
                    Violation::WrongTargetUri {
                        expected: uri("https://Example.COM/"),
                        found: Some(uri(TARGET))
                    }
                ),
                (
                    3,
                    Violation::WrongTargetUri {
                        expected: uri("https://Example.COM/"),
                        found: Some(uri(TARGET))
                    }
                ),
                (
                    4,
                    Violation::WrongRequestHost {
                        expected: HOST.to_owned(),
                        found: Some("www.example.com".to_owned())
                    }
                ),
                (
                    7,
                    Violation::WrongRequestHost {
                        expected: HOST.to_owned(),
                        found: None
                    }
                ),
            ]
        );
    }

    #[test]
    fn requests_outside_a_collection_are_unconstrained() {
        let mut records = capture();
        records[0].body = "software: test\r\n".to_owned();
        records[1] = records[1]
            .clone()
            .set("WARC-Target-URI", "https://www.example.com/");

        assert!(
            findings(&records)
                .iter()
                .all(|(_, violation)| !matches!(violation, Violation::WrongRequestHost { .. }))
        );
    }

    #[test]
    fn metadata_outside_a_capture_is_unconstrained() {
        let mut records = capture();
        records.push(
            TestRecord::new("metadata", OTHER_ID, "via: https://example.com/\r\n")
                .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
                .with("WARC-Refers-To", format!("<{RESPONSE_ID}>"))
                .with("Content-Type", "application/warc-fields"),
        );

        assert_eq!(findings(&records), []);
    }

    #[test]
    fn an_unreadable_record_is_passed_through_and_forgets_the_capture() {
        let mut records = capture();
        records[2] = records[2].clone().set("WARC-Date", "yesterday");

        let items: Vec<_> = Linter::new(&render(&records)[..]).collect();

        assert_eq!(items.len(), 4);
        assert!(matches!(&items[0], Ok(Ok(id)) if id == &uri(WARCINFO_ID)));
        assert!(matches!(&items[1], Ok(Ok(id)) if id == &uri(REQUEST_ID)));
        assert!(matches!(items[2], Err(read::Error::Untyped(_))));
        assert!(matches!(&items[3], Ok(Ok(id)) if id == &uri(METADATA_ID)));
    }

    #[test]
    fn a_stream_error_ends_iteration() {
        let mut bytes = render(&capture());
        bytes.truncate(bytes.len() - 10);

        let items: Vec<_> = Linter::new(&bytes[..]).collect();

        assert_eq!(items.len(), 4);
        assert!(matches!(items[3], Err(read::Error::UnexpectedEndOfBody)));
    }

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
    }

    #[test]
    fn lints_a_real_archive() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/data/warcio/example-iana.org-chunked.warc"
        ))
        .expect("the fixture is present");

        let checked: Vec<Checked> = Linter::new(&bytes[..])
            .collect::<Result<_, _>>()
            .expect("every record reads");

        assert!(checked.iter().all(Result::is_err));
        assert_eq!(
            checked
                .into_iter()
                .filter_map(Result::err)
                .map(|finding| (finding.index, finding.violation))
                .collect::<Vec<_>>(),
            [
                (
                    0,
                    Violation::NonCanonicalHeaderOrder {
                        preceding: "WARC-Record-ID".to_owned(),
                        following: "WARC-Type".to_owned(),
                    }
                ),
                (0, Violation::MissingCollectionId),
                (0, Violation::MissingBlockDigest),
                (
                    1,
                    Violation::NonCanonicalHeaderOrder {
                        preceding: "WARC-Record-ID".to_owned(),
                        following: "WARC-Date".to_owned(),
                    }
                ),
                (1, Violation::MissingWarcinfoId),
                (1, Violation::ResponseWithoutRequest),
                (
                    2,
                    Violation::NonCanonicalHeaderOrder {
                        preceding: "WARC-Record-ID".to_owned(),
                        following: "WARC-Date".to_owned(),
                    }
                ),
                (2, Violation::MissingWarcinfoId),
                (2, Violation::MissingPayloadDigest),
                (2, Violation::RequestWithoutResponse { found: None }),
            ]
        );
    }
}
