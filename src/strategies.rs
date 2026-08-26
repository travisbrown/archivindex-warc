//! Proptest strategies for the record representations and the grammars their values are read
//! against.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use fluent_uri::Uri;
use proptest::prelude::*;
use proptest::sample::select;

use crate::parse::raw;
use crate::parse::untyped::name::Field;
use crate::parse::untyped::value::ValueForm;
use crate::record::extension::NoExtension;
use crate::record::fields::warcinfo::{WarcinfoBody, WarcinfoField};
use crate::record::header::truncated_type::TruncatedType;
use crate::record::header::{
    ContinuationHeader, ConversionHeader, CoreHeaders, MetadataHeader, PayloadHeaders,
    RequestHeader, ResourceHeader, ResponseHeader, RevisitHeader, RevisitProfile, SegmentNumber,
    WarcinfoHeader,
};
use crate::record::{FieldsBlock, Record};
use crate::value::{Algorithm, LabelledDigest, MediaType, Text, WarcDate, WarcDatePrecision};
use crate::version::WarcVersion;

/// Characters the `token` grammar admits, spanning both of its letter cases and each of the
/// punctuation marks a separator could be mistaken for.
const TOKEN_CHARS: &[char] = &['a', 'Z', '0', '9', '-', '_', '.', '!', '~', '*', '\''];

/// Fragments a `TEXT` value is built from, including octets that are not ASCII and the two
/// characters a `quoted-string` has to escape.
const TEXT_FRAGMENTS: &[&str] = &["a", "Z9", "-", "x y", "\t", "é", "日", "\\", "\""];

/// A version of the standard.
pub fn warc_version() -> impl Strategy<Value = WarcVersion> {
    select(vec![WarcVersion::V1_0, WarcVersion::V1_1])
}

/// A `token`.
pub fn token() -> impl Strategy<Value = String> {
    proptest::collection::vec(select(TOKEN_CHARS), 1..=12)
        .prop_map(|chars| chars.into_iter().collect())
}

/// A `TEXT` value, written bare or as a `quoted-string`.
///
/// The content neither opens nor closes with white space, which a field value is read without,
/// and opens with a character that does not begin a `quoted-string`.
pub fn text() -> impl Strategy<Value = Text> {
    (
        select(&['a', 'Z', '0', 'é']),
        proptest::collection::vec(select(TEXT_FRAGMENTS), 0..=5),
        select(&['a', 'Z', '9']),
        any::<bool>(),
    )
        .prop_map(|(first, fragments, last, quoted)| {
            let content = format!("{first}{}{last}", fragments.concat());
            let spelled = if quoted {
                let escaped = content.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{escaped}\"")
            } else {
                content
            };

            Text::parse(spelled.as_bytes()).expect("invariant violation: a generated TEXT value")
        })
}

/// An absolute URI, with a path, a query, and a fragment that may hold characters RFC 3986
/// requires be percent-encoded.
pub fn uri() -> impl Strategy<Value = Uri<String>> {
    (
        select(vec!["http", "https", "urn", "dns"]),
        select(vec!["//example.com", "//example.org:8080", "uuid:0-1-2"]),
        proptest::collection::vec(
            select(vec!["a", "Z", "0", "-", "~", "%20", "%C3%A9"]),
            0..=4,
        ),
        proptest::option::of(select(vec!["q=1", "q=%20", ""])),
        proptest::option::of(select(vec!["top", "%C3%A9", ""])),
    )
        .prop_map(|(scheme, authority, segments, query, fragment)| {
            let path = if authority.starts_with("//") {
                segments
                    .iter()
                    .fold(String::new(), |path, segment| path + "/" + segment)
            } else {
                segments.concat()
            };
            let query = query.map_or_else(String::new, |query| format!("?{query}"));
            let fragment = fragment.map_or_else(String::new, |fragment| format!("#{fragment}"));

            Uri::parse(format!("{scheme}:{authority}{path}{query}{fragment}"))
                .expect("invariant violation: a generated URI parses")
        })
}

/// An IPv4 or IPv6 address.
pub fn ip_address() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        any::<[u8; 16]>().prop_map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
    ]
}

/// A date at a precision the given version can spell.
///
/// WARC 1.0 writes seconds and nothing else, so a value at any other precision is one that
/// version cannot round-trip.
pub fn warc_date(version: WarcVersion) -> impl Strategy<Value = WarcDate> {
    let precisions = match version {
        WarcVersion::V1_0 => vec![WarcDatePrecision::Second],
        WarcVersion::V1_1 => vec![
            WarcDatePrecision::Year,
            WarcDatePrecision::Month,
            WarcDatePrecision::Day,
            WarcDatePrecision::Minute,
            WarcDatePrecision::Second,
            WarcDatePrecision::Fraction(1),
            WarcDatePrecision::Fraction(3),
            WarcDatePrecision::Fraction(9),
        ],
    };

    // The range spans the whole four-digit year the grammar writes.
    (
        0..=253_402_300_799_i64,
        0..1_000_000_000_u32,
        select(precisions),
    )
        .prop_map(|(seconds, nanoseconds, precision)| {
            let date_time = DateTime::<Utc>::from_timestamp(seconds, nanoseconds)
                .expect("invariant violation: a generated instant is in range");

            WarcDate::new(date_time, precision)
        })
}

/// A `media-type`, with parameters written bare, quoted, and with the optional white space the
/// grammar allows around each separator.
pub fn media_type() -> impl Strategy<Value = MediaType> {
    (
        token(),
        token(),
        proptest::collection::vec(
            (
                select(vec!["", " ", "\t"]),
                token(),
                select(vec!["v", "\"quoted value\"", "\"with \\\" escape\""]),
            ),
            0..=3,
        ),
        // A `;` closing the value introduces no parameter, which archives write and this crate
        // keeps. White space after it is not generated, since a field line is read without its
        // trailing white space.
        select(vec!["", ";"]),
    )
        .prop_map(|(type_name, subtype, parameters, trailing)| {
            let mut spelled = format!("{type_name}/{subtype}");
            for (space, name, value) in parameters {
                spelled.push(';');
                spelled.push_str(space);
                spelled.push_str(&name);
                spelled.push('=');
                spelled.push_str(value);
            }
            spelled.push_str(trailing);

            MediaType::parse(spelled.as_bytes())
                .expect("invariant violation: a generated media type parses")
        })
}

/// A `labelled-digest` of a length its algorithm produces.
pub fn labelled_digest() -> impl Strategy<Value = LabelledDigest> {
    select(Algorithm::ALL.as_slice()).prop_flat_map(|algorithm| {
        proptest::collection::vec(any::<u8>(), algorithm.digest_length())
            .prop_map(move |digest| LabelledDigest::from_digest(algorithm, &digest))
    })
}

/// A parsed field value of any of the grammars a defined field selects.
pub fn value_form(version: WarcVersion) -> impl Strategy<Value = ValueForm> {
    prop_oneof![
        (uri(), any::<bool>()).prop_map(|(uri, bracketed)| ValueForm::Uri { uri, bracketed }),
        warc_date(version).prop_map(ValueForm::Date),
        any::<u64>().prop_map(ValueForm::Digits),
        token().prop_map(|token| ValueForm::Token(token.into())),
        labelled_digest().prop_map(ValueForm::Digest),
        media_type().prop_map(ValueForm::MediaType),
        text().prop_map(ValueForm::Text),
        ip_address().prop_map(ValueForm::IpAddress),
    ]
}

/// A field line of a raw header block: a `token` name and a value written with the leading white
/// space, folds, and trailing white space the grammar admits.
fn raw_field() -> impl Strategy<Value = (String, Vec<u8>)> {
    (
        token(),
        select(vec!["", " ", "  ", "\t"]),
        proptest::collection::vec(select(vec!["a", "Z9", "-", "x y", "é"]), 1..=4),
        select(vec!["", "\r\n ", "\r\n\t"]),
        select(vec!["", " "]),
    )
        .prop_map(|(name, leading, fragments, fold, trailing)| {
            let value = format!("{leading}{}{fold}{}{trailing}", fragments.concat(), "tail");

            (name, value.into_bytes())
        })
}

/// A raw record whose `Content-Length` frames its block.
pub fn raw_record() -> impl Strategy<Value = raw::Record> {
    (
        warc_version(),
        proptest::collection::vec(raw_field(), 0..=6),
        proptest::collection::vec(any::<u8>(), 0..=64),
    )
        .prop_map(|(version, fields, body)| {
            let mut header = raw::RecordHeader::new(version);
            header.headers = fields
                // A `Content-Length` written among the generated fields would frame a block other
                // than this one, so the name is left to the field appended below.
                .into_iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("Content-Length"))
                .collect();
            header.headers.push((
                "Content-Length".to_owned(),
                format!(" {}", body.len()).into_bytes(),
            ));

            header.with_body(body)
        })
}

/// A truncation reason, either one the standard names or one it does not.
fn truncated() -> impl Strategy<Value = TruncatedType> {
    prop_oneof![
        select(vec![
            TruncatedType::Length,
            TruncatedType::Time,
            TruncatedType::Disconnect,
            TruncatedType::Unspecified,
        ]),
        // An unknown reason is normalized to lower case as it is read, so only a lower-case
        // spelling survives a round trip.
        token().prop_map(|token| TruncatedType::Unknown(token.to_lowercase())),
    ]
}

/// Fields claimed by neither the standard nor the extension in force.
///
/// Names are prefixed so that they cannot collide with a field the standard defines, which a
/// record of a standard type cannot carry beside the typed field of the same name.
fn unrecognized() -> impl Strategy<Value = Vec<(String, String)>> {
    proptest::collection::vec(
        (token(), token()).prop_map(|(name, value)| (format!("X-{name}"), value)),
        0..=3,
    )
}

/// The fields every record carries, with the digest and length that rendering supplies left out.
fn core(version: WarcVersion) -> impl Strategy<Value = CoreHeaders> {
    (
        uri(),
        warc_date(version),
        proptest::option::of(media_type()),
        proptest::option::of(truncated()),
        unrecognized(),
    )
        .prop_map(
            |(record_id, date, content_type, truncated, unrecognized)| CoreHeaders {
                record_id,
                date,
                content_length: None,
                block_digest: None,
                content_type,
                truncated,
                unrecognized,
            },
        )
}

/// The fields describing a record's payload, with the digest that rendering supplies left out.
fn payload() -> impl Strategy<Value = PayloadHeaders> {
    proptest::option::of(media_type()).prop_map(|identified_payload_type| PayloadHeaders {
        payload_digest: None,
        identified_payload_type,
    })
}

/// A block of octets.
fn body() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=64)
}

/// An `application/warc-fields` block, built rather than parsed so that it carries no source
/// block of its own.
fn warcinfo_body() -> impl Strategy<Value = WarcinfoBody> {
    proptest::collection::vec(
        (
            select(vec![
                WarcinfoField::Operator,
                WarcinfoField::Software,
                WarcinfoField::Hostname,
            ]),
            token(),
        ),
        0..=4,
    )
    .prop_map(|fields| {
        let mut body = WarcinfoBody::new();
        for (field, value) in fields {
            body.push(field, value)
                .expect("invariant violation: a generated warc-fields line is writable");
        }

        body
    })
}

/// A `revisit` profile, and a block and truncation reason the profile admits.
///
/// The identical payload digest profile asserts that the payload is elsewhere, so a record under
/// it carries a payload digest and, unless it declares the truncation, no block.
fn revisit_profile() -> impl Strategy<Value = (RevisitProfile, Option<LabelledDigest>)> {
    prop_oneof![
        (warc_version(), labelled_digest()).prop_map(|(version, digest)| (
            RevisitProfile::IdenticalPayloadDigest(version),
            Some(digest)
        )),
        select(vec![
            RevisitProfile::ServerNotModified(WarcVersion::V1_0),
            RevisitProfile::ServerNotModified(WarcVersion::V1_1),
        ])
        .prop_map(|profile| (profile, None)),
        uri().prop_map(|uri| (RevisitProfile::Other(uri.to_string()), None)),
    ]
}

/// A record of any type the standard defines, at a version that can spell every value it carries.
pub fn record() -> impl Strategy<Value = Record<NoExtension>> {
    warc_version().prop_flat_map(record_of_version)
}

/// A record whose header carries the core, payload, and capture fields and nothing besides.
///
/// The three record types this covers differ only in the name of their header type.
macro_rules! capture_record {
    ($version:expr, $record:ident, $header:ident) => {
        (core($version), payload(), capture_fields(), body())
            .prop_map(move |(core, payload, capture, body)| {
                let (target_uri, warcinfo_id, ip_address, concurrent_to, segment_origin) = capture;

                Record::$record {
                    header: $header {
                        version: $version,
                        core,
                        payload,
                        target_uri,
                        warcinfo_id,
                        ip_address,
                        concurrent_to,
                        segment_origin,
                        other: (),
                    },
                    body,
                }
            })
            .boxed()
    };
}

/// A record declaring the given version.
fn record_of_version(version: WarcVersion) -> impl Strategy<Value = Record<NoExtension>> {
    prop_oneof![
        warcinfo_record(version),
        capture_record!(version, Response, ResponseHeader),
        capture_record!(version, Resource, ResourceHeader),
        capture_record!(version, Request, RequestHeader),
        metadata_record(version),
        revisit_record(version),
        conversion_record(version),
        continuation_record(version),
    ]
}

/// A `warcinfo` record, whose block is the fields it declares.
fn warcinfo_record(version: WarcVersion) -> BoxedStrategy<Record<NoExtension>> {
    (
        core(version),
        proptest::option::of(text()),
        any::<bool>(),
        warcinfo_body(),
    )
        .prop_map(move |(core, filename, segment_origin, body)| {
            let mut header = WarcinfoHeader {
                version,
                core,
                filename,
                segment_origin,
                other: (),
            };
            header.core.content_type = Some(MediaType::WARC_FIELDS);

            Record::Warcinfo {
                header,
                body: FieldsBlock::Fields(body),
            }
        })
        .boxed()
}

/// A `metadata` record, whose block is read as fields only when it declares them.
fn metadata_record(version: WarcVersion) -> BoxedStrategy<Record<NoExtension>> {
    (
        core(version),
        capture_fields(),
        proptest::option::of(uri()),
        body(),
    )
        .prop_map(move |(core, capture, refers_to, body)| {
            let (target_uri, warcinfo_id, ip_address, concurrent_to, segment_origin) = capture;

            Record::Metadata {
                header: MetadataHeader {
                    version,
                    core,
                    target_uri: Some(target_uri),
                    warcinfo_id,
                    ip_address,
                    concurrent_to,
                    refers_to,
                    segment_origin,
                    other: (),
                },
                body: FieldsBlock::Raw(body),
            }
        })
        .boxed()
}

/// A `revisit` record, whose profile settles its digest and block.
fn revisit_record(version: WarcVersion) -> BoxedStrategy<Record<NoExtension>> {
    (
        core(version),
        payload(),
        capture_fields(),
        revisit_profile(),
        proptest::option::of(uri()),
        proptest::option::of(uri()),
    )
        .prop_map(
            move |(core, payload, capture, profile, refers_to, refers_to_target_uri)| {
                let (target_uri, warcinfo_id, ip_address, concurrent_to, segment_origin) = capture;
                let (profile, payload_digest) = profile;

                Record::Revisit {
                    header: RevisitHeader {
                        version,
                        core,
                        payload: PayloadHeaders {
                            payload_digest,
                            ..payload
                        },
                        target_uri,
                        warcinfo_id,
                        profile,
                        ip_address,
                        concurrent_to,
                        refers_to,
                        // The two fields WARC 1.1 named are the two 1.0 cannot write.
                        refers_to_target_uri: refers_to_target_uri
                            .filter(|_| version == WarcVersion::V1_1),
                        refers_to_date: None,
                        segment_origin,
                        other: (),
                    },
                    body: Vec::new(),
                }
            },
        )
        .boxed()
}

/// A `conversion` record.
fn conversion_record(version: WarcVersion) -> BoxedStrategy<Record<NoExtension>> {
    (
        core(version),
        payload(),
        capture_fields(),
        proptest::option::of(uri()),
        body(),
    )
        .prop_map(move |(core, payload, capture, refers_to, body)| {
            let (target_uri, warcinfo_id, _, _, segment_origin) = capture;

            Record::Conversion {
                header: ConversionHeader {
                    version,
                    core,
                    payload,
                    target_uri,
                    warcinfo_id,
                    refers_to,
                    segment_origin,
                    other: (),
                },
                body,
            }
        })
        .boxed()
}

/// A `continuation` record, numbered from the two its first continuation carries.
fn continuation_record(version: WarcVersion) -> BoxedStrategy<Record<NoExtension>> {
    (
        core(version),
        payload(),
        capture_fields(),
        2..=u64::MAX,
        uri(),
        proptest::option::of(any::<u64>()),
        body(),
    )
        .prop_map(
            move |(core, payload, capture, number, segment_origin_id, total_length, body)| {
                let (target_uri, warcinfo_id, _, _, _) = capture;

                Record::Continuation {
                    header: ContinuationHeader {
                        version,
                        core,
                        payload,
                        target_uri,
                        warcinfo_id,
                        segment_number: SegmentNumber::new(number)
                            .expect("invariant violation: a generated segment number is valid"),
                        segment_origin_id,
                        segment_total_length: total_length,
                        other: (),
                    },
                    body,
                }
            },
        )
        .boxed()
}

/// The fields a record describing a capture carries beside its core and payload fields.
type CaptureFields = (
    Uri<String>,
    Option<Uri<String>>,
    Option<IpAddr>,
    Vec<Uri<String>>,
    bool,
);

/// A target URI and the optional fields that accompany it on a capture.
fn capture_fields() -> impl Strategy<Value = CaptureFields> {
    (
        uri(),
        proptest::option::of(uri()),
        proptest::option::of(ip_address()),
        proptest::collection::vec(uri(), 0..=2),
        any::<bool>(),
    )
}

/// A defined field and a value of the grammar its name selects.
pub fn field_and_form() -> impl Strategy<Value = (Field, ValueForm)> {
    // Every value is read against the 1.1 grammar here, which admits each spelling 1.0 has.
    value_form(WarcVersion::V1_1).prop_map(|form| {
        let field = match form {
            ValueForm::Uri { .. } => Field::TargetURI,
            ValueForm::Date(_) => Field::Date,
            ValueForm::Digits(_) => Field::ContentLength,
            ValueForm::Token(_) => Field::WarcType,
            ValueForm::Digest(_) => Field::BlockDigest,
            ValueForm::MediaType(_) => Field::ContentType,
            ValueForm::Text(_) => Field::Filename,
            ValueForm::IpAddress(_) => Field::IPAddress,
        };

        (field, form)
    })
}
