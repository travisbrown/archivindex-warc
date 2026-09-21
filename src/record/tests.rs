use std::net::Ipv4Addr;

use proptest::prelude::*;
use proptest::property_test;

use super::*;
use crate::record::extension::{ExtensionFields, ExtensionTruncatedReason, Never, Unclaimed};
use crate::record::header::SegmentNumber;
use crate::strategies;
use crate::value::{Encoding, Text, marker};

const RECORD_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";
const DATE: &str = "2020-07-08T02:52:55Z";

/// The block the block-digest tests declare digests of.
const DIGESTED_BLOCK: &[u8] = b"hello";

/// Build a grammatical record from header lines for semantic conversion tests.
///
/// The three fields every record carries come first, so that each test writes only the lines
/// its own record type adds to them.
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

/// Lift a grammatical record under the core vocabulary alone, which is what the tests here mean
/// by `Record` unless they name an extension.
fn lift_grammar(grammar: untyped::Record) -> Result<Record, Error> {
    Record::try_from(grammar)
}

/// Lift a WARC 1.1 record of the given type under the core vocabulary alone.
fn lift(record_type: &str, lines: &[(&str, &str)]) -> Result<Record, Error> {
    lift_grammar(grammar(record_type, lines))
}

/// Lift the header block of a WARC 1.1 record of the given type, framing the given block.
///
/// The block itself is dropped, since a header block is what is wanted here, but the length it
/// is framed by is what the header block declares.
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

/// The names a rendered record's block is written with, in order.
fn written_names(record: &raw::Record) -> Vec<&str> {
    record
        .header
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect()
}

/// A vocabulary standing in for a small archiving extension: one record type of its own, one
/// truncation reason, and one field it adds to `warcinfo` records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Sitemaps;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SitemapType {
    /// A type of the extension's own, spelled with a capital to pin down that a record is
    /// written under the name its type gives itself rather than the one it was read with.
    Sitemap,
    /// A type that answers to a name of its own and then names one the standard defines, which
    /// is what a record must not be lifted as.
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

/// A vocabulary whose one field spells the name of a field the standard defines, which is what
/// no record may be written with twice.
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

/// A vocabulary whose one field spells the name of a field the standard defines for the record
/// type it is attached to, which is what no record may be written with twice.
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
    assert_eq!(header.core.unrecognized, []);
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
        header.filename.as_ref().map(Text::to_str_lossy).as_deref(),
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
    assert_eq!(again, record);
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

/// The length of a record's block is measured when it is asked for, so it follows a block that
/// is edited, and it is the length the record renders under.
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
    // canonically and is longer than the block by that one line, not by that line and the space
    // the original block wasted. The length the record was read declaring is the length of a
    // block it no longer carries, so it is cleared for the block to answer.
    record.core_mut().content_length = None;

    let length = record.content_length();
    let raw = record.into_raw().expect("renderable record");
    assert_eq!(raw.body.len() as u64, length);
    assert_eq!(raw.content_length(), length);
}

/// Both complete records and standalone headers retain the declared content length.
#[test]
fn a_declared_length_is_kept_as_it_was_read() {
    let lines = [("WARC-Target-URI", "http://example.com/")];

    let record = lift_grammar(grammar_of(WarcVersion::V1_1, "response", &lines, b"hello"))
        .expect("liftable record");
    assert_eq!(record.core().content_length, Some(5));

    let header = lift_header("response", &lines, b"hello").expect("liftable header block");
    assert_eq!(header.core().content_length, Some(5));
}

/// Attaching a body checks its length against the header's declaration.
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

/// Rendering checks the content length of directly constructed or modified records.
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

/// Rendering with digests gives a record declaring no block digest one.
#[test]
fn a_record_declaring_no_block_digest_is_given_one() {
    let raw = lift_grammar(grammar_of(
        WarcVersion::V1_1,
        "response",
        &[("WARC-Target-URI", "http://example.com/")],
        DIGESTED_BLOCK,
    ))
    .expect("liftable record")
    .into_raw_with_digests(marker::Sha256)
    .expect("renderable record");

    assert_eq!(
        written(&raw, "WARC-Block-Digest").as_deref(),
        Some("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    );
}

#[test]
fn added_digests_are_written_in_the_chosen_format() {
    let raw = payload_record("response", &[], RESPONSE_BLOCK)
        .into_raw_with_digests_in(
            DigestFormat {
                algorithm: Algorithm::Sha1,
                encoding: Encoding::Base16,
            },
            DigestFormat::recommended(Algorithm::Sha256),
        )
        .expect("renderable record");

    assert_eq!(
        written(&raw, "WARC-Block-Digest").as_deref(),
        Some("sha1:43a34659680d1ddd9b394cbe523a9b40c7b01427")
    );
    assert_eq!(
        written(&raw, "WARC-Payload-Digest").as_deref(),
        Some(ADDED_PAYLOAD_DIGEST)
    );
}

/// A build enabling every algorithm leaves nothing to check.
#[test]
fn a_digest_cannot_be_added_with_an_algorithm_the_build_lacks() {
    let Some(algorithm) = Algorithm::ALL
        .into_iter()
        .find(|algorithm| !algorithm.is_supported())
    else {
        return;
    };

    let result = lift_grammar(grammar_of(
        WarcVersion::V1_1,
        "response",
        &[("WARC-Target-URI", "http://example.com/")],
        DIGESTED_BLOCK,
    ))
    .expect("liftable record")
    .into_raw_with_digests_in(
        DigestFormat::recommended(Algorithm::Sha256),
        DigestFormat::recommended(algorithm),
    );

    assert!(matches!(
        result,
        Err(RenderError::UnsupportedDigestAlgorithm(found)) if found == algorithm
    ));
}

/// Digest options do not skip validation of declared digests.
#[test]
fn added_digests_follow_the_rendering_the_caller_chose() {
    let record = || {
        lift_grammar(grammar_of(
            WarcVersion::V1_1,
            "response",
            &[("WARC-Target-URI", "http://example.com/")],
            DIGESTED_BLOCK,
        ))
        .expect("liftable record")
    };

    let sha_1 = record()
        .into_raw_with_digests(marker::Sha1)
        .expect("renderable record");
    assert_eq!(
        written(&sha_1, "WARC-Block-Digest").as_deref(),
        Some("sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N")
    );

    let undigested = record().into_raw().expect("renderable record");
    assert_eq!(written(&undigested, "WARC-Block-Digest"), None);

    // A declared digest the block does not have is still an error without added digests.
    assert!(
        declaring_digest("md5:00000000000000000000000000000000")
            .into_raw()
            .is_err()
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

/// A label naming no algorithm this crate knows, whatever the build enables.
const UNKNOWN_DIGEST: &str = "crc32:1c330fb2d66be8b5";

/// Valid, absent, and uncheckable digests do not report a failure.
#[test]
fn a_record_declaring_a_digest_it_has_reports_nothing() {
    for value in [
        "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
        "md5:5d41402abc4b2a76b9719d911017c592",
        UNKNOWN_DIGEST,
        "crc32:not-a-digest",
    ] {
        let record = declaring_digest(value);

        assert_eq!(record.incorrect_block_digest(), None, "{value}");
        assert_eq!(record.incorrect_payload_digest(), None, "{value}");
    }

    let record = payload_record("response", &[], RESPONSE_BLOCK);

    assert_eq!(record.incorrect_block_digest(), None);
    assert_eq!(record.incorrect_payload_digest(), None);
}

/// Unknown algorithms are preserved without validation.
#[test]
fn a_block_digest_under_an_unknown_algorithm_is_not_checked() {
    for value in [UNKNOWN_DIGEST, "crc32:not-a-digest"] {
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

/// Disabled algorithms are preserved without validation.
///
/// Which algorithms a build can compute follows from the features of `archivindex-warc-digest`,
/// so one it cannot is chosen at run time rather than named here. A build enabling every
/// algorithm leaves nothing to check.
#[test]
fn a_digest_under_a_disabled_algorithm_is_not_checked() {
    use crate::value::Algorithm;

    let Some(algorithm) = Algorithm::ALL
        .into_iter()
        .find(|algorithm| !algorithm.is_supported())
    else {
        return;
    };
    // The value is never decoded, since the digest to compare it with cannot be computed.
    let value = format!("{}:1c330fb2d66be8b5", algorithm.label());
    let record = declaring_digest(&value);

    assert_eq!(record.incorrect_block_digest(), None, "{value}");
    assert_eq!(record.incorrect_payload_digest(), None, "{value}");

    let raw = record.into_raw().expect("renderable record");

    assert_eq!(
        written(&raw, "WARC-Block-Digest").as_deref(),
        Some(value.as_str())
    );
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

    lift_grammar(grammar_of(WarcVersion::V1_1, record_type, &all, body)).expect("liftable record")
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

/// Rendering with digests adds payload digests when the complete payload can be determined.
#[test]
fn a_record_declaring_no_payload_digest_is_given_one() {
    for (record_type, block, digest) in [
        ("response", RESPONSE_BLOCK, Some(ADDED_PAYLOAD_DIGEST)),
        ("request", RESPONSE_BLOCK, Some(ADDED_PAYLOAD_DIGEST)),
        ("resource", DIGESTED_BLOCK, Some(ADDED_PAYLOAD_DIGEST)),
        ("conversion", DIGESTED_BLOCK, Some(ADDED_PAYLOAD_DIGEST)),
        ("metadata", DIGESTED_BLOCK, None),
    ] {
        let raw = payload_record(record_type, &[], block)
            .into_raw_with_digests(marker::Sha256)
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

/// Every record type keeps its block somewhere different, and the one accessor reads any of
/// them: a block read as fields renders as the bytes it was read from, and one kept as read is
/// handed out rather than copied.
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

/// WARC 1.1 clause 5.15 lets a record declare its block incomplete, and a `warc-fields` block
/// cut mid-field is such a block, so its octets come back as they stand.
#[test]
fn a_malformed_warc_fields_body_declared_truncated_is_read_as_it_stands() {
    const BLOCK: &[u8] = b"software: tool/1.0\r\nhttp-he";

    let record = Record::<NoExtension>::try_from(grammar_of(
        WarcVersion::V1_1,
        "warcinfo",
        &[
            ("Content-Type", "application/warc-fields"),
            ("WARC-Truncated", "length"),
        ],
        BLOCK,
    ))
    .expect("a block declared truncated is readable");
    let Record::Warcinfo { body, .. } = record else {
        panic!("not a warcinfo");
    };
    assert_eq!(body, FieldsBlock::Raw(BLOCK.to_vec()));
}

/// A URI is held as the URI it names, and written back in the brackets the declared version
/// calls for: WARC 1.0 brackets every one of them, and WARC 1.1 only the five whose value is a
/// record identifier.
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

    // The record was read as a WARC 1.0 record and says so, so it is written as one without
    // being told.
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

/// A profile URI in angle brackets names the profile it spells, rather than reading as one the
/// standard does not define, and carries that profile's requirements with it.
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

/// Duplicate standard fields are rejected except for `WARC-Concurrent-To`.
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
/// whatever the record declares, so a record declaring 1.0 and carrying a 1.1 date is refused
/// here.
#[test]
fn a_warc_1_0_date_is_held_to_the_second() {
    let sub_second = "2020-07-08T02:52:55.123456Z";
    let mut lines = vec![
        ("WARC-Type", "resource"),
        ("WARC-Record-ID", "<urn:uuid:a>"),
    ];
    lines.push(("WARC-Date", sub_second));
    lines.push(("WARC-Target-URI", "<http://example.com/>"));
    let grammar = untyped::Record::try_from(crate::io::test_record(WarcVersion::V1_0, &lines, b""))
        .expect("readable record");

    assert_eq!(
        Record::<NoExtension>::try_from(grammar),
        Err(Error::MalformedField {
            field: Field::Date,
            value: sub_second.to_owned(),
        })
    );
}

/// Semantic parsing rejects the two WARC 1.1 reference fields on records declaring WARC 1.0.
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

    let raw = record
        .into_raw_with_digests(marker::Sha256)
        .expect("renderable record");
    assert_eq!(
        written_names(&raw),
        [
            "WARC-Type",
            "WARC-Target-URI",
            "WARC-Date",
            "WARC-Record-ID",
            "WARC-Payload-Digest",
            "WARC-Block-Digest",
            "Content-Length",
            "X-First",
            "x-second",
        ]
    );
}

/// Rendering normalizes standard field names and header order.
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
        .into_raw_with_digests(marker::Sha256)
        .expect("renderable record");

    assert_eq!(
        written_names(&raw),
        [
            "WARC-Type",
            "WARC-Target-URI",
            "WARC-Date",
            "WARC-Record-ID",
            "WARC-Payload-Digest",
            "WARC-Block-Digest",
            "Content-Length",
        ]
    );
}

/// Rendering preserves non-UTF-8 filename bytes and whether the filename was quoted.
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

/// Rendering rejects unrecognized fields with invalid names or values before they reach the
/// writer.
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

/// Unrecognized fields cannot use reserved standard names, even when the typed field is absent.
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

/// Extension records retain additional standard fields, but rendering still enforces version
/// restrictions.
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

/// Rendering rejects duplicate nonrepeatable standard fields retained on extension records.
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
/// Successful rendering must preserve the semantic record when parsed again.
fn assert_survives_rendering<E: Extension>(record: &Record<E>) {
    let Ok(raw) = record.clone().into_raw() else {
        return;
    };
    let grammar = untyped::Record::try_from(raw).expect("a rendered record is grammatical");

    assert_eq!(Record::<E>::try_from(grammar).ok(), Some(record.clone()));
}

/// Records modified through their public fields after parsing.
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

    // A record declaring WARC 1.0 writes its URI-valued fields bracketed, and carries a date at
    // the one precision that version spells.
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

    // A record of a type no version of the standard defines is under no constraint about which
    // fields it carries, so it keeps standard names as read and writes them back.
    let sitemap = Record::<Sitemaps>::try_from(grammar(
        "sitemap",
        &[("WARC-Target-URI", "http://example.com/")],
    ))
    .expect("liftable record");
    assert_eq!(sitemap.core().unrecognized.len(), 1);
    assert_survives_rendering(&sitemap);
}

/// WARC 1.0 spells a date one way, so a record declaring that version cannot carry a date at a
/// precision only WARC 1.1 spells: writing it would drop what its extra digits say.
#[test]
fn a_date_the_declared_version_cannot_spell_is_not_written() {
    let mut record =
        lift("response", &[("WARC-Target-URI", "http://example.com/")]).expect("liftable record");
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

/// Continuation segment numbers begin at `2`; `1` identifies the origin record.
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
    // A type the standard does not define is one it does not constrain, so the known field is
    // preserved rather than rejected.
    assert_eq!(
        header.core.unrecognized,
        [(
            "WARC-Target-URI".to_owned(),
            "http://example.com/sitemap.xml".to_owned(),
        )]
    );
    assert_eq!(record.type_name(), "Sitemap");
}

/// Rendering preserves the record-type spelling supplied by the extension.
#[test]
fn an_extension_record_type_keeps_its_own_spelling() {
    let raw = Record::<Sitemaps>::try_from(grammar("sitemap", &[]))
        .expect("liftable record")
        .into_raw()
        .expect("renderable record");

    assert_eq!(written(&raw, "WARC-Type").as_deref(), Some("Sitemap"));
}

/// An extension may not redefine the types the standard defines, so a type that names one of
/// them is refused as it is read rather than being written back as a standard record.
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

/// What an extension writes is held to the same rule as a field kept as read, whether it names
/// a field the record already carries or one its type is forbidden.
#[test]
fn an_extension_cannot_name_a_field_the_standard_defines() {
    let record =
        Record::<Impersonating>::try_from(grammar("warcinfo", &[])).expect("liftable record");
    assert_eq!(
        record.into_raw(),
        Err(RenderError::ReservedField(Field::RecordID))
    );

    let record = Record::<Renaming>::try_from(grammar("warcinfo", &[])).expect("liftable record");
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

/// The digest is what the identical-payload-digest profile asserts, so a record naming that
/// profile without one is rejected, under either version's spelling of the URI.
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
/// record carrying one and not saying it is truncated is not written. Clause 6.7.2 obliges the
/// writer, so such a record is still read, and archives that hold one can be opened.
#[test]
fn an_identical_payload_digest_revisit_declares_the_truncation_its_block_is() {
    // The second record declares a reason saying its block is something other than the
    // truncation this profile has it be.
    for lines in [&[][..], &[("WARC-Truncated", "time")][..]] {
        let record = lift_grammar(identical_payload_digest_revisit(lines, b"HTTP/1.1 200 OK"))
            .expect("a record a writer left undeclared is readable");

        assert_eq!(
            record.into_raw(),
            Err(RenderError::Block(BlockError::UndeclaredRevisitTruncation(
                15
            )))
        );
    }
}

/// A record that declares the truncation, and one that carries no block at all, are both what
/// the profile describes.
#[test]
fn an_identical_payload_digest_revisit_carries_a_truncated_block_or_none() {
    for (lines, body) in [
        (&[("WARC-Truncated", "length")][..], &b"HTTP/1.1 200 OK"[..]),
        (&[], b""),
    ] {
        let record =
            lift_grammar(identical_payload_digest_revisit(lines, body)).expect("liftable record");

        assert_survives_rendering(&record);
        assert!(record.into_raw().is_ok());
    }
}

/// Removing the required truncation declaration prevents rendering, although reading tolerates
/// its absence.
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

/// Custom revisit profiles do not require a payload digest.
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

/// The server-not-modified and custom profiles do not require a payload digest.
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

/// A series is numbered from the origin record's `1`, so a `continuation` numbering itself `0`
/// or `1` claims a position that is not a continuation of anything.
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

    // A `warcinfo` record is forbidden a target URI, an address, and a capture event, and has
    // no payload to describe.
    let warcinfo = warcinfo();
    assert!(warcinfo.target_uri().is_none());
    assert!(warcinfo.ip_address().is_none());
    assert_eq!(warcinfo.concurrent_to(), [] as [fluent_uri::Uri<String>; 0]);
    assert!(warcinfo.payload().is_none());
}

/// The origin of a series and its continuations report their segment number through the one
/// accessor, however the header stores it.
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

/// The bytes a record writes, with the digests and length rendering supplies.
fn render_bytes(record: Record) -> Vec<u8> {
    record
        .into_raw()
        .expect("a rendered record")
        .to_bytes()
        .expect("a framed record")
}

/// Parse rendered bytes into a semantic record.
fn lift_bytes(bytes: &[u8]) -> Record {
    let raw = crate::io::read::WarcReader::new(bytes)
        .iter_raw_records()
        .records()
        .next()
        .expect("a record")
        .expect("a well-formed record");

    Record::try_from(untyped::Record::try_from(raw).expect("a grammatical record"))
        .expect("a record of a type the standard defines")
}

/// Rendering a parsed semantic record is stable across another parse and render cycle.
///
/// Compare parsed records because rendering fills in the generated record's missing length and
/// requested digests.
#[property_test]
fn round_trips_a_record_through_its_rendering(#[strategy = strategies::record()] record: Record) {
    let written = render_bytes(record);
    let lifted = lift_bytes(&written);

    let rewritten = render_bytes(lifted.clone());

    prop_assert_eq!(&rewritten, &written);
    prop_assert_eq!(lift_bytes(&rewritten), lifted);
}
