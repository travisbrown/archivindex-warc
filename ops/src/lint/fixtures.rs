//! Records and lint passes shared by the tests of the rules.

use std::io::Write;

use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::value::{Algorithm, LabelledDigest, WarcDate};
use archivindex_warc::version::WarcVersion;
use flate2::Compression;
use flate2::write::GzEncoder;
use fluent_uri::Uri;

use super::{Checked, Finding, Linter, Violation};
use crate::gzip::MemberReader;

pub(super) const WARCINFO_ID: &str = "urn:uuid:aaaaaaaa-0000-4000-8000-000000000000";
pub(super) const REQUEST_ID: &str = "urn:uuid:bbbbbbbb-0000-4000-8000-000000000000";
pub(super) const RESPONSE_ID: &str = "urn:uuid:cccccccc-0000-4000-8000-000000000000";
pub(super) const METADATA_ID: &str = "urn:uuid:dddddddd-0000-4000-8000-000000000000";
pub(super) const OTHER_ID: &str = "urn:uuid:eeeeeeee-0000-4000-8000-000000000000";
pub(super) const HOST: &str = "example.com";
pub(super) const COLLECTION: &str = "example.com-20240401120000";
pub(super) const FILENAME: &str = "example.com-20240401120000.warc.gz";
pub(super) const TARGET: &str = "https://example.com/";
pub(super) const DATE: &str = "2024-04-01T12:00:00Z";
/// What a fixture writes where the digest of the field's subject belongs, which rendering
/// replaces with that digest. A test wanting a digest a record does not have writes its own.
pub(super) const DIGEST: &str = "sha1:PLACEHOLDER";
pub(super) const REQUEST_BLOCK: &str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
pub(super) const RESPONSE_BLOCK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

/// A record's header fields and block, before rendering.
#[derive(Clone)]
pub(super) struct TestRecord {
    pub(super) headers: Vec<(&'static str, String)>,
    pub(super) body: String,
    preserve_header_order: bool,
}

impl TestRecord {
    pub(super) fn new(record_type: &str, id: &str, body: &str) -> Self {
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

    pub(super) fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));

        self
    }

    pub(super) fn set(mut self, name: &str, value: &str) -> Self {
        let (_, current) = self
            .headers
            .iter_mut()
            .find(|(header, _)| *header == name)
            .expect("the field is present");
        *current = value.to_owned();

        self
    }

    pub(super) fn without(mut self, name: &str) -> Self {
        self.headers.retain(|(header, _)| *header != name);

        self
    }

    pub(super) fn in_written_order(mut self) -> Self {
        self.preserve_header_order = true;

        self
    }

    /// A WARC 1.1 record, framed by the body's length.
    pub(super) fn render(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"WARC/1.1\r\n");
        let mut headers = self.headers.iter().collect::<Vec<_>>();
        if !self.preserve_header_order {
            headers.sort_by_key(|(name, _)| {
                Field::from_name(name).map_or(usize::MAX, Field::canonical_rank)
            });
        }
        for (name, value) in headers {
            let computed = (value == DIGEST).then(|| digest(covered(name, &self.body)));
            let value = computed.as_deref().unwrap_or(value);
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(self.body.as_bytes());
        out.extend_from_slice(b"\r\n\r\n");
    }
}

/// What a digest field covers.
///
/// A payload digest covers the entity-body of an HTTP message, which is what follows the empty
/// line closing its head. A `resource` block holds no such line and is covered whole.
pub(super) fn covered<'a>(field: &str, body: &'a str) -> &'a str {
    if field == "WARC-Payload-Digest"
        && let Some((_, entity_body)) = body.split_once("\r\n\r\n")
    {
        entity_body
    } else {
        body
    }
}

/// A digest as a record declares it.
pub(super) fn labelled(value: &str) -> LabelledDigest {
    LabelledDigest::parse(value.as_bytes()).expect("a well-formed labelled digest")
}

/// The digest of what a field covers, written as the fixtures declare digests.
pub(super) fn digest(content: &str) -> String {
    LabelledDigest::compute(Algorithm::Sha1, content.as_bytes())
        .expect("the sha1 algorithm is enabled")
        .to_string()
}

pub(super) fn warcinfo() -> TestRecord {
    warcinfo_with_id(WARCINFO_ID)
}

/// A `warcinfo` record naming the collection, in the file named for it.
pub(super) fn warcinfo_with_id(id: &str) -> TestRecord {
    TestRecord::new(
        "warcinfo",
        id,
        &format!("software: test\r\nisPartOf: {COLLECTION}\r\n"),
    )
    .with("WARC-Filename", FILENAME)
    .with("Content-Type", "application/warc-fields")
}

pub(super) fn request() -> TestRecord {
    TestRecord::new("request", REQUEST_ID, REQUEST_BLOCK)
        .with("WARC-Target-URI", TARGET)
        .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
        .with("WARC-Payload-Digest", DIGEST)
        .with("Content-Type", "application/http;msgtype=request")
}

pub(super) fn response() -> TestRecord {
    TestRecord::new("response", RESPONSE_ID, RESPONSE_BLOCK)
        .with("WARC-Target-URI", TARGET)
        .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
        .with("WARC-Concurrent-To", format!("<{REQUEST_ID}>"))
        .with("WARC-Payload-Digest", DIGEST)
        .with("Content-Type", "application/http;msgtype=response")
}

pub(super) fn metadata() -> TestRecord {
    TestRecord::new("metadata", METADATA_ID, "fetchTimeMs: 12\r\n")
        .with("WARC-Target-URI", TARGET)
        .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
        .with("WARC-Concurrent-To", format!("<{RESPONSE_ID}>"))
        .with("Content-Type", "application/warc-fields")
}

pub(super) fn resource(id: &str) -> TestRecord {
    TestRecord::new("resource", id, "hello")
        .with("WARC-Target-URI", "https://example.com/resource")
        .with("WARC-Warcinfo-ID", format!("<{WARCINFO_ID}>"))
        .with("WARC-Payload-Digest", DIGEST)
        .with("Content-Type", "text/plain")
}

/// A `response` record made the `revisit` of the record `original` identifies, under the
/// identical payload digest profile.
///
/// The block is kept and declared truncated, as clause 6.7.2 asks.
pub(super) fn revisit_of(response: TestRecord, original: &str) -> TestRecord {
    response
        .set("WARC-Type", "revisit")
        .with(
            "WARC-Profile",
            "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
        )
        .with("WARC-Truncated", "length")
        .with("WARC-Refers-To", format!("<{original}>"))
        .with("WARC-Refers-To-Target-URI", TARGET)
        .with("WARC-Refers-To-Date", DATE)
}

/// A WARC 1.1 date.
pub(super) fn date(value: &str) -> WarcDate {
    WarcDate::parse(value, WarcVersion::V1_1).expect("a valid date")
}

/// A clean capture: a warcinfo record followed by a request, response, metadata triple.
pub(super) fn capture() -> Vec<TestRecord> {
    vec![warcinfo(), request(), response(), metadata()]
}

/// An identifier for a further record a test adds, distinct for each `nonce`.
pub(super) fn other_id(nonce: usize) -> String {
    format!("urn:uuid:eeeeeeee-0000-4000-8000-0000000001{nonce:02}")
}

/// Copies of `records` under identifiers of their own, keeping the references among them.
///
/// A field naming a record outside the copy, such as the `warcinfo` record a capture belongs
/// to, keeps the identifier it names.
pub(super) fn copies(records: &[TestRecord], nonce: usize) -> Vec<TestRecord> {
    let own = records.iter().map(declared_id).collect::<Vec<_>>();

    records
        .iter()
        .map(|record| {
            let mut copy = record.clone();
            for (_, value) in &mut copy.headers {
                if own.contains(&*value) {
                    // Identifiers are written between brackets, which the copy keeps.
                    value.insert_str(value.len() - 1, &format!("-{nonce}"));
                }
            }

            copy
        })
        .collect()
}

/// The identifier a record declares, as its field is written.
pub(super) fn declared_id(record: &TestRecord) -> String {
    record
        .headers
        .iter()
        .find(|(name, _)| *name == "WARC-Record-ID")
        .expect("the record declares an identifier")
        .1
        .clone()
}

pub(super) fn render(records: &[TestRecord]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        record.render(&mut out);
    }

    out
}

pub(super) fn uri(value: &str) -> Uri<String> {
    Uri::parse(value.to_owned()).expect("a valid URI")
}

/// Every item of a lint pass, which must hold no read errors.
pub(super) fn lint(records: &[TestRecord]) -> Vec<Checked> {
    lint_file(&render(records))
}

/// Every item of a lint pass over a file written byte for byte, which must hold no read errors.
pub(super) fn lint_file(file: &[u8]) -> Vec<Checked> {
    Linter::new(file)
        .collect::<Result<_, _>>()
        .expect("every record reads")
}

/// The findings of a lint pass, by position.
///
/// Each finding's rule name is checked against its serialized form here, so every test
/// expecting a finding checks that pairing too.
pub(super) fn findings(records: &[TestRecord]) -> Vec<(usize, Violation)> {
    faults(lint(records))
}

/// The findings among the results of a lint pass, by position.
pub(super) fn faults(checked: Vec<Checked>) -> Vec<(usize, Violation)> {
    checked
        .into_iter()
        .filter_map(Result::err)
        .map(|finding| {
            assert_eq!(serialized_rule(&finding), finding.violation.rule());

            (finding.index, finding.violation)
        })
        .collect()
}

/// The members spelled as one gzip stream.
pub(super) fn gzip(members: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for member in members {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(member).expect("a member is written");
        out.extend_from_slice(&encoder.finish().expect("a member is finished"));
    }

    out
}

/// The findings of a lint pass over a gzip file whose framing is checked, by position.
pub(super) fn gzip_findings(members: &[&[u8]]) -> Vec<(usize, Violation)> {
    let stream = gzip(members);
    let reader = MemberReader::new(&stream[..]);
    let framing = reader.framing();

    faults(
        Linter::new(reader)
            .checking_gzip_framing(framing)
            .collect::<Result<_, _>>()
            .expect("every record reads"),
    )
}

/// The rule name the serialized form of a finding writes.
pub(super) fn serialized_rule(finding: &Finding) -> String {
    serde_json::to_value(finding).expect("a finding serializes")["rule"]
        .as_str()
        .expect("a serialized finding names its rule")
        .to_owned()
}
