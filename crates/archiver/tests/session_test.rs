//! End-to-end crawl session tests against a local HTTP server serving canned responses.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use archivindex_archiver::capture::{CaptureControl, CaptureEvent, CaptureSummary, Origin};
use archivindex_archiver::config::{Operator, SessionConfig, Software};
use archivindex_archiver::session::{
    self, Capture, CaptureProcessor, Crawl, Discovery, RetryConfig, Session,
};
use archivindex_archiver::{Archiver, Config, Error};
use archivindex_test_support::http::{
    Request, dead_port, response, serve_concurrently_with, serve_with,
};
use archivindex_warc::record::fields::Field;
use archivindex_warc::record::fields::dcmi::DcmiTerm;
use archivindex_warc::record::fields::metadata::MetadataField;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::record::header::RevisitProfile;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::record::{FieldsBlock, Record};
use archivindex_warc::value::{MediaType, WarcDate};
use archivindex_warc::version::WarcVersion;
use archivindex_warc_revisit_index::Index;
use archivindex_warc_revisit_index::payload::RevisitTarget;
use archivindex_warc_revisit_index::resource::{ResourceKey, ResourceStateUpdate, Variance};
use data_encoding::BASE64;
use fluent_uri::Uri;

mod support;

use support::{records, sha256};

/// A gzip-compressed archive whose sessions run as the test operator.
fn gzip_config() -> Config {
    Config {
        gzip_warc: true,
        operator: Some(operator()),
        ..Config::default()
    }
}

/// [`gzip_config`] storing every duplicate payload as a revisit, since the canned payloads are
/// shorter than the default minimum.
fn revisiting_config() -> Config {
    Config {
        min_revisit_payload_length: 0,
        ..gzip_config()
    }
}

/// The operator most tests run their sessions as, configured by [`gzip_config`].
fn operator() -> Operator {
    Operator {
        name: "Test Operator".to_owned(),
        email: Some("operator@example.com".to_owned()),
    }
}

fn archiver(config: Config) -> Archiver {
    Archiver::new(config).expect("test archiver configuration should be valid")
}

/// A canned HTTP/1.1 response for a request path: a small site whose home page links to two other
/// pages, one of which links back to the home page.
fn respond(path: &str) -> Vec<u8> {
    match path {
        "/" => response(
            "200 OK",
            &[("content-type", "text/html")],
            "<html>home links: /about /missing</html>",
        ),
        "/about" => response(
            "200 OK",
            &[("content-type", "text/html")],
            "<html>about links: /</html>",
        ),
        "/redirect" => response(
            "302 Found",
            &[("content-type", "text/plain"), ("location", "/about")],
            "",
        ),
        _ => response("404 Not Found", &[("content-type", "text/plain")], "gone"),
    }
}

/// Serve the given number of connections on an ephemeral local port, returning the request paths in
/// the order they arrived.
fn serve(connections: usize) -> std::io::Result<(u16, thread::JoinHandle<Vec<String>>)> {
    serve_with(connections, |request| {
        let path = request.path();
        (respond(path), path.to_owned())
    })
}

const LAST_MODIFIED: &str = "Wed, 01 Jan 2025 00:00:00 GMT";
const EXTERNAL_RECORD_ID: &str = "urn:uuid:00000000-0000-4000-8000-000000000001";

fn uri(value: &str) -> Uri<String> {
    Uri::parse(value).expect("test URI").to_owned()
}

fn warc_date(value: &str) -> WarcDate {
    WarcDate::parse(value, WarcVersion::V1_1).expect("test WARC date")
}

/// Answer a request for a versioned page, whose `ETag` advances once: an unconditional request or
/// one for a stale version gets the current page in full, while one for the current version gets
/// `304 Not Modified`, carrying the page's validators without a body.
fn respond_versioned(request: &Request, versions: usize) -> Vec<u8> {
    let requested = request
        .header("if-none-match")
        .and_then(|etag| etag.trim_matches('"').parse::<usize>().ok());
    let current = requested.map_or(1, |etag| versions.min(etag + 1));

    if requested == Some(current) {
        format!(
            "HTTP/1.1 304 Not Modified\r\netag: \"{current}\"\r\nlast-modified: {LAST_MODIFIED}\r\n\
             connection: close\r\n\r\n"
        )
        .into_bytes()
    } else {
        response(
            "200 OK",
            &[
                ("content-type", "text/html"),
                ("etag", &format!("\"{current}\"")),
                ("last-modified", LAST_MODIFIED),
            ],
            &format!("<html>version {current}</html>"),
        )
    }
}

/// The space-separated tokens of a payload that name paths (start with `/`), as absolute URLs.
fn extract_links(payload: &[u8], port: u16) -> Vec<String> {
    String::from_utf8_lossy(payload)
        .split_whitespace()
        .filter(|token| token.starts_with('/'))
        .map(|path| {
            let path = path.trim_end_matches("</html>");
            format!("http://127.0.0.1:{port}{path}")
        })
        .collect()
}

/// Inspect the canned site's HTML once for both links and its title.
struct SiteProcessor {
    port: u16,
}

impl CaptureProcessor for SiteProcessor {
    fn inspect(&mut self, capture: &Capture<'_>) -> Discovery {
        let text = std::str::from_utf8(capture.payload).ok();
        let title = text.and_then(|text| {
            text.contains("home")
                .then(|| "Home".to_owned())
                .or_else(|| text.contains("about").then(|| "About".to_owned()))
        });

        Discovery {
            links: extract_links(capture.payload, self.port),
            title,
            ..Discovery::default()
        }
    }
}

/// Return the same small link set for every capture, including the capture itself.
struct DeduplicationProcessor {
    port: u16,
}

impl CaptureProcessor for DeduplicationProcessor {
    fn inspect(&mut self, capture: &Capture<'_>) -> Discovery {
        Discovery {
            links: vec![
                format!("http://127.0.0.1:{}/", self.port),
                capture.url.to_owned(),
                format!("http://127.0.0.1:{}/about", self.port),
            ],
            title: None,
            ..Discovery::default()
        }
    }
}

/// Record what the processor sees without discovering further links.
struct ObservingProcessor<'a> {
    observed: &'a mut Vec<(String, String, u16, String)>,
}

impl CaptureProcessor for ObservingProcessor<'_> {
    fn inspect(&mut self, capture: &Capture<'_>) -> Discovery {
        self.observed.push((
            capture.url.to_owned(),
            capture.final_url.to_owned(),
            capture.status,
            String::from_utf8_lossy(capture.payload).into_owned(),
        ));

        Discovery::default()
    }
}

/// Return a fixed set of links for every capture.
struct FixedLinksProcessor {
    links: Vec<String>,
}

struct FailingProcessor;

impl CaptureProcessor for FailingProcessor {
    fn inspect(&mut self, _capture: &Capture<'_>) -> Discovery {
        Discovery {
            error: Some("cannot continue traversal".to_owned()),
            ..Discovery::default()
        }
    }
}

impl CaptureProcessor for FixedLinksProcessor {
    fn inspect(&mut self, _capture: &Capture<'_>) -> Discovery {
        Discovery {
            links: self.links.clone(),
            title: None,
            ..Discovery::default()
        }
    }
}

/// Discover the captured URL itself a fixed number of times, optionally recording the status and
/// payload of every capture seen. The session must repeat discoveries for it to have any effect.
struct RepeatingProcessor<'a> {
    remaining: usize,
    observed: Option<&'a mut Vec<(u16, String)>>,
}

impl CaptureProcessor for RepeatingProcessor<'_> {
    fn inspect(&mut self, capture: &Capture<'_>) -> Discovery {
        if let Some(observed) = self.observed.as_deref_mut() {
            observed.push((
                capture.status,
                String::from_utf8_lossy(capture.payload).into_owned(),
            ));
        }
        let links = if self.remaining == 0 {
            Vec::new()
        } else {
            self.remaining -= 1;
            vec![capture.url.to_owned()]
        };

        Discovery {
            links,
            ..Discovery::default()
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scripted exchange, read in order"
)]
fn persistent_index_is_read_only_and_supplies_historical_and_same_session_revisit_targets()
-> Result<(), Box<dyn std::error::Error>> {
    const HISTORICAL: &str = "historical payload";
    const NEW: &str = "new shared payload";

    let directory = tempfile::tempdir()?;
    let database = directory.path().join("revisits.sqlite3");
    let database_for_server = database.clone();
    let historical_target = RevisitTarget {
        payload_digest: sha256(HISTORICAL.as_bytes()),
        payload_length: Some(HISTORICAL.len() as u64),
        identified_payload_type: Some(MediaType::TEXT_PLAIN),
        record_id: uri(EXTERNAL_RECORD_ID),
        target_uri: uri("https://archive.example/historical"),
        warc_date: warc_date("2025-01-01T00:00:00Z"),
    };
    Index::open(&database)?.insert_payload(&historical_target)?;
    let (port, server) = serve_with(3, move |request| {
        let path = request.path();
        let body = if path == "/historical" {
            HISTORICAL
        } else {
            NEW
        };
        let new_payload_is_durable = Index::open(&database_for_server)
            .expect("open durable revisit index")
            .lookup_payload(&sha256(NEW.as_bytes()))
            .expect("inspect durable revisit index")
            .is_some();
        (
            response("200 OK", &[("content-type", "text/plain")], body),
            format!("{path}:{new_payload_is_durable}"),
        )
    })?;
    let historical_url = format!("http://127.0.0.1:{port}/historical");
    let first_new_url = format!("http://127.0.0.1:{port}/new-a");
    let second_new_url = format!("http://127.0.0.1:{port}/new-b");
    let output = directory.path().join("persistent-revisits.warc.gz");

    let summary = Session::new(
        archiver(revisiting_config()),
        "persistent-revisits",
        Crawl::seeds([&historical_url, &first_new_url, &second_new_url]),
        &output,
    )?
    .revisit_index(&database)
    .run()?;

    assert_eq!(
        server.join().expect("server thread"),
        ["/historical:false", "/new-a:false", "/new-b:false"]
    );
    assert!(summary.is_complete());

    let records = records(&std::fs::read(&output)?)?;
    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "revisit", "metadata", "request", "response", "metadata",
            "request", "revisit", "metadata",
        ]
    );

    let Record::Revisit {
        header: historical, ..
    } = &records[2]
    else {
        panic!("the historical duplicate should be a revisit");
    };
    assert_eq!(historical.profile, RevisitProfile::IDENTICAL_PAYLOAD_DIGEST);
    assert_eq!(
        historical.refers_to.as_ref(),
        Some(&uri(EXTERNAL_RECORD_ID))
    );
    assert_eq!(
        historical.refers_to_target_uri.as_ref().map(Uri::as_str),
        Some("https://archive.example/historical")
    );
    assert_eq!(
        historical.payload.identified_payload_type,
        Some(MediaType::TEXT_PLAIN)
    );

    let Record::Response {
        header: new_original,
        ..
    } = &records[5]
    else {
        panic!("the first new payload should be stored in full");
    };
    let Record::Revisit {
        header: new_revisit,
        ..
    } = &records[8]
    else {
        panic!("the second new payload should be a revisit");
    };
    assert_eq!(
        new_revisit.refers_to.as_ref(),
        Some(&new_original.core.record_id)
    );
    assert_eq!(
        new_revisit.refers_to_target_uri.as_ref().map(Uri::as_str),
        Some(first_new_url.as_str())
    );
    assert_eq!(
        new_revisit.payload.identified_payload_type,
        new_original.payload.identified_payload_type
    );

    assert!(
        Index::open(&database)?
            .lookup_payload(&sha256(NEW.as_bytes()))?
            .is_none(),
        "the finished WARC must be loaded explicitly"
    );

    Ok(())
}

#[test]
fn persistent_resource_state_drives_conditional_requests_and_not_modified_revisits()
-> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(1, |request| {
        (respond_versioned(request, 1), request.clone())
    })?;
    let url = format!("http://127.0.0.1:{port}/page");
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("resource-state.sqlite3");
    let output = directory.path().join("persistent-revalidation.warc.gz");
    let digest = sha256(b"<html>version 1</html>");
    let original_date = warc_date("2025-01-01T00:00:00Z");
    let index = Index::open(&database)?;
    index.insert_payload(&RevisitTarget {
        payload_digest: digest.clone(),
        payload_length: Some(22),
        identified_payload_type: Some(MediaType::TEXT_PLAIN),
        record_id: uri(EXTERNAL_RECORD_ID),
        target_uri: uri(&url),
        warc_date: original_date,
    })?;
    index.update_resource(
        &ResourceKey::new(uri(&url)),
        ResourceStateUpdate::Representation {
            etag: Some("\"1\"".to_owned()),
            last_modified: Some(LAST_MODIFIED.to_owned()),
            payload_digest: Some(digest.clone()),
            record_id: Some(uri(EXTERNAL_RECORD_ID)),
            warc_date: Some(original_date),
            observed_at: original_date,
            variance: Variance::Invariant,
        },
    )?;
    drop(index);

    let summary = Session::new(
        archiver(gzip_config()),
        "persistent-revalidation",
        Crawl::seeds([&url]),
        &output,
    )?
    .revisit_index(&database)
    .run()?;

    let requests = server.join().expect("server thread");
    assert_eq!(requests[0].header("if-none-match"), Some("\"1\""));
    assert_eq!(requests[0].header("if-modified-since"), Some(LAST_MODIFIED));
    assert_eq!(summary.seed_captures[0].status, 304);

    let records = records(&std::fs::read(&output)?)?;
    let Record::Revisit { header, .. } = &records[2] else {
        panic!("the persisted original should produce a revisit");
    };
    assert_eq!(header.profile, RevisitProfile::SERVER_NOT_MODIFIED);
    assert_eq!(header.refers_to.as_ref(), Some(&uri(EXTERNAL_RECORD_ID)));
    assert_eq!(header.refers_to_date, Some(original_date));
    assert_eq!(header.payload.payload_digest.as_ref(), Some(&digest));
    assert_eq!(
        header.payload.identified_payload_type,
        Some(MediaType::TEXT_PLAIN)
    );

    let state = Index::open(&database)?
        .lookup_resource(&ResourceKey::new(uri(&url)))?
        .expect("resource state should remain indexed");
    assert_eq!(state.payload_digest, Some(digest));
    assert_eq!(state.record_id, Some(uri(EXTERNAL_RECORD_ID)));
    assert_eq!(state.warc_date, Some(original_date));

    Ok(())
}

#[test]
fn resource_state_for_another_variant_does_not_drive_revalidation()
-> Result<(), Box<dyn std::error::Error>> {
    const DESKTOP_AGENT: &str = "DesktopBot/1.0";
    const MOBILE_AGENT: &str = "MobileBot/1.0";
    const MOBILE: &str = "<html>mobile</html>";

    let (port, server) = serve_with(1, |request| {
        let reply = response(
            "200 OK",
            &[
                ("content-type", "text/html"),
                ("etag", "\"mobile\""),
                ("last-modified", LAST_MODIFIED),
                ("vary", "User-Agent"),
            ],
            MOBILE,
        );
        (reply, request.clone())
    })?;
    let url = format!("http://127.0.0.1:{port}/page");
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("resource-state.sqlite3");
    let output = directory.path().join("variant.warc.gz");
    let desktop_digest = sha256(b"<html>desktop</html>");
    let original_date = warc_date("2025-01-01T00:00:00Z");

    // State captured by an earlier crawl that identified itself as a desktop client, for a
    // response that declared its representation selected by `User-Agent`.
    let index = Index::open(&database)?;
    index.insert_payload(&RevisitTarget {
        payload_digest: desktop_digest.clone(),
        payload_length: Some(20),
        identified_payload_type: None,
        record_id: uri(EXTERNAL_RECORD_ID),
        target_uri: uri(&url),
        warc_date: original_date,
    })?;
    index.update_resource(
        &ResourceKey::new(uri(&url)),
        ResourceStateUpdate::Representation {
            etag: Some("\"desktop\"".to_owned()),
            last_modified: Some(LAST_MODIFIED.to_owned()),
            payload_digest: Some(desktop_digest),
            record_id: Some(uri(EXTERNAL_RECORD_ID)),
            warc_date: Some(original_date),
            observed_at: original_date,
            variance: Variance::declared(Some("User-Agent"), |name| {
                (name == "user-agent").then_some(DESKTOP_AGENT)
            }),
        },
    )?;
    drop(index);

    let config = Config {
        user_agent: MOBILE_AGENT.to_owned(),
        ..gzip_config()
    };
    let summary = Session::new(archiver(config), "variant", Crawl::seeds([&url]), &output)?
        .revisit_index(&database)
        .run()?;

    let requests = server.join().expect("server thread");
    assert_eq!(requests[0].header("if-none-match"), None);
    assert_eq!(requests[0].header("if-modified-since"), None);
    assert_eq!(summary.seed_captures[0].status, 200);

    let records = records(&std::fs::read(&output)?)?;
    let Record::Response { header, .. } = &records[2] else {
        panic!("a representation selected by another request should be captured in full");
    };
    assert_eq!(
        header.payload.payload_digest.as_ref(),
        Some(&sha256(MOBILE.as_bytes()))
    );

    // Capturing another variant does not replace durable state automatically.
    let state = Index::open(&database)?
        .lookup_resource(&ResourceKey::new(uri(&url)))?
        .expect("resource state should remain indexed");
    assert_eq!(state.etag.as_deref(), Some("\"desktop\""));
    assert!(
        state
            .variance
            .matches(|name| (name == "user-agent").then_some(DESKTOP_AGENT))
    );
    assert!(
        !state
            .variance
            .matches(|name| (name == "user-agent").then_some(MOBILE_AGENT))
    );

    Ok(())
}

/// Crawl a page whose representation is selected by the `Vary` values given and repeat it. The
/// repeat matches the first request, so it must send the validators the crawl recorded, and the
/// server meets it with a challenge whose cookie the request is then repeated with, so that repeat
/// selects another representation and must not send them.
fn assert_validators_follow_the_cookie(
    vary: &'static [&'static str],
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const COOKIE: &str = "session=clearance";
    const BODY: &str = "<html>cleared</html>";

    let script = "v='cookie-value';\
        document.cookie='sucuri_cloudproxy_uuid_test=' + v + \
        ';path=/;max-age=86400;SameSite=Lax'; location.reload();";
    let challenge = format!(
        "<html><script>var sucuri_cloudproxy_js='',S='{}';</script></html>",
        BASE64.encode(script.as_bytes())
    );
    let headers = [
        ("content-type", "text/html"),
        ("etag", "\"v1\""),
        ("last-modified", LAST_MODIFIED),
    ]
    .into_iter()
    .chain(vary.iter().map(|value| ("vary", *value)))
    .collect::<Vec<_>>();
    let attempt = AtomicUsize::new(0);
    let (port, server) = serve_with(3, move |request| {
        let reply = if attempt.fetch_add(1, Ordering::Relaxed) == 1 {
            response(
                "307 Temporary Redirect",
                &[("content-type", "text/html"), ("x-sucuri-id", "12005")],
                &challenge,
            )
        } else {
            response("200 OK", &headers, BODY)
        };
        (reply, request.clone())
    })?;
    let url = format!("http://127.0.0.1:{port}/page");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join(output);

    let summary = Session::new(
        archiver(gzip_config()).cookie_for(&url, COOKIE)?,
        "cookie",
        Crawl::seeds([&url])
            .dedupe_discoveries(false)
            .processor(RepeatingProcessor {
                remaining: 1,
                observed: None,
            }),
        &output,
    )?
    .run()?;

    let requests = server.join().expect("server thread");
    assert_eq!(summary.seed_captures.len(), 1);
    assert_eq!(summary.extra_captures.len(), 1);
    assert_eq!(requests[1].header("cookie"), Some(COOKIE));
    assert_eq!(requests[1].header("if-none-match"), Some("\"v1\""));
    assert_eq!(requests[1].header("if-modified-since"), Some(LAST_MODIFIED));
    assert_eq!(
        requests[2].header("cookie"),
        Some("session=clearance; sucuri_cloudproxy_uuid_test=cookie-value")
    );
    assert_eq!(requests[2].header("if-none-match"), None);
    assert_eq!(requests[2].header("if-modified-since"), None);

    Ok(())
}

/// A server may send `Vary` as several field lines. Every field it names selects the stored
/// representation, so a request differing in any of them must not reuse its validators. Reading
/// only the first line would leave the cookie unrecorded.
#[test]
fn vary_sent_as_several_lines_selects_on_every_field_it_names()
-> Result<(), Box<dyn std::error::Error>> {
    assert_validators_follow_the_cookie(&["User-Agent", "Cookie"], "multiline-vary.warc.gz")
}

/// A challenge cookie is injected per request rather than configured, so a response selected by
/// it is only recorded correctly if the request as sent is what resolves the declared `Vary`.
/// Resolving it against the configured fields alone would record the cookie as absent.
#[test]
fn vary_cookie_records_the_cookie_the_request_carried() -> Result<(), Box<dyn std::error::Error>> {
    assert_validators_follow_the_cookie(&["Cookie"], "cookie-vary.warc.gz")
}

#[test]
fn a_repeated_discovery_is_an_identical_payload_revisit() -> Result<(), Box<dyn std::error::Error>>
{
    let (port, server) = serve(2)?;
    let url = format!("http://127.0.0.1:{port}/about");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("repeat.warc.gz");

    let summary = Session::new(
        archiver(revisiting_config()),
        "repeat",
        Crawl::seeds([&url])
            .dedupe_discoveries(false)
            .processor(RepeatingProcessor {
                remaining: 1,
                observed: None,
            }),
        &output,
    )?
    .run()?;

    assert_eq!(server.join().expect("server thread"), ["/about", "/about"]);
    assert!(summary.is_complete());
    assert_eq!(summary.seed_captures.len(), 1);
    assert_eq!(summary.seed_captures[0].origin, Origin::Seed);
    assert_eq!(summary.extra_captures.len(), 1);
    assert_eq!(
        summary.extra_captures[0].origin,
        Origin::Extra { via: url.clone() }
    );

    // The second capture's payload matches the first, so it is stored as a revisit record.
    let records = records(&std::fs::read(&output)?)?;

    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "response", "metadata", "request", "revisit", "metadata",
        ]
    );

    let Record::Response {
        header: original,
        body: original_body,
    } = &records[2]
    else {
        panic!("the first capture should store a full response record");
    };
    let Record::Revisit {
        header: revisit,
        body: revisit_body,
    } = &records[5]
    else {
        panic!("the second capture should store a revisit record");
    };

    // The revisit uses the identical-payload-digest profile and points back at the original
    // record, capture URI, and date, sharing the original's payload digest.
    assert_eq!(revisit.profile, RevisitProfile::IDENTICAL_PAYLOAD_DIGEST);
    assert_eq!(revisit.target_uri.as_str(), url);
    assert_eq!(revisit.refers_to.as_ref(), Some(&original.core.record_id));
    assert_eq!(
        revisit.refers_to_target_uri.as_ref().map(Uri::as_str),
        Some(url.as_str())
    );
    assert_eq!(revisit.refers_to_date, Some(original.core.date));
    assert!(original.payload.payload_digest.is_some());
    assert_eq!(
        revisit.payload.payload_digest,
        original.payload.payload_digest
    );
    assert_eq!(revisit.core.content_type, Some(MediaType::HTTP_RESPONSE));
    assert_eq!(revisit.core.truncated, Some(TruncatedType::Length));

    // The revisit block is exactly the head of the (identical) response it stands for.
    assert!(revisit_body.ends_with(b"\r\n\r\n"));
    assert!(revisit_body.len() < original_body.len());
    assert_eq!(
        revisit_body.as_slice(),
        &original_body[..revisit_body.len()]
    );

    Ok(())
}

#[test]
fn a_repeat_of_a_validated_response_is_a_server_not_modified_revisit()
-> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(2, |request| {
        (respond_versioned(request, 1), request.clone())
    })?;
    let url = format!("http://127.0.0.1:{port}/page");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("revalidate.warc.gz");
    let mut observed = Vec::new();

    let summary = Session::new(
        archiver(gzip_config()),
        "revalidate",
        Crawl::seeds([&url])
            .dedupe_discoveries(false)
            .processor(RepeatingProcessor {
                remaining: 1,
                observed: Some(&mut observed),
            }),
        &output,
    )?
    .run()?;

    // The first request is unconditional; the repeat carries the stored response's validators.
    let requests = server.join().expect("server thread");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].header("if-none-match"), None);
    assert_eq!(requests[0].header("if-modified-since"), None);
    assert_eq!(requests[1].header("if-none-match"), Some("\"1\""));
    assert_eq!(requests[1].header("if-modified-since"), Some(LAST_MODIFIED));

    // The processor sees the revalidated repeat as a 304 with no payload.
    assert_eq!(
        observed,
        [
            (200, "<html>version 1</html>".to_owned()),
            (304, String::new())
        ]
    );
    assert!(summary.is_complete());
    assert_eq!(
        summary
            .seed_captures
            .iter()
            .chain(&summary.extra_captures)
            .map(|capture| capture.status)
            .collect::<Vec<_>>(),
        [200, 304]
    );

    let records = records(&std::fs::read(&output)?)?;

    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "response", "metadata", "request", "revisit", "metadata",
        ]
    );

    let Record::Response {
        header: original, ..
    } = &records[2]
    else {
        panic!("the first capture should store a full response record");
    };
    let Record::Revisit {
        header: revisit,
        body: revisit_body,
    } = &records[5]
    else {
        panic!("the revalidated repeat should store a revisit record");
    };

    // The revisit uses the server-not-modified profile, points back at the original record, and
    // stands for the original payload, whose digest it repeats.
    assert_eq!(revisit.profile, RevisitProfile::SERVER_NOT_MODIFIED);
    assert_eq!(revisit.target_uri.as_str(), url);
    assert_eq!(revisit.refers_to.as_ref(), Some(&original.core.record_id));
    assert_eq!(
        revisit.refers_to_target_uri.as_ref().map(Uri::as_str),
        Some(url.as_str())
    );
    assert_eq!(revisit.refers_to_date, Some(original.core.date));
    assert!(original.payload.payload_digest.is_some());
    assert_eq!(
        revisit.payload.payload_digest,
        original.payload.payload_digest
    );
    assert_eq!(revisit.core.content_type, Some(MediaType::HTTP_RESPONSE));

    // The revisit block is the whole `304` response as received, which is nothing but its head,
    // so it is not truncated.
    assert_eq!(revisit.core.truncated, None);
    assert!(revisit_body.starts_with(b"HTTP/1.1 304 Not Modified\r\n"));
    assert!(revisit_body.ends_with(b"\r\n\r\n"));

    Ok(())
}

#[test]
fn changed_content_is_repeated_in_full_and_revalidated_by_its_new_validators()
-> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(3, |request| {
        (respond_versioned(request, 2), request.clone())
    })?;
    let url = format!("http://127.0.0.1:{port}/page");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("changed.warc.gz");

    let summary = Session::new(
        archiver(gzip_config()),
        "changed",
        Crawl::seeds([&url])
            .dedupe_discoveries(false)
            .processor(RepeatingProcessor {
                remaining: 2,
                observed: None,
            }),
        &output,
    )?
    .run()?;

    // Each repeat is conditional on the latest stored version: the first finds the page changed
    // and is answered in full, and the second confirms the new version unchanged.
    let requests = server.join().expect("server thread");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.header("if-none-match"))
            .collect::<Vec<_>>(),
        [None, Some("\"1\""), Some("\"2\"")]
    );
    assert!(summary.is_complete());
    assert_eq!(
        summary
            .seed_captures
            .iter()
            .chain(&summary.extra_captures)
            .map(|capture| capture.status)
            .collect::<Vec<_>>(),
        [200, 200, 304]
    );

    let records = records(&std::fs::read(&output)?)?;

    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "response", "metadata", "request", "response", "metadata",
            "request", "revisit", "metadata",
        ]
    );

    let (Record::Response { header: first, .. }, Record::Response { header: second, .. }) =
        (&records[2], &records[5])
    else {
        panic!("both changed versions should store full response records");
    };
    let Record::Revisit {
        header: revisit, ..
    } = &records[8]
    else {
        panic!("the revalidated repeat should store a revisit record");
    };

    assert_ne!(first.payload.payload_digest, second.payload.payload_digest);
    assert_eq!(revisit.profile, RevisitProfile::SERVER_NOT_MODIFIED);
    assert_eq!(revisit.refers_to.as_ref(), Some(&second.core.record_id));
    assert_eq!(
        revisit.payload.payload_digest,
        second.payload.payload_digest
    );

    Ok(())
}

#[test]
fn session_waits_between_queued_requests() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(2, |_| {
        (
            response("200 OK", &[("content-type", "text/plain")], "ok"),
            Instant::now(),
        )
    })?;
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("delayed.warc.gz");
    let delay = Duration::from_millis(50);

    let summary = Session::new(
        archiver(gzip_config()),
        "delayed",
        Crawl::seeds([
            format!("http://127.0.0.1:{port}/first"),
            format!("http://127.0.0.1:{port}/second"),
        ]),
        output,
    )?
    .request_delay(delay)
    .run()?;
    let requests = server.join().expect("server thread should not panic");

    assert!(summary.is_complete());
    assert_eq!(requests.len(), 2);
    assert!(requests[1].duration_since(requests[0]) >= delay);

    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scripted exchange, read in order"
)]
fn session_crawls_discovered_urls_depth_first() -> Result<(), Box<dyn std::error::Error>> {
    // The seeds are the home page and a redirect whose final URL is /about. The home page links
    // directly to /about and /missing, which are requested before the second seed.
    let (port, server) = serve(5)?;
    let seeds = [
        format!("http://127.0.0.1:{port}/"),
        format!("http://127.0.0.1:{port}/redirect"),
    ];

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let summary = Session::new(
        archiver(Config {
            user_agent: "session-test/1.0".to_owned(),
            ..revisiting_config()
        }),
        "crawl-2026.08",
        Crawl::seeds(&seeds).processor(SiteProcessor { port }),
        &path,
    )?
    .software("session-test-crawler", "9.9")
    .run()?;
    let request_paths = server.join().expect("server thread should not panic");

    // The home page's discoveries are requested in processor order before the redirect seed, and
    // the link back to the home page from /about repeats a seed, so it is skipped.
    assert_eq!(
        request_paths,
        ["/", "/about", "/missing", "/redirect", "/about"]
    );

    assert!(summary.is_complete());
    assert_eq!(
        summary
            .seed_captures
            .iter()
            .map(|capture| capture.url.as_str())
            .collect::<Vec<_>>(),
        seeds.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(
        summary
            .extra_captures
            .iter()
            .map(|capture| (capture.url.as_str(), capture.status))
            .collect::<Vec<_>>(),
        vec![
            (format!("http://127.0.0.1:{port}/about").as_str(), 200),
            (format!("http://127.0.0.1:{port}/missing").as_str(), 404),
        ]
    );

    // The warcinfo record names the session and the User-Agent sent with every request.
    let records = records(&std::fs::read(&path)?)?;

    let Record::Warcinfo { header, body } = &records[0] else {
        panic!("the first record should be a warcinfo record");
    };
    let FieldsBlock::Fields(fields) = body else {
        panic!("the warcinfo body should parse as warc-fields");
    };

    assert_eq!(
        fields
            .iter()
            .map(|(field, _)| field.name())
            .collect::<Vec<_>>(),
        [
            "format",
            "conformsTo",
            "software",
            "operator",
            "http-header-user-agent",
            "isPartOf",
        ]
    );

    assert_eq!(
        header
            .filename
            .as_ref()
            .and_then(archivindex_warc::value::Text::to_str),
        Some("crawl-2026.08.warc.gz")
    );
    assert_eq!(fields.http_header_user_agent(), Some("session-test/1.0"));
    assert_eq!(
        fields.get(&WarcinfoField::Dcmi(DcmiTerm::IsPartOf)),
        Some("crawl-2026.08")
    );
    assert_eq!(fields.software(), Some("session-test-crawler/9.9"));
    assert_eq!(
        fields.operator(),
        Some("Test Operator <operator@example.com>")
    );

    // One warcinfo record, then request, response, and metadata records for each of the five
    // exchanges (the redirect seed contributes two hops). The redirect's /about response repeats
    // the discovered capture's payload, so it is stored as a revisit record.
    assert_eq!(records.len(), 16);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.type_name() == "revisit")
            .count(),
        1
    );

    // Discovered captures carry the URI of the page they were discovered on as `via` in their
    // metadata records; seed captures (redirect hops included) carry none. Both discoveries came
    // from the home page's payload, and a processor title goes on the final hop.
    let metadata = records
        .iter()
        .filter(|record| record.type_name() == "metadata")
        .map(|record| {
            let Record::Metadata {
                body: FieldsBlock::Fields(fields),
                ..
            } = record
            else {
                panic!("the metadata body should parse as warc-fields");
            };

            (
                fields.via(),
                fields.get(&MetadataField::Dcmi(DcmiTerm::Title)),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        metadata,
        vec![
            (None, Some("Home")),
            (Some(seeds[0].as_str()), Some("About")),
            (Some(seeds[0].as_str()), None),
            (None, None),
            (None, Some("About")),
        ]
    );

    Ok(())
}

#[test]
fn extras_are_captured_before_the_seeds_with_their_via() -> Result<(), Box<dyn std::error::Error>> {
    // The extra repeating the seed is captured as given, so the seed is requested twice.
    let (port, server) = serve(3)?;
    let home = format!("http://127.0.0.1:{port}/");
    let about = format!("http://127.0.0.1:{port}/about");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("extras.warc.gz");

    let crawl = Crawl::new([
        session::Request::extra(&about, "https://example.com/links"),
        session::Request::extra(&home, &about),
        session::Request::seed(&home),
    ]);
    let summary = Session::new(archiver(gzip_config()), "extras", crawl, &output)?.run()?;

    assert_eq!(server.join().expect("server thread"), ["/about", "/", "/"]);
    assert!(summary.is_complete());
    assert_eq!(
        summary
            .seed_captures
            .iter()
            .map(|capture| (capture.url.as_str(), &capture.origin))
            .collect::<Vec<_>>(),
        [(home.as_str(), &Origin::Seed)]
    );
    assert_eq!(
        summary
            .extra_captures
            .iter()
            .map(|capture| (capture.url.as_str(), &capture.origin))
            .collect::<Vec<_>>(),
        [
            (
                about.as_str(),
                &Origin::Extra {
                    via: "https://example.com/links".to_owned()
                }
            ),
            (home.as_str(), &Origin::Extra { via: about.clone() }),
        ]
    );

    let records = records(&std::fs::read(&output)?)?;
    let via = records
        .iter()
        .filter_map(|record| match record {
            Record::Metadata {
                body: FieldsBlock::Fields(fields),
                ..
            } => Some(fields.via()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        via,
        [
            Some("https://example.com/links"),
            Some(about.as_str()),
            None
        ]
    );

    Ok(())
}

#[test]
fn session_captures_post_requests_with_headers_and_bodies() -> Result<(), Box<dyn std::error::Error>>
{
    let (port, server) = serve_with(1, |request| {
        (
            response(
                "200 OK",
                &[("content-type", "application/json")],
                r#"{"ok":true}"#,
            ),
            request.clone(),
        )
    })?;
    let url = format!("http://127.0.0.1:{port}/lookup");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("post.warc");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        "x-api-key",
        http::HeaderValue::from_static("test-credential"),
    );
    let body = br#"{"email":"person@example.com"}"#.to_vec();
    let request = session::Request::post(&url, body.clone()).with_headers(headers);

    let summary = Session::new(
        archiver(Config::default()),
        "post",
        Crawl::new([request]),
        &output,
    )?
    .retry(RetryConfig {
        attempts: 1,
        ..RetryConfig::default()
    })
    .run()?;
    let requests = server.join().expect("server thread should not panic");

    assert!(summary.is_complete());
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].path(), "/lookup");
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
    assert_eq!(requests[0].header("x-api-key"), Some("test-credential"));
    assert_eq!(requests[0].body(), body);

    let archive = records(&std::fs::read(output)?)?;
    let recorded_request = archive.iter().find_map(|record| match record {
        Record::Request { body, .. } => Some(body.as_slice()),
        _ => None,
    });
    assert!(recorded_request.is_some_and(|request| request.ends_with(&body)));

    Ok(())
}

/// A response to a method other than `GET` or `HEAD` describes the outcome of acting on the
/// resource, not the bytes a later request will be given, so it must not become the state the next
/// `GET` of that URL revalidates against. Storing it would have that `GET` sent the `POST`
/// response's validators and record its `304` as a revisit of a payload it never received.
#[test]
fn a_post_response_is_not_stored_as_the_urls_representation()
-> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(2, |request| {
        (
            response(
                "200 OK",
                &[
                    ("content-type", "text/html"),
                    ("etag", "\"v1\""),
                    ("last-modified", LAST_MODIFIED),
                ],
                "<html>acted</html>",
            ),
            request.clone(),
        )
    })?;
    let url = format!("http://127.0.0.1:{port}/lookup");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("post-state.warc.gz");

    let summary = Session::new(
        archiver(gzip_config()),
        "post-state",
        Crawl::new([
            session::Request::post(&url, b"q=1".to_vec()),
            session::Request::seed(&url),
        ]),
        &output,
    )?
    .run()?;
    let requests = server.join().expect("server thread");

    assert!(summary.is_complete());
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[1].method(), "GET");

    // The `GET` is unconditional: the `POST` left no representation state to revalidate against.
    assert_eq!(requests[1].header("if-none-match"), None);
    assert_eq!(requests[1].header("if-modified-since"), None);

    // Both captures are stored in full, so neither claims a payload the other received.
    let records = records(&std::fs::read(&output)?)?;
    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "response", "metadata", "request", "response", "metadata",
        ]
    );

    Ok(())
}

/// A cookie a request supplies wins over a held pair of the same name, and the other pairs held
/// for the host still join it, so that supplying one does not withhold the clearance a challenge
/// issued, which the host expects back on every later request. Several supplied lines are sent as
/// the one value the grammar combines them into, which is also the value a declared `Vary: Cookie`
/// is resolved against.
#[test]
fn a_supplied_cookie_joins_the_pairs_held_for_the_host() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(1, |request| (respond(request.path()), request.clone()))?;
    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("supplied-cookie.warc.gz");
    let mut headers = http::HeaderMap::new();
    headers.append(
        http::header::COOKIE,
        http::HeaderValue::from_static("session=supplied"),
    );
    headers.append(
        http::header::COOKIE,
        http::HeaderValue::from_static("theme=dark"),
    );

    let summary = Session::new(
        archiver(gzip_config()).cookie_for(&url, "session=held; clearance=2")?,
        "supplied-cookie",
        Crawl::new([session::Request::seed(&url).with_headers(headers)]),
        &output,
    )?
    .run()?;
    let requests = server.join().expect("server thread");

    assert!(summary.is_complete());
    // The supplied lines and the held pairs are sent as one `Cookie` line, which is the value a
    // declared `Vary: Cookie` is resolved against on both the request and the record side.
    assert_eq!(
        requests[0]
            .head()
            .to_ascii_lowercase()
            .matches("\r\ncookie:")
            .count(),
        1
    );
    assert_eq!(
        requests[0].header("cookie"),
        Some("session=supplied; theme=dark; clearance=2")
    );

    Ok(())
}

/// A request the server may have already acted on is not replayed, whatever the retry
/// configuration allows, since repeating it would ask for that action a second time.
#[test]
fn a_post_that_fails_is_not_retried() -> Result<(), Box<dyn std::error::Error>> {
    let port = dead_port()?;
    let url = format!("http://127.0.0.1:{port}/submit");
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("post-retry.warc.gz");
    let started = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&started);

    let summary = Session::new(
        archiver(gzip_config()),
        "post-retry",
        Crawl::new([session::Request::post(&url, b"q=1".to_vec())]),
        &output,
    )?
    .events(move |event: CaptureEvent<'_>| {
        if matches!(event, CaptureEvent::Started { .. }) {
            counted.fetch_add(1, Ordering::Relaxed);
        }
        CaptureControl::Continue
    })
    .retry(RetryConfig {
        attempts: 4,
        initial_backoff: Duration::from_secs(30),
        max_backoff: Duration::from_secs(30),
    })
    .run()?;

    // The connection fails, which is transient, and a `GET` here would be attempted four times.
    assert!(!summary.is_complete());
    assert_eq!(summary.failures.len(), 1);
    assert_eq!(started.load(Ordering::Relaxed), 1);

    Ok(())
}

#[test]
fn session_skips_discoveries_that_repeat_a_given_url() -> Result<(), Box<dyn std::error::Error>> {
    // Every page links to both seeds and itself, and one seed repeats: the seeds are requested as
    // given, and no discovery is requested.
    let (port, server) = serve(3)?;
    let seeds = [
        format!("http://127.0.0.1:{port}/"),
        format!("http://127.0.0.1:{port}/"),
        format!("http://127.0.0.1:{port}/about"),
    ];

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let summary = Session::new(
        archiver(gzip_config()),
        "dedup",
        Crawl::seeds(&seeds).processor(DeduplicationProcessor { port }),
        &path,
    )?
    .operator("Solo", None)
    .run()?;
    let request_paths = server.join().expect("server thread should not panic");

    assert_eq!(request_paths, ["/", "/", "/about"]);
    assert!(summary.is_complete());
    assert_eq!(summary.seed_captures.len(), 3);
    assert!(summary.extra_captures.is_empty());

    // An operator override without an email replaces the configured operator and is recorded by
    // name alone; the software defaults to this crate.
    let records = records(&std::fs::read(&path)?)?;
    let Record::Warcinfo {
        body: FieldsBlock::Fields(fields),
        ..
    } = &records[0]
    else {
        panic!("the first record should be a warcinfo record with warc-fields");
    };

    assert_eq!(fields.operator(), Some("Solo"));
    assert_eq!(
        fields.software(),
        Some(concat!("archivindex-archiver/", env!("CARGO_PKG_VERSION")))
    );

    Ok(())
}

#[test]
fn session_starts_from_the_configured_settings() -> Result<(), Box<dyn std::error::Error>> {
    const BODY: &str = "<html>home links: /about /missing</html>";

    let (port, server) = serve(1)?;
    let url = format!("http://127.0.0.1:{port}/");

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("configured.warc.gz");
    let database = directory.path().join("configured-revisits.sqlite3");
    Index::open(&database)?.insert_payload(&RevisitTarget {
        payload_digest: sha256(BODY.as_bytes()),
        payload_length: Some(BODY.len() as u64),
        identified_payload_type: None,
        record_id: uri(EXTERNAL_RECORD_ID),
        target_uri: uri("https://archive.example/configured"),
        warc_date: warc_date("2025-01-01T00:00:00Z"),
    })?;

    let config = Config {
        software: Software {
            name: "configured-crawler".to_owned(),
            version: "3.1".to_owned(),
        },
        session: SessionConfig {
            revisit_index: Some(database),
            ..SessionConfig::default()
        },
        min_revisit_payload_length: 0,
        ..gzip_config()
    };
    let summary =
        Session::new(archiver(config), "configured", Crawl::seeds([&url]), &path)?.run()?;
    let request_paths = server.join().expect("server thread should not panic");

    assert_eq!(request_paths, ["/"]);
    assert!(summary.is_complete());
    assert_eq!(summary.seed_captures.len(), 1);
    assert_eq!(summary.extra_captures.len(), 0);

    // The configured software, operator, and revisit index are used without builder overrides.
    let records = records(&std::fs::read(&path)?)?;
    let Record::Warcinfo {
        body: FieldsBlock::Fields(fields),
        ..
    } = &records[0]
    else {
        panic!("the first record should be a warcinfo record with warc-fields");
    };

    assert_eq!(fields.software(), Some("configured-crawler/3.1"));
    assert_eq!(
        fields.operator(),
        Some("Test Operator <operator@example.com>")
    );
    let Record::Revisit { header, .. } = &records[2] else {
        panic!("the configured index's payload should produce a revisit");
    };
    assert_eq!(header.refers_to.as_ref(), Some(&uri(EXTERNAL_RECORD_ID)));

    Ok(())
}

#[test]
fn session_without_a_configured_operator_names_none() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve(1)?;
    let url = format!("http://127.0.0.1:{port}/");

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("anonymous.warc.gz");

    let config = Config {
        operator: None,
        ..gzip_config()
    };
    let summary = Session::new(archiver(config), "anonymous", Crawl::seeds([&url]), &path)?
        .limit(1)
        .run()?;
    server.join().expect("server thread should not panic");

    assert!(summary.is_complete());

    let records = records(&std::fs::read(&path)?)?;
    let Record::Warcinfo {
        body: FieldsBlock::Fields(fields),
        ..
    } = &records[0]
    else {
        panic!("the first record should be a warcinfo record with warc-fields");
    };

    assert_eq!(fields.operator(), None);
    assert_eq!(
        fields.software(),
        Some(concat!("archivindex-archiver/", env!("CARGO_PKG_VERSION")))
    );

    Ok(())
}

#[test]
fn session_limit_stops_with_discoveries_still_queued() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve(1)?;
    let url = format!("http://127.0.0.1:{port}/");

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("limited.warc.gz");

    let mut crawl = Crawl::seeds([&url]).processor(SiteProcessor { port });
    let summary = Session::new(archiver(gzip_config()), "limited", &mut crawl, &path)?
        .limit(1)
        .run()?;
    let request_paths = server.join().expect("server thread should not panic");

    assert_eq!(request_paths, ["/"]);
    assert!(summary.is_complete());
    assert_eq!(summary.seed_captures.len(), 1);
    assert_eq!(summary.extra_captures.len(), 0);

    // The home page's discoveries are left for a later session, in the order they would have been
    // requested.
    assert_eq!(
        crawl.unrequested().cloned().collect::<Vec<_>>(),
        [
            session::Request::extra(format!("http://127.0.0.1:{port}/about"), &url),
            session::Request::extra(format!("http://127.0.0.1:{port}/missing"), &url),
        ]
    );
    assert_eq!(records(&std::fs::read(&path)?)?.len(), 4);

    Ok(())
}

#[test]
fn session_rejects_an_unwritable_operator_before_writing() -> Result<(), Box<dyn std::error::Error>>
{
    // Reject the invalid operator before creating output or contacting the deliberately unreachable
    // seed.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let result = Session::new(
        archiver(gzip_config()),
        "bad-operator",
        Crawl::seeds(["http://127.0.0.1:9/"]),
        &path,
    )?
    .operator("Line\r\nBreak", None)
    .run();

    assert!(matches!(result, Err(Error::WarcFields(_))));
    assert!(!path.exists());

    Ok(())
}

#[test]
fn session_retries_transient_failures_with_backoff() -> Result<(), Box<dyn std::error::Error>> {
    // The first connection stalls past the client timeout before responding; the retry is then
    // served promptly.
    let (port, server) = serve_concurrently_with(2, |attempt, request| {
        if attempt == 0 {
            thread::sleep(Duration::from_millis(300));
        }
        (respond(request.path()), ())
    })?;

    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let summary = Session::new(
        archiver(Config {
            timeout: Duration::from_millis(100),
            ..gzip_config()
        }),
        "retry",
        Crawl::seeds([&url]),
        &path,
    )?
    .retry(RetryConfig {
        attempts: 3,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
    })
    .run()?;
    server.join().expect("server thread should not panic");

    assert!(summary.is_complete());
    assert_eq!(summary.seed_captures.len(), 1);
    assert_eq!(summary.seed_captures[0].status, 200);

    // The stalled attempt completed no exchange: one warcinfo record plus one exchange's records.
    assert_eq!(records(&std::fs::read(&path)?)?.len(), 4);

    Ok(())
}

#[test]
fn session_retries_retryable_http_statuses() -> Result<(), Box<dyn std::error::Error>> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let server_attempts = Arc::clone(&attempts);
    let (port, server) = serve_with(2, move |request| {
        let attempt = server_attempts.fetch_add(1, Ordering::Relaxed);
        let reply = if attempt == 0 {
            response(
                "503 Service Unavailable",
                &[("content-type", "text/plain"), ("retry-after", "0")],
                "try later",
            )
        } else {
            response("200 OK", &[("content-type", "text/plain")], "complete")
        };
        (reply, request.path().to_owned())
    })?;
    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("status-retry.warc.gz");
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_for_sink = Arc::clone(&events);

    let summary = Session::new(
        archiver(gzip_config()),
        "status-retry",
        Crawl::seeds([&url]),
        &path,
    )?
    .events(move |event: CaptureEvent<'_>| {
        events_for_sink
            .lock()
            .expect("event lock")
            .push(match event {
                CaptureEvent::Started { attempt, .. } => format!("started:{attempt}"),
                CaptureEvent::Retrying { attempt, .. } => format!("retrying:{attempt}"),
                CaptureEvent::Captured { .. } => "captured".to_owned(),
                CaptureEvent::Written { .. } => "written".to_owned(),
                CaptureEvent::Failed { .. } => "failed".to_owned(),
            });
        CaptureControl::Continue
    })
    .retry(RetryConfig {
        attempts: 2,
        initial_backoff: Duration::from_secs(30),
        max_backoff: Duration::from_secs(30),
    })
    .run()?;
    let requests = server.join().expect("server thread should not panic");

    assert_eq!(attempts.load(Ordering::Relaxed), 2);
    assert_eq!(requests, ["/", "/"]);
    assert!(summary.is_complete());
    assert_eq!(summary.seed_captures[0].status, 200);
    assert_eq!(
        *events.lock().expect("event lock"),
        [
            "started:1",
            "retrying:2",
            "started:2",
            "captured",
            "written"
        ]
    );

    // Both attempts are archived, the 503 ahead of the 200.
    let records = records(&std::fs::read(&path)?)?;
    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "response", "metadata", "request", "response", "metadata"
        ]
    );
    let (Record::Response { body: first, .. }, Record::Response { body: second, .. }) =
        (&records[2], &records[5])
    else {
        panic!("both attempts should store full response records");
    };
    assert!(first.starts_with(b"HTTP/1.1 503 ") && first.ends_with(b"try later"));
    assert!(second.starts_with(b"HTTP/1.1 200 ") && second.ends_with(b"complete"));

    Ok(())
}

#[test]
fn session_honours_an_http_date_retry_after() -> Result<(), Box<dyn std::error::Error>> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let server_attempts = Arc::clone(&attempts);
    let (port, server) = serve_with(2, move |request| {
        let attempt = server_attempts.fetch_add(1, Ordering::Relaxed);
        let reply = if attempt == 0 {
            // A real `Retry-After` date is an IMF-fixdate in GMT, not RFC 2822's `+0000` form.
            let retry_at = (chrono::Utc::now() + chrono::Duration::seconds(2))
                .format("%a, %d %b %Y %H:%M:%S GMT");
            response(
                "503 Service Unavailable",
                &[
                    ("content-type", "text/plain"),
                    ("retry-after", &retry_at.to_string()),
                ],
                "try later",
            )
        } else {
            response("200 OK", &[("content-type", "text/plain")], "complete")
        };
        (reply, request.path().to_owned())
    })?;
    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("date-retry.warc.gz");
    let delays = Arc::new(Mutex::new(Vec::new()));
    let delays_for_sink = Arc::clone(&delays);

    let summary = Session::new(
        archiver(gzip_config()),
        "date-retry",
        Crawl::seeds([&url]),
        &path,
    )?
    .events(move |event: CaptureEvent<'_>| {
        if let CaptureEvent::Retrying { delay, .. } = event {
            delays_for_sink.lock().expect("delay lock").push(delay);
        }
        CaptureControl::Continue
    })
    .retry(RetryConfig {
        attempts: 2,
        initial_backoff: Duration::from_secs(30),
        max_backoff: Duration::from_secs(30),
    })
    .run()?;
    server.join().expect("server thread should not panic");

    assert_eq!(attempts.load(Ordering::Relaxed), 2);
    assert!(summary.is_complete());
    // The header's date, not the 30 s backoff, set the delay.
    let delays = delays.lock().expect("delay lock").clone();
    assert_eq!(delays.len(), 1);
    assert!(delays[0] <= Duration::from_secs(2), "delay {:?}", delays[0]);

    Ok(())
}

#[test]
fn session_reports_exhausted_http_status_retries() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(2, |request| {
        (
            response(
                "503 Service Unavailable",
                &[("content-type", "text/plain")],
                "busy",
            ),
            request.path().to_owned(),
        )
    })?;
    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("status-exhausted.warc.gz");

    let summary = Session::new(
        archiver(revisiting_config()),
        "status-exhausted",
        Crawl::seeds([&url]),
        &path,
    )?
    .retry(RetryConfig {
        attempts: 2,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
    })
    .run()?;
    server.join().expect("server thread should not panic");

    assert!(!summary.is_complete());
    assert!(matches!(
        summary.failures[0].error,
        Error::HttpStatus { status: 503, .. }
    ));

    // Every attempt's response is archived, the repeated body as a revisit, though the URL is
    // recorded as a failure.
    let records = records(&std::fs::read(&path)?)?;
    assert_eq!(
        records.iter().map(Record::type_name).collect::<Vec<_>>(),
        [
            "warcinfo", "request", "response", "metadata", "request", "revisit", "metadata"
        ]
    );

    Ok(())
}

#[test]
fn session_cancelled_during_a_retry_keeps_the_completed_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve_with(1, |request| {
        (
            response(
                "503 Service Unavailable",
                &[("content-type", "text/plain")],
                "busy",
            ),
            request.path().to_owned(),
        )
    })?;
    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("status-cancelled.warc.gz");

    let mut crawl = Crawl::seeds([&url]);
    let summary = Session::new(
        archiver(gzip_config()),
        "status-cancelled",
        &mut crawl,
        &path,
    )?
    .events(|event: CaptureEvent<'_>| {
        if matches!(event, CaptureEvent::Retrying { .. }) {
            CaptureControl::Cancel
        } else {
            CaptureControl::Continue
        }
    })
    .retry(RetryConfig {
        attempts: 2,
        initial_backoff: Duration::from_secs(30),
        max_backoff: Duration::from_secs(30),
    })
    .run()?;
    server.join().expect("server thread should not panic");

    // The cancelled capture is neither a capture nor a failure, but its 503 exchange is archived,
    // and the URL is left to request again.
    assert!(summary.cancelled);
    assert!(summary.seed_captures.is_empty());
    assert!(summary.failures.is_empty());
    assert_eq!(
        crawl.unrequested().cloned().collect::<Vec<_>>(),
        [session::Request::seed(url)]
    );
    assert_eq!(
        records(&std::fs::read(&path)?)?
            .iter()
            .map(Record::type_name)
            .collect::<Vec<_>>(),
        ["warcinfo", "request", "response", "metadata"]
    );

    Ok(())
}

#[test]
fn processor_failure_stops_with_an_incomplete_summary() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve(1)?;
    let url = format!("http://127.0.0.1:{port}/");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("processor-failure.warc.gz");

    let summary = Session::new(
        archiver(gzip_config()),
        "processor-failure",
        Crawl::seeds([&url]).processor(FailingProcessor),
        &path,
    )?
    .run()?;
    server.join().expect("server thread should not panic");

    assert!(!summary.is_complete());
    assert!(matches!(summary.failures[0].error, Error::Driver { .. }));

    Ok(())
}

#[test]
fn session_reports_exhausted_retries_as_failures() -> Result<(), Box<dyn std::error::Error>> {
    let port = dead_port()?;
    let url = format!("http://127.0.0.1:{port}/");

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let summary = Session::new(
        archiver(gzip_config()),
        "unreachable",
        Crawl::seeds([&url]),
        &path,
    )?
    .retry(RetryConfig {
        attempts: 2,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(10),
    })
    .run()?;

    assert!(!summary.is_complete());
    assert!(summary.fatal_error.is_none());
    assert_eq!(summary.failures.len(), 1);
    assert_eq!(summary.failures[0].url, url);

    // The WARC is still written, holding only its warcinfo record.
    assert_eq!(records(&std::fs::read(&path)?)?.len(), 1);

    Ok(())
}

#[test]
fn session_does_not_retry_permanent_failures() -> Result<(), Box<dyn std::error::Error>> {
    // A hostless URL is a permanent error, regardless of the retry settings.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let summary = Session::new(
        archiver(gzip_config()),
        "no-retry",
        Crawl::seeds(["data:text/plain,hi"]),
        &path,
    )?
    .retry(RetryConfig {
        attempts: 100,
        initial_backoff: Duration::from_secs(60),
        max_backoff: Duration::from_secs(60),
    })
    .run()?;

    assert!(!summary.is_complete());
    assert!(matches!(summary.failures[0].error, Error::MissingHost(_)));

    Ok(())
}

#[test]
fn session_rejects_invalid_identifiers() {
    let seeds: [&str; 0] = [];

    for id in ["", "has space", "sl/ash", "qu?ery", "ünïcode"] {
        assert!(
            Session::new(
                archiver(gzip_config()),
                id,
                Crawl::seeds(seeds),
                "out.warc.gz"
            )
            .is_err(),
            "identifier {id:?} should be rejected"
        );
    }

    assert!(
        Session::new(
            archiver(gzip_config()),
            "ok-id_1.2~3",
            Crawl::seeds(seeds),
            "out.warc.gz"
        )
        .is_ok()
    );
}

#[test]
fn session_refuses_an_existing_output() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");
    let database = directory.path().join("state.sqlite3");
    std::fs::write(&path, b"existing")?;
    let url = "https://example.com/";

    let result = Session::new(
        archiver(gzip_config()),
        "existing",
        Crawl::seeds([url]),
        &path,
    )?
    .revisit_index(&database)
    .run();

    assert!(result.is_err());
    let key = ResourceKey::new(Uri::parse(url)?.to_owned());
    assert!(Index::open(database)?.lookup_resource(&key)?.is_none());

    Ok(())
}

#[test]
fn session_with_no_seeds_writes_an_empty_collection() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let seeds: [&str; 0] = [];
    let summary =
        Session::new(archiver(gzip_config()), "empty", Crawl::seeds(seeds), &path)?.run()?;

    assert!(summary.is_complete());
    assert!(summary.seed_captures.is_empty());

    // The WARC holds only its warcinfo record.
    assert_eq!(records(&std::fs::read(&path)?)?.len(), 1);

    Ok(())
}

#[test]
fn session_writes_to_named_partial_before_publishing() -> Result<(), Box<dyn std::error::Error>> {
    let (port, server) = serve(1)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");
    let partial_path = directory.path().join("session.warc.gz.partial");
    let url = format!("http://127.0.0.1:{port}/");
    let mut saw_partial = false;

    let summary = Session::new(
        archiver(gzip_config()),
        "visible-partial",
        Crawl::seeds([&url]),
        &path,
    )?
    .events(|event: CaptureEvent<'_>| {
        if matches!(event, CaptureEvent::Started { .. }) {
            saw_partial = true;
            assert!(partial_path.exists());
            assert!(std::fs::metadata(&partial_path).is_ok_and(|metadata| metadata.len() > 0));
            assert!(!path.exists());
        }
        CaptureControl::Continue
    })
    .run()?;
    server.join().expect("server thread should not panic");

    assert!(summary.is_complete());
    assert!(saw_partial);
    assert!(path.exists());
    assert!(!partial_path.exists());

    Ok(())
}

#[test]
fn session_processor_sees_the_final_response_of_a_chain() -> Result<(), Box<dyn std::error::Error>>
{
    // The redirect seed's processor runs on /about's payload (the final hop), and the reported
    // final URL names the hop rather than the seed.
    let (port, server) = serve(2)?;
    let url = format!("http://127.0.0.1:{port}/redirect");

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let mut observed = Vec::new();
    let summary = Session::new(
        archiver(gzip_config()),
        "final-hop",
        Crawl::seeds([&url]).processor(ObservingProcessor {
            observed: &mut observed,
        }),
        &path,
    )?
    .run()?;
    server.join().expect("server thread should not panic");

    assert!(summary.is_complete());
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, url);
    assert_eq!(observed[0].1, format!("http://127.0.0.1:{port}/about"));
    assert_eq!(observed[0].2, 200);
    assert!(observed[0].3.contains("about links"));

    Ok(())
}

#[test]
fn session_skips_a_discovery_that_repeats_a_later_seed() -> Result<(), Box<dyn std::error::Error>> {
    // A discovered URL that repeats a seed is skipped even when found before the seed itself is
    // requested, and the seed is still requested in its turn.
    let (port, server) = serve(3)?;
    let seeds = [
        format!("http://127.0.0.1:{port}/"),
        format!("http://127.0.0.1:{port}/about"),
    ];

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("session.warc.gz");

    let about = seeds[1].clone();
    let missing = format!("http://127.0.0.1:{port}/missing");
    let discovered = vec![about, missing.clone()];
    let summary = Session::new(
        archiver(gzip_config()),
        "seed-set",
        Crawl::seeds(&seeds).processor(FixedLinksProcessor { links: discovered }),
        &path,
    )?
    .run()?;

    assert_eq!(
        server.join().expect("server thread should not panic"),
        ["/", "/missing", "/about"]
    );

    assert!(
        summary.is_complete(),
        "failures: {:?}, fatal: {:?}",
        summary
            .failures
            .iter()
            .map(|failure| (failure.url.as_str(), failure.error.to_string()))
            .collect::<Vec<_>>(),
        summary.fatal_error
    );
    assert_eq!(
        summary
            .seed_captures
            .iter()
            .map(|capture| capture.url.as_str())
            .collect::<Vec<_>>(),
        seeds.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(
        summary
            .extra_captures
            .iter()
            .map(|capture| capture.url.as_str())
            .collect::<Vec<_>>(),
        [missing.as_str()]
    );

    Ok(())
}

#[derive(Default)]
struct RecordingDriver {
    requests: std::collections::VecDeque<session::Request>,
    inspection: session::Inspection,
    inspected: usize,
    acknowledgments: Vec<Option<CaptureSummary>>,
}

impl session::Driver for RecordingDriver {
    fn next(&mut self) -> Option<session::Request> {
        assert_eq!(self.inspected, self.acknowledgments.len());
        self.requests.pop_front()
    }

    fn inspect(&mut self, _: &Capture<'_>) -> session::Inspection {
        self.inspected += 1;
        self.inspection.clone()
    }

    fn recorded(&mut self, capture: Option<&CaptureSummary>) {
        self.acknowledgments.push(capture.cloned());
    }
}

#[test]
fn recording_acknowledgment_respects_cancellation_and_failures()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in [
        "started",
        "captured",
        "written",
        "rejected",
        "record-error",
        "publish-error",
    ] {
        let (port, server) = serve(usize::from(mode != "started"))?;
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("acknowledged.warc.gz");
        let mut driver = RecordingDriver {
            requests: [session::Request::seed(format!("http://127.0.0.1:{port}/"))].into(),
            inspection: session::Inspection {
                error: (mode == "rejected").then(|| "rejected".to_owned()),
                title: (mode == "record-error").then(|| "invalid\0title".to_owned()),
            },
            ..RecordingDriver::default()
        };
        let result = Session::new(
            archiver(gzip_config()),
            "acknowledged",
            &mut driver,
            &output,
        )?
        .events(|event: CaptureEvent<'_>| {
            if matches!(event, CaptureEvent::Written { .. }) && mode == "publish-error" {
                std::fs::write(&output, b"existing output").expect("create publication collision");
            }
            if matches!(
                (mode, event),
                ("started", CaptureEvent::Started { .. })
                    | ("captured", CaptureEvent::Captured { .. })
                    | ("written", CaptureEvent::Written { .. })
            ) {
                CaptureControl::Cancel
            } else {
                CaptureControl::Continue
            }
        })
        .run();
        server.join().expect("server thread");
        assert_eq!(driver.inspected, usize::from(mode != "started"), "{mode}");
        match mode {
            "record-error" => {
                assert!(driver.acknowledgments.is_empty());
                assert!(
                    result.is_err()
                        || result
                            .as_ref()
                            .is_ok_and(|summary| summary.fatal_error.is_some())
                );
            }
            "started" => {
                assert!(driver.acknowledgments.is_empty());
                assert!(result?.cancelled);
            }
            "publish-error" => {
                assert!(result.is_err());
                assert_eq!(driver.acknowledgments.len(), 1);
                assert_eq!(std::fs::read(&output)?, b"existing output");
            }
            "rejected" => {
                assert_eq!(driver.acknowledgments, [None]);
                assert_eq!(result?.failures.len(), 1);
            }
            _ => {
                let summary = result?;
                assert!(summary.cancelled);
                assert_eq!(
                    driver.acknowledgments,
                    [Some(summary.seed_captures[0].clone())]
                );
            }
        }
    }
    Ok(())
}

#[test]
fn recording_acknowledgment_identifies_partial_occurrences_of_a_repeated_url()
-> Result<(), Box<dyn std::error::Error>> {
    let count = AtomicUsize::new(0);
    let (port, server) = serve_with(3, move |_| {
        let bytes = if count.fetch_add(1, Ordering::Relaxed) == 1 {
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort".to_vec()
        } else {
            response("200 OK", &[], "complete")
        };
        (bytes, ())
    })?;
    let directory = tempfile::tempdir()?;
    let mut driver = RecordingDriver {
        requests: vec![session::Request::seed(format!("http://127.0.0.1:{port}/")); 3].into(),
        ..RecordingDriver::default()
    };
    let summary = Session::new(
        archiver(gzip_config()),
        "partial",
        &mut driver,
        directory.path().join("partial.warc.gz"),
    )?
    .retry(RetryConfig {
        attempts: 1,
        ..RetryConfig::default()
    })
    .run()?;
    server.join().expect("server thread");
    assert_eq!(
        driver.acknowledgments,
        summary
            .seed_captures
            .iter()
            .cloned()
            .map(Some)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        summary
            .seed_captures
            .iter()
            .map(CaptureSummary::is_partial)
            .collect::<Vec<_>>(),
        [false, true, false]
    );
    Ok(())
}
