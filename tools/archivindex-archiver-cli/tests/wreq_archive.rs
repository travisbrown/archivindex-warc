//! WARC integration and application-exchange attribution for the optional backend.
use std::sync::atomic::{AtomicUsize, Ordering};

use archivindex_archiver::config::Software;
use archivindex_archiver::{Archiver, Config};
use archivindex_http_client::Engine;
use archivindex_http_client::wreq::WreqClient;
use archivindex_test_support::http::proxy::RecordingProxy;
use archivindex_test_support::http::{RequestExt as _, response, serve_with};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::{FieldsBlock, Record};
use data_encoding::BASE64;
use wreq_util::Profile;

/// The software field of the `warcinfo` record ends with the backend and the profile it emulates.
#[test]
fn redirects_and_challenge_answers_are_archived_exactly_once() {
    let script = "v='clearance';document.cookie='sucuri_cloudproxy_uuid_test=' + v + ';path=/;max-age=86400;SameSite=Lax'; location.reload();";
    let encoded = BASE64.encode(script.as_bytes());
    let challenge =
        format!("<html><script>var sucuri_cloudproxy_js='',S='{encoded}';</script></html>");
    let attempt = AtomicUsize::new(0);
    let server = serve_with(3, move |request| {
        let reply = match attempt.fetch_add(1, Ordering::Relaxed) {
            0 => response(302, &[("location", "/challenge")], ""),
            1 => response(
                307,
                &[("content-type", "text/html"), ("x-sucuri-id", "12005")],
                &challenge,
            ),
            _ => {
                assert_eq!(
                    request.header("cookie"),
                    Some("sucuri_cloudproxy_uuid_test=clearance")
                );
                response(200, &[("X-MiXeD", "yes")], "accepted")
            }
        };
        (reply, ())
    })
    .unwrap();
    let port = server.port();
    let proxy = RecordingProxy::start(port, |_, bytes| {
        let text = String::from_utf8(std::mem::take(bytes)).unwrap();
        *bytes = text
            .replace("302 Found", "302 Follow Me")
            .replace("307 Temporary Redirect", "307 Challenge")
            .replace("200 OK", "200 Accepted")
            .replace("x-mixed: yes", "X-MiXeD: yes")
            .into_bytes();
    })
    .unwrap();
    let port = proxy.port();
    let archiver = Archiver::with_backend(
        Config::default(),
        std::sync::Arc::new(WreqClient::new(Profile::Chrome136)),
    )
    .unwrap();
    let mut output = Vec::new();
    let summary = archiver
        .archive([format!("http://127.0.0.1:{port}/start")], &mut output)
        .unwrap();
    assert!(summary.is_complete(), "{summary:?}");
    let observed = proxy.finish().unwrap();
    let _ = server.finish();
    let records = WarcReader::new(output.as_slice())
        .iter_records::<NoExtension>()
        .records()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let requests: Vec<_> = records
        .iter()
        .filter(|r| r.type_name() == "request")
        .collect();
    let responses: Vec<_> = records
        .iter()
        .filter(|r| r.type_name() == "response")
        .collect();
    assert!(records.iter().all(|record| record.protocols().is_empty()));
    assert_eq!(requests.len(), 3);
    assert_eq!(responses.len(), 3);
    for ((request, response), exchange) in requests.iter().zip(responses).zip(observed) {
        assert_eq!(request.body_bytes().as_ref(), exchange.request);
        assert_eq!(response.body_bytes().as_ref(), exchange.response);
    }
    let Record::Warcinfo {
        body: FieldsBlock::Fields(fields),
        ..
    } = &records[0]
    else {
        panic!("the first record should be a warcinfo record with warc-fields");
    };
    let Software { name, version } = Software::default();
    let engine = Engine::wreq_with_profile(Profile::Chrome136);
    assert_eq!(engine.profile, Some("chrome_136"));
    assert_eq!(
        fields.software(),
        Some(format!("{name}/{version} {engine}").as_str())
    );
}

#[test]
fn profiles_are_named_explicitly_and_validated() {
    assert_eq!(
        archivindex_http_client::wreq::parse_profile("chrome_136").unwrap(),
        Profile::Chrome136
    );
    assert!(archivindex_http_client::wreq::parse_profile("chrome_136 ").is_err());
    assert!(archivindex_http_client::wreq::parse_profile("not_a_browser").is_err());
    assert!(archivindex_http_client::wreq::parse_profile("").is_err());
}
