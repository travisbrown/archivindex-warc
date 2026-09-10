//! WARC integration and application-exchange attribution for the optional backend.
use std::sync::atomic::{AtomicUsize, Ordering};

use archivindex_archiver::{Archiver, Config};
use archivindex_archiver_backend_wreq::{Profile, WreqBackend};
use archivindex_test_support::http::{response, serve_with};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use data_encoding::BASE64;

#[test]
fn redirects_and_challenge_answers_are_archived_exactly_once() {
    let script = "v='clearance';document.cookie='sucuri_cloudproxy_uuid_test=' + v + ';path=/;max-age=86400;SameSite=Lax'; location.reload();";
    let encoded = BASE64.encode(script.as_bytes());
    let challenge =
        format!("<html><script>var sucuri_cloudproxy_js='',S='{encoded}';</script></html>");
    let attempt = AtomicUsize::new(0);
    let (port, server) = serve_with(3, move |request| {
        let reply = match attempt.fetch_add(1, Ordering::Relaxed) {
            0 => response("302 Follow Me", &[("location", "/challenge")], ""),
            1 => response(
                "307 Challenge",
                &[("content-type", "text/html"), ("x-sucuri-id", "12005")],
                &challenge,
            ),
            _ => {
                assert_eq!(
                    request.header("cookie"),
                    Some("sucuri_cloudproxy_uuid_test=clearance")
                );
                response("200 Accepted", &[("X-MiXeD", "yes")], "accepted")
            }
        };
        let observed = (request.bytes().to_vec(), reply.clone());
        (reply, observed)
    })
    .unwrap();
    let archiver = Archiver::with_backend(
        Config::default(),
        std::sync::Arc::new(WreqBackend::new(Profile::Chrome136)),
    )
    .unwrap();
    let mut output = Vec::new();
    let summary = archiver
        .archive([format!("http://127.0.0.1:{port}/start")], &mut output)
        .unwrap();
    assert!(summary.is_complete(), "{summary:?}");
    let observed = server.join().unwrap();
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
    assert_eq!(requests.len(), 3);
    assert_eq!(responses.len(), 3);
    for ((request, response), (sent, received)) in requests.iter().zip(responses).zip(observed) {
        assert_eq!(request.body_bytes().as_ref(), sent);
        assert_eq!(response.body_bytes().as_ref(), received);
    }
}

#[test]
fn profiles_are_named_explicitly_and_validated() {
    assert_eq!(
        archivindex_archiver_backend_wreq::parse_profile("chrome_136").unwrap(),
        Profile::Chrome136
    );
    assert!(archivindex_archiver_backend_wreq::parse_profile("chrome_136 ").is_err());
    assert!(archivindex_archiver_backend_wreq::parse_profile("not_a_browser").is_err());
    assert!(archivindex_archiver_backend_wreq::parse_profile("").is_err());
}
