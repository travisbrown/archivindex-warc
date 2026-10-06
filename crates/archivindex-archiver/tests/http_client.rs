//! WARC records and summaries produced from the shared HTTP client's transport metadata.

use std::sync::Arc;
use std::time::{Duration, Instant};

use archivindex_archiver::{Archiver, Config};
use archivindex_http::message::ResponseMetadata;
use archivindex_http_client::framing::Truncation;
use archivindex_http_client::{
    Client, Exchange as HttpExchange, Fidelity, HttpProtocol, Request, TlsVersion,
};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::header::protocol::Protocol;
use archivindex_warc::record::header::truncated_type::TruncatedType;

#[derive(Debug)]
struct Captured(HttpExchange);

impl Client for Captured {
    fn fetch_with_deadline(
        &self,
        _: Request<'_>,
        _: Option<Instant>,
    ) -> Result<HttpExchange, archivindex_http_client::Error> {
        Ok(self.0.clone())
    }
}

#[test]
fn transport_metadata_is_recorded_on_the_correct_warc_records() {
    for (target, http_protocol, tls_version, protocols) in [
        ("http://example.com/", HttpProtocol::Http1, None, vec![]),
        (
            "http://example.com/",
            HttpProtocol::Http2,
            None,
            vec![Protocol::H2C],
        ),
        (
            "https://example.com/",
            HttpProtocol::Http1,
            Some(TlsVersion::V1_2),
            vec![Protocol::TLS_1_2],
        ),
        (
            "https://example.com/",
            HttpProtocol::Http2,
            Some(TlsVersion::V1_3),
            vec![Protocol::H2, Protocol::TLS_1_3],
        ),
    ] {
        for (truncated, reason) in [
            (None, None),
            (Some(Truncation::Length), Some(TruncatedType::Length)),
            (Some(Truncation::Time), Some(TruncatedType::Time)),
            (
                Some(Truncation::Disconnect),
                Some(TruncatedType::Disconnect),
            ),
        ] {
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
            let ip_address = Some("192.0.2.1".parse().unwrap());
            let started_at = "2026-10-06T12:34:56.123456Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap();
            let captured = HttpExchange {
                request: request.clone(),
                status: 200,
                response_body_offset: ResponseMetadata::parse(&response).unwrap().body_offset,
                response: response.clone(),
                fidelity: Fidelity::Reconstructed,
                http_protocol,
                tls_version,
                target_uri: target.to_owned().parse().unwrap(),
                ip_address,
                started_at,
                fetch_time: Duration::from_millis(25),
                truncated,
            };
            let archiver =
                Archiver::with_backend(Config::default(), Arc::new(Captured(captured))).unwrap();
            let mut bytes = Vec::new();
            let summary = archiver.archive([target], &mut bytes).unwrap();
            assert!(summary.failures.is_empty(), "{summary:?}");
            assert_eq!(summary.captures[0].truncated, reason);
            assert_eq!(
                summary.is_complete(),
                !matches!(truncated, Some(Truncation::Time | Truncation::Disconnect))
            );
            let records = WarcReader::new(bytes.as_slice())
                .iter_records::<NoExtension>()
                .records()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let request_record = records.iter().find(|r| r.type_name() == "request").unwrap();
            let response_record = records
                .iter()
                .find(|r| r.type_name() == "response")
                .unwrap();
            assert_eq!(request_record.core().date.date_time(), started_at);
            assert_eq!(response_record.core().date.date_time(), started_at);
            assert_eq!(request_record.protocols(), protocols);
            assert_eq!(response_record.protocols(), protocols);
            assert_eq!(request_record.core().truncated, None);
            assert_eq!(response_record.core().truncated, reason);
            assert_eq!(request_record.ip_address(), None);
            assert_eq!(response_record.ip_address(), ip_address);
            assert_eq!(request_record.body_bytes().as_ref(), request);
            assert_eq!(response_record.body_bytes().as_ref(), response);
        }
    }
}

/// A reconstructed client supplies the same WARC capture interface as the recorder.
#[test]
fn reqwest_exchanges_can_be_archived_without_an_adapter() {
    use archivindex_http_client::reqwest::ReqwestClient;
    use archivindex_test_support::http::{response, serve_with};

    let server = serve_with(1, |_| {
        (
            response(200, &[("content-type", "text/plain")], "hello"),
            (),
        )
    })
    .unwrap();
    let target = format!("http://127.0.0.1:{}/", server.port());
    let archiver =
        Archiver::with_backend(Config::default(), Arc::new(ReqwestClient::new())).unwrap();
    let mut bytes = Vec::new();
    let summary = archiver.archive([target], &mut bytes).unwrap();
    assert!(summary.is_complete(), "{summary:?}");
    let _ = server.finish();
    let records = WarcReader::new(bytes.as_slice())
        .iter_records::<NoExtension>()
        .records()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let response = records
        .iter()
        .find(|r| r.type_name() == "response")
        .unwrap();
    assert_eq!(
        response.payload_bytes().unwrap().unwrap().as_ref(),
        b"hello"
    );
}
