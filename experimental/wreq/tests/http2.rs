//! Negotiated HTTP/2 capture against a local TLS server, independent of external sites.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use archivindex_archiver::{Archiver, Config};
use archivindex_archiver_backend_wreq::{Profile, WreqBackend};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::header::protocol::Protocol;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use http::{HeaderMap, Method, Response, StatusCode, Uri, Version};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Finish {
    Complete,
    Trailers,
    Stall,
    Reset,
}

#[derive(Clone, Copy)]
struct Reply {
    status: StatusCode,
    body: &'static [u8],
    finish: Finish,
    before_headers: bool,
    encoded: bool,
}

impl Default for Reply {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            body: b"hello",
            finish: Finish::Complete,
            before_headers: false,
            encoded: false,
        }
    }
}

struct Received {
    headers: HeaderMap,
    body: Vec<u8>,
}

fn serve(reply: Reply, count: usize) -> (Uri, WreqBackend, thread::JoinHandle<Vec<Received>>) {
    serve_with_versions(reply, &vec![&rustls::version::TLS13; count])
}

fn serve_with_versions(
    reply: Reply,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> (Uri, WreqBackend, thread::JoinHandle<Vec<Received>>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = cert.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let acceptors: Vec<_> = versions
        .iter()
        .map(|version| {
            let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key.clone_key().into())
                .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];
            (TlsAcceptor::from(Arc::new(config)), version.version)
        })
        .collect();
    let store = wreq::tls::trust::CertStore::builder()
        .add_der_cert(&certificate)
        .build()
        .unwrap();
    let backend = WreqBackend::new(Profile::Chrome136).tls_cert_store(store);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let mut received = Vec::new();
            for (acceptor, version) in acceptors {
                let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
                let tls = acceptor.accept(socket).await.unwrap();
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                assert_eq!(tls.get_ref().1.protocol_version(), Some(version));
                let mut connection = h2::server::handshake(tls).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.version(), Version::HTTP_2);
                let (parts, mut body) = request.into_parts();
                let mut ping = connection.ping_pong().unwrap();
                let pings = async {
                    loop {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        if ping.ping(h2::Ping::opaque()).await.is_err() { break; }
                    }
                };
                let work = async {
                    let mut data = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        data.extend_from_slice(&chunk);
                    }
                    received.push(Received { headers: parts.headers, body: data });
                    if reply.before_headers { tokio::time::sleep(Duration::from_millis(300)).await; return; }
                    let no_body = parts.method == Method::HEAD || matches!(reply.status.as_u16(), 204 | 304);
                    let mut response = Response::builder().status(reply.status)
                        .header("set-cookie", "a=1").header("set-cookie", "b=2")
                        .header("content-type", "application/octet-stream");
                    if reply.encoded { response = response.header("content-encoding", "gzip"); }
                    if reply.status != StatusCode::NO_CONTENT {
                        response = response.header("content-length", reply.body.len());
                    }
                    let mut stream = respond.send_response(response.body(()).unwrap(), no_body).unwrap();
                    if !no_body {
                        let end = reply.finish == Finish::Complete;
                        stream.send_data(reply.body.into(), end).unwrap();
                        if reply.finish == Finish::Trailers {
                            let mut trailers = HeaderMap::new();
                            trailers.append("x-checksum", "first".parse().unwrap());
                            trailers.append("x-checksum", "second".parse().unwrap());
                            stream.send_trailers(trailers).unwrap();
                        }
                        if reply.finish == Finish::Reset {
                            // Let the partial data reach the client before resetting the stream.
                            tokio::time::sleep(Duration::from_millis(30)).await;
                            stream.send_reset(h2::Reason::CANCEL);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                };
                tokio::pin!(work);
                tokio::select! {
                    () = &mut work => {},
                    () = pings => {},
                    other = connection.accept() => { assert!(other.is_none_or(|r| r.is_err())); },
                }
            }
            received
        })
    });
    (
        format!("https://localhost:{port}/wp-json?q=1")
            .parse()
            .unwrap(),
        backend,
        server,
    )
}

#[test]
fn captures_negotiated_http2_with_finalized_request_headers_and_trailers() {
    let (target, backend, server) = serve(
        Reply {
            finish: Finish::Trailers,
            ..Reply::default()
        },
        1,
    );
    let mut headers = HeaderMap::new();
    headers.append("x-duplicate", "one".parse().unwrap());
    headers.append("x-duplicate", "two".parse().unwrap());
    headers.insert("connection", "x-hop".parse().unwrap());
    headers.insert("x-hop", "remove-me".parse().unwrap());
    let captured = backend
        .fetch(&Method::POST, &target, &headers, Some(b"request body"))
        .unwrap();
    let received = server.join().unwrap().pop().unwrap();
    assert_eq!(received.body, b"request body");
    let protocols = [Protocol::H2, "tls/1.3".parse().unwrap()];
    assert_eq!(captured.request_protocols, protocols);
    assert_eq!(captured.response_protocols, protocols);
    assert_eq!(captured.truncated, None);
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"hello");
    assert!(
        captured
            .response
            .ends_with(b"0\r\nx-checksum: first\r\nx-checksum: second\r\n\r\n")
    );
    let request = String::from_utf8(captured.request).unwrap();
    assert!(request.starts_with("POST /wp-json?q=1 HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\nrequest body"));
    for (name, value) in &received.headers {
        assert!(
            request.contains(&format!("{}: {}\r\n", name, value.to_str().unwrap())),
            "{name}"
        );
    }
    assert!(!request.contains("x-hop"));
    assert!(!request.contains("connection:"));
    assert!(request.contains("user-agent: Mozilla/5.0"));
}

#[test]
fn head_and_bodyless_statuses_preserve_representation_length() {
    for (method, status) in [
        (Method::HEAD, StatusCode::OK),
        (Method::GET, StatusCode::NO_CONTENT),
        (Method::GET, StatusCode::NOT_MODIFIED),
    ] {
        let (target, backend, server) = serve(
            Reply {
                status,
                ..Reply::default()
            },
            1,
        );
        let captured = backend
            .fetch(&method, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();
        assert!(captured.stored_body().is_empty());
        assert_eq!(captured.truncated, None);
        if status != StatusCode::NO_CONTENT {
            assert!(String::from_utf8_lossy(&captured.response).contains("content-length: 5\r\n"));
        }
    }
}

#[test]
fn caps_count_reconstructed_bytes_and_distinguish_exact_completion() {
    let (target, backend, server) = serve(Reply::default(), 1);
    let complete = backend
        .fetch(&Method::GET, &target, &HeaderMap::new(), None)
        .unwrap();
    server.join().unwrap();
    for (cap, truncated) in [
        (complete.response.len(), None),
        (complete.response.len() - 1, Some(TruncatedType::Length)),
    ] {
        let (target, backend, server) = serve(Reply::default(), 1);
        let captured = backend
            .max_response_length(Some(cap as u64))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();
        assert_eq!(captured.response.len(), cap);
        assert_eq!(captured.truncated, truncated);
    }
}

#[test]
fn stalled_and_reset_streams_retain_truncated_payloads() {
    for reset in [false, true] {
        let (target, backend, server) = serve(
            Reply {
                finish: if reset { Finish::Reset } else { Finish::Stall },
                ..Reply::default()
            },
            1,
        );
        let captured = backend
            .io_timeout(Some(Duration::from_millis(100)))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            captured.truncated,
            Some(if reset {
                TruncatedType::Disconnect
            } else {
                TruncatedType::Time
            })
        );
        assert_eq!(captured.stored_body(), b"5\r\nhello\r\n");
    }
}

#[test]
fn timeout_before_headers_fails() {
    let (target, backend, server) = serve(
        Reply {
            before_headers: true,
            ..Reply::default()
        },
        1,
    );
    assert!(
        backend
            .io_timeout(Some(Duration::from_millis(100)))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .is_err()
    );
    server.join().unwrap();
}

#[test]
fn archive_and_revisit_records_keep_original_protocols() {
    let (target, backend, server) = serve_with_versions(
        Reply::default(),
        &[&rustls::version::TLS12, &rustls::version::TLS13],
    );
    let archiver = Archiver::with_backend(
        Config {
            min_revisit_payload_length: 0,
            ..Config::default()
        },
        Arc::new(backend),
    )
    .unwrap();
    let mut output = Vec::new();
    let summary = archiver
        .archive([target.to_string(), target.to_string()], &mut output)
        .unwrap();
    assert!(summary.is_complete(), "{summary:?}");
    server.join().unwrap();
    let records = WarcReader::new(output.as_slice())
        .iter_records::<NoExtension>()
        .records()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let captures: Vec<_> = records
        .iter()
        .filter(|record| matches!(record.type_name(), "request" | "response" | "revisit"))
        .collect();
    assert_eq!(captures.len(), 4);
    assert!(
        captures
            .iter()
            .any(|record| record.type_name() == "revisit")
    );
    let requests: Vec<_> = captures
        .iter()
        .filter(|record| record.type_name() == "request")
        .collect();
    assert_eq!(requests.len(), 2);
    for (request, version) in requests.iter().zip(["tls/1.2", "tls/1.3"]) {
        assert_eq!(
            request.protocols(),
            [Protocol::H2, version.parse().unwrap()]
        );
    }
    let response = captures
        .iter()
        .find(|record| record.type_name() == "response")
        .unwrap();
    let revisit = captures
        .iter()
        .find(|record| record.type_name() == "revisit")
        .unwrap();
    assert_eq!(
        response.protocols(),
        [Protocol::H2, "tls/1.2".parse().unwrap()]
    );
    assert_eq!(
        revisit.protocols(),
        [Protocol::H2, "tls/1.3".parse().unwrap()]
    );
}

#[test]
fn content_coding_is_preserved_without_decompression() {
    const GZIP: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00";
    let (target, backend, server) = serve(
        Reply {
            body: GZIP,
            encoded: true,
            ..Reply::default()
        },
        1,
    );
    let captured = backend
        .fetch(&Method::GET, &target, &HeaderMap::new(), None)
        .unwrap();
    server.join().unwrap();
    assert_eq!(captured.entity_body().unwrap().as_ref(), GZIP);
    assert!(String::from_utf8_lossy(&captured.response).contains("content-encoding: gzip\r\n"));
}

#[test]
fn response_head_must_fit_the_capture_limit() {
    let (target, backend, server) = serve(Reply::default(), 1);
    assert!(
        backend
            .max_response_length(Some(1))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .is_err()
    );
    server.join().unwrap();
}

#[test]
fn absolute_deadline_truncates_an_http2_response() {
    let (target, backend, server) = serve(
        Reply {
            finish: Finish::Stall,
            ..Reply::default()
        },
        1,
    );
    let captured = backend
        .io_timeout(None)
        .fetch_by(
            &Method::GET,
            &target,
            &HeaderMap::new(),
            None,
            std::time::Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
    server.join().unwrap();
    assert_eq!(captured.truncated, Some(TruncatedType::Time));
    assert_eq!(captured.stored_body(), b"5\r\nhello\r\n");
}
