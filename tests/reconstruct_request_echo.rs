//! Fidelity check for `record::http::reconstruct_request` against a real HTTP client.
//!
//! A loopback listener captures the bytes sent by a real client. Reconstructing the parsed request
//! must reproduce them, so client serialization changes fail this test.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use archivindex_warc::record::http::reconstruct_request;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Uri, Version};

/// Echo one captured HTTP/1.1 request as the response body.
fn echo_server() -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("one connection");
        let mut captured = Vec::new();
        let mut buffer = [0u8; 1024];

        while message_length(&captured).is_none_or(|length| captured.len() < length) {
            let read = stream.read(&mut buffer).expect("readable request");
            assert_ne!(read, 0, "the client hung up mid-request");
            captured.extend_from_slice(&buffer[..read]);
        }

        let response = [
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                captured.len()
            )
            .into_bytes(),
            captured.clone(),
        ]
        .concat();
        stream.write_all(&response).expect("writable response");

        captured
    });

    (port, handle)
}

/// Return the complete request length once its header section has arrived.
fn message_length(buffered: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(buffered);
    let headers_end = text.find("\r\n\r\n")? + 4;
    let body_length = text[..headers_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("a numeric length"))
        })
        .unwrap_or(0);

    Some(headers_end + body_length)
}

/// Parse a captured HTTP/1.1 request into the parts a caller assembles.
fn parse_request(captured: &[u8]) -> (Method, Uri, Version, HeaderMap, Vec<u8>) {
    let headers_end = captured
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete header section")
        + 4;
    let head = std::str::from_utf8(&captured[..headers_end]).expect("readable headers");
    let mut lines = head.trim_end().lines();

    let request_line = lines.next().expect("a request line");
    let mut parts = request_line.split(' ');
    let method: Method = parts.next().expect("a method").parse().expect("a method");
    let target: Uri = parts.next().expect("a target").parse().expect("a target");
    assert_eq!(parts.next(), Some("HTTP/1.1"), "{request_line}");

    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(": ").expect("a header line");
            (
                name.parse::<HeaderName>().expect("a header name"),
                HeaderValue::from_str(value).expect("a header value"),
            )
        })
        .collect();

    (
        method,
        target,
        Version::HTTP_11,
        headers,
        captured[headers_end..].to_vec(),
    )
}

/// Build an HTTP/1.1-only loopback client.
fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("a client")
}

/// Parsed `GET` parts reproduce the bytes sent by the client.
#[test]
fn reconstructs_the_bytes_a_get_request_put_on_the_wire() {
    let (port, capture) = echo_server();

    let echoed = client()
        .get(format!("http://127.0.0.1:{port}/echo/path?q=1"))
        .header("accept", "*/*")
        .header("user-agent", "archivindex-warc-test/0.0")
        .send()
        .expect("a response")
        .bytes()
        .expect("an echoed body");
    let captured = capture.join().expect("a captured request");
    assert_eq!(echoed.as_ref(), captured, "the echo returns the request");

    let (method, target, version, headers, body) = parse_request(&captured);
    assert!(body.is_empty(), "a GET request carries no body");

    let reconstructed = reconstruct_request(&method, &target, version, &headers, None);
    assert_eq!(
        String::from_utf8_lossy(&reconstructed),
        String::from_utf8_lossy(&captured)
    );
}

/// Parsed `POST` parts reproduce the sent body and its framing.
#[test]
fn reconstructs_the_bytes_a_post_request_put_on_the_wire() {
    let (port, capture) = echo_server();

    client()
        .post(format!("http://127.0.0.1:{port}/submit"))
        .header("content-type", "text/plain")
        .body("the request body")
        .send()
        .expect("a response");
    let captured = capture.join().expect("a captured request");

    let (method, target, version, headers, body) = parse_request(&captured);
    assert_eq!(body, b"the request body");

    let reconstructed = reconstruct_request(&method, &target, version, &headers, Some(&body));
    assert_eq!(
        String::from_utf8_lossy(&reconstructed),
        String::from_utf8_lossy(&captured)
    );
}
