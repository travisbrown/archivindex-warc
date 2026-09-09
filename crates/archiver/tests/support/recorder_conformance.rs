use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use archivindex_archiver::recorder::{CapturedExchange, Error};
use archivindex_warc::record::Record;
use archivindex_warc::record::capture::CaptureRecords;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use http::{HeaderMap, HeaderValue, Method, Uri};

/// Read one complete HTTP/1.1 request.
fn read_request(stream: &mut impl Read) -> Vec<u8> {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 1024];

    while message_length(&captured).is_none_or(|length| captured.len() < length) {
        let read = stream.read(&mut buffer).expect("readable request");
        assert_ne!(read, 0, "the client hung up mid-request");
        captured.extend_from_slice(&buffer[..read]);
    }

    captured
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

/// Serve one scripted response and return the received request from the thread.
fn serve(response: &'static [u8]) -> (u16, thread::JoinHandle<Vec<u8>>) {
    serve_then(response, Duration::ZERO)
}

/// Serve one response, then wait before closing the connection.
fn serve_then(response: &'static [u8], linger: Duration) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("one connection");
        let captured = read_request(&mut stream);
        stream.write_all(response).expect("writable response");
        thread::sleep(linger);

        captured
    });

    (port, handle)
}

/// Fetch from a loopback server without optional headers or a body.
fn fetch(recorder: &Recorder, port: u16, path: &str) -> CapturedExchange {
    let target: Uri = format!("http://127.0.0.1:{port}{path}")
        .parse()
        .expect("a target");

    recorder
        .fetch(&Method::GET, &target, &HeaderMap::new(), None)
        .expect("a recorded exchange")
}

#[test]
fn records_the_request_and_response_bytes_exactly() {
    let response: &[u8] =
        b"HTTP/1.1 200 Okey-Dokey\r\nContent-Length: 5\r\nX-MiXeD-CaSe: Kept\r\n\r\nhello";
    let (port, capture) = serve(response);

    let target: Uri = format!("http://127.0.0.1:{port}/path?q=1")
        .parse()
        .expect("a target");
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("recorder-test/0.0"));

    let captured = recorder()
        .fetch(&Method::GET, &target, &headers, None)
        .expect("a recorded exchange");
    let received = capture.join().expect("a served request");

    assert_eq!(captured.request, received);
    let request = String::from_utf8_lossy(&captured.request);
    let request = request.to_ascii_lowercase();
    assert!(
        request.starts_with("get /path?q=1 http/1.1\r\n"),
        "{request}"
    );
    assert!(
        request.contains(&format!("host: 127.0.0.1:{port}\r\n")),
        "{request}"
    );
    assert!(
        request.contains("user-agent: recorder-test/0.0\r\n"),
        "{request}"
    );
    assert!(request.contains("connection: close\r\n"), "{request}");

    assert_eq!(captured.response, response);
    assert_eq!(captured.ip_address.to_string(), "127.0.0.1");
    assert_eq!(captured.target_uri.as_str(), target.to_string());
    assert_eq!(captured.truncated, None);
}

#[test]
fn records_a_chunked_response_verbatim_and_renders_its_records() {
    let response: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n\
        4;ext=a\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n";
    let (port, capture) = serve(response);

    let captured = fetch(&recorder(), port, "/chunked");
    capture.join().expect("a served request");

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, None);

    let records: CaptureRecords = captured
        .capture_event()
        .exchange(captured.request.clone(), captured.response)
        .expect("capture records");
    assert!(records.metadata.is_some(), "a fetch time was declared");
    records.request.into_raw().expect("a renderable request");
    let raw = records.response.into_raw().expect("a renderable response");
    assert_eq!(raw.body, response);
}

#[test]
fn records_a_close_delimited_response_to_the_close() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\nX-No-Framing: declared\r\n\r\nthe close ends this";
    let (port, capture) = serve(response);

    let captured = fetch(&recorder(), port, "/unframed");
    capture.join().expect("a served request");

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, None);
}

#[test]
fn records_a_head_response_through_its_header_section() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let (port, capture) = serve(response);

    let target: Uri = format!("http://127.0.0.1:{port}/")
        .parse()
        .expect("a target");
    let captured = recorder()
        .fetch(&Method::HEAD, &target, &HeaderMap::new(), None)
        .expect("a recorded exchange");
    capture.join().expect("a served request");

    assert_eq!(captured.response, response);
    assert!(captured.request.starts_with(b"HEAD / HTTP/1.1\r\n"));
}

#[test]
fn frames_and_records_a_request_body() {
    let response: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    let (port, capture) = serve(response);

    let target: Uri = format!("http://127.0.0.1:{port}/submit")
        .parse()
        .expect("a target");
    let captured = recorder()
        .fetch(
            &Method::POST,
            &target,
            &HeaderMap::new(),
            Some(b"the request body"),
        )
        .expect("a recorded exchange");
    let received = capture.join().expect("a served request");

    assert_eq!(captured.request, received);
    let request = String::from_utf8_lossy(&captured.request);
    let request = request.to_ascii_lowercase();
    assert!(request.contains("content-length: 16\r\n"), "{request}");
    assert!(request.ends_with("\r\n\r\nthe request body"), "{request}");
    assert_eq!(captured.response, response);
}

#[test]
fn the_length_bound_truncates_the_record_and_it_still_renders() {
    let response: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nabcdefghijklmnopqrstuvwxyz";
    let (port, capture) = serve(response);

    let captured = fetch(
        &recorder().max_response_length(Some(45)),
        port,
        "/truncated",
    );
    capture.join().expect("a served request");

    assert_eq!(captured.response, &response[..45]);
    assert_eq!(captured.truncated, Some(TruncatedType::Length));

    let records: CaptureRecords = captured
        .capture_event()
        .exchange(captured.request.clone(), captured.response)
        .expect("capture records");
    let Record::Response { header, .. } = &records.response else {
        panic!("not a response record");
    };
    assert_eq!(header.core.truncated, Some(TruncatedType::Length));
    records
        .response
        .into_raw()
        .expect("a renderable truncated response");
}

#[test]
fn a_read_timeout_inside_the_body_truncates_for_reason_time() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial";
    let (port, capture) = serve_then(response, Duration::from_millis(500));

    let captured = fetch(
        &recorder().io_timeout(Some(Duration::from_millis(100))),
        port,
        "/slow",
    );

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, Some(TruncatedType::Time));
    capture.join().expect("a served request");
}

#[test]
fn a_deadline_inside_the_body_truncates_for_reason_time() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("one connection");
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .expect("writable head");
        // A byte within every read timeout, until the client hangs up.
        while stream.write_all(b"x").is_ok() {
            thread::sleep(Duration::from_millis(20));
        }
    });
    let target: Uri = format!("http://127.0.0.1:{port}/trickle")
        .parse()
        .expect("a target");

    let captured = recorder()
        .io_timeout(Some(Duration::from_secs(5)))
        .fetch_by(
            &Method::GET,
            &target,
            &HeaderMap::new(),
            None,
            Instant::now() + Duration::from_millis(200),
        )
        .expect("a recorded exchange");

    assert_eq!(captured.truncated, Some(TruncatedType::Time));
    assert!(
        captured.fetch_time < Duration::from_secs(5),
        "{:?}",
        captured.fetch_time
    );
    server.join().expect("a served request");
}

#[test]
fn a_passed_deadline_fails_before_connecting() {
    let target: Uri = "http://127.0.0.1:9/".parse().expect("a target");

    let result = recorder().fetch_by(
        &Method::GET,
        &target,
        &HeaderMap::new(),
        None,
        Instant::now(),
    );

    assert!(matches!(
        result,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut
    ));
}

#[test]
fn a_non_http_scheme_is_refused() {
    let target: Uri = "ftp://example.com/".parse().expect("a target");
    let result = recorder().fetch(&Method::GET, &target, &HeaderMap::new(), None);

    assert!(matches!(result, Err(Error::UnsupportedScheme)));
}

#[test]
fn records_the_exact_bytes_over_tls() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nX-Secure: YES\r\n\r\nsecrets";
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("a certificate");
    let certificate = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .expect("a server config");

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();
    let capture = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("one connection");
        let connection =
            rustls::ServerConnection::new(Arc::new(server_config)).expect("a TLS session");
        let mut tls = rustls::StreamOwned::new(connection, stream);
        let captured = read_request(&mut tls);
        tls.write_all(response).expect("writable response");
        tls.conn.send_close_notify();
        tls.flush().expect("a flushed close");

        captured
    });

    let target: Uri = format!("https://localhost:{port}/tls")
        .parse()
        .expect("a target");
    let captured = trusted_recorder(&certificate)
        .fetch(&Method::GET, &target, &HeaderMap::new(), None)
        .expect("a recorded exchange");
    let received = capture.join().expect("a served request");

    assert_eq!(captured.request, received);
    assert_eq!(captured.response, response);
    assert!(
        String::from_utf8_lossy(&captured.request).to_ascii_lowercase().contains(&format!("host: localhost:{port}\r\n"))
    );
}

#[test]
fn preserves_interim_duplicate_headers_whitespace_and_fragmented_chunks() {
    let interim = b"HTTP/1.1 103 Hints\r\nLink: </style>\r\n\r\n";
    let response = b"HTTP/1.1 200 Very Fine\r\nX-MiXeD:\t kept \t\r\nX-MiXeD: second\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n3;foo=bar\r\na\0b\r\n2\r\ncd\r\n0;done=yes\r\nX-End: yes\r\n\r\n";
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        stream.write_all(interim).unwrap();
        for byte in response { stream.write_all(&[*byte]).unwrap(); }
        request
    });
    let captured = fetch(&recorder(), port, "/fragmented");
    assert_eq!(captured.request, server.join().unwrap());
    assert_eq!(captured.response, response);
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"a\0bcd");
    assert_eq!(captured.truncated, None);
}

#[test]
fn retains_a_disconnect_after_the_head() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
    let (port, server) = serve(response);
    let captured = fetch(&recorder(), port, "/disconnect");
    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, Some(TruncatedType::Disconnect));
    server.join().unwrap();
}

#[test]
fn incomplete_and_oversized_heads_fail() {
    for (response, cap) in [
        (b"HTTP/1.1 200 OK\r\nContent-".as_slice(), None),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(), Some(10)),
    ] {
        let (port, server) = serve(response);
        let target = format!("http://127.0.0.1:{port}/").parse().unwrap();
        assert!(recorder().max_response_length(cap).fetch(&Method::GET, &target, &HeaderMap::new(), None).is_err());
        server.join().unwrap();
    }
}

#[test]
fn exact_caps_complete_without_false_truncation() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\n\r\nok".as_slice(),
    ] {
        let (port, server) = serve(response);
        let captured = fetch(&recorder().max_response_length(Some(response.len() as u64)), port, "/cap");
        assert_eq!(captured.response, response);
        assert_eq!(captured.truncated, None);
        server.join().unwrap();
    }
}

#[test]
fn concurrent_captures_keep_their_own_bytes() {
    let workers: Vec<_> = (0..8).map(|index| thread::spawn(move || {
        let (port, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let captured = fetch(&recorder(), port, &format!("/request-{index}"));
        assert_eq!(captured.request, server.join().unwrap());
        assert!(captured.request.starts_with(format!("GET /request-{index} HTTP/1.1\r\n").as_bytes()));
    })).collect();
    for worker in workers { worker.join().unwrap(); }
}

#[test]
fn a_known_length_limit_does_not_wait_for_the_rest_of_the_body() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nprefix";
    let (port, server) = serve_then(response, Duration::from_millis(500));
    let captured = fetch(&recorder().max_response_length(Some(response.len() as u64)), port, "/limit");
    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, Some(TruncatedType::Length));
    assert!(captured.fetch_time < Duration::from_millis(400));
    server.join().unwrap();
}
