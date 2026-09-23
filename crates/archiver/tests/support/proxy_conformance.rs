// Included by both backends' loopback suites, which supply backend(), trusted_backend(), and
// read_request(). The proxy serves the destination itself so reserved hostnames need no DNS.
mod proxy_tests {
    use std::net::{IpAddr, TcpStream};

    use super::*;

    const HOST: &str = "origin.invalid";
    const RESPONSE: &[u8] =
        b"HTTP/1.1 200 Captured\r\nX-MiXeD: kept\r\nContent-Length: 2\r\n\r\nok";

    fn accept(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Accepted sockets can inherit nonblocking mode on macOS.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    return stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "proxy connection timed out");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("proxy accept failed: {error}"),
            }
        }
    }

    fn byte(stream: &mut TcpStream) -> u8 {
        let mut value = [0];
        stream.read_exact(&mut value).unwrap();
        value[0]
    }

    fn field(stream: &mut TcpStream) -> Vec<u8> {
        let mut value = vec![0; usize::from(byte(stream))];
        stream.read_exact(&mut value).unwrap();
        value
    }

    fn negotiate(stream: &mut TcpStream, remote_dns: bool, port: u16, auth: bool) {
        assert_eq!(byte(stream), 5);
        let methods = field(stream);
        let method = if auth { 2 } else { 0 };
        assert!(methods.contains(&method));
        stream.write_all(&[5, method]).unwrap();
        if auth {
            assert_eq!(byte(stream), 1);
            assert_eq!(field(stream), b"user@name");
            assert_eq!(field(stream), b"pass:word");
            stream.write_all(&[1, 0]).unwrap();
        }
        let mut header = [0; 3];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header, [5, 1, 0]);
        match byte(stream) {
            3 => {
                let host = field(stream);
                if remote_dns {
                    assert_eq!(host, HOST.as_bytes());
                } else {
                    // wreq also sends IP literals in domain form with socks5h.
                    assert!(
                        std::str::from_utf8(&host)
                            .unwrap()
                            .parse::<IpAddr>()
                            .unwrap()
                            .is_loopback()
                    );
                }
            }
            kind @ (1 | 4) => {
                assert!(!remote_dns);
                let ip = if kind == 1 {
                    let mut octets = [0; 4];
                    stream.read_exact(&mut octets).unwrap();
                    IpAddr::from(octets)
                } else {
                    let mut octets = [0; 16];
                    stream.read_exact(&mut octets).unwrap();
                    IpAddr::from(octets)
                };
                assert!(ip.is_loopback());
            }
            kind => panic!("unexpected address kind {kind}"),
        }
        let mut requested_port = [0; 2];
        stream.read_exact(&mut requested_port).unwrap();
        assert_eq!(u16::from_be_bytes(requested_port), port);
        stream.write_all(&[5, 0, 0, 1, 192, 0, 2, 1, 0, 0]).unwrap();
    }

    fn serve_proxy(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!("socks5h://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let mut stream = accept(&listener);
                    negotiate(&mut stream, true, 80, false);
                    let request = read_request(&mut stream);
                    stream.write_all(&response).unwrap();
                    request
                })
                .collect()
        });
        (uri, server)
    }

    #[test]
    fn remote_dns_records_only_the_http_exchange_and_omits_the_proxy_ip() {
        let (proxy, server) = serve_proxy(vec![RESPONSE.to_vec()]);
        let captured = backend()
            .proxy(Some(&proxy))
            .unwrap()
            .fetch(
                &Method::GET,
                &format!("http://{HOST}/path").parse().unwrap(),
                &HeaderMap::new(),
                None,
            )
            .unwrap();
        assert_eq!(captured.request, server.join().unwrap()[0]);
        assert_eq!(captured.response, RESPONSE);
        assert_eq!(captured.ip_address, None);
        let records = captured
            .capture_event()
            .exchange(captured.request, captured.response)
            .unwrap();
        assert_eq!(records.response.ip_address(), None);
        assert_eq!(records.request.ip_address(), None);
    }

    #[test]
    fn local_dns_resolves_hostnames_and_ip_literals_remain_usable() {
        for (scheme, host) in [
            ("socks5", "localhost"),
            ("socks5h", "127.0.0.1"),
            ("socks5h", "[::1]"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let proxy = format!("{scheme}://{}", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                let mut stream = accept(&listener);
                negotiate(&mut stream, false, 8080, false);
                let request = read_request(&mut stream);
                stream.write_all(RESPONSE).unwrap();
                request
            });
            let target = format!("http://{host}:8080/local").parse().unwrap();
            let captured = backend()
                .proxy(Some(&proxy))
                .unwrap()
                .fetch(&Method::GET, &target, &HeaderMap::new(), None)
                .unwrap();
            assert_eq!(captured.request, server.join().unwrap());
        }
    }

    #[test]
    fn authenticated_https_uses_origin_tls_and_captures_plaintext() {
        let generated = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!(
            "socks5h://user%40name:pass%3Aword@{}",
            listener.local_addr().unwrap()
        );
        let server = thread::spawn(move || {
            let mut stream = accept(&listener);
            negotiate(&mut stream, true, 443, true);
            let connection = rustls::ServerConnection::new(Arc::new(tls)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let request = read_request(&mut stream);
            stream.write_all(RESPONSE).unwrap();
            stream.flush().unwrap();
            request
        });
        let target = format!("https://{HOST}/secure").parse().unwrap();
        let captured = trusted_backend(&certificate)
            .proxy(Some(&proxy))
            .unwrap()
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(captured.request, server.join().unwrap());
        assert_eq!(captured.response, RESPONSE);
    }

    #[test]
    fn rejected_proxy_never_falls_back_to_a_direct_connection() {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("socks5h://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut stream = accept(&listener);
            assert_eq!(byte(&mut stream), 5);
            field(&mut stream);
            stream.write_all(&[5, 255]).unwrap();
        });
        let target = format!("http://{}/", origin.local_addr().unwrap())
            .parse()
            .unwrap();
        assert!(
            backend()
                .proxy(Some(&proxy))
                .unwrap()
                .fetch(&Method::GET, &target, &HeaderMap::new(), None)
                .is_err()
        );
        server.join().unwrap();
        origin.set_nonblocking(true).unwrap();
        assert_eq!(
            origin.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn stalled_proxy_handshakes_obey_connect_timeouts_and_capture_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("socks5h://{}", listener.local_addr().unwrap());
        let target = format!("http://{HOST}/").parse().unwrap();
        let backend = backend()
            .proxy(Some(&proxy))
            .unwrap()
            .connect_timeout(Some(Duration::from_millis(100)))
            .io_timeout(Some(Duration::from_millis(100)));
        let start = Instant::now();
        assert!(
            backend
                .fetch(&Method::GET, &target, &HeaderMap::new(), None)
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        let start = Instant::now();
        assert!(
            backend
                .connect_timeout(None)
                .io_timeout(None)
                .fetch_by(
                    &Method::GET,
                    &target,
                    &HeaderMap::new(),
                    None,
                    start + Duration::from_millis(100)
                )
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn invalid_proxy_uri_fails_before_fetching() {
        for proxy in [
            "socks5h://127.0.0.1:invalid",
            "http://localhost:1080",
            "socks4://localhost:1080",
        ] {
            assert!(backend().proxy(Some(proxy)).is_err());
        }
    }

    #[test]
    fn retries_redirects_and_challenges_stay_on_the_proxy_and_warc_omits_its_ip() {
        use archivindex_archiver::session::{Crawl, RetryConfig, Session};
        use archivindex_warc::io::read::WarcReader;
        use archivindex_warc::record::FieldsBlock;
        use archivindex_warc::record::extension::NoExtension;
        use archivindex_warc::record::fields::warcinfo::WarcinfoField;

        let script = "v='clearance';document.cookie='sucuri_cloudproxy_uuid_test=' + v + ';path=/;max-age=86400;SameSite=Lax'; location.reload();";
        let encoded = data_encoding::BASE64.encode(script.as_bytes());
        let challenge =
            format!("<html><script>var sucuri_cloudproxy_js='',S='{encoded}';</script></html>");
        let challenge_response = format!(
            "HTTP/1.1 307 Challenge\r\nContent-Type: text/html\r\nX-Sucuri-Id: 12005\r\nContent-Length: {}\r\n\r\n{challenge}",
            challenge.len()
        );
        let (proxy, server) = serve_proxy(vec![
            b"HTTP/1.1 503 Retry\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 302 Follow\r\nLocation: http://origin.invalid/next\r\nContent-Length: 0\r\n\r\n".to_vec(),
            challenge_response.into_bytes(),
            RESPONSE.to_vec(),
        ]);
        let archiver = proxied_archiver(&proxy);
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("proxy.warc");
        let summary = Session::new(
            archiver,
            "proxy",
            Crawl::seeds([format!("http://{HOST}/first")]),
            &output,
        )
        .unwrap()
        .retry(RetryConfig {
            attempts: 2,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        })
        .run()
        .unwrap();
        assert!(summary.is_complete(), "{summary:?}");
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(b"GET /first HTTP/1.1\r\n"));
        assert_eq!(requests[0], requests[1]);
        assert!(requests[2].starts_with(b"GET /next HTTP/1.1\r\n"));
        assert!(requests[3].starts_with(b"GET /next HTTP/1.1\r\n"));
        assert!(
            String::from_utf8_lossy(&requests[3]).contains("sucuri_cloudproxy_uuid_test=clearance")
        );
        let file = std::fs::File::open(output).unwrap();
        let records = WarcReader::new(std::io::BufReader::new(file))
            .iter_records::<NoExtension>()
            .records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|record| record.type_name() == "response")
                .count(),
            4
        );
        assert!(records.iter().all(|record| record.ip_address().is_none()));
        let Record::Warcinfo {
            body: FieldsBlock::Fields(fields),
            ..
        } = &records[0]
        else {
            panic!("warcinfo with fields")
        };
        assert_eq!(
            fields.get(&WarcinfoField::from("archivindex-proxy")),
            Some(proxy.as_str())
        );
    }
}
