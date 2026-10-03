//! WARC capture through a SOCKS proxy.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use archivindex_warc::record::Record;

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

fn proxied_archiver(proxy: &str) -> archivindex_archiver::Archiver {
    archivindex_archiver::Archiver::new(archivindex_archiver::Config {
        proxy: Some(proxy.to_owned()),
        ..archivindex_archiver::Config::default()
    })
    .unwrap()
}

const HOST: &str = "origin.invalid";
const RESPONSE: &[u8] = b"HTTP/1.1 200 Captured\r\nX-MiXeD: kept\r\nContent-Length: 2\r\n\r\nok";

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

fn negotiate(stream: &mut TcpStream) {
    assert_eq!(byte(stream), 5);
    assert!(field(stream).contains(&0));
    stream.write_all(&[5, 0]).unwrap();
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header, [5, 1, 0, 3]);
    assert_eq!(field(stream), HOST.as_bytes());
    let mut port = [0; 2];
    stream.read_exact(&mut port).unwrap();
    assert_eq!(u16::from_be_bytes(port), 80);
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
                negotiate(&mut stream);
                let request = read_request(&mut stream);
                stream.write_all(&response).unwrap();
                request
            })
            .collect()
    });
    (uri, server)
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
        b"HTTP/1.1 302 Follow\r\nLocation: http://origin.invalid/next\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
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
