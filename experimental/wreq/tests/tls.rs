//! Negotiated TLS metadata for exact HTTP/1 capture, including SOCKS tunnels.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use archivindex_archiver::{Archiver, Config};
use archivindex_archiver_backend_wreq::{Profile, WreqBackend};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::header::protocol::Protocol;

const RESPONSE: &[u8] = b"HTTP/1.1 200 Captured\r\nX-MiXeD: Kept\r\nContent-Length: 5\r\n\r\nhello";

fn negotiate_socks(stream: &mut std::net::TcpStream) {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).unwrap();
    let mut request = [0; 5];
    stream.read_exact(&mut request).unwrap();
    assert_eq!(request, [5, 1, 0, 3, 9]);
    let mut target = [0; 11];
    stream.read_exact(&mut target).unwrap();
    assert_eq!(&target[..9], b"localhost");
    assert_eq!(&target[9..], &443u16.to_be_bytes());
    stream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 1, 187])
        .unwrap();
}

fn serve(
    version: &'static rustls::SupportedProtocolVersion,
    proxy: bool,
) -> (String, WreqBackend, thread::JoinHandle<Vec<u8>>) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = generated.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .unwrap();
    let store = wreq::tls::trust::CertStore::builder()
        .add_der_cert(&certificate)
        .build()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = WreqBackend::new(Profile::Chrome136).tls_cert_store(store);
    let (target, backend) = if proxy {
        (
            "https://localhost/secure".to_owned(),
            backend.proxy(Some(&format!("socks5h://{addr}"))).unwrap(),
        )
    } else {
        (format!("https://localhost:{}/secure", addr.port()), backend)
    };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if proxy {
            negotiate_socks(&mut stream);
        }
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, stream);
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192, "oversized request headers");
            let mut byte = [0];
            tls.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert_eq!(tls.conn.protocol_version(), Some(version.version));
        assert!(tls.conn.alpn_protocol().is_none());
        tls.write_all(RESPONSE).unwrap();
        tls.conn.send_close_notify();
        tls.flush().unwrap();
        request
    });
    (target, backend, server)
}

#[test]
fn http1_records_negotiated_tls_directly_and_through_socks() {
    for (version, protocol) in [
        (&rustls::version::TLS12, "tls/1.2"),
        (&rustls::version::TLS13, "tls/1.3"),
    ] {
        for proxy in [false, true] {
            let (target, backend, server) = serve(version, proxy);
            let archiver = Archiver::with_backend(Config::default(), Arc::new(backend)).unwrap();
            let mut output = Vec::new();
            let summary = archiver.archive([target], &mut output).unwrap();
            assert!(summary.is_complete(), "{summary:?}");
            let received = server.join().unwrap();
            let records = WarcReader::new(output.as_slice())
                .iter_records::<NoExtension>()
                .records()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let captures: Vec<_> = records
                .iter()
                .filter(|record| matches!(record.type_name(), "request" | "response"))
                .collect();
            assert_eq!(captures.len(), 2);
            for record in captures {
                assert_eq!(record.protocols(), [protocol.parse::<Protocol>().unwrap()]);
                let expected = if record.type_name() == "request" {
                    received.as_slice()
                } else {
                    RESPONSE
                };
                assert_eq!(record.body_bytes().as_ref(), expected);
                if proxy {
                    assert!(record.ip_address().is_none());
                }
            }
        }
    }
}
