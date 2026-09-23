//! Run the shared exactness contract against the optional wreq backend.
use archivindex_archiver_backend_wreq::{Profile, WreqBackend as Backend};

const fn backend() -> Backend {
    Backend::new(Profile::Chrome136)
}
fn trusted_backend(certificate: &rustls::pki_types::CertificateDer<'static>) -> Backend {
    let store = wreq::tls::trust::CertStore::builder()
        .add_der_cert(certificate)
        .build()
        .expect("a root");
    backend().tls_cert_store(store)
}
// The exactness contract every backend must satisfy, shared with the built-in recorder.
include!("../../../crates/archiver/tests/support/backend_conformance.rs");

#[test]
fn no_hidden_redirects_or_retries() {
    for status in ["302 Follow", "503 Unavailable", "disconnect"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let serving = listener.try_clone().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = serving.accept().unwrap();
            let request = read_request(&mut stream);
            if status != "disconnect" {
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
            }
            request
        });
        let target = format!("http://127.0.0.1:{port}/first").parse().unwrap();
        let result = backend()
            .io_timeout(Some(Duration::from_millis(200)))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None);
        let request = server.join().unwrap();
        if status == "disconnect" {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().request, request);
        }
        listener.set_nonblocking(true).unwrap();
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[tokio::test]
async fn synchronous_capture_works_inside_a_tokio_runtime() {
    let (port, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let captured = fetch(&backend(), port, "/nested");
    assert_eq!(captured.request, server.join().unwrap());
}
fn proxied_archiver(proxy: &str) -> archivindex_archiver::Archiver {
    archivindex_archiver::Archiver::with_backend(
        archivindex_archiver::Config::default(),
        Arc::new(backend().proxy(Some(proxy)).unwrap()),
    )
    .unwrap()
}
include!("../../../crates/archiver/tests/support/proxy_conformance.rs");
