//! Negotiated HTTP/2 capture against a local TLS server, independent of external sites.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use archivindex_archiver::{Archiver, Config};
use archivindex_http_client::wreq::WreqClient;
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::header::protocol::Protocol;
use http::{Response, Uri, Version};
use tokio_rustls::TlsAcceptor;
use wreq_util::Profile;

fn serve_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> (Uri, WreqClient, thread::JoinHandle<()>) {
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
    let backend = WreqClient::new(Profile::Chrome136)
        .http2(true)
        .tls_cert_store(store);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            for (acceptor, version) in acceptors {
                let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
                let tls = acceptor.accept(socket).await.unwrap();
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                assert_eq!(tls.get_ref().1.protocol_version(), Some(version));
                let mut connection = h2::server::handshake(tls).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.version(), Version::HTTP_2);
                let work = async {
                    let response = Response::builder().status(200)
                        .header("content-length", 5)
                        .body(()).unwrap();
                    let mut stream = respond.send_response(response, false).unwrap();
                    stream.send_data(b"hello".as_slice().into(), true).unwrap();
                    tokio::time::sleep(Duration::from_millis(300)).await;
                };
                tokio::pin!(work);
                tokio::select! {
                    () = &mut work => {},
                    other = connection.accept() => { assert!(other.is_none_or(|r| r.is_err())); },
                }
            }
        });
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
fn archive_and_revisit_records_keep_original_protocols() {
    let (target, backend, server) =
        serve_with_versions(&[&rustls::version::TLS12, &rustls::version::TLS13]);
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
