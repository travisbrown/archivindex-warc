//! Exactness checks for the built-in recorder backend against scripted loopback servers.
use archivindex_archiver::recorder::Recorder as Backend;

fn backend() -> Backend {
    Backend::new()
}
fn trusted_backend(certificate: &rustls::pki_types::CertificateDer<'static>) -> Backend {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).expect("a root");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    backend().tls_config(std::sync::Arc::new(config))
}
include!("support/backend_conformance.rs");
fn proxied_archiver(proxy: &str) -> archivindex_archiver::Archiver {
    archivindex_archiver::Archiver::new(archivindex_archiver::Config {
        proxy: Some(proxy.to_owned()),
        ..archivindex_archiver::Config::default()
    })
    .unwrap()
}
include!("support/proxy_conformance.rs");
