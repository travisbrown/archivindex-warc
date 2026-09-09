//! Exactness checks for the default recorder against scripted loopback servers.
use archivindex_archiver::recorder::Recorder;

fn recorder() -> Recorder {
    Recorder::new()
}
fn trusted_recorder(certificate: &rustls::pki_types::CertificateDer<'static>) -> Recorder {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).expect("a root");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    recorder().tls_config(std::sync::Arc::new(config))
}
include!("support/recorder_conformance.rs");
