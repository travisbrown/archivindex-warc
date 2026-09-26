//! HTTP/1 wire capture and reconstructed HTTP/2 capture with browser TLS emulation.
//!
//! Each fetch owns an isolated client and runtime. Redirects, retries, cookies, automatic proxies,
//! decompression, and pooling are disabled. The selected profile supplies TLS and HTTP/2 settings;
//! configured request headers override profile headers.
//!
//! HTTP/1 messages are captured exactly. HTTP/2 exchanges are reconstructed as HTTP/1.1 messages,
//! with `WARC-Protocol: h2` identifying their original protocol. Content coding is preserved and
//! chunked framing retains response trailers. Both HTTP versions also record the negotiated TLS
//! version when available. Block digests cover the stored representation.
//!
//! Calls are synchronous and can run inside an existing Tokio runtime. See the crate README for
//! capture limits, reconstruction, and timeout semantics.

mod capture;

use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

use archivindex_archiver::backend::{
    Backend, CapturedExchange, DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT, Error,
};
use http::{HeaderMap, Method, Uri};
/// A versioned browser/client profile supplied by wreq-util.
pub use wreq_util::Profile;

/// An isolated HTTP/1 and HTTP/2 backend using `BoringSSL` and browser emulation.
#[derive(Clone)]
pub struct WreqBackend {
    profile: Profile,
    proxy: Option<wreq::Proxy>,
    connect_timeout: Option<Duration>,
    io_timeout: Option<Duration>,
    max_response_length: Option<u64>,
    cert_store: Option<wreq::tls::trust::CertStore>,
}

impl std::fmt::Debug for WreqBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WreqBackend")
            .field("profile", &self.profile)
            .field("proxied", &self.proxy.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_response_length", &self.max_response_length)
            .field("custom_cert_store", &self.cert_store.is_some())
            .finish()
    }
}

impl WreqBackend {
    /// Select a profile, including its TLS and HTTP/2 settings.
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self {
            profile,
            proxy: None,
            connect_timeout: Some(DEFAULT_TIMEOUT),
            io_timeout: Some(DEFAULT_TIMEOUT),
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
            cert_store: None,
        }
    }

    /// Set an explicit proxy for every request, or use direct connections with `None`.
    ///
    /// Supports `socks5://` for local DNS and `socks5h://` for proxy DNS, with optional username
    /// and password credentials. Environment proxy settings remain disabled. Invalid or unsupported
    /// URIs return an error before any request is sent.
    pub fn proxy(mut self, proxy: Option<&str>) -> Result<Self, Error> {
        self.proxy = proxy
            .map(|proxy| {
                // wreq accepts nonnumeric ports and defers failure until connecting.
                let invalid = || io::Error::new(ErrorKind::InvalidInput, "invalid proxy URI");
                let uri = fluent_uri::Uri::parse(proxy).map_err(|_| invalid())?;
                if !matches!(uri.scheme().as_str(), "socks5" | "socks5h") {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "expected socks5:// or socks5h://",
                    )
                    .into());
                }
                let authority = uri
                    .authority()
                    .filter(|authority| !authority.host().is_empty())
                    .ok_or_else(invalid)?;
                if authority.port_to_u16().map_err(|_| invalid())? == Some(0) {
                    return Err(invalid().into());
                }
                wreq::Proxy::all(proxy).map_err(backend_error)
            })
            .transpose()?;
        Ok(self)
    }

    /// Bound connecting, including DNS and TLS, or remove the bound with `None`.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Bound idle exchange progress after connecting, or remove the bound with `None`.
    ///
    /// HTTP/2 connection control traffic does not count as response progress.
    #[must_use]
    pub const fn io_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Bound stored response bytes, including the final head and transfer framing.
    ///
    /// HTTP/2 counts the reconstructed message, not binary connection traffic.
    #[must_use]
    pub const fn max_response_length(mut self, limit: Option<u64>) -> Self {
        self.max_response_length = limit;
        self
    }

    /// Replace the default Mozilla root certificate store.
    #[must_use]
    pub fn tls_cert_store(mut self, store: wreq::tls::trust::CertStore) -> Self {
        self.cert_store = Some(store);
        self
    }

    /// Perform and retain exactly one application exchange.
    pub fn fetch(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<CapturedExchange, Error> {
        self.fetch_within(method, target, headers, body, None)
    }

    /// Perform one exchange with a deadline covering DNS, connecting, and response capture.
    pub fn fetch_by(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<CapturedExchange, Error> {
        self.fetch_within(method, target, headers, body, Some(deadline))
    }

    fn fetch_within(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        if !matches!(target.scheme_str(), Some("http" | "https")) {
            return Err(Error::UnsupportedScheme);
        }
        if target.host().is_none_or(str::is_empty) {
            return Err(Error::MissingHost);
        }
        if deadline.is_some_and(|end| end <= Instant::now()) {
            return Err(
                io::Error::new(ErrorKind::TimedOut, "the fetch deadline has passed").into(),
            );
        }
        // Avoid nesting block_on inside a caller's async runtime. Dispose all HTTP tasks
        // even when the parser finishes before wreq's codec.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let captured =
                        runtime.block_on(self.capture(method, target, headers, body, deadline));
                    // System DNS uses spawn_blocking. Waiting for it during runtime Drop would
                    // undo a connect/capture timeout; it may finish after the caller returns.
                    runtime.shutdown_background();
                    captured
                })
                .join()
                .map_err(|_| io::Error::other("the wreq capture worker panicked"))?
        })
    }
}

/// A profile name that no known browser/client profile matches.
#[derive(Clone, Debug, thiserror::Error)]
#[error("unknown profile `{0}`")]
pub struct UnknownProfile(pub String);

/// Look up a profile by the name used in configuration, such as `chrome_136`.
///
/// # Errors
///
/// Fails when no profile has that name.
pub fn parse_profile(name: &str) -> Result<Profile, UnknownProfile> {
    use serde::de::IntoDeserializer;
    let deserializer: serde::de::value::StrDeserializer<'_, serde::de::value::Error> =
        name.into_deserializer();
    serde::Deserialize::deserialize(deserializer).map_err(|_| UnknownProfile(name.to_owned()))
}

/// Report a wreq failure through the archiver's catch-all backend error variant.
fn backend_error(error: wreq::Error) -> Error {
    Error::Other(Box::new(error))
}

impl Backend for WreqBackend {
    fn fetch_within(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        Self::fetch_within(self, method, target, headers, body, deadline)
    }
}
