//! Exact HTTP/1 capture with browser-derived TLS emulation (feature `wreq`, Rust 1.98+).
//!
//! Each fetch owns a client, runtime, and observer. Redirects, retries, cookies, automatic
//! proxies, decompression, and pooling are disabled. Profiles are applied before forcing HTTP/1;
//! this changes ALPN and therefore does not reproduce a browser's complete fingerprint.
//! The archiver's configured headers take precedence over profile headers.
//!
//! The response block comes exclusively from the plaintext observer, through the archiver's
//! shared framing parser. No parsed wreq response is reconstructed. A completed capture or limit
//! cancels the request and disposes its connection. The HTTP codec may reject some responses the
//! built-in recorder accepts; codec errors are reported when the wire capture is not already
//! complete.
//!
//! Calls are synchronous and run a dedicated thread/runtime, including when called within an
//! existing Tokio runtime. Connect timeouts include DNS and TLS; the capture deadline covers DNS
//! too. After connecting, the idle timeout bounds absence of plaintext read or write progress.

use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use archivindex_archiver::backend::{
    Backend, CapturedExchange, DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT, Error,
    ResponseCapture, ResponseError,
};
use archivindex_warc::record::http::ResponseMetadata;
use chrono::Utc;
use http::{HeaderMap, HeaderValue, Method, Uri, header};
use http_body_util::BodyExt;
use tokio::sync::Notify;
use wreq::connection_observer::{ConnectionEvent, ConnectionObserver};
/// A versioned browser/client profile supplied by wreq-util.
pub use wreq_util::Profile;

/// An isolated, byte-exact HTTP/1 backend using `BoringSSL` and browser emulation.
#[derive(Clone)]
pub struct WreqBackend {
    profile: Profile,
    connect_timeout: Option<Duration>,
    io_timeout: Option<Duration>,
    max_response_length: Option<u64>,
    cert_store: Option<wreq::tls::trust::CertStore>,
}

impl std::fmt::Debug for WreqBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WreqBackend")
            .field("profile", &self.profile)
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_response_length", &self.max_response_length)
            .field("custom_cert_store", &self.cert_store.is_some())
            .finish()
    }
}

impl WreqBackend {
    /// Select a profile. HTTP/1 is forced after applying it.
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self {
            profile,
            connect_timeout: Some(DEFAULT_TIMEOUT),
            io_timeout: Some(DEFAULT_TIMEOUT),
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
            cert_store: None,
        }
    }

    /// Bound connecting, including DNS and TLS, or remove the bound with `None`.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Bound idle plaintext reads and writes after connecting, or remove the bound with `None`.
    #[must_use]
    pub const fn io_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Bound retained wire bytes, including the final response head and chunk framing.
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

    async fn capture(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        let tap = Arc::new(Tap {
            state: Mutex::new(State {
                response: ResponseCapture::new(*method == Method::HEAD, self.max_response_length),
                request: Vec::new(),
                error: None,
                id: None,
                ip_address: None,
                last_activity: None,
            }),
            done: Notify::new(),
            activity: Notify::new(),
        });
        let mut builder = wreq::Client::builder()
            .emulation(self.profile)
            .http1_only()
            .redirect(wreq::redirect::Policy::none())
            .retry(wreq::retry::Policy::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .pool_max_idle_per_host(0)
            .connection_observer(tap.clone());
        if let Some(timeout) = self.connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(store) = &self.cert_store {
            builder = builder.tls_cert_store(store.clone());
        }
        let client = builder.build().map_err(backend_error)?;
        let mut headers = headers.clone();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        // A provided byte body has a known length. Do not let caller framing turn it into
        // a different message or smuggle a subsequent request.
        headers.remove(header::TRANSFER_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
        let mut request = client
            .request(method.clone(), target.to_string())
            .headers(headers);
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        let date = Utc::now();
        let clock = Instant::now();
        let operation = async {
            let mut response = request.send().await?;
            // Drive the codec, discarding its transfer-decoded frames. Only the tap records.
            while let Some(frame) = response.frame().await {
                frame?;
            }
            Ok::<(), wreq::Error>(())
        };
        let expire = async {
            if let Some(deadline) = deadline {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            () = tap.done.notified() => {},
            () = expire => tap.end(true),
            () = tap.idle(self.io_timeout) => tap.end(true),
            result = operation => {
                if let Err(error) = result {
                    if error.is_timeout() { tap.end(true); }
                    else if error.is_connect() { tap.fail(io::Error::other(error).into()); }
                    else { tap.fail(backend_error(error)); }
                } else {
                    // Codec completion is not evidence of transport EOF. Framed responses
                    // must already be complete according to our parser.
                    let mut state = tap.state();
                    if !state.response.is_done() && state.error.is_none() {
                        state.error = Some(io::Error::other("wreq ended before the wire message boundary").into());
                    }
                }
            }
        }
        let fetch_time = clock.elapsed();
        let mut state = tap.state();
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        let response = std::mem::replace(&mut state.response, ResponseCapture::new(false, None));
        let (response, truncated) = response.into_parts();
        let response_metadata =
            ResponseMetadata::parse(&response).ok_or(ResponseError::MalformedStatusLine)?;
        Ok(CapturedExchange {
            request: std::mem::take(&mut state.request),
            response,
            response_metadata,
            target_uri: fluent_uri::Uri::parse(target.to_string().as_str())?.to_owned(),
            ip_address: state
                .ip_address
                .ok_or_else(|| io::Error::other("missing peer address"))?,
            date,
            fetch_time,
            truncated,
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

struct Tap {
    state: Mutex<State>,
    done: Notify,
    activity: Notify,
}
struct State {
    response: ResponseCapture,
    request: Vec<u8>,
    error: Option<Error>,
    id: Option<u64>,
    ip_address: Option<IpAddr>,
    last_activity: Option<Instant>,
}

impl Tap {
    /// Borrow the capture state, tolerating poisoning.
    ///
    /// A panic in one observer callback must not turn every later callback into a second
    /// panic, which during a connection drop would abort the process.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn idle(&self, timeout: Option<Duration>) {
        let Some(timeout) = timeout else {
            return std::future::pending().await;
        };
        loop {
            let last = self.state().last_activity;
            if let Some(last) = last {
                tokio::select! {
                    biased;
                    () = self.activity.notified() => {},
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(last + timeout)) => return,
                }
            } else {
                self.activity.notified().await;
            }
        }
    }

    fn end(&self, timed_out: bool) {
        let mut state = self.state();
        if state.error.is_none()
            && let Err(error) = state.response.end(timed_out)
        {
            state.error = Some(error.into());
        }
        drop(state);
        self.done.notify_one();
    }

    fn fail(&self, error: Error) {
        let mut state = self.state();
        if !state.response.is_done() && state.error.is_none() {
            state.error = Some(error);
        }
        drop(state);
        self.done.notify_one();
    }
}

impl ConnectionObserver for Tap {
    fn observe(&self, event: ConnectionEvent<'_>) {
        match event {
            ConnectionEvent::Eof { .. } => {
                self.end(false);
                return;
            }
            ConnectionEvent::ReadError { error, .. } => {
                match error.kind() {
                    ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset => self.end(false),
                    ErrorKind::TimedOut | ErrorKind::WouldBlock => self.end(true),
                    _ => self.fail(io::Error::new(error.kind(), error.to_string()).into()),
                }
                return;
            }
            // The request did not reach the peer in full, so no exchange can be attributed to it.
            // A response already captured in full is kept: `fail` leaves a finished capture alone.
            ConnectionEvent::WriteError { error, .. }
            | ConnectionEvent::FlushError { error, .. } => {
                self.fail(io::Error::new(error.kind(), error.to_string()).into());
                return;
            }
            // Closing our write half can fail once a complete response has been read, and a
            // connection that is genuinely gone reports that again on the read side. Neither
            // outcome invalidates what was captured.
            ConnectionEvent::ShutdownError { .. } => return,
            _ => {}
        }
        let mut state = self.state();
        if state.error.is_some() {
            return;
        }
        if matches!(
            event,
            ConnectionEvent::Connected { .. }
                | ConnectionEvent::Read { .. }
                | ConnectionEvent::Write { .. }
        ) {
            state.last_activity = Some(Instant::now());
            self.activity.notify_one();
        }
        match event {
            ConnectionEvent::Connected {
                id,
                remote_addr,
                http2,
                ..
            } => {
                if state.id.replace(id).is_some() || http2 {
                    state.error =
                        Some(io::Error::other("unexpected additional connection or HTTP/2").into());
                }
                state.ip_address = remote_addr.map(|addr| addr.ip());
            }
            ConnectionEvent::Read { id, bytes } => {
                if state.id != Some(id) {
                    state.error = Some(io::Error::other("unexpected connection ID").into());
                } else if let Err(error) = state.response.push(bytes) {
                    state.error = Some(error.into());
                }
            }
            ConnectionEvent::Write { id, bytes } => {
                if state.id == Some(id) {
                    state.request.extend_from_slice(bytes);
                } else {
                    state.error = Some(io::Error::other("unexpected connection ID").into());
                }
            }
            _ => {}
        }
        if state.error.is_some() || state.response.is_done() {
            self.done.notify_one();
        }
    }
}
