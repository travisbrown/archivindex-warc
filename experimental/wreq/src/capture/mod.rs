//! Per-fetch transport observation and message capture.

mod http2;

use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use archivindex_archiver::backend::{CapturedExchange, Error, ResponseCapture, ResponseError};
use archivindex_warc::record::header::protocol::Protocol;
use archivindex_warc::record::http::{ResponseMetadata, reconstruct_request};
use chrono::Utc;
use http::{HeaderMap, Method, Uri, Version, header};
use http_body_util::BodyExt;
use tokio::sync::Notify;
use wreq::IntoEmulation;
use wreq::connection_observer::{ConnectionEvent, ConnectionObserver};
use wreq::header::OrigHeaderMap;
use wreq::tls::TlsVersion;

use super::{WreqBackend, backend_error};

impl WreqBackend {
    /// Build the isolated client with the selected transport settings and capture observer.
    ///
    /// Returns the profile's header ordering separately, for the request callback to apply.
    fn client(&self, tap: Arc<Tap>) -> Result<(wreq::Client, OrigHeaderMap), Error> {
        let mut profile = self.profile.into_emulation();
        // The wrapper delegates ordering/casing to the profile and observes finalized headers.
        // Leave the default-header map intact, but install the ordering callback on the request.
        let orig_headers = std::mem::replace(&mut profile.orig_headers, OrigHeaderMap::new());
        let mut builder = wreq::Client::builder()
            .emulation(profile)
            .redirect(wreq::redirect::Policy::none())
            .retry(wreq::retry::Policy::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .pool_max_idle_per_host(0)
            .connection_observer(tap);
        if let Some(proxy) = &self.proxy {
            builder = builder.proxy(proxy.clone());
        }
        if let Some(timeout) = self.connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(store) = &self.cert_store {
            builder = builder.tls_cert_store(store.clone());
        }
        let client = builder.build().map_err(backend_error)?;
        Ok((client, orig_headers))
    }

    pub(super) async fn capture(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        let head = *method == Method::HEAD;
        let tap = Arc::new(Tap::new(head, self.max_response_length));
        let (client, orig_headers) = self.client(tap.clone())?;
        let mut headers = headers.clone();
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
        let mut request: http::Request<wreq::Body> = request.build().map_err(backend_error)?.into();
        http2::observe_headers(&mut request, orig_headers, tap.clone());
        let sent_target = request.uri().clone();
        let date = Utc::now();
        let clock = Instant::now();
        let operation = tap.receive(client, request, head);
        let expire = async {
            match deadline {
                Some(deadline) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            () = tap.done.notified() => {},
            () = expire => tap.end(true),
            () = tap.idle(self.io_timeout) => tap.end(true),
            result = operation => {
                if let Err(error) = result {
                    tap.fail(error);
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
        let mut state = std::mem::replace(&mut *tap.state(), State::new(head, None));
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        let request = state.recorded_request(method, &sent_target, body)?;
        let protocols = state.protocols();
        let (response, truncated) = state.response.into_parts();
        let response_metadata =
            ResponseMetadata::parse(&response).ok_or(ResponseError::MalformedStatusLine)?;
        Ok(CapturedExchange {
            request,
            request_protocols: protocols.clone(),
            response_protocols: protocols,
            response,
            response_metadata,
            target_uri: fluent_uri::Uri::parse(target.to_string().as_str())?.to_owned(),
            ip_address: if self.proxy.is_some() {
                None
            } else {
                Some(
                    state
                        .ip_address
                        .ok_or_else(|| io::Error::other("missing peer address"))?,
                )
            },
            date,
            fetch_time,
            truncated,
        })
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
    http2: bool,
    tls_version: Option<TlsVersion>,
    request_headers: Option<HeaderMap>,
    h2_request: http2::RequestCapture,
}

impl State {
    fn new(head: bool, cap: Option<u64>) -> Self {
        Self {
            response: ResponseCapture::new(head, cap),
            request: Vec::new(),
            error: None,
            id: None,
            ip_address: None,
            last_activity: None,
            http2: false,
            tls_version: None,
            request_headers: None,
            h2_request: http2::RequestCapture::default(),
        }
    }

    /// Close the capture because the transport ended or ran out of time.
    fn end(&mut self, timed_out: bool) {
        if self.error.is_none()
            && let Err(error) = self.response.end(timed_out)
        {
            self.error = Some(error.into());
        }
    }

    /// Fail the exchange, unless the response was already captured in full.
    fn fail(&mut self, error: Error) {
        if !self.response.is_done() && self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn protocols(&self) -> Vec<Protocol> {
        let tls = match self.tls_version {
            Some(TlsVersion::TLS_1_0) => Some(Protocol::TLS_1_0),
            Some(TlsVersion::TLS_1_1) => Some(Protocol::TLS_1_1),
            Some(TlsVersion::TLS_1_2) => Some(Protocol::TLS_1_2),
            Some(TlsVersion::TLS_1_3) => Some(Protocol::TLS_1_3),
            // Omit unavailable or unrecognized versions rather than infer one from the profile.
            _ => None,
        };
        self.http2
            .then_some(Protocol::H2)
            .into_iter()
            .chain(tls)
            .collect()
    }

    fn recorded_request(
        &mut self,
        method: &Method,
        target: &Uri,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if self.http2 {
            if !self.h2_request.is_complete() {
                return Err(io::Error::other("HTTP/2 request was not completely written").into());
            }
            let mut headers = self
                .request_headers
                .take()
                .ok_or_else(|| io::Error::other("missing finalized HTTP/2 request headers"))?;
            if !headers.contains_key(header::HOST) {
                let authority = target
                    .authority()
                    .ok_or_else(|| io::Error::other("missing request authority"))?;
                headers.insert(
                    header::HOST,
                    authority
                        .as_str()
                        .parse()
                        .map_err(|error| Error::Other(Box::new(error)))?,
                );
            }
            Ok(reconstruct_request(
                method,
                target,
                Version::HTTP_2,
                &headers,
                body,
            ))
        } else {
            Ok(std::mem::take(&mut self.request))
        }
    }
}

impl Tap {
    fn new(head: bool, cap: Option<u64>) -> Self {
        Self {
            state: Mutex::new(State::new(head, cap)),
            done: Notify::new(),
            activity: Notify::new(),
        }
    }

    async fn receive(
        &self,
        client: wreq::Client,
        request: http::Request<wreq::Body>,
        head: bool,
    ) -> Result<(), Error> {
        let mut response = client
            .execute(request.into())
            .await
            .map_err(backend_error)?;
        let h2 = response.version() == Version::HTTP_2;
        if h2 {
            self.h2_head(response.status(), response.headers(), head)?;
        }
        while let Some(frame) = response.frame().await {
            match frame {
                Ok(frame) if h2 => {
                    if let Some(data) = frame.data_ref() {
                        self.h2_data(data)?;
                    } else if let Some(trailers) = frame.trailers_ref() {
                        self.h2_trailers(trailers)?;
                    }
                }
                Ok(_) => {}
                // The reconstructed head is already stored, so a stream error truncates the
                // response. HTTP/1 disconnects reach the connection observer instead.
                Err(_) if h2 => {
                    self.end(false);
                    return Ok(());
                }
                Err(error) => return Err(backend_error(error)),
            }
        }
        if h2 {
            self.h2_trailers(&HeaderMap::new())?;
        }
        Ok(())
    }

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
        self.state().end(timed_out);
        self.done.notify_one();
    }

    fn fail(&self, error: Error) {
        self.state().fail(error);
        self.done.notify_one();
    }

    /// Record exchange progress, restarting the idle timeout.
    fn progress(&self, state: &mut State) {
        state.last_activity = Some(Instant::now());
        self.activity.notify_one();
    }
}

impl ConnectionObserver for Tap {
    fn observe(&self, event: ConnectionEvent<'_>) {
        let mut state = self.state();
        match event {
            // HTTP/2 stream ends and errors reach the response body instead.
            ConnectionEvent::Eof { .. } | ConnectionEvent::ReadError { .. } if state.http2 => {
                return;
            }
            ConnectionEvent::Eof { .. } => state.end(false),
            ConnectionEvent::ReadError { error, .. } => match error.kind() {
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset => state.end(false),
                ErrorKind::TimedOut | ErrorKind::WouldBlock => state.end(true),
                _ => state.fail(io::Error::new(error.kind(), error.to_string()).into()),
            },
            // The request did not reach the peer in full, so no exchange can be attributed to it.
            // A response already captured in full is kept: `fail` leaves a finished capture alone.
            ConnectionEvent::WriteError { error, .. }
            | ConnectionEvent::FlushError { error, .. } => {
                state.fail(io::Error::new(error.kind(), error.to_string()).into());
            }
            // Closing our write half can fail once a complete response has been read, and a
            // connection that is genuinely gone reports that again on the read side. Neither
            // outcome invalidates what was captured.
            ConnectionEvent::ShutdownError { .. } => return,
            _ if state.error.is_some() => return,
            ConnectionEvent::Connected {
                id,
                remote_addr,
                http2,
                tls_version,
                ..
            } => {
                // Connecting starts the idle clock for both protocols.
                self.progress(&mut state);
                state.http2 = http2;
                state.tls_version = tls_version;
                if state.id.replace(id).is_some() {
                    state.error = Some(io::Error::other("unexpected additional connection").into());
                }
                state.ip_address = remote_addr.map(|addr| addr.ip());
            }
            ConnectionEvent::Read { id, bytes } => {
                if state.id != Some(id) {
                    state.error = Some(io::Error::other("unexpected connection ID").into());
                } else if !state.http2 {
                    // HTTP/2 reads include connection control traffic, so only the reconstructed
                    // response counts as its progress.
                    self.progress(&mut state);
                    if let Err(error) = state.response.push(bytes) {
                        state.error = Some(error.into());
                    }
                }
            }
            ConnectionEvent::Write { id, bytes } => {
                if state.id != Some(id) {
                    state.error = Some(io::Error::other("unexpected connection ID").into());
                } else if state.http2 {
                    match state.h2_request.push(bytes) {
                        Ok(true) => self.progress(&mut state),
                        Ok(false) => {}
                        Err(error) => state.error = Some(error.into()),
                    }
                } else {
                    self.progress(&mut state);
                    state.request.extend_from_slice(bytes);
                }
            }
            _ => {}
        }
        if state.error.is_some() || state.response.is_done() {
            drop(state);
            self.done.notify_one();
        }
    }
}
