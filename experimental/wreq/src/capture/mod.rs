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

use super::{WreqBackend, backend_error};

impl WreqBackend {
    /// Build the isolated client with the selected transport settings and capture observer.
    fn client(&self, tap: Arc<Tap>) -> Result<wreq::Client, Error> {
        let mut profile = self.profile.into_emulation();
        // The wrapper delegates ordering/casing to the profile and observes finalized headers.
        // Leave the default-header map intact, but install the ordering callback on the request.
        profile.orig_headers = wreq::header::OrigHeaderMap::new();
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
        builder.build().map_err(backend_error)
    }

    pub(super) async fn capture(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        let tap = Arc::new(Tap::new(*method == Method::HEAD, self.max_response_length));
        let client = self.client(tap.clone())?;
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
        http2::observe_headers(
            &mut request,
            self.profile.into_emulation().orig_headers,
            tap.clone(),
        );
        let sent_target = request.uri().clone();
        let date = Utc::now();
        let clock = Instant::now();
        let operation = tap.receive(client, request, *method == Method::HEAD);
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
                    if tap.state().h2_response_started && matches!(error, Error::Other(_)) {
                        let timed_out = matches!(&error, Error::Other(error)
                            if error.downcast_ref::<wreq::Error>().is_some_and(wreq::Error::is_timeout));
                        tap.end(timed_out);
                    } else {
                        tap.fail(error);
                    }
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
        let request = state.recorded_request(method, &sent_target, body)?;
        let protocols = if state.http2 {
            vec![Protocol::H2]
        } else {
            Vec::new()
        };
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
    h2_response_started: bool,
    request_headers: Option<HeaderMap>,
    h2_request: http2::RequestCapture,
}

impl State {
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
            state: Mutex::new(State {
                response: ResponseCapture::new(head, cap),
                request: Vec::new(),
                error: None,
                id: None,
                ip_address: None,
                last_activity: None,
                http2: false,
                h2_response_started: false,
                request_headers: None,
                h2_request: http2::RequestCapture::default(),
            }),
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
            let frame = frame.map_err(backend_error)?;
            if h2 {
                if let Some(data) = frame.data_ref() {
                    self.h2_data(data)?;
                } else if let Some(trailers) = frame.trailers_ref() {
                    self.h2_trailers(trailers)?;
                }
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
        if self.state().http2
            && matches!(
                event,
                ConnectionEvent::Eof { .. } | ConnectionEvent::ReadError { .. }
            )
        {
            return;
        }
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
        if !state.http2
            && matches!(
                event,
                ConnectionEvent::Connected { .. }
                    | ConnectionEvent::Read { .. }
                    | ConnectionEvent::Write { .. }
            )
        {
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
                state.http2 = http2;
                if state.id.replace(id).is_some() {
                    state.error = Some(io::Error::other("unexpected additional connection").into());
                }
                state.ip_address = remote_addr.map(|addr| addr.ip());
            }
            ConnectionEvent::Read { id, bytes } => {
                if state.id != Some(id) {
                    state.error = Some(io::Error::other("unexpected connection ID").into());
                } else if !state.http2
                    && let Err(error) = state.response.push(bytes)
                {
                    state.error = Some(error.into());
                }
            }
            ConnectionEvent::Write { id, bytes } => {
                if state.id == Some(id) {
                    if state.http2 {
                        match state.h2_request.push(bytes) {
                            Ok(true) => {
                                state.last_activity = Some(Instant::now());
                                self.activity.notify_one();
                            }
                            Ok(false) => {}
                            Err(error) => state.error = Some(error.into()),
                        }
                    } else {
                        state.request.extend_from_slice(bytes);
                    }
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
