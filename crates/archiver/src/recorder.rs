//! Byte-exact capture of live HTTP exchanges.
//!
//! [`Recorder`] is the capture backend this crate ships. It performs an HTTP/1.1 exchange over its
//! own connection and returns the exact request and response bytes in [`CapturedExchange`]. It
//! serializes the request itself and stores the response verbatim, parsing only enough to find the
//! message boundary. This preserves chunked coding, header spelling, and the reason phrase, so
//! block digests cover bytes that crossed the wire. To archive an exchange performed by another
//! client, use [`record::http`](archivindex_warc::record::http) to reconstruct blocks from parsed
//! parts.
//!
//! Each fetch opens one connection for one request and response. It does not follow redirects,
//! decode content, or reuse the connection. It adds `host` when absent and defaults a missing
//! `connection` header to `close`. Interim (`1xx`) responses are discarded. An unframed response,
//! or one whose final transfer coding is not `chunked`, ends when the connection closes.
//!
//! [`max_response_length`](Recorder::max_response_length) limits stored response bytes. After a
//! complete header section, a size limit, disconnect, or read timeout returns a truncated response.
//! Before that point, failures return an error. [`Recorder::new`] sets [`DEFAULT_TIMEOUT`] per
//! connection step and [`DEFAULT_MAX_RESPONSE_LENGTH`] per response. Timeout and size setters
//! accept `None` to remove their bounds. [`Recorder::fetch_by`] adds a deadline, excluding DNS
//! resolution.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use archivindex_warc::record::http::{ResponseMetadata, reconstruct_request};
use chrono::Utc;
use fluent_uri::Uri;
use http::{HeaderMap, HeaderValue, Method, Version, header};
use rustls::pki_types::ServerName;

use crate::backend::framing::read_response;
use crate::backend::{
    CapturedExchange, DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT, Error, ResponseError,
};

/// An HTTP/1.1 client that records the exact bytes of one exchange per fetch.
#[derive(Clone, Debug)]
pub struct Recorder {
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Option<Duration>,
    io_timeout: Option<Duration>,
    max_response_length: Option<u64>,
}

impl Recorder {
    /// Create a recorder using `webpki-roots` and `aws-lc-rs`, with [`DEFAULT_TIMEOUT`] for each
    /// connection step and [`DEFAULT_MAX_RESPONSE_LENGTH`] for the response.
    ///
    /// The crypto provider is named rather than taken from the process default, which is undefined
    /// when a dependency graph enables more than one.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the aws-lc-rs provider supports every default protocol version"
    )]
    #[must_use]
    pub fn new() -> Self {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the aws-lc-rs provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        Self {
            tls: Arc::new(tls),
            connect_timeout: Some(DEFAULT_TIMEOUT),
            io_timeout: Some(DEFAULT_TIMEOUT),
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
        }
    }

    /// Replace the TLS client configuration.
    #[must_use]
    pub fn tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls = config;

        self
    }

    /// Set the connection timeout for each resolved address, or lift it with `None`.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;

        self
    }

    /// Set the timeout for each connection read or write, or lift it with `None`.
    ///
    /// A read timeout after the header section truncates the response instead of failing. Name
    /// resolution is not timed.
    #[must_use]
    pub const fn io_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.io_timeout = timeout;

        self
    }

    /// Set the maximum stored response length, including the header section, or lift it with
    /// `None`.
    ///
    /// Reaching the limit records a `length` truncation. A header section larger than the limit
    /// fails because it cannot be partially recorded.
    #[must_use]
    pub const fn max_response_length(mut self, length: Option<u64>) -> Self {
        self.max_response_length = length;

        self
    }

    /// Perform one HTTP/1.1 exchange and record its exact bytes.
    ///
    /// The request is serialized from its parts. Missing `host` and `connection` headers are added,
    /// and framing is normalized for a provided body. The response is recorded verbatim from its
    /// final status line through the message boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for an invalid target, a connection or TLS failure, an incomplete header
    /// section, or malformed response framing. A size limit, disconnect, or read timeout after the
    /// header section instead returns a response with [`CapturedExchange::truncated`] set.
    pub fn fetch(
        &self,
        method: &Method,
        target: &http::Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<CapturedExchange, Error> {
        self.fetch_within(method, target, headers, body, None)
    }

    /// Perform one exchange as [`fetch`](Self::fetch) does, ending it at `deadline`.
    ///
    /// Connection and I/O timeouts are limited by the remaining time. DNS resolution is not timed,
    /// so this is not a strict wall-clock limit. Reaching the deadline fails the exchange before a
    /// complete response header, or returns a `time` truncation afterward.
    ///
    /// # Errors
    ///
    /// As for [`fetch`](Self::fetch), with a passed deadline reported as a timed-out I/O operation.
    pub fn fetch_by(
        &self,
        method: &Method,
        target: &http::Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<CapturedExchange, Error> {
        self.fetch_within(method, target, headers, body, Some(deadline))
    }

    pub(crate) fn fetch_within(
        &self,
        method: &Method,
        target: &http::Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        let tls = match target.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err(Error::UnsupportedScheme),
        };
        let authority = target.authority().ok_or(Error::MissingHost)?;
        let raw_host = authority.host();
        if raw_host.is_empty() {
            return Err(Error::MissingHost);
        }
        // URIs bracket IPv6 hosts; DNS resolution and SNI do not.
        let host = raw_host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(raw_host);
        let port = target.port_u16().unwrap_or(if tls { 443 } else { 80 });

        let target_string = target.to_string();
        let target_uri = Uri::parse(target_string.as_str())?.to_owned();

        let mut prepared = HeaderMap::with_capacity(headers.len() + 2);
        if !headers.contains_key(header::HOST) {
            let authority_text = authority.as_str();
            let host_port = authority_text
                .split('@')
                .next_back()
                .unwrap_or(authority_text);
            prepared.insert(
                header::HOST,
                HeaderValue::from_str(host_port)
                    .expect("invariant violation: a URI authority failed as a header value"),
            );
        }
        for (name, value) in headers {
            prepared.append(name.clone(), value.clone());
        }
        if !headers.contains_key(header::CONNECTION) {
            prepared.append(header::CONNECTION, HeaderValue::from_static("close"));
        }

        let request = reconstruct_request(method, target, Version::HTTP_11, &prepared, body);

        let date = Utc::now();
        let clock = Instant::now();

        let stream = self.connect(host, port, deadline)?;
        let ip_address = stream.peer_addr()?.ip();
        stream.set_read_timeout(self.io_timeout)?;
        stream.set_write_timeout(self.io_timeout)?;

        let stream = if tls {
            let server_name = ServerName::try_from(host.to_owned())?;
            let connection = rustls::ClientConnection::new(Arc::clone(&self.tls), server_name)?;
            Stream::Tls(Box::new(rustls::StreamOwned::new(connection, stream)))
        } else {
            Stream::Plain(stream)
        };
        let mut transport = Transport {
            stream,
            io_timeout: self.io_timeout,
            deadline,
        };

        transport.write_all(&request)?;
        transport.flush()?;

        let (response, truncated) = read_response(
            &mut transport,
            *method == Method::HEAD,
            self.max_response_length,
        )?;
        let response_metadata =
            ResponseMetadata::parse(&response).ok_or(ResponseError::MalformedStatusLine)?;
        let fetch_time = clock.elapsed();

        Ok(CapturedExchange {
            request,
            response,
            response_metadata,
            target_uri,
            ip_address,
            date,
            fetch_time,
            truncated,
        })
    }

    /// Connect to the first resolved address that succeeds.
    fn connect(
        &self,
        host: &str,
        port: u16,
        deadline: Option<Instant>,
    ) -> Result<TcpStream, Error> {
        let mut failure = None;
        for address in (host, port).to_socket_addrs()? {
            let attempt = bound(self.connect_timeout, deadline)?.map_or_else(
                || TcpStream::connect(address),
                |timeout| TcpStream::connect_timeout(&address, timeout),
            );
            match attempt {
                Ok(stream) => return Ok(stream),
                Err(error) => failure = Some(error),
            }
        }

        Err(failure
            .unwrap_or_else(|| {
                std::io::Error::new(ErrorKind::NotFound, "the host resolved to no addresses")
            })
            .into())
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

/// The tighter of a step's timeout and the time left to a deadline.
///
/// A deadline that has passed is a timed-out operation, since the socket refuses a zero timeout.
fn bound(
    timeout: Option<Duration>,
    deadline: Option<Instant>,
) -> std::io::Result<Option<Duration>> {
    let Some(deadline) = deadline else {
        return Ok(timeout);
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "the fetch deadline has passed",
        ));
    }

    Ok(Some(timeout.map_or(left, |timeout| timeout.min(left))))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

/// A connection whose every read and write is bounded by the I/O timeout and the deadline.
struct Transport {
    stream: Stream,
    io_timeout: Option<Duration>,
    deadline: Option<Instant>,
}

impl Transport {
    /// Bound the next socket operation by the time left to the deadline, when there is one.
    ///
    /// Without a deadline the socket keeps the timeout set when it was connected.
    fn arm(&self) -> std::io::Result<()> {
        if self.deadline.is_none() {
            return Ok(());
        }
        let timeout = bound(self.io_timeout, self.deadline)?;
        let socket = match &self.stream {
            Stream::Plain(stream) => stream,
            Stream::Tls(stream) => &stream.sock,
        };
        socket.set_read_timeout(timeout)?;
        socket.set_write_timeout(timeout)
    }
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        match &mut self.stream {
            Stream::Plain(stream) => stream.read(buffer),
            Stream::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        match &mut self.stream {
            Stream::Plain(stream) => stream.write(buffer),
            Stream::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.arm()?;
        match &mut self.stream {
            Stream::Plain(stream) => stream.flush(),
            Stream::Tls(stream) => stream.flush(),
        }
    }
}
