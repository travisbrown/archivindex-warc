//! Byte-exact capture of live HTTP exchanges.
//!
//! [`Recorder`] performs an HTTP/1.1 exchange over its own connection and returns the exact request
//! and response bytes in [`CapturedExchange`]. It serializes the request itself and stores the
//! response verbatim, parsing only enough to find the message boundary. This preserves chunked
//! coding, header spelling, and the reason phrase, so block digests cover bytes that crossed the
//! wire. To archive an exchange performed by another client, use
//! [`record::http`](archivindex_warc::record::http) to reconstruct blocks from parsed parts.
//!
//! Each fetch opens one connection for one request and response. It does not follow redirects,
//! decode content, or reuse the connection. It adds `host` when absent and defaults a missing
//! `connection` header to `close`. Interim (`1xx`) responses are discarded. An unframed response,
//! or one whose final transfer coding is not `chunked`, ends when the connection closes.
//!
//! [`max_response_length`](Recorder::max_response_length) bounds stored response bytes. A limit,
//! disconnect, or I/O timeout truncates the response instead of failing the fetch; the reason is
//! available in [`CapturedExchange::truncated`]. [`Recorder::new`] bounds each connection step at
//! [`DEFAULT_TIMEOUT`] and the response at [`DEFAULT_MAX_RESPONSE_LENGTH`]; each setter lifts its
//! bound when given `None`. The timeout bounds each step, not the exchange: a peer sending one
//! byte before each read times out never trips it. [`Recorder::fetch_by`] bounds the whole
//! exchange by a deadline as well.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use archivindex_warc::record::capture::CaptureEvent;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::record::http::{ResponseMetadata, reconstruct_request};
use chrono::{DateTime, Utc};
use fluent_uri::Uri;
use http::{HeaderMap, HeaderValue, Method, Version, header};
use rustls::pki_types::ServerName;

/// The connection and I/O timeout of a new recorder.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The response-size bound of a new recorder, in bytes.
pub const DEFAULT_MAX_RESPONSE_LENGTH: u64 = 256 * 1024 * 1024;

const MAX_HEADER_LENGTH: usize = 64 * 1024;

const READ_LENGTH: usize = 8 * 1024;

/// Errors returned while performing a recorded exchange.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The target is not an absolute HTTP or HTTPS URI.
    #[error("the target URI must be absolute, with an `http` or `https` scheme")]
    UnsupportedScheme,
    /// The target names no host.
    #[error("the target URI names no host")]
    MissingHost,
    /// The target cannot be represented as a `WARC-Target-URI`.
    #[error("the target URI is not a URI: {0}")]
    TargetUri(#[from] fluent_uri::ParseError),
    /// The host cannot name a TLS server.
    #[error("the host cannot name a TLS server: {0}")]
    ServerName(#[from] rustls::pki_types::InvalidDnsNameError),
    /// The TLS session could not be created.
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Response framing is malformed.
    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// Malformed responses whose message boundary cannot be determined.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResponseError {
    /// The response does not begin with an HTTP status line.
    #[error("the response does not begin with an HTTP status line")]
    MalformedStatusLine,
    /// The server switched protocols with a `101` the request did not ask for.
    #[error("the server switched protocols with a `101` the request did not ask for")]
    UnsolicitedUpgrade,
    /// The connection ended before a complete header section arrived.
    #[error("the connection ended before a complete response header section arrived")]
    IncompleteHeaderSection,
    /// The header section exceeds the recorder's limit.
    #[error("the response header section exceeds the recorder's limit")]
    OversizedHeaderSection,
    /// The response declares `Content-Length` values that disagree.
    #[error("the response declares `Content-Length` values that disagree")]
    ConflictingContentLength,
    /// A declared `Content-Length` is not a valid decimal length.
    #[error("the declared `Content-Length` `{0}` is not a valid decimal length")]
    MalformedContentLength(String),
    /// A declared chunk size is not a valid hexadecimal length.
    #[error("the declared chunk size `{0}` is not a hexadecimal length")]
    MalformedChunkSize(String),
    /// A chunk's data is not followed by the terminating CRLF.
    #[error("a chunk's data is not followed by CRLF")]
    UnterminatedChunk,
}

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
    /// The crypto provider is named rather than taken from the process default, which is
    /// undefined when a dependency graph enables more than one.
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
    /// The request is serialized from its parts. Missing `host` and `connection` headers are
    /// added, and framing is normalized for a provided body. The response is recorded verbatim
    /// from its final status line through the message boundary.
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
    /// Each connection step is bounded by the time left as well as by its timeout, so the
    /// exchange ends within one step's timeout of the deadline. Reaching it is reported as a
    /// read timeout is: a failure before the response header section is complete, and a `time`
    /// truncation after.
    ///
    /// # Errors
    ///
    /// As for [`fetch`](Self::fetch), with a passed deadline reported as a timed-out I/O
    /// operation.
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

/// A recorded exchange and the fields needed to build its capture records.
///
/// [`capture_event`](Self::capture_event) copies the shared fields into a [`CaptureEvent`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedExchange {
    /// Request bytes exactly as written.
    pub request: Vec<u8>,
    /// Response bytes exactly as read, from the final status line through the recorded end.
    pub response: Vec<u8>,
    /// Parsed fields and boundaries of the recorded response.
    pub response_metadata: ResponseMetadata,
    /// The requested URI.
    pub target_uri: Uri<String>,
    /// The peer IP address.
    pub ip_address: IpAddr,
    /// When network activity began.
    pub date: DateTime<Utc>,
    /// Time from starting network activity to finishing the response.
    pub fetch_time: Duration,
    /// Why the response was truncated, if applicable.
    pub truncated: Option<TruncatedType>,
}

impl CapturedExchange {
    /// Create a capture event with this exchange's shared fields.
    #[must_use]
    pub fn capture_event(&self) -> CaptureEvent {
        let event = CaptureEvent::new(self.target_uri.clone(), self.date)
            .ip_address(self.ip_address)
            .fetch_time(self.fetch_time);

        match self.truncated.clone() {
            Some(reason) => event.truncated(reason),
            None => event,
        }
    }

    /// Return the decoded response entity body.
    pub fn entity_body(
        &self,
    ) -> Result<std::borrow::Cow<'_, [u8]>, archivindex_warc::record::payload::Error> {
        archivindex_warc::record::payload::entity_body(&self.response)
    }

    /// Return the recorded bytes after the response header section without transfer decoding.
    #[must_use]
    pub fn stored_body(&self) -> &[u8] {
        &self.response[self.response_metadata.body_offset..]
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

enum ReadEvent {
    /// Bytes were appended to the buffer.
    Data,
    /// The connection closed, cleanly or not.
    Closed,
    /// The read timed out.
    TimedOut,
}

/// Append one transport read to the buffer.
///
/// Rustls reports a close without `close_notify` as `UnexpectedEof`; treat it as a disconnect and
/// retain the bytes received so far.
fn fill(source: &mut impl Read, buffer: &mut Vec<u8>) -> std::io::Result<ReadEvent> {
    let mut chunk = [0u8; READ_LENGTH];

    loop {
        return match source.read(&mut chunk) {
            Ok(0) => Ok(ReadEvent::Closed),
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);

                Ok(ReadEvent::Data)
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(ReadEvent::Closed),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(ReadEvent::TimedOut)
            }
            Err(error) => Err(error),
        };
    }
}

enum BodyFraming {
    /// The message ends with its header section.
    None,
    /// The body is this many bytes.
    Length(u64),
    /// The body is chunked, ending after the trailer section.
    Chunked,
    /// The body extends to the close of the connection.
    Close,
}

/// Read one response verbatim and report any truncation.
fn read_response(
    source: &mut impl Read,
    head_request: bool,
    max_length: Option<u64>,
) -> Result<(Vec<u8>, Option<TruncatedType>), Error> {
    let mut buffer = Vec::with_capacity(READ_LENGTH);
    let header_bound = max_length.map_or(MAX_HEADER_LENGTH, |cap| {
        MAX_HEADER_LENGTH.min(usize::try_from(cap).unwrap_or(usize::MAX))
    });
    let (status, header_end) = read_final_header_section(source, &mut buffer, header_bound)?;
    let framing = body_framing(&buffer[..header_end], head_request, status)?;
    let mut truncated = None;

    match framing {
        BodyFraming::None => buffer.truncate(header_end),
        BodyFraming::Length(length) => {
            let message_end = header_end as u64 + length;
            loop {
                if buffer.len() as u64 >= message_end {
                    cut(&mut buffer, message_end);
                    break;
                }
                if reached_cap(&buffer, max_length) {
                    truncated = Some(TruncatedType::Length);
                    break;
                }
                match fill(source, &mut buffer)? {
                    ReadEvent::Data => {}
                    ReadEvent::Closed => {
                        truncated = Some(TruncatedType::Disconnect);
                        break;
                    }
                    ReadEvent::TimedOut => {
                        truncated = Some(TruncatedType::Time);
                        break;
                    }
                }
            }
        }
        BodyFraming::Chunked => {
            let mut scanner = ChunkScanner::new(header_end);
            loop {
                if let Some(message_end) = scanner.advance(&buffer)? {
                    buffer.truncate(message_end);
                    break;
                }
                if reached_cap(&buffer, max_length) {
                    truncated = truncation_at_cap(source, Some(TruncatedType::Disconnect))?;
                    break;
                }
                match fill(source, &mut buffer)? {
                    ReadEvent::Data => {}
                    ReadEvent::Closed => {
                        truncated = Some(TruncatedType::Disconnect);
                        break;
                    }
                    ReadEvent::TimedOut => {
                        truncated = Some(TruncatedType::Time);
                        break;
                    }
                }
            }
        }
        BodyFraming::Close => loop {
            if reached_cap(&buffer, max_length) {
                truncated = truncation_at_cap(source, None)?;
                break;
            }
            match fill(source, &mut buffer)? {
                ReadEvent::Data => {}
                ReadEvent::Closed => break,
                ReadEvent::TimedOut => {
                    truncated = Some(TruncatedType::Time);
                    break;
                }
            }
        },
    }

    if let Some(cap) = max_length
        && buffer.len() as u64 > cap
    {
        cut(&mut buffer, cap);
        truncated = Some(TruncatedType::Length);
    }

    Ok((buffer, truncated))
}

fn truncation_at_cap(
    source: &mut impl Read,
    on_close: Option<TruncatedType>,
) -> Result<Option<TruncatedType>, std::io::Error> {
    Ok(match probe(source)? {
        ReadEvent::Data => Some(TruncatedType::Length),
        ReadEvent::Closed => on_close,
        ReadEvent::TimedOut => Some(TruncatedType::Time),
    })
}

fn probe(source: &mut impl Read) -> Result<ReadEvent, std::io::Error> {
    let mut byte = [0];
    loop {
        return match source.read(&mut byte) {
            Ok(0) => Ok(ReadEvent::Closed),
            Ok(_) => Ok(ReadEvent::Data),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(ReadEvent::Closed),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(ReadEvent::TimedOut)
            }
            Err(error) => Err(error),
        };
    }
}

fn reached_cap(buffer: &[u8], max_length: Option<u64>) -> bool {
    max_length.is_some_and(|cap| buffer.len() as u64 >= cap)
}

fn cut(buffer: &mut Vec<u8>, boundary: u64) {
    buffer.truncate(
        usize::try_from(boundary)
            .expect("invariant violation: a boundary within the buffer overflowed usize"),
    );
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// Read into `buffer` until it holds the final response's header section, returning the status
/// and the section's length.
///
/// Interim responses are discarded so the recording begins at the final status line. No request
/// asks to upgrade, so a `101` is a protocol violation after which the stream is not HTTP.
fn read_final_header_section(
    source: &mut impl Read,
    buffer: &mut Vec<u8>,
    header_bound: usize,
) -> Result<(u16, usize), Error> {
    loop {
        if let Some(header_end) = find_header_end(buffer) {
            if header_end > header_bound {
                return Err(ResponseError::OversizedHeaderSection.into());
            }
            let status = parse_status(buffer)?;
            if status == 101 {
                return Err(ResponseError::UnsolicitedUpgrade.into());
            }
            if (100..200).contains(&status) {
                buffer.drain(..header_end);
                continue;
            }

            return Ok((status, header_end));
        }
        if buffer.len() > header_bound {
            return Err(ResponseError::OversizedHeaderSection.into());
        }
        match fill(source, buffer)? {
            ReadEvent::Data => {}
            ReadEvent::Closed | ReadEvent::TimedOut => {
                return Err(ResponseError::IncompleteHeaderSection.into());
            }
        }
    }
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn parse_status(buffer: &[u8]) -> Result<u16, ResponseError> {
    let line_end = find_crlf(buffer).ok_or(ResponseError::MalformedStatusLine)?;
    let mut parts = buffer[..line_end].splitn(3, |&byte| byte == b' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();

    if !version.starts_with(b"HTTP/") || code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(ResponseError::MalformedStatusLine);
    }

    Ok(code
        .iter()
        .fold(0, |value, &byte| value * 10 + u16::from(byte - b'0')))
}

/// Determine response framing according to RFC 9112 section 6.3.
///
/// `Transfer-Encoding` overrides `Content-Length`. A final coding other than `chunked`, or no
/// framing fields, makes the response close-delimited.
fn body_framing(
    header_section: &[u8],
    head_request: bool,
    status: u16,
) -> Result<BodyFraming, ResponseError> {
    if head_request || status == 204 || status == 304 {
        return Ok(BodyFraming::None);
    }

    // Join obsolete line folds before parsing fields; the recorded bytes remain unchanged.
    let text = String::from_utf8_lossy(header_section)
        .replace("\r\n ", " ")
        .replace("\r\n\t", " ");

    let mut final_coding: Option<String> = None;
    let mut content_length: Option<u64> = None;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if let Some(coding) = value.split(',').next_back() {
                final_coding = Some(coding.trim().to_ascii_lowercase());
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            for token in value.split(',') {
                let token = token.trim();
                let length = token
                    .parse::<u64>()
                    .map_err(|_| ResponseError::MalformedContentLength(token.to_owned()))?;
                if content_length
                    .replace(length)
                    .is_some_and(|seen| seen != length)
                {
                    return Err(ResponseError::ConflictingContentLength);
                }
            }
        }
    }

    Ok(match (final_coding, content_length) {
        (Some(coding), _) if coding == "chunked" => BodyFraming::Chunked,
        (Some(_), _) | (None, None) => BodyFraming::Close,
        (None, Some(length)) => BodyFraming::Length(length),
    })
}

/// Incrementally locates the end of a chunked body.
///
/// [`advance`](Self::advance) returns the offset after the trailer section once the body is
/// complete. It never changes the buffered bytes.
struct ChunkScanner {
    /// The offset of the next unexamined byte.
    offset: usize,
    stage: ChunkStage,
}

enum ChunkStage {
    /// A chunk-size line.
    Size,
    /// Chunk data and its terminating CRLF.
    Data(u64),
    /// The trailer section, ending at an empty line.
    Trailers,
}

impl ChunkScanner {
    /// Start at the first chunk-size line.
    const fn new(offset: usize) -> Self {
        Self {
            offset,
            stage: ChunkStage::Size,
        }
    }

    /// Scan available bytes and return the message end when complete.
    fn advance(&mut self, buffer: &[u8]) -> Result<Option<usize>, ResponseError> {
        loop {
            match self.stage {
                ChunkStage::Size => {
                    let Some(line_end) = find_crlf(&buffer[self.offset..]) else {
                        return Ok(None);
                    };
                    let line = &buffer[self.offset..self.offset + line_end];
                    let size_text = line
                        .split(|&byte| byte == b';')
                        .next()
                        .unwrap_or(line)
                        .trim_ascii();
                    let size = parse_chunk_size(size_text)?;
                    self.offset += line_end + 2;
                    self.stage = if size == 0 {
                        ChunkStage::Trailers
                    } else {
                        ChunkStage::Data(size)
                    };
                }
                ChunkStage::Data(remaining) => {
                    let held = (buffer.len() - self.offset) as u64;
                    if held < remaining + 2 {
                        return Ok(None);
                    }
                    let data_end = self.offset
                        + usize::try_from(remaining)
                            .expect("invariant violation: buffered chunk data overflowed usize");
                    if &buffer[data_end..data_end + 2] != b"\r\n" {
                        return Err(ResponseError::UnterminatedChunk);
                    }
                    self.offset = data_end + 2;
                    self.stage = ChunkStage::Size;
                }
                ChunkStage::Trailers => {
                    let Some(line_end) = find_crlf(&buffer[self.offset..]) else {
                        return Ok(None);
                    };
                    self.offset += line_end + 2;
                    if line_end == 0 {
                        return Ok(Some(self.offset));
                    }
                }
            }
        }
    }
}

/// Parse a chunk size while reserving room for its trailing CRLF.
fn parse_chunk_size(text: &[u8]) -> Result<u64, ResponseError> {
    let malformed =
        || ResponseError::MalformedChunkSize(String::from_utf8_lossy(text).into_owned());

    if text.is_empty() {
        return Err(malformed());
    }

    let mut size = 0u64;
    for &byte in text {
        let digit = char::from(byte).to_digit(16).ok_or_else(malformed)?;
        size = size
            .checked_mul(16)
            .and_then(|size| size.checked_add(u64::from(digit)))
            .filter(|size| *size <= u64::MAX - 2)
            .ok_or_else(malformed)?;
    }

    Ok(size)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    fn read_all(
        response: &[u8],
        head_request: bool,
        max_length: Option<u64>,
    ) -> (Vec<u8>, Option<TruncatedType>) {
        read_response(&mut Cursor::new(response), head_request, max_length).expect("a response")
    }

    struct YieldAt<'a> {
        bytes: &'a [u8],
        first: usize,
        offset: usize,
    }

    impl Read for YieldAt<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let remaining = &self.bytes[self.offset..];
            if remaining.is_empty() {
                return Ok(0);
            }
            let bound = if self.offset == 0 {
                self.first
            } else {
                remaining.len()
            };
            let length = output.len().min(remaining.len()).min(bound);
            output[..length].copy_from_slice(&remaining[..length]);
            self.offset += length;
            Ok(length)
        }
    }

    fn read_at_cap(response: &[u8], cap: usize) -> (Vec<u8>, Option<TruncatedType>) {
        read_response(
            &mut YieldAt {
                bytes: response,
                first: cap,
                offset: 0,
            },
            false,
            Some(cap as u64),
        )
        .expect("a response")
    }

    #[test]
    fn a_content_length_body_ends_at_the_declared_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn a_chunked_body_is_recorded_verbatim_through_its_trailers() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            4;ext=a\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn a_response_without_framing_extends_to_the_close() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nunbounded";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn a_non_chunked_final_transfer_coding_extends_to_the_close() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 1\r\n\r\nmore than one";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn a_head_response_ends_with_its_header_section() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let (recorded, truncated) = read_all(response, true, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn an_interim_response_is_discarded() {
        let response = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n\
            HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        assert_eq!(truncated, None);
    }

    #[test]
    fn an_unsolicited_upgrade_is_an_error() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x02ok";
        let result = read_response(&mut Cursor::new(response), false, None);

        assert!(matches!(
            result,
            Err(Error::Response(ResponseError::UnsolicitedUpgrade))
        ));
    }

    #[test]
    fn a_disconnect_inside_the_body_truncates_the_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, Some(TruncatedType::Disconnect));
    }

    #[test]
    fn the_length_bound_cuts_the_body_and_declares_the_reason() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (recorded, truncated) = read_all(response, false, Some(40));

        assert_eq!(recorded, &response[..40]);
        assert_eq!(truncated, Some(TruncatedType::Length));
    }

    #[test]
    fn an_exact_length_bound_marks_each_incomplete_framing() {
        let length = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcdefghij";
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nabcdefghij\r\n0\r\n\r\n";
        let close = b"HTTP/1.1 200 OK\r\n\r\nabcdefghij";

        for (response, cap) in [
            (length.as_slice(), length.len() - 5),
            (chunked.as_slice(), chunked.len() - 10),
            (close.as_slice(), close.len() - 5),
        ] {
            let (recorded, truncated) = read_at_cap(response, cap);
            assert_eq!(recorded, &response[..cap]);
            assert_eq!(truncated, Some(TruncatedType::Length));
        }
    }

    #[test]
    fn close_delimited_eof_exactly_at_the_bound_is_complete() {
        let response = b"HTTP/1.1 200 OK\r\n\r\ncomplete";
        let (recorded, truncated) = read_all(response, false, Some(response.len() as u64));

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn a_header_section_over_the_length_bound_is_an_error() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let result = read_response(&mut Cursor::new(response), false, Some(10));

        assert!(matches!(
            result,
            Err(Error::Response(ResponseError::OversizedHeaderSection))
        ));
    }

    #[test]
    fn conflicting_content_lengths_are_an_error() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
        let result = read_response(&mut Cursor::new(response), false, None);

        assert!(matches!(
            result,
            Err(Error::Response(ResponseError::ConflictingContentLength))
        ));
    }

    #[test]
    fn repeated_identical_content_lengths_agree() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }

    #[test]
    fn a_malformed_chunk_size_is_an_error() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n";
        let result = read_response(&mut Cursor::new(response), false, None);

        assert!(matches!(
            result,
            Err(Error::Response(ResponseError::MalformedChunkSize(size))) if size == "xyz"
        ));
    }

    #[test]
    fn a_missing_status_line_is_an_error() {
        let response = b"ICY 200 OK\r\n\r\n";
        let result = read_response(&mut Cursor::new(response), false, None);

        assert!(matches!(
            result,
            Err(Error::Response(ResponseError::MalformedStatusLine))
        ));
    }

    #[test]
    fn a_close_before_the_header_section_completes_is_an_error() {
        let response = b"HTTP/1.1 200 OK\r\nContent-";
        let result = read_response(&mut Cursor::new(response), false, None);

        assert!(matches!(
            result,
            Err(Error::Response(ResponseError::IncompleteHeaderSection))
        ));
    }

    #[test]
    fn folded_header_lines_join_before_framing_is_read() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length:\r\n 5\r\n\r\nhello";
        let (recorded, truncated) = read_all(response, false, None);

        assert_eq!(recorded, response);
        assert_eq!(truncated, None);
    }
}
