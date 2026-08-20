//! Byte-exact capture of live HTTP exchanges.
//!
//! [`Recorder`] performs an HTTP/1.1 exchange over its own connection and returns the exact request
//! and response bytes in [`CapturedExchange`]. It serializes the request itself and stores the
//! response verbatim, parsing only enough to find the message boundary. This preserves chunked
//! coding, header spelling, and the reason phrase, so block digests cover bytes that crossed the
//! wire. To archive an exchange performed by another client, use
//! [`record::http`](crate::record::http) to reconstruct blocks from parsed parts.
//!
//! Each fetch opens one connection for one request and response. It does not follow redirects,
//! decode content, or reuse the connection. It adds `host` when absent and defaults a missing
//! `connection` header to `close`. Interim (`1xx`) responses are discarded. An unframed response,
//! or one whose final transfer coding is not `chunked`, ends when the connection closes.
//!
//! [`max_response_length`](Recorder::max_response_length) bounds stored response bytes. A limit,
//! disconnect, or I/O timeout truncates the response instead of failing the fetch; the reason is
//! available in [`CapturedExchange::truncated`]. Without a bound, response size is unlimited.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fluent_uri::Uri;
use http::{HeaderMap, HeaderValue, Method, Version, header};
/// The TLS API used by [`Recorder`], re-exported for building a custom
/// [`ClientConfig`](rustls::ClientConfig).
pub use rustls;
use rustls::pki_types::ServerName;

use crate::record::capture::CaptureEvent;
use crate::record::header::truncated_type::TruncatedType;
use crate::record::http::{ResponseMetadata, reconstruct_request};

const MAX_HEADER_LENGTH: usize = 64 * 1024;

const READ_LENGTH: usize = 8 * 1024;

/// Errors returned while performing a recorded exchange.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The target is not an absolute HTTP or HTTPS URI.
    #[error("The target URI must be absolute, with an `http` or `https` scheme.")]
    UnsupportedScheme,
    /// The target names no host.
    #[error("The target URI names no host.")]
    MissingHost,
    /// The target cannot be represented as a `WARC-Target-URI`.
    #[error("The target URI is not a URI: {0}")]
    TargetUri(#[from] fluent_uri::ParseError),
    /// The host cannot name a TLS server.
    #[error("The host cannot name a TLS server: {0}")]
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
    #[error("The response does not begin with an HTTP status line.")]
    MalformedStatusLine,
    /// The connection ended before a complete header section arrived.
    #[error("The connection ended before a complete response header section arrived.")]
    IncompleteHeaderSection,
    /// The header section exceeds the recorder's limit.
    #[error("The response header section is longer than the recorder accepts.")]
    OversizedHeaderSection,
    /// The response declares `Content-Length` values that disagree.
    #[error("The response declares `Content-Length` values that disagree.")]
    ConflictingContentLength,
    /// A declared `Content-Length` is not a valid decimal length.
    #[error("The declared `Content-Length` `{0}` is not a length.")]
    MalformedContentLength(String),
    /// A declared chunk size is not a valid hexadecimal length.
    #[error("The declared chunk size `{0}` is not a hexadecimal length.")]
    MalformedChunkSize(String),
    /// A chunk's data is not followed by the terminating CRLF.
    #[error("A chunk's data is not followed by CRLF.")]
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
    /// Create a recorder using `webpki-roots`, without timeouts or a response-size bound.
    #[must_use]
    pub fn new() -> Self {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        Self {
            tls: Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ),
            connect_timeout: None,
            io_timeout: None,
            max_response_length: None,
        }
    }

    /// Replace the TLS client configuration.
    #[must_use]
    pub fn tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls = config;

        self
    }

    /// Set the connection timeout for each resolved address.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);

        self
    }

    /// Set the timeout for each connection read or write.
    ///
    /// A read timeout after the header section truncates the response instead of failing.
    #[must_use]
    pub const fn io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = Some(timeout);

        self
    }

    /// Set the maximum stored response length, including the header section.
    ///
    /// Reaching the limit records a `length` truncation. A header section larger than the limit
    /// fails because it cannot be partially recorded.
    #[must_use]
    pub const fn max_response_length(mut self, length: u64) -> Self {
        self.max_response_length = Some(length);

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
    // The `http` crate has already validated the URI, including its use as a header value.
    #[allow(clippy::missing_panics_doc)]
    pub fn fetch(
        &self,
        method: &Method,
        target: &http::Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
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

        let stream = self.connect(host, port)?;
        let ip_address = stream.peer_addr()?.ip();
        stream.set_read_timeout(self.io_timeout)?;
        stream.set_write_timeout(self.io_timeout)?;

        let mut transport = if tls {
            let server_name = ServerName::try_from(host.to_owned())?;
            let connection = rustls::ClientConnection::new(Arc::clone(&self.tls), server_name)?;
            Transport::Tls(Box::new(rustls::StreamOwned::new(connection, stream)))
        } else {
            Transport::Plain(stream)
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
    fn connect(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        let Some(timeout) = self.connect_timeout else {
            return TcpStream::connect((host, port)).map_err(Error::Io);
        };

        let mut failure = None;
        for address in (host, port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&address, timeout) {
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
    pub fn entity_body(&self) -> Result<std::borrow::Cow<'_, [u8]>, crate::record::payload::Error> {
        crate::record::payload::entity_body(&self.response)
    }

    /// Return the recorded bytes after the response header section without transfer decoding.
    #[must_use]
    pub fn stored_body(&self) -> &[u8] {
        &self.response[self.response_metadata.body_offset..]
    }
}

enum Transport {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
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

    // Discard interim responses so the recording begins at the final status line.
    let (status, header_end) = loop {
        if let Some(header_end) = find_header_end(&buffer) {
            if header_end > header_bound {
                return Err(ResponseError::OversizedHeaderSection.into());
            }
            let status = parse_status(&buffer)?;
            if (100..200).contains(&status) {
                buffer.drain(..header_end);
                continue;
            }

            break (status, header_end);
        }
        if buffer.len() > header_bound {
            return Err(ResponseError::OversizedHeaderSection.into());
        }
        match fill(source, &mut buffer)? {
            ReadEvent::Data => {}
            ReadEvent::Closed | ReadEvent::TimedOut => {
                return Err(ResponseError::IncompleteHeaderSection.into());
            }
        }
    };

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
    use std::io::Cursor;

    use super::*;

    fn read_all(
        response: &[u8],
        head_request: bool,
        max_length: Option<u64>,
    ) -> (Vec<u8>, Option<TruncatedType>) {
        read_response(&mut Cursor::new(response), head_request, max_length).expect("a response")
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
