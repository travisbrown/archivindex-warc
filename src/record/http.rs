//! HTTP message reconstruction for `application/http` blocks.
//!
//! These functions rebuild HTTP/1.1 messages for clients that expose parsed parts but not the
//! serialized message. Reconstruction uses the [`http`] crate's lowercased header names and the
//! status code's canonical reason phrase; providing a body also rewrites its framing. Its block
//! digest therefore does not verify the bytes sent by the origin.
//!
//! A provided body is framed by `content-length` after any `Transfer-Encoding` is removed. Reading
//! the block with [`payload::entity_body`](crate::record::payload::entity_body) recovers that body.

use http::{HeaderMap, Method, StatusCode, Uri, Version};

use crate::parsing::{is_lws, is_token, next_line};

/// Parsed fields and boundaries of a recorded HTTP response message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseMetadata {
    /// Final HTTP response status.
    pub status: u16,
    /// Offset at which the recorded message body begins.
    pub body_offset: usize,
    headers: Fields,
}

impl ResponseMetadata {
    /// Parse a complete HTTP response header section.
    #[must_use]
    pub fn parse(response: &[u8]) -> Option<Self> {
        let head = parse_head(response)?;
        let mut parts = head.start_line.splitn(3, |&byte| byte == b' ');
        let version = parts.next()?;
        let code = parts.next()?;
        if !version.starts_with(b"HTTP/") || code.len() != 3 || !code.iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let status = code
            .iter()
            .fold(0, |value, &byte| value * 10 + u16::from(byte - b'0'));

        Some(Self {
            status,
            body_offset: head.body_offset,
            headers: head.headers,
        })
    }

    /// Return the first response header value, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_value(&self.headers, name)
    }

    /// Return every response header value with this name, in the order received.
    ///
    /// A field may be sent as several lines; a recipient combining them into one value separates
    /// them with a comma (RFC 9110 section 5.3). `Vary` in particular is often split this way.
    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        header_values(&self.headers, name)
    }
}

/// Parsed fields and boundaries of a recorded HTTP request message.
///
/// A `Vary` response names the request fields that selected the representation, so reading them
/// back from the recorded request is what makes a stored response reusable for a later request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestMetadata {
    /// Offset at which the recorded message body begins.
    pub body_offset: usize,
    method: String,
    target: Vec<u8>,
    headers: Fields,
}

impl RequestMetadata {
    /// Parse a complete HTTP request header section.
    ///
    /// The method must be a token and the request line must end in an `HTTP/` version, which
    /// rejects a target containing the space that would split it.
    #[must_use]
    pub fn parse(request: &[u8]) -> Option<Self> {
        let head = parse_head(request)?;
        let mut parts = head.start_line.splitn(3, |&byte| byte == b' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if !is_token(method) || target.is_empty() || !version.starts_with(b"HTTP/") {
            return None;
        }

        Some(Self {
            body_offset: head.body_offset,
            // A token is ASCII by definition, so this cannot fail after the check above.
            method: std::str::from_utf8(method).ok()?.to_owned(),
            target: target.to_vec(),
            headers: head.headers,
        })
    }

    /// Return the request method, as it was sent.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the request target, as it was sent.
    ///
    /// RFC 9112 confines a request target to ASCII, but a recorded request may carry raw octets
    /// that a client sent unencoded, so this is exposed as bytes rather than as text.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.target
    }

    /// Return the first request header value, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_value(&self.headers, name)
    }

    /// Return every request header value with this name, in the order received.
    ///
    /// Matching a request against a `Vary` field uses the comma-joined value of its lines.
    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        header_values(&self.headers, name)
    }
}

/// The field lines of a message head, in the order received, with their names as sent.
type Fields = Vec<(String, Vec<u8>)>;

/// A parsed header section, less the start line, which each message form reads for itself.
struct Head<'a> {
    start_line: &'a [u8],
    body_offset: usize,
    headers: Fields,
}

/// Split a header section into its start line, its body offset, and its unfolded field lines.
///
/// Line endings are read as they are elsewhere in this crate, so a bare `LF` terminates a line,
/// which is what RFC 9112 section 2.2 asks of a recipient.
///
/// Returns `None` when the section is unterminated or a field line has no name.
fn parse_head(message: &[u8]) -> Option<Head<'_>> {
    let start_line = next_line(message, 0)?;
    let mut offset = start_line.next;
    let mut headers = Fields::new();

    loop {
        let line = next_line(message, offset)?;
        let content = &message[offset..line.end];
        offset = line.next;

        if content.is_empty() {
            return Some(Head {
                start_line: &message[..start_line.end],
                body_offset: offset,
                headers,
            });
        }

        if content.first().copied().is_some_and(is_lws) {
            let (_, value) = headers.last_mut()?;
            value.push(b' ');
            value.extend_from_slice(trim_ascii(content));
            continue;
        }

        let colon = content.iter().position(|&byte| byte == b':')?;
        let name = std::str::from_utf8(&content[..colon]).ok()?.to_owned();
        headers.push((name, trim_ascii(&content[colon + 1..]).to_vec()));
    }
}

fn header_values<'h, 'n>(
    headers: &'h [(String, Vec<u8>)],
    name: &'n str,
) -> impl Iterator<Item = &'h [u8]> + use<'h, 'n> {
    headers
        .iter()
        .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

/// The first value with this name, borrowed from `headers` alone so a caller may pass a temporary.
fn header_value<'h>(headers: &'h [(String, Vec<u8>)], name: &str) -> Option<&'h [u8]> {
    header_values(headers, name).next()
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

/// Errors returned while reconstructing an HTTP message.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A non-empty body was provided for a status that forbids one.
    #[error("A {0} response cannot carry a body.")]
    BodyForbidden(StatusCode),
}

/// Reconstruct an HTTP/1.1 response block from parsed message parts.
///
/// With `body` set to `None`, framing headers are preserved (for example, for a response to a
/// `HEAD` request). A provided body must have transfer coding removed. Reconstruction removes
/// `Transfer-Encoding` and writes its length unless a lone `Content-Length` already matches.
///
/// Informational, `204`, and `304` responses cannot contain a body. Their headers are preserved;
/// in particular, a `304` may describe the selected representation with `Content-Length`.
///
/// HTTP/2 and later have no HTTP/1.1 wire form, so their parts use the `HTTP/1.1` version token.
///
/// # Errors
///
/// Returns [`Error::BodyForbidden`] if the status forbids a non-empty body.
pub fn reconstruct_response(
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let body = match body {
        Some(body) if forbids_body(status) => {
            if body.is_empty() {
                None
            } else {
                return Err(Error::BodyForbidden(status));
            }
        }
        body => body,
    };

    let reason = status.canonical_reason().unwrap_or_default();
    let mut message = Vec::with_capacity(16 + reason.len() + header_capacity(headers, body));

    message.extend_from_slice(version_token(version).as_bytes());
    message.push(b' ');
    message.extend_from_slice(status.as_str().as_bytes());
    // The space is mandatory even when no reason phrase follows it (RFC 9112 section 4).
    message.push(b' ');
    message.extend_from_slice(reason.as_bytes());
    message.extend_from_slice(b"\r\n");

    write_headers_and_body(&mut message, headers, body);

    Ok(message)
}

/// Reconstruct an HTTP/1.1 request block from parsed message parts.
///
/// The target is written in origin-form; `headers` must therefore contain the authority in
/// `Host`. With `body` set to `None`, headers are preserved. For a provided body,
/// `Transfer-Encoding` is removed and the length is written unless a lone `Content-Length`
/// already matches.
///
/// HTTP/2 and later have no HTTP/1.1 wire form, so their parts use the `HTTP/1.1` version token.
pub fn reconstruct_request(
    method: &Method,
    target: &Uri,
    version: Version,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let target = target
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let mut message = Vec::with_capacity(
        method.as_str().len() + target.len() + 12 + header_capacity(headers, body),
    );

    message.extend_from_slice(method.as_str().as_bytes());
    message.push(b' ');
    message.extend_from_slice(target.as_bytes());
    message.push(b' ');
    message.extend_from_slice(version_token(version).as_bytes());
    message.extend_from_slice(b"\r\n");

    write_headers_and_body(&mut message, headers, body);

    message
}

fn forbids_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

const fn version_token(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    }
}

fn header_capacity(headers: &HeaderMap, body: Option<&[u8]>) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum::<usize>()
        + body.map_or(0, |body| body.len() + 24)
        + 2
}

fn framing_matches(headers: &HeaderMap, body: &[u8]) -> bool {
    let mut lengths = headers.get_all(http::header::CONTENT_LENGTH).iter();

    matches!(
        (lengths.next(), lengths.next()),
        (Some(value), None)
            if value
                .to_str()
                .is_ok_and(|value| value.trim().parse() == Ok(body.len() as u64))
    )
}

fn write_headers_and_body(message: &mut Vec<u8>, headers: &HeaderMap, body: Option<&[u8]>) {
    let keep_length = body.is_none_or(|body| framing_matches(headers, body));

    for (name, value) in headers {
        if body.is_some()
            && (name == http::header::TRANSFER_ENCODING
                || (name == http::header::CONTENT_LENGTH && !keep_length))
        {
            continue;
        }

        message.extend_from_slice(name.as_str().as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(value.as_bytes());
        message.extend_from_slice(b"\r\n");
    }

    if let Some(body) = body {
        if !keep_length {
            message.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
        }

        message.extend_from_slice(b"\r\n");
        message.extend_from_slice(body);
    } else {
        message.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use http::header::{HeaderName, HeaderValue};
    use http::{HeaderMap, Method, StatusCode, Uri, Version};

    use super::{
        Error, RequestMetadata, ResponseMetadata, reconstruct_request, reconstruct_response,
    };

    #[test]
    fn response_metadata_preserves_boundaries_and_header_values() {
        let response = b"HTTP/1.1 206 Partial Content\r\nX-Test: first\r\nx-test: second\r\nX-Binary: \xff\r\n\r\nbody";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(metadata.status, 206);
        assert_eq!(&response[metadata.body_offset..], b"body");
        assert_eq!(metadata.header("X-TEST"), Some(b"first".as_slice()));
        assert_eq!(metadata.header("x-binary"), Some(b"\xff".as_slice()));
    }

    #[test]
    fn response_metadata_unfolds_continuation_lines() {
        let response = b"HTTP/1.0 200 OK\r\nX-Test: one\r\n\ttwo\r\n three\r\n\r\n";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(metadata.header("x-test"), Some(b"one two three".as_slice()));
    }

    /// The head is framed as `payload::entity_body` frames it, bare `LF` included.
    #[test]
    fn response_metadata_reads_lines_ended_with_a_bare_line_feed() {
        let response = b"HTTP/1.1 200 OK\nContent-Type: text/html\r\n\r\nhi";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(metadata.status, 200);
        assert_eq!(
            metadata.header("content-type"),
            Some(b"text/html".as_slice())
        );
        assert_eq!(
            &response[metadata.body_offset..],
            crate::record::payload::entity_body(response)
                .unwrap()
                .as_ref()
        );
    }

    #[test]
    fn response_metadata_rejects_incomplete_or_malformed_messages() {
        assert!(ResponseMetadata::parse(b"HTTP/1.1 200 OK\r\nX: y\r\n").is_none());
        assert!(ResponseMetadata::parse(b"not HTTP\r\n\r\n").is_none());
        assert!(ResponseMetadata::parse(b"HTTP/1.1 20 OK\r\n\r\n").is_none());
    }

    /// Repeated fields are returned in receive order.
    #[test]
    fn repeated_response_headers_are_returned_in_order() {
        let response = b"HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\nvary: User-Agent\r\n\r\n";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(
            metadata.headers("vary").collect::<Vec<_>>(),
            [b"Accept-Encoding".as_slice(), b"User-Agent".as_slice()]
        );
        assert_eq!(metadata.headers("etag").next(), None);
    }

    #[test]
    fn request_metadata_preserves_boundaries_and_header_values() {
        let request = b"POST /submit?q=1 HTTP/1.1\r\nHost: example.com\r\n\
                        Content-Length: 4\r\nX-Binary: \xff\r\n\r\nbody";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(metadata.method(), "POST");
        assert_eq!(metadata.target(), b"/submit?q=1");
        assert_eq!(&request[metadata.body_offset..], b"body");
        assert_eq!(metadata.header("HOST"), Some(b"example.com".as_slice()));
        assert_eq!(metadata.header("x-binary"), Some(b"\xff".as_slice()));
        assert_eq!(metadata.header("accept"), None);
    }

    /// Request metadata exposes every field used to select a representation.
    #[test]
    fn request_metadata_reads_the_fields_that_select_a_representation() {
        let request = b"GET / HTTP/1.1\r\nUser-Agent: MobileBot/1.0\r\n\
                        Accept-Encoding: gzip\r\naccept-encoding: br\r\n\r\n";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(
            metadata.header("user-agent"),
            Some(b"MobileBot/1.0".as_slice())
        );
        assert_eq!(
            metadata.headers("Accept-Encoding").collect::<Vec<_>>(),
            [b"gzip".as_slice(), b"br".as_slice()]
        );
    }

    #[test]
    fn request_metadata_unfolds_continuation_lines() {
        let request = b"GET / HTTP/1.1\r\nX-Test: one\r\n\ttwo\r\n three\r\n\r\n";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(metadata.header("x-test"), Some(b"one two three".as_slice()));
    }

    /// Origin, absolute, authority, and asterisk targets are accepted.
    #[test]
    fn request_metadata_accepts_every_request_target_form() {
        let targets: [&[u8]; 4] = [
            b"/origin",
            b"http://example.com/absolute",
            b"example.com:443",
            b"*",
        ];

        for target in targets {
            let mut request = b"GET ".to_vec();
            request.extend_from_slice(target);
            request.extend_from_slice(b" HTTP/1.1\r\n\r\n");
            let metadata = RequestMetadata::parse(&request).unwrap();

            assert_eq!(metadata.target(), target);
        }
    }

    #[test]
    fn request_metadata_rejects_incomplete_or_malformed_messages() {
        // No terminating blank line.
        assert!(RequestMetadata::parse(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
        // A response, which the recorded block of a request record must not be.
        assert!(RequestMetadata::parse(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
        // No version.
        assert!(RequestMetadata::parse(b"GET /\r\n\r\n").is_none());
        // A space in the target splits the request line.
        assert!(RequestMetadata::parse(b"GET /a b HTTP/1.1\r\n\r\n").is_none());
        // A method that is not a token.
        assert!(RequestMetadata::parse(b"GE(T / HTTP/1.1\r\n\r\n").is_none());
        assert!(RequestMetadata::parse(b" / HTTP/1.1\r\n\r\n").is_none());
        // A field line without a name.
        assert!(RequestMetadata::parse(b"GET / HTTP/1.1\r\nnocolon\r\n\r\n").is_none());
    }

    fn headers(lines: &[(&'static str, &'static str)]) -> HeaderMap {
        lines
            .iter()
            .map(|(name, value)| {
                (
                    HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                )
            })
            .collect()
    }

    /// A recorded body replaces transfer coding with length framing.
    #[test]
    fn response_with_a_body_rewrites_its_framing() {
        let message = reconstruct_response(
            Version::HTTP_11,
            StatusCode::OK,
            &headers(&[
                ("content-type", "text/plain"),
                ("transfer-encoding", "chunked"),
                ("content-length", "999"),
            ]),
            Some(b"hello world!"),
        )
        .unwrap();

        assert_eq!(
            message,
            b"HTTP/1.1 200 OK\r\n\
              content-type: text/plain\r\n\
              content-length: 12\r\n\
              \r\n\
              hello world!"
        );
    }

    /// The status line retains its required space when no reason phrase is available.
    #[test]
    fn status_line_keeps_its_space_without_a_reason_phrase() {
        let message = reconstruct_response(
            Version::HTTP_11,
            StatusCode::from_u16(520).unwrap(),
            &HeaderMap::new(),
            Some(b"?"),
        )
        .unwrap();

        assert_eq!(message, b"HTTP/1.1 520 \r\ncontent-length: 1\r\n\r\n?");
    }

    /// A bodyless status preserves headers that describe the selected representation.
    #[test]
    fn bodiless_status_preserves_its_headers() {
        for body in [None, Some(&b""[..])] {
            let message = reconstruct_response(
                Version::HTTP_11,
                StatusCode::NOT_MODIFIED,
                &headers(&[("content-length", "1234"), ("etag", "\"abc\"")]),
                body,
            )
            .unwrap();

            assert_eq!(
                message,
                b"HTTP/1.1 304 Not Modified\r\n\
                  content-length: 1234\r\n\
                  etag: \"abc\"\r\n\
                  \r\n"
            );
        }
    }

    /// A bodyless status rejects a non-empty body.
    #[test]
    fn bodiless_status_refuses_a_body() {
        let error = reconstruct_response(
            Version::HTTP_11,
            StatusCode::NO_CONTENT,
            &HeaderMap::new(),
            Some(b"x"),
        )
        .unwrap_err();

        assert_eq!(error, Error::BodyForbidden(StatusCode::NO_CONTENT));
        assert_eq!(
            error.to_string(),
            "A 204 No Content response cannot carry a body."
        );
    }

    /// An absent body preserves framing headers.
    #[test]
    fn absent_body_preserves_framing_headers() {
        let message = reconstruct_response(
            Version::HTTP_11,
            StatusCode::OK,
            &headers(&[("content-length", "5")]),
            None,
        )
        .unwrap();

        assert_eq!(message, b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n");
    }

    /// Versions without an HTTP/1.1 wire form are written with the `HTTP/1.1` token.
    #[test]
    fn version_tokens() {
        for (version, expected) in [
            (Version::HTTP_09, &b"HTTP/0.9 200 OK\r\n\r\n"[..]),
            (Version::HTTP_10, b"HTTP/1.0 200 OK\r\n\r\n"),
            (Version::HTTP_11, b"HTTP/1.1 200 OK\r\n\r\n"),
            (Version::HTTP_2, b"HTTP/1.1 200 OK\r\n\r\n"),
            (Version::HTTP_3, b"HTTP/1.1 200 OK\r\n\r\n"),
        ] {
            let message =
                reconstruct_response(version, StatusCode::OK, &HeaderMap::new(), None).unwrap();

            assert_eq!(message, expected, "{version:?}");
        }
    }

    /// Entity-body extraction recovers the recorded body.
    #[test]
    fn entity_body_reads_back_the_recorded_body() {
        let body: &[u8] = b"the recorded body";
        let message = reconstruct_response(
            Version::HTTP_11,
            StatusCode::OK,
            &headers(&[("transfer-encoding", "chunked")]),
            Some(body),
        )
        .unwrap();

        assert_eq!(
            crate::record::payload::entity_body(&message)
                .unwrap()
                .as_ref(),
            body
        );
    }

    /// Origin-form retains the query and leaves the authority in `Host`.
    #[test]
    fn request_target_is_written_in_origin_form() {
        let target: Uri = "http://example.com/a/b?q=1".parse().unwrap();
        let message = reconstruct_request(
            &Method::GET,
            &target,
            Version::HTTP_11,
            &headers(&[("host", "example.com")]),
            None,
        );

        assert_eq!(
            message,
            b"GET /a/b?q=1 HTTP/1.1\r\nhost: example.com\r\n\r\n"
        );
    }

    /// A target with no path names the root resource.
    #[test]
    fn request_target_defaults_to_the_root() {
        let target: Uri = "http://example.com".parse().unwrap();
        let message = reconstruct_request(
            &Method::GET,
            &target,
            Version::HTTP_11,
            &HeaderMap::new(),
            None,
        );

        assert_eq!(message, b"GET / HTTP/1.1\r\n\r\n");
    }

    /// A matching `Content-Length` remains in place.
    #[test]
    fn matching_content_length_is_kept_in_place() {
        let message = reconstruct_response(
            Version::HTTP_11,
            StatusCode::OK,
            &headers(&[("content-length", "5"), ("server", "test")]),
            Some(b"hello"),
        )
        .unwrap();

        assert_eq!(
            message,
            b"HTTP/1.1 200 OK\r\n\
              content-length: 5\r\n\
              server: test\r\n\
              \r\n\
              hello"
        );
    }

    /// A recorded request body is framed by its length, like a response body.
    #[test]
    fn request_with_a_body_rewrites_its_framing() {
        let target: Uri = "/submit".parse().unwrap();
        let message = reconstruct_request(
            &Method::POST,
            &target,
            Version::HTTP_11,
            &headers(&[("host", "example.com"), ("transfer-encoding", "chunked")]),
            Some(b"hello"),
        );

        assert_eq!(
            message,
            b"POST /submit HTTP/1.1\r\n\
              host: example.com\r\n\
              content-length: 5\r\n\
              \r\n\
              hello"
        );
    }
}
