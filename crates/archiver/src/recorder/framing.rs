//! Message framing shared by every capture backend.
//!
//! [`ResponseCapture`] turns received bytes into the stored response of one exchange. It owns the
//! rules that decide where a response ends, when it is complete, and why it was cut short, so any
//! backend driving it records the same bytes as any other.

use std::io::{ErrorKind, Read};

use archivindex_warc::record::header::truncated_type::TruncatedType;

use super::{Error, ResponseError};

const MAX_HEADER_LENGTH: usize = 64 * 1024;

const READ_LENGTH: usize = 8 * 1024;

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

/// Incremental capture of one response's wire bytes, shared by every backend.
///
/// Feed it transport reads with [`push`](Self::push) and close it with [`end`](Self::end). The
/// final response is bounded by the configured cap. Interim headers have a separate 64 KiB bound
/// and are discarded, so every backend uses the same framing, truncation, and byte content.
pub struct ResponseCapture {
    buffer: Vec<u8>,
    head_request: bool,
    cap: Option<u64>,
    framing: Option<BodyFraming>,
    header_end: usize,
    scanner: Option<ChunkScanner>,
    done: bool,
    truncated: Option<TruncatedType>,
}

impl ResponseCapture {
    /// Start a capture.
    ///
    /// Set `head_request` when the request method was `HEAD`, so that a declared body length is
    /// not awaited. `cap` bounds retained wire bytes, including the header section.
    #[must_use]
    pub const fn new(head_request: bool, cap: Option<u64>) -> Self {
        Self {
            buffer: Vec::new(),
            head_request,
            cap,
            framing: None,
            header_end: 0,
            scanner: None,
            done: false,
            truncated: None,
        }
    }

    /// Whether the response is complete, capped, or truncated, so no further bytes are wanted.
    ///
    /// A backend should stop reading and dispose of its connection once this is true.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// Feed newly received bytes.
    ///
    /// Extra bytes beyond the cap provide length evidence but are never stored. Interim heads
    /// have their own bound and do not consume the final cap. Bytes offered after the capture is
    /// done are ignored.
    ///
    /// # Errors
    ///
    /// Fails when the response cannot be framed, including an oversized or malformed header
    /// section and malformed chunk framing.
    ///
    /// # Panics
    ///
    /// Panics only if a message boundary already inside the buffer does not fit in a `usize`,
    /// which the cap and the buffer's own length make impossible.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), ResponseError> {
        while self.framing.is_none() && !bytes.is_empty() && !self.done {
            if self.buffer.len() >= MAX_HEADER_LENGTH {
                return Err(ResponseError::OversizedHeaderSection);
            }
            // A head can end only at LF. Copy a line fragment at a time, retaining the suffix
            // across transport reads so split delimiters and coalesced interim heads work alike.
            if let [byte] = bytes {
                self.buffer.push(*byte);
                bytes = &[];
            } else {
                let length = bytes
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |index| index + 1)
                    .min(MAX_HEADER_LENGTH - self.buffer.len());
                self.buffer.extend_from_slice(&bytes[..length]);
                bytes = &bytes[length..];
            }
            if !self.buffer.ends_with(b"\r\n\r\n") {
                continue;
            }
            let status = parse_status(&self.buffer)?;
            if status == 101 {
                return Err(ResponseError::UnsolicitedUpgrade);
            }
            if (100..200).contains(&status) {
                self.buffer.clear();
                continue;
            }
            if self.cap.is_some_and(|cap| self.buffer.len() as u64 > cap) {
                return Err(ResponseError::OversizedHeaderSection);
            }
            self.header_end = self.buffer.len();
            self.framing = Some(body_framing(&self.buffer, self.head_request, status)?);
            if matches!(self.framing, Some(BodyFraming::Chunked)) {
                self.scanner = Some(ChunkScanner::new(self.header_end));
            }
        }
        if self.done || self.framing.is_none() {
            return Ok(());
        }
        let room = self
            .cap
            .unwrap_or(u64::MAX)
            .saturating_sub(self.buffer.len() as u64);
        let remaining = match self.framing {
            Some(BodyFraming::None) => 0,
            Some(BodyFraming::Length(length)) => length
                .saturating_sub((self.buffer.len() - self.header_end) as u64)
                .min(room),
            _ => room,
        };
        let kept = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.buffer.extend_from_slice(&bytes[..kept]);
        let overflow = kept < bytes.len();
        match self.framing {
            Some(BodyFraming::None) => {
                self.buffer.truncate(self.header_end);
                self.done = true;
            }
            Some(BodyFraming::Length(length)) => {
                let end = (self.header_end as u64).saturating_add(length);
                if self.buffer.len() as u64 >= end {
                    self.buffer
                        .truncate(usize::try_from(end).expect("a buffered boundary"));
                    self.done = true;
                } else if self.at_cap() {
                    self.finish(Some(TruncatedType::Length));
                }
            }
            Some(BodyFraming::Chunked) => {
                if let Some(end) = self
                    .scanner
                    .as_mut()
                    .expect("a chunk scanner")
                    .advance(&self.buffer)?
                {
                    self.buffer.truncate(end);
                    self.done = true;
                } else if overflow {
                    self.finish(Some(TruncatedType::Length));
                }
            }
            Some(BodyFraming::Close) if overflow => self.finish(Some(TruncatedType::Length)),
            Some(BodyFraming::Close) | None => {}
        }
        Ok(())
    }

    fn finish(&mut self, truncated: Option<TruncatedType>) {
        self.done = true;
        self.truncated = truncated;
    }

    fn at_cap(&self) -> bool {
        self.cap.is_some_and(|cap| self.buffer.len() as u64 >= cap)
    }

    /// Close the capture because the transport ended or ran out of time.
    ///
    /// A close-delimited response ends complete; any other unfinished response is truncated,
    /// with a reason of `time` when `timed_out` and `disconnect` otherwise. Calling this on a
    /// capture that is already done changes nothing.
    ///
    /// # Errors
    ///
    /// Fails when no complete response header section was ever received.
    pub fn end(&mut self, timed_out: bool) -> Result<(), ResponseError> {
        if self.done {
            return Ok(());
        }
        if self.framing.is_none() {
            return Err(ResponseError::IncompleteHeaderSection);
        }
        self.finish(if timed_out {
            Some(TruncatedType::Time)
        } else if matches!(self.framing, Some(BodyFraming::Close)) {
            None
        } else {
            Some(TruncatedType::Disconnect)
        });
        Ok(())
    }

    /// Take the retained response bytes and the reason they were truncated, if any.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Option<TruncatedType>) {
        (self.buffer, self.truncated)
    }
}

enum ReadEvent {
    /// Number of bytes read into the supplied buffer.
    Data(usize),
    /// The connection closed, cleanly or not.
    Closed,
    /// The read timed out.
    TimedOut,
}

/// Read once into the transport buffer.
///
/// Rustls reports a close without `close_notify` as `UnexpectedEof`; treat it as a disconnect and
/// retain the bytes received so far.
fn fill(source: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<ReadEvent> {
    loop {
        return match source.read(buffer) {
            Ok(0) => Ok(ReadEvent::Closed),
            Ok(read) => Ok(ReadEvent::Data(read)),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(ReadEvent::Closed),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(ReadEvent::TimedOut)
            }
            Err(error) => Err(error),
        };
    }
}

/// Read one response verbatim using the same incremental parser as connection observers.
pub fn read_response(
    source: &mut impl Read,
    head_request: bool,
    max_length: Option<u64>,
) -> Result<(Vec<u8>, Option<TruncatedType>), Error> {
    let mut capture = ResponseCapture::new(head_request, max_length);
    let mut bytes = [0; READ_LENGTH];
    while !capture.is_done() {
        match fill(source, &mut bytes)? {
            ReadEvent::Data(read) => capture.push(&bytes[..read])?,
            ReadEvent::Closed => capture.end(false)?,
            ReadEvent::TimedOut => capture.end(true)?,
        }
    }
    Ok(capture.into_parts())
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
                let token = token.trim_matches([' ', '\t']);
                if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ResponseError::MalformedContentLength(token.to_owned()));
                }
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
    /// First byte that can still begin a CRLF in the current incomplete line.
    line_search: usize,
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
            line_search: offset,
            stage: ChunkStage::Size,
        }
    }

    /// Search only new bytes, retaining one byte for a CRLF split across reads.
    fn line_end(&mut self, buffer: &[u8]) -> Option<usize> {
        let start = self.line_search.max(self.offset);
        if let Some(relative) = find_crlf(&buffer[start..]) {
            let end = start + relative;
            self.line_search = end + 2;
            Some(end)
        } else {
            self.line_search = buffer.len().saturating_sub(1);
            None
        }
    }

    /// Scan available bytes and return the message end when complete.
    fn advance(&mut self, buffer: &[u8]) -> Result<Option<usize>, ResponseError> {
        loop {
            match self.stage {
                ChunkStage::Size => {
                    let Some(line_end) = self.line_end(buffer) else {
                        return Ok(None);
                    };
                    let line = &buffer[self.offset..line_end];
                    let size_text = line
                        .split(|&byte| byte == b';')
                        .next()
                        .unwrap_or(line)
                        .trim_ascii();
                    let size = parse_chunk_size(size_text)?;
                    self.offset = line_end + 2;
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
                    let Some(line_end) = self.line_end(buffer) else {
                        return Ok(None);
                    };
                    let empty = line_end == self.offset;
                    self.offset = line_end + 2;
                    if empty {
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
    fn every_chunked_split_and_wire_cap_preserves_the_same_prefix() {
        let response = b"HTTP/1.1 200 Odd\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=yes\r\na\0b\r\n2\r\ncd\r\n0\r\nX-End: yes\r\n\r\n";
        let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        for split in 0..=response.len() {
            for cap in head_end..=response.len() {
                let mut capture = ResponseCapture::new(false, Some(cap as u64));
                capture.push(&response[..split]).unwrap();
                capture.push(&response[split..]).unwrap();
                assert!(capture.is_done(), "split={split}, cap={cap}");
                let (bytes, truncated) = capture.into_parts();
                assert_eq!(bytes, response[..cap], "split={split}, cap={cap}");
                assert_eq!(
                    truncated,
                    (cap < response.len()).then_some(TruncatedType::Length)
                );
            }
        }
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

    #[test]
    fn interim_headers_do_not_consume_the_final_response_limit() {
        let final_response = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut response = format!(
            "HTTP/1.1 103 Early Hints\r\nLink: {}\r\n\r\n",
            "x".repeat(128)
        )
        .into_bytes();
        response.extend_from_slice(final_response);
        for chunk_size in [1, 7, response.len()] {
            let mut capture = ResponseCapture::new(false, Some(final_response.len() as u64));
            for chunk in response.chunks(chunk_size) {
                capture.push(chunk).unwrap();
            }
            assert!(capture.is_done());
            assert_eq!(capture.into_parts(), (final_response.to_vec(), None));
        }
    }

    #[test]
    fn content_lengths_require_ascii_decimal_digits() {
        for value in ["+5", "-5", "", "1e1", "\u{a0}5", "5\u{a0}"] {
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\nhello");
            assert!(
                matches!(
                    read_response(&mut response.as_bytes(), false, None),
                    Err(Error::Response(ResponseError::MalformedContentLength(_)))
                ),
                "{value:?}"
            );
        }
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: \t005 \t\r\n\r\nhello";
        assert_eq!(read_all(response, false, None), (response.to_vec(), None));
    }

    #[test]
    fn every_header_split_keeps_only_the_final_message() {
        for message in [
            b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
        ] {
            let mut wire = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n".to_vec();
            wire.extend_from_slice(message);
            wire.extend_from_slice(b"not part of the response");
            for split in 0..=wire.len() {
                let mut capture = ResponseCapture::new(false, None);
                capture.push(&wire[..split]).unwrap();
                capture.push(&wire[split..]).unwrap();
                assert!(capture.is_done());
                assert_eq!(capture.into_parts(), (message.to_vec(), None));
            }
        }
    }

    #[test]
    fn long_chunk_extensions_and_trailers_survive_fragmented_reads() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;name={}\r\nbody\r\n0\r\nX-Trailer: {}\r\n\r\n",
            "a".repeat(24 * 1024),
            "b".repeat(24 * 1024)
        );
        for chunk_size in [1, 3, 16, 8192] {
            let mut capture = ResponseCapture::new(false, None);
            for chunk in response.as_bytes().chunks(chunk_size) {
                capture.push(chunk).unwrap();
            }
            assert!(capture.is_done());
            assert_eq!(capture.into_parts(), (response.as_bytes().to_vec(), None));
        }
    }
}
