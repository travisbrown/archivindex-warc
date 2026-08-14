use crate::parser;
use crate::{BufferedBody, EmptyBody, Error, MB, RawRecordHeader, Record, StreamingBody};

use crate::header::WarcHeader;

use indexmap::IndexMap;

use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[cfg(feature = "gzip")]
use libflate::gzip::MultiDecoder as GzipReader;

/// A reader which iteratively parses WARC records from a stream.
pub struct WarcReader<R> {
    reader: R,
}

impl<R: BufRead> WarcReader<R> {
    /// Create a new reader.
    pub const fn new(r: R) -> Self {
        Self { reader: r }
    }

    /// Create an iterator over all of the raw records read.
    ///
    /// This only does well-formedness checks on the headers. See `RawRecordHeader` for more
    /// information.
    pub fn iter_raw_records(self) -> RawRecordIter<R> {
        RawRecordIter::new(self.reader)
    }

    /// Create an iterator over all of the records read.
    ///
    /// This will fully build each record and check it for semantic correctness. See the `Record`
    /// type for more information.
    pub fn iter_records(self) -> RecordIter<R> {
        RecordIter::new(self.reader)
    }

    /// Create a streaming iterator over all of the records read.
    ///
    /// This will build each record header, and allow the caller to decide whether to read
    /// the body or not.
    pub const fn stream_records(&mut self) -> StreamingIter<'_, R> {
        StreamingIter::new(&mut self.reader)
    }
}

impl WarcReader<BufReader<fs::File>> {
    /// Create a new reader which reads from file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(&path)?;

        let reader = BufReader::with_capacity(MB, file);

        Ok(Self::new(reader))
    }
}

#[cfg(feature = "gzip")]
impl WarcReader<BufReader<GzipReader<BufReader<fs::File>>>> {
    /// Create a new reader which reads from a compressed file.
    ///
    /// Only GZIP compression is currently supported.
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(&path)?;

        let gzip_stream = GzipReader::new(BufReader::with_capacity(MB, file))?;
        Ok(Self::new(BufReader::new(gzip_stream)))
    }
}

/// Collect parsed header lines into a header block and the values of the repeatable field.
///
/// The specification forbids repeating any named field except `WARC-Concurrent-To`, whose
/// values are all preserved in order of appearance.
///
/// # Errors
///
/// Returns `Error::DuplicateHeader` if any other named field appears more than once.
#[allow(clippy::type_complexity)]
fn collect_headers<'a>(
    parsed: Vec<(&'a str, std::borrow::Cow<'a, [u8]>)>,
) -> Result<(IndexMap<WarcHeader, Vec<u8>>, Vec<Vec<u8>>), Error> {
    let mut headers = IndexMap::with_capacity(parsed.len());
    let mut concurrent_to = Vec::new();

    for (token, value) in parsed {
        let header = WarcHeader::from(token);
        if header == WarcHeader::ConcurrentTo {
            concurrent_to.push(value.into_owned());
        } else {
            match headers.entry(header) {
                indexmap::map::Entry::Occupied(entry) => {
                    return Err(Error::DuplicateHeader(entry.key().clone()));
                }
                indexmap::map::Entry::Vacant(entry) => {
                    entry.insert(value.into_owned());
                }
            }
        }
    }

    Ok((headers, concurrent_to))
}

/// Check that a parsed header block was consumed in full.
///
/// `parser::headers` stops at the first line that does not match the named-field grammar, so a
/// remainder other than the blank line that terminates the block means such a line was present.
/// That line, and every line after it, would otherwise be silently dropped.
fn check_header_block_end(remainder: &[u8]) -> Result<(), Error> {
    if remainder == b"\r\n" {
        return Ok(());
    }

    let line_len = remainder
        .iter()
        .position(|&byte| byte == b'\r' || byte == b'\n')
        .unwrap_or(remainder.len());

    Err(Error::ParseHeaders(nom::Err::Error(
        nom::error::Error::new(
            remainder[..line_len].to_vec(),
            nom::error::ErrorKind::Verify,
        ),
    )))
}

/// Read lines up to and including the blank line that terminates a header block.
///
/// The header block is left in `header_buffer`, which is cleared first so callers can reuse
/// one buffer across records.
///
/// Returns `None` on a clean end-of-stream at a record boundary.
fn read_header_block<R: BufRead>(
    reader: &mut R,
    header_buffer: &mut Vec<u8>,
) -> Option<Result<(), Error>> {
    header_buffer.clear();
    loop {
        let bytes_read = match reader.read_until(b'\n', header_buffer) {
            Err(io) => return Some(Err(Error::ReadData(io))),
            Ok(len) => len,
        };

        if bytes_read == 0 {
            return None;
        }

        if bytes_read == 2 && header_buffer.ends_with(b"\r\n") {
            return Some(Ok(()));
        }
    }
}

/// Parse a raw header block into its headers and the expected body length.
///
/// A record without `Content-Length` cannot be framed: there is no way to know where its body
/// ends, so the missing field is reported rather than defaulted.
fn parse_header_block(buffer: &[u8]) -> Result<(RawRecordHeader, u64), Error> {
    let (remainder, (version, headers, expected_body_len)) =
        parser::headers(buffer).map_err(|e| {
            Error::ParseHeaders(
                e.map(|inner| nom::error::Error::new(inner.input.to_owned(), inner.code)),
            )
        })?;
    check_header_block_end(remainder)?;

    let expected_body_len =
        expected_body_len.ok_or(Error::MissingHeader(WarcHeader::ContentLength))?;

    let (headers, concurrent_to) = collect_headers(headers)?;
    let headers = RawRecordHeader {
        version: version.to_owned(),
        headers,
        concurrent_to,
    };

    Ok((headers, expected_body_len))
}

/// Read a record body of the given length, plus the `\r\n\r\n` record terminator.
fn read_body<R: BufRead>(reader: &mut R, expected_body_len: u64) -> Result<Vec<u8>, Error> {
    // The body plus its 4-byte terminator must fit in a single in-memory buffer. A length for
    // which that is impossible (a hostile value near the platform maximum, or a >4 GiB record
    // on a 32-bit target) is rejected up front, rather than overflowing the arithmetic below;
    // such records can still be read with `WarcReader::stream_records`.
    let expected_body_len = usize::try_from(expected_body_len).map_err(|_| Error::BodyTooLarge)?;
    let maximum_read_range = expected_body_len
        .checked_add(4)
        .ok_or(Error::BodyTooLarge)?;
    // Size the buffer to the record, but cap the speculative allocation at `MB` so a bogus
    // `Content-Length` cannot force a huge up-front allocation.
    let mut body_buffer: Vec<u8> = Vec::with_capacity(std::cmp::min(maximum_read_range, MB));
    let mut body_bytes_read = 0;
    loop {
        let bytes_read = match reader.read_until(b'\n', &mut body_buffer) {
            Err(io) => return Err(Error::ReadData(io)),
            Ok(len) => len,
        };

        body_bytes_read += bytes_read;

        // we expect 4 characters (`\r\n\r\n`) after the body
        if bytes_read == 2 && body_bytes_read == maximum_read_range {
            // The terminator is what separates one record from the next, so a body followed by
            // anything else has not been framed as the header block said it was.
            if &body_buffer[expected_body_len..] != b"\r\n\r\n" {
                return Err(Error::MalformedRecordTerminator);
            }
            body_buffer.truncate(expected_body_len);
            return Ok(body_buffer);
        }

        if bytes_read == 0 {
            return Err(Error::UnexpectedEOB);
        }

        if body_bytes_read > maximum_read_range {
            return Err(Error::ReadOverflow);
        }
    }
}

/// An iterator of raw records streamed from a reader. See `RawRecord` for more information.
///
/// Every error this iterator returns is stream-level: it leaves the reader at an unspecified
/// position. The iterator is therefore fused after one, and after the input has ended.
pub struct RawRecordIter<R> {
    reader: R,
    finished: bool,
    header_buffer: Vec<u8>,
}

impl<R: BufRead> RawRecordIter<R> {
    pub(crate) const fn new(reader: R) -> Self {
        Self {
            reader,
            finished: false,
            header_buffer: Vec::new(),
        }
    }

    /// Read the next record; the `Iterator` impl wraps this with the fusing logic.
    fn next_record(&mut self) -> Option<<Self as Iterator>::Item> {
        match read_header_block(&mut self.reader, &mut self.header_buffer)? {
            Ok(()) => {}
            Err(e) => return Some(Err(e)),
        }

        let (headers, expected_body_len) = match parse_header_block(&self.header_buffer) {
            Ok(parsed) => parsed,
            Err(e) => return Some(Err(e)),
        };

        let body = match read_body(&mut self.reader, expected_body_len) {
            Ok(body) => body,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok((headers, body)))
    }
}

impl<R: BufRead> Iterator for RawRecordIter<R> {
    type Item = Result<(RawRecordHeader, Vec<u8>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let item = self.next_record();
        self.finished = !matches!(item, Some(Ok(_)));
        item
    }
}

/// An iterator which returns the records read by a reader.
///
/// A record which cannot be validated is returned as an error, and iteration continues with
/// the next record. A stream-level error fuses the iterator, as it does the raw one.
pub struct RecordIter<R> {
    raw_iter: RawRecordIter<R>,
}

impl<R: BufRead> RecordIter<R> {
    pub(crate) const fn new(reader: R) -> Self {
        Self {
            raw_iter: RawRecordIter::new(reader),
        }
    }
}

impl<R: BufRead> Iterator for RecordIter<R> {
    type Item = Result<Record<BufferedBody>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.raw_iter.next()? {
            Ok((headers, body)) => Some(
                headers
                    .try_into()
                    .map(|record: Record<EmptyBody>| record.add_body(body)),
            ),
            Err(e) => Some(Err(e)),
        }
    }
}

/// An iterator-like type to "stream" records from a reader.
///
/// This API returns records which use the `StreamingBody` type. This allows reading record headers
/// and metadata without reading the bodies. Bodies can be read or skipped as desired.
///
/// This is streaming iterator is particularly useful for streams of records which are indefinite
/// or contain and records of unknown size.
pub struct StreamingIter<'r, R> {
    reader: &'r mut R,
    current_item_size: u64,
    first_record: bool,
    /// Set once a stream-level error has been returned, so that further calls do not read
    /// from a stream left at an unspecified position.
    finished: bool,
    header_buffer: Vec<u8>,
}

impl<R: BufRead> StreamingIter<'_, R> {
    pub(crate) const fn new(reader: &mut R) -> StreamingIter<'_, R> {
        StreamingIter {
            reader,
            current_item_size: 0,
            first_record: true,
            finished: false,
            header_buffer: Vec::new(),
        }
    }

    fn skip_body(&mut self) -> Result<(), Error> {
        let mut body_bytes_left = self.current_item_size;
        while body_bytes_left > 0 {
            let buffered_len = match self.reader.fill_buf() {
                Err(io) => return Err(Error::ReadData(io)),
                Ok(buffered) => buffered.len(),
            };
            if buffered_len == 0 {
                return Err(Error::UnexpectedEOB);
            }
            // The skip is bounded by the buffer length, so it always fits in `usize`.
            let bytes_skipped = usize::try_from(body_bytes_left)
                .map_or(buffered_len, |left| left.min(buffered_len));
            self.reader.consume(bytes_skipped);
            body_bytes_left -= bytes_skipped as u64;
        }

        let mut crlfs = [0; 4];

        match self.reader.read_exact(&mut crlfs) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::UnexpectedEOB);
            }
            Err(io) => return Err(Error::ReadData(io)),
        }

        if &crlfs == b"\r\n\r\n" {
            Ok(())
        } else {
            Err(Error::MalformedRecordTerminator)
        }
    }

    /// Advance the stream to the next item.
    ///
    /// Returns one of the following:
    /// * `Some(Ok(r))` is the next record read from the stream.
    /// * `Some(Err)` indicates there was a read error.
    /// * `None` indicates no more records are returned. The iterator is fused: once the input
    ///   has cleanly ended, every further call returns `None`.
    pub fn next_item(&mut self) -> Option<Result<Record<StreamingBody<'_, R>>, Error>> {
        if self.finished {
            return None;
        }

        if self.first_record {
            self.first_record = false;
        } else if let Err(e) = self.skip_body() {
            self.finished = true;
            return Some(Err(e));
        }

        match read_header_block(self.reader, &mut self.header_buffer) {
            None => {
                self.finished = true;
                return None;
            }
            Some(Ok(())) => {}
            Some(Err(e)) => {
                self.finished = true;
                return Some(Err(e));
            }
        }

        let (headers, expected_body_len) = match parse_header_block(&self.header_buffer) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.finished = true;
                return Some(Err(e));
            }
        };
        self.current_item_size = expected_body_len;

        match headers.try_into() {
            Ok(b) => {
                let record: Record<_> = b;
                let fixed_stream_result = record
                    .add_fixed_stream(self.reader, &mut self.current_item_size)
                    .map_err(Error::ReadData);
                Some(fixed_stream_result)
            }
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod from_path_tests {
    use crate::WarcReader;

    #[test]
    fn reads_existing_file() {
        let raw: &[u8] = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:from-path:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reads_existing_file.warc");
        std::fs::write(&path, raw).unwrap();

        let reader = WarcReader::from_path(&path).unwrap();
        let record = reader.iter_records().next().unwrap().unwrap();
        assert_eq!(record.warc_id(), "<urn:test:from-path:record-0>");
        assert_eq!(record.body(), b"12345");
    }

    #[test]
    fn missing_file_is_not_found_and_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing_file.warc");
        let Err(err) = WarcReader::from_path(&path) else {
            panic!("expected opening a missing file to fail");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod iter_raw_tests {
    use indexmap::IndexMap;
    use std::io::{BufReader, Cursor};
    use std::iter::FromIterator;

    use crate::{Error, WarcHeader, WarcReader};
    macro_rules! create_reader {
        ($raw:expr) => {{ BufReader::new(Cursor::new($raw.get(..).unwrap())) }};
    }

    #[test]
    fn basic_record() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:basic-record:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let expected_version = "1.0";
        let expected_headers: IndexMap<WarcHeader, Vec<u8>> = IndexMap::from_iter(vec![
            (WarcHeader::WarcType, b"dunno".to_vec()),
            (WarcHeader::ContentLength, b"5".to_vec()),
            (
                WarcHeader::RecordID,
                b"<urn:test:basic-record:record-0>".to_vec(),
            ),
            (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
        ]);
        let expected_body: &[u8] = b"12345";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        let (headers, body) = reader.next().unwrap().unwrap();
        assert_eq!(headers.version, expected_version);
        assert_eq!(headers.as_ref(), &expected_headers);
        assert_eq!(body, expected_body);
    }

    /// A hostile `Content-Length` near the unsigned 64-bit maximum must be rejected cleanly:
    /// the buffered path cannot possibly hold such a body, and the length arithmetic must not
    /// overflow (which previously panicked in debug builds and wrapped in release).
    #[test]
    fn huge_content_length_is_rejected_without_panicking() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            Content-Length: 18446744073709551615\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::BodyTooLarge) => {}
            other => panic!(
                "expected a body-too-large error, got {:?}",
                other.map(|(headers, _)| headers)
            ),
        }
    }

    /// A `Content-Length` value beyond the unsigned 64-bit range is not a length at all; it is
    /// rejected as a parse error naming the field.
    #[test]
    fn content_length_beyond_u64_is_a_parse_error() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            Content-Length: 99999999999999999999999999\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::ParseHeaders(nom::Err::Error(e))) => {
                assert_eq!(e.input, b"Content-Length".to_vec());
            }
            other => panic!(
                "expected a parse error naming content-length, got {:?}",
                other.map(|(headers, _)| headers)
            ),
        }
    }

    #[test]
    fn two_records() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:two-records:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: another\r\n\
            WARC-Record-Id: <urn:test:two-records:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:56Z\r\n\
            Content-Length: 6\r\n\
            \r\n\
            123456\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        {
            let expected_version = "1.0";
            let expected_headers: IndexMap<WarcHeader, Vec<u8>> = IndexMap::from_iter(vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:two-records:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]);
            let expected_body: &[u8] = b"12345";

            let (headers, body) = reader.next().unwrap().unwrap();
            assert_eq!(headers.version, expected_version);
            assert_eq!(headers.as_ref(), &expected_headers);
            assert_eq!(body, expected_body);
        }

        {
            let expected_version = "1.0";
            let expected_headers: IndexMap<WarcHeader, Vec<u8>> = IndexMap::from_iter(vec![
                (WarcHeader::WarcType, b"another".to_vec()),
                (WarcHeader::ContentLength, b"6".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:two-records:record-1>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:56Z".to_vec()),
            ]);
            let expected_body: &[u8] = b"123456";

            let (headers, body) = reader.next().unwrap().unwrap();
            assert_eq!(headers.version, expected_version);
            assert_eq!(headers.as_ref(), &expected_headers);
            assert_eq!(body, expected_body);
        }
    }

    /// The bytes after a body are the record terminator, so a record whose body is followed by
    /// four other bytes is rejected rather than read as if it had ended properly.
    #[test]
    fn invalid_record_terminator() {
        // After the 4-byte body, the record ends with `c\nd\n` instead of `\r\n\r\n`; the byte
        // counts line up, but the terminator bytes are wrong.
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 4\r\n\
            \r\n\
            a\nb\nc\nd\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::MalformedRecordTerminator) => {}
            other => panic!(
                "expected a parse error for an invalid record terminator, got {:?}",
                other.map(|(headers, body)| (headers, String::from_utf8_lossy(&body).to_string()))
            ),
        }
    }

    /// A header line that does not match the named-field grammar is rejected with an error
    /// carrying that line, rather than it (and every line after it) being silently dropped.
    #[test]
    fn malformed_header_line_is_rejected() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            bad header line without a colon\r\n\
            Content-Length: 5\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::ParseHeaders(nom::Err::Error(inner))) => {
                assert_eq!(inner.input, b"bad header line without a colon".to_vec());
            }
            other => panic!(
                "expected a parse error naming the malformed line, got {:?}",
                other.map(|(headers, _)| headers)
            ),
        }
    }

    /// A stream-level error leaves the reader at an unspecified position, so the iterator
    /// fuses instead of yielding garbage parsed from the middle of the broken record.
    #[test]
    fn raw_iter_fuses_after_stream_error() {
        // A record with a malformed terminator, followed by a perfectly valid record that a
        // non-fused iterator would happily (and wrongly) yield.
        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            \r\n\
            12345ABCD\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:after-error:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(reader.next().unwrap().is_err());
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
    }

    /// A field value folded across lines with leading whitespace is unfolded, each fold
    /// reading as a single space.
    #[test]
    fn folded_header_value_is_unfolded() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: metadata\r\n\
            Content-Length: 0\r\n\
            WARC-Record-ID: <urn:test:folded:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            Unfolded-Test: this value\r\n\
            \tspans lines\r\n\
            \r\n\
            \r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        let (headers, body) = reader.next().unwrap().unwrap();
        assert!(body.is_empty());
        assert_eq!(
            headers
                .as_ref()
                .get(&WarcHeader::Unknown("unfolded-test".to_owned()))
                .unwrap(),
            &b"this value spans lines".to_vec()
        );
    }

    /// The specification forbids repeating any named field except `WARC-Concurrent-To`; a
    /// record that repeats one is rejected with an error naming the field.
    #[test]
    fn repeated_field_is_rejected() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-ID: <urn:test:repeated:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            WARC-Target-URI: https://example.com/first\r\n\
            WARC-Target-URI: https://example.com/second\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::DuplicateHeader(WarcHeader::TargetURI)) => {}
            other => panic!(
                "expected a duplicate target-uri error, got {:?}",
                other.map(|(headers, _)| headers)
            ),
        }
    }

    /// `WARC-Concurrent-To` is the one field the specification allows to repeat; every value
    /// is preserved, in order of appearance.
    #[test]
    fn repeated_concurrent_to_is_preserved() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: request\r\n\
            Content-Length: 0\r\n\
            WARC-Record-ID: <urn:test:concurrent:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            WARC-Concurrent-To: <urn:test:concurrent:record-1>\r\n\
            WARC-Concurrent-To: <urn:test:concurrent:record-2>\r\n\
            \r\n\
            \r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        let (headers, body) = reader.next().unwrap().unwrap();
        assert!(body.is_empty());
        assert!(headers.as_ref().get(&WarcHeader::ConcurrentTo).is_none());
        assert_eq!(
            headers.concurrent_to,
            vec![
                b"<urn:test:concurrent:record-1>".to_vec(),
                b"<urn:test:concurrent:record-2>".to_vec(),
            ]
        );
    }

    /// A record without `Content-Length` cannot be framed; it is rejected with an error naming
    /// the missing field rather than misread as having an empty body.
    #[test]
    fn missing_content_length_is_rejected() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            WARC-Record-ID: <urn:test:missing-length:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::MissingHeader(WarcHeader::ContentLength)) => {}
            other => panic!(
                "expected a missing content-length error, got {:?}",
                other.map(|(headers, _)| headers)
            ),
        }
    }

    /// WARC 1.0 requires complete UTC timestamps with second precision.
    #[test]
    fn warc_1_0_reading_rejects_subseconds() {
        let raw = b"\
            WARC/1.0\r\n\
            WARC-Type: resource\r\n\
            Content-Length: 0\r\n\
            WARC-Record-ID: <urn:test:warc-1.0-date:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55.123456Z\r\n\
            \r\n\
            \r\n\
            \r\n\
        ";

        let result = WarcReader::new(create_reader!(raw))
            .iter_records()
            .next()
            .unwrap();
        assert!(matches!(
            result,
            Err(Error::MalformedHeader(WarcHeader::Date, _))
        ));
    }
}

#[cfg(test)]
mod next_item_tests {
    use std::io::{BufReader, Cursor};

    use crate::{Error, WarcReader};

    macro_rules! create_reader {
        ($raw:expr) => {{ BufReader::new(Cursor::new($raw.get(..).unwrap())) }};
    }

    #[test]
    fn first_item() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:basic-record:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();
        let record = stream_iter
            .next_item()
            .unwrap()
            .unwrap()
            .into_buffered()
            .unwrap();
        assert_eq!(record.warc_version(), "1.0");
        assert_eq!(record.content_length(), 5);
        assert_eq!(record.warc_id(), "<urn:test:basic-record:record-0>");
        assert_eq!(record.body(), b"12345");
    }

    #[test]
    fn both_items() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:two-records:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: another\r\n\
            WARC-Record-Id: <urn:test:two-records:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:56Z\r\n\
            Content-Length: 6\r\n\
            \r\n\
            123456\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        {
            let record = stream_iter
                .next_item()
                .unwrap()
                .unwrap()
                .into_buffered()
                .unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 5);
            assert_eq!(record.warc_id(), "<urn:test:two-records:record-0>");
            assert_eq!(record.body(), b"12345");
        }

        {
            let record = stream_iter
                .next_item()
                .unwrap()
                .unwrap()
                .into_buffered()
                .unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 6);
            assert_eq!(record.warc_id(), "<urn:test:two-records:record-1>");
            assert_eq!(record.body(), b"123456");
        }
    }

    #[test]
    fn only_second_item() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:two-records:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: another\r\n\
            WARC-Record-Id: <urn:test:two-records:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:56Z\r\n\
            Content-Length: 6\r\n\
            \r\n\
            123456\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        let _skipped = stream_iter.next_item().unwrap().unwrap();

        {
            let record = stream_iter
                .next_item()
                .unwrap()
                .unwrap()
                .into_buffered()
                .unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 6);
            assert_eq!(record.warc_id(), "<urn:test:two-records:record-1>");
            assert_eq!(record.body(), b"123456");
        }
    }

    #[test]
    fn triple_items() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:three-records:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: another\r\n\
            WARC-Record-Id: <urn:test:three-records:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:56Z\r\n\
            Content-Length: 6\r\n\
            \r\n\
            123456\r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: yet another\r\n\
            WARC-Record-Id: <urn:test:three-records:record-2>\r\n\
            WARC-Date: 2020-07-08T02:52:56Z\r\n\
            Content-Length: 8\r\n\
            \r\n\
            12345678\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        {
            let record = stream_iter
                .next_item()
                .unwrap()
                .unwrap()
                .into_buffered()
                .unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 5);
            assert_eq!(record.warc_id(), "<urn:test:three-records:record-0>");
            assert_eq!(record.body(), b"12345");
        }

        {
            let record = stream_iter
                .next_item()
                .unwrap()
                .unwrap()
                .into_buffered()
                .unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 6);
            assert_eq!(record.warc_id(), "<urn:test:three-records:record-1>");
            assert_eq!(record.body(), b"123456");
        }

        {
            let record = stream_iter
                .next_item()
                .unwrap()
                .unwrap()
                .into_buffered()
                .unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 8);
            assert_eq!(record.warc_id(), "<urn:test:three-records:record-2>");
            assert_eq!(record.body(), b"12345678");
        }
    }

    #[test]
    fn skip_body_larger_than_bufreader_buffer() {
        let body = vec![b'x'; 20_000];
        let mut raw = format!(
            "WARC/1.0\r\n\
             Warc-Type: dunno\r\n\
             WARC-Record-Id: <urn:test:skip-large-body:record-0>\r\n\
             WARC-Date: 2020-07-08T02:52:55Z\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(&body);
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend_from_slice(
            b"WARC/1.0\r\n\
              Warc-Type: another\r\n\
              WARC-Record-Id: <urn:test:skip-large-body:record-1>\r\n\
              WARC-Date: 2020-07-08T02:52:56Z\r\n\
              Content-Length: 6\r\n\
              \r\n\
              123456\r\n\
              \r\n",
        );

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        let _skipped = stream_iter.next_item().unwrap().unwrap();

        let record = stream_iter
            .next_item()
            .unwrap()
            .unwrap()
            .into_buffered()
            .unwrap();
        assert_eq!(record.warc_id(), "<urn:test:skip-large-body:record-1>");
        assert_eq!(record.body(), b"123456");
    }

    /// The streaming path frames bodies as unsigned 64-bit lengths on every platform, so a
    /// record too large to buffer still yields a streaming record reporting its full size.
    #[test]
    fn streaming_reports_unbuffered_content_length() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            WARC-Record-Id: <urn:test:huge-record:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            Content-Length: 18446744073709551615\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        let record = stream_iter.next_item().unwrap().unwrap();
        assert_eq!(record.content_length(), u64::MAX);
    }

    #[test]
    fn empty_content_length() {
        let raw = b"\
        WARC/1.0\r\n\
        Warc-Type: empty-record\r\n\
        Content-Length: 0\r\n\
        WARC-Record-Id: <urn:test:empty-content-length>\r\n\
        WARC-Date: 2020-07-08T02:52:57Z\r\n\
        \r\n\
        \r\n\
    ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        let record = stream_iter
            .next_item()
            .unwrap()
            .unwrap()
            .into_buffered()
            .unwrap();
        assert_eq!(record.warc_version(), "1.0");
        assert_eq!(record.content_length(), 0);
        assert_eq!(record.warc_id(), "<urn:test:empty-content-length>");
        assert_eq!(record.body(), b"");
    }

    #[test]
    fn zero_and_nonzero_content_length() {
        let raw = b"\
        WARC/1.0\r\n\
        Warc-Type: empty-record\r\n\
        Content-Length: 0\r\n\
        WARC-Record-Id: <urn:test:zero-content-length>\r\n\
        WARC-Date: 2020-07-08T02:52:57Z\r\n\
        \r\n\
        \r\n\
        \r\n\
        WARC/1.0\r\n\
        Warc-Type: non-empty-record\r\n\
        Content-Length: 7\r\n\
        WARC-Record-Id: <urn:test:nonzero-content-length>\r\n\
        WARC-Date: 2020-07-08T02:52:58Z\r\n\
        \r\n\
        1234567\r\n\
        \r\n\
    ";

        let reader = WarcReader::new(create_reader!(raw));
        let mut iter = reader.iter_records();

        // Test the first record with Content-Length: 0
        {
            let record = iter.next().unwrap().unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 0);
            assert_eq!(record.warc_id(), "<urn:test:zero-content-length>");
            assert_eq!(record.body(), b"");
        }

        // Test the second record with non-zero Content-Length
        {
            let record = iter.next().unwrap().unwrap();
            assert_eq!(record.warc_version(), "1.0");
            assert_eq!(record.content_length(), 7);
            assert_eq!(record.warc_id(), "<urn:test:nonzero-content-length>");
            assert_eq!(record.body(), b"1234567");
        }
    }

    /// The declared `Content-Length` is reported unchanged while the body is being consumed,
    /// rather than shrinking with every read.
    #[test]
    fn streaming_content_length_is_stable_while_reading() {
        use std::io::Read;

        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:stable-length:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();
        let mut record = stream_iter.next_item().unwrap().unwrap();

        assert_eq!(record.content_length(), 5);

        let mut first_two = [0_u8; 2];
        record.read_exact(&mut first_two).unwrap();
        assert_eq!(&first_two, b"12");
        assert_eq!(record.content_length(), 5);
        assert_eq!(
            record.header(crate::WarcHeader::ContentLength).as_deref(),
            Some("5")
        );

        // Buffering collects the rest of the body; the unread portion is what remains.
        let buffered = record.into_buffered().unwrap();
        assert_eq!(buffered.body(), b"345");
    }

    /// After the final `None`, further calls keep returning `None` instead of yielding a
    /// spurious error for a body the iterator already consumed.
    #[test]
    fn next_item_is_fused_after_end() {
        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:fused:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        // Leave the record's body unread so that reaching the end must skip it.
        let _record = stream_iter.next_item().unwrap().unwrap();
        assert!(stream_iter.next_item().is_none());
        assert!(stream_iter.next_item().is_none());
        assert!(stream_iter.next_item().is_none());
    }

    /// A record whose declared body length outruns the stream: 5 bytes are declared but only
    /// 2 are present.
    const TRUNCATED_BODY: &[u8] = b"\
        WARC/1.1\r\n\
        Warc-Type: dunno\r\n\
        Content-Length: 5\r\n\
        WARC-Record-Id: <urn:test:truncated:record-0>\r\n\
        WARC-Date: 2020-07-08T02:52:55Z\r\n\
        \r\n\
        12";

    /// A stream-level error fuses the streaming iterator instead of yielding further errors
    /// from an unspecified position.
    #[test]
    fn next_item_fuses_after_stream_error() {
        let mut reader = WarcReader::new(create_reader!(TRUNCATED_BODY));
        let mut stream_iter = reader.stream_records();

        // Leave the first record's body unread so that the next call must skip it and hit
        // the truncation.
        let _record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(
            stream_iter.next_item(),
            Some(Err(Error::UnexpectedEOB))
        ));
        assert!(stream_iter.next_item().is_none());
        assert!(stream_iter.next_item().is_none());
    }
}

#[cfg(all(test, feature = "gzip"))]
mod gzip_tests {
    use std::io::Write;

    use crate::{
        BufferedBody, Record, RecordBuilder, RecordType, WarcHeader, WarcReader, WarcWriter,
    };

    fn record(body: &[u8], url: &str) -> Record<BufferedBody> {
        RecordBuilder::default()
            .warc_type(RecordType::Response)
            .header(WarcHeader::TargetURI, url)
            .body(body.to_vec())
            .build()
            .expect("record should build")
    }

    /// Records written through the gzip writer read back through the gzip reader.
    #[test]
    fn gzip_path_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("round-trip.warc.gz");

        let mut writer = WarcWriter::from_path_gzip(&path).unwrap();
        writer
            .write(&record(b"first body", "https://example.com/1"))
            .unwrap();
        writer
            .write(&record(b"second body", "https://example.com/2"))
            .unwrap();
        // The gzip stream must be finished, or the file is truncated.
        let gzip_stream = writer
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)
            .unwrap();
        gzip_stream.finish().into_result().unwrap();

        let reader = WarcReader::from_path_gzip(&path).unwrap();
        let records = reader
            .iter_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].body(), b"first body");
        assert_eq!(
            records[0].header(WarcHeader::TargetURI).as_deref(),
            Some("https://example.com/1")
        );
        assert_eq!(records[1].body(), b"second body");
        assert_eq!(
            records[1].header(WarcHeader::TargetURI).as_deref(),
            Some("https://example.com/2")
        );
    }

    /// A `.warc.gz` holding each record as its own gzip member — the conventional layout for
    /// compressed WARC files, and the case the multi-member decoder exists for — reads back
    /// as a single record stream.
    #[test]
    fn gzip_multi_member_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-member.warc.gz");

        let mut file = std::fs::File::create(&path).unwrap();
        for (body, url) in [
            (&b"first body"[..], "https://example.com/1"),
            (&b"second body"[..], "https://example.com/2"),
        ] {
            let mut encoder = libflate::gzip::Encoder::new(Vec::new()).unwrap();
            WarcWriter::new(&mut encoder)
                .write(&record(body, url))
                .unwrap();
            let member = encoder.finish().into_result().unwrap();
            file.write_all(&member).unwrap();
        }
        drop(file);

        let reader = WarcReader::from_path_gzip(&path).unwrap();
        let records = reader
            .iter_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].body(), b"first body");
        assert_eq!(records[1].body(), b"second body");
    }

    /// The streaming iterator reads gzip input like any other, skipping and buffering across
    /// member boundaries.
    #[test]
    fn gzip_streaming_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("streaming.warc.gz");

        let mut writer = WarcWriter::from_path_gzip(&path).unwrap();
        writer
            .write(&record(b"first body", "https://example.com/1"))
            .unwrap();
        writer
            .write(&record(b"second body", "https://example.com/2"))
            .unwrap();
        let gzip_stream = writer
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)
            .unwrap();
        gzip_stream.finish().into_result().unwrap();

        let mut reader = WarcReader::from_path_gzip(&path).unwrap();
        let mut stream_iter = reader.stream_records();

        // Skip the first record's body entirely, then buffer the second.
        let _skipped = stream_iter.next_item().unwrap().unwrap();
        let second = stream_iter
            .next_item()
            .unwrap()
            .unwrap()
            .into_buffered()
            .unwrap();

        assert_eq!(second.body(), b"second body");
        assert!(stream_iter.next_item().is_none());
    }
}
