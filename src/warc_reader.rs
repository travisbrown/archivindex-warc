use crate::parser;
use crate::{BufferedBody, Error, RawRecordHeader, Record, StreamingBody};

use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[cfg(feature = "gzip")]
use libflate::gzip::MultiDecoder as GzipReader;

const KB: usize = 1_024;
const MB: usize = 1_048_576;

/// A reader which iteratively parses WARC records from a stream.
pub struct WarcReader<R> {
    reader: R,
}

impl<R: BufRead> WarcReader<R> {
    /// Create a new reader.
    pub fn new(r: R) -> Self {
        WarcReader { reader: r }
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
    pub fn stream_records(&mut self) -> StreamingIter<'_, R> {
        StreamingIter::new(&mut self.reader)
    }
}

impl WarcReader<BufReader<fs::File>> {
    /// Create a new reader which reads from file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let reader = BufReader::with_capacity(MB, file);

        Ok(WarcReader::new(reader))
    }
}

#[cfg(feature = "gzip")]
impl WarcReader<BufReader<GzipReader<BufReader<std::fs::File>>>> {
    /// Create a new reader which reads from a compressed file.
    ///
    /// Only GZIP compression is currently supported.
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(&path)?;

        let gzip_stream = GzipReader::new(BufReader::with_capacity(MB, file))?;
        Ok(WarcReader::new(BufReader::new(gzip_stream)))
    }
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

    Err(Error::ParseHeaders(nom::Err::Error((
        remainder[..line_len].to_vec(),
        nom::error::ErrorKind::Verify,
    ))))
}

/// An iterator of raw records streamed from a reader. See `RawRecord` for more information.
pub struct RawRecordIter<R> {
    reader: R,
}

impl<R: BufRead> RawRecordIter<R> {
    pub(crate) fn new(reader: R) -> RawRecordIter<R> {
        RawRecordIter { reader }
    }
}

impl<R: BufRead> Iterator for RawRecordIter<R> {
    type Item = Result<(RawRecordHeader, Vec<u8>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut header_buffer: Vec<u8> = Vec::with_capacity(64 * KB);
        let mut found_headers = false;
        while !found_headers {
            let bytes_read = match self.reader.read_until(b'\n', &mut header_buffer) {
                Err(io) => return Some(Err(Error::ReadData(io))),
                Ok(len) => len,
            };

            if bytes_read == 0 {
                return None;
            }

            if bytes_read == 2 {
                let last_two_chars = header_buffer.len() - 2;
                if &header_buffer[last_two_chars..] == b"\r\n" {
                    found_headers = true;
                }
            }
        }

        let headers_parsed = match parser::headers(&header_buffer) {
            Err(e) => {
                return Some(Err(Error::ParseHeaders(
                    e.map(|inner| (inner.input.to_owned(), inner.code)),
                )))
            }
            Ok((remainder, parsed)) => {
                if let Err(e) = check_header_block_end(remainder) {
                    return Some(Err(e));
                }
                parsed
            }
        };
        let version_ref = headers_parsed.0;
        let headers_ref = headers_parsed.1;
        let expected_body_len = headers_parsed.2;

        let mut body_buffer: Vec<u8> = Vec::with_capacity(MB);
        let mut found_body = false;
        let mut body_bytes_read = 0;
        let maximum_read_range = expected_body_len + 4;
        while !found_body {
            let bytes_read = match self.reader.read_until(b'\n', &mut body_buffer) {
                Err(io) => return Some(Err(Error::ReadData(io))),
                Ok(len) => len,
            };

            body_bytes_read += bytes_read;

            // we expect 4 characters (\r\n\r\n) after the body
            if bytes_read == 2 && body_bytes_read == maximum_read_range {
                if &body_buffer[expected_body_len..] != b"\r\n\r\n" {
                    let synthetic_err: nom::Err<(Vec<u8>, nom::error::ErrorKind)> =
                        nom::Err::Failure((
                            vec![0x0d, 0x0a, 0x0d, 0x0a],
                            nom::error::ErrorKind::Tag,
                        ));
                    return Some(Err(Error::ParseHeaders(synthetic_err)));
                }
                found_body = true;
            }

            if bytes_read == 0 {
                return Some(Err(Error::UnexpectedEOB));
            }

            if body_bytes_read > maximum_read_range {
                return Some(Err(Error::ReadOverflow));
            }
        }

        let body_ref = &body_buffer[..expected_body_len];

        let headers = RawRecordHeader {
            version: version_ref.to_owned(),
            headers: headers_ref
                .into_iter()
                .map(|(token, value)| (token.into(), value.to_owned()))
                .collect(),
        };
        let body = body_ref.to_owned();
        Some(Ok((headers, body)))
    }
}

/// An iterator which returns the records read by a reader.
pub struct RecordIter<R> {
    reader: R,
}

impl<R: BufRead> RecordIter<R> {
    pub(crate) fn new(reader: R) -> RecordIter<R> {
        RecordIter { reader }
    }
}

impl<R: BufRead> Iterator for RecordIter<R> {
    type Item = Result<Record<BufferedBody>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut header_buffer: Vec<u8> = Vec::with_capacity(64 * KB);
        let mut found_headers = false;
        while !found_headers {
            let bytes_read = match self.reader.read_until(b'\n', &mut header_buffer) {
                Err(io) => return Some(Err(Error::ReadData(io))),
                Ok(len) => len,
            };

            if bytes_read == 0 {
                return None;
            }

            if bytes_read == 2 {
                let last_two_chars = header_buffer.len() - 2;
                if &header_buffer[last_two_chars..] == b"\r\n" {
                    found_headers = true;
                }
            }
        }

        let headers_parsed = match parser::headers(&header_buffer) {
            Err(e) => {
                return Some(Err(Error::ParseHeaders(
                    e.map(|inner| (inner.input.to_owned(), inner.code)),
                )));
            }

            Ok((remainder, parsed)) => {
                if let Err(e) = check_header_block_end(remainder) {
                    return Some(Err(e));
                }
                parsed
            }
        };
        let version_ref = headers_parsed.0;
        let headers_ref = headers_parsed.1;
        let expected_body_len = headers_parsed.2;

        let mut body_buffer: Vec<u8> = Vec::with_capacity(MB);
        let mut found_body = false;
        let mut body_bytes_read = 0;
        let maximum_read_range = expected_body_len + 4;
        while !found_body {
            let bytes_read = match self.reader.read_until(b'\n', &mut body_buffer) {
                Err(io) => return Some(Err(Error::ReadData(io))),
                Ok(len) => len,
            };

            body_bytes_read += bytes_read;

            // we expect 4 characters (\r\n\r\n) after the body
            if bytes_read == 2 && body_bytes_read == maximum_read_range {
                if &body_buffer[expected_body_len..] != b"\r\n\r\n" {
                    let synthetic_err: nom::Err<(Vec<u8>, nom::error::ErrorKind)> =
                        nom::Err::Failure((
                            vec![0x0d, 0x0a, 0x0d, 0x0a],
                            nom::error::ErrorKind::Tag,
                        ));
                    return Some(Err(Error::ParseHeaders(synthetic_err)));
                }
                found_body = true;
            }

            if bytes_read == 0 {
                return Some(Err(Error::UnexpectedEOB));
            }

            if body_bytes_read > maximum_read_range {
                return Some(Err(Error::ReadOverflow));
            }
        }

        let body_ref = &body_buffer[..expected_body_len];

        let headers = RawRecordHeader {
            version: version_ref.to_owned(),
            headers: headers_ref
                .into_iter()
                .map(|(token, value)| (token.into(), value.to_owned()))
                .collect(),
        };
        let body = body_ref.to_owned();
        match headers.try_into() {
            Ok(b) => {
                let buffered: Record<_> = b;
                Some(Ok(buffered.add_body(body)))
            }
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
}

impl<R: BufRead> StreamingIter<'_, R> {
    pub(crate) fn new(reader: &mut R) -> StreamingIter<'_, R> {
        StreamingIter {
            reader,
            current_item_size: 0,
            first_record: true,
        }
    }

    fn skip_body(&mut self) -> Result<(), Error> {
        let mut read_buffer = [0u8; MB];
        let maximum_read_range = self.current_item_size;
        let mut body_bytes_left = maximum_read_range;
        while body_bytes_left > 0 {
            let read_size = std::cmp::min(body_bytes_left, read_buffer.len() as u64) as usize;
            let bytes_read = match self.reader.read(&mut read_buffer[..read_size]) {
                Err(io) => return Err(Error::ReadData(io)),
                Ok(len) => len as u64,
            };
            if bytes_read == 0 {
                return Err(Error::UnexpectedEOB);
            }
            body_bytes_left -= bytes_read;
        }

        let mut crlfs = [0; 4];

        match self.reader.read_exact(&mut crlfs) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::UnexpectedEOB)
            }
            Err(io) => return Err(Error::ReadData(io)),
        }

        if &crlfs == b"\x0d\x0a\x0d\x0a" {
            Ok(())
        } else {
            let synthetic_err: nom::Err<(Vec<u8>, nom::error::ErrorKind)> =
                nom::Err::Failure((vec![0x0d, 0x0a, 0x0d, 0x0a], nom::error::ErrorKind::Tag));
            Err(Error::ParseHeaders(synthetic_err))
        }
    }

    /// Advance the stream to the next item.
    ///
    /// Returns one of the following:
    /// * Some(Ok(r))` is the next record read from the stream.
    /// * `Some(Err)` indicates there was a read error.
    /// * `None` indicates no more records are returned.
    pub fn next_item(&mut self) -> Option<Result<Record<StreamingBody<'_, R>>, Error>> {
        if self.first_record {
            self.first_record = false;
        } else if let Err(e) = self.skip_body() {
            return Some(Err(e));
        }

        let mut header_buffer: Vec<u8> = Vec::with_capacity(64 * KB);
        let mut found_headers = false;
        while !found_headers {
            let bytes_read = match self.reader.read_until(b'\n', &mut header_buffer) {
                Err(io) => return Some(Err(Error::ReadData(io))),
                Ok(len) => len,
            };

            if bytes_read == 0 {
                return None;
            }

            if bytes_read == 2 {
                let last_two_chars = header_buffer.len() - 2;
                if &header_buffer[last_two_chars..] == b"\r\n" {
                    found_headers = true;
                }
            }
        }

        let headers_parsed = match parser::headers(&header_buffer) {
            Err(e) => {
                return Some(Err(Error::ParseHeaders(
                    e.map(|inner| (inner.input.to_owned(), inner.code)),
                )))
            }
            Ok((remainder, parsed)) => {
                if let Err(e) = check_header_block_end(remainder) {
                    return Some(Err(e));
                }
                parsed
            }
        };
        let version_ref = headers_parsed.0;
        let headers_ref = headers_parsed.1;
        self.current_item_size = headers_parsed.2 as u64;

        let headers = RawRecordHeader {
            version: version_ref.to_owned(),
            headers: headers_ref
                .into_iter()
                .map(|(token, value)| (token.into(), value.to_owned()))
                .collect(),
        };
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
mod iter_raw_tests {
    use std::collections::HashMap;
    use std::io::{BufReader, Cursor};
    use std::iter::FromIterator;

    use crate::{Error, WarcHeader, WarcReader};
    macro_rules! create_reader {
        ($raw:expr) => {{
            BufReader::new(Cursor::new($raw.get(..).unwrap()))
        }};
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
        let expected_headers: HashMap<WarcHeader, Vec<u8>> = HashMap::from_iter(vec![
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
            let expected_headers: HashMap<WarcHeader, Vec<u8>> = HashMap::from_iter(vec![
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
            let expected_headers: HashMap<WarcHeader, Vec<u8>> = HashMap::from_iter(vec![
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
            Err(Error::ParseHeaders(_)) => {}
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
            Err(Error::ParseHeaders(nom::Err::Error((input, _)))) => {
                assert_eq!(input, b"bad header line without a colon".to_vec());
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
    #[ignore = "known bug (IO-004: iterators not fused)"]
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
    #[ignore = "known bug (PARSE-002: WARC field grammar divergence)"]
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

    /// The specification forbids repeating a named field; when a record repeats one anyway,
    /// the first occurrence wins consistently: the body is framed by the first
    /// `Content-Length`, so the surviving header values must be the first ones too.
    #[test]
    #[ignore = "known bug (PARSE-002: WARC field grammar divergence)"]
    fn repeated_field_keeps_first_occurrence() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            Content-Length: 5\r\n\
            Content-Length: 500\r\n\
            WARC-Record-ID: <urn:test:repeated:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            WARC-Target-URI: https://example.com/first\r\n\
            WARC-Target-URI: https://example.com/second\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        let (headers, body) = reader.next().unwrap().unwrap();
        assert_eq!(body, b"12345");
        assert_eq!(
            headers.as_ref().get(&WarcHeader::ContentLength).unwrap(),
            &b"5".to_vec()
        );
        assert_eq!(
            headers.as_ref().get(&WarcHeader::TargetURI).unwrap(),
            &b"https://example.com/first".to_vec()
        );
    }

    /// A record without `Content-Length` cannot be framed; it is rejected with an error naming
    /// the missing field rather than misread as having an empty body.
    #[test]
    #[ignore = "known bug (PARSE-003: missing content-length accepted)"]
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
    #[ignore = "known bug (RECORD-010: 1.0 reader accepts subsecond dates)"]
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
        ($raw:expr) => {{
            BufReader::new(Cursor::new($raw.get(..).unwrap()))
        }};
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
    #[ignore = "known bug (RECORD-004: content length shrinks)"]
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
    #[ignore = "known bug (IO-005: next_item not fused)"]
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
    #[ignore = "known bug (IO-004: iterators not fused)"]
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
