use std::io::{BufRead, BufReader};
use std::path::Path;
use std::{fs, io};

#[cfg(feature = "gzip")]
use flate2::bufread::MultiGzDecoder as GzipReader;

use crate::{
    BufferedBody, Error, FieldName, MB, RawRecordHeader, Record, StreamingBody, WarcHeader, parser,
};

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

        let gzip_stream = GzipReader::new(BufReader::with_capacity(MB, file));
        Ok(Self::new(BufReader::new(gzip_stream)))
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

    Err(Error::ParseHeaders(nom::Err::Error(
        nom::error::Error::new(
            remainder[..line_len].to_vec(),
            nom::error::ErrorKind::Verify,
        ),
    )))
}

/// The maximum size of a buffered record header block.
///
/// The specification places no bound on header blocks, but readers must buffer them, so a
/// hostile or corrupt stream whose header block never ends has to be stopped somewhere;
/// 1 MiB is far beyond any legitimate block.
const MAX_HEADER_BLOCK: usize = MB;

/// The outcome of one [`read_line_bounded`] call.
enum LineRead {
    /// A full line ending in `\n` was appended; the length includes the newline.
    Line(usize),
    /// The stream ended; any partial final line was appended to the buffer.
    Eof,
    /// Completing the line would grow the buffer past the limit.
    LimitExceeded,
}

/// Read one `\n`-terminated line into `buffer` without ever letting it grow past `limit`.
///
/// Unlike [`BufRead::read_until`], which buffers an entire delimiter-free stream within a
/// single call, this never reads more than `limit - buffer.len()` bytes.
fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> Result<LineRead, Error> {
    let mut appended = 0;
    loop {
        let available = match reader.fill_buf() {
            Err(io) => return Err(Error::ReadData(io)),
            Ok(available) => available,
        };
        if available.is_empty() {
            return Ok(LineRead::Eof);
        }

        let allowance = limit - buffer.len();
        if let Some(index) = available
            .iter()
            .take(allowance)
            .position(|&byte| byte == b'\n')
        {
            buffer.extend_from_slice(&available[..=index]);
            reader.consume(index + 1);
            return Ok(LineRead::Line(appended + index + 1));
        }

        if available.len() >= allowance {
            return Ok(LineRead::LimitExceeded);
        }

        let taken = available.len();
        buffer.extend_from_slice(available);
        reader.consume(taken);
        appended += taken;
    }
}

/// Read lines up to and including the blank line that terminates a header block, reading at
/// most [`MAX_HEADER_BLOCK`] bytes.
///
/// The header block is left in `header_buffer`, which is cleared first so callers can reuse
/// one buffer across records.
///
/// Returns `None` on a clean end-of-stream at a record boundary. End-of-stream with header
/// bytes already buffered is truncated input, and is an error.
fn read_header_block<R: BufRead>(
    reader: &mut R,
    header_buffer: &mut Vec<u8>,
) -> Option<Result<(), Error>> {
    header_buffer.clear();
    loop {
        match read_line_bounded(reader, header_buffer, MAX_HEADER_BLOCK) {
            Err(e) => return Some(Err(e)),
            Ok(LineRead::Eof) => {
                // A record boundary is the only place the input may cleanly end. Anything
                // buffered here is a header block whose terminating blank line never arrived:
                // the input was truncated mid-record, or uses bare-`\n` line endings (which
                // never match the `\r\n` check below, and would otherwise read as an empty
                // stream with no error).
                if header_buffer.is_empty() {
                    return None;
                }
                return Some(Err(Error::UnexpectedEOH));
            }
            Ok(LineRead::LimitExceeded) => return Some(Err(Error::HeaderBlockTooLarge)),
            Ok(LineRead::Line(2)) if header_buffer.ends_with(b"\r\n") => return Some(Ok(())),
            Ok(LineRead::Line(_)) => {}
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

    // Field names are kept exactly as they were spelled, and in the order they were read, so
    // that the block serializes back to the bytes it was parsed from.
    let headers = RawRecordHeader::from_fields(
        version,
        headers
            .into_iter()
            .map(|(token, value)| (FieldName::as_read(token), value.into_owned())),
    );
    // The specification forbids repeating any named field except `WARC-Concurrent-To`.
    headers.check_for_duplicates()?;

    Ok((headers, expected_body_len))
}

/// Read a record body of the given length, plus the `\r\n\r\n` record terminator.
fn read_body<R: BufRead>(reader: &mut R, expected_body_len: u64) -> Result<Vec<u8>, Error> {
    // The body plus its 4-byte terminator must fit in a single in-memory buffer. A length for
    // which that is impossible (a hostile value near the platform maximum, or a >4 GiB record
    // on a 32-bit target) is rejected up front, rather than overflowing the arithmetic below;
    // such records can still be read with `WarcReader::stream_records`.
    let expected_body_len = usize::try_from(expected_body_len).map_err(|_| Error::BodyTooLarge)?;
    let needed = expected_body_len
        .checked_add(4)
        .ok_or(Error::BodyTooLarge)?;
    // Size the buffer to the record, but cap the speculative allocation at `MB` so a bogus
    // `Content-Length` cannot force a huge up-front allocation. Reads are bounded by the
    // declared length: exactly the body and its 4-byte `\r\n\r\n` terminator are consumed,
    // regardless of what follows in the stream.
    let mut body_buffer: Vec<u8> = Vec::with_capacity(std::cmp::min(needed, MB));
    while body_buffer.len() < needed {
        let available = match reader.fill_buf() {
            Err(io) => return Err(Error::ReadData(io)),
            Ok(available) => available,
        };
        if available.is_empty() {
            return Err(Error::UnexpectedEOB);
        }

        let taken = available.len().min(needed - body_buffer.len());
        body_buffer.extend_from_slice(&available[..taken]);
        reader.consume(taken);
    }

    // A record whose actual body outruns its declared length puts body bytes where the
    // terminator belongs, so overlong records surface here too.
    if &body_buffer[expected_body_len..] != b"\r\n\r\n" {
        return Err(Error::MalformedRecordTerminator);
    }
    body_buffer.truncate(expected_body_len);
    Ok(body_buffer)
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
            // The parser already validated `Content-Length` (it framed the body just read), so
            // the value flows through rather than being parsed again.
            Ok((headers, body)) => {
                Some(Record::from_validated_raw(headers).map(|record| record.add_body(body)))
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
    /// Set through the current record when `into_buffered` consumed and verified its
    /// terminator, so that `skip_body` does not read it a second time.
    terminator_consumed: bool,
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
            terminator_consumed: false,
            first_record: true,
            finished: false,
            header_buffer: Vec::new(),
        }
    }

    fn skip_body(&mut self) -> Result<(), Error> {
        if self.terminator_consumed {
            return Ok(());
        }

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
        self.terminator_consumed = false;

        // The parser already validated `Content-Length` (it produced `expected_body_len`), so
        // the value flows through rather than being parsed again.
        match Record::from_validated_raw(headers) {
            Ok(record) => Some(Ok(record.add_managed_stream(
                self.reader,
                &mut self.current_item_size,
                &mut self.terminator_consumed,
            ))),
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
    use std::io::{BufReader, Cursor};

    use crate::{Error, FieldName, RawRecordHeader, WarcHeader, WarcReader};
    macro_rules! create_reader {
        ($raw:expr) => {{ BufReader::new(Cursor::new($raw.get(..).unwrap())) }};
    }

    /// A stream that never terminates its header block is stopped at the size bound instead of
    /// being buffered without limit.
    #[test]
    fn oversized_header_block_without_newlines() {
        let raw = vec![b'A'; 2 * crate::MB];

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(matches!(
            reader.next(),
            Some(Err(Error::HeaderBlockTooLarge))
        ));
    }

    /// The header-block bound also applies to a block of well-formed lines that never ends.
    #[test]
    fn oversized_header_block_with_newlines() {
        let mut raw = b"WARC/1.1\r\n".to_vec();
        while raw.len() <= 2 * crate::MB {
            raw.extend_from_slice(b"a: b\r\n");
        }

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(matches!(
            reader.next(),
            Some(Err(Error::HeaderBlockTooLarge))
        ));
    }

    /// A record whose actual body outruns its declared `Content-Length` puts body bytes where
    /// the terminator belongs; only the declared range is read.
    #[test]
    fn oversized_body_reports_malformed_terminator() {
        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            \r\n\
            1234567890\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(matches!(
            reader.next(),
            Some(Err(Error::MalformedRecordTerminator))
        ));
    }

    /// The stream ends inside the record body.
    #[test]
    fn body_eof_mid_body() {
        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 10\r\n\
            \r\n\
            12";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(matches!(reader.next(), Some(Err(Error::UnexpectedEOB))));
    }

    /// The stream ends inside the record terminator.
    #[test]
    fn body_eof_mid_terminator() {
        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            \r\n\
            12345\r\n";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(matches!(reader.next(), Some(Err(Error::UnexpectedEOB))));
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

        let expected_headers = RawRecordHeader::from_fields(
            crate::WarcVersion::V1_0,
            [
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ],
        );
        let expected_body: &[u8] = b"12345";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        let (headers, body) = reader.next().unwrap().unwrap();
        assert_eq!(headers, expected_headers);
        assert_eq!(body, expected_body);

        // Names are equal whatever their spelling, so the comparison above says nothing about
        // how they were spelled; each is in fact kept exactly as it was read.
        assert_eq!(
            headers.names().map(FieldName::name).collect::<Vec<_>>(),
            ["Warc-Type", "Content-Length", "WARC-Record-Id", "WARC-Date"]
        );
    }

    /// The WARC 1.0 defined-field registry does not include either of the fields added in
    /// WARC 1.1.
    #[test]
    fn warc_1_0_reading_rejects_warc_1_1_headers() {
        let cases: &[(&[u8], WarcHeader)] = &[
            (
                b"\
                    WARC/1.0\r\n\
                    WARC-Type: revisit\r\n\
                    Content-Length: 0\r\n\
                    WARC-Record-ID: <urn:test:warc-1.0-field:record-0>\r\n\
                    WARC-Date: 2020-07-08T02:52:55Z\r\n\
                    WARC-Refers-To-Date: 2020-07-07T02:52:55Z\r\n\
                    \r\n\
                    \r\n\
                    \r\n\
                ",
                WarcHeader::RefersToDate,
            ),
            (
                b"\
                    WARC/1.0\r\n\
                    WARC-Type: revisit\r\n\
                    Content-Length: 0\r\n\
                    WARC-Record-ID: <urn:test:warc-1.0-field:record-1>\r\n\
                    WARC-Date: 2020-07-08T02:52:55Z\r\n\
                    WARC-Refers-To-Target-URI: https://example.com/\r\n\
                    \r\n\
                    \r\n\
                    \r\n\
                ",
                WarcHeader::RefersToTargetURI,
            ),
        ];

        for (raw, expected_header) in cases {
            let result = WarcReader::new(create_reader!(raw))
                .iter_records()
                .next()
                .unwrap();
            match result {
                Err(Error::MalformedHeader(actual_header, _)) => {
                    assert_eq!(&actual_header, expected_header);
                }
                other => panic!("expected a version error for {expected_header}, got {other:?}"),
            }
        }
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

    /// A stream that ends in the middle of a header block is truncated input, not a clean
    /// end-of-archive.
    #[test]
    fn truncated_header_block_is_an_error() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Le\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::UnexpectedEOH) => {}
            other => panic!(
                "expected an error for a truncated header block, got {:?}",
                other.map(|(headers, _)| headers)
            ),
        }
    }

    /// A file written with bare-`\n` line endings never matches the `\r\n` framing the
    /// standard requires, and must be reported as an error rather than reading as an empty
    /// archive.
    #[test]
    fn bare_lf_line_endings_are_an_error() {
        let raw = b"\
            WARC/1.0\n\
            Warc-Type: dunno\n\
            Content-Length: 5\n\
            \n\
            12345\n\
            \n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        match reader.next().unwrap() {
            Err(Error::UnexpectedEOH) => {}
            other => panic!(
                "expected an error for bare-LF line endings, got {:?}",
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
            // The field lines are compared in the order they appear in the record.
            let expected_headers = RawRecordHeader::from_fields(
                crate::WarcVersion::V1_0,
                [
                    (WarcHeader::WarcType, b"dunno".to_vec()),
                    (WarcHeader::ContentLength, b"5".to_vec()),
                    (
                        WarcHeader::RecordID,
                        b"<urn:test:two-records:record-0>".to_vec(),
                    ),
                    (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
                ],
            );
            let expected_body: &[u8] = b"12345";

            let (headers, body) = reader.next().unwrap().unwrap();
            assert_eq!(headers, expected_headers);
            assert_eq!(body, expected_body);
        }

        {
            let expected_headers = RawRecordHeader::from_fields(
                crate::WarcVersion::V1_0,
                [
                    (WarcHeader::WarcType, b"another".to_vec()),
                    (
                        WarcHeader::RecordID,
                        b"<urn:test:two-records:record-1>".to_vec(),
                    ),
                    (WarcHeader::Date, b"2020-07-08T02:52:56Z".to_vec()),
                    (WarcHeader::ContentLength, b"6".to_vec()),
                ],
            );
            let expected_body: &[u8] = b"123456";

            let (headers, body) = reader.next().unwrap().unwrap();
            assert_eq!(headers, expected_headers);
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
                .get(&WarcHeader::Unknown("unfolded-test".to_owned()))
                .unwrap(),
            b"this value spans lines"
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
        assert_eq!(
            headers
                .get_all(&WarcHeader::ConcurrentTo)
                .collect::<Vec<_>>(),
            vec![
                &b"<urn:test:concurrent:record-1>"[..],
                &b"<urn:test:concurrent:record-2>"[..],
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
        assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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

    /// The streaming path reports truncated header blocks just as the buffered path does.
    #[test]
    fn streaming_truncated_header_block_is_an_error() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Le\
        ";

        let mut reader = WarcReader::new(create_reader!(raw));
        let mut stream_iter = reader.stream_records();

        match stream_iter.next_item().unwrap() {
            Err(Error::UnexpectedEOH) => {}
            other => panic!(
                "expected an error for a truncated header block, got {:?}",
                other.map(|record| record.content_length())
            ),
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
        assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
            assert_eq!(record.content_length(), 0);
            assert_eq!(record.warc_id(), "<urn:test:zero-content-length>");
            assert_eq!(record.body(), b"");
        }

        // Test the second record with non-zero Content-Length
        {
            let record = iter.next().unwrap().unwrap();
            assert_eq!(record.warc_version(), crate::WarcVersion::V1_0);
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

    /// A record whose body is complete but whose stream ends without a record terminator.
    const MISSING_TERMINATOR: &[u8] = b"\
        WARC/1.1\r\n\
        Warc-Type: dunno\r\n\
        Content-Length: 5\r\n\
        WARC-Record-Id: <urn:test:missing-terminator>\r\n\
        WARC-Date: 2020-07-08T02:52:55Z\r\n\
        \r\n\
        12345";

    /// A record followed by four bytes that are not `\r\n\r\n`.
    const MALFORMED_TERMINATOR: &[u8] = b"\
        WARC/1.1\r\n\
        Warc-Type: dunno\r\n\
        Content-Length: 5\r\n\
        WARC-Record-Id: <urn:test:malformed-terminator>\r\n\
        WARC-Date: 2020-07-08T02:52:55Z\r\n\
        \r\n\
        12345ABCD";

    #[test]
    fn into_buffered_errors_on_truncated_body() {
        let mut reader = WarcReader::new(create_reader!(TRUNCATED_BODY));
        let mut stream_iter = reader.stream_records();

        let record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(record.into_buffered(), Err(Error::UnexpectedEOB)));
    }

    #[test]
    fn into_buffered_errors_on_missing_terminator() {
        let mut reader = WarcReader::new(create_reader!(MISSING_TERMINATOR));
        let mut stream_iter = reader.stream_records();

        let record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(record.into_buffered(), Err(Error::UnexpectedEOB)));
    }

    #[test]
    fn into_buffered_errors_on_malformed_terminator() {
        let mut reader = WarcReader::new(create_reader!(MALFORMED_TERMINATOR));
        let mut stream_iter = reader.stream_records();

        let record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(
            record.into_buffered(),
            Err(Error::MalformedRecordTerminator)
        ));
    }

    /// A body streamed from outside a WARC file (via `add_fixed_stream`) has no terminator to
    /// verify, but a short stream is still reported.
    #[test]
    fn into_buffered_checks_truncation_for_external_streams() {
        use crate::{EmptyBody, Record};

        let mut complete: &[u8] = b"12345";
        let mut length = 5;
        let record = Record::<EmptyBody>::new()
            .add_fixed_stream(&mut complete, &mut length)
            .into_buffered()
            .unwrap();
        assert_eq!(record.body(), b"12345");

        let mut short: &[u8] = b"12";
        let mut length = 5;
        let result = Record::<EmptyBody>::new()
            .add_fixed_stream(&mut short, &mut length)
            .into_buffered();
        assert!(matches!(result, Err(Error::UnexpectedEOB)));
    }

    #[test]
    fn skip_errors_on_eof_mid_body() {
        let mut reader = WarcReader::new(create_reader!(TRUNCATED_BODY));
        let mut stream_iter = reader.stream_records();

        // Leave the first record's body unread so that the next call must skip it.
        let _record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(
            stream_iter.next_item(),
            Some(Err(Error::UnexpectedEOB))
        ));
    }

    #[test]
    fn skip_errors_on_missing_terminator() {
        let mut reader = WarcReader::new(create_reader!(MISSING_TERMINATOR));
        let mut stream_iter = reader.stream_records();

        let _record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(
            stream_iter.next_item(),
            Some(Err(Error::UnexpectedEOB))
        ));
    }

    #[test]
    fn skip_errors_on_malformed_terminator() {
        let mut reader = WarcReader::new(create_reader!(MALFORMED_TERMINATOR));
        let mut stream_iter = reader.stream_records();

        let _record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(
            stream_iter.next_item(),
            Some(Err(Error::MalformedRecordTerminator))
        ));
    }

    /// A reader that serves a prefix of valid data and then fails with an I/O error.
    struct FailingReader {
        data: Cursor<Vec<u8>>,
    }

    impl std::io::Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let available = std::io::BufRead::fill_buf(self)?;
            let read = available.len().min(buf.len());
            buf[..read].copy_from_slice(&available[..read]);
            std::io::BufRead::consume(self, read);

            Ok(read)
        }
    }

    impl std::io::BufRead for FailingReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.data.position() == self.data.get_ref().len() as u64 {
                return Err(std::io::Error::other("stream failed"));
            }

            std::io::BufRead::fill_buf(&mut self.data)
        }

        fn consume(&mut self, amt: usize) {
            std::io::BufRead::consume(&mut self.data, amt);
        }
    }

    #[test]
    fn skip_reports_io_errors() {
        let mut reader = FailingReader {
            data: Cursor::new(TRUNCATED_BODY.to_vec()),
        };
        let mut stream_iter = crate::warc_reader::StreamingIter::new(&mut reader);

        // The header block parses from the served prefix; skipping the unread body then hits
        // the I/O error.
        let _record = stream_iter.next_item().unwrap().unwrap();
        assert!(matches!(
            stream_iter.next_item(),
            Some(Err(Error::ReadData(_)))
        ));
    }

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
            .finish()
            .map_err(std::io::IntoInnerError::into_error)
            .unwrap();
        gzip_stream.finish().unwrap();

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
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            WarcWriter::new(&mut encoder)
                .write(&record(body, url))
                .unwrap();
            let member = encoder.finish().unwrap();
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
            .finish()
            .map_err(std::io::IntoInnerError::into_error)
            .unwrap();
        gzip_stream.finish().unwrap();

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
