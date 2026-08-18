//! Reading records from an optionally gzip-compressed WARC file.
//!
//! [`WarcReader`] returns records at any of the crate's three representation levels. Record bodies
//! are read fully into memory. The three `filter` iterators can inspect a header block and skip its
//! body without buffering it.

use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::path::Path;
use std::{fs, io};

#[cfg(feature = "gzip")]
use flate2::bufread::MultiGzDecoder as GzipReader;

use crate::io::MB;
use crate::parse::{raw, untyped};
use crate::record;
use crate::record::extension::{Extension, NoExtension};

/// The ways reading a record can fail.
///
/// Stream and raw framing failures leave the reader at an unknown position and stop iteration.
/// Errors at the untyped or semantic level affect only one record, so iteration can continue.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying read from the data source failed.
    #[error("Error reading data source.")]
    Source(#[from] std::io::Error),
    /// The record's header block exceeds the supported maximum size.
    #[error("Record header block too large.")]
    HeaderBlockTooLarge,
    /// The record's declared `Content-Length` is too large for its body to be buffered in memory
    /// on this platform.
    #[error("Record body too large to buffer.")]
    BodyTooLarge,
    /// The stream ended before the record's declared `Content-Length` was reached.
    #[error("Unexpected end of body.")]
    UnexpectedEndOfBody,
    /// The `\r\n\r\n` terminator after the record's body was missing or malformed. The record
    /// was read completely, but is invalid.
    #[error("Malformed record terminator.")]
    MalformedRecordTerminator,
    /// The octets read are not a record.
    #[error(transparent)]
    Raw(#[from] raw::Error),
    /// A field's value does not match the grammar its name selects.
    #[error(transparent)]
    Untyped(#[from] untyped::Error),
    /// The record is not one the standard, or the extension in force, permits.
    #[error(transparent)]
    Record(#[from] record::Error),
}

#[cfg(test)]
mod error_tests {
    use super::Error;
    use crate::parse::{raw, untyped};

    /// Stream errors use local messages; transparent variants use their source messages.
    #[test]
    fn each_error_states_its_failure() {
        let expectations = [
            (
                Error::Source(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                "Error reading data source.",
                true,
            ),
            (
                Error::HeaderBlockTooLarge,
                "Record header block too large.",
                false,
            ),
            (
                Error::BodyTooLarge,
                "Record body too large to buffer.",
                false,
            ),
            (Error::UnexpectedEndOfBody, "Unexpected end of body.", false),
            (
                Error::MalformedRecordTerminator,
                "Malformed record terminator.",
                false,
            ),
            (
                Error::Raw(raw::Error::MissingContentLength),
                "Missing Content-Length.",
                false,
            ),
            (
                Error::Untyped(untyped::Error {
                    name: "WARC-Date".to_owned(),
                    source: crate::value::Error::Date("yesterday".to_owned()),
                }),
                "Malformed WARC-Date field: not a timestamp: yesterday",
                true,
            ),
        ];

        for (error, message, has_source) in expectations {
            assert_eq!(error.to_string(), message);
            assert_eq!(
                std::error::Error::source(&error).is_some(),
                has_source,
                "{message}"
            );
        }
    }
}

/// A reader which iteratively parses WARC records from a stream.
pub struct WarcReader<R> {
    reader: R,
}

impl<R: BufRead> WarcReader<R> {
    /// Create a new reader.
    pub const fn new(r: R) -> Self {
        Self { reader: r }
    }

    /// Iterate over records at the raw level.
    ///
    /// Each record is a [`raw::Record`]: its field names and values are exactly the ones on
    /// the wire, checked only for the grammar of a header block and for the `Content-Length`
    /// that frames the body.
    pub fn iter_raw_records(self) -> RawIter<R> {
        RawIter::new(self.reader)
    }

    /// Iterate over records at the untyped level.
    ///
    /// Field values are parsed against their grammars, but semantic rules for the declared version
    /// and record type are not checked.
    pub fn iter_untyped_records(self) -> UntypedIter<R> {
        UntypedIter::new(self.reader)
    }

    /// Iterate over records at the semantic level.
    ///
    /// Each record is a [`record::Record<E>`](record::Record), with its fields checked against the
    /// rules for its record type and its declared version. `E` is the extension in force, which
    /// decides the record types, truncation reasons, and fields beyond the ones the standard
    /// defines; [`NoExtension`] is the standard alone. `E` must be named at the call site:
    ///
    /// ```
    /// use archivindex_warc::io::read::WarcReader;
    /// use archivindex_warc::record::extension::NoExtension;
    ///
    /// let archive = b"\
    ///     WARC/1.1\r\n\
    ///     WARC-Type: resource\r\n\
    ///     WARC-Record-ID: <urn:uuid:d0e6a1a0-0000-4000-8000-000000000000>\r\n\
    ///     WARC-Date: 2024-04-01T12:00:00Z\r\n\
    ///     WARC-Target-URI: https://example.com/\r\n\
    ///     Content-Length: 5\r\n\
    ///     \r\n\
    ///     hello\r\n\
    ///     \r\n";
    ///
    /// let reader = WarcReader::new(&archive[..]);
    /// let records = reader
    ///     .iter_records::<NoExtension>()
    ///     .collect::<Result<Vec<_>, _>>()?;
    ///
    /// assert_eq!(records[0].type_name(), "resource");
    /// # Ok::<(), archivindex_warc::io::read::Error>(())
    /// ```
    pub fn iter_records<E: Extension>(self) -> RecordIter<R, E> {
        RecordIter::new(self.reader)
    }

    /// Iterate over records accepted by a predicate at the raw level.
    ///
    /// The predicate is shown each record's header block and decides whether the record is wanted.
    /// The body of a refused record is consumed without being buffered, so an archive can be
    /// searched by its header blocks alone.
    pub fn filter_raw_records<F: FnMut(&raw::RecordHeader) -> bool>(
        self,
        filter: F,
    ) -> FilterRawIter<R, F> {
        FilterRawIter {
            reading: Reading::new(self.reader),
            filter,
        }
    }

    /// Iterate over records accepted by a predicate at the untyped level.
    ///
    /// The predicate is shown a header block whose fields have already been parsed against the
    /// grammar, so it decides on typed values rather than on raw bytes. The body of a refused
    /// record is consumed without being buffered.
    pub fn filter_untyped_records<F: FnMut(&untyped::RecordHeader) -> bool>(
        self,
        filter: F,
    ) -> FilterUntypedIter<R, F> {
        FilterUntypedIter {
            reading: Reading::new(self.reader),
            filter,
        }
    }

    /// Iterate over records accepted by a predicate at the semantic level.
    ///
    /// The predicate is shown a [`record::RecordHeader<E>`](record::RecordHeader): the header
    /// block checked against the rules for its record type and its declared version. The body of a
    /// refused record is consumed without being buffered.
    ///
    /// `E` is the extension in force, as for [`iter_records`](Self::iter_records). It must be
    /// named at the call site, along with a `_` for the predicate's type:
    /// `filter_records::<NoExtension, _>(..)`.
    pub fn filter_records<E: Extension, F: FnMut(&record::RecordHeader<E>) -> bool>(
        self,
        filter: F,
    ) -> FilterRecordIter<R, F, E> {
        FilterRecordIter {
            reading: Reading::new(self.reader),
            filter,
            extension: PhantomData,
        }
    }
}

impl WarcReader<BufReader<fs::File>> {
    /// Create a reader for a file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(&path)?;

        let reader = BufReader::with_capacity(MB, file);

        Ok(Self::new(reader))
    }
}

#[cfg(feature = "gzip")]
#[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
impl WarcReader<BufReader<GzipReader<BufReader<fs::File>>>> {
    /// Create a reader for a gzip-compressed file.
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(&path)?;

        let gzip_stream = GzipReader::new(BufReader::with_capacity(MB, file));
        Ok(Self::new(BufReader::new(gzip_stream)))
    }
}

/// The limit for a buffered header block.
///
/// The standard sets no limit, but a bound prevents unending input from exhausting memory.
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
            Err(io) => return Err(Error::Source(io)),
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
                return Some(Err(Error::Raw(raw::Error::UnexpectedEndOfHeaderBlock)));
            }
            Ok(LineRead::LimitExceeded) => return Some(Err(Error::HeaderBlockTooLarge)),
            Ok(LineRead::Line(2)) if header_buffer.ends_with(b"\r\n") => return Some(Ok(())),
            Ok(LineRead::Line(_)) => {}
        }
    }
}

/// Read a record body of the given length, plus the `\r\n\r\n` record terminator.
fn read_body<R: BufRead>(reader: &mut R, expected_body_len: u64) -> Result<Vec<u8>, Error> {
    // The body plus its 4-byte terminator must fit in a single in-memory buffer. A length for
    // which that is impossible (a hostile value near the platform maximum, or a >4 GiB record
    // on a 32-bit target) is rejected up front, rather than overflowing the arithmetic below.
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
            Err(io) => return Err(Error::Source(io)),
            Ok(available) => available,
        };
        if available.is_empty() {
            return Err(Error::UnexpectedEndOfBody);
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

/// Consume a record body of the given length, plus the `\r\n\r\n` record terminator, without
/// buffering any of it.
///
/// The terminator is checked exactly as [`read_body`] checks it, so a record whose body outruns
/// its declared length is an error whether or not the body was wanted. Nothing is allocated for
/// the body, so even a length too large to buffer can be skipped.
fn skip_body<R: BufRead>(reader: &mut R, expected_body_len: u64) -> Result<(), Error> {
    let mut remaining = expected_body_len;
    while remaining > 0 {
        let available = match reader.fill_buf() {
            Err(io) => return Err(Error::Source(io)),
            Ok(available) => available,
        };
        if available.is_empty() {
            return Err(Error::UnexpectedEndOfBody);
        }

        // `remaining` may exceed what a `usize` can hold, so the minimum is taken in the wider
        // type before narrowing.
        let taken = available
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        reader.consume(taken);
        remaining -= taken as u64;
    }

    let mut terminator = [0; 4];
    match reader.read_exact(&mut terminator) {
        Err(io) if io.kind() == io::ErrorKind::UnexpectedEof => Err(Error::UnexpectedEndOfBody),
        Err(io) => Err(Error::Source(io)),
        Ok(()) if terminator != *b"\r\n\r\n" => Err(Error::MalformedRecordTerminator),
        Ok(()) => Ok(()),
    }
}

/// The stream, reusable header buffer, and error state shared by all iterators in this module.
struct Reading<R> {
    reader: R,
    /// Set once the input has ended or an error has been yielded. Every error here is
    /// stream-level: it leaves the reader at an unspecified position, so iteration fuses rather
    /// than yielding garbage records from the middle of a partly consumed one.
    finished: bool,
    header_buffer: Vec<u8>,
}

impl<R: BufRead> Reading<R> {
    const fn new(reader: R) -> Self {
        Self {
            reader,
            finished: false,
            header_buffer: Vec::new(),
        }
    }

    /// The next record's header block, and the body length its `Content-Length` declares.
    ///
    /// Returns `None` at a clean end of stream, and thereafter. The body must be read or
    /// skipped before this is called again.
    fn next_header(&mut self) -> Option<Result<(raw::RecordHeader, u64), Error>> {
        if self.finished {
            return None;
        }

        match read_header_block(&mut self.reader, &mut self.header_buffer) {
            None => {
                self.finished = true;
                None
            }
            Some(Err(error)) => {
                self.finished = true;
                Some(Err(error))
            }
            Some(Ok(())) => {
                let parsed = raw::RecordHeader::parse(&self.header_buffer).map_err(Error::Raw);

                Some(self.fuse_on_error(parsed))
            }
        }
    }

    /// Read the body a header declared, buffering it.
    fn read_body(&mut self, expected_body_len: u64) -> Result<Vec<u8>, Error> {
        let body = read_body(&mut self.reader, expected_body_len);

        self.fuse_on_error(body)
    }

    /// Consume the body a header declared without buffering it.
    fn skip_body(&mut self, expected_body_len: u64) -> Result<(), Error> {
        let skipped = skip_body(&mut self.reader, expected_body_len);

        self.fuse_on_error(skipped)
    }

    /// The next record, header block and body together.
    fn next_record(&mut self) -> Option<Result<raw::Record, Error>> {
        let (header, expected_body_len) = match self.next_header()? {
            Ok(header) => header,
            Err(error) => return Some(Err(error)),
        };

        Some(
            self.read_body(expected_body_len)
                .map(|body| header.with_body(body)),
        )
    }

    /// Stop iteration if a read failed, since where the reader is left is not known.
    const fn fuse_on_error<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.finished = true;
        }

        result
    }
}

/// An iterator over the records of a reader, at the raw level.
///
/// After an I/O or framing error the underlying reader is at an unspecified position, so the
/// iterator is fused: every further call returns `None`.
pub struct RawIter<R> {
    reading: Reading<R>,
}

impl<R: BufRead> RawIter<R> {
    const fn new(reader: R) -> Self {
        Self {
            reading: Reading::new(reader),
        }
    }
}

impl<R: BufRead> Iterator for RawIter<R> {
    type Item = Result<raw::Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reading.next_record()
    }
}

/// An iterator over the records of a reader, at the untyped level.
///
/// After an I/O or framing error the underlying reader is at an unspecified position, so the
/// iterator is fused: every further call returns `None`. A field value that does not match its
/// grammar is a record-level error: the record is consumed completely, so iteration continues
/// with the next one.
pub struct UntypedIter<R> {
    raw: RawIter<R>,
}

impl<R: BufRead> UntypedIter<R> {
    const fn new(reader: R) -> Self {
        Self {
            raw: RawIter::new(reader),
        }
    }
}

impl<R: BufRead> Iterator for UntypedIter<R> {
    type Item = Result<untyped::Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.raw
                .next()?
                .and_then(|record| Ok(untyped::Record::try_from(record)?)),
        )
    }
}

/// An iterator over the records of a reader, at the semantic level.
///
/// `E` is the extension in force. A record the standard does not permit is a record-level error,
/// so iteration continues with the next one; the iterator fuses only where [`UntypedIter`] does.
pub struct RecordIter<R, E = NoExtension> {
    untyped: UntypedIter<R>,
    /// The extension is carried as a marker rather than a value. The function type keeps `E`
    /// from affecting the iterator's auto traits.
    extension: PhantomData<fn() -> E>,
}

impl<R: BufRead, E: Extension> RecordIter<R, E> {
    const fn new(reader: R) -> Self {
        Self {
            untyped: UntypedIter::new(reader),
            extension: PhantomData,
        }
    }
}

impl<R: BufRead, E: Extension> Iterator for RecordIter<R, E> {
    type Item = Result<record::Record<E>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.untyped
                .next()?
                .and_then(|record| Ok(record::Record::try_from(record)?)),
        )
    }
}

/// An iterator over the records a predicate keeps, at the raw level.
///
/// The body of a record the predicate refuses is consumed without being buffered.
pub struct FilterRawIter<R, F> {
    reading: Reading<R>,
    filter: F,
}

impl<R: BufRead, F: FnMut(&raw::RecordHeader) -> bool> Iterator for FilterRawIter<R, F> {
    type Item = Result<raw::Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (header, expected_body_len) = match self.reading.next_header()? {
                Ok(header) => header,
                Err(error) => return Some(Err(error)),
            };

            if (self.filter)(&header) {
                return Some(
                    self.reading
                        .read_body(expected_body_len)
                        .map(|body| header.with_body(body)),
                );
            }

            if let Err(error) = self.reading.skip_body(expected_body_len) {
                return Some(Err(error));
            }
        }
    }
}

/// An iterator over the records a predicate keeps, at the untyped level.
///
/// The predicate decides on a header block that has already been parsed against the grammar, so a
/// header block that fails to parse is a record-level error: the body is consumed before the
/// error is yielded, leaving the reader at the next record.
pub struct FilterUntypedIter<R, F> {
    reading: Reading<R>,
    filter: F,
}

impl<R: BufRead, F: FnMut(&untyped::RecordHeader) -> bool> Iterator for FilterUntypedIter<R, F> {
    type Item = Result<untyped::Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (header, expected_body_len) = match self.reading.next_header()? {
                Ok(header) => header,
                Err(error) => return Some(Err(error)),
            };

            let header = match untyped::RecordHeader::try_from(header) {
                Ok(header) => header,
                // When both fail, the stream-level failure is the one to report, since it says
                // why nothing further can be read.
                Err(malformed) => {
                    return Some(Err(match self.reading.skip_body(expected_body_len) {
                        Ok(()) => malformed.into(),
                        Err(interrupted) => interrupted,
                    }));
                }
            };

            if (self.filter)(&header) {
                return Some(
                    self.reading
                        .read_body(expected_body_len)
                        .map(|body| header.with_body(body)),
                );
            }

            if let Err(error) = self.reading.skip_body(expected_body_len) {
                return Some(Err(error));
            }
        }
    }
}

/// An iterator over the records a predicate keeps, at the semantic level.
///
/// `E` is the extension in force. The predicate decides on a header block that has already been
/// lifted, so a header block the standard refuses is a record-level error, just like one the
/// grammar refuses: the body is consumed before the error is yielded, leaving the reader at the
/// next record.
pub struct FilterRecordIter<R, F, E = NoExtension> {
    reading: Reading<R>,
    filter: F,
    /// The extension is carried as a marker rather than a value. The function type keeps `E`
    /// from affecting the iterator's auto traits.
    extension: PhantomData<fn() -> E>,
}

impl<R: BufRead, E: Extension, F: FnMut(&record::RecordHeader<E>) -> bool> Iterator
    for FilterRecordIter<R, F, E>
{
    type Item = Result<record::Record<E>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (header, expected_body_len) = match self.reading.next_header()? {
                Ok(header) => header,
                Err(error) => return Some(Err(error)),
            };

            let lifted = untyped::RecordHeader::try_from(header)
                .map_err(Error::Untyped)
                .and_then(|header| record::RecordHeader::try_from(header).map_err(Error::Record));

            let header = match lifted {
                Ok(header) => header,
                // When both fail, the stream-level failure is the one to report, since it says
                // why nothing further can be read.
                Err(refused) => {
                    return Some(Err(match self.reading.skip_body(expected_body_len) {
                        Ok(()) => refused,
                        Err(interrupted) => interrupted,
                    }));
                }
            };

            if (self.filter)(&header) {
                return Some(self.reading.read_body(expected_body_len).and_then(|body| {
                    header
                        .with_body(body)
                        .map_err(|block| Error::Record(block.into()))
                }));
            }

            if let Err(error) = self.reading.skip_body(expected_body_len) {
                return Some(Err(error));
            }
        }
    }
}

#[cfg(test)]
mod from_path_tests {
    use super::WarcReader;
    use crate::parse::untyped::name::Field;

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
        let record = reader.iter_untyped_records().next().unwrap().unwrap();

        assert_eq!(
            record
                .header
                .get(Field::RecordID)
                .unwrap()
                .form()
                .unwrap()
                .to_string(),
            "<urn:test:from-path:record-0>"
        );
        assert_eq!(record.body, b"12345");
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

    use super::{Error, WarcReader};
    use crate::parse::untyped::name::Field;
    use crate::parse::{raw, untyped};

    macro_rules! create_reader {
        ($raw:expr) => {{ BufReader::new(Cursor::new($raw.get(..).unwrap())) }};
    }

    /// The first record a reader yields.
    macro_rules! first {
        ($raw:expr) => {{
            WarcReader::new(create_reader!($raw))
                .iter_raw_records()
                .next()
                .unwrap()
        }};
    }

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

        assert!(matches!(first!(raw), Err(Error::MalformedRecordTerminator)));
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
        assert!(matches!(
            reader.next(),
            Some(Err(Error::MalformedRecordTerminator))
        ));
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
    }

    /// After the final `None`, further calls keep returning `None` rather than reading the
    /// terminator of the record already yielded as though it opened another one.
    #[test]
    fn the_iterators_stay_exhausted_after_a_clean_end() {
        let raw = b"\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:exhausted:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut raw_iter = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(raw_iter.next().unwrap().is_ok());
        for _ in 0..3 {
            assert!(raw_iter.next().is_none());
        }

        let mut untyped_iter = WarcReader::new(create_reader!(raw)).iter_untyped_records();
        assert!(untyped_iter.next().unwrap().is_ok());
        for _ in 0..3 {
            assert!(untyped_iter.next().is_none());
        }
    }

    /// A stream that never terminates its header block is stopped at the size bound instead of
    /// being buffered without limit.
    #[test]
    fn oversized_header_block_without_newlines() {
        let raw = vec![b'A'; 2 * crate::io::MB];

        assert!(matches!(first!(raw), Err(Error::HeaderBlockTooLarge)));
    }

    /// The header-block bound also applies to a block of well-formed lines that never ends.
    #[test]
    fn oversized_header_block_with_newlines() {
        let mut raw = b"WARC/1.1\r\n".to_vec();
        while raw.len() <= 2 * crate::io::MB {
            raw.extend_from_slice(b"a: b\r\n");
        }

        assert!(matches!(first!(raw), Err(Error::HeaderBlockTooLarge)));
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

        assert!(matches!(first!(raw), Err(Error::MalformedRecordTerminator)));
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

        assert!(matches!(first!(raw), Err(Error::UnexpectedEndOfBody)));
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

        assert!(matches!(first!(raw), Err(Error::UnexpectedEndOfBody)));
    }

    /// Every field line is kept as it was written: the name in its own spelling, the value
    /// with the white space around it, and all of them in the order they appeared.
    #[test]
    fn basic_record() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length:5\r\n\
            WARC-Record-Id: <urn:test:basic-record:record-0>\r\n\
            WARC-Date:  2020-07-08T02:52:55Z \r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let record = first!(raw).unwrap();

        assert_eq!(record.header.version, crate::version::WarcVersion::V1_0);
        assert_eq!(record.body, b"12345");
        assert_eq!(
            record.header.headers,
            vec![
                ("Warc-Type".to_owned(), b" dunno".to_vec()),
                ("Content-Length".to_owned(), b"5".to_vec()),
                (
                    "WARC-Record-Id".to_owned(),
                    b" <urn:test:basic-record:record-0>".to_vec()
                ),
                ("WARC-Date".to_owned(), b"  2020-07-08T02:52:55Z ".to_vec()),
            ]
        );
    }

    /// A folded value is kept fold and all, preserving the bytes the record was written with.
    #[test]
    fn folded_header_value_is_kept_verbatim() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: metadata\r\n\
            Content-Length: 0\r\n\
            Unfolded-Test: this value\r\n\
            \tspans lines\r\n\
            \r\n\
            \r\n\
            \r\n\
        ";

        let record = first!(raw).unwrap();

        assert!(record.body.is_empty());
        assert_eq!(
            record.header.get("unfolded-test").unwrap(),
            b" this value\r\n\tspans lines"
        );
    }

    /// The raw level keeps lines that the semantic level would refuse (a repeated field, a field
    /// the declared version does not define), so archives holding such records can still be read
    /// and rewritten.
    #[test]
    fn reading_keeps_what_the_semantic_layer_will_refuse() {
        let raw = b"\
            WARC/1.0\r\n\
            WARC-Type: revisit\r\n\
            Content-Length: 0\r\n\
            WARC-Date: 2020-07-08T02:52:55.123456Z\r\n\
            WARC-Refers-To-Date: 2020-07-07T02:52:55Z\r\n\
            WARC-Target-URI: https://example.com/first\r\n\
            WARC-Target-URI: https://example.com/second\r\n\
            \r\n\
            \r\n\
            \r\n\
        ";

        // The untyped level reads it too: a sub-second date and a field WARC 1.1 added are both
        // well formed, whatever the record's declared version allows.
        let record = WarcReader::new(create_reader!(raw))
            .iter_untyped_records()
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(
            record
                .header
                .get_all(Field::TargetURI)
                .map(|value| value.form().unwrap().to_string())
                .collect::<Vec<_>>(),
            ["https://example.com/first", "https://example.com/second"]
        );
        assert_eq!(
            record
                .header
                .get(Field::Date)
                .unwrap()
                .form()
                .unwrap()
                .to_string(),
            "2020-07-08T02:52:55.123456Z"
        );
        assert!(record.header.get(Field::RefersToDate).is_some());
    }

    /// A field line that is not `field-name ":" field-value` is rejected with an error
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

        match first!(raw) {
            Err(Error::Raw(raw::Error::MalformedFieldLine(line))) => {
                assert_eq!(line, "bad header line without a colon");
            }
            other => panic!("expected an error naming the malformed line, got {other:?}"),
        }
    }

    /// A field whose value does not match the grammar its name selects is a record-level
    /// error: the record is consumed completely, so reading continues with the next one.
    #[test]
    fn record_iter_continues_after_a_malformed_value() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Date: the day before yesterday\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:after-malformed:record-1>\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_untyped_records();

        match reader.next().unwrap() {
            Err(Error::Untyped(untyped::Error { name, .. })) => assert_eq!(name, "WARC-Date"),
            other => panic!("expected an error naming the malformed field, got {other:?}"),
        }

        let record = reader.next().unwrap().unwrap();
        assert_eq!(
            record
                .header
                .get(Field::RecordID)
                .unwrap()
                .form()
                .unwrap()
                .to_string(),
            "<urn:test:after-malformed:record-1>"
        );
        assert!(reader.next().is_none());
    }

    /// A record without `Content-Length` cannot be framed; it is rejected with an error naming
    /// the missing field rather than misread as having an empty body.
    #[test]
    fn missing_content_length_is_rejected() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            WARC-Record-ID: <urn:test:missing-length:record-0>\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        assert!(matches!(
            first!(raw),
            Err(Error::Raw(raw::Error::MissingContentLength))
        ));
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

        assert!(matches!(first!(raw), Err(Error::BodyTooLarge)));
    }

    /// A `Content-Length` value beyond the unsigned 64-bit range is not a length at all, so
    /// the record cannot be framed.
    #[test]
    fn content_length_beyond_u64_is_rejected() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: dunno\r\n\
            Content-Length: 99999999999999999999999999\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        assert!(matches!(
            first!(raw),
            Err(Error::Raw(raw::Error::MalformedContentLength(_)))
        ));
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

        assert!(matches!(
            first!(raw),
            Err(Error::Raw(raw::Error::UnexpectedEndOfHeaderBlock))
        ));
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

        assert!(matches!(
            first!(raw),
            Err(Error::Raw(raw::Error::UnexpectedEndOfHeaderBlock))
        ));
    }

    #[test]
    fn two_records() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:two-records:record-0>\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.1\r\n\
            Warc-Type: another\r\n\
            WARC-Record-Id: <urn:test:two-records:record-1>\r\n\
            Content-Length: 6\r\n\
            \r\n\
            123456\r\n\
            \r\n\
        ";

        let records = WarcReader::new(create_reader!(raw))
            .iter_raw_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].header.version, crate::version::WarcVersion::V1_0);
        assert_eq!(records[0].body, b"12345");
        assert_eq!(
            records[0].header.get("warc-record-id"),
            Some(&b" <urn:test:two-records:record-0>"[..])
        );
        assert_eq!(records[1].header.version, crate::version::WarcVersion::V1_1);
        assert_eq!(records[1].body, b"123456");
        assert_eq!(
            records[1].header.get("warc-record-id"),
            Some(&b" <urn:test:two-records:record-1>"[..])
        );
    }

    /// A record may declare no body at all, and the blank line that would hold one is the
    /// terminator of that record rather than the opening of the next.
    #[test]
    fn an_empty_body_is_framed_like_any_other() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: empty-record\r\n\
            Content-Length: 0\r\n\
            WARC-Record-Id: <urn:test:empty-body:record-0>\r\n\
            \r\n\
            \r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: non-empty-record\r\n\
            Content-Length: 7\r\n\
            WARC-Record-Id: <urn:test:empty-body:record-1>\r\n\
            \r\n\
            1234567\r\n\
            \r\n\
        ";

        let records = WarcReader::new(create_reader!(raw))
            .iter_raw_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].body, b"");
        assert_eq!(
            records[0].header.get("warc-record-id"),
            Some(&b" <urn:test:empty-body:record-0>"[..])
        );
        assert_eq!(records[1].body, b"1234567");
        assert_eq!(
            records[1].header.get("warc-record-id"),
            Some(&b" <urn:test:empty-body:record-1>"[..])
        );
    }
}

#[cfg(test)]
mod filter_tests {
    use super::{Error, WarcReader};
    use crate::parse::untyped;
    use crate::parse::untyped::name::Field;
    use crate::parse::untyped::value::HeaderValue;
    use crate::record::extension::NoExtension;

    /// Three records whose bodies name them, so a body read after a skip that went wrong cannot
    /// pass for the body of another record.
    const THREE_RECORDS: &[u8] = b"\
        WARC/1.1\r\n\
        WARC-Type: resource\r\n\
        WARC-Record-ID: <urn:test:filter:record-0>\r\n\
        WARC-Date: 2020-07-08T02:52:55Z\r\n\
        WARC-Target-URI: https://example.com/first\r\n\
        Content-Length: 5\r\n\
        \r\n\
        first\r\n\
        \r\n\
        WARC/1.1\r\n\
        WARC-Type: resource\r\n\
        WARC-Record-ID: <urn:test:filter:record-1>\r\n\
        WARC-Date: 2020-07-08T02:52:56Z\r\n\
        WARC-Target-URI: https://example.com/second\r\n\
        Content-Length: 6\r\n\
        \r\n\
        second\r\n\
        \r\n\
        WARC/1.1\r\n\
        WARC-Type: resource\r\n\
        WARC-Record-ID: <urn:test:filter:record-2>\r\n\
        WARC-Date: 2020-07-08T02:52:57Z\r\n\
        WARC-Target-URI: https://example.com/third\r\n\
        Content-Length: 5\r\n\
        \r\n\
        third\r\n\
        \r\n\
    ";

    /// Every record's header block is offered, and only the kept records are read whole.
    #[test]
    fn filter_raw_yields_only_the_records_it_keeps() {
        let mut offered = 0;
        let bodies = WarcReader::new(THREE_RECORDS)
            .filter_raw_records(|header| {
                offered += 1;
                header
                    .get("WARC-Target-URI")
                    .is_some_and(|uri| !uri.ends_with(b"first"))
            })
            .map(|record| record.unwrap().body)
            .collect::<Vec<_>>();

        assert_eq!(bodies, [b"second".to_vec(), b"third".to_vec()]);
        assert_eq!(offered, 3);
    }

    /// A record the predicate refuses is framed exactly as a kept one is, so a body that
    /// outruns its declared length is an error whether or not the body was wanted.
    #[test]
    fn filter_raw_checks_a_skipped_record_terminator() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            Content-Length: 5\r\n\
            \r\n\
            1234567890\r\n\
            \r\n\
        ";

        let mut records = WarcReader::new(&raw[..]).filter_raw_records(|_| false);

        assert!(matches!(
            records.next(),
            Some(Err(Error::MalformedRecordTerminator))
        ));
        assert!(records.next().is_none());
    }

    /// The predicate decides on parsed values rather than on raw bytes.
    #[test]
    fn filter_untyped_decides_on_a_read_value() {
        let record_ids = WarcReader::new(THREE_RECORDS)
            .filter_untyped_records(|header| {
                header
                    .get(Field::TargetURI)
                    .and_then(HeaderValue::form)
                    .is_some_and(|uri| uri.to_string().ends_with("third"))
            })
            .map(|record| {
                record
                    .unwrap()
                    .header
                    .get(Field::RecordID)
                    .unwrap()
                    .form()
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(record_ids, ["<urn:test:filter:record-2>"]);
    }

    /// A header block the grammar refuses is a record-level error: its body is consumed before
    /// the error is yielded, so the record after it is still read.
    #[test]
    fn filter_untyped_continues_after_a_malformed_header() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            Content-Length: 5\r\n\
            WARC-Date: the day before yesterday\r\n\
            \r\n\
            first\r\n\
            \r\n\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:after-malformed:record-1>\r\n\
            Content-Length: 6\r\n\
            \r\n\
            second\r\n\
            \r\n\
        ";

        let mut records = WarcReader::new(&raw[..]).filter_untyped_records(|_| true);

        match records.next().unwrap() {
            Err(Error::Untyped(untyped::Error { name, .. })) => assert_eq!(name, "WARC-Date"),
            other => panic!("expected an error naming the malformed field, got {other:?}"),
        }

        assert_eq!(records.next().unwrap().unwrap().body, b"second");
        assert!(records.next().is_none());
    }

    /// The predicate decides on the typed fields of a lifted header.
    #[test]
    fn filter_records_decides_on_a_lifted_header() {
        let record_ids = WarcReader::new(THREE_RECORDS)
            .filter_records::<NoExtension, _>(|header| {
                header
                    .target_uri()
                    .is_some_and(|uri| uri.as_str().ends_with("second"))
            })
            .map(|record| record.unwrap().core().record_id.as_str().to_owned())
            .collect::<Vec<_>>();

        assert_eq!(record_ids, ["urn:test:filter:record-1"]);
    }

    /// A header block the standard refuses is a record-level error, exactly as one the grammar
    /// refuses is: its body is consumed before the error is yielded, so the record after it is
    /// still read.
    #[test]
    fn filter_records_continues_after_a_header_the_standard_refuses() {
        // A resource record must name what it is a resource of, and the first one does not.
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:refused:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            Content-Length: 5\r\n\
            \r\n\
            first\r\n\
            \r\n\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:refused:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:56Z\r\n\
            WARC-Target-URI: https://example.com/second\r\n\
            Content-Length: 6\r\n\
            \r\n\
            second\r\n\
            \r\n\
        ";

        let mut offered = 0;
        let mut records = WarcReader::new(&raw[..]).filter_records::<NoExtension, _>(|_| {
            offered += 1;
            true
        });

        assert!(matches!(records.next(), Some(Err(Error::Record(_)))));
        assert_eq!(
            records.next().unwrap().unwrap().body_bytes().as_ref(),
            b"second"
        );
        assert!(records.next().is_none());
        // The refused record never reached the predicate.
        assert_eq!(offered, 1);
    }
}

#[cfg(test)]
mod iter_records_tests {
    use super::{Error, WarcReader};
    use crate::record::extension::{Extension, ExtensionRecordType, Never, NoExtension};
    use crate::record::{BlockError, Record};

    /// A record of a type the standard does not name, which only an extension can lift.
    const SITEMAP_RECORD: &[u8] = b"\
        WARC/1.1\r\n\
        WARC-Type: sitemap\r\n\
        WARC-Record-ID: <urn:test:extension:record-0>\r\n\
        WARC-Date: 2020-07-08T02:52:55Z\r\n\
        Content-Length: 5\r\n\
        \r\n\
        hello\r\n\
        \r\n\
    ";

    /// An extension that defines one record type and nothing else.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Sitemaps;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SitemapType;

    impl ExtensionRecordType for SitemapType {
        fn type_name(&self) -> &'static str {
            "sitemap"
        }

        fn from_type_name(name: &str) -> Option<Self> {
            name.eq_ignore_ascii_case("sitemap").then_some(Self)
        }
    }

    impl Extension for Sitemaps {
        type Types = SitemapType;
        type TruncatedReasons = Never;
        type WarcinfoFields = ();
        type ResponseFields = ();
        type ResourceFields = ();
        type RequestFields = ();
        type MetadataFields = ();
        type RevisitFields = ();
        type ConversionFields = ();
        type ContinuationFields = ();
    }

    /// Reading walks all three levels in one call.
    #[test]
    fn lifts_the_records_it_reads() {
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:lifted:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            WARC-Target-URI: https://example.com/\r\n\
            Content-Length: 5\r\n\
            \r\n\
            hello\r\n\
            \r\n\
        ";

        let record = WarcReader::new(&raw[..])
            .iter_records::<NoExtension>()
            .next()
            .unwrap()
            .unwrap();

        let Record::Resource { header, body } = record else {
            panic!("not a resource");
        };
        assert_eq!(header.target_uri, "https://example.com/");
        assert_eq!(header.core.record_id, "urn:test:lifted:record-0");
        assert_eq!(body, b"hello");
    }

    /// A record the standard does not permit is a record-level error, which leaves the record
    /// consumed completely, so reading continues with the next one.
    #[test]
    fn continues_after_a_record_the_standard_refuses() {
        // A resource record must name what it is a resource of, and this one does not.
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:refused:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            Content-Length: 5\r\n\
            \r\n\
            first\r\n\
            \r\n\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:refused:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            WARC-Target-URI: https://example.com/\r\n\
            Content-Length: 6\r\n\
            \r\n\
            second\r\n\
            \r\n\
        ";

        let mut records = WarcReader::new(&raw[..]).iter_records::<NoExtension>();

        assert!(matches!(records.next(), Some(Err(Error::Record(_)))));
        assert_eq!(records.next().unwrap().unwrap().type_name(), "resource");
        assert!(records.next().is_none());
    }

    /// Invalid digests are preserved at every reading layer and reported by the semantic record.
    #[test]
    fn reads_a_block_digest_the_block_does_not_have() {
        // The declared value is SHA-1 of an empty block.
        let raw = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            WARC-Record-ID: <urn:test:digest:record-0>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            WARC-Target-URI: https://example.com/\r\n\
            WARC-Block-Digest: sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ\r\n\
            Content-Length: 5\r\n\
            \r\n\
            hello\r\n\
            \r\n\
        ";

        assert!(
            WarcReader::new(&raw[..])
                .iter_untyped_records()
                .next()
                .unwrap()
                .is_ok()
        );

        for read in [
            WarcReader::new(&raw[..])
                .iter_records::<NoExtension>()
                .next(),
            WarcReader::new(&raw[..])
                .filter_records::<NoExtension, _>(|_| true)
                .next(),
        ] {
            let record = read.expect("a record").expect("a readable record");

            assert!(
                matches!(
                    record.incorrect_block_digest(),
                    Some(BlockError::BlockDigestMismatch { .. })
                ),
                "{record:?}"
            );
        }
    }

    /// A record of a type only an extension names is refused without the extension and lifts with
    /// it.
    #[test]
    fn an_extension_decides_what_lifts() {
        let mut without = WarcReader::new(SITEMAP_RECORD).iter_records::<NoExtension>();
        assert!(matches!(without.next(), Some(Err(Error::Record(_)))));

        let record = WarcReader::new(SITEMAP_RECORD)
            .iter_records::<Sitemaps>()
            .next()
            .unwrap()
            .unwrap();

        assert!(matches!(record, Record::Other { .. }));
        assert_eq!(record.type_name(), "sitemap");
    }
}

#[cfg(all(test, feature = "gzip"))]
mod gzip_tests {
    use super::WarcReader;
    use crate::io::test_record;
    use crate::io::write::WarcWriter;
    use crate::parse::raw;
    use crate::version::WarcVersion;

    /// A record whose body names it, so a body read from the wrong gzip member cannot pass.
    fn record(url: &str, body: &[u8]) -> raw::Record {
        test_record(
            WarcVersion::V1_1,
            &[("WARC-Type", "response"), ("WARC-Target-URI", url)],
            body,
        )
    }

    /// Records written one gzip member at a time read back as the records they were.
    #[test]
    fn reads_a_multi_member_gzip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reads_a_multi_member_gzip_file.warc.gz");

        let mut writer = WarcWriter::from_path_gzip(&path).unwrap();
        writer
            .write(&record("http://example.com/first", b"first"))
            .unwrap();
        writer
            .write(&record("http://example.com/second", b"second"))
            .unwrap();
        writer.finish().unwrap();

        let records = WarcReader::from_path_gzip(&path)
            .unwrap()
            .iter_raw_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].body, b"first");
        assert_eq!(
            records[1].header.get("WARC-Target-URI"),
            Some(&b" http://example.com/second"[..])
        );
    }

    /// A file whose records were each compressed as an independent member with `write_gzip` reads
    /// as a whole archive.
    #[test]
    fn reads_records_written_as_independent_members() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("reads_records_written_as_independent_members.warc.gz");

        let file = std::fs::File::create(&path).unwrap();
        let mut writer = WarcWriter::new(file);
        writer
            .write_gzip(&record("http://example.com/first", b"first"))
            .unwrap();
        writer
            .write_gzip(&record("http://example.com/second", b"second"))
            .unwrap();
        writer.flush().unwrap();

        let bodies = WarcReader::from_path_gzip(&path)
            .unwrap()
            .iter_raw_records()
            .map(|record| record.unwrap().body)
            .collect::<Vec<_>>();

        assert_eq!(bodies, [b"first".to_vec(), b"second".to_vec()]);
    }
}
