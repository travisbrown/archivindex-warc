//! Reading records from an optionally gzip-compressed WARC file.
//!
//! [`WarcReader`] returns records at any of the crate's three representation levels. Record bodies
//! are read fully into memory. The three `filter` iterators can inspect a header block and skip its
//! body without buffering it.
//!
//! Some writers emit blank-line padding between records, and concatenation can leave it behind.
//! Readers skip this padding, and every iterator reports how many blank lines preceded the most
//! recently returned record.
//!
//! Every iterator also reports the [`Frame`] of the record it read last: the offset and length of
//! the record in the stream, for indexes that reference records by location. A reader made by
//! [`WarcReader::from_members`] frames records by the members of the container they were read
//! from, which for a gzip file locates them in the file rather than in what it decompresses to.

use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::path::Path;
use std::{fs, io};

#[cfg(feature = "gzip")]
use crate::io::gzip::MemberReader;
use crate::io::{Counted, MB};
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
    #[error("cannot read the data source")]
    Source(#[from] std::io::Error),
    /// The record's header block exceeds the supported maximum size.
    #[error("record header block too large")]
    HeaderBlockTooLarge,
    /// The record's declared `Content-Length` is too large for its body to be buffered in memory
    /// on this platform.
    #[error("record body too large to buffer")]
    BodyTooLarge,
    /// The stream ended before the record's declared `Content-Length` was reached.
    #[error("unexpected end of body")]
    UnexpectedEndOfBody,
    /// The `\r\n\r\n` terminator after the record's body was missing or malformed. The record
    /// was read completely, but is invalid.
    #[error("malformed record terminator")]
    MalformedRecordTerminator,
    /// The octets read are not a record.
    ///
    /// This includes a record declaring a version this crate does not read. Its header block is
    /// not parsed, so its body cannot be skipped, and iteration ends at that record.
    #[error(transparent)]
    Raw(#[from] raw::Error),
    /// A field's value does not match the grammar its name selects.
    #[error(transparent)]
    Untyped(#[from] untyped::Error),
    /// The record is not one the standard, or the extension in force, permits.
    #[error(transparent)]
    Record(#[from] record::Error),
}

/// The location of a record in the stream it was read from.
///
/// Offsets and lengths count the bytes the reader consumed, from the record's version line
/// through its terminator.
///
/// A reader created by [`WarcReader::from_members`], including
/// [`WarcReader::from_path_gzip`], counts container bytes instead. The frame spans every member
/// from the one containing the version line through the last member ending before the next
/// record. It therefore includes any inter-record padding. Its length is zero if any of those
/// members also contains part of another record, because no container range then represents this
/// record alone.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Frame {
    /// The offset of the record's version line, or of the member holding it.
    pub offset: u64,
    /// The number of bytes from the version line through the record terminator, or of the
    /// members holding the record.
    pub length: u64,
}

/// Where a byte lies in the members of the container a [`Members`] stream reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Location {
    /// The offset of the member containing the byte, or the end of the container after EOF.
    pub member: u64,
    /// Whether the byte is the first in its member. Also set after EOF.
    pub boundary: bool,
}

/// A decompressed stream that can report container-member boundaries.
///
/// [`WarcReader::from_members`] uses these boundaries to report container-relative frames, as it
/// does for the gzip members of a `.warc.gz` file.
pub trait Members: BufRead {
    /// Where the next byte to be read lies.
    ///
    /// Reaching that byte may mean opening the next member. A failure to do so is reported by
    /// the read that follows, and the location is then the end of what was read.
    fn location(&mut self) -> Location;
}

/// A reader which iteratively parses WARC records from a stream.
pub struct WarcReader<R> {
    reader: R,
    /// Where the next byte to read lies in the members of the stream, when frames count the
    /// bytes of the container. A function pointer rather than a bound on `R`, so that the
    /// reader is one type over any stream.
    locate: Option<fn(&mut R) -> Location>,
}

impl<R: BufRead> WarcReader<R> {
    /// Create a new reader.
    pub const fn new(r: R) -> Self {
        Self {
            reader: r,
            locate: None,
        }
    }

    /// Iterate over records at the raw level.
    ///
    /// Each record is a [`raw::Record`]: its field names and values are exactly the ones on
    /// the wire, checked only for the grammar of a header block and for the `Content-Length`
    /// that frames the body.
    pub fn iter_raw_records(self) -> RawIter<R> {
        RawIter::new(self.reader, self.locate)
    }

    /// Iterate over records at the untyped level.
    ///
    /// Field values are parsed against their grammars, but semantic rules for the declared version
    /// and record type are not checked.
    pub fn iter_untyped_records(self) -> UntypedIter<R> {
        UntypedIter::new(self.reader, self.locate)
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
        RecordIter::new(self.reader, self.locate)
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
            reading: Reading::new(self.reader, self.locate),
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
            reading: Reading::new(self.reader, self.locate),
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
            reading: Reading::new(self.reader, self.locate),
            filter,
            extension: PhantomData,
        }
    }
}

impl<R: Members> WarcReader<R> {
    /// Create a reader that frames records by the members of `reader`'s container.
    pub const fn from_members(reader: R) -> Self {
        Self {
            reader,
            locate: Some(R::location),
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
impl WarcReader<MemberReader<BufReader<fs::File>>> {
    /// Create a reader for a gzip-compressed file, whose frames are the gzip members holding
    /// each record.
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(&path)?;

        Ok(Self::from_members(MemberReader::new(
            BufReader::with_capacity(MB, file),
        )))
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
        // This runs over every header byte of every record, so the scan is vectorized.
        let bounded = &available[..available.len().min(allowance)];
        if let Some(index) = memchr::memchr(b'\n', bounded) {
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

/// Whether the buffer holds nothing but one line ending, which is a blank line standing where a
/// record's version line belongs.
fn is_blank_line(header_buffer: &[u8]) -> bool {
    header_buffer == b"\r\n" || header_buffer == b"\n"
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

/// How the records of a stream are framed.
enum Framing<R> {
    /// By the bytes of the stream.
    Bytes,
    /// By the members of the container the stream reads.
    Members {
        /// Where the next byte to read lies.
        locate: fn(&mut R) -> Location,
        /// The frame of the record read last.
        frame: Frame,
        /// The offset of the member holding the next byte to read.
        next: u64,
        /// Whether the record read last begins its member, blank lines before it aside, so that
        /// the members it ends in frame it.
        begins: bool,
    },
}

/// Where reading past the blank lines before a record stopped.
struct Padding {
    /// The number of blank lines read.
    blank_lines: usize,
    /// How the read of the line after them ended.
    read: LineRead,
    /// The offset of the last member one of the lines began, or the end of the container when
    /// reading reached it, for a [`Members`] stream.
    began: Option<u64>,
}

/// The stream, reusable header buffer, and error state shared by all iterators in this module.
struct Reading<R> {
    reader: Counted<R>,
    framing: Framing<R>,
    /// Set once the input has ended or an error has been yielded. Every error here is
    /// stream-level: it leaves the reader at an unspecified position, so iteration fuses rather
    /// than yielding garbage records from the middle of a partly consumed one.
    finished: bool,
    /// An error met reading ahead of the record returned last, to yield next.
    pending: Option<Error>,
    /// The blank lines read ahead of the record returned last, once the first line of the header
    /// block after them is in `header_buffer`.
    ahead: Option<Padding>,
    header_buffer: Vec<u8>,
    /// The number of blank lines skipped before the header block read last.
    blank_lines: usize,
    /// The offset of the header block read last.
    offset: u64,
}

impl<R: BufRead> Reading<R> {
    const fn new(reader: R, locate: Option<fn(&mut R) -> Location>) -> Self {
        let framing = match locate {
            Some(locate) => Framing::Members {
                locate,
                frame: Frame {
                    offset: 0,
                    length: 0,
                },
                next: 0,
                begins: false,
            },
            None => Framing::Bytes,
        };

        Self {
            reader: Counted::new(reader),
            framing,
            finished: false,
            pending: None,
            ahead: None,
            header_buffer: Vec::new(),
            blank_lines: 0,
            offset: 0,
        }
    }

    /// Locate the next byte to read in the members of the stream, extending the frame of the
    /// record read last through any member that has ended.
    ///
    /// Returns the offset of the member the byte begins, if it begins one.
    fn locate(&mut self) -> Option<u64> {
        let Framing::Members {
            locate,
            frame,
            next,
            begins,
        } = &mut self.framing
        else {
            return None;
        };

        let location = locate(self.reader.get_mut());
        *next = location.member;
        if location.boundary && *begins {
            frame.length = location.member - frame.offset;
        }

        location.boundary.then_some(location.member)
    }

    /// Read past the blank lines standing before a record, leaving its first line in the header
    /// buffer.
    ///
    /// Writers pad the space between records with blank lines, and concatenating archives
    /// leaves them behind. A blank line where a version line belongs is that padding, so it is
    /// counted and dropped rather than read as the start of a header block.
    fn read_past_padding(&mut self) -> Result<Padding, Error> {
        let mut blank_lines = 0;
        let mut began = None;
        loop {
            began = self.locate().or(began);
            match read_line_bounded(&mut self.reader, &mut self.header_buffer, MAX_HEADER_BLOCK)? {
                LineRead::Line(_) if is_blank_line(&self.header_buffer) => {
                    self.header_buffer.clear();
                    blank_lines += 1;
                }
                read => {
                    return Ok(Padding {
                        blank_lines,
                        read,
                        began,
                    });
                }
            }
        }
    }

    /// Read the rest of a header block whose first line the read `first` put in the header
    /// buffer, up to and including the blank line that terminates it, reading at most
    /// [`MAX_HEADER_BLOCK`] bytes in all.
    ///
    /// Returns `None` on a clean end-of-stream at a record boundary. End-of-stream with header
    /// bytes already buffered is truncated input, and is an error.
    fn read_header_block(&mut self, first: LineRead) -> Option<Result<(), Error>> {
        let mut read = first;
        loop {
            match read {
                LineRead::Eof => {
                    // A record boundary is the only place the input may cleanly end. Anything
                    // buffered here is a header block whose terminating blank line never
                    // arrived: the input was truncated mid-record, or uses bare-`\n` line
                    // endings (which never match the `\r\n` check below, and would otherwise
                    // read as an empty stream with no error).
                    if self.header_buffer.is_empty() {
                        return None;
                    }
                    return Some(Err(Error::Raw(raw::Error::UnexpectedEndOfHeaderBlock)));
                }
                LineRead::LimitExceeded => return Some(Err(Error::HeaderBlockTooLarge)),
                LineRead::Line(2) if self.header_buffer.ends_with(b"\r\n") => {
                    return Some(Ok(()));
                }
                LineRead::Line(_) => {}
            }

            read = match read_line_bounded(
                &mut self.reader,
                &mut self.header_buffer,
                MAX_HEADER_BLOCK,
            ) {
                Ok(read) => read,
                Err(error) => return Some(Err(error)),
            };
        }
    }

    /// Begin the frame of the record about to be read at the member holding it, for a
    /// [`Members`] stream.
    ///
    /// `began` is the member the record, or the blank lines before it, began, if any.
    const fn begin_frame(&mut self, began: Option<u64>) {
        if let Framing::Members {
            frame,
            next,
            begins,
            ..
        } = &mut self.framing
        {
            *frame = Frame {
                offset: *next,
                length: 0,
            };
            *begins = matches!(began, Some(member) if member == *next);
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

        let padding = match (self.pending.take(), self.ahead.take()) {
            (Some(error), _) => Err(error),
            (None, Some(padding)) => Ok(padding),
            (None, None) => {
                self.header_buffer.clear();
                self.read_past_padding()
            }
        };
        let padding = match padding {
            Ok(padding) => padding,
            Err(error) => {
                self.begin_frame(None);
                return Some(self.fuse_on_error(Err(error)));
            }
        };
        self.blank_lines = padding.blank_lines;
        self.begin_frame(padding.began);

        let read = self.read_header_block(padding.read);
        // Whatever the header block read holds was consumed after the padding before it, and
        // begins the record. At the end of the input it holds nothing.
        self.offset = self.reader.position - self.header_buffer.len() as u64;

        match read {
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

    /// Read past the blank lines after a record, for a [`Members`] stream, so that its frame
    /// reaches the end of the last member holding nothing after it but those lines.
    ///
    /// The frame of a record counted in bytes ends at its terminator, so nothing is read ahead.
    fn finish_record(&mut self) {
        if matches!(self.framing, Framing::Bytes) {
            return;
        }

        self.header_buffer.clear();
        match self.read_past_padding() {
            Ok(padding) => self.ahead = Some(padding),
            Err(error) => self.pending = Some(error),
        }
    }

    /// Read the body a header declared, buffering it.
    fn read_body(&mut self, expected_body_len: u64) -> Result<Vec<u8>, Error> {
        let body = read_body(&mut self.reader, expected_body_len);

        let body = self.fuse_on_error(body)?;
        self.finish_record();

        Ok(body)
    }

    /// Consume the body a header declared without buffering it.
    fn skip_body(&mut self, expected_body_len: u64) -> Result<(), Error> {
        let skipped = skip_body(&mut self.reader, expected_body_len);

        self.fuse_on_error(skipped)?;
        self.finish_record();

        Ok(())
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

    /// The number of blank lines skipped before the header block read last.
    const fn blank_lines(&self) -> usize {
        self.blank_lines
    }

    /// The frame of the header block read last and everything consumed after it, or of the
    /// members holding the record read last.
    const fn frame(&self) -> Frame {
        match &self.framing {
            Framing::Bytes => Frame {
                offset: self.offset,
                length: self.reader.position - self.offset,
            },
            Framing::Members { frame, .. } => *frame,
        }
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
/// iterator is fused: every further call returns `None`. A record declaring a WARC version other
/// than 1.0 or 1.1 is a framing error: the body is framed by the `Content-Length` of a header
/// block this crate parses only under a version it knows, so the record cannot be skipped and the
/// rest of the stream is unreachable.
pub struct RawIter<R> {
    reading: Reading<R>,
}

impl<R: BufRead> RawIter<R> {
    const fn new(reader: R, locate: Option<fn(&mut R) -> Location>) -> Self {
        Self {
            reading: Reading::new(reader, locate),
        }
    }

    /// The number of blank lines skipped before the record returned last.
    ///
    /// A blank line between records is padding the standard does not allow for, which some
    /// writers emit and concatenating archives leaves behind. Once iteration has ended, this is
    /// the number of blank lines the input ends with.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.reading.blank_lines()
    }

    /// The frame of the record read last, returned or not.
    ///
    /// The frame begins at the record's version line and runs through its terminator, so it
    /// locates the record for a later read on its own:
    ///
    /// ```
    /// use archivindex_warc::io::read::WarcReader;
    ///
    /// let archive = b"\
    ///     WARC/1.1\r\n\
    ///     WARC-Type: resource\r\n\
    ///     Content-Length: 5\r\n\
    ///     \r\n\
    ///     hello\r\n\
    ///     \r\n";
    ///
    /// let mut records = WarcReader::new(&archive[..]).iter_raw_records();
    /// let record = records.next().expect("a record")?;
    /// let frame = records.frame();
    ///
    /// assert_eq!((frame.offset, frame.length), (0, archive.len() as u64));
    /// let start = usize::try_from(frame.offset)?;
    /// let end = start + usize::try_from(frame.length)?;
    /// let located = WarcReader::new(&archive[start..end])
    ///     .iter_raw_records()
    ///     .next()
    ///     .expect("the record it frames")?;
    /// assert_eq!(located, record);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// After a read error, the length is the number of bytes consumed before the error, or the
    /// members ended before it. Once iteration has ended, the frame is empty and stands where
    /// the input ends.
    #[must_use]
    pub const fn frame(&self) -> Frame {
        self.reading.frame()
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
    const fn new(reader: R, locate: Option<fn(&mut R) -> Location>) -> Self {
        Self {
            raw: RawIter::new(reader, locate),
        }
    }

    /// The number of blank lines skipped before the record returned last.
    ///
    /// A blank line between records is padding the standard does not allow for, which some
    /// writers emit and concatenating archives leaves behind. Once iteration has ended, this is
    /// the number of blank lines the input ends with.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.raw.blank_lines()
    }

    /// The frame of the record read last, returned or not.
    ///
    /// After a read error, the length is the number of bytes consumed before the error, or the
    /// members ended before it. Once iteration has ended, the frame is empty and stands where
    /// the input ends. See [`RawIter::frame`] for an example.
    #[must_use]
    pub const fn frame(&self) -> Frame {
        self.raw.frame()
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
    const fn new(reader: R, locate: Option<fn(&mut R) -> Location>) -> Self {
        Self {
            untyped: UntypedIter::new(reader, locate),
            extension: PhantomData,
        }
    }

    /// The number of blank lines skipped before the record returned last.
    ///
    /// A blank line between records is padding the standard does not allow for, which some
    /// writers emit and concatenating archives leaves behind. Once iteration has ended, this is
    /// the number of blank lines the input ends with.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.untyped.blank_lines()
    }

    /// The frame of the record read last, returned or not.
    ///
    /// After a read error, the length is the number of bytes consumed before the error, or the
    /// members ended before it. Once iteration has ended, the frame is empty and stands where
    /// the input ends. See [`RawIter::frame`] for an example.
    #[must_use]
    pub const fn frame(&self) -> Frame {
        self.untyped.frame()
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

impl<R: BufRead, F> FilterRawIter<R, F> {
    /// The number of blank lines skipped before the record returned last.
    ///
    /// A blank line between records is padding the standard does not allow for, which some
    /// writers emit and concatenating archives leaves behind. Once iteration has ended, this is
    /// the number of blank lines the input ends with.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.reading.blank_lines()
    }

    /// The frame of the record read last, returned or not.
    ///
    /// After a read error, the length is the number of bytes consumed before the error, or the
    /// members ended before it. Once iteration has ended, the frame is empty and stands where
    /// the input ends. See [`RawIter::frame`] for an example.
    #[must_use]
    pub const fn frame(&self) -> Frame {
        self.reading.frame()
    }
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

impl<R: BufRead, F> FilterUntypedIter<R, F> {
    /// The number of blank lines skipped before the record returned last.
    ///
    /// A blank line between records is padding the standard does not allow for, which some
    /// writers emit and concatenating archives leaves behind. Once iteration has ended, this is
    /// the number of blank lines the input ends with.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.reading.blank_lines()
    }

    /// The frame of the record read last, returned or not.
    ///
    /// After a read error, the length is the number of bytes consumed before the error, or the
    /// members ended before it. Once iteration has ended, the frame is empty and stands where
    /// the input ends. See [`RawIter::frame`] for an example.
    #[must_use]
    pub const fn frame(&self) -> Frame {
        self.reading.frame()
    }
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

impl<R: BufRead, F, E> FilterRecordIter<R, F, E> {
    /// The number of blank lines skipped before the record returned last.
    ///
    /// A blank line between records is padding the standard does not allow for, which some
    /// writers emit and concatenating archives leaves behind. Once iteration has ended, this is
    /// the number of blank lines the input ends with.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.reading.blank_lines()
    }

    /// The frame of the record read last, returned or not.
    ///
    /// After a read error, the length is the number of bytes consumed before the error, or the
    /// members ended before it. Once iteration has ended, the frame is empty and stands where
    /// the input ends. See [`RawIter::frame`] for an example.
    #[must_use]
    pub const fn frame(&self) -> Frame {
        self.reading.frame()
    }
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
mod error_tests {
    use super::Error;
    use crate::parse::{raw, untyped};

    /// Stream errors use local messages; transparent variants use their source messages.
    #[test]
    fn each_error_states_its_failure() {
        let expectations = [
            (
                Error::Source(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                "cannot read the data source",
                true,
            ),
            (
                Error::HeaderBlockTooLarge,
                "record header block too large",
                false,
            ),
            (
                Error::BodyTooLarge,
                "record body too large to buffer",
                false,
            ),
            (Error::UnexpectedEndOfBody, "unexpected end of body", false),
            (
                Error::MalformedRecordTerminator,
                "malformed record terminator",
                false,
            ),
            (
                Error::Raw(raw::Error::MissingContentLength),
                "missing Content-Length",
                false,
            ),
            (
                Error::Untyped(untyped::Error {
                    name: "WARC-Date".to_owned(),
                    source: crate::value::Error::Date("yesterday".to_owned()),
                }),
                "malformed WARC-Date field: not a timestamp: yesterday",
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

    /// A version this crate does not read is a framing error, so the records after it are not
    /// reached.
    #[test]
    fn raw_iter_fuses_after_an_unsupported_version() {
        let raw = b"\
            WARC/1.2\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.1\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            WARC-Record-Id: <urn:test:after-version:record-1>\r\n\
            WARC-Date: 2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut reader = WarcReader::new(create_reader!(raw)).iter_raw_records();
        assert!(matches!(
            reader.next(),
            Some(Err(Error::Raw(raw::Error::MalformedVersion(crate::version::Error(version)))))
                if version == "1.2"
        ));
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

        assert_eq!(record.body, [] as [u8; 0]);
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
    use std::io::Write;

    use flate2::write::GzEncoder;

    use super::{Error, Frame, WarcReader};
    use crate::io::gzip::MemberReader;
    use crate::io::test_record;
    use crate::io::write::{Compression, WarcWriter};
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

    /// A file whose records were each compressed as an independent member reads as a whole
    /// archive.
    #[test]
    fn reads_records_written_as_independent_members() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("reads_records_written_as_independent_members.warc.gz");

        let file = std::fs::File::create(&path).unwrap();
        let mut writer = WarcWriter::new(file).with_compression(Compression::gzip());
        writer
            .write(&record("http://example.com/first", b"first"))
            .unwrap();
        writer
            .write(&record("http://example.com/second", b"second"))
            .unwrap();
        writer.flush().unwrap();

        let bodies = WarcReader::from_path_gzip(&path)
            .unwrap()
            .iter_raw_records()
            .map(|record| record.unwrap().body)
            .collect::<Vec<_>>();

        assert_eq!(bodies, [b"first".to_vec(), b"second".to_vec()]);
    }

    /// The gzip members holding the records of a stream, with the offset at which each ends.
    fn members(members: &[&[u8]]) -> (Vec<u8>, Vec<u64>) {
        let mut stream = Vec::new();
        let mut ends = Vec::with_capacity(members.len());
        for member in members {
            let mut encoder = GzEncoder::new(&mut stream, flate2::Compression::fast());
            encoder.write_all(member).unwrap();
            encoder.finish().unwrap();
            ends.push(stream.len() as u64);
        }

        (stream, ends)
    }

    /// The record spelled as stored.
    fn stored(record: &raw::Record) -> Vec<u8> {
        let mut stored = Vec::new();
        record.write_to(&mut stored).unwrap();

        stored
    }

    /// The frames of the records in a gzip stream, followed by the frame at its end.
    fn frames(stream: &[u8]) -> Vec<Frame> {
        let mut records = WarcReader::from_members(MemberReader::new(stream)).iter_raw_records();
        let mut frames = Vec::new();
        while records.next().is_some() {
            frames.push(records.frame());
        }
        frames.push(records.frame());

        frames
    }

    const fn frame(offset: u64, length: u64) -> Frame {
        Frame { offset, length }
    }

    /// The frames of a gzip file's records are the members the writer stored them in, and stand
    /// at the end of the file once it is read.
    #[test]
    fn frames_records_by_the_members_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("frames_records_by_the_members_written.warc.gz");

        let mut writer = WarcWriter::from_path_gzip(&path).unwrap();
        let first = writer
            .write(&record("http://example.com/first", b"first"))
            .unwrap();
        let second = writer
            .write(&record("http://example.com/second", b"second"))
            .unwrap();
        writer.finish().unwrap();
        let size = std::fs::metadata(&path).unwrap().len();

        let mut records = WarcReader::from_path_gzip(&path)
            .unwrap()
            .iter_raw_records();
        records.next().unwrap().unwrap();
        let first_frame = records.frame();
        records.next().unwrap().unwrap();
        let second_frame = records.frame();
        assert!(records.next().is_none());
        let end_frame = records.frame();

        assert_eq!(first_frame, frame(first.offset, first.length));
        assert_eq!(second_frame, frame(second.offset, second.length));
        assert_eq!(end_frame, frame(size, 0));
    }

    /// A record split over members is framed by all of them, and the frame of one sharing a
    /// member with another record is empty.
    #[test]
    fn frames_a_record_by_every_member_it_alone_fills() {
        let first = stored(&record("http://example.com/first", b"first"));
        let second = stored(&record("http://example.com/second", b"second"));
        let third = stored(&record("http://example.com/third", b"third"));
        let (split_first, split_second) = first.split_at(first.len() / 2);
        let (mut shared, ends) = members(&[
            split_first,
            split_second,
            &[&second[..], &third[..]].concat(),
        ]);
        shared.extend_from_slice(&members(&[&third]).0);

        assert_eq!(
            frames(&shared),
            [
                frame(0, ends[1]),
                frame(ends[1], 0),
                frame(ends[1], 0),
                frame(ends[2], shared.len() as u64 - ends[2]),
                frame(shared.len() as u64, 0),
            ]
        );
    }

    /// Blank lines inside a member belong to the frame of the record before them, and are
    /// reported before the record after them.
    #[test]
    fn frames_through_the_blank_lines_after_a_record() {
        let first = stored(&record("http://example.com/first", b"first"));
        let second = stored(&record("http://example.com/second", b"second"));
        let (stream, ends) = members(&[
            &[&first[..], b"\r\n\r\n"].concat(),
            b"\r\n",
            &[b"\r\n", &second[..], b"\r\n"].concat(),
        ]);

        let mut records =
            WarcReader::from_members(MemberReader::new(&stream[..])).iter_raw_records();
        records.next().unwrap().unwrap();
        let first_frame = records.frame();
        records.next().unwrap().unwrap();
        let padding = records.blank_lines();
        let second_frame = records.frame();
        assert!(records.next().is_none());
        let trailing = records.blank_lines();

        assert_eq!(first_frame, frame(0, ends[1]));
        assert_eq!(padding, 4);
        assert_eq!(second_frame, frame(ends[1], ends[2] - ends[1]));
        assert_eq!(trailing, 1);
    }

    /// The `filter` iterators skip bodies without reading them, and frame records the same.
    #[test]
    fn frames_skipped_records_by_their_members() {
        let (stream, ends) = members(&[
            &stored(&record("http://example.com/first", b"first")),
            &stored(&record("http://example.com/second", b"second")),
        ]);

        let mut records = WarcReader::from_members(MemberReader::new(&stream[..]))
            .filter_raw_records(|header| {
                header.get("WARC-Target-URI") == Some(b" http://example.com/second")
            });
        let mut frames = Vec::new();
        while let Some(record) = records.next() {
            record.unwrap();
            frames.push(records.frame());
        }

        assert_eq!(frames, [frame(ends[0], ends[1] - ends[0])]);
    }

    /// Octets after the last member fail the read after the record before them, whose frame is
    /// whole. The failure leaves the frame empty at the end of the last member.
    #[test]
    fn reports_what_follows_the_last_member_after_the_record_before_it() {
        let (mut stream, ends) = members(&[&stored(&record("http://example.com/first", b"first"))]);
        stream.extend_from_slice(b"not a member");

        let mut records =
            WarcReader::from_members(MemberReader::new(&stream[..])).iter_raw_records();
        records.next().unwrap().unwrap();
        let first_frame = records.frame();
        let error = records.next().unwrap().unwrap_err();
        let error_frame = records.frame();

        assert_eq!(first_frame, frame(0, ends[0]));
        assert!(matches!(error, Error::Source(_)));
        assert_eq!(error_frame, frame(ends[0], 0));
        assert!(records.next().is_none());
    }
}

#[cfg(test)]
mod blank_line_tests {
    use super::WarcReader;

    /// A WARC 1.1 resource record framed by the length of its body.
    fn record(body: &str) -> String {
        format!(
            "WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: {}\r\n\r\n{body}\r\n\r\n",
            body.len()
        )
    }

    /// The body of each record of `archive` with the blank lines read before it, and the number
    /// of blank lines the archive ends with.
    fn read(archive: &str) -> (Vec<(String, usize)>, usize) {
        let mut records = WarcReader::new(archive.as_bytes()).iter_raw_records();
        let mut read = Vec::new();
        while let Some(record) = records.next() {
            let record = record.expect("every record reads");
            read.push((
                String::from_utf8(record.body).expect("a body of text"),
                records.blank_lines(),
            ));
        }

        (read, records.blank_lines())
    }

    /// A blank line between records is padding, which reading skips rather than reading it as the
    /// start of a record.
    #[test]
    fn skips_the_blank_lines_between_records() {
        let archive = format!("{}\r\n{}", record("first"), record("second"));

        assert_eq!(
            read(&archive),
            (vec![("first".to_owned(), 0), ("second".to_owned(), 1)], 0)
        );
    }

    /// Padding before the first record and after the last is skipped as well.
    #[test]
    fn skips_the_blank_lines_an_archive_opens_and_ends_with() {
        let archive = format!("\r\n\r\n{}\r\n", record("only"));

        assert_eq!(read(&archive), (vec![("only".to_owned(), 2)], 1));
    }

    /// A blank line written with a bare line feed is padding too, as bare line feeds are read
    /// elsewhere in this crate.
    #[test]
    fn skips_a_blank_line_written_with_a_bare_line_feed() {
        let archive = format!("{}\n{}", record("first"), record("second"));

        assert_eq!(
            read(&archive),
            (vec![("first".to_owned(), 0), ("second".to_owned(), 1)], 0)
        );
    }

    /// An archive of blank lines alone holds no records, and ends cleanly.
    #[test]
    fn reads_an_archive_of_blank_lines_as_no_records() {
        assert_eq!(read("\r\n\r\n"), (vec![], 2));
    }

    /// Every iterator counts the padding, whatever level it reads records at.
    #[test]
    fn counts_the_padding_at_every_level() {
        let archive = format!("\r\n{}", record("only"));

        let mut filtered = WarcReader::new(archive.as_bytes()).filter_raw_records(|_| true);
        assert!(filtered.next().is_some());
        assert_eq!(filtered.blank_lines(), 1);

        let mut untyped = WarcReader::new(archive.as_bytes()).iter_untyped_records();
        assert!(untyped.next().is_some());
        assert_eq!(untyped.blank_lines(), 1);
    }
}

#[cfg(test)]
mod frame_tests {
    use super::{Error, Frame, WarcReader};
    use crate::parse::raw;
    use crate::record::extension::NoExtension;

    /// A WARC 1.1 resource record framed by the length of its body.
    fn record(body: &str) -> String {
        format!(
            "WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: {}\r\n\r\n{body}\r\n\r\n",
            body.len()
        )
    }

    /// The records of `archive` with their frames, and the frame reported once reading has
    /// ended.
    fn read(archive: &[u8]) -> (Vec<(raw::Record, Frame)>, Frame) {
        let mut records = WarcReader::new(archive).iter_raw_records();
        let mut read = Vec::new();
        while let Some(record) = records.next() {
            read.push((record.expect("every record reads"), records.frame()));
        }

        (read, records.frame())
    }

    /// Records are framed by where they lie in the input, and the input ends after the last.
    #[test]
    fn frames_each_record_where_it_lies() {
        let first = record("first");
        let second = record("second");
        let archive = format!("{first}{second}");

        let (read, end) = read(archive.as_bytes());

        let frames = read.iter().map(|(_, frame)| *frame).collect::<Vec<_>>();
        assert_eq!(
            frames,
            [
                Frame {
                    offset: 0,
                    length: first.len() as u64
                },
                Frame {
                    offset: first.len() as u64,
                    length: second.len() as u64
                },
            ]
        );
        assert_eq!(
            end,
            Frame {
                offset: archive.len() as u64,
                length: 0
            }
        );
    }

    /// Padding before a record is not part of its frame, and padding after the last record
    /// moves where the input ends.
    #[test]
    fn frames_a_record_without_the_padding_around_it() {
        let only = record("only");
        let archive = format!("\r\n\n{only}\r\n");

        let (read, end) = read(archive.as_bytes());

        assert_eq!(
            read[0].1,
            Frame {
                offset: 3,
                length: only.len() as u64
            }
        );
        assert_eq!(end.offset, archive.len() as u64);
        assert_eq!(end.length, 0);
    }

    /// A frame locates its record: the bytes it covers read as that record alone.
    #[test]
    fn a_frame_reads_back_as_its_record() {
        let archive = format!("{}\r\n{}", record("first"), record("second"));

        let (read, _) = read(archive.as_bytes());

        for (record, frame) in read {
            let start = usize::try_from(frame.offset).unwrap();
            let end = start + usize::try_from(frame.length).unwrap();
            let (located, _) = self::read(&archive.as_bytes()[start..end]);
            assert_eq!(located.len(), 1);
            assert_eq!(located[0].0, record);
        }
    }

    /// A record that cannot be read is framed by the bytes consumed before the failure.
    #[test]
    fn frames_a_record_that_fails_by_what_was_consumed() {
        let first = record("first");
        let archive = format!("{first}WARC/1.1\r\nContent-Length: 5\r\n\r\nhel");

        let mut records = WarcReader::new(archive.as_bytes()).iter_raw_records();
        records.next().unwrap().unwrap();
        let error = records.next().unwrap().unwrap_err();

        assert!(matches!(error, Error::UnexpectedEndOfBody));
        assert_eq!(
            records.frame(),
            Frame {
                offset: first.len() as u64,
                length: (archive.len() - first.len()) as u64
            }
        );
    }

    /// A record the filter refuses is framed too, as is a record that fails to lift.
    #[test]
    fn frames_at_every_level() {
        let first = record("first");
        let archive = format!("{first}{}", record("second"));
        let second = Frame {
            offset: first.len() as u64,
            length: archive.len() as u64 - first.len() as u64,
        };

        let mut untyped = WarcReader::new(archive.as_bytes()).iter_untyped_records();
        untyped.next().unwrap().unwrap();
        untyped.next().unwrap().unwrap();
        assert_eq!(untyped.frame(), second);

        let mut lifted = WarcReader::new(archive.as_bytes()).iter_records::<NoExtension>();
        lifted.next().unwrap().unwrap_err();
        lifted.next().unwrap().unwrap_err();
        assert_eq!(lifted.frame(), second);

        let mut filtered = WarcReader::new(archive.as_bytes())
            .filter_raw_records(|header| header.get("Content-Length") == Some(b" 6"));
        assert_eq!(filtered.next().unwrap().unwrap().body, b"second");
        assert_eq!(filtered.frame(), second);

        let mut filtered = WarcReader::new(archive.as_bytes()).filter_untyped_records(|_| false);
        assert!(filtered.next().is_none());
        assert_eq!(filtered.frame().length, 0);

        let mut filtered =
            WarcReader::new(archive.as_bytes()).filter_records::<NoExtension, _>(|_| true);
        assert!(filtered.next().unwrap().is_err());
        assert!(filtered.next().unwrap().is_err());
        assert_eq!(filtered.frame(), second);
    }
}
