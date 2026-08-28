//! Reading records from an optionally gzip-compressed WARC file.
//!
//! [`WarcReader`] returns records at any of the crate's three representation levels. Record bodies
//! are read fully into memory. The three `filter` iterators can inspect a header block and skip its
//! body without buffering it.
//!
//! Every iterator yields each record [`Located`]: with the [`Location`] of the record in the
//! input, and the number of blank lines skipped before it. A blank line between records is
//! padding the standard does not allow for, which some writers emit and concatenating archives
//! leaves behind; readers skip it. The location is the record's [`Frame`] in a plain stream, and
//! its [`Placement`] in the members of a gzip file, for a reader made by
//! [`WarcReader::from_gzip`]. A reader over a stream that seeks reads the one record a frame
//! locates, for lookups by an index over the file. An iterator's `records` method drops the
//! locations, for callers that want the records alone.

use std::fmt::{self, Display};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
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
    /// The frame read holds no record.
    #[error("the frame holds no record")]
    EmptyFrame,
    /// The frame read holds more than one record.
    #[error("the frame holds more than one record")]
    OverfullFrame,
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

/// The location of a record in the input it was read from.
///
/// In a plain stream, the offset and length count the bytes from the record's version line
/// through its terminator. In a gzip file, they count the octets of the members holding the
/// record, which hold nothing else; [`Location::frame`] reports one only then.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Frame {
    /// The offset of the record's version line.
    pub offset: u64,
    /// The number of bytes from the version line through the record terminator.
    pub length: u64,
}

/// Where a record lies in the members of the gzip stream it was read from.
///
/// The members holding a record locate it in the compressed file, as an index over the file
/// needs, when they hold nothing else; [`Location::frame`] is that location. Blank lines before
/// or after the record within its members are read past as padding, and count as nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Placement {
    /// The offset in the file of the member holding the record's first octet.
    pub offset: u64,
    /// The number of octets of the file from that member through the last member holding the
    /// record, or the blank lines after it, when the record ends that member. A record followed
    /// in its last member by another has no length that locates it.
    pub length: Option<u64>,
    /// The number of members holding the record's octets.
    pub members: u64,
    /// Whether the record, or the blank lines before it, begins its member.
    pub begins: bool,
}

impl Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offset {}, length {}", self.offset, self.length)
    }
}

impl Display for Placement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offset {}", self.offset)?;
        if let Some(length) = self.length {
            write!(f, ", length {length}")?;
        }
        let plural = if self.members == 1 { "" } else { "s" };
        write!(f, ", {} member{plural}", self.members)
    }
}

impl Placement {
    /// Where a record lies, given the location of its first octet and of the octet after its
    /// last.
    const fn between(start: Position, end: Position) -> Self {
        let (length, open) = if end.boundary {
            (Some(end.member - start.member), 0)
        } else {
            (None, 1)
        };

        Self {
            offset: start.member,
            length,
            members: end.held - start.held + open,
            begins: start.boundary,
        }
    }
}

/// Where a record lies in the input it was read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Location {
    /// The frame of a record in a plain stream.
    Plain(Frame),
    /// The placement of a record in the members of a gzip stream.
    Gzip(Placement),
}

impl Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(frame) => frame.fmt(f),
            Self::Gzip(placement) => placement.fmt(f),
        }
    }
}

impl Location {
    /// The frame that locates the record on its own, which [`WarcReader::record_at`] reads.
    ///
    /// Every record in a plain stream has one. A record in a gzip stream has one when the
    /// members holding it hold nothing else, blank lines aside: the frame covers those members,
    /// and decompressing the octets it covers yields the record alone.
    #[must_use]
    pub const fn frame(&self) -> Option<Frame> {
        match *self {
            Self::Plain(frame) => Some(frame),
            Self::Gzip(Placement {
                offset,
                length: Some(length),
                begins: true,
                ..
            }) => Some(Frame { offset, length }),
            Self::Gzip(_) => None,
        }
    }

    /// The placement of the record in the members of a gzip stream, when it was read from one.
    #[must_use]
    pub const fn placement(&self) -> Option<Placement> {
        match *self {
            Self::Plain(_) => None,
            Self::Gzip(placement) => Some(placement),
        }
    }
}

/// A value read from a record, with where the record lies in the input.
///
/// The iterators of this module yield the result of reading each record this way, so an error is
/// located as a record is: by the octets consumed before the failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Located<T> {
    /// Where the record lies in the input.
    pub location: Location,
    /// The number of blank lines skipped before the record.
    pub blank_lines: usize,
    /// The value read.
    pub value: T,
}

impl<T> Located<T> {
    /// The frame that locates the record on its own, as [`Location::frame`] reports it.
    #[must_use]
    pub const fn frame(&self) -> Option<Frame> {
        self.location.frame()
    }

    /// The placement of the record in the members of a gzip stream, as [`Location::placement`]
    /// reports it.
    #[must_use]
    pub const fn placement(&self) -> Option<Placement> {
        self.location.placement()
    }

    /// The same location and padding, holding what `f` makes of the value.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Located<U> {
        Located {
            location: self.location,
            blank_lines: self.blank_lines,
            value: f(self.value),
        }
    }
}

/// An iterator over the values of located items, with the locations dropped.
///
/// The `records` method of every iterator in this module makes one, for callers that want the
/// records alone: the items are then `Result`s, which collect into one.
pub struct Records<I> {
    located: I,
}

impl<T, I: Iterator<Item = Located<T>>> Iterator for Records<I> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.located.next().map(|located| located.value)
    }
}

/// The methods every iterator in this module shares.
macro_rules! located_iterator {
    ($iterator:ident<$($param:ident),+>, $($reading:ident).+) => {
        impl<$($param),+> $iterator<$($param),+> {
            /// The end of the input, once iteration has reached it.
            ///
            /// The location is empty and stands where the input ends; the blank lines are the
            /// ones the input ends with. This is `None` until the iterator has returned `None`,
            /// and after an error, since where the reader stopped is then unknown.
            #[must_use]
            pub const fn end(&self) -> Option<Located<()>> {
                self.$($reading).+.end()
            }

            /// The records alone, with their locations dropped.
            #[must_use]
            pub const fn records(self) -> Records<Self> {
                Records { located: self }
            }
        }
    };
}

/// Where a byte lies in the members of a gzip stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Position {
    /// The offset in the file of the member holding the byte, or the end of the file after the
    /// last member.
    pub(crate) member: u64,
    /// Whether the byte is the first in its member. Also set after the last member.
    pub(crate) boundary: bool,
    /// The number of members holding octets that ended before the byte.
    pub(crate) held: u64,
}

/// The stream a reader reads: bytes as they are, or the members of a gzip stream.
enum Source<R> {
    /// The bytes of the stream.
    Bytes(R),
    /// The members of a gzip stream, decompressed.
    #[cfg(feature = "gzip")]
    Members(MemberReader<R>),
}

impl<R: BufRead> Source<R> {
    /// Where the next byte to read lies in the members of a gzip stream.
    #[cfg_attr(
        not(feature = "gzip"),
        allow(
            clippy::missing_const_for_fn,
            clippy::needless_pass_by_ref_mut,
            clippy::unused_self
        )
    )]
    fn position(&mut self) -> Option<Position> {
        match self {
            Self::Bytes(_) => None,
            #[cfg(feature = "gzip")]
            Self::Members(members) => Some(members.position()),
        }
    }
}

impl<R: BufRead> Read for Source<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Bytes(bytes) => bytes.read(into),
            #[cfg(feature = "gzip")]
            Self::Members(members) => members.read(into),
        }
    }
}

impl<R: BufRead> BufRead for Source<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Bytes(bytes) => bytes.fill_buf(),
            #[cfg(feature = "gzip")]
            Self::Members(members) => members.fill_buf(),
        }
    }

    fn consume(&mut self, amount: usize) {
        match self {
            Self::Bytes(bytes) => bytes.consume(amount),
            #[cfg(feature = "gzip")]
            Self::Members(members) => members.consume(amount),
        }
    }
}

/// A reader which iteratively parses WARC records from a stream.
pub struct WarcReader<R> {
    reader: R,
    /// Whether the stream is gzip, read member by member.
    #[cfg(feature = "gzip")]
    gzip: bool,
}

impl<R: BufRead> WarcReader<R> {
    /// Create a new reader.
    pub const fn new(r: R) -> Self {
        Self {
            reader: r,
            #[cfg(feature = "gzip")]
            gzip: false,
        }
    }

    /// Create a reader for a gzip stream, whose records are placed in the members holding them.
    ///
    /// The stream ends with its last member; trailing data that is not another member is an
    /// error. Each record's [`Placement`] locates it in the compressed stream:
    ///
    /// ```
    /// use std::io::{Cursor, Write};
    ///
    /// use archivindex_warc::io::read::WarcReader;
    /// use flate2::Compression;
    /// use flate2::write::GzEncoder;
    ///
    /// let mut file = Vec::new();
    /// for body in ["first", "second"] {
    ///     let record = format!(
    ///         "WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: {}\r\n\r\n{body}\r\n\r\n",
    ///         body.len()
    ///     );
    ///     let mut member = GzEncoder::new(&mut file, Compression::fast());
    ///     member.write_all(record.as_bytes())?;
    ///     member.finish()?;
    /// }
    ///
    /// let mut records = WarcReader::from_gzip(&file[..]).iter_raw_records();
    /// records.next().expect("the first record").value?;
    /// let second = records.next().expect("the second record");
    /// let frame = second.frame().expect("the record lies in a member of its own");
    ///
    /// let read = WarcReader::from_gzip(Cursor::new(&file)).raw_record_at(frame)?;
    /// assert_eq!(read, second.value?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "gzip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
    pub const fn from_gzip(r: R) -> Self {
        Self {
            reader: r,
            gzip: true,
        }
    }

    /// The stream the reader reads, with its members decompressed when it is gzip.
    #[cfg_attr(not(feature = "gzip"), allow(clippy::missing_const_for_fn))]
    fn stream(self) -> Counted<Source<R>> {
        #[cfg(feature = "gzip")]
        if self.gzip {
            return Counted::new(Source::Members(MemberReader::new(self.reader)));
        }

        Counted::new(Source::Bytes(self.reader))
    }

    /// Iterate over records at the raw level.
    ///
    /// Each record is a [`raw::Record`]: its field names and values are exactly the ones on
    /// the wire, checked only for the grammar of a header block and for the `Content-Length`
    /// that frames the body.
    pub fn iter_raw_records(self) -> RawIter<R> {
        RawIter::new(self.stream())
    }

    /// Iterate over records at the untyped level.
    ///
    /// Field values are parsed against their grammars, but semantic rules for the declared version
    /// and record type are not checked.
    pub fn iter_untyped_records(self) -> UntypedIter<R> {
        UntypedIter::new(self.stream())
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
    ///     .records()
    ///     .collect::<Result<Vec<_>, _>>()?;
    ///
    /// assert_eq!(records[0].type_name(), "resource");
    /// # Ok::<(), archivindex_warc::io::read::Error>(())
    /// ```
    pub fn iter_records<E: Extension>(self) -> RecordIter<R, E> {
        RecordIter::new(self.stream())
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
            reading: Reading::new(self.stream()),
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
            reading: Reading::new(self.stream()),
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
            reading: Reading::new(self.stream()),
            filter,
            extension: PhantomData,
        }
    }
}

impl<R: BufRead + Seek> WarcReader<R> {
    /// Read the record a frame locates, at the raw level.
    ///
    /// The frame is one an index holds for the record: the one an iterator yielded the record
    /// with, as [`Location::frame`] reports it, or the one the writer returned. Only the octets
    /// the frame covers are read, so the reader can read any number of records in any order:
    ///
    /// ```
    /// use std::io::Cursor;
    ///
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
    /// let located = records.next().expect("a record");
    /// let frame = located.frame().expect("a plain stream frames every record");
    /// let record = located.value?;
    ///
    /// let mut reader = WarcReader::new(Cursor::new(archive));
    /// assert_eq!(reader.raw_record_at(frame)?, record);
    /// assert_eq!(reader.raw_record_at(frame)?, record);
    /// # Ok::<(), archivindex_warc::io::read::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// A frame holding no record is [`Error::EmptyFrame`], and one holding a further record
    /// after the first and the blank lines after it is [`Error::OverfullFrame`]. A frame that
    /// ends within its record fails as a stream that ends there does.
    pub fn raw_record_at(&mut self, frame: Frame) -> Result<raw::Record, Error> {
        self.reader.seek(SeekFrom::Start(frame.offset))?;
        let mut reading = Reading::new(self.window(frame));

        let (header, expected_body_len) = reading.next_header().ok_or(Error::EmptyFrame)??;
        let body = reading.read_body(expected_body_len)?;

        match reading.next_header() {
            None => Ok(header.with_body(body)),
            Some(Ok(_)) => Err(Error::OverfullFrame),
            Some(Err(error)) => Err(error),
        }
    }

    /// Read the record a frame locates, at the untyped level.
    ///
    /// # Errors
    ///
    /// As for [`raw_record_at`](Self::raw_record_at), and [`Error::Untyped`] when a field's value
    /// does not match its grammar.
    pub fn untyped_record_at(&mut self, frame: Frame) -> Result<untyped::Record, Error> {
        Ok(untyped::Record::try_from(self.raw_record_at(frame)?)?)
    }

    /// Read the record a frame locates, at the semantic level, under the extension `E`.
    ///
    /// # Errors
    ///
    /// As for [`untyped_record_at`](Self::untyped_record_at), and [`Error::Record`] when the
    /// record breaks a rule of its type or its declared version.
    pub fn record_at<E: Extension>(&mut self, frame: Frame) -> Result<record::Record<E>, Error> {
        Ok(record::Record::try_from(self.untyped_record_at(frame)?)?)
    }

    /// The octets of the stream within `frame`, which the reader is positioned at the start of,
    /// with their members decompressed when the stream is gzip.
    #[cfg_attr(not(feature = "gzip"), allow(clippy::missing_const_for_fn))]
    fn window(&mut self, frame: Frame) -> Counted<Source<&mut R>> {
        #[cfg(feature = "gzip")]
        if self.gzip {
            let members = MemberReader::window(&mut self.reader, frame);

            return Counted::new(Source::Members(members));
        }

        Counted::window(Source::Bytes(&mut self.reader), frame)
    }
}

impl WarcReader<BufReader<fs::File>> {
    /// Create a reader for a file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self::new(buffered(path)?))
    }

    /// Create a reader for a gzip-compressed file, whose records are placed in the gzip members
    /// holding them.
    #[cfg(feature = "gzip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self::from_gzip(buffered(path)?))
    }
}

/// Open the file at `path` behind a buffer sized for reading records.
fn buffered<P: AsRef<Path>>(path: P) -> io::Result<BufReader<fs::File>> {
    Ok(BufReader::with_capacity(MB, fs::File::open(path)?))
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

/// Where reading past the blank lines before a record stopped.
struct Padding {
    /// The number of blank lines read.
    blank_lines: usize,
    /// How the read of the line after them ended.
    read: LineRead,
}

/// The stream, reusable header buffer, and error state shared by all iterators in this module.
struct Reading<R> {
    reader: Counted<Source<R>>,
    /// Set once the input has ended or an error has been yielded. Every error here is
    /// stream-level: it leaves the reader at an unspecified position, so iteration fuses rather
    /// than yielding garbage records from the middle of a partly consumed one.
    finished: bool,
    /// Set once the input has ended cleanly, at a record boundary.
    ended: bool,
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
    /// The number of bytes consumed from that header block through the end of the record, or
    /// through the error that ended it.
    length: u64,
    /// Where the record being read began, in the members of a gzip stream.
    start: Position,
    /// Where the record read last lies in the members of a gzip stream.
    placement: Option<Placement>,
}

impl<R> Reading<R> {
    /// The frame of the header block read last and everything consumed after it, through the
    /// end of the record or of the read that failed.
    const fn frame(&self) -> Frame {
        Frame {
            offset: self.offset,
            length: self.length,
        }
    }

    /// The value, located where the record read last lies, with the blank lines before it.
    const fn located<T>(&self, value: T) -> Located<T> {
        let location = match self.placement {
            Some(placement) => Location::Gzip(placement),
            None => Location::Plain(self.frame()),
        };

        Located {
            location,
            blank_lines: self.blank_lines,
            value,
        }
    }

    /// The end of the input, once it has been reached cleanly.
    const fn end(&self) -> Option<Located<()>> {
        if self.ended {
            Some(self.located(()))
        } else {
            None
        }
    }
}

impl<R: BufRead> Reading<R> {
    const fn new(reader: Counted<Source<R>>) -> Self {
        Self {
            reader,
            finished: false,
            ended: false,
            pending: None,
            ahead: None,
            header_buffer: Vec::new(),
            blank_lines: 0,
            offset: 0,
            length: 0,
            start: Position {
                member: 0,
                boundary: false,
                held: 0,
            },
            placement: None,
        }
    }

    /// Read past the blank lines standing before a record, leaving its first line in the header
    /// buffer.
    ///
    /// Writers pad the space between records with blank lines, and concatenating archives
    /// leaves them behind. A blank line where a version line belongs is that padding, so it is
    /// counted and dropped rather than read as the start of a header block.
    ///
    /// In a gzip stream, the placement of the record read last is extended through every member
    /// ended before the padding, or by it, since those hold nothing after the record but blank
    /// lines. The record after the padding begins its member when it, or the padding within its
    /// member, does.
    fn read_past_padding(&mut self) -> Result<Padding, Error> {
        let mut blank_lines = 0;
        let mut began = None;
        loop {
            if let Some(location) = self.reader.get_mut().position() {
                if location.boundary {
                    began = Some(location.member);
                    if let Some(placement) = &mut self.placement {
                        placement.length = Some(location.member - placement.offset);
                    }
                }
                self.start = location;
            }
            match read_line_bounded(&mut self.reader, &mut self.header_buffer, MAX_HEADER_BLOCK)? {
                LineRead::Line(_) if is_blank_line(&self.header_buffer) => {
                    self.header_buffer.clear();
                    blank_lines += 1;
                }
                read => {
                    self.start.boundary = began == Some(self.start.member);
                    return Ok(Padding { blank_lines, read });
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
        // Whatever the header buffer holds was consumed after the padding before it, and begins
        // the record. At the end of the input it holds nothing.
        self.offset = self.reader.position - self.header_buffer.len() as u64;
        let padding = match padding {
            Ok(padding) => padding,
            Err(error) => return Some(self.fuse_on_error(Err(error))),
        };
        self.blank_lines = padding.blank_lines;

        match self.read_header_block(padding.read) {
            None => {
                self.finish();
                self.ended = true;
                None
            }
            Some(Err(error)) => Some(self.fuse_on_error(Err(error))),
            Some(Ok(())) => {
                let parsed = raw::RecordHeader::parse(&self.header_buffer).map_err(Error::Raw);

                Some(self.fuse_on_error(parsed))
            }
        }
    }

    /// End the record read last where reading stopped, placing it in the members of a gzip
    /// stream.
    ///
    /// The members holding a record end only once the next byte is reached, so a gzip stream is
    /// read past the blank lines after the record, up to the first line of the next. Nothing is
    /// read ahead once the stream has ended or failed.
    fn end_record(&mut self) {
        self.length = self.reader.position - self.offset;
        let Some(end) = self.reader.get_mut().position() else {
            return;
        };
        self.placement = Some(Placement::between(self.start, end));
        if self.finished {
            return;
        }

        self.header_buffer.clear();
        match self.read_past_padding() {
            Ok(padding) => self.ahead = Some(padding),
            Err(error) => self.pending = Some(error),
        }
    }

    /// Stop iteration at a clean end of stream.
    fn finish(&mut self) {
        self.finished = true;
        self.end_record();
    }

    /// Read the body a header declared, buffering it.
    fn read_body(&mut self, expected_body_len: u64) -> Result<Vec<u8>, Error> {
        let body = read_body(&mut self.reader, expected_body_len);

        let body = self.fuse_on_error(body)?;
        self.end_record();

        Ok(body)
    }

    /// Consume the body a header declared without buffering it.
    fn skip_body(&mut self, expected_body_len: u64) -> Result<(), Error> {
        let skipped = skip_body(&mut self.reader, expected_body_len);

        self.fuse_on_error(skipped)?;
        self.end_record();

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

    /// Stop iteration if a read failed, since where the reader is left is not known.
    fn fuse_on_error<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.finish();
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
    const fn new(stream: Counted<Source<R>>) -> Self {
        Self {
            reading: Reading::new(stream),
        }
    }
}

impl<R: BufRead> Iterator for RawIter<R> {
    type Item = Located<Result<raw::Record, Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.reading.next_record()?;

        Some(self.reading.located(result))
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
    const fn new(stream: Counted<Source<R>>) -> Self {
        Self {
            raw: RawIter::new(stream),
        }
    }
}

impl<R: BufRead> Iterator for UntypedIter<R> {
    type Item = Located<Result<untyped::Record, Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.raw
                .next()?
                .map(|result| result.and_then(|record| Ok(untyped::Record::try_from(record)?))),
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
    const fn new(stream: Counted<Source<R>>) -> Self {
        Self {
            untyped: UntypedIter::new(stream),
            extension: PhantomData,
        }
    }
}

impl<R: BufRead, E: Extension> Iterator for RecordIter<R, E> {
    type Item = Located<Result<record::Record<E>, Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.untyped
                .next()?
                .map(|result| result.and_then(|record| Ok(record::Record::try_from(record)?))),
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

impl<R: BufRead, F: FnMut(&raw::RecordHeader) -> bool> FilterRawIter<R, F> {
    /// The next record the predicate keeps, or the next error.
    fn next_result(&mut self) -> Option<Result<raw::Record, Error>> {
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

impl<R: BufRead, F: FnMut(&raw::RecordHeader) -> bool> Iterator for FilterRawIter<R, F> {
    type Item = Located<Result<raw::Record, Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.next_result()?;

        Some(self.reading.located(result))
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

impl<R: BufRead, F: FnMut(&untyped::RecordHeader) -> bool> FilterUntypedIter<R, F> {
    /// The next record the predicate keeps, or the next error.
    fn next_result(&mut self) -> Option<Result<untyped::Record, Error>> {
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

impl<R: BufRead, F: FnMut(&untyped::RecordHeader) -> bool> Iterator for FilterUntypedIter<R, F> {
    type Item = Located<Result<untyped::Record, Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.next_result()?;

        Some(self.reading.located(result))
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

impl<R: BufRead, E: Extension, F: FnMut(&record::RecordHeader<E>) -> bool>
    FilterRecordIter<R, F, E>
{
    /// The next record the predicate keeps, or the next error.
    fn next_result(&mut self) -> Option<Result<record::Record<E>, Error>> {
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

impl<R: BufRead, E: Extension, F: FnMut(&record::RecordHeader<E>) -> bool> Iterator
    for FilterRecordIter<R, F, E>
{
    type Item = Located<Result<record::Record<E>, Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.next_result()?;

        Some(self.reading.located(result))
    }
}

located_iterator!(RawIter<R>, reading);
located_iterator!(UntypedIter<R>, raw.reading);
located_iterator!(RecordIter<R, E>, untyped.raw.reading);
located_iterator!(FilterRawIter<R, F>, reading);
located_iterator!(FilterUntypedIter<R, F>, reading);
located_iterator!(FilterRecordIter<R, F, E>, reading);

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
            (Error::EmptyFrame, "the frame holds no record", false),
            (
                Error::OverfullFrame,
                "the frame holds more than one record",
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
        let record = reader
            .iter_untyped_records()
            .records()
            .next()
            .unwrap()
            .unwrap();

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
                .records()
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

        let mut reader = WarcReader::new(create_reader!(raw))
            .iter_raw_records()
            .records();
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

        let mut reader = WarcReader::new(create_reader!(raw))
            .iter_raw_records()
            .records();
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

        let mut raw_iter = WarcReader::new(create_reader!(raw))
            .iter_raw_records()
            .records();
        assert!(raw_iter.next().unwrap().is_ok());
        for _ in 0..3 {
            assert!(raw_iter.next().is_none());
        }

        let mut untyped_iter = WarcReader::new(create_reader!(raw))
            .iter_untyped_records()
            .records();
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
            .records()
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

        let mut reader = WarcReader::new(create_reader!(raw))
            .iter_untyped_records()
            .records();

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
            .records()
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
            .records()
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
            .records()
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

        let mut records = WarcReader::new(&raw[..])
            .filter_raw_records(|_| false)
            .records();

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
            .records()
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

        let mut records = WarcReader::new(&raw[..])
            .filter_untyped_records(|_| true)
            .records();

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
            .records()
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
        let mut records = WarcReader::new(&raw[..])
            .filter_records::<NoExtension, _>(|_| {
                offered += 1;
                true
            })
            .records();

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
            .records()
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

        let mut records = WarcReader::new(&raw[..])
            .iter_records::<NoExtension>()
            .records();

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
                .records()
                .next()
                .unwrap()
                .is_ok()
        );

        for read in [
            WarcReader::new(&raw[..])
                .iter_records::<NoExtension>()
                .records()
                .next(),
            WarcReader::new(&raw[..])
                .filter_records::<NoExtension, _>(|_| true)
                .records()
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
        let mut without = WarcReader::new(SITEMAP_RECORD)
            .iter_records::<NoExtension>()
            .records();
        assert!(matches!(without.next(), Some(Err(Error::Record(_)))));

        let record = WarcReader::new(SITEMAP_RECORD)
            .iter_records::<Sitemaps>()
            .records()
            .next()
            .unwrap()
            .unwrap();

        assert!(matches!(record, Record::Other { .. }));
        assert_eq!(record.type_name(), "sitemap");
    }
}

#[cfg(all(test, feature = "gzip"))]
mod gzip_tests {
    use std::io::{Cursor, Write};

    use flate2::write::GzEncoder;

    use super::{Error, Frame, Placement, WarcReader};
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
            .records()
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
            .records()
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

    /// The placements of the records in a gzip stream, followed by the placement at its end.
    fn placements(stream: &[u8]) -> Vec<Placement> {
        let mut records = WarcReader::from_gzip(stream).iter_raw_records();
        let mut placements = records
            .by_ref()
            .map(|located| located.placement().unwrap())
            .collect::<Vec<_>>();
        placements.push(records.end().unwrap().placement().unwrap());

        placements
    }

    const fn placed(offset: u64, length: Option<u64>, members: u64, begins: bool) -> Placement {
        Placement {
            offset,
            length,
            members,
            begins,
        }
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
        let first_frame = records.next().unwrap().map(Result::unwrap).frame();
        let second_frame = records.next().unwrap().map(Result::unwrap).frame();
        assert!(records.next().is_none());
        let end_frame = records.end().unwrap().frame();

        let frame = |offset, length| Some(Frame { offset, length });
        assert_eq!(first_frame, frame(first.offset, first.length));
        assert_eq!(second_frame, frame(second.offset, second.length));
        assert_eq!(end_frame, frame(size, 0));
    }

    /// A record split over members is placed in all of them, and a record sharing a member with
    /// another has no length of its own unless it begins the member.
    #[test]
    fn places_a_record_in_every_member_holding_it() {
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
        let total = shared.len() as u64;

        assert_eq!(
            placements(&shared),
            [
                placed(0, Some(ends[1]), 2, true),
                placed(ends[1], None, 1, true),
                placed(ends[1], Some(ends[2] - ends[1]), 1, false),
                placed(ends[2], Some(total - ends[2]), 1, true),
                placed(total, Some(0), 0, true),
            ]
        );
    }

    /// Blank lines inside a member belong to the placement of the record before them, and are
    /// reported before the record after them.
    #[test]
    fn places_through_the_blank_lines_after_a_record() {
        let first = stored(&record("http://example.com/first", b"first"));
        let second = stored(&record("http://example.com/second", b"second"));
        let (stream, ends) = members(&[
            &[&first[..], b"\r\n\r\n"].concat(),
            b"\r\n",
            &[b"\r\n", &second[..], b"\r\n"].concat(),
        ]);

        let mut records = WarcReader::from_gzip(&stream[..]).iter_raw_records();
        let first = records.next().unwrap().map(Result::unwrap);
        let second = records.next().unwrap().map(Result::unwrap);
        assert!(records.next().is_none());
        let end = records.end().unwrap();

        assert_eq!(first.placement(), Some(placed(0, Some(ends[1]), 1, true)));
        assert_eq!(second.blank_lines, 4);
        assert_eq!(
            second.placement(),
            Some(placed(ends[1], Some(ends[2] - ends[1]), 1, true))
        );
        assert_eq!(end.blank_lines, 1);
    }

    /// The `filter` iterators skip bodies without reading them, and place records the same.
    #[test]
    fn places_skipped_records_in_their_members() {
        let (stream, ends) = members(&[
            &stored(&record("http://example.com/first", b"first")),
            &stored(&record("http://example.com/second", b"second")),
        ]);

        let placements = WarcReader::from_gzip(&stream[..])
            .filter_raw_records(|header| {
                header.get("WARC-Target-URI") == Some(b" http://example.com/second")
            })
            .map(|located| located.map(Result::unwrap).placement().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            placements,
            [placed(ends[0], Some(ends[1] - ends[0]), 1, true)]
        );
    }

    /// A frame a placement reports reads back as its record, whichever members hold it, and a
    /// frame cut within a member is an error.
    #[test]
    fn reads_the_record_a_placement_frames() {
        let first = stored(&record("http://example.com/first", b"first"));
        let second = stored(&record("http://example.com/second", b"second"));
        let (split_first, split_second) = first.split_at(first.len() / 2);
        let (stream, ends) = members(&[
            split_first,
            split_second,
            b"\r\n",
            &[&second[..], b"\r\n"].concat(),
        ]);

        let framed = WarcReader::from_gzip(&stream[..])
            .iter_raw_records()
            .map(|located| (located.frame().unwrap(), located.value.unwrap()))
            .collect::<Vec<_>>();
        let mut reader = WarcReader::from_gzip(Cursor::new(&stream));
        let read = framed
            .iter()
            .map(|(frame, _)| reader.raw_record_at(*frame).unwrap())
            .collect::<Vec<_>>();
        let cut = reader
            .raw_record_at(Frame {
                offset: ends[2],
                length: ends[3] - ends[2] - 1,
            })
            .unwrap_err();

        assert_eq!(framed[0].0.length, ends[2]);
        assert_eq!(framed.len(), 2);
        assert_eq!(read, [framed[0].1.clone(), framed[1].1.clone()]);
        assert!(matches!(cut, Error::Source(_)));
    }

    /// Octets after the last member fail the read after the record before them, which is placed
    /// whole. The failure leaves an empty placement at the end of the last member, and no end.
    #[test]
    fn reports_what_follows_the_last_member_after_the_record_before_it() {
        let (mut stream, ends) = members(&[&stored(&record("http://example.com/first", b"first"))]);
        stream.extend_from_slice(b"not a member");

        let mut records = WarcReader::from_gzip(&stream[..]).iter_raw_records();
        let first = records.next().unwrap().map(Result::unwrap);
        let failed = records.next().unwrap();

        assert_eq!(first.placement(), Some(placed(0, Some(ends[0]), 1, true)));
        assert!(matches!(failed.value, Err(Error::Source(_))));
        assert_eq!(failed.placement(), Some(placed(ends[0], Some(0), 0, true)));
        assert!(records.next().is_none());
        assert!(records.end().is_none());
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
        let read = records
            .by_ref()
            .map(|located| {
                assert!(located.placement().is_none());
                let frame = located.frame().expect("a plain stream frames every record");
                (located.value.expect("every record reads"), frame)
            })
            .collect();
        let end = records.end().expect("the input ends cleanly");

        (read, end.frame().expect("a plain stream frames its end"))
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

    /// A record that cannot be read is framed by the bytes consumed before the failure, and the
    /// input then has no end.
    #[test]
    fn frames_a_record_that_fails_by_what_was_consumed() {
        let first = record("first");
        let archive = format!("{first}WARC/1.1\r\nContent-Length: 5\r\n\r\nhel");

        let mut records = WarcReader::new(archive.as_bytes()).iter_raw_records();
        records.next().unwrap().value.unwrap();
        let failed = records.next().unwrap();

        assert!(matches!(failed.value, Err(Error::UnexpectedEndOfBody)));
        assert_eq!(
            failed.frame(),
            Some(Frame {
                offset: first.len() as u64,
                length: (archive.len() - first.len()) as u64
            })
        );
        assert!(records.end().is_none());
    }

    /// A record is framed at every level, whether it reads, fails to lift, or is kept by a
    /// filter, and a filter that refuses every record still reaches the end.
    #[test]
    fn frames_at_every_level() {
        let first = record("first");
        let archive = format!("{first}{}", record("second"));
        let second = Some(Frame {
            offset: first.len() as u64,
            length: archive.len() as u64 - first.len() as u64,
        });

        let mut untyped = WarcReader::new(archive.as_bytes()).iter_untyped_records();
        untyped.next().unwrap().value.unwrap();
        assert_eq!(untyped.next().unwrap().map(Result::unwrap).frame(), second);

        let mut lifted = WarcReader::new(archive.as_bytes()).iter_records::<NoExtension>();
        lifted.next().unwrap().value.unwrap_err();
        assert_eq!(
            lifted.next().unwrap().map(Result::unwrap_err).frame(),
            second
        );

        let kept = WarcReader::new(archive.as_bytes())
            .filter_raw_records(|header| header.get("Content-Length") == Some(b" 6"))
            .next()
            .unwrap();
        assert_eq!(kept.frame(), second);
        assert_eq!(kept.value.unwrap().body, b"second");

        let mut refused = WarcReader::new(archive.as_bytes()).filter_untyped_records(|_| false);
        assert!(refused.next().is_none());
        assert_eq!(refused.end().unwrap().frame().unwrap().length, 0);

        let mut filtered =
            WarcReader::new(archive.as_bytes()).filter_records::<NoExtension, _>(|_| true);
        filtered.next().unwrap().value.unwrap_err();
        assert_eq!(
            filtered.next().unwrap().map(Result::unwrap_err).frame(),
            second
        );
    }
}

#[cfg(test)]
mod access_tests {
    use std::io::Cursor;

    use super::{Error, Frame, WarcReader};
    use crate::record::extension::NoExtension;

    /// A WARC 1.1 resource record framed by the length of its body, with the fields the
    /// semantic level requires.
    fn record(body: &str) -> String {
        format!(
            "WARC/1.1\r\n\
             WARC-Type: resource\r\n\
             WARC-Record-ID: <urn:uuid:d0e6a1a0-0000-4000-8000-00000000000{}>\r\n\
             WARC-Date: 2024-04-01T12:00:00Z\r\n\
             WARC-Target-URI: https://example.com/\r\n\
             Content-Length: {}\r\n\r\n{body}\r\n\r\n",
            body.len() % 10,
            body.len()
        )
    }

    /// Frames reported reading `archive` through read back as their records, in any order.
    #[test]
    fn reads_the_record_a_frame_locates() {
        let archive = format!("{}\r\n{}", record("first"), record("second"));
        let framed = WarcReader::new(archive.as_bytes())
            .iter_raw_records()
            .map(|located| (located.frame().unwrap(), located.value.unwrap()))
            .collect::<Vec<_>>();

        let mut reader = WarcReader::new(Cursor::new(&archive));
        let read = framed
            .iter()
            .rev()
            .map(|(frame, _)| reader.raw_record_at(*frame).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(framed.len(), 2);
        assert_eq!(read, [framed[1].1.clone(), framed[0].1.clone()]);
    }

    /// Blank lines within a frame around its record are padding.
    #[test]
    fn reads_through_the_padding_within_a_frame() {
        let only = record("only");
        let archive = format!("\r\n{only}\r\n\r\n");
        let frame = Frame {
            offset: 0,
            length: archive.len() as u64,
        };

        let read = WarcReader::new(Cursor::new(&archive))
            .raw_record_at(frame)
            .unwrap();

        assert_eq!(read.body, b"only");
    }

    /// A frame is refused when it holds no record, a further record, or part of its record.
    #[test]
    fn refuses_a_frame_that_is_not_one_record() {
        let first = record("first");
        let archive = format!("{first}{}", record("second"));
        let mut reader = WarcReader::new(Cursor::new(&archive));
        let frame = |offset: usize, length: usize| Frame {
            offset: offset as u64,
            length: length as u64,
        };

        let empty = reader.raw_record_at(frame(0, 0)).unwrap_err();
        let overfull = reader.raw_record_at(frame(0, archive.len())).unwrap_err();
        let cut = reader.raw_record_at(frame(0, first.len() - 6)).unwrap_err();
        let beyond = reader.raw_record_at(frame(archive.len(), 1)).unwrap_err();

        assert!(matches!(empty, Error::EmptyFrame));
        assert!(matches!(overfull, Error::OverfullFrame));
        assert!(matches!(cut, Error::UnexpectedEndOfBody));
        assert!(matches!(beyond, Error::EmptyFrame));
    }

    /// The untyped and semantic levels lift the record the frame locates, and report what
    /// lifting refuses.
    #[test]
    fn reads_at_every_level() {
        let only = record("only");
        let bare = "WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: 0\r\n\r\n\r\n\r\n";
        let archive = format!("{only}{bare}");
        let mut reader = WarcReader::new(Cursor::new(&archive));
        let full = Frame {
            offset: 0,
            length: only.len() as u64,
        };
        let stripped = Frame {
            offset: only.len() as u64,
            length: bare.len() as u64,
        };

        let untyped = reader.untyped_record_at(full).unwrap();
        let lifted = reader.record_at::<NoExtension>(full).unwrap();
        let refused = reader.record_at::<NoExtension>(stripped).unwrap_err();

        assert_eq!(untyped.body, b"only");
        assert_eq!(lifted.type_name(), "resource");
        assert!(matches!(refused, Error::Record(_)));
    }
}

#[cfg(test)]
mod location_tests {
    use super::{Frame, Location, Placement};

    #[test]
    fn displays_a_frame_by_offset_and_length() {
        let location = Location::Plain(Frame {
            offset: 12,
            length: 345,
        });

        assert_eq!(location.to_string(), "offset 12, length 345");
    }

    #[test]
    fn displays_a_placement_with_its_members_and_any_length() {
        let closed = Location::Gzip(Placement {
            offset: 12,
            length: Some(345),
            members: 1,
            begins: true,
        });
        let open = Location::Gzip(Placement {
            offset: 12,
            length: None,
            members: 2,
            begins: false,
        });

        assert_eq!(closed.to_string(), "offset 12, length 345, 1 member");
        assert_eq!(open.to_string(), "offset 12, 2 members");
    }
}
