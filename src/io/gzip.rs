//! Reading a gzip file member by member.
//!
//! Compressed WARC files conventionally store each record in its own gzip member, allowing records
//! to be located and decompressed independently. [`MemberReader`] exposes the members as one
//! stream while retaining their file offsets, so a
//! [`WarcReader`](crate::io::read::WarcReader) can frame records by member.

use std::io::{self, BufRead, Read};

use flate2::bufread::GzDecoder;

use crate::io::Counted;
use crate::io::read::{Location, Members};

/// The number of bytes a [`MemberReader`] decompresses at a time.
const BUFFER: usize = 64 * 1024;

/// A reader over the members of a gzip stream.
///
/// Members are exposed in order as one decompressed stream. The stream ends with the last member;
/// trailing data that is not another member is an error.
///
/// A [`WarcReader`](crate::io::read::WarcReader) made from it frames each record by the members
/// holding it, so the frame locates the record in the compressed file:
///
/// ```
/// use std::io::{BufReader, Write};
///
/// use archivindex_warc::io::gzip::MemberReader;
/// use archivindex_warc::io::read::WarcReader;
/// use flate2::Compression;
/// use flate2::bufread::GzDecoder;
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
/// let mut records = WarcReader::from_members(MemberReader::new(&file[..])).iter_raw_records();
/// records.next().expect("the first record")?;
/// let second = records.next().expect("the second record")?;
/// let frame = records.frame();
///
/// let start = usize::try_from(frame.offset)?;
/// let end = start + usize::try_from(frame.length)?;
/// let located = WarcReader::new(BufReader::new(GzDecoder::new(&file[start..end])))
///     .iter_raw_records()
///     .next()
///     .expect("the record it frames")?;
/// assert_eq!(located, second);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct MemberReader<R> {
    source: Source<Counted<R>>,
    buffer: Box<[u8]>,
    /// Where the bytes of `buffer` that have not been consumed begin.
    start: usize,
    /// Where the bytes of `buffer` that have been decompressed end.
    end: usize,
    /// The offset in the file of the member the buffer holds.
    member: u64,
    /// The offset in the member's contents of the buffer's first byte.
    chunk: u64,
    /// The offset in the file at which the member read to its end most recently ended.
    ended_at: u64,
    /// The number of members read to their end.
    ended: u64,
}

/// Where the next decompressed byte comes from.
enum Source<R> {
    /// A member is being read.
    Member(Box<GzDecoder<R>>),
    /// The stream is positioned at the start of a member.
    Between(R),
    /// A read failed, which the next read reports.
    Failed(io::Error),
    /// The stream has ended, or a read of it failed and was reported.
    Done,
}

impl<R: BufRead> MemberReader<R> {
    /// Read the gzip members of `source`.
    #[must_use]
    pub fn new(source: R) -> Self {
        Self {
            source: Source::Between(Counted::new(source)),
            buffer: vec![0; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            member: 0,
            chunk: 0,
            ended_at: 0,
            ended: 0,
        }
    }

    /// The number of members read to their end.
    #[must_use]
    pub const fn ended(&self) -> u64 {
        self.ended
    }

    /// Refill the buffer from the member being read, opening the next one where it ends.
    ///
    /// The buffer is left empty once the stream has ended. A failed read ends the stream.
    fn refill(&mut self) -> io::Result<()> {
        loop {
            match std::mem::replace(&mut self.source, Source::Done) {
                Source::Between(mut source) => {
                    // The end of the stream is told from a member before a decoder is opened on
                    // it, since the decoder would report an incomplete header instead.
                    if source.fill_buf()?.is_empty() {
                        return Ok(());
                    }
                    self.member = source.position;
                    self.chunk = 0;
                    self.start = 0;
                    self.end = 0;
                    self.source = Source::Member(Box::new(GzDecoder::new(source)));
                }
                Source::Member(mut decoder) => {
                    let read = decoder.read(&mut self.buffer)?;
                    if read > 0 {
                        self.chunk += self.end as u64;
                        self.start = 0;
                        self.end = read;
                        self.source = Source::Member(decoder);
                        return Ok(());
                    }
                    let source = decoder.into_inner();
                    self.ended_at = source.position;
                    self.ended += 1;
                    self.source = Source::Between(source);
                }
                Source::Failed(error) => return Err(error),
                Source::Done => return Ok(()),
            }
        }
    }
}

impl<R: BufRead> BufRead for MemberReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.start == self.end {
            self.refill()?;
        }

        Ok(&self.buffer[self.start..self.end])
    }

    fn consume(&mut self, amount: usize) {
        self.start += amount.min(self.end - self.start);
    }
}

impl<R: BufRead> Read for MemberReader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let taken = available.len().min(into.len());
        into[..taken].copy_from_slice(&available[..taken]);
        self.consume(taken);

        Ok(taken)
    }
}

impl<R: BufRead> Members for MemberReader<R> {
    fn location(&mut self) -> Location {
        let filled = match self.fill_buf() {
            Ok(bytes) => !bytes.is_empty(),
            Err(error) => {
                self.source = Source::Failed(error);
                false
            }
        };

        if filled {
            Location {
                member: self.member,
                boundary: self.chunk == 0 && self.start == 0,
            }
        } else {
            Location {
                member: self.ended_at,
                boundary: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    /// The members spelled as one gzip stream, with the offset at which each ends.
    fn stream(members: &[&str]) -> (Vec<u8>, Vec<u64>) {
        let mut out = Vec::new();
        let mut ends = Vec::with_capacity(members.len());
        for member in members {
            let mut encoder = GzEncoder::new(&mut out, Compression::fast());
            encoder
                .write_all(member.as_bytes())
                .expect("a member is written");
            encoder.finish().expect("a member is finished");
            ends.push(out.len() as u64);
        }

        (out, ends)
    }

    /// Everything a reader reads, with the number of members it read.
    fn read(stream: &[u8]) -> (String, u64) {
        let mut reader = MemberReader::new(stream);
        let mut contents = String::new();
        reader
            .read_to_string(&mut contents)
            .expect("the stream reads");

        (contents, reader.ended())
    }

    /// The location of a byte that begins the member at `member`.
    const fn boundary(member: u64) -> Location {
        Location {
            member,
            boundary: true,
        }
    }

    /// The members of a stream read as one, as they do through any gzip reader.
    #[test]
    fn reads_the_members_as_one_stream() {
        let (contents, ended) = read(&stream(&["hello", " ", "world"]).0);

        assert_eq!(contents, "hello world");
        assert_eq!(ended, 3);
    }

    /// A member holding nothing is read to its end like any other.
    #[test]
    fn reads_a_member_holding_nothing() {
        let (contents, ended) = read(&stream(&["hello", "", "world"]).0);

        assert_eq!(contents, "helloworld");
        assert_eq!(ended, 3);
    }

    /// A member longer than the buffer is read in several parts, and ends once.
    #[test]
    fn reads_a_member_longer_than_the_buffer() {
        let member = "abcdefgh".repeat(BUFFER / 4);
        let (contents, ended) = read(&stream(&[&member]).0);

        assert_eq!(contents, member);
        assert_eq!(ended, 1);
    }

    #[test]
    fn reads_an_empty_stream_as_nothing() {
        let mut reader = MemberReader::new(&[][..]);

        assert_eq!(reader.location(), boundary(0));
        assert_eq!(read(&[]), (String::new(), 0));
    }

    /// Octets after the last member are not a member, which reading them says.
    #[test]
    fn refuses_what_follows_the_last_member() {
        let (mut stream, _) = stream(&["hello"]);
        stream.extend_from_slice(b"not a member");

        let mut contents = Vec::new();
        let error = MemberReader::new(&stream[..])
            .read_to_end(&mut contents)
            .expect_err("the trailing octets are not a member");

        assert_eq!(contents, b"hello");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// A byte is located by the member holding it, and known to begin the member or not.
    #[test]
    fn locates_each_byte_in_the_file() {
        let (stream, ends) = stream(&["hello", "", "world"]);
        let mut reader = MemberReader::new(&stream[..]);
        let mut read = [0; 2];

        assert_eq!(reader.location(), boundary(0));
        reader.read_exact(&mut read).expect("two bytes read");
        assert_eq!(
            reader.location(),
            Location {
                member: 0,
                boundary: false
            }
        );
        reader.read_exact(&mut [0; 3]).expect("three bytes read");
        // The empty member is read past on the way to the next byte.
        assert_eq!(reader.location(), boundary(ends[1]));
        reader.read_exact(&mut [0; 5]).expect("five bytes read");
        assert_eq!(reader.location(), boundary(ends[2]));
    }

    /// Locating the next byte can fail to open its member, and the read after it reports that.
    #[test]
    fn reports_a_failure_to_locate_on_the_read_that_follows() {
        let (mut stream, ends) = stream(&["hello"]);
        stream.extend_from_slice(b"not a member");
        let mut reader = MemberReader::new(&stream[..]);
        reader.read_exact(&mut [0; 5]).expect("five bytes read");

        assert_eq!(reader.location(), boundary(ends[0]));
        let error = reader
            .fill_buf()
            .expect_err("the trailing octets are not a member");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(reader.fill_buf().expect("the stream has ended").is_empty());
    }
}
