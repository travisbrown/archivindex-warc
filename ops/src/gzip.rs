//! Reading a gzip file member by member, recording where its members end.
//!
//! [`archivindex_warc::io::gzip::MemberReader`] locates each member in the compressed file. The
//! linter instead needs member boundaries in the decompressed stream after giving the reader to
//! [`Linter`](crate::lint::Linter), so this [`MemberReader`] records them in a shared [`Framing`].

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, BufRead, Read};
use std::rc::Rc;

use archivindex_warc::io::gzip;

/// A handle to where the members of a gzip stream end, shared with the [`MemberReader`]
/// recording them.
#[derive(Clone, Debug, Default)]
pub struct Framing(Rc<RefCell<Reading>>);

/// What a reader has recorded so far.
#[derive(Debug, Default)]
struct Reading {
    /// The number of decompressed bytes consumed.
    position: u64,
    /// The offsets in the decompressed stream at which members ended, not yet taken.
    boundaries: Vec<u64>,
}

impl Framing {
    /// The number of decompressed bytes consumed so far.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.0.borrow().position
    }

    /// Move the member boundaries recorded since the last call onto the back of `into`, in
    /// order.
    pub fn take_boundaries(&self, into: &mut VecDeque<u64>) {
        into.extend(self.0.borrow_mut().boundaries.drain(..));
    }
}

/// A reader over the members of a gzip stream, recording where each ends in what it reads.
pub struct MemberReader<R> {
    members: gzip::MemberReader<R>,
    framing: Framing,
}

impl<R: BufRead> MemberReader<R> {
    /// Read the gzip members of `source`.
    pub fn new(source: R) -> Self {
        Self {
            members: gzip::MemberReader::new(source),
            framing: Framing::default(),
        }
    }

    /// The handle to the framing this reader records.
    #[must_use]
    pub fn framing(&self) -> Framing {
        self.framing.clone()
    }
}

impl<R: BufRead> BufRead for MemberReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let ended = self.members.ended();
        self.members.fill_buf()?;
        // A member ends only once everything decompressed before it was consumed, so every
        // member that ended here ended at the position consumed.
        let mut reading = self.framing.0.borrow_mut();
        let position = reading.position;
        reading
            .boundaries
            .extend((ended..self.members.ended()).map(|_| position));
        drop(reading);

        self.members.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.members.consume(amount);
        self.framing.0.borrow_mut().position += amount as u64;
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    /// The members spelled as one gzip stream.
    fn stream(members: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for member in members {
            let mut encoder = GzEncoder::new(&mut out, Compression::fast());
            encoder
                .write_all(member.as_bytes())
                .expect("a member is written");
            encoder.finish().expect("a member is finished");
        }

        out
    }

    /// Everything a reader reads, with the boundaries it records.
    fn read(stream: &[u8]) -> (String, Vec<u64>) {
        let mut reader = MemberReader::new(stream);
        let framing = reader.framing();
        let mut contents = String::new();
        reader
            .read_to_string(&mut contents)
            .expect("the stream reads");
        let mut boundaries = VecDeque::new();
        framing.take_boundaries(&mut boundaries);

        (contents, boundaries.into())
    }

    /// The members of a stream read as one, as they do through any gzip reader, and every
    /// member's end is recorded where it falls in what was read.
    #[test]
    fn reads_the_members_as_one_stream() {
        let (contents, boundaries) = read(&stream(&["hello", " ", "world"]));

        assert_eq!(contents, "hello world");
        assert_eq!(boundaries, [5, 6, 11]);
    }

    /// A member holding nothing ends where the one before it did.
    #[test]
    fn reads_a_member_holding_nothing() {
        let (contents, boundaries) = read(&stream(&["hello", "", "world"]));

        assert_eq!(contents, "helloworld");
        assert_eq!(boundaries, [5, 5, 10]);
    }

    /// Taking the boundaries leaves only those recorded afterwards.
    #[test]
    fn takes_the_boundaries_recorded_since_the_last_call() {
        let stream = stream(&["hello", "world"]);
        let mut reader = MemberReader::new(&stream[..]);
        let framing = reader.framing();
        let mut boundaries = VecDeque::new();

        reader.read_exact(&mut [0; 6]).expect("six bytes read");
        framing.take_boundaries(&mut boundaries);
        let first = Vec::from(std::mem::take(&mut boundaries));
        reader.read_exact(&mut [0; 4]).expect("four bytes read");
        assert!(reader.fill_buf().expect("the stream ends").is_empty());
        framing.take_boundaries(&mut boundaries);

        assert_eq!(first, [5]);
        assert_eq!(boundaries, [10]);
        assert_eq!(framing.position(), 10);
    }
}
