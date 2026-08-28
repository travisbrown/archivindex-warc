//! Reading and writing WARC files.
//!
//! [`read::WarcReader`] reads a byte stream at any record representation level.
//! [`write::WarcWriter`] writes records back to a byte stream. [`gzip::MemberReader`] reads a
//! gzip file member by member, and [`read::WarcReader::from_gzip`] places records by member.

use std::io::{self, BufRead, Read};

use crate::io::read::Frame;

#[cfg(feature = "gzip")]
#[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
pub mod gzip;
pub mod read;
pub mod write;

/// One binary megabyte, used for reader and writer buffers.
const MB: usize = 1_048_576;

/// A stream that counts the bytes consumed from it, and ends at a limit.
pub(crate) struct Counted<R> {
    reader: R,
    /// The offset of the next byte to read.
    pub(crate) position: u64,
    /// The offset at which the stream ends.
    limit: u64,
}

impl<R> Counted<R> {
    pub(crate) const fn new(reader: R) -> Self {
        Self {
            reader,
            position: 0,
            limit: u64::MAX,
        }
    }

    /// The bytes of `reader` within `frame`, which `reader` is positioned at the start of.
    pub(crate) const fn window(reader: R, frame: Frame) -> Self {
        Self {
            reader,
            position: frame.offset,
            limit: frame.offset.saturating_add(frame.length),
        }
    }

    pub(crate) const fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

impl<R: BufRead> Read for Counted<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let taken = available.len().min(into.len());
        into[..taken].copy_from_slice(&available[..taken]);
        self.consume(taken);

        Ok(taken)
    }
}

impl<R: BufRead> BufRead for Counted<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let remaining = usize::try_from(self.limit - self.position).unwrap_or(usize::MAX);
        let available = self.reader.fill_buf()?;

        Ok(&available[..available.len().min(remaining)])
    }

    fn consume(&mut self, amount: usize) {
        self.reader.consume(amount);
        self.position += amount as u64;
    }
}

/// Build a test record with the given field lines and body.
#[cfg(test)]
pub(crate) fn test_record(
    version: crate::version::WarcVersion,
    lines: &[(&str, &str)],
    body: &[u8],
) -> crate::parse::raw::Record {
    let mut headers: Vec<(String, Vec<u8>)> = lines
        .iter()
        .map(|(name, value)| ((*name).to_owned(), format!(" {value}").into_bytes()))
        .collect();
    headers.push((
        "Content-Length".to_owned(),
        format!(" {}", body.len()).into_bytes(),
    ));

    crate::parse::raw::RecordHeader { version, headers }.with_body(body.to_vec())
}
