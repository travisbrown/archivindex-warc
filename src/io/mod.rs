//! Reading and writing WARC files.
//!
//! [`read::WarcReader`] reads a byte stream at any record representation level.
//! [`write::WarcWriter`] writes records back to a byte stream. [`gzip::MemberReader`] reads a
//! gzip file member by member, so that records are framed by member.

use std::io::{self, BufRead, Read};

#[cfg(feature = "gzip")]
#[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
pub mod gzip;
pub mod read;
pub mod write;

/// One binary megabyte, used for reader and writer buffers.
const MB: usize = 1_048_576;

/// A stream that counts the bytes consumed from it.
pub(crate) struct Counted<R> {
    reader: R,
    /// The number of bytes consumed.
    pub(crate) position: u64,
}

impl<R> Counted<R> {
    pub(crate) const fn new(reader: R) -> Self {
        Self {
            reader,
            position: 0,
        }
    }

    pub(crate) const fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.reader.read(buffer)?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: BufRead> BufRead for Counted<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
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
