//! Writing records to a WARC file, optionally gzip-compressed.

use std::io::{BufWriter, Write};
use std::path::Path;
use std::{fs, io};

#[cfg(feature = "gzip")]
use flate2::write::GzEncoder as GzipWriter;

use crate::io::MB;
use crate::parse::raw;

/// The ways writing a record can fail.
///
/// A write fails either because the sink refused the bytes or because the record failed
/// validation. A rejected record leaves no bytes in the output, so a [`Self::Raw`] means the
/// archive is exactly as it was before the call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying write to the output stream failed.
    #[error("Error writing to output stream.")]
    Sink(#[from] std::io::Error),
    /// The record cannot be written, because an archive holding it could not be read back.
    #[error(transparent)]
    Raw(#[from] raw::Error),
}

#[cfg(test)]
mod error_tests {
    use super::Error;
    use crate::parse::raw;

    /// A sink that refused the bytes is reported as itself, and a record that could not be read
    /// back is reported as the fault the octets have, since that variant is transparent.
    #[test]
    fn each_error_states_its_failure() {
        let sink = Error::Sink(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert_eq!(sink.to_string(), "Error writing to output stream.");
        assert!(std::error::Error::source(&sink).is_some());

        let unreadable = Error::Raw(raw::Error::ContentLengthMismatch {
            declared: 5,
            actual: 7,
        });
        assert_eq!(
            unreadable.to_string(),
            "Content-Length declares 5 bytes, but the body is 7."
        );
        assert!(std::error::Error::source(&unreadable).is_none());
    }
}

/// A writer for WARC records.
pub struct WarcWriter<W> {
    writer: W,
}

impl<W> WarcWriter<W> {
    /// Return a shared reference to the inner writer.
    pub const fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Return a mutable reference to the inner writer.
    pub const fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consume this writer and return the inner writer.
    ///
    /// This method does not flush or otherwise finish the inner writer. Use [`Self::flush`]
    /// first when necessary, or [`Self::finish`] when the inner writer is a
    /// [`std::io::BufWriter`].
    ///
    /// ```
    /// let writer = archivindex_warc::io::write::WarcWriter::new(Vec::new());
    /// let output = writer.into_inner();
    /// assert!(output.is_empty());
    /// ```
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> WarcWriter<W> {
    /// Create a writer for an output stream.
    pub const fn new(w: W) -> Self {
        Self { writer: w }
    }

    /// Flush the inner writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Write a single record.
    ///
    /// The record is validated before anything is emitted, so a record that could not be read
    /// back leaves no partial bytes in the output. The number of bytes written is returned
    /// upon success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sink`] when the output stream refuses the bytes, or [`Error::Raw`]
    /// carrying the reason the record cannot be written.
    pub fn write(&mut self, record: &raw::Record) -> Result<usize, Error> {
        record.write_to(&mut self.writer)
    }
}

impl<W: Write> WarcWriter<BufWriter<W>> {
    /// Flush the buffered writer, then consume it and return its inner writer.
    ///
    /// # Finishing compressed streams
    ///
    /// For gzip output, this flushes only the outer buffer. Call `finish` on the returned gzip
    /// stream to write its trailer.
    #[cfg_attr(
        feature = "gzip",
        doc = r#"

```
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let dir = tempfile::tempdir()?;
let writer =
    archivindex_warc::io::write::WarcWriter::from_path_gzip(dir.path().join("example.warc.gz"))?;
// ... write records ...
let gzip_stream = writer
    .finish()
    .map_err(std::io::IntoInnerError::into_error)?;
gzip_stream.finish()?;
# Ok(())
# }
```"#
    )]
    pub fn finish(self) -> Result<W, std::io::IntoInnerError<BufWriter<W>>> {
        self.writer.into_inner()
    }
}

impl WarcWriter<BufWriter<fs::File>> {
    /// Create a writer that appends to a file.
    ///
    /// The file is created if it does not exist and appended to if it does: existing
    /// records are never overwritten, and the result is a valid archive because WARC files
    /// are defined to be concatenable. To overwrite an existing file with a fresh archive
    /// instead, create the file with [`std::fs::File::create`] and pass it to
    /// [`WarcWriter::new`].
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .create(true)
            .truncate(false)
            .append(true)
            .open(&path)?;
        let writer = BufWriter::with_capacity(MB, file);

        Ok(Self::new(writer))
    }
}

#[cfg(feature = "gzip")]
impl<W: Write> WarcWriter<W> {
    /// Write a single record as an independent gzip member.
    ///
    /// This follows the record-at-a-time compression convention for gzip WARC files: each
    /// record is compressed as its own complete gzip member, so the returned length frames a
    /// range that can be located by an index and decompressed on its own, and consecutive
    /// calls produce a valid multi-member stream (as read by
    /// [`WarcReader::from_path_gzip`](crate::io::read::WarcReader::from_path_gzip)). The member is
    /// finished before this method returns, so no separate finishing step is needed.
    ///
    /// The number of compressed bytes written is returned upon success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sink`] when the output stream refuses the bytes, or [`Error::Raw`]
    /// carrying the reason the record cannot be written.
    pub fn write_gzip(&mut self, record: &raw::Record) -> Result<usize, Error> {
        // Validate before constructing the encoder: an encoder emits a gzip header even for
        // an empty stream when it is finished or dropped, and a rejected record must leave no
        // bytes in the output.
        record.validate()?;

        // The compressed length is what frames the member for indexing, so the encoder's
        // output is counted rather than its input.
        let mut counter = CountingWriter {
            writer: &mut self.writer,
            bytes_written: 0,
        };
        let mut encoder = GzipWriter::new(&mut counter, flate2::Compression::default());
        WarcWriter::new(&mut encoder).write(record)?;
        // Finishing flushes the compressed data and writes the gzip trailer, completing the
        // member; it also releases the encoder's borrow of the counter.
        encoder.finish()?;

        Ok(counter.bytes_written)
    }
}

/// A writer which counts the bytes passing through it.
#[cfg(feature = "gzip")]
struct CountingWriter<W> {
    writer: W,
    bytes_written: usize,
}

#[cfg(feature = "gzip")]
impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(buffer)?;
        self.bytes_written += written;

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod write_tests {
    use std::io::{self, Write};

    use super::{Error, WarcWriter};
    use crate::io::test_record;
    use crate::parse::raw;
    use crate::version::WarcVersion;

    /// A record that could not be read back is rejected before anything is emitted: a value
    /// carrying a line break that would split the field in two, and a name that is not a
    /// token.
    #[test]
    fn write_rejects_a_record_that_could_not_be_read_back() {
        let valid = test_record(
            WarcVersion::V1_1,
            &[("WARC-Type", "resource"), ("WARC-Target-URI", "https://a/")],
            b"body!",
        );

        // The base record is written without complaint.
        let mut writer = WarcWriter::new(Vec::new());
        writer.write(&valid).unwrap();

        for (name, value) in [
            ("WARC-Target-URI", "https://a/\r\nwarc-type: evil"),
            ("evil name", "v"),
        ] {
            let mut record = valid.clone();
            record
                .header
                .headers
                .push((name.to_owned(), value.as_bytes().to_vec()));

            let mut writer = WarcWriter::new(Vec::new());
            let error = writer.write(&record).expect_err("injection is rejected");

            assert!(
                matches!(error, Error::Raw(raw::Error::MalformedFieldLine(_))),
                "{error}"
            );
            assert!(writer.get_ref().is_empty(), "no partial record is written");
        }
    }

    /// A record is written with its field names' spelling and its line order preserved, so an
    /// archive can be rewritten byte for byte. A repeated field is as much a part of that as a
    /// spelling is.
    #[test]
    fn write_preserves_header_spelling_and_order() {
        let raw: &[u8] = b"\
            WARC/1.1\r\n\
            WARC-Type: resource\r\n\
            Warc-Record-Id: <urn:test:spelling:record-0>\r\n\
            WARC-CONCURRENT-TO: <urn:test:spelling:record-1>\r\n\
            WARC-Concurrent-To: <urn:test:spelling:record-2>\r\n\
            content-length:  5\r\n\
            WARC-Date:\t2020-07-08T02:52:55Z\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        let mut writer = WarcWriter::new(Vec::new());
        for record in crate::io::read::WarcReader::new(raw).iter_raw_records() {
            writer.write(&record.unwrap()).unwrap();
        }

        assert_eq!(writer.get_ref().as_slice(), raw);
    }

    /// A record whose declared length does not frame its body is refused, since it would take
    /// the following record's bytes with it when read back.
    #[test]
    fn write_rejects_a_body_the_length_does_not_frame() {
        let mut record = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"body!");
        record.body = b"longer body".to_vec();

        let mut writer = WarcWriter::new(Vec::new());
        let error = writer.write(&record).expect_err("mismatch is rejected");

        assert!(
            matches!(
                error,
                Error::Raw(raw::Error::ContentLengthMismatch {
                    declared: 5,
                    actual: 11
                })
            ),
            "{error}"
        );
        assert!(writer.get_ref().is_empty(), "no partial record is written");
    }

    /// A written record reads back as the record that was written.
    #[test]
    fn written_record_round_trips_through_the_reader() {
        let record = test_record(
            WarcVersion::V1_1,
            &[
                ("WARC-Type", "response"),
                ("WARC-Record-ID", "<urn:test:round-trip:record-0>"),
                ("WARC-Date", "2020-07-08T02:52:55.123456Z"),
                ("WARC-Target-URI", "https://example.com/a?b=c"),
            ],
            b"payload",
        );

        let mut writer = WarcWriter::new(Vec::new());
        writer.write(&record).unwrap();

        let read_back = crate::io::read::WarcReader::new(writer.get_ref().as_slice())
            .iter_raw_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(read_back, vec![record]);
    }

    /// A writer that accepts at most one byte per `write` call.
    struct TrickleWriter(Vec<u8>);

    impl Write for TrickleWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let taken = data.len().min(1);
            self.0.extend_from_slice(&data[..taken]);

            Ok(taken)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_writes_do_not_truncate() {
        let record = test_record(WarcVersion::V1_0, &[("WARC-Type", "dunno")], b"12345");

        let mut writer = WarcWriter::new(TrickleWriter(Vec::new()));
        let bytes_written = writer.write(&record).unwrap();

        let expected: &[u8] =
            b"WARC/1.0\r\nWARC-Type: dunno\r\nContent-Length: 5\r\n\r\n12345\r\n\r\n";
        assert_eq!(writer.get_ref().0.as_slice(), expected);
        assert_eq!(bytes_written, expected.len());
    }

    #[test]
    fn inner_writer_is_accessible_and_recoverable() {
        let mut writer = WarcWriter::new(Vec::new());
        assert!(writer.get_ref().is_empty());

        writer.get_mut().extend_from_slice(b"prefix");
        writer.flush().unwrap();

        assert_eq!(writer.into_inner(), b"prefix");
    }
}

#[cfg(feature = "gzip")]
impl WarcWriter<BufWriter<GzipWriter<std::fs::File>>> {
    /// Create a new writer which writes to a GZIP-compressed file.
    ///
    /// The file is created if it does not exist and appended to if it does: existing
    /// records are never overwritten, and the appended records form a new gzip member,
    /// which is valid in a compressed WARC file and is what `WarcReader::from_path_gzip`
    /// reads. To overwrite an existing file with a fresh archive instead, create the file
    /// with [`std::fs::File::create`], wrap it in a gzip encoder, and pass it to
    /// [`WarcWriter::new`].
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .create(true)
            .truncate(false)
            .append(true)
            .open(&path)?;
        let gzip_stream = GzipWriter::new(file, flate2::Compression::default());
        let writer = BufWriter::with_capacity(MB, gzip_stream);

        Ok(Self::new(writer))
    }
}

#[cfg(test)]
mod from_path_tests {
    use super::WarcWriter;
    use crate::io::test_record;
    use crate::parse::raw;
    use crate::version::WarcVersion;

    fn record_with_body(body: &[u8]) -> raw::Record {
        test_record(WarcVersion::V1_0, &[("WARC-Type", "dunno")], body)
    }

    #[test]
    fn reopening_an_existing_file_appends_to_it() {
        let first = record_with_body(b"the-first-record-written");
        let second = record_with_body(b"appended-later");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.warc");

        for record in [&first, &second] {
            let mut writer = WarcWriter::from_path(&path).unwrap();
            writer.write(record).unwrap();
            writer.finish().unwrap();
        }

        let mut expected_writer = WarcWriter::new(Vec::new());
        expected_writer.write(&first).unwrap();
        expected_writer.write(&second).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), expected_writer.into_inner());
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn reopening_an_existing_gzip_file_appends_a_new_member() {
        let first_body = b"the-first-record-written".to_vec();
        let second_body = b"appended-later".to_vec();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.warc.gz");

        for body in [&first_body, &second_body] {
            let mut writer = WarcWriter::from_path_gzip(&path).unwrap();
            writer.write(&record_with_body(body)).unwrap();
            // The compression stream must be finish()ed, or the member will be truncated.
            let gzip_stream = writer
                .finish()
                .map_err(std::io::IntoInnerError::into_error)
                .unwrap();
            gzip_stream.finish().unwrap();
        }

        let reader = crate::io::read::WarcReader::from_path_gzip(&path).unwrap();
        let bodies: Vec<Vec<u8>> = reader
            .iter_raw_records()
            .map(|record| record.unwrap().body)
            .collect();
        assert_eq!(bodies, vec![first_body, second_body]);
    }
}

#[cfg(all(test, feature = "gzip"))]
mod write_gzip_tests {
    use std::io::{BufReader, Read};

    use super::{Error, WarcWriter};
    use crate::io::test_record;
    use crate::parse::raw;
    use crate::version::WarcVersion;

    /// Parse the records in a plain (uncompressed) WARC byte stream.
    fn read_records(bytes: &[u8]) -> Vec<raw::Record> {
        crate::io::read::WarcReader::new(bytes)
            .iter_raw_records()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Each record becomes its own complete gzip member: the returned lengths frame ranges
    /// that decompress independently, and the concatenation reads back as a multi-member
    /// stream.
    #[test]
    fn each_record_is_an_independently_framed_gzip_member() {
        let first = test_record(
            WarcVersion::V1_1,
            &[("WARC-Type", "resource")],
            b"the first payload",
        );
        let second = test_record(
            WarcVersion::V1_1,
            &[("WARC-Type", "resource")],
            b"the second payload",
        );

        let mut writer = WarcWriter::new(Vec::new());
        let first_length = writer.write_gzip(&first).unwrap();
        let second_length = writer.write_gzip(&second).unwrap();
        let bytes = writer.into_inner();

        // The returned lengths tile the output exactly, as index offsets require.
        assert_eq!(first_length + second_length, bytes.len());

        // Each framed range is a complete gzip member on its own; a single-member decoder
        // must be able to decode it in isolation.
        let (first_member, second_member) = bytes.split_at(first_length);
        for (member, record) in [(first_member, &first), (second_member, &second)] {
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(member)
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(read_records(&decoded), vec![record.clone()]);
        }

        // The whole stream reads back through the multi-member gzip reader.
        let reader = crate::io::read::WarcReader::new(BufReader::new(
            flate2::bufread::MultiGzDecoder::new(bytes.as_slice()),
        ));
        let read_back: Vec<_> = reader.iter_raw_records().collect::<Result<_, _>>().unwrap();
        assert_eq!(read_back, vec![first, second]);
    }

    /// A rejected record leaves no bytes in the output, not even a gzip header.
    #[test]
    fn rejected_record_writes_no_bytes() {
        let mut record = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"body!");
        record
            .header
            .headers
            .push(("WARC-Record-ID".to_owned(), b" <urn:a>\r\nevil: x".to_vec()));

        let mut writer = WarcWriter::new(Vec::new());
        let error = writer
            .write_gzip(&record)
            .expect_err("injection should be rejected");

        assert!(
            matches!(error, Error::Raw(raw::Error::MalformedFieldLine(_))),
            "{error}"
        );
        assert!(writer.get_ref().is_empty(), "no partial member is written");
    }
}
