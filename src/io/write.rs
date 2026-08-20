//! Writing records to a WARC file, optionally gzip-compressed.

use std::io::{BufWriter, Write};
use std::path::Path;
use std::{fs, io};

#[cfg(feature = "gzip")]
use flate2::{GzBuilder, write::GzEncoder as GzipWriter};
use sha2::Digest as _;

use crate::io::MB;
use crate::parse::raw;
use crate::value::{DigestAlgorithm, LabelledDigest};

/// The default gzip compression level used by [`WarcWriter::write_gzip`].
#[cfg(feature = "gzip")]
pub const DEFAULT_GZIP_COMPRESSION_LEVEL: u32 = 6;

/// The greatest gzip compression level accepted by [`WarcWriter::write_gzip_with_level`].
#[cfg(feature = "gzip")]
pub const MAX_GZIP_COMPRESSION_LEVEL: u32 = 9;

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
    /// A gzip compression level was outside the supported range from 0 through 9.
    #[cfg(feature = "gzip")]
    #[error("gzip compression level must be between 0 and 9, got {0}")]
    InvalidGzipCompressionLevel(u32),
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

/// The location, length, and optional digest of a written record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Written {
    /// The offset of the record's first stored byte.
    pub offset: u64,
    /// The number of bytes stored.
    pub length: u64,
    /// The SHA-256 digest of the stored bytes, present when the writer computes digests.
    pub digest: Option<LabelledDigest>,
}

/// A writer for WARC records.
///
/// Offsets count only bytes emitted by this writer's record-writing methods. Writing directly
/// to the inner writer does not advance the tracked position.
pub struct WarcWriter<W> {
    writer: W,
    position: u64,
    digests: bool,
}

impl<W> WarcWriter<W> {
    /// Compute a SHA-256 digest of each record's stored bytes.
    ///
    /// Each record-writing method returns the digest in [`Written`]. For an independent gzip
    /// member, the digest covers the compressed bytes.
    #[must_use]
    pub const fn with_digests(mut self) -> Self {
        self.digests = true;
        self
    }

    /// Return the offset at which the next record will be written.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

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
        Self {
            writer: w,
            position: 0,
            digests: false,
        }
    }

    /// Flush the inner writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Write a single record.
    ///
    /// Validation happens before writing, so an invalid record leaves the output unchanged. A
    /// sink error can leave a partial record; the tracked position includes any bytes the sink
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sink`] when the output stream refuses the bytes, or [`Error::Raw`]
    /// carrying the reason the record cannot be written.
    pub fn write(&mut self, record: &raw::Record) -> Result<Written, Error> {
        let mut tap = TapWriter::new(&mut self.writer, self.digests);
        let result = record.write_to(&mut tap);
        let finished = tap.finish();
        let written = self.frame(finished);
        result?;

        Ok(written)
    }

    /// Advance the position and describe the completed frame.
    fn frame(&mut self, (length, digest): (u64, Option<LabelledDigest>)) -> Written {
        let offset = self.position;
        self.position += length;

        Written {
            offset,
            length,
            digest,
        }
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
    ///
    /// The initial position is the file's existing length.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .create(true)
            .truncate(false)
            .append(true)
            .open(&path)?;
        let position = file.metadata()?.len();
        let mut writer = Self::new(BufWriter::with_capacity(MB, file));
        writer.position = position;

        Ok(writer)
    }
}

#[cfg(feature = "gzip")]
impl<W: Write> WarcWriter<W> {
    /// Write a single record as an independent gzip member.
    ///
    /// This follows the record-at-a-time compression convention for gzip WARC files. Each
    /// record becomes a complete member that can be indexed and decompressed independently;
    /// consecutive calls produce a valid multi-member stream (as read by
    /// [`WarcReader::from_path_gzip`](crate::io::read::WarcReader::from_path_gzip)). The returned
    /// [`Written`] frames the compressed member. The member is finished before this method
    /// returns, so no separate finishing step is needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sink`] when the output stream refuses the bytes, or [`Error::Raw`]
    /// carrying the reason the record cannot be written.
    pub fn write_gzip(&mut self, record: &raw::Record) -> Result<Written, Error> {
        self.write_gzip_with_level(record, DEFAULT_GZIP_COMPRESSION_LEVEL)
    }

    /// Write a single record as an independent gzip member at `level`.
    ///
    /// Levels range from 0 (no compression) through 9 (best compression). The gzip header is
    /// reproducible across platforms: `MTIME` is zero, `OS` is 255, and no optional header fields
    /// are present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidGzipCompressionLevel`] when `level` is greater than 9,
    /// [`Error::Sink`] when the output stream refuses the bytes, or [`Error::Raw`] carrying the
    /// reason the record cannot be written.
    pub fn write_gzip_with_level(
        &mut self,
        record: &raw::Record,
        level: u32,
    ) -> Result<Written, Error> {
        if level > MAX_GZIP_COMPRESSION_LEVEL {
            return Err(Error::InvalidGzipCompressionLevel(level));
        }

        // Validate before constructing the encoder: an encoder emits a gzip header even for
        // an empty stream when it is finished or dropped, and a rejected record must leave no
        // bytes in the output.
        record.validate()?;

        // Indexes frame the compressed member, so measure the encoder's output.
        let mut tap = TapWriter::new(&mut self.writer, self.digests);
        let result = write_member(&mut tap, record, level);
        let finished = tap.finish();
        let written = self.frame(finished);
        result?;

        Ok(written)
    }
}

/// Compress one record as a complete gzip member.
#[cfg(feature = "gzip")]
fn write_member<W: Write>(writer: W, record: &raw::Record, level: u32) -> Result<(), Error> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(writer, flate2::Compression::new(level));
    WarcWriter::new(&mut encoder).write(record)?;
    // `finish` flushes the data and writes the gzip trailer.
    encoder.finish()?;

    Ok(())
}

/// A writer that counts and optionally hashes the bytes passing through it.
struct TapWriter<W> {
    writer: W,
    length: u64,
    hasher: Option<sha2::Sha256>,
}

impl<W> TapWriter<W> {
    fn new(writer: W, digest: bool) -> Self {
        Self {
            writer,
            length: 0,
            hasher: digest.then(sha2::Sha256::new),
        }
    }

    /// Return the byte count and requested digest.
    fn finish(self) -> (u64, Option<LabelledDigest>) {
        let digest = self
            .hasher
            .map(|hasher| LabelledDigest::from_digest(DigestAlgorithm::Sha256, &hasher.finalize()));

        (self.length, digest)
    }
}

impl<W: Write> Write for TapWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(buffer)?;
        self.length += written as u64;

        if let Some(hasher) = &mut self.hasher {
            hasher.update(&buffer[..written]);
        }

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
        let written = writer.write(&record).unwrap();

        let expected: &[u8] =
            b"WARC/1.0\r\nWARC-Type: dunno\r\nContent-Length: 5\r\n\r\n12345\r\n\r\n";
        assert_eq!(writer.get_ref().0.as_slice(), expected);
        assert_eq!(written.length, expected.len() as u64);
    }

    /// Consecutive writes report contiguous frames; digests remain absent unless enabled.
    #[test]
    fn write_reports_the_frame_of_each_record() {
        let first = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"one");
        let second = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"two-two");

        let mut writer = WarcWriter::new(Vec::new());
        let first_written = writer.write(&first).unwrap();
        let second_written = writer.write(&second).unwrap();

        assert_eq!(first_written.offset, 0);
        assert_eq!(second_written.offset, first_written.length);
        assert_eq!(
            writer.position(),
            first_written.length + second_written.length
        );
        assert_eq!(writer.position(), writer.get_ref().len() as u64);
        assert_eq!(first_written.digest, None);
        assert_eq!(second_written.digest, None);
    }

    /// Digesting covers each record's stored bytes.
    #[test]
    fn write_digests_the_stored_bytes() {
        use sha2::Digest as _;

        let record = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"body!");

        let mut writer = WarcWriter::new(Vec::new()).with_digests();
        let written = writer.write(&record).unwrap();

        let expected = crate::value::LabelledDigest::from_digest(
            crate::value::DigestAlgorithm::Sha256,
            &sha2::Sha256::digest(writer.get_ref()),
        );
        assert_eq!(written.digest, Some(expected));
    }

    #[test]
    fn inner_writer_is_accessible_and_recoverable() {
        let mut writer = WarcWriter::new(Vec::new());
        assert_eq!(writer.get_ref().as_slice(), [] as [u8; 0]);

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
    ///
    /// Records written through this writer share one compression stream. Reported offsets count
    /// uncompressed input and therefore do not locate records in the compressed file. To frame
    /// records individually, use [`Self::write_gzip`] with a plain sink.
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

    /// A reopened writer reports offsets from the end of the existing file.
    #[test]
    fn reopened_file_reports_file_offsets() {
        let record = record_with_body(b"the-first-record-written");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.warc");

        let mut writer = WarcWriter::from_path(&path).unwrap();
        let first_written = writer.write(&record).unwrap();
        writer.finish().unwrap();

        assert_eq!(first_written.offset, 0);

        let mut writer = WarcWriter::from_path(&path).unwrap();
        assert_eq!(writer.position(), first_written.length);

        let second_written = writer.write(&record).unwrap();
        assert_eq!(second_written.offset, first_written.length);
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

    use super::{DEFAULT_GZIP_COMPRESSION_LEVEL, Error, WarcWriter};
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

    /// A generated multi-record gzip WARC stores every record in an independent member with the
    /// reproducible header: `MTIME = 0`, `OS = 255`, and no `FHCRC`, `FEXTRA`, `FNAME`, or
    /// `FCOMMENT` fields.
    #[test]
    fn multi_record_gzip_warc_has_independent_reproducible_members() {
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
        let first_written = writer.write_gzip(&first).unwrap();
        let second_written = writer.write_gzip(&second).unwrap();
        let bytes = writer.into_inner();

        // The frames tile the output exactly, as an index requires.
        assert_eq!(first_written.offset, 0);
        assert_eq!(second_written.offset, first_written.length);
        assert_eq!(
            first_written.length + second_written.length,
            bytes.len() as u64
        );

        // Each framed range has the required header and is a complete gzip member on its own; a
        // single-member decoder must be able to decode it in isolation.
        let (first_member, second_member) =
            bytes.split_at(usize::try_from(first_written.length).unwrap());
        for (member, record) in [(first_member, &first), (second_member, &second)] {
            assert_reproducible_header(member, 0);
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

    /// Check every fixed gzip header field. `FLG = 0` confirms `FHCRC`, `FEXTRA`, `FNAME`, and
    /// `FCOMMENT` are all absent (along with `FTEXT` and the reserved flags).
    fn assert_reproducible_header(member: &[u8], xfl: u8) {
        assert_eq!(
            &member[..10],
            &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, 255],
            "ID1 ID2 CM FLG MTIME[4] XFL OS"
        );
    }

    /// The default and configured compression levels preserve deterministic headers and set the
    /// level-dependent `XFL` byte as specified by the encoder.
    #[test]
    fn gzip_headers_are_reproducible_at_all_distinct_xfl_levels() {
        let record = test_record(
            WarcVersion::V1_1,
            &[("WARC-Type", "resource")],
            &[b'a'; 4096],
        );

        for (level, xfl) in [(0, 4), (1, 4), (DEFAULT_GZIP_COMPRESSION_LEVEL, 0), (9, 2)] {
            let mut writer = WarcWriter::new(Vec::new());
            writer.write_gzip_with_level(&record, level).unwrap();
            let member = writer.into_inner();
            assert_reproducible_header(&member, xfl);

            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(member.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(read_records(&decoded), std::slice::from_ref(&record));
        }
    }

    /// An invalid compression level is rejected before a header or any other bytes are emitted.
    #[test]
    fn invalid_gzip_compression_level_writes_no_bytes() {
        let record = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"body");
        let mut writer = WarcWriter::new(Vec::new());

        assert!(matches!(
            writer.write_gzip_with_level(&record, 10),
            Err(Error::InvalidGzipCompressionLevel(10))
        ));
        assert!(writer.get_ref().is_empty());
    }

    /// A gzip member's digest covers the compressed bytes in its reported frame.
    #[test]
    fn write_gzip_digests_the_compressed_member() {
        use sha2::Digest as _;

        let first = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"one");
        let second = test_record(WarcVersion::V1_1, &[("WARC-Type", "resource")], b"two");

        let mut writer = WarcWriter::new(Vec::new()).with_digests();
        let frames = [
            writer.write_gzip(&first).unwrap(),
            writer.write_gzip(&second).unwrap(),
        ];
        let bytes = writer.into_inner();

        for written in frames {
            let start = usize::try_from(written.offset).unwrap();
            let end = start + usize::try_from(written.length).unwrap();
            let expected = crate::value::LabelledDigest::from_digest(
                crate::value::DigestAlgorithm::Sha256,
                &sha2::Sha256::digest(&bytes[start..end]),
            );
            assert_eq!(written.digest, Some(expected));
        }
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
