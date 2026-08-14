use crate::header::WarcHeader;
use crate::{BufferedBody, MB, RawRecordHeader, Record};

use std::fs;
use std::io;
use std::io::{BufWriter, Write};
use std::path::Path;

#[cfg(feature = "gzip")]
use flate2::write::GzEncoder as GzipWriter;

/// A writer which writes records to an output stream.
pub struct WarcWriter<W> {
    writer: W,
}

impl<W: Write> WarcWriter<W> {
    /// Create a new writer.
    pub const fn new(w: W) -> Self {
        Self { writer: w }
    }

    /// Write a single record.
    ///
    /// The number of bytes written is returned upon success.
    pub fn write(&mut self, record: &Record<BufferedBody>) -> io::Result<usize> {
        // Validate every header line before emitting anything, mirroring `write_raw`, so that a
        // rejected record leaves no partial bytes in the output.
        let version = record.warc_version();
        record
            .visit_header_lines(|header, value| {
                crate::record::validate_header(header, value)?;
                crate::record::validate_header_version(version, header)
            })
            .map_err(invalid_input)?;

        let writer = &mut self.writer;
        let mut bytes_written = 0;
        let mut emit = |data: &[u8]| -> io::Result<()> {
            writer.write_all(data)?;
            bytes_written += data.len();
            Ok(())
        };

        emit(b"WARC/")?;
        emit(record.warc_version().as_str().as_bytes())?;
        emit(b"\r\n")?;
        record.visit_header_lines(|header, value| {
            emit(header.name().as_bytes())?;
            emit(b": ")?;
            emit(value)?;
            emit(b"\r\n")
        })?;
        emit(b"\r\n")?;

        emit(record.body())?;
        emit(b"\r\n")?;
        emit(b"\r\n")?;

        Ok(bytes_written)
    }

    /// Write a single raw record.
    ///
    /// The number of bytes written is returned upon success.
    pub fn write_raw<B>(&mut self, headers: &RawRecordHeader, body: &B) -> io::Result<usize>
    where
        B: AsRef<[u8]>,
    {
        let body = body.as_ref();

        // Validate the whole header block against the body it frames before emitting anything,
        // so that a rejected record leaves no partial bytes in the output.
        validate_raw_header(headers, body.len() as u64).map_err(invalid_input)?;

        let writer = &mut self.writer;
        let mut bytes_written = 0;
        // A closure keeps the write-then-count pair in one place. `write_all` loops until the
        // whole slice is accepted, which `write` does not do.
        let mut emit = |data: &[u8]| -> io::Result<()> {
            writer.write_all(data)?;
            bytes_written += data.len();
            Ok(())
        };

        emit(b"WARC/")?;
        emit(headers.version.as_str().as_bytes())?;
        emit(b"\r\n")?;

        for (token, value) in headers.as_ref() {
            emit(token.name().as_bytes())?;
            emit(b": ")?;
            emit(value)?;
            emit(b"\r\n")?;
        }
        // `WARC-Concurrent-To` may repeat: each value becomes its own header line.
        for value in &headers.concurrent_to {
            emit(WarcHeader::ConcurrentTo.name().as_bytes())?;
            emit(b": ")?;
            emit(value)?;
            emit(b"\r\n")?;
        }
        emit(b"\r\n")?;

        emit(body)?;
        emit(b"\r\n")?;
        emit(b"\r\n")?;

        Ok(bytes_written)
    }
}

impl<W: Write> WarcWriter<BufWriter<W>> {
    /// Consume this writer and return the inner writer.
    ///
    /// # Flushing Compressed Data Streams
    ///
    /// This method is necessary to be called at the end of a GZIP-compressed stream. An extra call
    /// is needed to flush the buffer of data, and write a trailer to the output stream.
    #[cfg_attr(
        feature = "gzip",
        doc = r#"

```
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let dir = tempfile::tempdir()?;
let writer = warc::WarcWriter::from_path_gzip(dir.path().join("example.warc.gz"))?;
// ... write records ...
let gzip_stream = writer
    .into_inner()
    .map_err(std::io::IntoInnerError::into_error)?;
gzip_stream.finish()?;
# Ok(())
# }
```"#
    )]
    pub fn into_inner(self) -> Result<W, std::io::IntoInnerError<BufWriter<W>>> {
        self.writer.into_inner()
    }
}

impl WarcWriter<BufWriter<fs::File>> {
    /// Create a new writer which writes to a file.
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

/// Map a header-validation failure to the `InvalidInput` I/O error reported by the write
/// path, preserving the typed error as its source.
fn invalid_input(error: crate::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

/// Reject a raw header block that would serialize to a record no reader could parse back: a
/// value containing a line break, an unknown header name outside the token grammar, or a
/// `Content-Length` that is not the length of the body the block frames.
///
/// The declared length is what a reader counts out to find the end of the record, so a block
/// that declares any other number, or none at all, does not frame the body it is written with.
fn validate_raw_header(headers: &RawRecordHeader, body_len: u64) -> Result<(), crate::Error> {
    for (header, value) in headers.as_ref() {
        crate::record::validate_header(header, value)?;
    }
    // `WARC-Concurrent-To` values live outside the header map, so they need their own pass.
    for value in &headers.concurrent_to {
        crate::record::validate_header(&WarcHeader::ConcurrentTo, value)?;
    }

    let declared = headers
        .as_ref()
        .get(&WarcHeader::ContentLength)
        .ok_or(crate::Error::MissingHeader(WarcHeader::ContentLength))?;
    let declared = std::str::from_utf8(declared)
        .ok()
        .and_then(crate::parse_content_length)
        .ok_or_else(|| {
            crate::Error::MalformedHeader(
                WarcHeader::ContentLength,
                "not a digit sequence between 0 and 2^64-1".to_string(),
            )
        })?;

    if declared == body_len {
        Ok(())
    } else {
        Err(crate::Error::ContentLengthMismatch {
            declared,
            actual: body_len,
        })
    }
}

#[cfg(test)]
mod write_raw_tests {
    use super::WarcWriter;
    use crate::{BufferedBody, RawRecordHeader, Record, WarcHeader};
    use std::io::{self, Write};

    /// A block that any writer should accept, to derive rejected blocks from.
    fn valid_headers() -> RawRecordHeader {
        RawRecordHeader {
            version: crate::WarcVersion::V1_1,
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
            ]
            .into_iter()
            .collect(),
            concurrent_to: Vec::new(),
        }
    }

    /// Assert that writing the given raw header block fails with `InvalidInput` and emits no
    /// bytes.
    fn assert_rejected(headers: &RawRecordHeader) {
        let mut writer = WarcWriter::new(Vec::new());
        let error = writer
            .write_raw(headers, b"body!")
            .expect_err("the block should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(writer.writer.is_empty(), "no partial record is written");
    }

    /// Raw header blocks that could not be parsed back are rejected before anything is
    /// written: injected values, invalid unknown names, and injected `WARC-Concurrent-To`
    /// values.
    #[test]
    fn write_raw_rejects_header_injection() {
        let mut injected_value = valid_headers();
        injected_value.as_mut().insert(
            WarcHeader::TargetURI,
            b"https://a/\r\nwarc-type: evil".to_vec(),
        );
        assert_rejected(&injected_value);

        let mut invalid_name = valid_headers();
        invalid_name
            .as_mut()
            .insert(WarcHeader::Unknown("evil name".to_string()), b"v".to_vec());
        assert_rejected(&invalid_name);

        let mut injected_concurrent_to = valid_headers();
        injected_concurrent_to
            .concurrent_to
            .push(b"<urn:a>\r\nevil: x".to_vec());
        assert_rejected(&injected_concurrent_to);

        // The block the three are derived from is written without complaint.
        let mut writer = WarcWriter::new(Vec::new());
        writer.write_raw(&valid_headers(), b"body!").unwrap();
    }

    /// Typed setters that bypass `set_header` are caught when the record is written.
    #[test]
    fn write_rejects_injection_through_typed_setters() {
        let mut record = Record::<BufferedBody>::default();
        record.set_warc_id("<urn:a>\r\nevil: x");

        let mut writer = WarcWriter::new(Vec::new());
        let error = writer
            .write(&record)
            .expect_err("injection should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(writer.writer.is_empty());
    }

    #[test]
    fn write_matches_into_raw_parts() {
        let mut record = Record::<BufferedBody>::default();
        record.replace_body(b"body-bytes".to_vec());

        let mut record_writer = WarcWriter::new(Vec::new());
        let record_len = record_writer.write(&record).unwrap();

        let (headers, body) = record.into_raw_parts();
        let mut raw_writer = WarcWriter::new(Vec::new());
        let raw_len = raw_writer.write_raw(&headers, &body).unwrap();

        assert_eq!(record_writer.writer, raw_writer.writer);
        assert_eq!(record_len, raw_len);
    }

    /// A written record follows the WARC 1.1 grammar byte for byte: version line, named
    /// fields, and block all terminated by CRLF, with two CRLFs closing the record.
    #[test]
    fn written_record_follows_the_warc_1_1_grammar() {
        let record = crate::RecordBuilder::default()
            .warc_type(crate::RecordType::Response)
            .warc_id("<urn:test:grammar:record-0>")
            .header(WarcHeader::Date, "2020-07-08T02:52:55Z")
            .header(WarcHeader::TargetURI, "https://example.com/")
            .body(b"body".to_vec())
            .build()
            .unwrap();

        let mut writer = WarcWriter::new(Vec::new());
        let bytes_written = writer.write(&record).unwrap();

        let expected: &[u8] = b"WARC/1.1\r\n\
            warc-type: response\r\n\
            warc-record-id: <urn:test:grammar:record-0>\r\n\
            warc-date: 2020-07-08T02:52:55Z\r\n\
            warc-target-uri: https://example.com/\r\n\
            content-length: 4\r\n\
            \r\n\
            body\r\n\
            \r\n";
        assert_eq!(writer.writer.as_slice(), expected);
        assert_eq!(bytes_written, expected.len());
    }

    /// WARC 1.0 dates have second precision, even when the stored instant includes a
    /// fractional second.
    #[test]
    fn warc_1_0_writing_omits_subseconds() {
        let mut record = crate::Record::<crate::BufferedBody>::default();
        record
            .set_header(WarcHeader::Date, "2020-07-08T02:52:55.123456Z")
            .unwrap();
        record.set_warc_version(crate::WarcVersion::V1_0);

        let mut writer = WarcWriter::new(Vec::new());
        writer.write(&record).unwrap();

        let written = String::from_utf8(writer.writer).unwrap();
        assert!(
            written.contains("warc-date: 2020-07-08T02:52:55Z\r\n"),
            "{written:?}"
        );
    }

    /// The typed writer does not emit either of the fields added in WARC 1.1 on a WARC 1.0
    /// record.
    #[test]
    fn warc_1_0_writing_rejects_warc_1_1_headers() {
        for (header, value) in [
            (WarcHeader::RefersToDate, "2020-07-07T02:52:55Z"),
            (WarcHeader::RefersToTargetURI, "https://example.com/"),
        ] {
            let mut record = crate::Record::<crate::BufferedBody>::default();
            record.set_warc_version(crate::WarcVersion::V1_0);
            record.set_header(header.clone(), value).unwrap();

            let mut writer = WarcWriter::new(Vec::new());
            let error = writer
                .write(&record)
                .expect_err("WARC 1.1-only header should be rejected");

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(writer.writer.is_empty(), "no partial record is written");
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<crate::Error>()),
                Some(crate::Error::MalformedHeader(actual_header, _))
                    if actual_header == &header
            ));
        }
    }

    /// A record written by the writer reads back identically, including a sub-second
    /// `WARC-Date`, which WARC 1.1 permits at up to nanosecond precision.
    #[test]
    fn written_record_round_trips_through_the_reader() {
        let mut record = Record::with_body("payload");
        record
            .set_header(WarcHeader::TargetURI, "https://example.com/a?b=c")
            .unwrap();

        let mut writer = WarcWriter::new(Vec::new());
        writer.write(&record).unwrap();

        let read_back = crate::WarcReader::new(writer.writer.as_slice())
            .iter_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(read_back, vec![record]);
    }

    /// Repeated `WARC-Concurrent-To` values are each written as their own header line and
    /// survive a round trip through the reader.
    #[test]
    fn repeated_concurrent_to_round_trips() {
        let mut record = crate::Record::with_body("payload");
        record.add_concurrent_to("<urn:test:concurrent:record-1>");
        record.add_concurrent_to("<urn:test:concurrent:record-2>");

        let mut writer = WarcWriter::new(Vec::new());
        writer.write(&record).unwrap();

        let written = String::from_utf8(writer.writer.clone()).unwrap();
        assert_eq!(
            written
                .matches("warc-concurrent-to: <urn:test:concurrent:record-")
                .count(),
            2
        );

        let read_back = crate::WarcReader::new(writer.writer.as_slice())
            .iter_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(read_back, vec![record]);
    }

    /// A writer that accepts at most one byte per `write` call.
    struct TrickleWriter(Vec<u8>);

    impl Write for TrickleWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let n = data.len().min(1);
            self.0.extend_from_slice(&data[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_writes_do_not_truncate() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
            ]
            .into_iter()
            .collect(),
            concurrent_to: Vec::new(),
        };

        let mut writer = WarcWriter::new(TrickleWriter(Vec::new()));
        let bytes_written = writer.write_raw(&headers, b"12345").unwrap();

        // The field order follows the header map's iteration order, so check the lines
        // rather than one fixed serialization of the block.
        let written = String::from_utf8(writer.writer.0).unwrap();
        assert!(written.starts_with("WARC/1.0\r\n"), "{}", written);
        assert!(written.contains("warc-type: dunno\r\n"), "{}", written);
        assert!(written.contains("content-length: 5\r\n"), "{}", written);
        assert!(written.ends_with("\r\n\r\n12345\r\n\r\n"), "{}", written);
        assert_eq!(bytes_written, written.len());
    }

    /// A block frames its body by declaring its length, and a reader trusts that declaration
    /// to find where the record ends, so a block whose `Content-Length` is not the length of
    /// the body it is written with, or that declares none at all, writes a record no reader
    /// can read back.
    #[test]
    fn write_raw_rejects_a_length_the_body_does_not_have() {
        // The body `assert_rejected` writes is five bytes long.
        let mut wrong_length = valid_headers();
        wrong_length
            .as_mut()
            .insert(WarcHeader::ContentLength, b"99".to_vec());
        assert_rejected(&wrong_length);

        let mut no_length = valid_headers();
        no_length.as_mut().shift_remove(&WarcHeader::ContentLength);
        assert_rejected(&no_length);

        let mut writer = WarcWriter::new(Vec::new());
        writer.write_raw(&valid_headers(), b"body!").unwrap();
    }
}

#[cfg(test)]
mod from_path_tests {
    use super::WarcWriter;
    use crate::{RawRecordHeader, WarcHeader};

    fn record_with_body(body: &[u8]) -> RawRecordHeader {
        RawRecordHeader {
            version: crate::WarcVersion::V1_0,
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (
                    WarcHeader::ContentLength,
                    body.len().to_string().into_bytes(),
                ),
            ]
            .into_iter()
            .collect(),
            concurrent_to: Vec::new(),
        }
    }

    #[test]
    fn reopening_an_existing_file_appends_to_it() {
        let first_body = &b"the-first-record-written"[..];
        let second_body = &b"appended-later"[..];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.warc");

        let mut writer = WarcWriter::from_path(&path).unwrap();
        writer
            .write_raw(&record_with_body(first_body), &first_body)
            .unwrap();
        writer.into_inner().unwrap();

        let mut writer = WarcWriter::from_path(&path).unwrap();
        writer
            .write_raw(&record_with_body(second_body), &second_body)
            .unwrap();
        writer.into_inner().unwrap();

        let mut expected_writer = WarcWriter::new(Vec::new());
        expected_writer
            .write_raw(&record_with_body(first_body), &first_body)
            .unwrap();
        expected_writer
            .write_raw(&record_with_body(second_body), &second_body)
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), expected_writer.writer);
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
            writer.write_raw(&record_with_body(body), body).unwrap();
            // The compression stream must be finish()ed, or the member will be truncated.
            let gzip_stream = writer
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)
                .unwrap();
            gzip_stream.finish().unwrap();
        }

        let reader = crate::WarcReader::from_path_gzip(&path).unwrap();
        let bodies: Vec<Vec<u8>> = reader
            .iter_raw_records()
            .map(|record| record.unwrap().1)
            .collect();
        assert_eq!(bodies, vec![first_body, second_body]);
    }
}
