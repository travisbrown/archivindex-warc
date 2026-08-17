use crate::{BufferedBody, RawRecordHeader, Record};

use std::fs;
use std::io;
use std::io::{BufWriter, Write};
use std::path::Path;

#[cfg(feature = "gzip")]
use libflate::gzip::Encoder as GzipWriter;

const MB: usize = 1_048_576;

/// A writer which writes records to an output stream.
pub struct WarcWriter<W> {
    writer: W,
}

impl<W: Write> WarcWriter<W> {
    /// Create a new writer.
    pub fn new(w: W) -> Self {
        WarcWriter { writer: w }
    }

    /// Write a single record.
    ///
    /// The number of bytes written is returned upon success.
    pub fn write(&mut self, record: &Record<BufferedBody>) -> io::Result<usize> {
        let (headers, body) = record.clone().into_raw_parts();
        self.write_raw(headers, &body)
    }

    /// Write a single raw record.
    ///
    /// The number of bytes written is returned upon success.
    pub fn write_raw<B>(&mut self, headers: RawRecordHeader, body: &B) -> io::Result<usize>
    where
        B: AsRef<[u8]>,
    {
        // Validate the whole header block before emitting anything, so that a rejected record
        // leaves no partial bytes in the output.
        validate_raw_header(&headers).map_err(invalid_input)?;

        let writer = &mut self.writer;
        let mut bytes_written = 0;
        // A closure keeps the write-then-count pair in one place. `write_all` loops until the
        // whole slice is accepted, which `write` does not do.
        let mut emit = |data: &[u8]| -> io::Result<()> {
            writer.write_all(data)?;
            bytes_written += data.len();
            Ok(())
        };

        emit(&[87, 65, 82, 67, 47])?;
        emit(headers.version.as_bytes())?;
        emit(&[13, 10])?;

        for (token, value) in headers.as_ref().iter() {
            emit(token.to_string().as_bytes())?;
            emit(&[58, 32])?;
            emit(value)?;
            emit(&[13, 10])?;
        }
        emit(&[13, 10])?;

        emit(body.as_ref())?;
        emit(&[13, 10])?;
        emit(&[13, 10])?;

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
    ///
    /// ```ignore
    /// let gzip_stream = writer.into_inner()?;
    /// gzip_writer.finish().into_result()?;
    /// ```
    ///
    pub fn into_inner(self) -> Result<W, std::io::IntoInnerError<BufWriter<W>>> {
        self.writer.into_inner()
    }
}

impl WarcWriter<BufWriter<fs::File>> {
    /// Create a new writer which writes to a file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let writer = BufWriter::with_capacity(MB, file);

        Ok(WarcWriter::new(writer))
    }
}

#[cfg(feature = "gzip")]
impl WarcWriter<BufWriter<GzipWriter<std::fs::File>>> {
    /// Create a new writer which writes to a GZIP-compressed file.
    pub fn from_path_gzip<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let gzip_stream = GzipWriter::new(file)?;
        let writer = BufWriter::with_capacity(MB, gzip_stream);

        Ok(WarcWriter::new(writer))
    }
}

/// Map a header-validation failure to the `InvalidInput` I/O error reported by the write
/// path, preserving the typed error as its source.
fn invalid_input(error: crate::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

/// Reject a raw header block that would serialize to a record no reader could parse back: a
/// version or value containing a line break, or an unknown header name outside the token
/// grammar.
fn validate_raw_header(headers: &RawRecordHeader) -> Result<(), crate::Error> {
    let version = headers.version.as_bytes();
    if version.contains(&b'\r') || version.contains(&b'\n') {
        return Err(crate::Error::MalformedVersion(headers.version.clone()));
    }

    for (header, value) in headers.as_ref() {
        crate::record::validate_header(header, value)?;
    }

    Ok(())
}

#[cfg(test)]
mod write_raw_tests {
    use super::WarcWriter;
    use crate::{BufferedBody, RawRecordHeader, Record, WarcHeader};
    use std::io::{self, Write};

    /// A block that any writer should accept, to derive rejected blocks from.
    fn valid_headers() -> RawRecordHeader {
        RawRecordHeader {
            version: "1.1".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Assert that writing the given raw header block fails with `InvalidInput` and emits no
    /// bytes.
    fn assert_rejected(headers: RawRecordHeader) {
        let mut writer = WarcWriter::new(Vec::new());
        let error = writer
            .write_raw(headers, b"body!")
            .expect_err("the block should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(writer.writer.is_empty(), "no partial record is written");
    }

    /// Raw header blocks that could not be parsed back are rejected before anything is
    /// written: injected values, invalid unknown names, and an injected version string.
    #[test]
    fn write_raw_rejects_header_injection() {
        let mut injected_value = valid_headers();
        injected_value.as_mut().insert(
            WarcHeader::TargetURI,
            b"https://a/\r\nwarc-type: evil".to_vec(),
        );
        assert_rejected(injected_value);

        let mut invalid_name = valid_headers();
        invalid_name
            .as_mut()
            .insert(WarcHeader::Unknown("evil name".to_string()), b"v".to_vec());
        assert_rejected(invalid_name);

        let mut injected_version = valid_headers();
        injected_version.version = "1.1\r\nevil: x".to_owned();
        assert_rejected(injected_version);

        // The block the three are derived from is written without complaint.
        let mut writer = WarcWriter::new(Vec::new());
        writer.write_raw(valid_headers(), b"body!").unwrap();
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
            version: "1.0".to_owned(),
            headers: vec![(WarcHeader::WarcType, b"dunno".to_vec())]
                .into_iter()
                .collect(),
        };

        let mut writer = WarcWriter::new(TrickleWriter(Vec::new()));
        let bytes_written = writer.write_raw(headers, b"12345").unwrap();

        let expected: &[u8] = b"WARC/1.0\r\nwarc-type: dunno\r\n\r\n12345\r\n\r\n";
        assert_eq!(writer.writer.0.as_slice(), expected);
        assert_eq!(bytes_written, expected.len());
    }

    /// A block frames its body by declaring its length, and a reader trusts that declaration
    /// to find where the record ends, so a block whose `Content-Length` is not the length of
    /// the body it is written with, or that declares none at all, writes a record no reader
    /// can read back.
    #[test]
    #[ignore = "known bug (IO-006: write_raw ignores the declared Content-Length)"]
    fn write_raw_rejects_a_length_the_body_does_not_have() {
        // The body `assert_rejected` writes is five bytes long.
        let mut wrong_length = valid_headers();
        wrong_length
            .as_mut()
            .insert(WarcHeader::ContentLength, b"99".to_vec());
        assert_rejected(wrong_length);

        let mut no_length = valid_headers();
        no_length.as_mut().remove(&WarcHeader::ContentLength);
        assert_rejected(no_length);

        let mut writer = WarcWriter::new(Vec::new());
        writer.write_raw(valid_headers(), b"body!").unwrap();
    }
}
