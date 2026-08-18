//! A simple record representation, with minimal validation.
//!
//! This is the crate's lowest representation level. A [`Record`] contains a declared version,
//! field lines, and a fully buffered body. Field names preserve their case, and values preserve
//! all white space and folded continuations.
//!
//! Only `Content-Length` is interpreted because it is needed to find the end of the body.
//!
//! Raw records support byte-exact round-tripping.
//! [`untyped::Record`](crate::parse::untyped::Record) parses field values, and
//! [`record::Record`](crate::record::Record) validates their meaning.

use std::io::Write;

use crate::parse;
use crate::parsing::{
    is_folded_value, is_lws, is_token_char, lossy, parse_content_length, split_field_line,
};
use crate::version::WarcVersion;

/// The ways a run of octets can fail to be a record.
///
/// These are faults in the record itself, so the same error serves both reading and writing.
/// Stream-level failures are [`io::read::Error`](crate::io::read::Error) and
/// [`io::write::Error`](crate::io::write::Error).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The record's version line names a version this crate does not support.
    #[error(transparent)]
    MalformedVersion(#[from] crate::version::Error),
    /// The record does not open with a `WARC/` version line at all.
    ///
    /// Carries the line that was read in its place, which names no version to report.
    #[error("Malformed version line: {0}")]
    MalformedVersionLine(String),
    /// A header line does not match the `field-name ":" field-value` grammar.
    ///
    /// This includes an invalid name, a missing colon, an unattached continuation, or a line break
    /// outside a fold. Carries the offending line when parsing, or its field name when validating.
    #[error("Malformed field line: {0}")]
    MalformedFieldLine(String),
    /// The input ended before the header block's terminating blank line.
    ///
    /// Bare `LF` line endings also produce this error because WARC header lines require `CRLF`.
    #[error("Unexpected end of header block.")]
    UnexpectedEndOfHeaderBlock,
    /// A record carries no `Content-Length`, so its body cannot be framed.
    #[error("Missing Content-Length.")]
    MissingContentLength,
    /// A record carries more than one `Content-Length`, so where its body ends depends on which
    /// one a reader takes.
    #[error("Repeated Content-Length.")]
    RepeatedContentLength,
    /// A record's `Content-Length` is not the `1*DIGIT` the grammar requires, or names a length
    /// beyond the unsigned 64-bit range.
    #[error("Malformed Content-Length: {0}")]
    MalformedContentLength(String),
    /// A record's declared `Content-Length` does not match the body it carries, so writing it
    /// would produce an archive that cannot be read back.
    #[error("Content-Length declares {declared} bytes, but the body is {actual}.")]
    ContentLengthMismatch {
        /// The length the record's `Content-Length` field declares.
        declared: u64,
        /// The length of the body the record actually carries.
        actual: u64,
    },
}

/// A header block whose field lines are preserved as written.
///
/// A name is the token before the colon, in its original case. A value is every byte between the
/// colon and the CRLF ending the field, including leading and trailing white space and the
/// `CRLF SP` sequences of any folded continuation lines. A header block read from an archive
/// writes back byte for byte.
pub type RecordHeader = parse::RecordHeader<String, Vec<u8>>;

impl RecordHeader {
    /// Parse a complete header block, including its terminating blank line.
    ///
    /// Returns the header block together with the `Content-Length` that frames the body to come.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedVersionLine`] when the block does not begin with a `WARC/`
    /// version line and [`Error::MalformedVersion`] when that line names a version this crate
    /// does not support, [`Error::MalformedFieldLine`] when a line is not
    /// `field-name ":" field-value` or holds a line break that does not fold the value,
    /// [`Error::UnexpectedEndOfHeaderBlock`] when the block does not
    /// end with its blank line, and [`Error::MissingContentLength`],
    /// [`Error::RepeatedContentLength`], or [`Error::MalformedContentLength`] when the body cannot
    /// be framed.
    pub fn parse(block: &[u8]) -> Result<(Self, u64), Error> {
        let mut cursor = 0;
        let (start, end) = next_line(block, &mut cursor)?;
        let version = parse_version_line(&block[start..end])?;

        let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
        let mut content_length: Option<u64> = None;

        loop {
            let (start, end) = next_line(block, &mut cursor)?;
            // The blank line ends the block, and nothing may follow it.
            if start == end {
                if cursor != block.len() {
                    return Err(Error::MalformedFieldLine(lossy(&block[cursor..])));
                }
                break;
            }

            let line = &block[start..end];
            // A line here must open a field with a name and a colon. That rules out a line
            // beginning with linear white space (a continuation with nothing to continue) and
            // white space between the name and the colon (which a `warc-fields` body tolerates
            // but the header block grammar does not allow).
            let (name, colon) = split_field_line(line)
                .filter(|&(name, colon)| colon == name.len())
                .ok_or_else(|| Error::MalformedFieldLine(lossy(line)))?;

            // Folded continuation lines are contiguous with the value in the block, so the whole
            // value, folds and all, is one slice of the input rather than a copy per line.
            // `value_end` walks forward over each continuation.
            let value_start = start + colon + 1;
            let mut value_end = end;
            while block.get(cursor).copied().is_some_and(is_lws) {
                let (_, fold_end) = next_line(block, &mut cursor)?;
                value_end = fold_end;
            }

            // The name is a token, which admits only ASCII, so the lossy conversion never
            // actually replaces anything.
            let name = String::from_utf8_lossy(name).into_owned();
            let value = &block[value_start..value_end];

            // A CR that opens no fold would have ended the field line, and every layer above
            // reads one in a value as a fold, so it is refused here rather than carried along.
            if !is_folded_value(value) {
                return Err(Error::MalformedFieldLine(lossy(&block[start..value_end])));
            }

            if name.eq_ignore_ascii_case(CONTENT_LENGTH) {
                if content_length.is_some() {
                    return Err(Error::RepeatedContentLength);
                }
                content_length = Some(parse_length(value)?);
            }

            headers.push((name, value.to_vec()));
        }

        let content_length = content_length.ok_or(Error::MissingContentLength)?;

        Ok((Self { version, headers }, content_length))
    }

    /// The value of the first field with the given name, compared case-insensitively.
    ///
    /// The value is returned as it was read, so a caller wanting the value without its surrounding
    /// white space must trim it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.find(|field| field.eq_ignore_ascii_case(name))
            .map(Vec::as_slice)
    }

    /// The values of every field with the given name, compared case-insensitively, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        self.find_all(move |field| field.eq_ignore_ascii_case(name))
            .map(Vec::as_slice)
    }

    /// Validate this header block and return its declared `Content-Length`.
    ///
    /// Every field name must be a token, and no value may contain a bare CR or LF: the only line
    /// break a value may hold is the `CRLF SP` or `CRLF HTAB` of a fold, which continues the value
    /// rather than ending it. `Content-Length` must appear exactly once and must be `1*DIGIT`.
    /// Whether it matches the length of the body is checked by [`Record::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedFieldLine`], [`Error::MissingContentLength`],
    /// [`Error::RepeatedContentLength`], or [`Error::MalformedContentLength`].
    pub fn validate(&self) -> Result<u64, Error> {
        let mut declared = None;

        for (name, value) in &self.headers {
            if name.is_empty() || !name.bytes().all(is_token_char) {
                return Err(Error::MalformedFieldLine(name.clone()));
            }
            if !is_folded_value(value) {
                return Err(Error::MalformedFieldLine(name.clone()));
            }

            if name.eq_ignore_ascii_case(CONTENT_LENGTH) {
                if declared.is_some() {
                    return Err(Error::RepeatedContentLength);
                }
                declared = Some(parse_length(value)?);
            }
        }

        declared.ok_or(Error::MissingContentLength)
    }

    /// The number of bytes the header block occupies, including the blank line ending it.
    #[must_use]
    pub fn rendered_len(&self) -> usize {
        // "WARC/" + version + CRLF, then ":" and CRLF per field, then the closing CRLF.
        let version_line = 5 + self.version.as_str().len() + 2;
        let fields: usize = self
            .headers
            .iter()
            .map(|(name, value)| name.len() + 1 + value.len() + 2)
            .sum();

        version_line + fields + 2
    }

    /// Write the header block and return the number of bytes written.
    ///
    /// The block is validated first, so one that cannot be written emits nothing.
    ///
    /// # Errors
    ///
    /// Returns [`write::Error::Raw`](crate::io::write::Error::Raw) carrying the validation
    /// failure that stopped the write, or [`write::Error::Sink`](crate::io::write::Error::Sink)
    /// carrying a failure of the writer itself.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<usize, crate::io::write::Error> {
        self.validate()?;

        Ok(self.write(writer)?)
    }

    /// Write the header block without validating it, which the caller is assumed to have done.
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<usize> {
        let mut written = 0;
        let mut emit = |bytes: &[u8]| -> std::io::Result<()> {
            writer.write_all(bytes)?;
            written += bytes.len();
            Ok(())
        };

        emit(b"WARC/")?;
        emit(self.version.as_str().as_bytes())?;
        emit(b"\r\n")?;
        for (name, value) in &self.headers {
            emit(name.as_bytes())?;
            emit(b":")?;
            emit(value)?;
            emit(b"\r\n")?;
        }
        emit(b"\r\n")?;

        Ok(written)
    }
}

/// A WARC record held close to its raw bytes.
///
/// A record assembled by hand can be inconsistent, most obviously by declaring a `Content-Length`
/// that does not match its body. [`validate`](Record::validate) catches this, and writing performs
/// it, so an inconsistent record cannot reach an archive.
pub type Record = parse::Record<String, Vec<u8>>;

impl Record {
    /// Validate this record for writing.
    ///
    /// The header block must pass [`RecordHeader::validate`], and the `Content-Length` it declares
    /// must equal the length of the body it frames.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedFieldLine`], [`Error::MissingContentLength`],
    /// [`Error::MalformedContentLength`], or [`Error::ContentLengthMismatch`].
    pub fn validate(&self) -> Result<(), Error> {
        let declared = self.header.validate()?;
        let actual = self.content_length();
        if declared != actual {
            return Err(Error::ContentLengthMismatch { declared, actual });
        }

        Ok(())
    }

    /// Write the complete record and return the number of bytes written.
    ///
    /// The record is validated first, so a record that cannot be written emits nothing.
    ///
    /// # Errors
    ///
    /// Returns [`write::Error::Raw`](crate::io::write::Error::Raw) carrying the validation
    /// failure that stopped the write, or [`write::Error::Sink`](crate::io::write::Error::Sink)
    /// carrying a failure of the writer itself.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<usize, crate::io::write::Error> {
        self.validate()?;

        Ok(self.write(writer)?)
    }

    /// Write the record without validating it, which the caller is assumed to have done.
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<usize> {
        let header_len = self.header.write(writer)?;
        writer.write_all(&self.body)?;
        writer.write_all(b"\r\n\r\n")?;

        Ok(header_len + self.body.len() + 4)
    }

    /// The complete record as bytes.
    ///
    /// # Errors
    ///
    /// Returns the validation failure that stopped the write.
    ///
    /// # Panics
    ///
    /// This uses a `Vec` as the writer, whose [`std::io::Write`] implementation cannot fail.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;

        let mut bytes = Vec::with_capacity(self.header.rendered_len() + self.body.len() + 4);
        self.write(&mut bytes)
            .expect("invariant violation: writing into a Vec cannot fail");

        Ok(bytes)
    }
}

/// The one field name this layer knows.
const CONTENT_LENGTH: &str = "content-length";

/// The bounds of the next `\r\n`-terminated line, advancing `cursor` past its terminator.
///
/// Returns the line's start and the offset of its `\r`, so that a caller tracking a folded value
/// can extend it to the end of a continuation without copying.
fn next_line(block: &[u8], cursor: &mut usize) -> Result<(usize, usize), Error> {
    let start = *cursor;
    let line = crate::parsing::next_line(block, start).ok_or(Error::UnexpectedEndOfHeaderBlock)?;
    // The standard terminates every line with CRLF, and a bare LF inside a header block would
    // otherwise be read as a line ending whose CR belonged to a value.
    if !line.crlf {
        return Err(Error::MalformedFieldLine(lossy(&block[start..line.end])));
    }

    *cursor = line.next;

    Ok((start, line.end))
}

/// Read a `WARC/<version>` line.
fn parse_version_line(line: &[u8]) -> Result<WarcVersion, Error> {
    let version = line
        .strip_prefix(b"WARC/")
        .and_then(|version| std::str::from_utf8(version).ok())
        .ok_or_else(|| Error::MalformedVersionLine(lossy(line)))?;

    Ok(version.parse()?)
}

/// Read a `Content-Length` value, which the grammar surrounds with optional linear white space.
fn parse_length(value: &[u8]) -> Result<u64, Error> {
    std::str::from_utf8(value)
        .ok()
        .and_then(parse_content_length)
        .ok_or_else(|| Error::MalformedContentLength(lossy(value)))
}

#[cfg(test)]
mod tests {
    use super::{Error, RecordHeader};
    use crate::version::WarcVersion;

    /// A header block with the given field lines, terminated as the standard requires.
    fn block(lines: &[&str]) -> Vec<u8> {
        let mut block = b"WARC/1.0\r\n".to_vec();
        for line in lines {
            block.extend_from_slice(line.as_bytes());
            block.extend_from_slice(b"\r\n");
        }
        block.extend_from_slice(b"\r\n");

        block
    }

    #[test]
    fn parses_a_minimal_block() {
        let (header, length) =
            RecordHeader::parse(&block(&["WARC-Type: response", "Content-Length: 5"])).unwrap();

        assert_eq!(header.version, WarcVersion::V1_0);
        assert_eq!(length, 5);
        assert_eq!(
            header.headers,
            vec![
                ("WARC-Type".to_string(), b" response".to_vec()),
                ("Content-Length".to_string(), b" 5".to_vec()),
            ]
        );
    }

    /// The value is every byte after the colon, so the white space surrounding it is kept
    /// rather than trimmed away.
    #[test]
    fn keeps_surrounding_whitespace_in_the_value() {
        let (header, _) =
            RecordHeader::parse(&block(&["Content-Length:\t 7  ", "X-Empty:"])).unwrap();

        assert_eq!(header.headers[0].1, b"\t 7  ");
        assert_eq!(header.headers[1].1, b"");
    }

    /// A fold is kept exactly, CRLF and all, rather than being rewritten as one space.
    #[test]
    fn keeps_folds_verbatim() {
        let source = b"WARC/1.1\r\nX-Long: one\r\n  two\r\n\tthree\r\nContent-Length: 0\r\n\r\n";
        let (header, length) = RecordHeader::parse(source).unwrap();

        assert_eq!(header.version, WarcVersion::V1_1);
        assert_eq!(length, 0);
        assert_eq!(header.headers[0].1, b" one\r\n  two\r\n\tthree");
    }

    /// What was read is what is written.
    #[test]
    fn rewrites_a_block_byte_for_byte() {
        let source: &[u8] =
            b"WARC/1.1\r\nwarc-type:  metadata\r\nX-Long: one\r\n  two\r\nContent-Length: 3\r\n\r\n";
        let (header, _) = RecordHeader::parse(source).unwrap();

        let mut written = Vec::new();
        let count = header.write_to(&mut written).unwrap();

        assert_eq!(written, source);
        assert_eq!(count, source.len());
        assert_eq!(count, header.rendered_len());
    }

    #[test]
    fn writes_a_whole_record() {
        let (header, _) = RecordHeader::parse(&block(&["Content-Length: 3"])).unwrap();
        let record = header.with_body(b"abc".to_vec());

        assert_eq!(
            record.to_bytes().unwrap(),
            b"WARC/1.0\r\nContent-Length: 3\r\n\r\nabc\r\n\r\n"
        );
    }

    /// Field names are case-insensitive, and a name the standard lets repeat keeps every value.
    #[test]
    fn finds_fields_in_any_case() {
        let (header, length) = RecordHeader::parse(&block(&[
            "CONTENT-length: 4",
            "WARC-Concurrent-To: <urn:uuid:one>",
            "warc-concurrent-to: <urn:uuid:two>",
        ]))
        .unwrap();

        assert_eq!(length, 4);
        assert_eq!(header.get("content-length"), Some(&b" 4"[..]));
        assert_eq!(
            header.get_all("WARC-Concurrent-To").collect::<Vec<_>>(),
            vec![&b" <urn:uuid:one>"[..], &b" <urn:uuid:two>"[..]]
        );
        assert_eq!(header.get("absent"), None);
    }

    #[test]
    fn rejects_a_block_that_cannot_be_framed() {
        assert!(matches!(
            RecordHeader::parse(&block(&["WARC-Type: response"])),
            Err(Error::MissingContentLength)
        ));
        assert!(matches!(
            RecordHeader::parse(&block(&["Content-Length: +5"])),
            Err(Error::MalformedContentLength(_))
        ));
        assert!(matches!(
            RecordHeader::parse(&block(&["Content-Length: 5 5"])),
            Err(Error::MalformedContentLength(_))
        ));
    }

    /// A line naming a version is reported as the version it names, so the fault a caller reads
    /// is the version number alone. A line naming none is reported as the line, since there is
    /// no version in it to report.
    #[test]
    fn rejects_a_malformed_version_line() {
        assert_eq!(
            RecordHeader::parse(b"WARC/9.9\r\nContent-Length: 0\r\n\r\n"),
            Err(Error::MalformedVersion(crate::version::Error(
                "9.9".to_owned()
            )))
        );
        assert_eq!(
            RecordHeader::parse(b"Content-Length: 0\r\n\r\n"),
            Err(Error::MalformedVersionLine("Content-Length: 0".to_owned()))
        );
        assert_eq!(
            RecordHeader::parse(b"WARC/\xff\r\nContent-Length: 0\r\n\r\n"),
            Err(Error::MalformedVersionLine("WARC/\u{fffd}".to_owned()))
        );
    }

    #[test]
    fn rejects_malformed_field_lines() {
        // No colon.
        assert!(matches!(
            RecordHeader::parse(&block(&["Content-Length: 0", "nonsense"])),
            Err(Error::MalformedFieldLine(_))
        ));
        // A name that is not a token.
        assert!(matches!(
            RecordHeader::parse(&block(&["Content-Length: 0", "bad name: x"])),
            Err(Error::MalformedFieldLine(_))
        ));
        // A name with whitespace before the colon, which the token grammar forbids.
        assert!(matches!(
            RecordHeader::parse(&block(&["Content-Length: 0", "Name : x"])),
            Err(Error::MalformedFieldLine(_))
        ));
        // A continuation with nothing to continue.
        assert!(matches!(
            RecordHeader::parse(b"WARC/1.0\r\n  folded\r\n\r\n"),
            Err(Error::MalformedFieldLine(_))
        ));
        // A bare LF, which would otherwise leave a stray CR in a value.
        assert!(matches!(
            RecordHeader::parse(b"WARC/1.0\r\nContent-Length: 0\n\r\n"),
            Err(Error::MalformedFieldLine(_))
        ));
        // Anything after the blank line is rejected.
        assert!(matches!(
            RecordHeader::parse(b"WARC/1.0\r\nContent-Length: 0\r\n\r\nextra\r\n"),
            Err(Error::MalformedFieldLine(_))
        ));
    }

    /// The only line break a value may hold is the CRLF of a fold, and every layer above reads a
    /// CR in a value as opening one, so a bare CR must not get past this layer.
    #[test]
    fn rejects_a_bare_cr_in_a_value() {
        let block = block(&["Content-Length: 0", "X-Foo: a\rb"]);

        // Reading and validating a block have to agree on what is well formed, or a block can be
        // read that cannot be written back.
        assert!(matches!(
            RecordHeader::parse(&block).map(|(header, _)| header.validate()),
            Err(Error::MalformedFieldLine(_))
        ));
    }

    /// A control character breaks no framing, so this layer reads it and writes it back. The
    /// grammar layer is what refuses it.
    #[test]
    fn keeps_a_control_character_in_a_value() {
        for control in *b"\0\x1f\x7f" {
            let mut source = b"WARC/1.1\r\nContent-Length: 0\r\nX-Foo: a".to_vec();
            source.push(control);
            source.extend_from_slice(b"b\r\n\r\n");

            let (header, _) = RecordHeader::parse(&source).expect("parsed");
            assert_eq!(
                header.get("X-Foo"),
                Some([b' ', b'a', control, b'b'].as_slice())
            );
            assert!(header.validate().is_ok(), "{control:?}");

            let mut written = Vec::new();
            header.write_to(&mut written).expect("written");
            assert_eq!(written, source);
        }
    }

    /// `Content-Length` is what frames the body, so a second one leaves the end of the record
    /// ambiguous. It is refused whether or not it agrees with the first, and refused when the block
    /// is written as well as when it is read, since a reader taking the other one would find a
    /// different record there.
    #[test]
    fn rejects_a_repeated_content_length() {
        for lines in [
            ["Content-Length: 0", "Content-Length: 0"],
            ["Content-Length: 5", "Content-Length: 0"],
            ["Content-Length: 0", "Content-Length: five"],
            ["Content-Length: 0", "content-length: 0"],
        ] {
            let block = block(&lines);

            assert!(
                matches!(
                    RecordHeader::parse(&block),
                    Err(Error::RepeatedContentLength)
                ),
                "{lines:?}"
            );

            let mut header = RecordHeader {
                version: WarcVersion::V1_0,
                headers: Vec::new(),
            };
            for line in lines {
                let (name, value) = line.split_once(':').expect("a field line");
                header
                    .headers
                    .push((name.to_owned(), format!(" {}", value.trim()).into_bytes()));
            }

            assert!(
                matches!(header.validate(), Err(Error::RepeatedContentLength)),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn rejects_a_block_with_no_terminator() {
        assert!(matches!(
            RecordHeader::parse(b"WARC/1.0\r\nContent-Length: 0\r\n"),
            Err(Error::UnexpectedEndOfHeaderBlock)
        ));
    }

    #[test]
    fn refuses_to_write_an_inconsistent_record() {
        let (header, _) = RecordHeader::parse(&block(&["Content-Length: 3"])).unwrap();
        let record = header.with_body(b"much longer".to_vec());

        assert!(matches!(
            record.validate(),
            Err(Error::ContentLengthMismatch {
                declared: 3,
                actual: 11
            })
        ));
        assert!(record.to_bytes().is_err());
    }

    /// A value assembled in code can hold a line break that would split the field in two or
    /// truncate the block. This is caught at write time.
    #[test]
    fn refuses_to_write_a_value_that_would_break_the_block() {
        let (header, _) = RecordHeader::parse(&block(&["Content-Length: 0"])).unwrap();
        let mut record = header.with_body(Vec::new());

        record
            .header
            .headers
            .push(("X-Bad".to_string(), b" a\r\nContent-Length: 9".to_vec()));
        assert!(matches!(
            record.validate(),
            Err(Error::MalformedFieldLine(_))
        ));

        record.header.headers.pop();
        record
            .header
            .headers
            .push(("X-Bad".to_string(), b" a\nb".to_vec()));
        assert!(matches!(
            record.validate(),
            Err(Error::MalformedFieldLine(_))
        ));

        // A genuine fold is fine.
        record.header.headers.pop();
        record
            .header
            .headers
            .push(("X-Fine".to_string(), b" a\r\n b".to_vec()));
        assert!(record.validate().is_ok());
    }

    #[test]
    fn refuses_to_write_a_name_that_is_not_a_token() {
        let (header, _) = RecordHeader::parse(&block(&["Content-Length: 0"])).unwrap();
        let mut record = header.with_body(Vec::new());

        record.header.headers.push((String::new(), b" x".to_vec()));
        assert!(matches!(
            record.validate(),
            Err(Error::MalformedFieldLine(_))
        ));

        record.header.headers.pop();
        record
            .header
            .headers
            .push(("no spaces".to_string(), b" x".to_vec()));
        assert!(matches!(
            record.validate(),
            Err(Error::MalformedFieldLine(_))
        ));
    }

    /// Every fault the octets can have says what it is, and none of them wraps another error
    /// for a caller to unwrap: the version error a malformed version line carries is reported
    /// as itself, since the variant is transparent.
    #[test]
    fn each_error_states_its_failure() {
        let expectations = [
            (
                Error::MalformedVersion(crate::version::Error("0.9".to_owned())),
                "Malformed version: 0.9",
            ),
            (
                Error::MalformedVersionLine("HTTP/1.1 200 OK".to_owned()),
                "Malformed version line: HTTP/1.1 200 OK",
            ),
            (
                Error::MalformedFieldLine("no colon here".to_owned()),
                "Malformed field line: no colon here",
            ),
            (
                Error::UnexpectedEndOfHeaderBlock,
                "Unexpected end of header block.",
            ),
            (Error::MissingContentLength, "Missing Content-Length."),
            (
                Error::MalformedContentLength("12 34".to_owned()),
                "Malformed Content-Length: 12 34",
            ),
            (
                Error::ContentLengthMismatch {
                    declared: 5,
                    actual: 7,
                },
                "Content-Length declares 5 bytes, but the body is 7.",
            ),
        ];

        for (error, message) in expectations {
            assert_eq!(error.to_string(), message);
            assert!(std::error::Error::source(&error).is_none(), "{message}");
        }
    }
}
