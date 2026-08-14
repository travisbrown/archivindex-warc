use crate::header::WarcHeader;

/// An error type returned by WARC header parsing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occured identifing or parsing headers.
    #[error("Error parsing headers.")]
    ParseHeaders(#[source] nom::Err<nom::error::Error<Vec<u8>>>),
    /// A header required by the standard is missing from the record. The record was well-formed,
    /// but invalid.
    #[error("Missing required header: {0}")]
    MissingHeader(WarcHeader),
    /// A required header is not well-formed according to the standard.
    #[error("Malformed header: {0}: {1}")]
    MalformedHeader(WarcHeader, String),
    /// A named field other than `WARC-Concurrent-To` appeared more than once in a record. The
    /// record was well-formed, but invalid.
    #[error("Duplicate header: {0}")]
    DuplicateHeader(WarcHeader),
    /// The underlying read from the data source failed.
    #[error("Error reading data source.")]
    ReadData(#[source] std::io::Error),
    /// More data was read than expected by the header metadata. The record was well-formed, but
    /// invalid.
    #[error("Read further than expected.")]
    ReadOverflow,
    /// The record's declared `Content-Length` is too large for its body to be buffered in
    /// memory on this platform. Such a record may still be readable with
    /// `WarcReader::stream_records`, which does not buffer bodies.
    #[error("Record body too large to buffer.")]
    BodyTooLarge,
    /// The end of the record's body was found unexpectedly.
    #[error("Unexpected end of body.")]
    UnexpectedEOB,
    /// A version string does not name a WARC version supported by this crate.
    #[error("Malformed version: {0}")]
    MalformedVersion(String),
    /// A record's declared `Content-Length` does not match the body it carries, so writing it
    /// would produce an archive that cannot be read back.
    #[error("Content-Length declares {declared} bytes, but the body is {actual}.")]
    ContentLengthMismatch {
        /// The length the record's `Content-Length` field declares.
        declared: u64,
        /// The length of the body the record actually carries.
        actual: u64,
    },
    /// The `\r\n\r\n` terminator after the record's body was missing or malformed. The record
    /// was read completely, but is invalid.
    #[error("Malformed record terminator.")]
    MalformedRecordTerminator,
}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::header::WarcHeader;
    use std::error::Error as _;

    /// The derived messages and sources match the previous hand-written implementation.
    #[test]
    fn display_and_source_are_unchanged() {
        let io = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        let parse = nom::Err::Error(nom::error::Error::new(
            b"x".to_vec(),
            nom::error::ErrorKind::Verify,
        ));

        let expectations = [
            (Error::ParseHeaders(parse), "Error parsing headers.", true),
            (
                Error::MissingHeader(WarcHeader::Date),
                "Missing required header: warc-date",
                false,
            ),
            (
                Error::MalformedHeader(WarcHeader::Date, "not a W3C-DTF timestamp".to_string()),
                "Malformed header: warc-date: not a W3C-DTF timestamp",
                false,
            ),
            (
                Error::DuplicateHeader(WarcHeader::TargetURI),
                "Duplicate header: warc-target-uri",
                false,
            ),
            (Error::ReadData(io), "Error reading data source.", true),
            (Error::ReadOverflow, "Read further than expected.", false),
            (
                Error::BodyTooLarge,
                "Record body too large to buffer.",
                false,
            ),
            (Error::UnexpectedEOB, "Unexpected end of body.", false),
            (
                Error::MalformedVersion("0.9".to_string()),
                "Malformed version: 0.9",
                false,
            ),
            (
                Error::ContentLengthMismatch {
                    declared: 5,
                    actual: 7,
                },
                "Content-Length declares 5 bytes, but the body is 7.",
                false,
            ),
            (
                Error::MalformedRecordTerminator,
                "Malformed record terminator.",
                false,
            ),
        ];

        for (error, message, has_source) in expectations {
            assert_eq!(error.to_string(), message);
            assert_eq!(error.source().is_some(), has_source, "{message}");
        }
    }
}
