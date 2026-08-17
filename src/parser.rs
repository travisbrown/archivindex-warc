use nom::{
    bytes::streaming::{tag, take, take_while1},
    character::streaming::{line_ending, not_line_ending, space0, space1},
    combinator::complete,
    error::ErrorKind,
    multi::{many0, many1},
    sequence::tuple,
    IResult,
};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::str;

// TODO: evaluate the use of `ErrorKind::Verify` here.
fn version(input: &[u8]) -> IResult<&[u8], &str> {
    let (input, (_, version, _)) = tuple((tag("WARC/"), not_line_ending, line_ending))(input)?;

    let version_str = match str::from_utf8(version) {
        Err(_) => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                ErrorKind::Verify,
            )));
        }
        Ok(version) => version,
    };

    Ok((input, version_str))
}

/// Parse one named field, including any folded continuation lines.
///
/// The WARC grammar borrows the `LWS` rule from RFC 2616: a header line beginning with a space
/// or tab continues the previous field value, and each fold is read as a single space. Values
/// are borrowed unless folding forces a copy.
#[allow(clippy::type_complexity)]
fn header(input: &[u8]) -> IResult<&[u8], (&[u8], Cow<'_, [u8]>)> {
    let (input, (token, _, _, _, value, _)) = tuple((
        take_while1(crate::is_header_token_char),
        space0,
        tag(":"),
        space0,
        not_line_ending,
        line_ending,
    ))(input)?;

    // `complete` keeps a value ending exactly at the end of input from reporting `Incomplete`
    // while probing for a continuation line that is not there.
    let (input, continuations) =
        many0(complete(tuple((space1, not_line_ending, line_ending))))(input)?;

    let value = if continuations.is_empty() {
        Cow::Borrowed(value)
    } else {
        let mut folded = value.to_vec();
        for (_, continuation, _) in continuations {
            folded.push(b' ');
            folded.extend_from_slice(continuation);
        }
        Cow::Owned(folded)
    };

    Ok((input, (token, value)))
}

/// Parse a WARC header block.
///
/// Returns the version, the named fields in order of appearance, and the value of the
/// `Content-Length` field if one is present. The specification makes `Content-Length`
/// mandatory, but its absence is reported as `None` so the caller can raise an error naming
/// the missing field.
// TODO: evaluate the use of `ErrorKind::Verify` here.
#[allow(clippy::type_complexity)]
pub fn headers(input: &[u8]) -> IResult<&[u8], (&str, Vec<(&str, Cow<'_, [u8]>)>, Option<usize>)> {
    let (input, version) = version(input)?;
    let (input, headers) = many1(header)(input)?;

    let mut content_length: Option<usize> = None;
    let mut warc_headers: Vec<(&str, Cow<'_, [u8]>)> = Vec::with_capacity(headers.len());

    for header in headers {
        let token_str = match str::from_utf8(header.0) {
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    ErrorKind::Verify,
                )));
            }
            Ok(token) => token,
        };

        if content_length.is_none() && token_str.to_lowercase() == "content-length" {
            let value_str = match str::from_utf8(&header.1) {
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        ErrorKind::Verify,
                    )));
                }
                Ok(value) => value,
            };

            // The parser works in `usize` because it slices the body out of the input, so a
            // length beyond the address space cannot be honored here either.
            match crate::parse_content_length(value_str).and_then(|len| usize::try_from(len).ok()) {
                None => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        ErrorKind::Verify,
                    )));
                }
                Some(len) => {
                    content_length = Some(len);
                }
            }
        }

        warc_headers.push((token_str, header.1));
    }

    Ok((input, (version, warc_headers, content_length)))
}

/// Parse an entire WARC record.
///
/// A record without a `Content-Length` field cannot be framed (there is no way to know where
/// its body ends), so parsing one fails with an error pointing at its header block.
#[allow(clippy::type_complexity)]
pub fn record(input: &[u8]) -> IResult<&[u8], (&str, Vec<(&str, Cow<'_, [u8]>)>, &[u8])> {
    let (remainder, (headers, _)) = tuple((headers, line_ending))(input)?;
    let content_length = headers
        .2
        .ok_or_else(|| nom::Err::Error(nom::error::Error::new(input, ErrorKind::Verify)))?;
    let (remainder, (body, _, _)) =
        tuple((take(content_length), line_ending, line_ending))(remainder)?;

    Ok((remainder, (headers.0, headers.1, body)))
}

#[cfg(test)]
mod tests {
    use super::{header, headers, record, version};
    use nom::error::ErrorKind;
    use nom::Err;
    use nom::Needed;
    use std::borrow::Cow;

    #[test]
    fn version_parsing() {
        assert_eq!(version(&b"WARC/0.0\r\n"[..]), Ok((&b""[..], "0.0")));

        assert_eq!(version(&b"WARC/1.0\r\n"[..]), Ok((&b""[..], "1.0")));

        assert_eq!(
            version(&b"WARC/2.0-alpha\r\n"[..]),
            Ok((&b""[..], "2.0-alpha"))
        );
    }

    /// Only the two WARC versions supported by the crate are accepted; empty, older,
    /// hypothetical newer, and otherwise arbitrary version strings are rejected.
    #[test]
    #[ignore = "known bug (PARSE-005: unsupported WARC versions accepted)"]
    fn version_rejects_unsupported_values() {
        for value in ["", "0.0", "1.2", "2.0-alpha", "not-a-version"] {
            let raw = format!("WARC/{}\r\n", value);
            assert!(version(raw.as_bytes()).is_err(), "{:?}", value);
        }
    }

    /// A field name ends where its colon begins, so a line that puts white space in between is
    /// not a field line. Reading it as one drops bytes the block was written with, and writes
    /// the block back as something other than what was read.
    #[test]
    #[ignore = "known bug (PARSE-006: white space before a field's colon is dropped)"]
    fn header_pair_rejects_space_before_the_colon() {
        assert!(header(&b"another-header : with extra spaces\r\n"[..]).is_err());
    }

    /// DEL is a control character, so it cannot appear in a field-name token.
    #[test]
    #[ignore = "known bug (PARSE-004: DEL accepted in field names)"]
    fn header_pair_rejects_del_in_name() {
        assert!(header(b"evil\x7fname: value\r\n").is_err());
    }

    /// A field value folded across lines with leading whitespace is unfolded, each fold
    /// reading as a single space.
    #[test]
    fn header_pair_folded_value_parsing() {
        assert_eq!(
            header(&b"folded-header: one\r\n two\r\n\tthree\r\n"[..]),
            Ok((
                &b""[..],
                (&b"folded-header"[..], Cow::Owned(b"one two three".to_vec()))
            ))
        );
    }

    /// `Content-Length` follows the `1*DIGIT` grammar strictly: linear whitespace around the
    /// digits is tolerated, but signs, internal whitespace, and non-digits are not.
    #[test]
    fn content_length_grammar() {
        let block = |value: &str| format!("WARC/1.1\r\ncontent-length: {}\r\n\r\n", value);

        for (value, expected) in [("42", 42), ("42 ", 42), ("42\t", 42), ("0", 0)] {
            let raw = block(value);
            let parsed = headers(raw.as_bytes()).expect(value);
            assert_eq!((parsed.1).2, Some(expected), "{:?}", value);
        }

        // The last entry is a pair of non-ASCII (Arabic-Indic) digits.
        for value in ["+42", "-42", "4 2", "4a", "\u{0664}\u{0662}"] {
            let raw = block(value);
            assert!(headers(raw.as_bytes()).is_err(), "{:?}", value);
        }
    }

    #[test]
    fn header_pair_parsing() {
        assert_eq!(
            header(&b"some-header: all/the/things\r\n"[..]),
            Ok((
                &b""[..],
                (&b"some-header"[..], Cow::Borrowed(&b"all/the/things"[..]))
            ))
        );

        assert_eq!(
            header(&b"another-header : with extra spaces\r\n"[..]),
            Ok((
                &b""[..],
                (
                    &b"another-header"[..],
                    Cow::Borrowed(&b"with extra spaces"[..])
                )
            ))
        );

        assert_eq!(
            header(&b"incomplete-header : missing-line-ending"[..]),
            Err(Err::Incomplete(Needed::Unknown))
        );
    }

    #[test]
    fn headers_parsing() {
        let raw_invalid = b"\
            WARC/1.0\r\n\
            content-length: R2D2\r\n\
            that: is not\r\n\
            a-valid: content-length\r\n\
            \r\n\
        ";

        assert_eq!(
            headers(&raw_invalid[..]),
            Err(Err::Error(nom::error::Error::new(
                &b"\r\n"[..],
                ErrorKind::Verify
            )))
        );

        let raw = b"\
            WARC/1.0\r\n\
            content-length: 42\r\n\
            foo: is fantastic\r\n\
            bar: is beautiful\r\n\
            baz: is bananas\r\n\
            \r\n\
        ";
        let expected_version = "1.0";
        let expected_headers: Vec<(&str, Cow<'_, [u8]>)> = vec![
            ("content-length", Cow::Borrowed(b"42")),
            ("foo", Cow::Borrowed(b"is fantastic")),
            ("bar", Cow::Borrowed(b"is beautiful")),
            ("baz", Cow::Borrowed(b"is bananas")),
        ];
        let expected_len = Some(42);

        assert_eq!(
            headers(&raw[..]),
            Ok((
                &b"\r\n"[..],
                (expected_version, expected_headers, expected_len)
            ))
        );
    }

    #[test]
    fn parse_record() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            Content-Length: 5\r\n\
            \r\n\
            12345\r\n\
            \r\n\
            WARC/1.0\r\n\
            Warc-Type: another\r\n\
            Content-Length: 6\r\n\
            \r\n\
            123456\r\n\
            \r\n\
        ";

        let expected_version = "1.0";
        let expected_headers: Vec<(&str, Cow<'_, [u8]>)> = vec![
            ("Warc-Type", Cow::Borrowed(b"dunno")),
            ("Content-Length", Cow::Borrowed(b"5")),
        ];
        let expected_body: &[u8] = b"12345";

        assert_eq!(
            record(&raw[..]),
            Ok((
                &b"WARC/1.0\r\nWarc-Type: another\r\nContent-Length: 6\r\n\r\n123456\r\n\r\n"[..],
                (expected_version, expected_headers, expected_body)
            ))
        );
    }
}
