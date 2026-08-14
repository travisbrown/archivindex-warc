use std::borrow::Cow;
use std::str;

use nom::bytes::streaming::{tag, take, take_while1};
use nom::character::streaming::{line_ending, not_line_ending, space0, space1};
use nom::combinator::complete;
use nom::error::ErrorKind;
use nom::multi::{many0, many1};
use nom::{IResult, Parser};

fn verify_error(input: &[u8]) -> nom::Err<nom::error::Error<&[u8]>> {
    nom::Err::Error(nom::error::Error::new(input, ErrorKind::Verify))
}

fn version(input: &[u8]) -> IResult<&[u8], crate::WarcVersion> {
    let (input, (_, version, _)) = (tag("WARC/"), not_line_ending, line_ending).parse(input)?;

    let version_str = str::from_utf8(version).map_err(|_| verify_error(version))?;
    let version = version_str.parse().map_err(|_| verify_error(version))?;

    Ok((input, version))
}

/// Parse one named field, including any folded continuation lines.
///
/// The WARC grammar borrows the `LWS` rule from RFC 2616: a header line beginning with a space
/// or tab continues the previous field value, and each fold is read as a single space. Values
/// are borrowed unless folding forces a copy.
///
/// A field name ends where its colon begins: the grammar allows linear white space before a
/// value but none before the colon, so a line that puts some there is not a field line.
#[allow(clippy::type_complexity)]
fn header(input: &[u8]) -> IResult<&[u8], (&str, Cow<'_, [u8]>)> {
    let (input, (token, _, _, value, _)) = (
        take_while1(crate::is_header_token_char),
        tag(":"),
        space0,
        not_line_ending,
        line_ending,
    )
        .parse(input)?;

    // `complete` keeps a value ending exactly at the end of input from reporting `Incomplete`
    // while probing for a continuation line that is not there.
    let (input, continuations) =
        many0(complete((space1, not_line_ending, line_ending))).parse(input)?;

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

    // Tokens come from `take_while1(is_header_token_char)`, which admits only ASCII bytes,
    // so this conversion cannot fail.
    let token = str::from_utf8(token).expect("invariant violation: header token is not ASCII");

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
pub fn headers(
    input: &[u8],
) -> IResult<&[u8], (crate::WarcVersion, Vec<(&str, Cow<'_, [u8]>)>, Option<u64>)> {
    let (input, version) = version(input)?;
    let (input, headers) = many1(header).parse(input)?;

    // The specification puts no ceiling on `Content-Length`, so the full unsigned 64-bit range
    // is accepted here; whether a record of that size can be buffered is the caller's concern.
    let mut content_length: Option<u64> = None;
    let mut warc_headers: Vec<(&str, Cow<'_, [u8]>)> = Vec::with_capacity(headers.len());

    // Errors carry the offending field name rather than the remaining input, so they point at
    // the culprit. The value cannot be carried: a folded value is owned by this function.
    for (token, value) in headers {
        if content_length.is_none() && token.eq_ignore_ascii_case("content-length") {
            let value_str = str::from_utf8(&value).map_err(|_| verify_error(token.as_bytes()))?;
            let len = crate::parse_content_length(value_str)
                .ok_or_else(|| verify_error(token.as_bytes()))?;
            content_length = Some(len);
        }

        warc_headers.push((token, value));
    }

    Ok((input, (version, warc_headers, content_length)))
}

/// Parse an entire WARC record.
///
/// A record without a `Content-Length` field cannot be framed (there is no way to know where
/// its body ends), so parsing one fails with an error pointing at its header block.
#[allow(clippy::type_complexity)]
pub fn record(
    input: &[u8],
) -> IResult<&[u8], (crate::WarcVersion, Vec<(&str, Cow<'_, [u8]>)>, &[u8])> {
    let (remainder, (headers, _)) = (headers, line_ending).parse(input)?;
    let content_length = headers.2.ok_or_else(|| verify_error(input))?;
    // The body of an in-memory record must fit in a slice, so a length beyond the address
    // space cannot possibly be satisfied by `input` and is rejected as invalid.
    let content_length = usize::try_from(content_length).map_err(|_| verify_error(input))?;
    let (remainder, (body, _, _)) =
        (take(content_length), line_ending, line_ending).parse(remainder)?;

    Ok((remainder, (headers.0, headers.1, body)))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use nom::error::ErrorKind;
    use nom::{Err, Needed};

    use super::{header, headers, record, version};

    #[test]
    fn version_parsing() {
        assert_eq!(
            version(&b"WARC/1.0\r\n"[..]),
            Ok((&b""[..], crate::WarcVersion::V1_0))
        );
        assert_eq!(
            version(&b"WARC/1.1\r\n"[..]),
            Ok((&b""[..], crate::WarcVersion::V1_1))
        );
    }

    /// Only the two WARC versions supported by the crate are accepted; empty, older,
    /// hypothetical newer, and otherwise arbitrary version strings are rejected.
    #[test]
    fn version_rejects_unsupported_values() {
        for value in ["", "0.0", "1.2", "2.0-alpha", "not-a-version"] {
            let raw = format!("WARC/{value}\r\n");
            assert!(version(raw.as_bytes()).is_err(), "{value:?}");
        }
    }

    /// A field name ends where its colon begins, so a line that puts white space in between is
    /// not a field line. Reading it as one drops bytes the block was written with, and writes
    /// the block back as something other than what was read.
    #[test]
    fn header_pair_rejects_space_before_the_colon() {
        assert!(header(&b"another-header : with extra spaces\r\n"[..]).is_err());
    }

    /// DEL is a control character, so it cannot appear in a field-name token.
    #[test]
    fn header_pair_rejects_del_in_name() {
        assert!(header(b"evil\x7fname: value\r\n").is_err());
    }

    /// `Content-Length` follows the `1*DIGIT` grammar strictly: linear whitespace around the
    /// digits is tolerated, but signs, internal whitespace, and non-digits are not.
    #[test]
    fn content_length_grammar() {
        let block = |value: &str| format!("WARC/1.1\r\ncontent-length: {value}\r\n\r\n");

        for (value, expected) in [("42", 42), ("42 ", 42), ("42\t", 42), ("0", 0)] {
            let raw = block(value);
            let parsed = headers(raw.as_bytes()).expect(value);
            assert_eq!((parsed.1).2, Some(expected), "{value:?}");
        }

        // The last entry is a pair of non-ASCII (Arabic-Indic) digits.
        for value in ["+42", "-42", "4 2", "4a", "\u{0664}\u{0662}"] {
            let raw = block(value);
            assert!(headers(raw.as_bytes()).is_err(), "{value:?}");
        }
    }

    #[test]
    fn header_pair_parsing() {
        assert_eq!(
            header(&b"some-header: all/the/things\r\n"[..]),
            Ok((
                &b""[..],
                ("some-header", Cow::Borrowed(&b"all/the/things"[..]))
            ))
        );

        assert_eq!(
            header(&b"another-header:   with extra spaces\r\n"[..]),
            Ok((
                &b""[..],
                ("another-header", Cow::Borrowed(&b"with extra spaces"[..]))
            ))
        );

        assert_eq!(
            header(&b"incomplete-header: missing-line-ending"[..]),
            Err(Err::Incomplete(Needed::Unknown))
        );
    }

    /// A field value may span lines via LWS continuation; each fold reads as a single space.
    #[test]
    fn header_pair_folded_value_parsing() {
        assert_eq!(
            header(&b"folded-header: line one\r\n line two\r\n\t \tline three\r\n"[..]),
            Ok((
                &b""[..],
                (
                    "folded-header",
                    Cow::Owned(b"line one line two line three".to_vec())
                )
            ))
        );

        // A continuation line is part of the value, not the start of the next field.
        assert_eq!(
            header(&b"folded-header: one\r\n two\r\nnext-header: value\r\n"[..]),
            Ok((
                &b"next-header: value\r\n"[..],
                ("folded-header", Cow::Owned(b"one two".to_vec()))
            ))
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

        // The error points at the field whose value failed validation.
        assert_eq!(
            headers(&raw_invalid[..]),
            Err(Err::Error(nom::error::Error::new(
                &b"content-length"[..],
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
        let expected_version = crate::WarcVersion::V1_0;
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

    /// A missing `Content-Length` is reported as `None` rather than a parse failure, leaving
    /// the caller to raise an error naming the missing field.
    #[test]
    fn headers_parsing_without_content_length() {
        let raw = b"\
            WARC/1.0\r\n\
            foo: is fantastic\r\n\
            \r\n\
        ";

        assert_eq!(
            headers(&raw[..]),
            Ok((
                &b"\r\n"[..],
                (
                    crate::WarcVersion::V1_0,
                    vec![("foo", Cow::Borrowed(&b"is fantastic"[..]))],
                    None
                )
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

        let expected_version = crate::WarcVersion::V1_0;
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

    /// A record without `Content-Length` cannot be framed, so parsing it fails with an error
    /// pointing at its header block.
    #[test]
    fn parse_record_without_content_length() {
        let raw = b"\
            WARC/1.0\r\n\
            Warc-Type: dunno\r\n\
            \r\n\
            12345\r\n\
            \r\n\
        ";

        assert_eq!(
            record(&raw[..]),
            Err(Err::Error(nom::error::Error::new(
                &raw[..],
                ErrorKind::Verify
            )))
        );
    }
}
