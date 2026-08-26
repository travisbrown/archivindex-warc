//! Low-level scanning helpers shared by the parsing layers.
//!
//! These helpers scan the field lines shared by WARC headers and `warc-fields` bodies. Callers
//! decide whether to apply the strict header grammar or the more lenient body grammar.

use std::borrow::Cow;

/// Whether a byte is allowed by the field name token grammar.
pub const fn is_token_char(byte: u8) -> bool {
    !matches!(byte, 0..=31
        | 127..=255
        | b'('
        | b')'
        | b'<'
        | b'>'
        | b'@'
        | b','
        | b';'
        | b':'
        | b'"'
        | b'/'
        | b'['
        | b']'
        | b'?'
        | b'='
        | b'{'
        | b'}'
        | b' '
        | b'\\')
}

/// Whether a byte is linear white space (`SP` or `HT`).
pub const fn is_lws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// Whether a byte is a control character.
const fn is_ctl(byte: u8) -> bool {
    byte < 32 || byte == 127
}

/// Whether a byte is `TEXT`, which is any octet except a control character that is not linear
/// white space.
pub const fn is_text_char(byte: u8) -> bool {
    !is_ctl(byte) || is_lws(byte)
}

/// Where a line's content ends and where the line after it begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Line {
    /// The offset just past the content, which is the first byte of the line ending.
    pub end: usize,
    /// The offset the following line begins at, past the line ending.
    pub next: usize,
    /// Whether the line ended with the `CRLF` the grammar calls for rather than a bare `LF`.
    pub crlf: bool,
}

/// Find the line beginning at `start`.
///
/// Returns `None` when no complete line remains: nothing is left, the last line has no line
/// ending, or `start` is past the end of the block.
pub fn next_line(block: &[u8], start: usize) -> Option<Line> {
    let offset = block.get(start..)?.iter().position(|&byte| byte == b'\n')?;
    let line_feed = start + offset;
    let crlf = offset > 0 && block[line_feed - 1] == b'\r';

    Some(Line {
        end: if crlf { line_feed - 1 } else { line_feed },
        next: line_feed + 1,
        crlf,
    })
}

/// Split a field line into the name it opens with and the offset of the colon that closes it.
///
/// Returns `None` unless the line begins with a token followed by optional white space and a colon.
/// The colon offset lets strict callers reject that white space.
pub fn split_field_line(line: &[u8]) -> Option<(&[u8], usize)> {
    let name_end = line
        .iter()
        .position(|&byte| !is_token_char(byte))
        .unwrap_or(line.len());
    if name_end == 0 {
        return None;
    }

    let mut colon = name_end;
    while line.get(colon).copied().is_some_and(is_lws) {
        colon += 1;
    }

    (line.get(colon) == Some(&b':')).then_some((&line[..name_end], colon))
}

/// Whether every byte of a value is a `token` character, and there is at least one.
pub fn is_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().copied().all(is_token_char)
}

/// Whether every byte of a value is `TEXT`.
pub fn is_text(value: &[u8]) -> bool {
    value.iter().copied().all(is_text_char)
}

/// Find the first line break that is not the `CRLF` of a fold.
///
/// A fold is `CRLF` followed by at least one space or tab. Any other line break would end the
/// field line rather than continue the value, so a value holding one cannot be written back as it
/// was read. Control characters other than line breaks are left to the grammar layer.
pub fn stray_line_break(value: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'\r' => {
                if value.get(index + 1) != Some(&b'\n')
                    || !matches!(value.get(index + 2), Some(b' ' | b'\t'))
                {
                    return Some(index);
                }
                index += 3;
            }
            b'\n' => return Some(index),
            _ => index += 1,
        }
    }

    None
}

/// Whether a value holds no line break other than the `CRLF` of a fold.
pub fn is_folded_value(value: &[u8]) -> bool {
    stray_line_break(value).is_none()
}

/// The rule a `quoted-string` did not match.
///
/// Offsets count from the opening quote, so they index the value as it was read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QuotedStringError {
    /// The value does not both open and close with a quote.
    #[error("it does not open and close with a quote")]
    Unterminated,
    /// The value ends on a backslash, which has nothing left to escape.
    #[error("the backslash at byte {index} escapes nothing")]
    DanglingEscape {
        /// Where the backslash is written.
        index: usize,
    },
    /// A quote inside the string is not escaped, so it would have ended the string.
    #[error("the quote at byte {index} is not escaped")]
    UnescapedQuote {
        /// Where the quote is written.
        index: usize,
    },
    /// A control character `TEXT` excludes is written inside the string.
    #[error("a control character is written at byte {index}")]
    ControlCharacter {
        /// Where the control character is written.
        index: usize,
    },
}

/// Resolve a `quoted-string` into the octets it stands for.
///
/// The surrounding quotes are removed, each `quoted-pair` loses its leading backslash, and an
/// unescaped quote, a trailing backslash, or a control character makes the value malformed. A
/// backslash escapes an octet, not a control character, so escaping one does not admit it.
/// Validation of the decoded octets belongs to the field-specific caller: a media type requires
/// UTF-8 text, while `WARC-Filename` may hold arbitrary `TEXT`.
///
/// # Errors
///
/// Returns the [`QuotedStringError`] naming the rule the value broke.
pub fn unquote(value: &[u8]) -> Result<Vec<u8>, QuotedStringError> {
    let inner = value
        .strip_prefix(b"\"")
        .and_then(|inner| inner.strip_suffix(b"\""))
        .ok_or(QuotedStringError::Unterminated)?;
    let mut unquoted = Vec::with_capacity(inner.len());
    let mut index = 0;
    // Offsets are reported against `value`, which the opening quote puts one ahead of `inner`.
    while index < inner.len() {
        match inner[index] {
            b'\\' => {
                let escaped = *inner
                    .get(index + 1)
                    .ok_or(QuotedStringError::DanglingEscape { index: index + 1 })?;
                if !is_text_char(escaped) {
                    return Err(QuotedStringError::ControlCharacter { index: index + 2 });
                }
                unquoted.push(escaped);
                index += 2;
            }
            // An unescaped quote would have ended the string, so the bounds are wrong.
            b'"' => return Err(QuotedStringError::UnescapedQuote { index: index + 1 }),
            byte if !is_text_char(byte) => {
                return Err(QuotedStringError::ControlCharacter { index: index + 1 });
            }
            byte => {
                unquoted.push(byte);
                index += 1;
            }
        }
    }

    Ok(unquoted)
}

/// Reduce a field value to the content its field's grammar applies to.
///
/// Leading and trailing white space is removed, and each folded continuation becomes one space.
///
/// The common case, a value with neither folds nor trailing space, borrows.
///
/// # Invariant
///
/// Every CR in `value` must open a `CRLF SP` or `CRLF HTAB` fold. This is what the raw layer
/// admits, both when it reads a block ([`RecordHeader::parse`]) and when it writes one
/// ([`RecordHeader::validate`]), so a value that has come from or is headed for that layer holds.
/// A value that breaks the invariant is not refused here: the CR is read as a fold anyway, and the
/// byte after it is dropped, so a caller holding a value from elsewhere must check it first.
///
/// [`RecordHeader::parse`]: crate::parse::raw::RecordHeader::parse
/// [`RecordHeader::validate`]: crate::parse::raw::RecordHeader::validate
pub fn unfold(value: &[u8]) -> Cow<'_, [u8]> {
    let trimmed = trim_white_space(value);
    if !trimmed.contains(&b'\r') {
        return Cow::Borrowed(trimmed);
    }

    let mut unfolded = Vec::with_capacity(trimmed.len());
    let mut index = 0;
    while index < trimmed.len() {
        if trimmed[index] == b'\r' {
            // A CR opens a fold, per the invariant above, and the fold with the run of white
            // space after it stands for a single space.
            index += 2;
            while matches!(trimmed.get(index), Some(b' ' | b'\t')) {
                index += 1;
            }
            unfolded.push(b' ');
        } else {
            unfolded.push(trimmed[index]);
            index += 1;
        }
    }

    Cow::Owned(unfolded)
}

/// Strip the white space from both ends of a value, the `CR` and `LF` of a fold included.
fn trim_white_space(value: &[u8]) -> &[u8] {
    let is_white_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\r' | b'\n');

    let start = value.iter().position(|&byte| !is_white_space(byte));
    let Some(start) = start else { return &[] };
    let end = value
        .iter()
        .rposition(|&byte| !is_white_space(byte))
        .unwrap_or(start);

    &value[start..=end]
}

/// Parse a `Content-Length` value per the specification's `1*DIGIT` grammar.
///
/// Surrounding spaces and tabs are accepted. Signs, internal white space, non digits, and values
/// beyond the `u64` range return `None`.
pub fn parse_content_length(value: &str) -> Option<u64> {
    let digits = value.trim_matches([' ', '\t']);

    // `parse` accepts exactly the `1*DIGIT` grammar plus an optional leading `+`, which is the one
    // deviation we have to reject ourselves.
    (!digits.starts_with('+'))
        .then(|| digits.parse().ok())
        .flatten()
}

/// Render bytes as text for an error message.
pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        Line, QuotedStringError, next_line, parse_content_length, split_field_line, unfold, unquote,
    };

    /// A line ends at its line ending, which is reported as written so that a strict reader can
    /// refuse a bare `LF` that a lenient one accepts.
    #[test]
    fn line_bounds() {
        let block = b"one\r\ntwo\nthree";

        assert_eq!(
            next_line(block, 0),
            Some(Line {
                end: 3,
                next: 5,
                crlf: true
            })
        );
        assert_eq!(
            next_line(block, 5),
            Some(Line {
                end: 8,
                next: 9,
                crlf: false
            })
        );
        // The last line is unterminated, so it is not reported.
        assert_eq!(next_line(block, 9), None);
    }

    /// A start past the end of the block reports no line, the way the end of a block does.
    #[test]
    fn line_bounds_past_the_end() {
        let block = b"one\r\n";

        assert_eq!(next_line(block, block.len()), None);
        assert_eq!(next_line(block, block.len() + 1), None);
    }

    /// An empty line is still a line: it is what ends a header block.
    #[test]
    fn empty_line_bounds() {
        assert_eq!(
            next_line(b"\r\n", 0),
            Some(Line {
                end: 0,
                next: 2,
                crlf: true
            })
        );
    }

    #[test]
    fn field_line_splitting() {
        assert_eq!(
            split_field_line(b"some-header: value"),
            Some((&b"some-header"[..], 11))
        );
        // The white space before the colon is left for the caller to judge.
        assert_eq!(
            split_field_line(b"some-header \t: value"),
            Some((&b"some-header"[..], 13))
        );

        // No name, no token where the name belongs, and no colon at all.
        for line in [
            &b": value"[..],
            &b" continuation"[..],
            &b"evil\x7fname: value"[..],
            &b"some-header value"[..],
            &b"some-header"[..],
        ] {
            assert_eq!(split_field_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn quoted_string_decoding() {
        assert_eq!(
            unquote(br#""with \"quotes\" and \\ slashes""#),
            Ok(br#"with "quotes" and \ slashes"#.to_vec())
        );
        assert_eq!(unquote(b"\"\""), Ok(Vec::new()));

        // A tab is white space rather than a control character here, escaped or not.
        assert_eq!(unquote(b"\"a\tb\""), Ok(b"a\tb".to_vec()));
        assert_eq!(unquote(b"\"a\\\tb\""), Ok(b"a\tb".to_vec()));
    }

    /// Each offset counts from the opening quote, so it indexes the value as it was read.
    #[test]
    fn quoted_string_failures() {
        for (malformed, expected) in [
            (b"not quoted".as_slice(), QuotedStringError::Unterminated),
            (
                br#""unterminated"#.as_slice(),
                QuotedStringError::Unterminated,
            ),
            (
                br#""with"gap""#.as_slice(),
                QuotedStringError::UnescapedQuote { index: 5 },
            ),
            (
                b"\"trailing\\\"".as_slice(),
                QuotedStringError::DanglingEscape { index: 9 },
            ),
            (
                b"\"a\0b\"".as_slice(),
                QuotedStringError::ControlCharacter { index: 2 },
            ),
            // An escape does not make a control character text.
            (
                b"\"a\\\0b\"".as_slice(),
                QuotedStringError::ControlCharacter { index: 3 },
            ),
        ] {
            assert_eq!(unquote(malformed), Err(expected), "{malformed:?}");
        }
    }

    #[test]
    fn unfolds_and_trims() {
        assert_eq!(unfold(b" value "), b"value".as_slice());
        assert_eq!(unfold(b"\t\tvalue\t"), b"value".as_slice());
        assert_eq!(unfold(b"   "), b"".as_slice());
        assert_eq!(unfold(b""), b"".as_slice());
        // A fold stands for a single space, however much white space follows it.
        assert_eq!(unfold(b" one\r\n  two"), b"one two".as_slice());
        assert_eq!(
            unfold(b" one\r\n\ttwo\r\n three"),
            b"one two three".as_slice()
        );
        // A value with a trailing fold trims to nothing after it.
        assert_eq!(unfold(b" one\r\n "), b"one".as_slice());
    }

    /// `Content-Length` follows the `1*DIGIT` grammar strictly: linear white space around the
    /// digits is tolerated, but signs, internal white space, and non-digits are not.
    #[test]
    fn content_length_grammar() {
        for (value, expected) in [("42", 42), ("42 ", 42), (" 42\t", 42), ("0", 0)] {
            assert_eq!(parse_content_length(value), Some(expected), "{value:?}");
        }

        // The last entry is a pair of non-ASCII (Arabic-Indic) digits.
        for value in ["+42", "-42", "4 2", "4a", "", "\u{0664}\u{0662}"] {
            assert_eq!(parse_content_length(value), None, "{value:?}");
        }
    }
}
