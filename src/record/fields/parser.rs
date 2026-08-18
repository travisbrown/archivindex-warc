//! The `warc-fields` grammar, which a `warcinfo` or `metadata` record writes its block in.
//!
//! The grammar is a sequence of `field-name ":" field-value` lines without a WARC version line.
//! Leading white space continues a value. This parser accepts white space before the colon and
//! bare `LF` line endings found in real archives.

use std::borrow::Cow;
use std::str;

use crate::parsing::{is_lws, next_line, split_field_line};

/// A field as it was read: its name, and its value with any folds already joined.
type Field<'a> = (&'a str, Cow<'a, [u8]>);

/// Read a `warc-fields` block without a version line.
///
/// Returns the unread remainder and the fields in order. Reading stops at the first line that is
/// not a named field. End of input also ends the block.
pub(super) fn fields(block: &[u8]) -> (&[u8], Vec<Field<'_>>) {
    let mut fields = Vec::new();
    let mut cursor = 0;

    while let Some((field, next)) = field(block, cursor) {
        fields.push(field);
        cursor = next;
    }

    (&block[cursor..], fields)
}

/// Read the field beginning at `start`, together with the offset the line after it begins at.
///
/// The WARC grammar borrows the `LWS` rule from RFC 2616: a line beginning with a space or tab
/// continues the previous field value, and each fold is read as a single space. Values are
/// borrowed unless folding forces a copy.
fn field(block: &[u8], start: usize) -> Option<(Field<'_>, usize)> {
    let line = next_line(block, start)?;
    let (name, colon) = split_field_line(content(block, start, line.end)?)?;

    // A token holds only ASCII, so this conversion cannot fail.
    let name = str::from_utf8(name).expect("invariant violation: field name is not ASCII");
    let mut value = Cow::Borrowed(trim_lws(&block[start + colon + 1..line.end]));
    let mut cursor = line.next;

    // Any number of continuation lines follow, each recognized by its leading white space. One
    // cut off short of its line ending is not a continuation, and ends the field: what it holds
    // is left for the caller to report.
    while block.get(cursor).copied().is_some_and(is_lws) {
        let Some(fold) = next_line(block, cursor) else {
            break;
        };
        let Some(continuation) = content(block, cursor, fold.end) else {
            break;
        };

        // A fold stands for a single space, except when nothing has been read yet: the grammar
        // lets any amount of linear white space precede a value, so a value written entirely
        // on continuation lines does not begin with one.
        let folded = value.to_mut();
        if !folded.is_empty() {
            folded.push(b' ');
        }
        folded.extend_from_slice(trim_lws(continuation));
        cursor = fold.next;
    }

    Some(((name, value), cursor))
}

/// A line's content, or `None` when it holds a `CR` that is not part of its line ending.
///
/// A value is `TEXT`, which admits no bare `CR`. Reading one as an ordinary byte would let a
/// block that is not `warc-fields` pass as fields whose values hold line breaks.
fn content(block: &[u8], start: usize, end: usize) -> Option<&[u8]> {
    let content = &block[start..end];

    (!content.contains(&b'\r')).then_some(content)
}

/// Strip the linear white space the grammar admits before the content of a field line and of each
/// of its continuations.
fn trim_lws(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|&byte| !is_lws(byte))
        .unwrap_or(value.len());

    &value[start..]
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::fields;

    #[test]
    fn field_parsing() {
        assert_eq!(
            fields(&b"some-header: all/the/things\r\n"[..]),
            (
                &b""[..],
                vec![("some-header", Cow::Borrowed(&b"all/the/things"[..]))]
            )
        );

        // A body is read leniently: neither the space before the colon nor the bare LF ending
        // the line is the grammar's, but both are common in the wild.
        assert_eq!(
            fields(&b"another-header : with extra spaces\n"[..]),
            (
                &b""[..],
                vec![("another-header", Cow::Borrowed(&b"with extra spaces"[..]))]
            )
        );
    }

    /// DEL is a control character, so it cannot appear in a field-name token, and a bare CR is
    /// not TEXT, so it cannot appear in a value.
    #[test]
    fn malformed_field_lines_are_left_unread() {
        for block in [
            &b"evil\x7fname: value\r\n"[..],
            &b"some-header: va\rlue\r\n"[..],
        ] {
            assert_eq!(fields(block), (block, vec![]), "{block:?}");
        }
    }

    /// A field value may span lines via LWS continuation; each fold reads as a single space.
    #[test]
    fn folded_value_parsing() {
        assert_eq!(
            fields(&b"folded-header: line one\r\n line two\r\n\t \tline three\r\n"[..]),
            (
                &b""[..],
                vec![(
                    "folded-header",
                    Cow::Owned(b"line one line two line three".to_vec())
                )]
            )
        );

        // A continuation line is part of the value, not the start of the next field.
        assert_eq!(
            fields(&b"folded-header: one\r\n two\r\nnext-header: value\r\n"[..]),
            (
                &b""[..],
                vec![
                    ("folded-header", Cow::Owned(b"one two".to_vec())),
                    ("next-header", Cow::Borrowed(&b"value"[..])),
                ]
            )
        );
    }

    /// Linear white space may precede a value, so a value written entirely on continuation
    /// lines does not pick up a leading space from the fold that begins it.
    #[test]
    fn folded_value_starting_on_a_continuation_line() {
        assert_eq!(
            fields(&b"folded-header:\r\n one\r\n two\r\n"[..]),
            (
                &b""[..],
                vec![("folded-header", Cow::Owned(b"one two".to_vec()))]
            )
        );
    }

    /// A `warc-fields` block is read without a version line ahead of it, and reading stops at
    /// the first line that is not a named field.
    #[test]
    fn block_parsing() {
        assert_eq!(
            fields(&b"software: one\r\nisPartOf: two\r\n\r\n"[..]),
            (
                &b"\r\n"[..],
                vec![
                    ("software", Cow::Borrowed(&b"one"[..])),
                    ("isPartOf", Cow::Borrowed(&b"two"[..])),
                ]
            )
        );

        // Input running out ends the block, so an unterminated last line is left over rather
        // than read as a field.
        assert_eq!(
            fields(&b"software: one"[..]),
            (&b"software: one"[..], vec![])
        );

        assert_eq!(fields(&b""[..]), (&b""[..], vec![]));
    }
}
