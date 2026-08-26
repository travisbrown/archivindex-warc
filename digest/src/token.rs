//! The `token` grammar of WARC 1.1, shared by algorithm labels and field names.

/// Whether a byte is allowed by the `token` grammar.
#[must_use]
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

/// Whether every byte of a value is a `token` character, and there is at least one.
#[must_use]
pub fn is_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().copied().all(is_token_char)
}

#[cfg(test)]
mod tests {
    use super::{is_token, is_token_char};

    #[test]
    fn separators_controls_and_non_ascii_are_not_token_characters() {
        assert!(is_token_char(b'a'));
        assert!(is_token_char(b'-'));
        assert!(!is_token_char(b':'));
        assert!(!is_token_char(b' '));
        assert!(!is_token_char(0));
        assert!(!is_token_char(0x80));
    }

    #[test]
    fn a_token_is_nonempty() {
        assert!(is_token(b"sha-256"));
        assert!(!is_token(b""));
        assert!(!is_token(b"sha 256"));
    }
}
