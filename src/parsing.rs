//! Low-level scanning helpers shared by the parsing layers.
//!
//! These helpers scan the field lines shared by WARC headers and `warc-fields` bodies. Callers
//! decide whether to apply the strict header grammar or the more lenient body grammar.

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

/// Whether every byte of a value is a `token` character, and there is at least one.
pub fn is_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().copied().all(is_token_char)
}

/// Render bytes as text for an error message.
pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
