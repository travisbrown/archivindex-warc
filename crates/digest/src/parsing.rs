//! Private grammar and decoding helpers.

use std::sync::LazyLock;

use data_encoding::{
    BASE32_NOPAD_NOCASE, Encoding as DataEncoding, HEXLOWER_PERMISSIVE, Specification,
};

use crate::Encoding;
use crate::token::is_token_char;

/// Base16 in either case.
static BASE16: DataEncoding = HEXLOWER_PERMISSIVE;

/// Base32 in either case, read once its padding is removed.
static BASE32: DataEncoding = BASE32_NOPAD_NOCASE;

/// Unpadded Base64 with both RFC 4648 alphabets accepted when decoding.
static BASE64_BOTH: LazyLock<DataEncoding> = LazyLock::new(|| {
    let mut specification = Specification::new();
    specification
        .symbols
        .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    specification.translate.from.push_str("-_");
    specification.translate.to.push_str("+/");
    specification
        .encoding()
        .expect("invariant violation: the Base64 specification is valid")
});

/// Whether a value matches `digest-value` as annotation #48 relaxes it.
pub fn is_digest_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|&byte| is_token_char(byte) || byte == b'=' || byte == b'/')
}

/// Read bytes already validated as ASCII as a string.
pub fn from_ascii(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("invariant violation: grammar admitted a non-ASCII byte")
}

/// Read a digest written in the given encoding.
pub fn decode(encoding: Encoding, value: &str) -> Option<Vec<u8>> {
    let (codec, digits) = codec_and_digits(encoding, value)?;
    codec.decode(digits).ok()
}

/// The number of bytes a value decodes to in this encoding, told from its digit count alone.
///
/// Returns `None` when the count is not one this encoding writes. The digits themselves are not
/// checked, so a `Some` does not mean [`decode`] succeeds.
pub fn decoded_length(encoding: Encoding, value: &str) -> Option<usize> {
    let (codec, digits) = codec_and_digits(encoding, value)?;
    codec.decode_len(digits.len()).ok()
}

/// The decoder for an encoding, with the value's digits once valid padding is removed.
fn codec_and_digits(encoding: Encoding, value: &str) -> Option<(&'static DataEncoding, &[u8])> {
    let value = value.as_bytes();
    match encoding {
        Encoding::Base16 => Some((&BASE16, value)),
        Encoding::Base32 => unpadded(value, 8).map(|digits| (&BASE32, digits)),
        Encoding::Base64 => unpadded(value, 4).map(|digits| (&*BASE64_BOTH, digits)),
    }
}

/// Remove valid `=` padding for an encoding with groups of `group` digits.
///
/// Returns `None` when the padding is not the number of `=` characters those digits call for.
fn unpadded(value: &[u8], group: usize) -> Option<&[u8]> {
    let end = value
        .iter()
        .position(|&byte| byte == b'=')
        .unwrap_or(value.len());
    let (digits, padding) = value.split_at(end);

    (padding.iter().all(|&byte| byte == b'=')
        && (padding.is_empty() || padding.len() == (group - digits.len() % group) % group))
        .then_some(digits)
}
