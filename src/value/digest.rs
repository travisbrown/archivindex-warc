//! The `labelled-digest` value carried by `WARC-Block-Digest` and `WARC-Payload-Digest`.

use std::fmt::Display;
use std::str::FromStr;

use super::from_ascii;
use crate::parsing::{is_token, is_token_char, lossy};

/// The digits Base16 is written with, which annotation #80 asks to be lowercase.
const BASE16_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The digits Base32 is written with, which annotation #80 asks to be uppercase.
const BASE32_DIGITS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The digits Base64 is written with, in the standard alphabet of RFC 4648.
const BASE64_DIGITS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The rule a `labelled-digest` value did not match.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The value has no `:` separating the algorithm from the digest.
    #[error("not a labelled digest: no `:` separating algorithm from digest in `{value}`")]
    NoSeparator {
        /// The value as it was read, with any octet that is not UTF-8 replaced.
        value: String,
    },
    /// The algorithm label is not a `token`.
    #[error("not a labelled digest: `{algorithm}` is not an algorithm label")]
    MalformedAlgorithm {
        /// The label as it was read, with any octet that is not UTF-8 replaced.
        algorithm: String,
    },
    /// The digest is not a `digest-value`.
    #[error("not a labelled digest: `{digest}` is not a digest value")]
    MalformedValue {
        /// The digest as it was read, with any octet that is not UTF-8 replaced.
        digest: String,
    },
}

/// A digest algorithm, as named by the `algorithm` half of a labelled digest.
///
/// Annotation #80 of the WARC 1.1 annotated specification lists a recommended label for each
/// algorithm and the compatibility labels that name the same algorithm. Labels are read without
/// regard to case, so `SHA-1`, `sha-1`, and `sha1` all name [`Sha1`](Self::Sha1).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DigestAlgorithm {
    /// MD5, labelled `md5`.
    Md5,
    /// SHA-1, labelled `sha1`, or `sha-1` for compatibility.
    Sha1,
    /// SHA-256, labelled `sha256`, or `sha-256` for compatibility.
    Sha256,
    /// An algorithm this crate does not know, under its label lowercased.
    Other(Box<str>),
}

impl DigestAlgorithm {
    /// The recommended label for this algorithm.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Other(label) => label,
        }
    }

    /// The number of bytes the algorithm produces, or `None` for one this crate does not know.
    #[must_use]
    pub const fn digest_length(&self) -> Option<usize> {
        match self {
            Self::Md5 => Some(16),
            Self::Sha1 => Some(20),
            Self::Sha256 => Some(32),
            Self::Other(_) => None,
        }
    }

    /// The encoding annotation #80 asks for when writing this algorithm's digests.
    ///
    /// Base32 pads a digest whose length is not a multiple of five bytes, and the annotation asks
    /// writers to avoid that padding by using Base16 instead.
    #[must_use]
    pub const fn recommended_encoding(&self) -> DigestEncoding {
        match self {
            Self::Sha1 => DigestEncoding::Base32,
            Self::Md5 | Self::Sha256 | Self::Other(_) => DigestEncoding::Base16,
        }
    }

    /// The algorithm a label names, with compatibility labels resolved and case discarded.
    fn from_label(label: &str) -> Self {
        if label.eq_ignore_ascii_case("md5") {
            Self::Md5
        } else if label.eq_ignore_ascii_case("sha1") || label.eq_ignore_ascii_case("sha-1") {
            Self::Sha1
        } else if label.eq_ignore_ascii_case("sha256") || label.eq_ignore_ascii_case("sha-256") {
            Self::Sha256
        } else {
            Self::Other(label.to_ascii_lowercase().into_boxed_str())
        }
    }
}

impl Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for DigestAlgorithm {
    type Err = Error;

    /// Read an algorithm label, which must be a `token`.
    fn from_str(label: &str) -> Result<Self, Self::Err> {
        if is_token(label.as_bytes()) {
            Ok(Self::from_label(label))
        } else {
            Err(Error::MalformedAlgorithm {
                algorithm: label.to_owned(),
            })
        }
    }
}

/// The base encoding a digest value is written in, as defined by RFC 4648.
///
/// Annotation #80 of the WARC 1.1 annotated specification names Base16 and Base32. Base64 is here
/// because the tools that write these archives write it, which is also what annotation #48
/// relaxes the `digest-value` grammar for.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestEncoding {
    /// Base16, written here in lowercase.
    Base16,
    /// Base32, written here in uppercase, padded with `=`.
    Base32,
    /// Base64, written here in the standard alphabet, padded with `=`.
    ///
    /// Values are read in the standard alphabet and in the URL-safe one, which spells the last two
    /// digits `-` and `_`.
    Base64,
}

impl DigestEncoding {
    /// Write a digest in this encoding, in the case annotation #80 asks for.
    ///
    /// # Errors
    ///
    /// Returns whatever error the writer returns.
    pub fn encode<W: std::fmt::Write>(self, digest: &[u8], writer: &mut W) -> std::fmt::Result {
        match self {
            Self::Base16 => {
                for byte in digest {
                    writer.write_char(char::from(BASE16_DIGITS[usize::from(byte >> 4)]))?;
                    writer.write_char(char::from(BASE16_DIGITS[usize::from(byte & 0x0f)]))?;
                }
            }
            Self::Base32 => {
                for group in digest.chunks(5) {
                    encode_group(group, 5, BASE32_DIGITS, 8, writer)?;
                }
            }
            Self::Base64 => {
                for group in digest.chunks(3) {
                    encode_group(group, 6, BASE64_DIGITS, 4, writer)?;
                }
            }
        }

        Ok(())
    }

    /// The number of characters this encoding writes a digest of the given length in.
    const fn encoded_length(self, digest_length: usize) -> usize {
        match self {
            Self::Base16 => digest_length * 2,
            Self::Base32 => digest_length.div_ceil(5) * 8,
            Self::Base64 => digest_length.div_ceil(3) * 4,
        }
    }

    /// Read a digest written in this encoding.
    ///
    /// Base16 and Base32 are read in either case. Base64 spells different digests with the same
    /// letters in different cases, so its case is significant.
    ///
    /// Returns `None` when the value is not written in this encoding.
    #[must_use]
    pub fn decode(self, value: &str) -> Option<Vec<u8>> {
        let mut digest = Vec::with_capacity(self.decoded_length(value)?);
        match self {
            Self::Base16 => {
                for pair in value.as_bytes().chunks_exact(2) {
                    digest.push((base16_digit(pair[0])? << 4) | base16_digit(pair[1])?);
                }
            }
            Self::Base32 => decode_digits(value.as_bytes(), 5, base32_digit, &mut digest)?,
            Self::Base64 => decode_digits(value.as_bytes(), 6, base64_digit, &mut digest)?,
        }

        Some(digest)
    }

    /// The number of bytes a value decodes to, or `None` when it is not written in this encoding.
    fn decoded_length(self, value: &str) -> Option<usize> {
        let value = value.as_bytes();
        match self {
            Self::Base16 => (value.len() % 2 == 0 && value.iter().all(u8::is_ascii_hexdigit))
                .then_some(value.len() / 2),
            Self::Base32 => {
                let digits = unpadded(value, 8)?;

                (digits.iter().all(|&byte| base32_digit(byte).is_some())
                    && matches!(digits.len() % 8, 0 | 2 | 4 | 5 | 7))
                .then_some(digits.len() * 5 / 8)
            }
            Self::Base64 => {
                let digits = unpadded(value, 4)?;

                (digits.iter().all(|&byte| base64_digit(byte).is_some())
                    && matches!(digits.len() % 4, 0 | 2 | 3))
                .then_some(digits.len() * 6 / 8)
            }
        }
    }
}

/// A `labelled-digest`: an algorithm name and the digest it produced.
///
/// ```text
/// labelled-digest = algorithm ":" digest-value
/// algorithm       = token
/// digest-value    = token
/// ```
///
/// The published grammar makes `digest-value` a `token`, which excludes `=` and `/`, and therefore
/// rules out Base32 padding and part of the Base64 alphabet. Annotation #48 of the WARC 1.1
/// annotated specification directs readers to accept both characters, and this type follows the
/// annotation.
///
/// Both halves are kept as they were written, since a record must be able to render as it was read.
/// Equality is over that spelling; [`matches`](Self::matches) is the comparison annotation #80 asks
/// for, which is over the algorithm and the digest bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LabelledDigest {
    algorithm: DigestAlgorithm,
    /// The label as read, kept only when it is not the algorithm's recommended label.
    label_as_read: Option<Box<str>>,
    value: Box<str>,
}

impl LabelledDigest {
    /// Read a labelled digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSeparator`] when the colon is missing, [`Error::MalformedAlgorithm`]
    /// when the algorithm is not a token, and [`Error::MalformedValue`] when the digest is not one
    /// (with `=` and `/` also allowed there, per annotation #48).
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        // An algorithm token cannot contain a colon, so the first colon separates the halves.
        let colon =
            value
                .iter()
                .position(|&byte| byte == b':')
                .ok_or_else(|| Error::NoSeparator {
                    value: lossy(value),
                })?;
        let (algorithm, digest) = (&value[..colon], &value[colon + 1..]);

        if !is_token(algorithm) {
            return Err(Error::MalformedAlgorithm {
                algorithm: lossy(algorithm),
            });
        }
        if !is_digest_value(digest) {
            return Err(Error::MalformedValue {
                digest: lossy(digest),
            });
        }

        // Both halves are checked above to hold only ASCII, so neither conversion can fail.
        let label = from_ascii(algorithm);
        let algorithm = DigestAlgorithm::from_label(label);

        Ok(Self {
            label_as_read: (label != algorithm.label()).then(|| label.into()),
            algorithm,
            value: from_ascii(digest).into(),
        })
    }

    /// A labelled digest of the given algorithm and value.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] naming the half that does not match its grammar.
    pub fn new(algorithm: &str, value: &str) -> Result<Self, Error> {
        Self::parse(format!("{algorithm}:{value}").as_bytes())
    }

    /// A labelled digest reporting the given digest bytes.
    ///
    /// The value is written under the algorithm's recommended label, in the encoding and case
    /// annotation #80 asks for.
    #[must_use]
    // Writing to a string is the one use of `encode` that cannot fail, so nothing here can panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_digest(algorithm: DigestAlgorithm, digest: &[u8]) -> Self {
        let encoding = algorithm.recommended_encoding();
        let mut value = String::with_capacity(encoding.encoded_length(digest.len()));
        encoding
            .encode(digest, &mut value)
            .expect("invariant violation: writing to a string cannot fail");

        Self {
            algorithm,
            label_as_read: None,
            value: value.into_boxed_str(),
        }
    }

    /// The digest algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &DigestAlgorithm {
        &self.algorithm
    }

    /// The algorithm label, as it was written.
    #[must_use]
    pub fn algorithm_as_read(&self) -> &str {
        self.label_as_read
            .as_deref()
            .unwrap_or_else(|| self.algorithm.label())
    }

    /// The digest value, as it was written (the standard does not fix an encoding).
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The encoding the value is written in, or `None` when that cannot be told.
    ///
    /// A value is in an encoding when its characters and length fit it, and, for an algorithm whose
    /// digest length is known, when it decodes to that many bytes. A value that fits more than one
    /// encoding, which a digest of a known length cannot, is in none of them here. Annotation #80
    /// gives the length of each encoding and asks for Base32 padding to be read as it is written
    /// here.
    #[must_use]
    pub fn encoding(&self) -> Option<DigestEncoding> {
        let mut fitting = [
            DigestEncoding::Base16,
            DigestEncoding::Base32,
            DigestEncoding::Base64,
        ]
        .into_iter()
        .filter(|encoding| {
            encoding.decoded_length(&self.value).is_some_and(|length| {
                self.algorithm
                    .digest_length()
                    .is_none_or(|expected| length == expected)
            })
        });

        let encoding = fitting.next()?;

        fitting.next().is_none().then_some(encoding)
    }

    /// The digest bytes, or `None` when the value's encoding cannot be told.
    #[must_use]
    pub fn decoded(&self) -> Option<Vec<u8>> {
        self.encoding()?.decode(&self.value)
    }

    /// Whether two labelled digests report the same digest.
    ///
    /// Annotation #80 asks for the base encoding to be resolved before comparing, so the algorithms
    /// are compared under their recommended labels and the values under the bytes they encode. Two
    /// values whose encoding cannot be told are compared as they were written.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
            && match (self.decoded(), other.decoded()) {
                (Some(digest), Some(other)) => digest == other,
                _ => self.value == other.value,
            }
    }
}

impl Display for LabelledDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm_as_read(), self.value)
    }
}

/// Whether a value matches `digest-value` as annotation #48 relaxes it.
fn is_digest_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|&byte| is_token_char(byte) || byte == b'=' || byte == b'/')
}

/// Write one group of bytes as digits of `width` bits, padding the digits the group does not
/// reach with `=`.
fn encode_group<W: std::fmt::Write>(
    group: &[u8],
    width: usize,
    alphabet: &[u8],
    per_group: usize,
    writer: &mut W,
) -> std::fmt::Result {
    // The group's bytes are gathered into the top of a 64-bit accumulator and read out from there.
    let bits = group.iter().enumerate().fold(0u64, |bits, (index, byte)| {
        bits | (u64::from(*byte) << (56 - 8 * index))
    });
    let digits = (group.len() * 8).div_ceil(width);

    for index in 0..per_group {
        if index < digits {
            // The mask holds a digit to the width the alphabet spells, so it indexes the alphabet.
            #[allow(clippy::cast_possible_truncation)]
            let digit = ((bits >> (64 - width * (index + 1))) & ((1 << width) - 1)) as usize;
            writer.write_char(char::from(alphabet[digit]))?;
        } else {
            writer.write_char('=')?;
        }
    }

    Ok(())
}

/// Read digits of `width` bits into whole bytes, stopping at the padding.
///
/// Returns `None` at the first character the alphabet does not spell.
fn decode_digits(
    value: &[u8],
    width: u32,
    digit: impl Fn(u8) -> Option<u8>,
    digest: &mut Vec<u8>,
) -> Option<()> {
    let (mut bits, mut filled) = (0u32, 0u32);
    for &byte in value.iter().take_while(|&&byte| byte != b'=') {
        bits = (bits << width) | u32::from(digit(byte)?);
        filled += width;
        if filled >= 8 {
            filled -= 8;
            digest.push(((bits >> filled) & 0xff) as u8);
        }
    }

    Some(())
}

/// The digits of a value whose encoding writes `group` of them at a time, or `None` when its
/// padding is not `=` characters in the number those digits call for.
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

/// The value of a Base16 digit, in either case.
const fn base16_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The value of a Base32 digit, in either case.
const fn base32_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

/// The value of a Base64 digit, in the standard alphabet or the URL-safe one.
const fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestAlgorithm, DigestEncoding, Error, LabelledDigest};

    /// The SHA-1 digest of the empty block, which the fixtures write in both encodings.
    const EMPTY_SHA1: [u8; 20] = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18,
        0x90, 0xaf, 0xd8, 0x07, 0x09,
    ];

    /// The MD5 digest of the empty block, whose length Base32 has to pad.
    const EMPTY_MD5: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
    ];

    fn parse(value: &str) -> LabelledDigest {
        LabelledDigest::parse(value.as_bytes()).expect("a labelled digest")
    }

    #[test]
    fn parses_labelled_digests() {
        let digest = parse("sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");

        assert_eq!(digest.algorithm(), &DigestAlgorithm::Sha1);
        assert_eq!(digest.algorithm_as_read(), "sha1");
        assert_eq!(digest.value(), "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");
        assert_eq!(digest.to_string(), "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");
    }

    /// Annotation #80 names the compatibility labels and asks readers to normalize them.
    #[test]
    fn reads_a_label_in_any_case_and_either_spelling() {
        for (label, algorithm) in [
            ("md5", DigestAlgorithm::Md5),
            ("MD5", DigestAlgorithm::Md5),
            ("sha1", DigestAlgorithm::Sha1),
            ("SHA-1", DigestAlgorithm::Sha1),
            ("sha-1", DigestAlgorithm::Sha1),
            ("sha256", DigestAlgorithm::Sha256),
            ("SHA-256", DigestAlgorithm::Sha256),
            ("Blake3", DigestAlgorithm::Other("blake3".into())),
        ] {
            let digest = parse(&format!("{label}:00"));

            assert_eq!(digest.algorithm(), &algorithm, "{label}");
            assert_eq!(digest.algorithm_as_read(), label, "{label}");
            assert_eq!(digest.to_string(), format!("{label}:00"), "{label}");
        }
    }

    #[test]
    fn writes_a_digest_as_annotation_80_asks() {
        assert_eq!(
            LabelledDigest::from_digest(DigestAlgorithm::Sha1, &EMPTY_SHA1).to_string(),
            "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ"
        );
        assert_eq!(
            LabelledDigest::from_digest(DigestAlgorithm::Md5, &EMPTY_MD5).to_string(),
            "md5:d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn tells_the_encoding_of_a_digest_value() {
        for (value, encoding) in [
            (
                "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
                Some(DigestEncoding::Base32),
            ),
            (
                "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
                Some(DigestEncoding::Base16),
            ),
            (
                "md5:d41d8cd98f00b204e9800998ecf8427e",
                Some(DigestEncoding::Base16),
            ),
            (
                "md5:2QOYZWMPACZAJ2MABGMOZ6CCPY======",
                Some(DigestEncoding::Base32),
            ),
            (
                "sha1:2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
                Some(DigestEncoding::Base64),
            ),
            // A value that fits every encoding, and one that fits none.
            ("xxh3:23456723456723456723456723456723", None),
            ("sha1:not-a-digest", None),
        ] {
            assert_eq!(parse(value).encoding(), encoding, "{value}");
        }
    }

    #[test]
    fn decodes_a_digest_value_in_either_case() {
        for value in [
            "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
            "sha1:3i42h3s6nnfq2msvx7xzkyayscx5qbyj",
            "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha1:DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
        ] {
            assert_eq!(
                parse(value).decoded().as_deref(),
                Some(&EMPTY_SHA1[..]),
                "{value}"
            );
        }
    }

    /// Annotation #80 asks for the encoding to be resolved before comparing digests.
    #[test]
    fn matches_the_same_digest_however_it_is_written() {
        let base32 = parse("SHA-1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");
        let base16 = parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");

        assert!(base32.matches(&base16));
        assert_ne!(base32, base16);
    }

    #[test]
    fn does_not_match_another_digest_or_another_algorithm() {
        let sha1 = parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");

        assert!(!sha1.matches(&parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd8070a")));
        assert!(!sha1.matches(&parse("sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709")));
    }

    /// The archives this crate reads carry Base64 digests, in both of RFC 4648's alphabets and
    /// with the padding left off.
    #[test]
    fn reads_a_digest_written_in_base64() {
        for value in [
            "sha1:2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
            "sha1:2jmj7l5rSw0yVb_vlWAYkK_YBwk=",
            "sha1:2jmj7l5rSw0yVb/vlWAYkK/YBwk",
        ] {
            assert_eq!(
                parse(value).decoded().as_deref(),
                Some(&EMPTY_SHA1[..]),
                "{value}"
            );
        }
    }

    /// Base64 spells different digests with the same letters in different cases, so a value read
    /// in it is not the same digest as the same letters in another case.
    #[test]
    fn reads_base64_case_by_case() {
        let base64 = parse("sha1:2jmj7l5rSw0yVb/vlWAYkK/YBwk=");

        assert!(base64.matches(&parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")));
        assert!(!base64.matches(&parse("sha1:2JMJ7L5RSW0YVB/VLWAYKK/YBWK=")));
    }

    /// A value in an encoding this crate cannot tell is not read as anything but itself.
    #[test]
    fn matches_an_undecodable_value_as_written() {
        let undecodable = parse("sha1:not-a-digest");

        assert!(undecodable.matches(&parse("sha1:not-a-digest")));
        assert!(!undecodable.matches(&parse("sha1:NOT-A-DIGEST")));
        assert!(!undecodable.matches(&parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")));
    }

    #[test]
    fn encodes_and_decodes_a_padded_digest() {
        for encoding in [
            DigestEncoding::Base16,
            DigestEncoding::Base32,
            DigestEncoding::Base64,
        ] {
            let mut encoded = String::new();
            encoding
                .encode(&EMPTY_MD5, &mut encoded)
                .expect("an encoded digest");

            assert_eq!(encoding.decode(&encoded).as_deref(), Some(&EMPTY_MD5[..]));
        }
    }

    /// Annotation #48 asks readers to accept the two characters Base32 padding and Base64 need,
    /// which the published `token` grammar excludes.
    #[test]
    fn accepts_the_characters_annotation_48_allows() {
        for value in [b"md5:BAZ===".as_slice(), b"sha-256:a/b+c=".as_slice()] {
            assert!(LabelledDigest::parse(value).is_ok(), "{value:?}");
        }
    }

    #[test]
    fn rejects_malformed_digests() {
        for (value, expected) in [
            (
                b"nocolon".as_slice(),
                Error::NoSeparator {
                    value: "nocolon".to_owned(),
                },
            ),
            (
                b":value".as_slice(),
                Error::MalformedAlgorithm {
                    algorithm: String::new(),
                },
            ),
            (
                b"algorithm:".as_slice(),
                Error::MalformedValue {
                    digest: String::new(),
                },
            ),
            (
                b"algorithm:with space".as_slice(),
                Error::MalformedValue {
                    digest: "with space".to_owned(),
                },
            ),
            (
                b"with space:value".as_slice(),
                Error::MalformedAlgorithm {
                    algorithm: "with space".to_owned(),
                },
            ),
        ] {
            assert_eq!(LabelledDigest::parse(value), Err(expected), "{value:?}");
        }
    }
}
