#![cfg_attr(docsrs, feature(doc_cfg))]
//! The `labelled-digest` value carried by `WARC-Block-Digest` and `WARC-Payload-Digest`.

pub mod algorithm;
mod label;
mod parsing;
#[cfg(test)]
mod strategies;
pub mod token;

use std::borrow::Cow;
use std::fmt::Display;

use algorithm::Algorithm;
use data_encoding::Encoding as DataEncoding;
use label::AlgorithmLabel;
use parsing::{from_ascii, is_digest_value};
use token::is_token;

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

/// The base encoding a digest value is written in, as defined by RFC 4648.
///
/// Annotation #80 of the WARC 1.1 annotated specification names Base16 and Base32. Base64 is also
/// supported because existing tools use it and annotation #48 permits its characters in a
/// `digest-value`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Encoding {
    /// Base16, written here in lowercase.
    Base16,
    /// Base32, written here in uppercase, padded with `=`.
    Base32,
    /// Base64, written in the standard alphabet and read in standard or URL-safe form.
    Base64,
}

impl Encoding {
    /// Every encoding this crate reads, in the order [`LabelledDigest::encoding`] tries them.
    pub const ALL: [Self; 3] = [Self::Base16, Self::Base32, Self::Base64];

    /// Write a digest in this encoding, in the case annotation #80 asks for.
    ///
    /// # Errors
    ///
    /// Returns whatever error the writer returns.
    pub fn encode<W: std::fmt::Write>(self, digest: &[u8], writer: &mut W) -> std::fmt::Result {
        writer.write_fmt(format_args!("{}", self.codec().encode_display(digest)))
    }

    /// The number of characters this encoding writes a digest of the given length in.
    fn encoded_length(self, digest_length: usize) -> usize {
        self.codec().encode_len(digest_length)
    }

    /// The canonical encoder for this base.
    const fn codec(self) -> DataEncoding {
        match self {
            Self::Base16 => data_encoding::HEXLOWER,
            Self::Base32 => data_encoding::BASE32,
            Self::Base64 => data_encoding::BASE64,
        }
    }

    /// Read a digest written in this encoding.
    ///
    /// Returns `None` if the value is not valid in this encoding. Base16 and Base32 are
    /// case-insensitive; Base64 is not.
    #[must_use]
    pub fn decode(self, value: &str) -> Option<Vec<u8>> {
        parsing::decode(self, value)
    }
}

/// A `labelled-digest`: an algorithm label and digest value separated by `:`.
///
/// The published grammar makes `digest-value` a `token`, which excludes `=` and `/`, and therefore
/// rules out Base32 padding and part of the Base64 alphabet. Annotation #48 of the WARC 1.1
/// annotated specification directs readers to accept both characters, and this type follows the
/// annotation.
///
/// Both halves are preserved as written, and [`Display`] writes them back as read. Equality is
/// the digest a value represents rather than the spelling it is written in: known labels and
/// decoded values are normalized, custom labels ignore ASCII case, and values of unknown encoding
/// compare as written. Compare spellings with [`algorithm_as_read`](Self::algorithm_as_read) and
/// [`value`](Self::value).
#[derive(Clone, Debug)]
pub struct LabelledDigest {
    algorithm: AlgorithmLabel,
    value: Box<str>,
}

impl LabelledDigest {
    /// Read a labelled digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSeparator`] when the colon is missing, [`Error::MalformedAlgorithm`]
    /// when the algorithm is not a token, and [`Error::MalformedValue`] when the digest value is
    /// not one, with `=` and `/` also allowed there per annotation #48.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        // An algorithm token cannot contain a colon, so the first colon separates the halves.
        let colon =
            value
                .iter()
                .position(|&byte| byte == b':')
                .ok_or_else(|| Error::NoSeparator {
                    value: String::from_utf8_lossy(value).into_owned(),
                })?;
        let (algorithm, digest) = (&value[..colon], &value[colon + 1..]);

        if !is_token(algorithm) {
            return Err(Error::MalformedAlgorithm {
                algorithm: String::from_utf8_lossy(algorithm).into_owned(),
            });
        }
        if !is_digest_value(digest) {
            return Err(Error::MalformedValue {
                digest: String::from_utf8_lossy(digest).into_owned(),
            });
        }

        // Both halves are checked above to hold only ASCII, so neither conversion can fail.
        let label = from_ascii(algorithm);

        Ok(Self {
            algorithm: AlgorithmLabel::new(label),
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

    /// A labelled digest using the algorithm's recommended label and encoding.
    #[must_use]
    // Writing to a string is the one use of `encode` that cannot fail, so nothing here can panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_digest(algorithm: Algorithm, digest: &[u8]) -> Self {
        let encoding = algorithm.recommended_encoding();
        let mut value = String::with_capacity(encoding.encoded_length(digest.len()));
        encoding
            .encode(digest, &mut value)
            .expect("invariant violation: writing to a string cannot fail");

        Self {
            algorithm: AlgorithmLabel::from_algorithm(algorithm),
            value: value.into_boxed_str(),
        }
    }

    /// The digest algorithm, or `None` when the label names one this crate does not know.
    #[must_use]
    pub const fn algorithm(&self) -> Option<Algorithm> {
        self.algorithm.algorithm()
    }

    /// The algorithm label, as it was written.
    #[must_use]
    pub fn algorithm_as_read(&self) -> Cow<'_, str> {
        self.algorithm.as_read()
    }

    /// The digest value, as written.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The value's encoding, or `None` if it is invalid or ambiguous.
    ///
    /// A value is in an encoding when its characters and length fit it, and, for an algorithm
    /// whose digest length is known, when it decodes to that many bytes. That length check is
    /// what leaves a known algorithm's digest fitting at most one encoding.
    #[must_use]
    pub fn encoding(&self) -> Option<Encoding> {
        self.decode_value().map(|(encoding, _)| encoding)
    }

    /// The digest bytes, or `None` when the value's encoding cannot be told.
    #[must_use]
    pub fn decoded(&self) -> Option<Vec<u8>> {
        self.decode_value().map(|(_, digest)| digest)
    }

    /// The one encoding the value fits, with the digest it decodes to.
    ///
    /// An encoding whose digit count cannot give the expected length is ruled out before
    /// anything is decoded, so a known algorithm's value is normally decoded once.
    fn decode_value(&self) -> Option<(Encoding, Vec<u8>)> {
        let expected = self.algorithm().map(Algorithm::digest_length);
        let mut fitting = Encoding::ALL.into_iter().filter_map(|encoding| {
            parsing::decoded_length(encoding, &self.value)
                .filter(|length| expected.is_none_or(|expected| *length == expected))
                .and_then(|_| encoding.decode(&self.value))
                .map(|digest| (encoding, digest))
        });

        let first = fitting.next()?;

        fitting.next().is_none().then_some(first)
    }
}

impl PartialEq for LabelledDigest {
    fn eq(&self, other: &Self) -> bool {
        // The same spelling is the same digest, or the same undecodable value.
        self.algorithm == other.algorithm
            && (self.value == other.value
                || match (self.decoded(), other.decoded()) {
                    (Some(digest), Some(other)) => digest == other,
                    _ => false,
                })
    }
}

impl Eq for LabelledDigest {}

impl std::hash::Hash for LabelledDigest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        // A value that decodes is the digest it decodes to, whatever it was written in, and one
        // that does not is only itself.
        match self.decoded() {
            Some(digest) => digest.hash(state),
            None => self.value.hash(state),
        }
    }
}

impl Display for LabelledDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.algorithm.write_to(f)?;
        write!(f, ":{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_strategy::proptest;

    use super::{Algorithm, Encoding, Error, LabelledDigest};
    use crate::{parsing, strategies};

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

    /// Any valid `labelled-digest` renders exactly as read.
    #[proptest]
    fn round_trips_a_valid_labelled_digest(
        #[strategy(strategies::token())] algorithm: String,
        #[strategy(strategies::digest_value())] value: String,
    ) {
        let written = format!("{algorithm}:{value}");
        let digest = parse(&written);

        prop_assert_eq!(digest.algorithm_as_read(), algorithm);
        prop_assert_eq!(digest.value(), value);
        prop_assert_eq!(digest.to_string(), written);
    }

    /// Every encoding round-trips arbitrary digest bytes.
    #[proptest]
    fn round_trips_any_digest_through_each_encoding(
        #[strategy(strategies::encoding())] encoding: Encoding,
        #[strategy(proptest::collection::vec(any::<u8>(), 0..=64))] digest: Vec<u8>,
    ) {
        let mut encoded = String::new();
        encoding
            .encode(&digest, &mut encoded)
            .expect("an encoded digest");

        let decoded = encoding.decode(&encoded);

        prop_assert_eq!(decoded.as_deref(), Some(digest.as_slice()));
    }

    /// Each algorithm's recommended representation round-trips unambiguously.
    #[proptest]
    fn round_trips_a_digest_of_any_algorithm(
        #[strategy(strategies::algorithm_and_digest())] input: (Algorithm, Vec<u8>),
    ) {
        let (algorithm, digest) = input;
        let labelled = LabelledDigest::from_digest(algorithm, &digest);

        let decoded = labelled.decoded();

        prop_assert_eq!(labelled.algorithm(), Some(algorithm));
        prop_assert_eq!(labelled.encoding(), Some(algorithm.recommended_encoding()));
        prop_assert_eq!(decoded.as_deref(), Some(digest.as_slice()));
    }

    #[test]
    fn parses_labelled_digests() {
        let digest = parse("sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");

        assert_eq!(digest.algorithm(), Some(Algorithm::Sha1));
        assert_eq!(digest.algorithm_as_read(), "sha1");
        assert_eq!(digest.value(), "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");
        assert_eq!(digest.to_string(), "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");
    }

    /// Annotation #80 names the compatibility labels and asks readers to normalize them.
    #[test]
    fn reads_each_known_label_in_any_case_and_compatibility_spelling() {
        for (label, algorithm, recommended, length) in [
            ("MD5", Algorithm::Md5, "md5", 16),
            ("SHA-1", Algorithm::Sha1, "sha1", 20),
            ("xxh3", Algorithm::Xxh3, "xxh3", 8),
            ("XXH128", Algorithm::Xxh128, "xxh128", 16),
            ("SHA-224", Algorithm::Sha224, "sha224", 28),
            ("SHA-256", Algorithm::Sha256, "sha256", 32),
            ("SHA-384", Algorithm::Sha384, "sha384", 48),
            ("SHA-512", Algorithm::Sha512, "sha512", 64),
            ("sha512-224", Algorithm::Sha512_224, "sha512-224", 28),
            ("sha512-256", Algorithm::Sha512_256, "sha512-256", 32),
            ("SHA3-224", Algorithm::Sha3_224, "sha3-224", 28),
            ("SHA3-256", Algorithm::Sha3_256, "sha3-256", 32),
            ("SHA3-384", Algorithm::Sha3_384, "sha3-384", 48),
            ("SHA3-512", Algorithm::Sha3_512, "sha3-512", 64),
            ("BLAKE2s", Algorithm::Blake2s, "blake2s", 32),
            ("BLAKE2b", Algorithm::Blake2b, "blake2b", 64),
            ("Blake3", Algorithm::Blake3, "blake3", 32),
        ] {
            let digest = parse(&format!("{label}:00"));

            assert_eq!(digest.algorithm(), Some(algorithm), "{label}");
            assert_eq!(algorithm.label(), recommended, "{label}");
            assert_eq!(algorithm.digest_length(), length, "{label}");
            assert_eq!(digest.algorithm_as_read(), label, "{label}");
            assert_eq!(digest.to_string(), format!("{label}:00"), "{label}");
        }
    }

    #[test]
    fn keeps_a_custom_algorithm_label_as_written() {
        let digest = parse("Future-Digest:00");

        assert_eq!(digest.algorithm(), None);
        assert_eq!(digest.algorithm_as_read(), "Future-Digest");
        assert_eq!(digest.to_string(), "Future-Digest:00");
        assert_eq!(digest, parse("future-digest:00"));
    }

    #[test]
    fn writes_a_digest_as_annotation_80_asks() {
        assert_eq!(
            LabelledDigest::from_digest(Algorithm::Sha1, &EMPTY_SHA1).to_string(),
            "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ"
        );
        assert_eq!(
            LabelledDigest::from_digest(Algorithm::Md5, &EMPTY_MD5).to_string(),
            "md5:d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn uses_the_typical_encodings_listed_by_annotation_80() {
        assert_eq!(Algorithm::Md5.recommended_encoding(), Encoding::Base16);
        assert_eq!(Algorithm::Sha1.recommended_encoding(), Encoding::Base32);
        assert_eq!(Algorithm::Xxh3.recommended_encoding(), Encoding::Base16);
        assert_eq!(Algorithm::Xxh128.recommended_encoding(), Encoding::Base16);
        assert_eq!(Algorithm::Sha256.recommended_encoding(), Encoding::Base16);
    }

    #[test]
    fn tells_the_encoding_of_a_digest_value() {
        for (value, encoding) in [
            (
                "sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
                Some(Encoding::Base32),
            ),
            (
                "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
                Some(Encoding::Base16),
            ),
            (
                "md5:d41d8cd98f00b204e9800998ecf8427e",
                Some(Encoding::Base16),
            ),
            (
                "md5:2QOYZWMPACZAJ2MABGMOZ6CCPY======",
                Some(Encoding::Base32),
            ),
            ("sha1:2jmj7l5rSw0yVb/vlWAYkK/YBwk=", Some(Encoding::Base64)),
            // A value that fits every encoding, and one that fits none.
            ("xxh3:23456723456723456723456723456723", None),
            ("sha1:not-a-digest", None),
        ] {
            assert_eq!(parse(value).encoding(), encoding, "{value}");
        }
    }

    /// A value that decodes has the length its digit count tells, so the count never rules
    /// out an encoding the value is written in.
    #[proptest]
    fn tells_a_decoded_length_from_the_digit_count(
        #[strategy(strategies::digest_value())] value: String,
        #[strategy(strategies::encoding())] encoding: Encoding,
    ) {
        if let Some(digest) = parsing::decode(encoding, &value) {
            prop_assert_eq!(
                parsing::decoded_length(encoding, &value),
                Some(digest.len())
            );
        }
    }

    #[test]
    fn rejects_a_value_of_the_right_length_with_the_wrong_digits() {
        let value = format!("md5:{}", "z".repeat(32));

        assert_eq!(parse(&value).encoding(), None);
        assert_eq!(parse(&value).decoded(), None);
        assert_eq!(parse(&value), parse(&value));
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

    /// The hash a value is stored under.
    fn hash_of(digest: &LabelledDigest) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::hash::DefaultHasher::new();
        digest.hash(&mut hasher);

        hasher.finish()
    }

    /// A digest is one value in every encoding it can be written in, and hashes as one.
    #[proptest]
    fn compares_and_hashes_a_digest_by_value(
        #[strategy(strategies::algorithm_and_digest())] input: (Algorithm, Vec<u8>),
        #[strategy(strategies::encoding())] encoding: Encoding,
    ) {
        let (algorithm, digest) = input;
        let mut value = String::new();
        encoding
            .encode(&digest, &mut value)
            .expect("an encoded digest");

        let recommended = LabelledDigest::from_digest(algorithm, &digest);
        let written = LabelledDigest::new(algorithm.label(), &value).expect("a labelled digest");

        prop_assert_eq!(&recommended, &written);
        prop_assert_eq!(hash_of(&recommended), hash_of(&written));
    }

    /// Annotation #80 asks for the encoding to be resolved before comparing digests.
    #[test]
    fn matches_the_same_digest_however_it_is_written() {
        let base32 = parse("SHA-1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ");
        let base16 = parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");

        assert_eq!(base32, base16);
        assert_ne!(base32.to_string(), base16.to_string());
    }

    #[test]
    fn does_not_match_another_digest_or_another_algorithm() {
        let sha1 = parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");

        assert_ne!(sha1, parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd8070a"));
        assert_ne!(
            sha1,
            parse("sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
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

        assert_eq!(
            base64,
            parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_ne!(base64, parse("sha1:2JMJ7L5RSW0YVB/VLWAYKK/YBWK="));
    }

    /// A value in an encoding this crate cannot tell is not read as anything but itself.
    #[test]
    fn matches_an_undecodable_value_as_written() {
        let undecodable = parse("sha1:not-a-digest");

        assert_eq!(undecodable, parse("sha1:not-a-digest"));
        assert_ne!(undecodable, parse("sha1:NOT-A-DIGEST"));
        assert_ne!(
            undecodable,
            parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
    }

    #[test]
    fn encodes_and_decodes_a_padded_digest() {
        for encoding in [Encoding::Base16, Encoding::Base32, Encoding::Base64] {
            let mut encoded = String::new();
            encoding
                .encode(&EMPTY_MD5, &mut encoded)
                .expect("an encoded digest");

            assert_eq!(encoding.decode(&encoded).as_deref(), Some(&EMPTY_MD5[..]));
        }
    }

    /// RFC 4648 requires unused bits at the end of an encoding to be zero.
    #[test]
    fn rejects_non_zero_trailing_bits() {
        assert_eq!(Encoding::Base32.decode("74======"), Some(vec![0xff]));
        assert_eq!(Encoding::Base32.decode("75======"), None);
        assert_eq!(Encoding::Base64.decode("/w=="), Some(vec![0xff]));
        assert_eq!(Encoding::Base64.decode("/x=="), None);
    }

    /// Archives may use either Base64 alphabet, even within a single value.
    #[test]
    fn reads_mixed_base64_alphabets() {
        assert_eq!(Encoding::Base64.decode("+_8="), Some(vec![0xfb, 0xff]));
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
