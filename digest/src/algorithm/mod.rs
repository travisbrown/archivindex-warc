//! Digest algorithms and computation.

mod compute;
pub mod marker;
mod supported;

use std::fmt::Display;
use std::str::FromStr;

use crate::{Encoding, label};

/// A label names no algorithm annotation #80 lists. The message includes the label.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown digest algorithm: {0:?}")]
pub struct UnknownAlgorithm(String);

/// A digest algorithm named by annotation #80 of the WARC 1.1 annotated specification.
///
/// The annotation gives each algorithm a recommended label and, for some, a compatibility label.
/// Labels are matched without regard to case, so `SHA-1`, `sha-1`, and `sha1` all name
/// [`Sha1`](Self::Sha1). A label outside the annotation's list is retained by
/// [`LabelledDigest`](crate::LabelledDigest) as a custom label and has no variant here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    /// MD5, labelled `md5`.
    Md5,
    /// SHA-1, labelled `sha1`, or `sha-1` for compatibility.
    Sha1,
    /// XXH3, labelled `xxh3`.
    Xxh3,
    /// XXH128, labelled `xxh128`.
    Xxh128,
    /// SHA-224, labelled `sha224`, or `sha-224` for compatibility.
    Sha224,
    /// SHA-256, labelled `sha256`, or `sha-256` for compatibility.
    Sha256,
    /// SHA-384, labelled `sha384`, or `sha-384` for compatibility.
    Sha384,
    /// SHA-512, labelled `sha512`, or `sha-512` for compatibility.
    Sha512,
    /// SHA-512/224, labelled `sha512-224`.
    Sha512_224,
    /// SHA-512/256, labelled `sha512-256`.
    Sha512_256,
    /// SHA3-224, labelled `sha3-224`.
    Sha3_224,
    /// SHA3-256, labelled `sha3-256`.
    Sha3_256,
    /// SHA3-384, labelled `sha3-384`.
    Sha3_384,
    /// SHA3-512, labelled `sha3-512`.
    Sha3_512,
    /// BLAKE2s, labelled `blake2s`.
    Blake2s,
    /// BLAKE2b, labelled `blake2b`.
    Blake2b,
    /// BLAKE3, labelled `blake3`.
    Blake3,
}

impl Algorithm {
    /// All algorithms named by annotation #80, in declaration order.
    pub const ALL: [Self; 17] = [
        Self::Md5,
        Self::Sha1,
        Self::Xxh3,
        Self::Xxh128,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha512_224,
        Self::Sha512_256,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Blake2s,
        Self::Blake2b,
        Self::Blake3,
    ];

    /// The recommended label for this algorithm.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Xxh3 => "xxh3",
            Self::Xxh128 => "xxh128",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha512_224 => "sha512-224",
            Self::Sha512_256 => "sha512-256",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Blake2s => "blake2s",
            Self::Blake2b => "blake2b",
            Self::Blake3 => "blake3",
        }
    }

    /// The number of bytes the algorithm produces.
    #[must_use]
    pub const fn digest_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Xxh3 => 8,
            Self::Md5 | Self::Xxh128 => 16,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha512_256 | Self::Sha3_256 | Self::Blake2s | Self::Blake3 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b => 64,
        }
    }

    /// The encoding annotation #80 asks for when writing this algorithm's digests.
    ///
    /// Base32 pads a digest whose length is not a multiple of five bytes, and the annotation asks
    /// writers to avoid that padding by using Base16 instead. The annotation's table nevertheless
    /// lists XXH128, a 16-byte digest, under Base32, which appears to be an error in the table;
    /// XXH128 follows the rule here and is Base16, like MD5.
    #[must_use]
    pub const fn recommended_encoding(self) -> Encoding {
        match self {
            Self::Sha1 => Encoding::Base32,
            Self::Md5
            | Self::Xxh3
            | Self::Xxh128
            | Self::Sha224
            | Self::Sha256
            | Self::Sha384
            | Self::Sha512
            | Self::Sha512_224
            | Self::Sha512_256
            | Self::Sha3_224
            | Self::Sha3_256
            | Self::Sha3_384
            | Self::Sha3_512
            | Self::Blake2s
            | Self::Blake2b
            | Self::Blake3 => Encoding::Base16,
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).label())
    }
}

impl FromStr for Algorithm {
    type Err = UnknownAlgorithm;

    /// Resolve a recommended or compatibility label, ignoring ASCII case.
    fn from_str(label: &str) -> Result<Self, UnknownAlgorithm> {
        label::algorithm(label)
            .map(|(algorithm, _)| algorithm)
            .ok_or_else(|| UnknownAlgorithm(label.to_owned()))
    }
}

/// Serializes as the recommended label.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::ser::Serialize for Algorithm {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

/// Deserializes from any label [`FromStr`] accepts.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::de::Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LabelVisitor;

        impl serde::de::Visitor<'_> for LabelVisitor {
            type Value = Algorithm;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a digest algorithm label")
            }

            fn visit_str<E: serde::de::Error>(self, label: &str) -> Result<Algorithm, E> {
                label.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(LabelVisitor)
    }
}

/// An incremental digest computation.
#[derive(Clone)]
pub struct Hasher(Algorithm, compute::Inner);

/// A computed digest, held inline: no algorithm here produces more than 64 octets.
///
/// It dereferences to its octets, so it is passed wherever a byte slice is.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Digest {
    octets: [u8; 64],
    length: usize,
}

// Only an enabled algorithm produces a digest.
#[cfg(any(
    feature = "md5",
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "blake2",
    feature = "blake3",
    feature = "xxh3"
))]
impl Digest {
    /// A digest of `octets`, which are at most 64.
    pub(super) fn new(octets: &[u8]) -> Self {
        let mut held = [0; 64];
        held[..octets.len()].copy_from_slice(octets);

        Self {
            octets: held,
            length: octets.len(),
        }
    }
}

impl std::ops::Deref for Digest {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.octets[..self.length]
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <[u8] as std::fmt::Debug>::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_strategy::proptest;

    use super::{Algorithm, UnknownAlgorithm};
    use crate::strategies;

    /// Every spelling of a known label parses to its algorithm.
    #[proptest]
    fn parses_a_known_label_in_any_case(
        #[strategy(strategies::known_label())] input: (Algorithm, String),
    ) {
        let (algorithm, spelling) = input;

        prop_assert_eq!(spelling.parse::<Algorithm>(), Ok(algorithm));
    }

    #[test]
    fn rejects_an_unknown_label() {
        assert_eq!(
            "crc32".parse::<Algorithm>(),
            Err(UnknownAlgorithm("crc32".to_owned()))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_as_the_recommended_label() {
        assert_eq!(
            serde_json::to_string(&Algorithm::Sha512_256).expect("a JSON string"),
            "\"sha512-256\""
        );
        assert_eq!(
            serde_json::from_str::<Algorithm>("\"SHA-256\"").expect("an algorithm"),
            Algorithm::Sha256
        );
        assert!(serde_json::from_str::<Algorithm>("\"crc32\"").is_err());
    }

    #[cfg(any(
        feature = "md5",
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "blake2",
        feature = "blake3",
        feature = "xxh3"
    ))]
    #[test]
    fn a_digest_is_its_octets() {
        use super::Digest;

        let digest = Digest::new(&[1, 2, 3]);

        assert_eq!(&*digest, &[1, 2, 3]);
        assert_eq!(digest.as_ref(), &[1, 2, 3]);
        assert_eq!(format!("{digest:?}"), "[1, 2, 3]");
        assert_eq!(digest, Digest::new(&[1, 2, 3]));
        assert_ne!(digest, Digest::new(&[1, 2, 3, 0]));
        assert_eq!(Digest::new(&[]).len(), 0);
        assert_eq!(Digest::new(&[7; 64]).len(), 64);
    }
}
