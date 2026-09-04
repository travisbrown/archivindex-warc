//! Feature-gated digest computation.

// Each import is needed when its feature is the only one enabled, and is redundant when
// another crate re-exports the same trait, so this cannot be an expectation.
#[cfg(feature = "blake2")]
#[allow(
    unused_imports,
    reason = "needed when this feature is the only one enabled"
)]
use blake2::Digest as _;
#[cfg(feature = "md5")]
#[allow(
    unused_imports,
    reason = "needed when this feature is the only one enabled"
)]
use md5::Digest as _;
#[cfg(feature = "sha1")]
#[allow(
    unused_imports,
    reason = "needed when this feature is the only one enabled"
)]
use sha1::Digest as _;
#[cfg(feature = "sha2")]
#[allow(
    unused_imports,
    reason = "needed when this feature is the only one enabled"
)]
use sha2::Digest as _;
#[cfg(feature = "sha3")]
#[allow(
    unused_imports,
    reason = "needed when this feature is the only one enabled"
)]
use sha3::Digest as _;

use super::{Algorithm, Digest, Hasher};
use crate::{Encoding, Format, LabelledDigest};

impl Algorithm {
    /// Whether this build can compute this algorithm.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        match self {
            Self::Md5 => cfg!(feature = "md5"),
            Self::Sha1 => cfg!(feature = "sha1"),
            Self::Xxh3 | Self::Xxh128 => cfg!(feature = "xxh3"),
            Self::Sha224
            | Self::Sha256
            | Self::Sha384
            | Self::Sha512
            | Self::Sha512_224
            | Self::Sha512_256 => cfg!(feature = "sha2"),
            Self::Sha3_224 | Self::Sha3_256 | Self::Sha3_384 | Self::Sha3_512 => {
                cfg!(feature = "sha3")
            }
            Self::Blake2s | Self::Blake2b => cfg!(feature = "blake2"),
            Self::Blake3 => cfg!(feature = "blake3"),
        }
    }

    /// Compute this algorithm's digest of `content`.
    ///
    /// Returns `None` if the algorithm is disabled.
    #[must_use]
    pub fn digest(self, content: &[u8]) -> Option<Digest> {
        let mut hasher = self.hasher()?;
        hasher.update(content);

        Some(hasher.finalize())
    }

    /// Create a hasher for computing this algorithm incrementally.
    ///
    /// Returns `None` if the algorithm is disabled.
    #[cfg(any(
        feature = "md5",
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "blake2",
        feature = "blake3",
        feature = "xxh3"
    ))]
    #[must_use]
    pub fn hasher(self) -> Option<Hasher> {
        let inner = match self {
            #[cfg(feature = "md5")]
            Self::Md5 => Inner::Md5(md5::Md5::new()),
            #[cfg(feature = "sha1")]
            Self::Sha1 => Inner::Sha1(sha1::Sha1::new()),
            // `Xxh3::new` is const, and a build with only XXH3 would then be asked for a
            // const `hasher`.
            #[cfg(feature = "xxh3")]
            Self::Xxh3 => Inner::Xxh3(xxhash_rust::xxh3::Xxh3::default()),
            #[cfg(feature = "xxh3")]
            Self::Xxh128 => Inner::Xxh128(xxhash_rust::xxh3::Xxh3::default()),
            #[cfg(feature = "sha2")]
            Self::Sha224 => Inner::Sha224(sha2::Sha224::new()),
            #[cfg(feature = "sha2")]
            Self::Sha256 => Inner::Sha256(sha2::Sha256::new()),
            #[cfg(feature = "sha2")]
            Self::Sha384 => Inner::Sha384(sha2::Sha384::new()),
            #[cfg(feature = "sha2")]
            Self::Sha512 => Inner::Sha512(sha2::Sha512::new()),
            #[cfg(feature = "sha2")]
            Self::Sha512_224 => Inner::Sha512_224(sha2::Sha512_224::new()),
            #[cfg(feature = "sha2")]
            Self::Sha512_256 => Inner::Sha512_256(sha2::Sha512_256::new()),
            #[cfg(feature = "sha3")]
            Self::Sha3_224 => Inner::Sha3_224(sha3::Sha3_224::new()),
            #[cfg(feature = "sha3")]
            Self::Sha3_256 => Inner::Sha3_256(sha3::Sha3_256::new()),
            #[cfg(feature = "sha3")]
            Self::Sha3_384 => Inner::Sha3_384(sha3::Sha3_384::new()),
            #[cfg(feature = "sha3")]
            Self::Sha3_512 => Inner::Sha3_512(sha3::Sha3_512::new()),
            #[cfg(feature = "blake2")]
            Self::Blake2s => Inner::Blake2s(blake2::Blake2s256::new()),
            #[cfg(feature = "blake2")]
            Self::Blake2b => Inner::Blake2b(blake2::Blake2b512::new()),
            #[cfg(feature = "blake3")]
            Self::Blake3 => Inner::Blake3(Box::new(blake3::Hasher::new())),
            // Matches algorithms disabled in this build.
            #[allow(unreachable_patterns, reason = "reachable unless every feature is on")]
            _ => return None,
        };

        Some(Hasher(self, inner))
    }

    /// Create a hasher for computing this algorithm incrementally.
    ///
    /// Returns `None`: this build enables no algorithm.
    #[cfg(not(any(
        feature = "md5",
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "blake2",
        feature = "blake3",
        feature = "xxh3"
    )))]
    #[must_use]
    pub const fn hasher(self) -> Option<Hasher> {
        None
    }
}

/// The algorithm-specific hashing state held by a [`Hasher`].
#[derive(Clone)]
pub enum Inner {
    #[cfg(feature = "md5")]
    Md5(md5::Md5),
    #[cfg(feature = "sha1")]
    Sha1(sha1::Sha1),
    #[cfg(feature = "xxh3")]
    Xxh3(xxhash_rust::xxh3::Xxh3),
    #[cfg(feature = "xxh3")]
    Xxh128(xxhash_rust::xxh3::Xxh3),
    #[cfg(feature = "sha2")]
    Sha224(sha2::Sha224),
    #[cfg(feature = "sha2")]
    Sha256(sha2::Sha256),
    #[cfg(feature = "sha2")]
    Sha384(sha2::Sha384),
    #[cfg(feature = "sha2")]
    Sha512(sha2::Sha512),
    #[cfg(feature = "sha2")]
    Sha512_224(sha2::Sha512_224),
    #[cfg(feature = "sha2")]
    Sha512_256(sha2::Sha512_256),
    #[cfg(feature = "sha3")]
    Sha3_224(sha3::Sha3_224),
    #[cfg(feature = "sha3")]
    Sha3_256(sha3::Sha3_256),
    #[cfg(feature = "sha3")]
    Sha3_384(sha3::Sha3_384),
    #[cfg(feature = "sha3")]
    Sha3_512(sha3::Sha3_512),
    #[cfg(feature = "blake2")]
    Blake2s(blake2::Blake2s256),
    #[cfg(feature = "blake2")]
    Blake2b(blake2::Blake2b512),
    /// Boxed because BLAKE3's hasher state is far larger than the other algorithms'.
    #[cfg(feature = "blake3")]
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    /// The algorithm this hasher computes.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.0
    }

    /// Feed `content` into the hasher.
    pub fn update(&mut self, content: &[u8]) {
        match &mut self.1 {
            #[cfg(feature = "md5")]
            Inner::Md5(hasher) => hasher.update(content),
            #[cfg(feature = "sha1")]
            Inner::Sha1(hasher) => hasher.update(content),
            #[cfg(feature = "xxh3")]
            Inner::Xxh3(hasher) | Inner::Xxh128(hasher) => hasher.update(content),
            #[cfg(feature = "sha2")]
            Inner::Sha224(hasher) => hasher.update(content),
            #[cfg(feature = "sha2")]
            Inner::Sha256(hasher) => hasher.update(content),
            #[cfg(feature = "sha2")]
            Inner::Sha384(hasher) => hasher.update(content),
            #[cfg(feature = "sha2")]
            Inner::Sha512(hasher) => hasher.update(content),
            #[cfg(feature = "sha2")]
            Inner::Sha512_224(hasher) => hasher.update(content),
            #[cfg(feature = "sha2")]
            Inner::Sha512_256(hasher) => hasher.update(content),
            #[cfg(feature = "sha3")]
            Inner::Sha3_224(hasher) => hasher.update(content),
            #[cfg(feature = "sha3")]
            Inner::Sha3_256(hasher) => hasher.update(content),
            #[cfg(feature = "sha3")]
            Inner::Sha3_384(hasher) => hasher.update(content),
            #[cfg(feature = "sha3")]
            Inner::Sha3_512(hasher) => hasher.update(content),
            #[cfg(feature = "blake2")]
            Inner::Blake2s(hasher) => hasher.update(content),
            #[cfg(feature = "blake2")]
            Inner::Blake2b(hasher) => hasher.update(content),
            #[cfg(feature = "blake3")]
            Inner::Blake3(hasher) => {
                hasher.update(content);
            }
            // A hasher exists only for an enabled algorithm.
            #[allow(unreachable_patterns, reason = "reachable unless every feature is on")]
            _ => {
                let _ = content;
                unreachable!("invariant violation: hasher for an algorithm the build lacks")
            }
        }
    }

    /// Finish and return the digest.
    #[must_use]
    pub fn finalize(self) -> Digest {
        match self.1 {
            #[cfg(feature = "md5")]
            Inner::Md5(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha1")]
            Inner::Sha1(hasher) => Digest::new(&hasher.finalize()),
            // The XXH canonical representation is big-endian.
            #[cfg(feature = "xxh3")]
            Inner::Xxh3(hasher) => Digest::new(&hasher.digest().to_be_bytes()),
            #[cfg(feature = "xxh3")]
            Inner::Xxh128(hasher) => Digest::new(&hasher.digest128().to_be_bytes()),
            #[cfg(feature = "sha2")]
            Inner::Sha224(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha2")]
            Inner::Sha256(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha2")]
            Inner::Sha384(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha2")]
            Inner::Sha512(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha2")]
            Inner::Sha512_224(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha2")]
            Inner::Sha512_256(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha3")]
            Inner::Sha3_224(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha3")]
            Inner::Sha3_256(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha3")]
            Inner::Sha3_384(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "sha3")]
            Inner::Sha3_512(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "blake2")]
            Inner::Blake2s(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "blake2")]
            Inner::Blake2b(hasher) => Digest::new(&hasher.finalize()),
            #[cfg(feature = "blake3")]
            Inner::Blake3(hasher) => Digest::new(hasher.finalize().as_bytes()),
            // A hasher exists only for an enabled algorithm.
            #[allow(unreachable_patterns, reason = "reachable unless every feature is on")]
            _ => unreachable!("invariant violation: hasher for an algorithm the build lacks"),
        }
    }

    /// Finish and return a labelled digest using the recommended label and encoding.
    #[must_use]
    pub fn finalize_labelled(self) -> LabelledDigest {
        let encoding = self.algorithm().recommended_encoding();

        self.finalize_labelled_in(encoding)
    }

    /// Finish and return a labelled digest using the recommended label and the given encoding.
    #[must_use]
    pub fn finalize_labelled_in(self, encoding: Encoding) -> LabelledDigest {
        let format = Format {
            algorithm: self.algorithm(),
            encoding,
        };

        LabelledDigest::from_digest_in(format, &self.finalize())
    }
}

/// Shows the algorithm without its hashing state.
impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Hasher").field(&self.algorithm()).finish()
    }
}

/// Feeds written bytes into the hasher.
impl std::io::Write for Hasher {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.update(buffer);

        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LabelledDigest {
    /// Compute a labelled digest using the recommended label and encoding.
    ///
    /// Returns `None` if the algorithm is disabled.
    #[must_use]
    pub fn compute(algorithm: Algorithm, content: &[u8]) -> Option<Self> {
        Some(Self::from_digest(algorithm, &algorithm.digest(content)?))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_strategy::proptest;

    use super::{Algorithm, LabelledDigest};
    use crate::strategies;

    /// Reference values come from `hashlib`, OpenSSL, and published XXH3 and BLAKE3 vectors.
    static REFERENCE_DIGESTS: &[(Algorithm, &[u8], &str)] = &[
        #[cfg(feature = "md5")]
        (
            Algorithm::Md5,
            b"hello",
            "md5:5d41402abc4b2a76b9719d911017c592",
        ),
        #[cfg(feature = "sha1")]
        (
            Algorithm::Sha1,
            b"hello",
            "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N",
        ),
        #[cfg(feature = "xxh3")]
        (Algorithm::Xxh3, b"", "xxh3:2d06800538d394c2"),
        #[cfg(feature = "xxh3")]
        (
            Algorithm::Xxh128,
            b"",
            "xxh128:99aa06d3014798d86001c324468d497f",
        ),
        #[cfg(feature = "sha2")]
        (
            Algorithm::Sha224,
            b"hello",
            "sha224:ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193",
        ),
        #[cfg(feature = "sha2")]
        (
            Algorithm::Sha256,
            b"hello",
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ),
        #[cfg(feature = "sha2")]
        (
            Algorithm::Sha384,
            b"hello",
            "sha384:59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
        ),
        #[cfg(feature = "sha2")]
        (
            Algorithm::Sha512,
            b"hello",
            "sha512:9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        ),
        #[cfg(feature = "sha2")]
        (
            Algorithm::Sha512_224,
            b"hello",
            "sha512-224:fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c",
        ),
        #[cfg(feature = "sha2")]
        (
            Algorithm::Sha512_256,
            b"hello",
            "sha512-256:e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a",
        ),
        #[cfg(feature = "sha3")]
        (
            Algorithm::Sha3_224,
            b"hello",
            "sha3-224:b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81",
        ),
        #[cfg(feature = "sha3")]
        (
            Algorithm::Sha3_256,
            b"hello",
            "sha3-256:3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392",
        ),
        #[cfg(feature = "sha3")]
        (
            Algorithm::Sha3_384,
            b"hello",
            "sha3-384:720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887",
        ),
        #[cfg(feature = "sha3")]
        (
            Algorithm::Sha3_512,
            b"hello",
            "sha3-512:75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",
        ),
        #[cfg(feature = "blake2")]
        (
            Algorithm::Blake2s,
            b"hello",
            "blake2s:19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25",
        ),
        #[cfg(feature = "blake2")]
        (
            Algorithm::Blake2b,
            b"hello",
            "blake2b:e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94",
        ),
        #[cfg(feature = "blake3")]
        (
            Algorithm::Blake3,
            b"",
            "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
    ];

    /// Every enabled algorithm computes its reference digest.
    #[test]
    fn computes_the_reference_digests() {
        for (algorithm, content, expected) in REFERENCE_DIGESTS {
            assert_eq!(
                LabelledDigest::compute(*algorithm, content).map(|digest| digest.to_string()),
                Some((*expected).to_owned()),
                "{algorithm}"
            );
        }
    }

    /// A digest is available exactly when its algorithm is enabled.
    #[proptest]
    fn computes_a_digest_exactly_when_supported(
        #[strategy(strategies::algorithm())] algorithm: Algorithm,
    ) {
        prop_assert_eq!(
            algorithm.digest(b"content").is_some(),
            algorithm.is_supported()
        );
    }

    /// A computed digest always has the algorithm's reported length.
    #[proptest]
    fn computes_a_digest_of_the_reported_length(
        #[strategy(strategies::algorithm())] algorithm: Algorithm,
        #[strategy(proptest::collection::vec(any::<u8>(), 0..=64))] content: Vec<u8>,
    ) {
        if let Some(digest) = algorithm.digest(&content) {
            prop_assert_eq!(digest.len(), algorithm.digest_length());
        }
    }

    /// Incremental hashing agrees with one-shot hashing for any chunking.
    #[proptest]
    fn hashes_incrementally_in_any_chunking(
        #[strategy(strategies::algorithm())] algorithm: Algorithm,
        #[strategy(proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..=16),
            0..=8,
        ))]
        chunks: Vec<Vec<u8>>,
    ) {
        let Some(mut hasher) = algorithm.hasher() else {
            prop_assert!(!algorithm.is_supported());
            return Ok(());
        };

        prop_assert_eq!(hasher.algorithm(), algorithm);

        for chunk in &chunks {
            hasher.update(chunk);
        }

        prop_assert_eq!(Some(hasher.finalize()), algorithm.digest(&chunks.concat()));
    }

    /// Incremental and one-shot hashing produce the same labelled digest.
    #[proptest]
    fn finalizes_the_labelled_digest_computing_writes(
        #[strategy(strategies::algorithm())] algorithm: Algorithm,
        #[strategy(proptest::collection::vec(any::<u8>(), 0..=64))] content: Vec<u8>,
    ) {
        if let Some(mut hasher) = algorithm.hasher() {
            hasher.update(&content);

            prop_assert_eq!(
                Some(hasher.finalize_labelled()),
                LabelledDigest::compute(algorithm, &content)
            );
        }
    }

    /// The `Write` implementation feeds bytes into the hasher.
    #[test]
    fn hashes_bytes_written_to_it() {
        use std::io::Write as _;

        for algorithm in Algorithm::ALL {
            let Some(mut hasher) = algorithm.hasher() else {
                continue;
            };

            hasher.write_all(b"hel").unwrap();
            hasher.write_all(b"lo").unwrap();
            hasher.flush().unwrap();

            assert_eq!(
                Some(hasher.finalize()),
                algorithm.digest(b"hello"),
                "{algorithm}"
            );
        }
    }

    /// A computed labelled digest decodes to the computed bytes.
    #[proptest]
    fn writes_a_computed_digest_that_reads_back(
        #[strategy(strategies::algorithm())] algorithm: Algorithm,
        #[strategy(proptest::collection::vec(any::<u8>(), 0..=64))] content: Vec<u8>,
    ) {
        if let Some(labelled) = LabelledDigest::compute(algorithm, &content) {
            let decoded = labelled.decoded();
            let computed = algorithm.digest(&content);

            prop_assert_eq!(labelled.algorithm(), Some(algorithm));
            prop_assert_eq!(decoded.as_deref(), computed.as_deref());
        }
    }
}
