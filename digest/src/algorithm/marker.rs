//! Type-level digest algorithm markers.
//!
//! [`Supported`] is implemented only for algorithms enabled by this build.

use super::{Algorithm, Hasher};

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Md5 {}
    impl Sealed for super::Sha1 {}
    impl Sealed for super::Xxh3 {}
    impl Sealed for super::Xxh128 {}
    impl Sealed for super::Sha224 {}
    impl Sealed for super::Sha256 {}
    impl Sealed for super::Sha384 {}
    impl Sealed for super::Sha512 {}
    impl Sealed for super::Sha512_224 {}
    impl Sealed for super::Sha512_256 {}
    impl Sealed for super::Sha3_224 {}
    impl Sealed for super::Sha3_256 {}
    impl Sealed for super::Sha3_384 {}
    impl Sealed for super::Sha3_512 {}
    impl Sealed for super::Blake2s {}
    impl Sealed for super::Blake2b {}
    impl Sealed for super::Blake3 {}
}

/// A sealed trait implemented by markers for enabled digest algorithms.
///
/// An implementation exists only for an enabled algorithm, so [`Supported::hasher`] returns a
/// [`Hasher`] directly where [`Algorithm::hasher`] returns an `Option`.
#[diagnostic::on_unimplemented(
    message = "this build does not enable the `{Self}` digest algorithm",
    note = "`{Self}`'s documentation names the `archivindex-warc-digest` feature that enables it"
)]
pub trait Supported: sealed::Sealed {
    /// The algorithm the marker names.
    const ALGORITHM: Algorithm;

    /// Create an incremental hasher for the algorithm.
    #[must_use]
    fn hasher() -> Hasher {
        Self::ALGORITHM
            .hasher()
            .expect("invariant violation: `Supported` is implemented only for enabled algorithms")
    }
}

/// MD5, enabled by the `md5` feature.
#[derive(Clone, Copy, Debug)]
pub struct Md5;
/// SHA-1, enabled by the `sha1` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha1;
/// XXH3, enabled by the `xxh3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Xxh3;
/// XXH128, enabled by the `xxh3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Xxh128;
/// SHA-224, enabled by the `sha2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha224;
/// SHA-256, enabled by the `sha2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha256;
/// SHA-384, enabled by the `sha2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha384;
/// SHA-512, enabled by the `sha2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha512;
/// SHA-512/224, enabled by the `sha2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha512_224;
/// SHA-512/256, enabled by the `sha2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha512_256;
/// SHA3-224, enabled by the `sha3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha3_224;
/// SHA3-256, enabled by the `sha3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha3_256;
/// SHA3-384, enabled by the `sha3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha3_384;
/// SHA3-512, enabled by the `sha3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Sha3_512;
/// BLAKE2s, enabled by the `blake2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Blake2s;
/// BLAKE2b, enabled by the `blake2` feature.
#[derive(Clone, Copy, Debug)]
pub struct Blake2b;
/// BLAKE3, enabled by the `blake3` feature.
#[derive(Clone, Copy, Debug)]
pub struct Blake3;
