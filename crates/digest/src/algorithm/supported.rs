//! Feature-gated [`Supported`] implementations.

// Each import is used only by the implementations an enabled feature provides, so this cannot
// be an expectation: with no algorithm feature enabled the imports really are unused.
#[allow(
    unused_imports,
    reason = "used only by the implementations a feature provides"
)]
use crate::algorithm::Algorithm;
#[allow(
    unused_imports,
    reason = "used only by the implementations a feature provides"
)]
use crate::algorithm::marker::{self, Supported};

#[cfg(feature = "md5")]
#[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
impl Supported for marker::Md5 {
    const ALGORITHM: Algorithm = Algorithm::Md5;
}

#[cfg(feature = "sha1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
impl Supported for marker::Sha1 {
    const ALGORITHM: Algorithm = Algorithm::Sha1;
}

#[cfg(feature = "xxh3")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxh3")))]
impl Supported for marker::Xxh3 {
    const ALGORITHM: Algorithm = Algorithm::Xxh3;
}

#[cfg(feature = "xxh3")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxh3")))]
impl Supported for marker::Xxh128 {
    const ALGORITHM: Algorithm = Algorithm::Xxh128;
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl Supported for marker::Sha224 {
    const ALGORITHM: Algorithm = Algorithm::Sha224;
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl Supported for marker::Sha256 {
    const ALGORITHM: Algorithm = Algorithm::Sha256;
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl Supported for marker::Sha384 {
    const ALGORITHM: Algorithm = Algorithm::Sha384;
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl Supported for marker::Sha512 {
    const ALGORITHM: Algorithm = Algorithm::Sha512;
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl Supported for marker::Sha512_224 {
    const ALGORITHM: Algorithm = Algorithm::Sha512_224;
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl Supported for marker::Sha512_256 {
    const ALGORITHM: Algorithm = Algorithm::Sha512_256;
}

#[cfg(feature = "sha3")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha3")))]
impl Supported for marker::Sha3_224 {
    const ALGORITHM: Algorithm = Algorithm::Sha3_224;
}

#[cfg(feature = "sha3")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha3")))]
impl Supported for marker::Sha3_256 {
    const ALGORITHM: Algorithm = Algorithm::Sha3_256;
}

#[cfg(feature = "sha3")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha3")))]
impl Supported for marker::Sha3_384 {
    const ALGORITHM: Algorithm = Algorithm::Sha3_384;
}

#[cfg(feature = "sha3")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha3")))]
impl Supported for marker::Sha3_512 {
    const ALGORITHM: Algorithm = Algorithm::Sha3_512;
}

#[cfg(feature = "blake2")]
#[cfg_attr(docsrs, doc(cfg(feature = "blake2")))]
impl Supported for marker::Blake2s {
    const ALGORITHM: Algorithm = Algorithm::Blake2s;
}

#[cfg(feature = "blake2")]
#[cfg_attr(docsrs, doc(cfg(feature = "blake2")))]
impl Supported for marker::Blake2b {
    const ALGORITHM: Algorithm = Algorithm::Blake2b;
}

#[cfg(feature = "blake3")]
#[cfg_attr(docsrs, doc(cfg(feature = "blake3")))]
impl Supported for marker::Blake3 {
    const ALGORITHM: Algorithm = Algorithm::Blake3;
}

// The check binds a hasher, which is an uninhabited type in a build with no algorithm.
#[cfg(all(
    test,
    any(
        feature = "md5",
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "blake2",
        feature = "blake3",
        feature = "xxh3"
    )
))]
mod tests {
    use super::{Supported, marker};

    /// Every marker agrees with the runtime hashing API.
    #[test]
    fn markers_agree_with_the_runtime_interface() {
        fn check<A: Supported>() {
            assert!(A::ALGORITHM.is_supported(), "{}", A::ALGORITHM);

            let mut hasher = A::hasher();
            hasher.update(b"content");
            assert_eq!(
                Some(hasher.finalize()),
                A::ALGORITHM.digest(b"content"),
                "{}",
                A::ALGORITHM
            );
        }

        #[cfg(feature = "md5")]
        check::<marker::Md5>();
        #[cfg(feature = "sha1")]
        check::<marker::Sha1>();
        #[cfg(feature = "xxh3")]
        check::<marker::Xxh3>();
        #[cfg(feature = "xxh3")]
        check::<marker::Xxh128>();
        #[cfg(feature = "sha2")]
        check::<marker::Sha224>();
        #[cfg(feature = "sha2")]
        check::<marker::Sha256>();
        #[cfg(feature = "sha2")]
        check::<marker::Sha384>();
        #[cfg(feature = "sha2")]
        check::<marker::Sha512>();
        #[cfg(feature = "sha2")]
        check::<marker::Sha512_224>();
        #[cfg(feature = "sha2")]
        check::<marker::Sha512_256>();
        #[cfg(feature = "sha3")]
        check::<marker::Sha3_224>();
        #[cfg(feature = "sha3")]
        check::<marker::Sha3_256>();
        #[cfg(feature = "sha3")]
        check::<marker::Sha3_384>();
        #[cfg(feature = "sha3")]
        check::<marker::Sha3_512>();
        #[cfg(feature = "blake2")]
        check::<marker::Blake2s>();
        #[cfg(feature = "blake2")]
        check::<marker::Blake2b>();
        #[cfg(feature = "blake3")]
        check::<marker::Blake3>();
    }
}
