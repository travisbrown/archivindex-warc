//! Computing and checking the digest of a content block.

// The three digest crates re-export the same `Digest` trait, so one import serves all of them.
use sha1::Digest as _;

use crate::record::BlockError;
use crate::value::{DigestAlgorithm, LabelledDigest};

/// The block digest a record that declares none is given.
///
/// The standard recommends no algorithm. SHA-256 is the strongest of the three this crate
/// computes, and annotation #80 of the WARC 1.1 annotated specification asks for Base16 in lower
/// case, which is what its digests are written in.
pub fn added_block_digest(block: &[u8]) -> LabelledDigest {
    LabelledDigest::from_digest(DigestAlgorithm::Sha256, &sha2::Sha256::digest(block))
}

/// The digest of a block under an algorithm this crate computes, or `None` under any other.
fn digest_block(algorithm: &DigestAlgorithm, block: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        DigestAlgorithm::Md5 => Some(md5::Md5::digest(block).to_vec()),
        DigestAlgorithm::Sha1 => Some(sha1::Sha1::digest(block).to_vec()),
        DigestAlgorithm::Sha256 => Some(sha2::Sha256::digest(block).to_vec()),
        DigestAlgorithm::Other(_) => None,
    }
}

/// The block digest to write for a block, checking the one a record declares.
///
/// A record that declares no digest is given one, since a digest can always be computed from the
/// block. A record that declares one under an algorithm this crate does not compute keeps it as
/// read and is not checked, since nothing here can tell whether it is right.
pub fn check_block_digest(
    declared: Option<LabelledDigest>,
    block: &[u8],
) -> Result<LabelledDigest, BlockError> {
    let Some(declared) = declared else {
        return Ok(added_block_digest(block));
    };

    let Some(digest) = digest_block(declared.algorithm(), block) else {
        return Ok(declared);
    };

    match declared.decoded() {
        None => Err(BlockError::MalformedBlockDigest(declared)),
        Some(value) if value != digest => Err(BlockError::BlockDigestMismatch {
            actual: LabelledDigest::from_digest(declared.algorithm().clone(), &digest),
            declared,
        }),
        Some(_) => Ok(declared),
    }
}

#[cfg(test)]
mod tests {
    use super::added_block_digest;

    /// The block the digests here are computed over.
    const BLOCK: &[u8] = b"hello";

    #[test]
    fn adds_a_sha_256_digest_in_lower_case_base16() {
        assert_eq!(
            added_block_digest(BLOCK).to_string(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
