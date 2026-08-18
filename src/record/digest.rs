//! Computing and checking the digest of a content block.

// The three digest crates re-export the same `Digest` trait, so one import serves all of them.
use sha1::Digest as _;

use crate::record::extension::Extension;
use crate::record::{BlockError, Record};
use crate::value::{DigestAlgorithm, LabelledDigest};

/// The block digest a record that declares none is given.
///
/// The standard recommends no algorithm. SHA-256 is the strongest of the three this crate
/// computes, and annotation #80 of the WARC 1.1 annotated specification asks for Base16 in lower
/// case, which is what its digests are written in.
pub fn added_block_digest(block: &[u8]) -> LabelledDigest {
    LabelledDigest::from_digest(DigestAlgorithm::Sha256, &sha2::Sha256::digest(block))
}

/// The SHA-1 block digest, written in unpadded upper-case Base32.
///
/// This is what the tools that read and write these archives write, and annotation #80 records
/// that practice. A SHA-1 digest is twenty octets, which Base32 spells without padding.
pub fn sha_1_block_digest(block: &[u8]) -> LabelledDigest {
    LabelledDigest::from_digest(DigestAlgorithm::Sha1, &sha1::Sha1::digest(block))
}

/// Add a SHA-1 block digest unless the record already declares one.
pub fn add_sha_1_block_digest<E: Extension>(record: &mut Record<E>) {
    if record.core().block_digest.is_none() {
        let digest = sha_1_block_digest(&record.body_bytes());
        record.core_mut().block_digest = Some(digest);
    }
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

/// Validate a declared block digest.
///
/// Unsupported algorithms are not checked.
pub fn verify_block_digest(declared: &LabelledDigest, block: &[u8]) -> Result<(), BlockError> {
    let Some(digest) = digest_block(declared.algorithm(), block) else {
        return Ok(());
    };

    // A failure names the digest that caused it, which is the only place a copy is needed.
    match declared.decoded() {
        None => Err(BlockError::MalformedBlockDigest(declared.clone())),
        Some(value) if value != digest => Err(BlockError::BlockDigestMismatch {
            actual: LabelledDigest::from_digest(declared.algorithm().clone(), &digest),
            declared: declared.clone(),
        }),
        Some(_) => Ok(()),
    }
}

/// Return the block digest to render, validating a declared digest if present.
///
/// If no digest is declared, the default digest is added.
pub fn check_block_digest(
    declared: Option<LabelledDigest>,
    block: &[u8],
) -> Result<LabelledDigest, BlockError> {
    let Some(declared) = declared else {
        return Ok(added_block_digest(block));
    };

    verify_block_digest(&declared, block)?;

    Ok(declared)
}

#[cfg(test)]
mod tests {
    use super::{added_block_digest, sha_1_block_digest};

    /// The block the digests here are computed over.
    const BLOCK: &[u8] = b"hello";

    #[test]
    fn adds_a_sha_256_digest_in_lower_case_base16() {
        assert_eq!(
            added_block_digest(BLOCK).to_string(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn writes_a_sha_1_digest_in_unpadded_upper_case_base32() {
        assert_eq!(
            sha_1_block_digest(BLOCK).to_string(),
            "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N"
        );
    }
}
