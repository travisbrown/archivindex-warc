//! Digest calculation and validation for record blocks and payloads.

// The three digest crates re-export the same `Digest` trait, so one import serves all of them.
use sha1::Digest as _;

use crate::record::extension::Extension;
use crate::record::{BlockError, Record, payload};
use crate::value::{DigestAlgorithm, LabelledDigest};

/// Compute the default digest for a block or payload.
///
/// The result uses SHA-256 and lowercase Base16.
pub fn added_digest(content: &[u8]) -> LabelledDigest {
    LabelledDigest::from_digest(DigestAlgorithm::Sha256, &sha2::Sha256::digest(content))
}

/// Compute a SHA-1 digest in unpadded uppercase Base32.
///
/// This format is widely used by existing WARC tools.
pub fn sha_1_digest(content: &[u8]) -> LabelledDigest {
    LabelledDigest::from_digest(DigestAlgorithm::Sha1, &sha1::Sha1::digest(content))
}

/// Add a SHA-1 block digest unless the record already declares one.
pub fn add_sha_1_block_digest<E: Extension>(record: &mut Record<E>) {
    if record.core().block_digest.is_none() {
        let digest = sha_1_digest(&record.body_bytes());
        record.core_mut().block_digest = Some(digest);
    }
}

/// Add a SHA-1 payload digest when the record is eligible and declares none.
///
/// Records that would not receive a payload digest during rendering are unchanged.
pub fn add_sha_1_payload_digest<E: Extension>(record: &mut Record<E>) {
    let digest = match record.payload() {
        Some(headers)
            if headers.payload_digest.is_none() && record.takes_added_payload_digest() =>
        {
            match record.payload_bytes() {
                Ok(Some(payload)) => sha_1_digest(&payload),
                Ok(None) | Err(_) => return,
            }
        }
        Some(_) | None => return,
    };

    if let Some(headers) = record.payload_mut() {
        headers.payload_digest = Some(digest);
    }
}

/// Compute a digest for a supported algorithm.
fn digest_content(algorithm: &DigestAlgorithm, content: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        DigestAlgorithm::Md5 => Some(md5::Md5::digest(content).to_vec()),
        DigestAlgorithm::Sha1 => Some(sha1::Sha1::digest(content).to_vec()),
        DigestAlgorithm::Sha256 => Some(sha2::Sha256::digest(content).to_vec()),
        DigestAlgorithm::Other(_) => None,
    }
}

/// A digest validation failure, independent of whether it applies to a block or payload.
enum Fault {
    /// The value is invalid for its declared algorithm.
    Malformed,
    /// The computed digest differs from the declared value.
    Mismatch(LabelledDigest),
}

/// Compare a declared digest with the supplied content.
///
/// Unsupported algorithms are not checked.
fn compare_digest(declared: &LabelledDigest, content: &[u8]) -> Option<Fault> {
    let digest = digest_content(declared.algorithm(), content)?;

    match declared.decoded() {
        None => Some(Fault::Malformed),
        Some(value) if value != digest => Some(Fault::Mismatch(LabelledDigest::from_digest(
            declared.algorithm().clone(),
            &digest,
        ))),
        Some(_) => None,
    }
}

/// Validate a declared block digest.
pub fn verify_block_digest(declared: &LabelledDigest, block: &[u8]) -> Result<(), BlockError> {
    match compare_digest(declared, block) {
        None => Ok(()),
        Some(Fault::Malformed) => Err(BlockError::MalformedBlockDigest(Box::new(declared.clone()))),
        Some(Fault::Mismatch(actual)) => Err(BlockError::BlockDigestMismatch {
            declared: Box::new(declared.clone()),
            actual: Box::new(actual),
        }),
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
        return Ok(added_digest(block));
    };

    verify_block_digest(&declared, block)?;

    Ok(declared)
}

/// Validate a declared payload digest.
pub fn verify_payload_digest(declared: &LabelledDigest, payload: &[u8]) -> Result<(), BlockError> {
    match compare_digest(declared, payload) {
        None => Ok(()),
        Some(Fault::Malformed) => Err(BlockError::MalformedPayloadDigest(Box::new(
            declared.clone(),
        ))),
        Some(Fault::Mismatch(actual)) => Err(BlockError::PayloadDigestMismatch {
            declared: Box::new(declared.clone()),
            actual: Box::new(actual),
        }),
    }
}

/// Validate a declared payload digest or compute one to add during rendering.
///
/// Returns the digest to add, and `None` where there is none to add (a declared digest that
/// validates, a segment or truncated record, or a payload this crate does not determine). A
/// malformed HTTP message is an error only when the record declares a payload digest.
pub fn check_payload_digest<E: Extension>(
    record: &Record<E>,
) -> Result<Option<LabelledDigest>, BlockError> {
    let Some(headers) = record.payload() else {
        return Ok(None);
    };
    if record.segment_number().is_some() || record.core().truncated.is_some() {
        return Ok(None);
    }

    let declared = headers.payload_digest.as_ref();
    let payload = match record.payload_bytes() {
        Ok(Some(payload)) => payload,
        Ok(None) | Err(payload::Error::UnsupportedTransferCoding(_)) => return Ok(None),
        Err(error) => {
            return if declared.is_some() {
                Err(error.into())
            } else {
                Ok(None)
            };
        }
    };

    match declared {
        Some(declared) => {
            verify_payload_digest(declared, &payload)?;
            Ok(None)
        }
        None if record.takes_added_payload_digest() => Ok(Some(added_digest(&payload))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{added_digest, sha_1_digest};

    /// The input used by the digest-format tests.
    const CONTENT: &[u8] = b"hello";

    #[test]
    fn adds_a_sha_256_digest_in_lower_case_base16() {
        assert_eq!(
            added_digest(CONTENT).to_string(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn writes_a_sha_1_digest_in_unpadded_upper_case_base32() {
        assert_eq!(
            sha_1_digest(CONTENT).to_string(),
            "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N"
        );
    }
}
