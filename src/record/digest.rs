//! Digest calculation and validation for record blocks and payloads.

use crate::record::extension::Extension;
use crate::record::{BlockError, Record, payload};
use crate::value::{Algorithm, DigestFormat, LabelledDigest};

/// Compute a digest in the given format.
pub fn added_digest(format: DigestFormat, content: &[u8]) -> LabelledDigest {
    let digest = format
        .algorithm
        .digest(content)
        .expect("invariant violation: added-digest algorithms are checked to be supported");

    LabelledDigest::from_digest_in(format, &digest)
}

/// Add a block digest unless the record already declares one.
pub fn add_block_digest<E: Extension>(record: &mut Record<E>, algorithm: Algorithm) {
    if record.core().block_digest.is_none() {
        let digest = added_digest(algorithm.into(), &record.body_bytes());
        record.core_mut().block_digest = Some(digest);
    }
}

/// Add a payload digest when the record is eligible and declares none.
///
/// Records that would not receive a payload digest during rendering are unchanged.
pub fn add_payload_digest<E: Extension>(record: &mut Record<E>, algorithm: Algorithm) {
    let digest = match record.payload() {
        Some(headers)
            if headers.payload_digest.is_none() && record.takes_added_payload_digest() =>
        {
            match record.payload_bytes() {
                Ok(Some(payload)) => added_digest(algorithm.into(), &payload),
                Ok(None) | Err(_) => return,
            }
        }
        Some(_) | None => return,
    };

    if let Some(headers) = record.payload_mut() {
        headers.payload_digest = Some(digest);
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
/// Digests under disabled algorithms are not checked.
fn compare_digest(declared: &LabelledDigest, content: &[u8]) -> Option<Fault> {
    let algorithm = declared.algorithm()?;
    let digest = algorithm.digest(content)?;

    match declared.decoded() {
        None => Some(Fault::Malformed),
        Some(value) if value != *digest => Some(Fault::Mismatch(LabelledDigest::from_digest(
            algorithm, &digest,
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
/// If absent, compute one in `added` when provided.
pub fn check_block_digest(
    declared: Option<LabelledDigest>,
    block: &[u8],
    added: Option<DigestFormat>,
) -> Result<Option<LabelledDigest>, BlockError> {
    let Some(declared) = declared else {
        return Ok(added.map(|format| added_digest(format, block)));
    };

    verify_block_digest(&declared, block)?;

    Ok(Some(declared))
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
/// Returns a newly computed digest only when the record needs one and `added` supplies a
/// format. A valid declared digest, a segment or truncated record, an undetermined payload, or
/// a `None` format yields `None`. A malformed HTTP message is an error only when a payload
/// digest is declared.
pub fn check_payload_digest<E: Extension>(
    record: &Record<E>,
    added: Option<DigestFormat>,
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
        None if record.takes_added_payload_digest() => {
            Ok(added.map(|format| added_digest(format, &payload)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, added_digest};

    /// The input used by the digest-format tests.
    const CONTENT: &[u8] = b"hello";

    #[test]
    fn adds_a_sha_256_digest_in_lower_case_base16() {
        assert_eq!(
            added_digest(Algorithm::Sha256.into(), CONTENT).to_string(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn adds_a_sha_1_digest_in_unpadded_upper_case_base32() {
        assert_eq!(
            added_digest(Algorithm::Sha1.into(), CONTENT).to_string(),
            "sha1:VL2MMHO4YXUKFWV63YHTWSBM3GXKSQ2N"
        );
    }
}
