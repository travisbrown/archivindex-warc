//! Shared support for integration tests: WARC readback and payload digests.

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::value::{Algorithm, LabelledDigest};

/// Parse every record of a WARC held in memory, gzip-compressed or plain as its first bytes say.
pub fn records(bytes: &[u8]) -> Result<Vec<Record>, archivindex_warc::io::read::Error> {
    let reader = if bytes.starts_with(&[0x1f, 0x8b]) {
        WarcReader::from_gzip(bytes)
    } else {
        WarcReader::new(bytes)
    };

    reader.iter_records::<NoExtension>().collect()
}

/// The labelled SHA-256 digest of a payload, as the archiver records it.
pub fn sha256(payload: &[u8]) -> LabelledDigest {
    LabelledDigest::compute(Algorithm::Sha256, payload).expect("sha256 is enabled")
}
