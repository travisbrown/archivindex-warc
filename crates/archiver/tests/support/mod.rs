//! Shared support for integration tests: WARC readback and payload digests.

use archivindex_archiver::id::Identity;
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

    let records: Vec<Record> = reader
        .iter_records::<NoExtension>()
        .records()
        .collect::<Result<_, _>>()?;
    for record in &records {
        let expected = Identity::from_record(record).unwrap().record_id();
        assert_eq!(record.core().record_id, expected);
        assert_eq!(
            Identity::from_raw(&record.clone().into_raw().unwrap())
                .unwrap()
                .record_id(),
            expected
        );
    }
    Ok(records)
}

/// The labelled SHA-256 digest of a payload, as the archiver records it.
pub fn sha256(payload: &[u8]) -> LabelledDigest {
    LabelledDigest::compute(Algorithm::Sha256, payload).expect("sha256 is enabled")
}
