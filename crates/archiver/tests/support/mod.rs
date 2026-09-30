//! Shared support for integration tests: WARC readback and payload digests.

use archivindex_archiver::id::{raw_record_id, record_id};
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
        let expected = record_id(record).unwrap();
        assert_eq!(record.core().record_id, expected);
        assert_eq!(
            raw_record_id(&record.clone().into_raw().unwrap()).unwrap(),
            expected
        );
    }
    Ok(records)
}

/// The labelled SHA-256 digest of a payload, as the archiver records it.
pub fn sha256(payload: &[u8]) -> LabelledDigest {
    LabelledDigest::compute(Algorithm::Sha256, payload).expect("sha256 is enabled")
}
