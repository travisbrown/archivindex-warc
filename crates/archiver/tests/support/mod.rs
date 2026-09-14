//! Shared support for integration tests: WARC readback and payload digests.

use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::value::{Algorithm, LabelledDigest};
use sha2::{Digest, Sha256};

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
        let kind = match record.type_name() {
            "warcinfo" => 1,
            "response" => 2,
            "resource" => 3,
            "request" => 4,
            "metadata" => 5,
            "revisit" => 6,
            "conversion" => 7,
            "continuation" => 8,
            other => panic!("unexpected record type: {other}"),
        };
        let target = record
            .target_uri()
            .map_or("", fluent_uri::Uri::as_str)
            .as_bytes();
        let mut bytes = vec![1, kind];
        bytes.extend_from_slice(
            &record
                .core()
                .date
                .date_time()
                .timestamp_millis()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&Sha256::digest(record.body_bytes()));
        bytes.extend_from_slice(&u32::try_from(target.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(target);
        assert_eq!(
            record.core().record_id.as_str(),
            format!(
                "https://archivindex.org/record/{}",
                data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
            )
        );
    }
    Ok(records)
}

/// The labelled SHA-256 digest of a payload, as the archiver records it.
pub fn sha256(payload: &[u8]) -> LabelledDigest {
    LabelledDigest::compute(Algorithm::Sha256, payload).expect("sha256 is enabled")
}
