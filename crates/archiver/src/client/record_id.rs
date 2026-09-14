//! Version 1 content-derived IDs for records authored by the archiver.
//!
//! Integers use big-endian byte order. Timestamps are signed Unix milliseconds; the block
//! digest is SHA-256 of the complete WARC content block, independent of output digest settings.
//! The target URI uses its exact UTF-8 bytes (no normalization), or zero bytes when absent.

use archivindex_warc::record::Record;
use fluent_uri::Uri;
use sha2::{Digest, Sha256};

/// Stable wire IDs. Changing these values requires a new record ID scheme version.
#[derive(Clone, Copy)]
#[repr(u8)]
enum RecordType {
    Warcinfo = 1,
    Response = 2,
    Resource = 3,
    Request = 4,
    Metadata = 5,
    Revisit = 6,
    Conversion = 7,
    Continuation = 8,
}

impl RecordType {
    const fn of(record: &Record) -> Self {
        match record {
            Record::Warcinfo { .. } => Self::Warcinfo,
            Record::Response { .. } => Self::Response,
            Record::Resource { .. } => Self::Resource,
            Record::Request { .. } => Self::Request,
            Record::Metadata { .. } => Self::Metadata,
            Record::Revisit { .. } => Self::Revisit,
            Record::Conversion { .. } => Self::Conversion,
            Record::Continuation { .. } => Self::Continuation,
            Record::Other { header, .. } => match header.extension {},
        }
    }
}

/// Assign an ID before creating links to this record or persisting its revisit target.
pub(super) fn assign_record_id(record: &mut Record) -> std::io::Result<()> {
    let target = record.target_uri().map_or("", Uri::as_str).as_bytes();
    let target_len = u32::try_from(target.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "record target URI exceeds u32 length",
        )
    })?;
    let mut hash = Sha256::new();
    hash.update([1, RecordType::of(record) as u8]);
    hash.update(
        record
            .core()
            .date
            .date_time()
            .timestamp_millis()
            .to_be_bytes(),
    );
    hash.update(Sha256::digest(record.body_bytes()));
    hash.update(target_len.to_be_bytes());
    hash.update(target);
    let id = format!(
        "https://archivindex.org/record/{}",
        data_encoding::HEXLOWER.encode(&hash.finalize())
    );
    record.core_mut().record_id = Uri::parse(id).expect("the record ID is a valid HTTPS URI");
    Ok(())
}

#[cfg(test)]
mod tests {
    use archivindex_warc::value::WarcDate;
    use chrono::DateTime;

    use super::*;

    fn response(timestamp: i64, target: &str, body: &[u8]) -> Record {
        Record::response(
            target,
            WarcDate::from(DateTime::from_timestamp_millis(timestamp).unwrap()),
        )
        .unwrap()
        .body(body.to_vec())
        .unwrap()
    }

    #[test]
    fn fixed_vector_and_repeatability() {
        let mut record = response(-1234, "https://example.org/a%2Fb?q=1", b"abc");
        assign_record_id(&mut record).unwrap();
        assert_eq!(
            record.core().record_id.as_str(),
            "https://archivindex.org/record/11fa44c3340e89aa75361616f12f67fbce02db58ccfdb64671dadf57344690a4"
        );
        let id = record.core().record_id.clone();
        assign_record_id(&mut record).unwrap();
        assert_eq!(record.core().record_id, id);
        let mut same = response(-1234, "https://example.org/a%2Fb?q=1", b"abc");
        assign_record_id(&mut same).unwrap();
        assert_eq!(same.core().record_id, id);
    }

    #[test]
    fn every_identity_field_matters() {
        let mut records = [
            response(1234, "https://example.org/a%2Fb", b"abc"),
            response(1235, "https://example.org/a%2Fb", b"abc"),
            response(1234, "https://example.org/a/b", b"abc"),
            response(1234, "https://example.org/a%2Fb", b"abd"),
            Record::request(
                "https://example.org/a%2Fb",
                WarcDate::from(DateTime::from_timestamp_millis(1234).unwrap()),
            )
            .unwrap()
            .body(b"abc".to_vec())
            .unwrap(),
        ];
        for record in &mut records {
            assign_record_id(record).unwrap();
        }
        for (index, record) in records.iter().enumerate() {
            for other in &records[..index] {
                assert_ne!(record.core().record_id, other.core().record_id);
            }
        }
    }

    #[test]
    fn absent_target_and_empty_block_vector() {
        let mut record = Record::warcinfo(WarcDate::from(DateTime::UNIX_EPOCH)).build();
        if let Record::Warcinfo { body, .. } = &mut record {
            *body = archivindex_warc::record::FieldsBlock::Raw(Vec::new());
        }
        assert!(record.body_bytes().is_empty());
        assign_record_id(&mut record).unwrap();
        assert_eq!(
            record.core().record_id.as_str(),
            "https://archivindex.org/record/a193009eaba158690053ac649ef1c5a3ec65a5323ec767510877606c6747a29d"
        );
    }
}
