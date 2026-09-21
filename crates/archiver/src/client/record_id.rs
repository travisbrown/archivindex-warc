//! Content-derived IDs for records the archiver authors.

use archivindex_warc::record::Record;

use crate::id::Identity;

/// Assign an ID before creating links to this record or persisting its revisit target.
pub(super) fn assign_record_id(record: &mut Record) -> std::io::Result<()> {
    let id = Identity::from_record(record)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .record_id();

    record.core_mut().record_id = id;

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

    /// The ID a typed record receives is the one the scheme's own vector fixes, so the properties
    /// read from the record reach the hash in the order and spelling the scheme defines.
    #[test]
    fn fixed_vector_and_repeatability() {
        let mut record = response(-1234, "https://example.org/a%2Fb?q=1", b"abc");
        assign_record_id(&mut record).unwrap();
        assert_eq!(
            record.core().record_id.as_str(),
            "https://archivindex.org/record/c70e0fa2a227bc36cbdb869f44904ad134ded72475c117ddf0e2e19fdc822bc7"
        );
        let id = record.core().record_id.clone();
        assign_record_id(&mut record).unwrap();
        assert_eq!(record.core().record_id, id);
        let mut same = response(-1234, "https://example.org/a%2Fb?q=1", b"abc");
        assign_record_id(&mut same).unwrap();
        assert_eq!(same.core().record_id, id);
    }

    /// A warcinfo record has no target URI, so the scheme's absent-target vector applies to it.
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
            "https://archivindex.org/record/1279f996e64d8d1678bf94a32349447c4685351027d9b62d29018b35809ed92f"
        );
    }
}
