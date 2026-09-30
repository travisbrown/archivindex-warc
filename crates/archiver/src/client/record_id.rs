//! Content-derived IDs for records the archiver authors.

use archivindex_warc::record::Record;

use crate::id;

/// Assign an ID before creating links to this record or persisting its revisit target.
pub(super) fn assign_record_id(record: &mut Record) -> std::io::Result<()> {
    let id = id::record_id(record)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

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
        let mut record = response(1234, "https://example.org/a%2Fb?q=1", b"abc");
        assign_record_id(&mut record).unwrap();
        assert_eq!(
            record.core().record_id.as_str(),
            "https://archivindex.org/record/2c0afc3a5dcf2c0f4d6e7081685af87a68ddbb85be536ea508778c01838160b5"
        );
        let id = record.core().record_id.clone();
        assign_record_id(&mut record).unwrap();
        assert_eq!(record.core().record_id, id);
        let mut same = response(1234, "https://example.org/a%2Fb?q=1", b"abc");
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
            "https://archivindex.org/record/cc7ce3429091f77a4d2be6d6cd29504bc1cdb6c59bd9a6b1325ea4e80d88d21a"
        );
    }
}
