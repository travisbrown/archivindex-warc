//! Rule 12: no two records share a `WARC-Record-ID`.

use std::io::BufRead;

use archivindex_warc::record::Record;

use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<R> {
    /// Check that no earlier record used this record's identifier, and remember it.
    pub(crate) fn check_record_id(&mut self, index: usize, record: &Record) {
        let record_id = &record.core().record_id;

        if let Some(&first) = self.record_ids.get(record_id) {
            self.report(index, record_id, Violation::DuplicateRecordId { first });
        } else {
            self.record_ids.insert(record_id.clone(), index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    /// Concatenating a file with itself is what usually repeats an identifier.
    #[test]
    fn no_two_records_share_an_identifier() {
        let mut records = capture();
        records.push(response().set("WARC-Record-ID", &format!("<{REQUEST_ID}>")));
        records.push(metadata().set("WARC-Record-ID", &format!("<{REQUEST_ID}>")));

        assert_eq!(
            findings(&records)
                .into_iter()
                .filter(|(_, violation)| matches!(violation, Violation::DuplicateRecordId { .. }))
                .collect::<Vec<_>>(),
            [
                (4, Violation::DuplicateRecordId { first: 1 }),
                (5, Violation::DuplicateRecordId { first: 1 }),
            ]
        );
    }
}
