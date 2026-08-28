//! Rules 16 and 17: a `revisit` record names the record it revisits in all three `WARC-Refers-To`
//! fields, and that record precedes it in the file.

use std::io::BufRead;

use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::Record;
use archivindex_warc::record::header::RevisitHeader;

use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<R> {
    /// Check that a `revisit` record carries every `WARC-Refers-To` field, and that the record
    /// `WARC-Refers-To` names precedes it.
    pub(crate) fn check_revisit(&mut self, index: usize, record: &Record) {
        let Record::Revisit { header, .. } = record else {
            return;
        };
        let record_id = &header.core.record_id;

        let missing = missing_refers_to_fields(header);
        if !missing.is_empty() {
            self.report(
                index,
                record_id,
                Violation::MissingRefersToFields { missing },
            );
        }

        if let Some(refers_to) = &header.refers_to
            && !self.record_ids.contains_key(refers_to)
        {
            self.report(
                index,
                record_id,
                Violation::RefersToUnknownRecord {
                    found: refers_to.clone(),
                },
            );
        }
    }
}

/// The `WARC-Refers-To` fields a `revisit` record lacks, in conventional order.
fn missing_refers_to_fields(header: &RevisitHeader) -> Vec<Field> {
    [
        (Field::RefersTo, header.refers_to.is_none()),
        (
            Field::RefersToTargetURI,
            header.refers_to_target_uri.is_none(),
        ),
        (Field::RefersToDate, header.refers_to_date.is_none()),
    ]
    .into_iter()
    .filter_map(|(field, missing)| missing.then_some(field))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    #[test]
    fn a_revisit_names_its_original_in_every_refers_to_field() {
        let mut records = capture();
        let mut later = copies(&capture()[1..], 1);
        later[1] = revisit_of(later[1].clone(), RESPONSE_ID).without("WARC-Refers-To-Date");
        records.extend(later);
        let mut last = copies(&capture()[1..], 2);
        last[1] = revisit_of(last[1].clone(), RESPONSE_ID)
            .without("WARC-Refers-To")
            .without("WARC-Refers-To-Target-URI")
            .without("WARC-Refers-To-Date");
        records.extend(last);

        assert_eq!(
            findings(&records),
            [
                (
                    5,
                    Violation::MissingRefersToFields {
                        missing: vec![Field::RefersToDate]
                    }
                ),
                (
                    8,
                    Violation::MissingRefersToFields {
                        missing: vec![
                            Field::RefersTo,
                            Field::RefersToTargetURI,
                            Field::RefersToDate
                        ]
                    }
                ),
            ]
        );
    }

    /// A record that follows the revisit is as unknown to it as one outside the file.
    #[test]
    fn a_revisit_refers_to_a_record_that_precedes_it() {
        let mut records = capture();
        let mut later = copies(&capture()[1..], 1);
        later[1] = revisit_of(later[1].clone(), OTHER_ID);
        records.extend(later);
        let mut last = copies(&capture()[1..], 2);
        let following = declared_id(&last[2]);
        last[1] = revisit_of(last[1].clone(), &following[1..following.len() - 1]);
        records.extend(last);

        assert_eq!(
            findings(&records),
            [
                (
                    5,
                    Violation::RefersToUnknownRecord {
                        found: uri(OTHER_ID)
                    }
                ),
                (
                    8,
                    Violation::RefersToUnknownRecord {
                        found: uri(&following[1..following.len() - 1])
                    }
                ),
            ]
        );
    }
}
