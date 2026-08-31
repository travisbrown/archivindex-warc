//! Rules 16, 17, and 18: a `revisit` record declares the truncation its block is, names the record
//! it revisits in all three `WARC-Refers-To` fields, and revisits a record that precedes it.

use std::io::BufRead;

use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::Record;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::record::header::{RevisitHeader, RevisitProfile};

use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<'_, R> {
    /// Check that a `revisit` record declares the truncation its block is, carries every
    /// `WARC-Refers-To` field, and names in `WARC-Refers-To` a record that precedes it.
    pub(crate) fn check_revisit(&mut self, index: usize, record: &Record) {
        let Record::Revisit { header, body } = record else {
            return;
        };

        if let Some(length) = undeclared_truncation(header, body) {
            self.fault(
                index,
                record,
                Violation::UndeclaredRevisitTruncation { length },
            );
        }

        let missing = missing_refers_to_fields(header);
        if !missing.is_empty() {
            self.fault(index, record, Violation::MissingRefersToFields { missing });
        }

        if let Some(refers_to) = &header.refers_to
            && !self.record_ids.contains_key(refers_to)
        {
            self.fault(
                index,
                record,
                Violation::RefersToUnknownRecord {
                    found: refers_to.clone(),
                },
            );
        }
    }
}

/// The length of a block a `revisit` record carries without declaring the truncation it is.
///
/// Clause 6.7.2 of the WARC 1.1 standard has a record under the identical payload digest profile
/// carry either no block or the beginning of the response it stands for, declared as
/// `WARC-Truncated: length`. No rule here applies to another profile.
fn undeclared_truncation(header: &RevisitHeader, body: &[u8]) -> Option<u64> {
    (!body.is_empty()
        && header.profile == RevisitProfile::IDENTICAL_PAYLOAD_DIGEST
        && !matches!(header.core.truncated, Some(TruncatedType::Length)))
    .then_some(body.len() as u64)
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

    /// Clause 6.7.2 obliges the writer, so a record that omits the field is read and reported
    /// rather than refused.
    #[test]
    fn a_revisit_declares_the_truncation_its_block_is() {
        let mut records = capture();
        let mut later = copies(&capture()[1..], 1);
        later[1] = revisit_of(later[1].clone(), RESPONSE_ID).set("WARC-Truncated", "time");
        records.extend(later);

        assert_eq!(
            findings(&records),
            [(
                5,
                Violation::UndeclaredRevisitTruncation {
                    length: records[5].body.len() as u64
                }
            )]
        );
    }

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
