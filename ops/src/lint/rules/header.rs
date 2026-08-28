//! Rules 3, 4, and 5: header fields in canonical order, an identifier no earlier record used, and
//! a date no earlier than the record before.

use std::io::BufRead;

use archivindex_warc::parse::untyped;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc::record::Record;

use crate::lint::{Linter, Violation};

/// Report the first adjacent pair whose ranks descend.
pub fn canonical_order_violation(header: &untyped::RecordHeader) -> Option<Violation> {
    header.headers.windows(2).find_map(|pair| {
        let preceding = &pair[0].0;
        let following = &pair[1].0;
        let rank = |field: Option<Field>| field.map_or(usize::MAX, Field::canonical_rank);
        (rank(preceding.field()) > rank(following.field())).then(|| {
            Violation::NonCanonicalHeaderOrder {
                preceding: preceding.name().to_owned(),
                following: following.name().to_owned(),
            }
        })
    })
}

impl<R: BufRead> Linter<R> {
    /// Report `order_violation`, found in the header as read, then check that no earlier record
    /// used this record's identifier and that the record is dated no earlier than the record
    /// before it, remembering both.
    pub(crate) fn check_header(
        &mut self,
        index: usize,
        record: &Record,
        order_violation: Option<Violation>,
    ) {
        if let Some(violation) = order_violation {
            self.fault(index, record, violation);
        }

        let record_id = &record.core().record_id;
        if let Some(&first) = self.record_ids.get(record_id) {
            self.fault(index, record, Violation::DuplicateRecordId { first });
        } else {
            self.record_ids.insert(record_id.clone(), index);
        }

        let date = record.core().date;
        if let Some((preceding, expected)) = self.previous_date
            && date.date_time() < expected.date_time()
        {
            self.fault(
                index,
                record,
                Violation::DateOutOfOrder {
                    preceding,
                    expected,
                    found: date,
                },
            );
        }
        self.previous_date = Some((index, date));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    #[test]
    fn header_fields_are_in_canonical_order() {
        let records = [warcinfo(), resource(OTHER_ID).in_written_order()];

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::NonCanonicalHeaderOrder {
                    preceding: "WARC-Record-ID".to_owned(),
                    following: "WARC-Date".to_owned(),
                }
            )]
        );
    }

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

    /// A record is compared with the one before it, so the record after an early one is in order
    /// even when it is dated before records earlier than that.
    #[test]
    fn records_are_dated_in_order() {
        let mut records = capture();
        records[1] = records[1].clone().set("WARC-Date", "2024-04-01T12:00:01Z");
        records[2] = records[2].clone().set("WARC-Date", "2024-04-01T11:59:59Z");

        assert_eq!(
            findings(&records),
            [(
                2,
                Violation::DateOutOfOrder {
                    preceding: 1,
                    expected: date("2024-04-01T12:00:01Z"),
                    found: date("2024-04-01T11:59:59Z"),
                }
            )]
        );
    }
}
