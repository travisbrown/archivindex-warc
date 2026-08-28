//! Rule 15: records are dated in the order they are written.

use std::io::BufRead;

use archivindex_warc::record::Record;

use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<R> {
    /// Check that the record is dated no earlier than the record before it, and remember its
    /// date.
    pub(crate) fn check_date(&mut self, index: usize, record: &Record) {
        let date = record.core().date;

        if let Some((preceding, expected)) = self.previous_date
            && date.date_time() < expected.date_time()
        {
            self.report(
                index,
                &record.core().record_id,
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
