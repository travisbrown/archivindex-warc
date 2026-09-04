//! Rules 1 and 2: each record lies in a gzip member of its own, and nothing stands between one
//! record and the next.

use std::io::BufRead;

use archivindex_warc::io::read::Located;
use archivindex_warc::record::Record;

use crate::lint::{Linter, Violation};

/// Where a record sat in the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Framing {
    /// The number of blank lines standing before the record.
    padding: usize,
    /// The gzip members holding the record, for a file the reader places its records in.
    members: Option<Members>,
}

/// The gzip members holding a record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Members {
    /// The position of the record held first by the member the record begins in, which is the
    /// record's own position when the record begins that member.
    first: usize,
    /// The number of members the record's octets lie in.
    count: u64,
}

impl<R: BufRead> Linter<'_, R> {
    /// Where the record just read sat in the file.
    ///
    /// The members are reported only for a file the reader places its records in.
    pub(crate) fn framing<T>(&mut self, located: &Located<T>) -> Framing {
        let index = self.index;
        let members = located.placement().map(|placement| {
            let first = if placement.begins {
                index
            } else {
                self.member_first
            };
            // A record whose octets are split ends the member the record after it begins in.
            if placement.begins || placement.members > 1 {
                self.member_first = index;
            }

            Members {
                first,
                count: placement.members,
            }
        });

        Framing {
            padding: located.blank_lines,
            members,
        }
    }

    /// Check that the record was alone in its gzip member, and that no blank line stood before it.
    pub(crate) fn check_framing(&mut self, index: usize, record: &Record, framing: Framing) {
        if let Some(Members { first, count }) = framing.members {
            if first != index {
                self.fault(index, record, Violation::SharedGzipMember { first });
            }
            if count > 1 {
                self.fault(index, record, Violation::SplitGzipMember { members: count });
            }
        }

        if framing.padding > 0 {
            self.fault(
                index,
                record,
                Violation::BlankLinesBefore {
                    lines: framing.padding,
                },
            );
        }
    }

    /// Report the blank lines the file ends with.
    ///
    /// Padding after a record that failed to read is left unreported, as that record is checked
    /// against no rule.
    pub(crate) fn finish_framing(&mut self) {
        let padding = self.records.end().map_or(0, |end| end.blank_lines);
        if let Some((index, record_id)) = self.last_record.take().filter(|_| padding > 0) {
            self.report(
                index,
                &record_id,
                Violation::TrailingBlankLines { lines: padding },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    /// A compressed file is written one record to a member, which is what the rule asks for.
    #[test]
    fn each_record_lies_in_a_gzip_member_of_its_own() {
        let records = gzip_capture()
            .iter()
            .map(|record| render(std::slice::from_ref(record)))
            .collect::<Vec<_>>();
        let members = records.iter().map(Vec::as_slice).collect::<Vec<_>>();

        assert_eq!(gzip_findings(&members), []);
    }

    /// A file written as one member, as a plain gzip of an uncompressed file is, faults every
    /// record but the one its member holds first.
    #[test]
    fn records_sharing_a_gzip_member_are_reported() {
        let records = gzip_capture();

        assert_eq!(
            gzip_findings(&[&render(&records)]),
            [
                (1, Violation::SharedGzipMember { first: 0 }),
                (2, Violation::SharedGzipMember { first: 0 }),
                (3, Violation::SharedGzipMember { first: 0 }),
            ]
        );
    }

    /// A record whose octets are split is reported, and the record after it still begins a member.
    #[test]
    fn a_record_split_across_gzip_members_is_reported() {
        let records = gzip_capture();
        let warcinfo = render(&records[..1]);
        let request = render(&records[1..2]);
        let (opening, rest) = request.split_at(request.len() / 2);
        let tail = render(&records[2..]);

        assert_eq!(
            gzip_findings(&[&warcinfo, opening, rest, &tail]),
            [
                (1, Violation::SplitGzipMember { members: 2 }),
                (3, Violation::SharedGzipMember { first: 2 }),
            ]
        );
    }

    /// A blank line between records is padding, which faults the record that follows it and
    /// leaves the capture around it intact.
    #[test]
    fn a_blank_line_between_records_faults_the_record_after_it() {
        let records = capture();
        let mut file = render(&records[..2]);
        file.extend_from_slice(b"\r\n");
        file.extend_from_slice(&render(&records[2..]));

        assert_eq!(
            faults(lint_file(&file)),
            vec![(2, Violation::BlankLinesBefore { lines: 1 })]
        );
    }

    /// Padding before the first record faults it as padding anywhere else does.
    #[test]
    fn blank_lines_before_the_first_record_fault_it() {
        let mut file = b"\r\n\r\n".to_vec();
        file.extend_from_slice(&render(&capture()));

        assert_eq!(
            faults(lint_file(&file)),
            vec![(0, Violation::BlankLinesBefore { lines: 2 })]
        );
    }

    /// Padding at the end of the file faults the record it follows.
    #[test]
    fn blank_lines_ending_the_file_fault_the_last_record() {
        let mut file = render(&capture());
        file.extend_from_slice(b"\r\n");

        assert_eq!(
            faults(lint_file(&file)),
            vec![(3, Violation::TrailingBlankLines { lines: 1 })]
        );
    }
}
