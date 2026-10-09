//! WARC lint passes and rules.

mod report;
mod rule;
mod rules;

use std::collections::{HashMap, VecDeque};
use std::io::BufRead;

use archivindex_warc::io::read::{self, UntypedIter, WarcReader};
use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::value::WarcDate;
use fluent_uri::Uri;
pub use report::{Checked, Custom, Finding, Severity, Subject, Violation};
pub use rule::{Findings, Rule};
use rules::capture::Pending;
use rules::framing::Framing;
use rules::header::canonical_order_violation;

/// An iterator over the findings of a lint pass.
///
/// Read errors come through as they are reported by the reader. A stream or framing error ends
/// iteration, as it does for the reader. A record the standard refuses is reported and skipped: it
/// takes a position in the file but is checked against no rule, and a capture waiting on it is
/// forgotten without a finding.
pub struct Linter<'a, R> {
    records: UntypedIter<R>,
    /// Whether the records are read from a gzip stream, which the file is named for.
    gzip: bool,
    /// Whether a UUID is refused as a record identifier.
    require_archivindex_ids: bool,
    /// The rules added to the pass, run after the rules this crate defines.
    rules: Vec<Box<dyn Rule + 'a>>,
    /// The position of the next record read.
    index: usize,
    /// The position of the record the gzip member being read holds first.
    member_first: usize,
    /// The position and identifier of the record read last, if it read.
    last_record: Option<(usize, Uri<String>)>,
    /// Where each identifier the file has used was used first.
    record_ids: HashMap<Uri<String>, usize>,
    /// The position and date of the record read last, if one has.
    previous_date: Option<(usize, WarcDate)>,
    /// The identifier of the most recent `warcinfo` record.
    warcinfo_id: Option<Uri<String>>,
    /// The host of the collection identifier the most recent `warcinfo` record names, if it names a
    /// well-formed one.
    collection_host: Option<String>,
    /// The capture record expected next, if a capture is under way.
    pending: Option<Pending>,
    /// The preceding record, if it broke no rule and the record after it may still fault it.
    clean: Option<Uri<String>>,
    /// Results not yet yielded, since one record can produce several.
    queue: VecDeque<Checked>,
    /// A read error to yield once the results queued before it have been.
    deferred: Option<read::Error>,
    /// Whether the end of the file has been settled.
    finished: bool,
}

impl<'a, R: BufRead> Linter<'a, R> {
    /// Lint the WARC records `reader` reads.
    ///
    /// The gzip framing of the file is checked when the reader places its records, as one made by
    /// [`WarcReader::from_gzip`] does.
    pub fn new(reader: WarcReader<R>) -> Self {
        let records = reader.iter_untyped_records();

        Self {
            gzip: records.is_gzip(),
            records,
            require_archivindex_ids: false,
            rules: Vec::new(),
            index: 0,
            member_first: 0,
            last_record: None,
            record_ids: HashMap::new(),
            previous_date: None,
            warcinfo_id: None,
            collection_host: None,
            pending: None,
            clean: None,
            queue: VecDeque::new(),
            deferred: None,
            finished: false,
        }
    }

    /// Set whether every record identifier must be the one the
    /// [Archivindex identity scheme](archivindex_warc_identifier) derives from its record.
    ///
    /// A pass accepts a UUID URN as well unless this is set.
    #[must_use]
    pub const fn require_archivindex_ids(mut self, require: bool) -> Self {
        self.require_archivindex_ids = require;

        self
    }

    /// Check every record against `rule` as well, after the rules this crate defines.
    ///
    /// A rule added by mutable reference is borrowed for the life of the pass, so one that gathers
    /// a summary beside its findings can be read once the pass is done with.
    #[must_use]
    pub fn with_rule(mut self, rule: impl Rule + 'a) -> Self {
        self.rules.push(Box::new(rule));

        self
    }

    /// The number of records consumed so far, counting unreadable ones.
    ///
    /// After a read error is yielded, the unreadable record's index is one less than this.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.index
    }

    /// Check one record against every rule, in the order the rules are listed, and queue what it
    /// yields.
    fn check(&mut self, record: &Record, order_violation: Option<Violation>, framing: Framing) {
        let index = self.index;
        self.index += 1;

        let mark = self.queue.len();
        let expected = self.settle(record);
        // The preceding record is only clean once this one has failed to fault it.
        self.settle_clean(mark);

        let mark = self.queue.len();
        self.check_framing(index, record, framing);
        self.check_header(index, record, order_violation);
        self.check_block(index, record);
        self.check_digests(index, record);
        self.check_identity(index, record);
        self.check_warcinfo(index, record);
        self.check_capture(index, record, expected);
        self.check_revisit(index, record);
        self.check_rules(index, record);
        self.last_record = Some((index, record.core().record_id.clone()));
        if self.queue.len() == mark {
            self.clean = Some(record.core().record_id.clone());
        }
    }

    /// Run the rules added to the pass over the record at `index`.
    fn check_rules(&mut self, index: usize, record: &Record) {
        for rule in &mut self.rules {
            rule.check(index, record, &mut Findings::new(&mut self.queue));
        }
    }

    /// Queue the held `Ok`, or drop it if a finding was queued past `mark`.
    fn settle_clean(&mut self, mark: usize) {
        if self.queue.len() == mark {
            self.release_clean();
        } else {
            self.clean = None;
        }
    }

    /// Queue the held `Ok`, now that nothing can fault the record it belongs to.
    fn release_clean(&mut self) {
        if let Some(record_id) = self.clean.take() {
            self.queue.push_back(Ok(record_id));
        }
    }

    /// Report a capture left waiting at the end of the file, and the blank lines it ends with.
    ///
    /// The iterator polls the records again once they run out, so this returns without reporting
    /// after the first call: an added rule may report in [`Rule::finish`] whenever it is asked.
    fn finish(&mut self) {
        if std::mem::replace(&mut self.finished, true) {
            return;
        }

        let mark = self.queue.len();
        self.finish_capture();
        self.finish_framing();
        self.settle_clean(mark);
        for rule in &mut self.rules {
            rule.finish(&mut Findings::new(&mut self.queue));
        }
    }

    /// Take a record that cannot be checked out of the file, keeping its position.
    ///
    /// The capture expectation it might have met is forgotten without a finding, so the record
    /// before it can no longer be faulted.
    fn skip(&mut self, error: read::Error) {
        for rule in &mut self.rules {
            rule.skip(self.index);
        }
        self.index += 1;
        self.pending = None;
        self.last_record = None;
        self.release_clean();
        self.deferred = Some(error);
    }

    /// Queue a finding against the record being checked.
    fn fault(&mut self, index: usize, record: &Record, violation: Violation) {
        self.report(index, &record.core().record_id, violation);
    }

    /// Queue a finding against a record by its position and identifier.
    fn report(&mut self, index: usize, record_id: &Uri<String>, violation: Violation) {
        self.queue.push_back(Err(Box::new(Finding {
            subject: Some(Subject {
                index,
                record_id: record_id.clone(),
            }),
            violation,
        })));
    }
}

impl<R: BufRead> Iterator for Linter<'_, R> {
    type Item = Result<Checked, read::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(checked) = self.queue.pop_front() {
                return Some(Ok(checked));
            }
            if let Some(error) = self.deferred.take() {
                return Some(Err(error));
            }

            let Some(located) = self.records.next() else {
                self.finish();
                if self.queue.is_empty() {
                    return None;
                }
                continue;
            };
            let framing = self.framing(&located);
            match located.value {
                Ok(untyped) => {
                    let order_violation = canonical_order_violation(&untyped.header);
                    match Record::<NoExtension>::try_from(untyped) {
                        Ok(record) => self.check(&record, order_violation, framing),
                        Err(error) => self.skip(error.into()),
                    }
                }
                Err(error) => self.skip(error),
            }
        }
    }
}

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;
