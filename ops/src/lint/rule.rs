//! Rules added to a lint pass from outside this crate.

use std::collections::VecDeque;

use archivindex_warc::record::Record;
use fluent_uri::Uri;

use super::report::{Checked, Custom, Finding, Subject, Violation};

/// A rule checked over a file alongside the rules this crate defines.
///
/// A pass runs each added rule over every record it reads, after its own rules and in the order
/// the rules were added, and asks each what the end of the file settles. A rule keeps whatever
/// state its checks call for, so a rule that only the whole file settles collects what it needs
/// as the records go by and reports in [`finish`](Rule::finish).
///
/// A rule passed to [`with_rule`](super::Linter::with_rule) by mutable reference is borrowed for
/// the life of the pass, so a rule that gathers a summary beside its findings can be read once
/// the pass is done with.
///
/// # Examples
///
/// ```
/// use archivindex_warc::record::Record;
/// use archivindex_warc_ops::lint::{Custom, Findings, Rule};
///
/// /// Every record of a file should carry a target URI.
/// #[derive(Default)]
/// struct TargetUris {
///     seen: usize,
/// }
///
/// impl Rule for TargetUris {
///     fn check(&mut self, index: usize, record: &Record, findings: &mut Findings<'_>) {
///         if record.target_uri().is_none() {
///             findings.fault(
///                 index,
///                 &record.core().record_id,
///                 Custom::warning("missing_target_uri", "the record carries no target URI"),
///             );
///         } else {
///             self.seen += 1;
///         }
///     }
///
///     fn finish(&mut self, findings: &mut Findings<'_>) {
///         if self.seen == 0 {
///             findings.fault_file(Custom::error("no_target_uris", "no record carries a target URI"));
///         }
///     }
/// }
/// ```
pub trait Rule {
    /// Check the record at `index`, reporting the rules it breaks.
    fn check(&mut self, index: usize, record: &Record, findings: &mut Findings<'_>);

    /// Report what only the end of the file settles.
    ///
    /// These findings follow every record's result, so one against a record already reported
    /// clean leaves that report as it was.
    fn finish(&mut self, findings: &mut Findings<'_>) {
        let _ = findings;
    }

    /// Note the record at `index`, which could not be read and so is checked against no rule.
    fn skip(&mut self, index: usize) {
        let _ = index;
    }
}

impl<R: Rule + ?Sized> Rule for &mut R {
    fn check(&mut self, index: usize, record: &Record, findings: &mut Findings<'_>) {
        (**self).check(index, record, findings);
    }

    fn finish(&mut self, findings: &mut Findings<'_>) {
        (**self).finish(findings);
    }

    fn skip(&mut self, index: usize) {
        (**self).skip(index);
    }
}

/// Where a rule reports what it finds.
///
/// A finding joins the results of the pass in the order it is reported, after the findings the
/// rules this crate defines report about the same record.
pub struct Findings<'a> {
    queue: &'a mut VecDeque<Checked>,
}

impl<'a> Findings<'a> {
    /// Report into the results a pass yields.
    pub(super) const fn new(queue: &'a mut VecDeque<Checked>) -> Self {
        Self { queue }
    }

    /// Report a rule the record at `index` breaks.
    ///
    /// A record any rule faults is not reported clean, whichever record was being checked.
    pub fn fault(&mut self, index: usize, record_id: &Uri<String>, violation: Custom) {
        self.push(
            Some(Subject {
                index,
                record_id: record_id.clone(),
            }),
            violation,
        );
    }

    /// Report a rule the file breaks that no one record accounts for.
    pub fn fault_file(&mut self, violation: Custom) {
        self.push(None, violation);
    }

    /// Queue a finding against a record, or against the file.
    fn push(&mut self, subject: Option<Subject>, violation: Custom) {
        self.queue.push_back(Err(Box::new(Finding {
            subject,
            violation: Violation::Custom(violation),
        })));
    }
}
