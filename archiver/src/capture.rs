//! Capture outcomes, lifecycle events, and cancellation.
//!
//! One-shot archiving and crawl sessions both report their work in these types.

use archivindex_warc::record::header::truncated_type::TruncatedType;
use chrono::{DateTime, Utc};

use crate::Error;

/// The outcome of an archiving run.
#[derive(Debug, Default)]
pub struct ArchiveSummary {
    /// URLs archived successfully, in request order.
    pub captures: Vec<CaptureSummary>,
    /// URLs that could not be captured.
    pub failures: Vec<Failure>,
    /// Whether an event sink requested a clean stop before all input was dispatched.
    pub cancelled: bool,
}

impl ArchiveSummary {
    /// Whether every URL was captured without cancellation or unexpected truncation.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty() && !self.cancelled && self.partial_captures() == 0
    }

    /// The number of captures cut short by something other than a configured bound.
    #[must_use]
    pub fn partial_captures(&self) -> usize {
        partial_captures(&self.captures)
    }
}

/// The number of captures cut short by something other than a configured bound.
pub(crate) fn partial_captures(captures: &[CaptureSummary]) -> usize {
    captures
        .iter()
        .filter(|capture| capture.is_partial())
        .count()
}

/// Where a requested URL came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Requested for its own sake: a session driver's seed, or a URL given to a one-shot archive
    /// run.
    Seed,
    /// Requested because of another capture.
    Extra {
        /// The URL the request was made via, recorded in the metadata record.
        via: String,
    },
}

impl Origin {
    /// The URL the request was made via, if any.
    #[must_use]
    pub fn via(&self) -> Option<&str> {
        match self {
            Self::Seed => None,
            Self::Extra { via } => Some(via),
        }
    }
}

/// The outcome of capturing one URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureSummary {
    /// The requested URL.
    pub url: String,
    /// Where the URL came from.
    pub origin: Origin,
    /// When capture of the final response began.
    pub date: DateTime<Utc>,
    /// The final response status.
    pub status: u16,
    /// The decoded entity-body length.
    pub size: u64,
    /// The number of redirects followed. Answering a challenge is not a redirect.
    pub redirects: usize,
    /// Why the final response was cut short, if it was.
    ///
    /// A capture retried as many times as the policy allows and still cut short is recorded with
    /// the reason its last attempt gave.
    pub truncated: Option<TruncatedType>,
}

impl CaptureSummary {
    /// Whether the response was cut short by something other than a configured bound.
    ///
    /// Reaching the configured length limit is expected. A disconnect or timeout means bytes were
    /// lost.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.truncated
            .as_ref()
            .is_some_and(|reason| *reason != TruncatedType::Length)
    }
}

/// A URL that could not be captured.
#[derive(Debug)]
pub struct Failure {
    /// The requested URL.
    pub url: String,
    /// Where the URL came from.
    pub origin: Origin,
    /// The capture failure.
    pub error: Error,
}

/// A live capture lifecycle notification.
#[derive(Clone, Copy, Debug)]
pub enum CaptureEvent<'a> {
    /// A URL capture attempt is starting.
    Started {
        /// Requested URL.
        url: &'a str,
        /// One-based attempt number.
        attempt: usize,
    },
    /// A transient failure will be retried after a delay.
    Retrying {
        /// Requested URL.
        url: &'a str,
        /// One-based number of the upcoming attempt.
        attempt: usize,
        /// Delay before that attempt.
        delay: std::time::Duration,
    },
    /// A URL produced a final HTTP response.
    Captured {
        /// Requested URL.
        url: &'a str,
        /// Final HTTP status.
        status: u16,
    },
    /// A URL could not be captured.
    Failed {
        /// Requested URL.
        url: &'a str,
        /// Final capture error.
        error: &'a Error,
    },
    /// The URL's records were written to the pending collection.
    Written {
        /// Requested URL.
        url: &'a str,
    },
}

/// Decision returned by a [`CaptureEventSink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureControl {
    /// Continue capturing.
    Continue,
    /// Stop dispatching work and finalize what has already completed.
    Cancel,
}

/// An observer that reports progress or requests clean cancellation.
pub trait CaptureEventSink {
    /// Observe one event and decide whether capture should continue.
    fn event(&mut self, event: CaptureEvent<'_>) -> CaptureControl;

    /// Report that a URL capture attempt is starting, returning whether the sink asked to stop.
    fn started(&mut self, url: &str, attempt: usize) -> bool {
        self.event(CaptureEvent::Started { url, attempt }) == CaptureControl::Cancel
    }
}

impl<F> CaptureEventSink for F
where
    F: for<'a> FnMut(CaptureEvent<'a>) -> CaptureControl,
{
    fn event(&mut self, event: CaptureEvent<'_>) -> CaptureControl {
        self(event)
    }
}
