//! Depth-first crawl sessions written to a single WARC file.
//!
//! A session requests its extras, then its seeds, in the order given, and follows the URLs its
//! processor discovers depth first, in the order the processor returns them. A discovery that
//! repeats a URL already given or discovered is skipped unless deduplication is turned off. A
//! repeated request for a URL whose earlier response carried an `ETag` or `Last-Modified`
//! validator is conditional, so that the server may answer `304 Not Modified` instead of
//! repeating the payload. Sessions retry transient failures, archiving the exchanges of every
//! attempt, and preserve completed work when a later recording failure ends the crawl.

use std::borrow::Cow;
use std::path::PathBuf;
use std::time::Duration;

use crate::capture::{
    CaptureControl, CaptureEvent, CaptureEventSink, CaptureSummary, Failure, Origin,
};
use crate::config::SessionConfig;
use crate::{Archiver, Error};

mod run;

/// A session identifier is empty or contains a character outside the RFC 3986 unreserved set.
///
/// Valid identifiers contain ASCII letters, digits, `-`, `.`, `_`, or `~`, so that the identifier
/// can name the session's WARC file and appear unencoded in that file's `warcinfo` record. The
/// error message includes the rejected identifier.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid session identifier: {0:?}")]
pub struct SessionIdError(String);

pub use crate::config::{Operator, Software};

/// A successfully captured page shown to a [`CaptureProcessor`].
#[derive(Clone, Debug)]
pub struct Capture<'a> {
    /// The URL as requested.
    pub url: &'a str,
    /// The final URL after redirects.
    pub final_url: &'a str,
    /// Where the URL came from.
    pub origin: Origin,
    /// The final HTTP status: `304` when the server revalidated a repeated request instead of
    /// repeating its payload.
    pub status: u16,
    /// The decoded entity body, or stored body bytes when decoding fails. Empty for a revalidated
    /// repeat, whose unchanged payload the earlier capture holds.
    pub payload: &'a [u8],
    /// The complete recorded HTTP response.
    pub response: &'a [u8],
    pub(crate) response_metadata: Cow<'a, archivindex_warc::record::http::ResponseMetadata>,
}

impl<'a> Capture<'a> {
    /// Build a capture from recorded response bytes to drive a [`CaptureProcessor`] outside a
    /// session.
    ///
    /// The status and headers are read from `response`, so a processor is shown exactly what a
    /// session would show it for that recording. Returns `None` if `response` does not begin with
    /// a complete HTTP response head.
    #[must_use]
    pub fn new(
        url: &'a str,
        final_url: &'a str,
        origin: Origin,
        payload: &'a [u8],
        response: &'a [u8],
    ) -> Option<Self> {
        let response_metadata = archivindex_warc::record::http::ResponseMetadata::parse(response)?;

        Some(Self {
            url,
            final_url,
            origin,
            status: response_metadata.status,
            payload,
            response,
            response_metadata: Cow::Owned(response_metadata),
        })
    }

    /// Return the first value of a response header as readable text.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.response_metadata
            .header(name)
            .and_then(|value| std::str::from_utf8(value).ok())
    }
}

/// Discoveries and a page title produced by a processor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Inspection {
    /// URLs to request next, in order, before anything else waiting in the session.
    ///
    /// Each is recorded with the inspected capture's final URL as `via`. A URL already given or
    /// discovered is skipped unless the session repeats discoveries, in which case a repeated
    /// request is conditional on the validators of the URL's earlier response, and a
    /// `304 Not Modified` answer reaches the processor with an empty payload.
    pub links: Vec<String>,
    /// A proposed title, recorded in the capture's metadata record.
    pub title: Option<String>,
    /// A failure that makes the traversal incomplete and stops the session after recording this
    /// capture.
    pub error: Option<String>,
}

impl Inspection {
    /// Stop traversal with a processor error after recording the current capture.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            error: Some(message.into()),
            ..Self::default()
        }
    }
}

/// Inspect successful captures to discover URLs and supply titles.
pub trait CaptureProcessor {
    /// Inspect one successful capture.
    fn inspect(&mut self, capture: &Capture<'_>) -> Inspection;
}

/// Retry policy for transient network failures.
///
/// The exchanges every attempt completes are written to the WARC file, ahead of the final
/// attempt's, and may serve as revisit targets like any other. The final attempt alone determines
/// the capture's summary and what the processor sees. Each earlier attempt's response stays in
/// memory until the URL's capture is written.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct RetryConfig {
    /// Total attempts, including the first. Zero is treated as one.
    pub attempts: usize,
    /// Delay before the first retry.
    #[serde(with = "humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum retry delay.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            attempts: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// The outcome of a session run.
#[derive(Debug, Default)]
pub struct SessionSummary {
    /// Successful seed captures in request order.
    pub seed_captures: Vec<CaptureSummary>,
    /// Successful extra and discovered captures in request order.
    pub extra_captures: Vec<CaptureSummary>,
    /// URLs that exhausted capture attempts.
    pub failures: Vec<Failure>,
    /// The error that ended crawling early, if the partial WARC could still be written.
    pub fatal_error: Option<Error>,
    /// Whether an event sink requested a clean stop.
    pub cancelled: bool,
    /// The URLs still to request when the session stopped, each with its `via`, in the order they
    /// would have been requested. A capture that was cancelled or could not be recorded comes
    /// first.
    ///
    /// A session resumes by passing the pairs with a `via` as its extras and the rest as its
    /// seeds.
    pub unrequested: Vec<(String, Option<String>)>,
}

impl SessionSummary {
    /// Whether the crawl finished without failures, cancellation, or unexpected truncation.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
            && self.fatal_error.is_none()
            && !self.cancelled
            && self.partial_captures() == 0
    }

    /// The number of captures cut short by something other than a configured bound.
    #[must_use]
    pub fn partial_captures(&self) -> usize {
        crate::capture::partial_captures(&self.seed_captures)
            + crate::capture::partial_captures(&self.extra_captures)
    }
}

/// A crawl of extras and seeds whose processor may discover more URLs.
pub struct Session<'a> {
    archiver: Archiver,
    id: String,
    operator: Option<Operator>,
    software: Software,
    seeds: Vec<String>,
    extras: Vec<(String, String)>,
    output: PathBuf,
    processor: Option<Box<dyn CaptureProcessor + 'a>>,
    retry: RetryConfig,
    request_delay: Duration,
    limit: Option<usize>,
    revisit_index: Option<PathBuf>,
    events: Option<Box<dyn CaptureEventSink + 'a>>,
    dedupe_discoveries: bool,
}

impl<'a> Session<'a> {
    /// Create a session, validating its URI-unreserved identifier.
    ///
    /// The software and operator recorded in `warcinfo` start as the archiver's
    /// [`Config`](crate::Config), and the retry policy, request delay, revisit index, and
    /// discovery deduplication as its [`SessionConfig`]; the builder methods override them.
    ///
    /// # Errors
    ///
    /// Returns [`SessionIdError`] if `id` is empty or contains a character outside the URI
    /// unreserved set.
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>, P: Into<PathBuf>>(
        archiver: Archiver,
        id: &str,
        seeds: I,
        output: P,
    ) -> Result<Self, SessionIdError> {
        if id.is_empty()
            || !id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            return Err(SessionIdError(id.to_owned()));
        }

        let SessionConfig {
            retry,
            request_delay,
            revisit_index,
            dedupe_discoveries,
        } = archiver.config.session.clone();
        let software = archiver.config.software.clone();
        let operator = archiver.config.operator.clone();

        Ok(Self {
            archiver,
            id: id.to_owned(),
            operator,
            software,
            seeds: seeds
                .into_iter()
                .map(|seed| seed.as_ref().to_owned())
                .collect(),
            extras: Vec::new(),
            output: output.into(),
            processor: None,
            retry,
            request_delay,
            limit: None,
            revisit_index,
            events: None,
            dedupe_discoveries,
        })
    }

    /// Override the crawling software name and version recorded in `warcinfo`.
    ///
    /// A name or version holding a control character cannot be written as a `warc-fields`
    /// value, so [`run`](Self::run) fails with [`Error::WarcFields`] before creating any output.
    #[must_use]
    pub fn software(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.software = Software {
            name: name.into(),
            version: version.into(),
        };
        self
    }

    /// Override the operator recorded in `warcinfo`, as `name` or `name <email>`.
    ///
    /// A name or email address holding a control character cannot be written as a `warc-fields`
    /// value, so [`run`](Self::run) fails with [`Error::WarcFields`] before creating any output.
    #[must_use]
    pub fn operator(mut self, name: impl Into<String>, email: Option<String>) -> Self {
        self.operator = Some(Operator {
            name: name.into(),
            email,
        });
        self
    }

    /// Request `extras` before the seeds, each as a pair of the URL to capture and the URL it was
    /// discovered on, which is recorded as `via` in its metadata record.
    ///
    /// Extras are requested in the order given, whether or not they repeat each other or a seed,
    /// and their discoveries are followed like a seed's. A session that stopped early resumes
    /// from the [`unrequested`](SessionSummary::unrequested) URLs of its summary.
    #[must_use]
    pub fn extras<I: IntoIterator<Item = (U, V)>, U: AsRef<str>, V: AsRef<str>>(
        mut self,
        extras: I,
    ) -> Self {
        self.extras = extras
            .into_iter()
            .map(|(url, via)| (url.as_ref().to_owned(), via.as_ref().to_owned()))
            .collect();
        self
    }

    /// Set the processor called for every successful capture.
    #[must_use]
    pub fn processor<P: CaptureProcessor + 'a>(mut self, processor: P) -> Self {
        self.processor = Some(Box::new(processor));
        self
    }

    /// Skip a discovered URL that repeats one already given or discovered, or request it again
    /// when `dedupe` is false.
    ///
    /// Seeds and extras are requested as given either way. Without deduplication, a processor
    /// is responsible for ending a crawl of pages that link to each other.
    #[must_use]
    pub const fn dedupe_discoveries(mut self, dedupe: bool) -> Self {
        self.dedupe_discoveries = dedupe;
        self
    }

    /// Observe capture lifecycle events and optionally request clean cancellation.
    #[must_use]
    pub fn events<E: CaptureEventSink + 'a>(mut self, events: E) -> Self {
        self.events = Some(Box::new(events));
        self
    }

    fn event(&mut self, event: CaptureEvent<'_>) -> CaptureControl {
        self.events
            .as_mut()
            .map_or(CaptureControl::Continue, |sink| sink.event(event))
    }

    /// Set the transient-failure retry policy.
    #[must_use]
    pub const fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// Wait for `delay` between successive queued capture requests.
    ///
    /// Retry attempts continue to use [`RetryConfig`]'s backoff instead of this delay.
    #[must_use]
    pub const fn request_delay(mut self, delay: Duration) -> Self {
        self.request_delay = delay;
        self
    }

    /// Limit successful requested-URL captures; failures do not count toward the limit.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Use the persistent revisit and resource-state database at `path`.
    ///
    /// Existing payload entries make matching responses revisits, and existing resource state
    /// supplies conditional request headers. New records enter a private in-memory overlay during
    /// the crawl, so later captures in the same session can use them. New captures are not added to
    /// the persistent index; the `load-revisit-index` command of `archivindex-warc` adds a
    /// published WARC to it. Without this option, the in-memory index lasts for the run.
    #[must_use]
    pub fn revisit_index(mut self, path: impl Into<PathBuf>) -> Self {
        self.revisit_index = Some(path.into());
        self
    }
}
