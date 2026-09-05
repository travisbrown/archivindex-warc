//! Driver-steered crawl sessions written to a single WARC file.
//!
//! A session asks its [`Driver`] for one URL at a time, requests it, and shows the driver the
//! capture before asking again, so the driver decides what is requested and in what order.
//! [`Crawl`] is a driver that follows the links a [`CaptureProcessor`] discovers depth first. A
//! repeated request for a URL whose earlier response carried an `ETag` or `Last-Modified`
//! validator is conditional, so that the server may answer `304 Not Modified` instead of
//! repeating the payload. Sessions retry transient failures, archiving the exchanges of every
//! attempt, and preserve completed work when a later recording failure ends the crawl.

use std::borrow::Cow;
use std::path::PathBuf;
use std::time::Duration;

use http::{HeaderMap, Method};

use crate::capture::{
    CaptureControl, CaptureEvent, CaptureEventSink, CaptureSummary, Failure, Origin,
};
use crate::config::SessionConfig;
use crate::{Archiver, Error};

mod crawl;
mod run;

pub use crawl::Crawl;

/// A session identifier is empty or contains a character outside the RFC 3986 unreserved set.
///
/// Valid identifiers contain ASCII letters, digits, `-`, `.`, `_`, or `~`, so that the identifier
/// can name the session's WARC file and appear unencoded in that file's `warcinfo` record. The
/// error message includes the rejected identifier.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid session identifier: {0:?}")]
pub struct SessionIdError(String);

pub use crate::config::{Operator, Software};

/// A successfully captured page shown to a [`Driver`].
#[derive(Clone, Debug)]
pub struct Capture<'a> {
    /// The URL as requested.
    pub url: &'a str,
    /// The final URL after redirects.
    pub final_url: &'a str,
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
    /// Build a capture from recorded response bytes to show a [`Driver`] outside a session.
    ///
    /// The status and headers are read from `response`, so a driver is shown exactly what a
    /// session would show it for that recording. Returns `None` if `response` does not begin with
    /// a complete HTTP response head.
    #[must_use]
    pub fn new(
        url: &'a str,
        final_url: &'a str,
        payload: &'a [u8],
        response: &'a [u8],
    ) -> Option<Self> {
        let response_metadata = archivindex_warc::record::http::ResponseMetadata::parse(response)?;

        Some(Self {
            url,
            final_url,
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

/// An HTTP request a [`Driver`] asks its session to make.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// The URL to request.
    pub url: String,
    /// Whether the URL is a seed or an extra, and what the extra was requested via.
    pub origin: Origin,
    /// The HTTP method to send.
    pub method: Method,
    /// Header fields added to the archiver's defaults.
    ///
    /// A field here replaces every configured value with the same name.
    pub headers: HeaderMap,
    /// The request body, when one should be sent.
    pub body: Option<Vec<u8>>,
}

impl Request {
    /// A request for a URL's own sake.
    pub fn seed(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            origin: Origin::Seed,
            method: Method::GET,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// A request made because of the capture of `via`, which the metadata record names.
    pub fn extra(url: impl Into<String>, via: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            origin: Origin::Extra { via: via.into() },
            method: Method::GET,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// A seed request that sends `body` with `POST`.
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self::seed(url).with_method(Method::POST).with_body(body)
    }

    /// Set the HTTP method.
    #[must_use]
    pub fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Set request header fields.
    ///
    /// A field here replaces every configured value with the same name.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Set the request body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// A title and verdict a driver gives a capture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Inspection {
    /// A proposed title, recorded in the capture's metadata record.
    pub title: Option<String>,
    /// A failure that makes the traversal incomplete and stops the session after recording this
    /// capture.
    pub error: Option<String>,
}

impl Inspection {
    /// Stop traversal with a driver error after recording the current capture.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            title: None,
            error: Some(message.into()),
        }
    }
}

/// Steer a session by choosing each URL it requests.
///
/// The session calls [`next`](Self::next) whenever it is ready to request a URL, and shows the
/// outcome of that request to [`inspect`](Self::inspect) or [`failed`](Self::failed) before
/// calling `next` again. A driver keeps whatever state it needs to decide the next request:
/// a queue of discovered links, a pagination cursor, or the results of earlier captures. A
/// request the session was cancelled before completing is reported to neither method.
///
/// A `&mut D` is itself a driver, so that a driver's state can be read after its session runs.
pub trait Driver {
    /// The next URL to request, or `None` when the traversal is complete.
    fn next(&mut self) -> Option<Request>;

    /// Inspect the successful capture of the request last returned by [`next`](Self::next).
    ///
    /// A repeated request the server answered with `304 Not Modified` arrives with an empty
    /// payload, since the earlier capture holds its unchanged payload.
    fn inspect(&mut self, capture: &Capture<'_>) -> Inspection;

    /// Acknowledge recording the request last returned by [`next`](Self::next).
    ///
    /// Called after inspection (or failure) and successful recording, before any `Written`
    /// event or next request, even when cancellation was requested after capture. `Some`
    /// describes the recorded capture, including unexpected truncation via
    /// [`CaptureSummary::is_partial`]. `None` means a capture failure or inspection rejection
    /// was recorded. Cancelled attempts and recording errors receive no acknowledgment.
    ///
    /// Recording does not imply publication: the session can still fail to finalize its
    /// archive. Only a successful [`Session::run`] result confirms publication.
    /// Does nothing by default.
    fn recorded(&mut self, capture: Option<&CaptureSummary>) {
        let _ = capture;
    }

    /// Note that the request last returned by [`next`](Self::next) exhausted its capture
    /// attempts.
    ///
    /// The session continues with the next request, so a driver waiting on the failed URL must
    /// move on rather than return it again. Does nothing by default.
    fn failed(&mut self, url: &str, error: &Error) {
        let _ = (url, error);
    }
}

impl<D: Driver + ?Sized> Driver for &mut D {
    fn next(&mut self) -> Option<Request> {
        (**self).next()
    }

    fn inspect(&mut self, capture: &Capture<'_>) -> Inspection {
        (**self).inspect(capture)
    }

    fn recorded(&mut self, capture: Option<&CaptureSummary>) {
        (**self).recorded(capture);
    }

    fn failed(&mut self, url: &str, error: &Error) {
        (**self).failed(url, error);
    }
}

/// Links, a title, and a verdict a [`CaptureProcessor`] produces for a capture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Discovery {
    /// URLs to request next, in order, before anything else waiting in the crawl.
    ///
    /// Each is recorded with the inspected capture's final URL as `via`. A URL already given or
    /// discovered is skipped unless the crawl repeats discoveries.
    pub links: Vec<String>,
    /// A proposed title, recorded in the capture's metadata record.
    pub title: Option<String>,
    /// A failure that makes the traversal incomplete and stops the session after recording this
    /// capture. Its links are not followed.
    pub error: Option<String>,
}

impl Discovery {
    /// Stop traversal with a processor error after recording the current capture.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            error: Some(message.into()),
            ..Self::default()
        }
    }
}

/// Inspect the successful captures of a [`Crawl`] to discover URLs and supply titles.
pub trait CaptureProcessor {
    /// Inspect one successful capture.
    fn inspect(&mut self, capture: &Capture<'_>) -> Discovery;
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

/// A crawl of the URLs a [`Driver`] asks for.
pub struct Session<'a> {
    archiver: Archiver,
    id: String,
    operator: Option<Operator>,
    software: Software,
    driver: Box<dyn Driver + 'a>,
    output: PathBuf,
    retry: RetryConfig,
    request_delay: Duration,
    limit: Option<usize>,
    revisit_index: Option<PathBuf>,
    events: Option<Box<dyn CaptureEventSink + 'a>>,
}

impl<'a> Session<'a> {
    /// Create a session, validating its URI-unreserved identifier.
    ///
    /// The software and operator recorded in `warcinfo` start as the archiver's
    /// [`Config`](crate::Config), and the retry policy, request delay, and revisit index as its
    /// [`SessionConfig`]; the builder methods override them.
    ///
    /// # Errors
    ///
    /// Returns [`SessionIdError`] if `id` is empty or contains a character outside the URI
    /// unreserved set.
    pub fn new<D: Driver + 'a, P: Into<PathBuf>>(
        archiver: Archiver,
        id: &str,
        driver: D,
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
        } = archiver.config.session.clone();
        let software = archiver.config.software.clone();
        let operator = archiver.config.operator.clone();

        Ok(Self {
            archiver,
            id: id.to_owned(),
            operator,
            software,
            driver: Box::new(driver),
            output: output.into(),
            retry,
            request_delay,
            limit: None,
            revisit_index,
            events: None,
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

    /// Limit successful captures; failures do not count toward the limit.
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
