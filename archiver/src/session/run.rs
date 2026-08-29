//! The request loop, driver dispatch, and retry policy.

use std::borrow::Cow;
use std::thread;
use std::time::Duration;

use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc_revisit_index::Index as RevisitIndex;

use super::{Capture, Inspection, Request, Session, SessionSummary};
use crate::Error;
use crate::capture::{ArchiveSummary, CaptureControl, CaptureEvent, Origin};
use crate::client::collection::Collection;
use crate::client::notify_outcome;
use crate::client::outcome::{CaptureOutcome, Exchange};

enum AttemptOutcome {
    Finished(CaptureOutcome),
    /// The event sink cancelled the capture, after the exchanges of any completed attempts.
    Cancelled(Vec<Exchange>),
}

enum CrawlOutcome {
    Complete,
    Cancelled,
    Fatal(Error),
}

impl CrawlOutcome {
    fn finish(self, archive: Result<ArchiveSummary, Error>) -> Result<SessionSummary, Error> {
        match (self, archive) {
            (Self::Fatal(error), Err(_)) | (_, Err(error)) => Err(error),
            (outcome, Ok(summary)) => Ok(outcome.into_summary(summary)),
        }
    }

    fn into_summary(self, summary: ArchiveSummary) -> SessionSummary {
        let (seed_captures, extra_captures) = summary
            .captures
            .into_iter()
            .partition(|capture| matches!(capture.origin, Origin::Seed));
        let (fatal_error, cancelled) = match self {
            Self::Complete => (None, false),
            Self::Cancelled => (None, true),
            Self::Fatal(error) => (Some(error), false),
        };

        SessionSummary {
            seed_captures,
            extra_captures,
            failures: summary.failures,
            fatal_error,
            cancelled,
        }
    }
}

impl Session<'_> {
    /// Run the crawl until the driver has nothing left to request and atomically publish its
    /// WARC file.
    pub fn run(mut self) -> Result<SessionSummary, Error> {
        let persistent_index = self
            .revisit_index
            .as_ref()
            .map(RevisitIndex::open)
            .transpose()?;
        let mut collection = self.archiver.session_collection(
            &self.id,
            &self.software,
            self.operator.as_ref(),
            &self.output,
            persistent_index,
        )?;
        let mut capture_count = 0;
        let mut requested = false;

        let crawl_outcome = loop {
            if self.limit.is_some_and(|limit| capture_count >= limit) {
                break CrawlOutcome::Complete;
            }
            let Some(Request { url, origin }) = self.driver.next() else {
                break CrawlOutcome::Complete;
            };
            if requested {
                thread::sleep(self.request_delay);
            }
            requested = true;
            if self
                .events
                .as_mut()
                .is_some_and(|events| events.started(&url, 1))
            {
                break CrawlOutcome::Cancelled;
            }
            let mut outcome = match self.capture_with_retry(&url, &collection) {
                AttemptOutcome::Finished(outcome) => outcome,
                AttemptOutcome::Cancelled(exchanges) => {
                    break match collection.record_abandoned(exchanges, origin.via()) {
                        Ok(()) => CrawlOutcome::Cancelled,
                        Err(error) => CrawlOutcome::Fatal(error),
                    };
                }
            };
            let cancel_after_write = self
                .events
                .as_mut()
                .is_some_and(|events| notify_outcome(events.as_mut(), &url, &outcome));
            let (title, driver_error) = match &outcome {
                CaptureOutcome::Captured { exchanges, .. } => {
                    let inspection = self.inspect(&url, exchanges);
                    if inspection.1.is_none() {
                        capture_count += 1;
                    }
                    inspection
                }
                CaptureOutcome::Failed { error, .. } => {
                    self.driver.failed(&url, error);
                    (None, None)
                }
            };
            let stop_after_write = driver_error.is_some();
            if let Some(error) = driver_error {
                outcome = outcome.fail(error);
            }
            if let Err(error) = collection.record(url.clone(), outcome, origin, title.as_deref()) {
                break CrawlOutcome::Fatal(error);
            }
            if cancel_after_write
                || self.event(CaptureEvent::Written { url: &url }) == CaptureControl::Cancel
            {
                break CrawlOutcome::Cancelled;
            }
            if stop_after_write {
                break CrawlOutcome::Complete;
            }
        };

        crawl_outcome.finish(collection.finish_to_path(&self.output))
    }

    /// Show a successful capture to the driver.
    fn inspect(&mut self, url: &str, exchanges: &[Exchange]) -> (Option<String>, Option<Error>) {
        let last = exchanges
            .last()
            .expect("a capture without an error has at least one exchange");
        let Inspection { title, error } = self.driver.inspect(&Capture {
            url,
            final_url: last.captured.target_uri.as_str(),
            status: last.status,
            payload: last.payload(),
            response: &last.captured.response,
            response_metadata: Cow::Borrowed(&last.captured.response_metadata),
        });

        (
            title,
            error.map(|message| Error::Driver {
                url: url.to_owned(),
                message,
            }),
        )
    }

    /// Capture a URL, revalidating the collection's earlier captures and retrying transient
    /// failures, retryable statuses, and responses cut short by a lost connection or an exceeded
    /// time bound, with exponential backoff.
    ///
    /// The exchanges every attempt completed are returned in order, ahead of the final attempt's,
    /// so that the WARC file holds each retried response.
    fn capture_with_retry(&mut self, url: &str, collection: &Collection) -> AttemptOutcome {
        let attempts = self.retry.attempts.max(1);
        let mut delays = RetryDelays::new(&self.retry);
        let mut earlier = Vec::new();

        for attempt in 0..attempts {
            if attempt > 0
                && self
                    .events
                    .as_mut()
                    .is_some_and(|events| events.started(url, attempt + 1))
            {
                return AttemptOutcome::Cancelled(earlier);
            }
            let last = attempt + 1 == attempts;
            let (exchanges, delay) = match self.archiver.capture(url, Some(collection)) {
                CaptureOutcome::Failed { exchanges, error } if is_transient(&error) && !last => {
                    (exchanges, delays.backoff)
                }
                CaptureOutcome::Failed { exchanges, error } => {
                    return AttemptOutcome::Finished(
                        CaptureOutcome::Failed { exchanges, error }.preceded_by(earlier),
                    );
                }
                CaptureOutcome::Captured {
                    exchanges,
                    redirects,
                } => {
                    let status = exchanges
                        .last()
                        .map(|exchange| exchange.status)
                        .filter(|status| is_retryable_status(*status));
                    if last {
                        return AttemptOutcome::Finished(
                            match status {
                                Some(status) => CaptureOutcome::Failed {
                                    exchanges,
                                    error: Error::HttpStatus {
                                        url: url.to_owned(),
                                        status,
                                    },
                                },
                                // A response cut short is kept, and the summary counts it.
                                None => CaptureOutcome::Captured {
                                    exchanges,
                                    redirects,
                                },
                            }
                            .preceded_by(earlier),
                        );
                    }
                    if status.is_none() && !is_retryable_truncation(&exchanges) {
                        return AttemptOutcome::Finished(
                            CaptureOutcome::Captured {
                                exchanges,
                                redirects,
                            }
                            .preceded_by(earlier),
                        );
                    }
                    let delay = exchanges
                        .last()
                        .map_or_else(|| delays.backoff, |exchange| delays.for_exchange(exchange));
                    (exchanges, delay)
                }
            };
            earlier.extend(exchanges);
            if self.event(CaptureEvent::Retrying {
                url,
                attempt: attempt + 2,
                delay,
            }) == CaptureControl::Cancel
            {
                return AttemptOutcome::Cancelled(earlier);
            }
            thread::sleep(delay);
            delays.advance();
        }

        unreachable!("at least one capture attempt is made")
    }
}

struct RetryDelays {
    backoff: Duration,
    maximum: Duration,
}

impl RetryDelays {
    fn new(config: &crate::session::RetryConfig) -> Self {
        Self {
            backoff: config.initial_backoff.min(config.max_backoff),
            maximum: config.max_backoff,
        }
    }

    fn advance(&mut self) {
        self.backoff = self
            .backoff
            .checked_mul(2)
            .unwrap_or(self.maximum)
            .min(self.maximum);
    }

    fn for_exchange(&self, exchange: &Exchange) -> Duration {
        self.for_retry_after(
            exchange.response_field("retry-after").as_deref(),
            chrono::Utc::now(),
        )
    }

    /// The delay a `Retry-After` value asks for, or the backoff when there is none or it cannot be
    /// read, capped at the maximum.
    fn for_retry_after(&self, value: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> Duration {
        value
            .and_then(|value| parse_retry_after(value, now))
            .unwrap_or(self.backoff)
            .min(self.maximum)
    }
}

const fn is_retryable_status(status: u16) -> bool {
    status == 429 || matches!(status, 500 | 502 | 503 | 504)
}

/// Interpret a `Retry-After` value as a delay.
///
/// RFC 9110 defines the value as a number of seconds or an HTTP-date, and a date that has already
/// passed asks for no delay at all.
fn parse_retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse() {
        return Some(Duration::from_secs(seconds));
    }

    let delay = (crate::http_date::parse(value, now)? - now).to_std();

    Some(delay.unwrap_or(Duration::ZERO))
}

/// Whether a capture was cut short for a reason another attempt could resolve.
///
/// The recorder reports a lost connection or an exceeded time bound as a successful capture of a
/// truncated response, so there is no error to inspect. `length` is a configured bound rather than
/// a failure, so it is never retried.
fn is_retryable_truncation(exchanges: &[Exchange]) -> bool {
    exchanges.last().is_some_and(|exchange| {
        matches!(
            exchange.captured.truncated,
            Some(TruncatedType::Disconnect | TruncatedType::Time)
        )
    })
}

const fn is_transient(error: &Error) -> bool {
    matches!(
        error,
        Error::Fetch(
            crate::recorder::Error::Io(_)
                | crate::recorder::Error::Response(
                    crate::recorder::ResponseError::IncompleteHeaderSection
                )
        )
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::session::RetryConfig;

    #[test]
    fn retry_delays_clamp_initial_values_and_overflowing_growth() {
        let delays = RetryDelays::new(&RetryConfig {
            attempts: 3,
            initial_backoff: Duration::MAX,
            max_backoff: Duration::from_secs(5),
        });
        assert_eq!(delays.backoff, Duration::from_secs(5));

        let mut delays = RetryDelays::new(&RetryConfig {
            attempts: 3,
            initial_backoff: Duration::MAX,
            max_backoff: Duration::MAX,
        });
        delays.advance();
        assert_eq!(delays.backoff, Duration::MAX);
    }

    #[test]
    fn retry_after_accepts_seconds_and_http_dates() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();

        assert_eq!(
            parse_retry_after(" 42 ", now),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            parse_retry_after("Fri, 21 Aug 2026 12:01:00 GMT", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Friday, 21-Aug-26 12:01:00 GMT", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Fri Aug 21 12:01:00 2026", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Fri, 21 Aug 2026 12:01:00 +0000", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Fri, 21 Aug 2026 11:59:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("not a delay", now), None);
    }

    #[test]
    fn a_past_retry_after_date_overrides_the_backoff() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
        let delays = RetryDelays::new(&RetryConfig {
            attempts: 3,
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(60),
        });

        assert_eq!(
            delays.for_retry_after(Some("Fri, 21 Aug 2026 11:59:00 GMT"), now),
            Duration::ZERO
        );
        assert_eq!(
            delays.for_retry_after(Some("not a delay"), now),
            Duration::from_secs(5)
        );
        assert_eq!(delays.for_retry_after(None, now), Duration::from_secs(5));
    }
}
