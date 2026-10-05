//! The request loop, driver dispatch, and retry policy.

use std::thread;

use archivindex_http_client::retry::{
    RetryDelays, is_retryable_status, is_retryable_truncation, is_transient,
};
use archivindex_warc_revisit_index::Index as RevisitIndex;

use super::{Capture, Inspection, Request, Session, SessionSummary};
use crate::Error;
use crate::capture::{ArchiveSummary, Origin, ProgressControl, ProgressEvent};
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
    /// Run the crawl until the driver has nothing left to request and atomically publish its WARC
    /// file.
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
            let Some(request) = self.driver.next() else {
                break CrawlOutcome::Complete;
            };
            let Request { url, origin, .. } = &request;
            if requested {
                thread::sleep(self.request_delay);
            }
            requested = true;
            if self
                .progress
                .as_mut()
                .is_some_and(|progress| progress.started(url, 1))
            {
                break CrawlOutcome::Cancelled;
            }
            let mut outcome = match self.capture_with_retry(&request, &collection) {
                AttemptOutcome::Finished(outcome) => outcome,
                AttemptOutcome::Cancelled(exchanges) => {
                    break match collection.record_abandoned(exchanges, origin.via()) {
                        Ok(()) => CrawlOutcome::Cancelled,
                        Err(error) => CrawlOutcome::Fatal(error),
                    };
                }
            };
            let cancel_after_write = self
                .progress
                .as_mut()
                .is_some_and(|progress| notify_outcome(progress.as_mut(), url, &outcome));
            let (title, driver_error) = match &outcome {
                CaptureOutcome::Captured { exchanges, .. } => {
                    let inspection = self.inspect(url, exchanges);
                    if inspection.1.is_none() {
                        capture_count += 1;
                    }
                    inspection
                }
                CaptureOutcome::Failed { error, .. } => {
                    self.driver.failed(url, error);
                    (None, None)
                }
            };
            let stop_after_write = driver_error.is_some();
            if let Some(error) = driver_error {
                outcome = outcome.fail(error);
            }
            match collection.record(url.clone(), outcome, origin.clone(), title.as_deref()) {
                Ok(capture) => self.driver.recorded(capture),
                Err(error) => break CrawlOutcome::Fatal(error),
            }
            if cancel_after_write
                || self.event(ProgressEvent::Written { url }) == ProgressControl::Cancel
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
        let capture = Capture::new(
            url,
            last.captured.target_uri.as_str(),
            last.payload(),
            &last.captured.response,
        )
        .expect("a captured exchange has a complete response head");
        let Inspection { title, error } = self.driver.inspect(&capture);

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
    /// Non-idempotent requests get one attempt because the server may have acted before the
    /// response was lost.
    ///
    /// The exchanges every attempt completed are returned in order, ahead of the final attempt's,
    /// so that the WARC file holds each retried response.
    fn capture_with_retry(&mut self, request: &Request, collection: &Collection) -> AttemptOutcome {
        let url = request.url.as_str();
        let attempts = if request.method.is_idempotent() {
            self.retry.attempts.max(1)
        } else {
            1
        };
        let mut delays = RetryDelays::new(self.retry.initial_backoff, self.retry.max_backoff);
        let mut earlier = Vec::new();

        for attempt in 0..attempts {
            if attempt > 0
                && self
                    .progress
                    .as_mut()
                    .is_some_and(|progress| progress.started(url, attempt + 1))
            {
                return AttemptOutcome::Cancelled(earlier);
            }
            let last = attempt + 1 == attempts;
            let (exchanges, delay) = match self.archiver.capture_request(request, Some(collection))
            {
                CaptureOutcome::Failed { exchanges, error }
                    if matches!(&error, Error::Fetch(source) if is_transient(source)) && !last =>
                {
                    (exchanges, delays.backoff())
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
                    if status.is_none()
                        && !exchanges.last().is_some_and(|exchange| {
                            is_retryable_truncation(exchange.captured.truncated)
                        })
                    {
                        return AttemptOutcome::Finished(
                            CaptureOutcome::Captured {
                                exchanges,
                                redirects,
                            }
                            .preceded_by(earlier),
                        );
                    }
                    let delay = exchanges.last().map_or_else(
                        || delays.backoff(),
                        |exchange| {
                            delays.for_retry_after(
                                exchange.response_field("retry-after").as_deref(),
                                chrono::Utc::now(),
                            )
                        },
                    );
                    (exchanges, delay)
                }
            };
            earlier.extend(exchanges);
            if self.event(ProgressEvent::Retrying {
                url,
                attempt: attempt + 2,
                delay,
            }) == ProgressControl::Cancel
            {
                return AttemptOutcome::Cancelled(earlier);
            }
            thread::sleep(delay);
            delays.advance();
        }

        unreachable!("at least one capture attempt is made")
    }
}
