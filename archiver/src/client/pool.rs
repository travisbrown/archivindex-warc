//! Bounded concurrent capture scheduling and input-order reassembly.

use std::collections::BTreeMap;
use std::sync::{Mutex, mpsc};
use std::thread;

use super::collection::Collection;
use super::notify_outcome;
use super::outcome::CaptureOutcome;
use crate::capture::{CaptureControl, CaptureEvent, CaptureEventSink, Origin};
use crate::{Archiver, Error};

type IndexedOutcome = (usize, String, CaptureOutcome);

/// Hands URLs to idle workers while the captures not yet recorded stay under a bound.
///
/// Captures are recorded in input order, so a slow one holds back every later one. Without the
/// bound the workers would keep completing captures behind it, each holding its response bodies,
/// until the input ran out.
struct Dispatcher<I> {
    urls: I,
    tasks: mpsc::Sender<(usize, String)>,
    /// Workers waiting for a URL.
    idle: usize,
    /// URLs handed out so far, which is also the index of the next one.
    dispatched: usize,
    /// The most URLs allowed to be dispatched but not yet recorded.
    limit: usize,
    /// The sink asked to stop.
    cancelled: bool,
}

impl<S: AsRef<str>, I: Iterator<Item = S>> Dispatcher<I> {
    /// Dispatch URLs until every worker is busy, the bound is reached, the input runs out, or the
    /// sink cancels.
    fn fill(&mut self, recorded: usize, events: &mut impl CaptureEventSink) {
        while !self.cancelled && self.idle > 0 && self.dispatched - recorded < self.limit {
            let Some(url) = self.urls.next() else { return };
            let url = url.as_ref().to_owned();
            if events.started(&url, 1) {
                self.cancelled = true;
                return;
            }
            let _ = self.tasks.send((self.dispatched, url));
            self.dispatched += 1;
            self.idle -= 1;
        }
    }
}

impl Archiver {
    /// Capture URLs with a pool of worker threads, recording outcomes in input order.
    ///
    /// At most twice `concurrency` captures are in flight or waiting to be recorded at once.
    pub(super) fn capture_concurrently<I: IntoIterator<Item = S>, S: AsRef<str>>(
        &self,
        urls: I,
        concurrency: usize,
        collection: &mut Collection,
        events: &mut impl CaptureEventSink,
    ) -> Result<bool, Error> {
        let (task_sender, task_receiver) = mpsc::channel::<(usize, String)>();
        let task_receiver = Mutex::new(task_receiver);
        let (outcome_sender, outcome_receiver) = mpsc::sync_channel::<IndexedOutcome>(concurrency);
        let mut dispatcher = Dispatcher {
            urls: urls.into_iter(),
            tasks: task_sender,
            idle: concurrency,
            dispatched: 0,
            limit: 2 * concurrency,
            cancelled: false,
        };

        thread::scope(|scope| {
            for _ in 0..concurrency {
                let task_receiver = &task_receiver;
                let outcome_sender = outcome_sender.clone();

                scope.spawn(move || {
                    loop {
                        let task = task_receiver
                            .lock()
                            .ok()
                            .and_then(|receiver| receiver.recv().ok());
                        let Some((index, url)) = task else { return };
                        let outcome = self.capture(&url, None);

                        if outcome_sender.send((index, url, outcome)).is_err() {
                            return;
                        }
                    }
                });
            }

            drop(outcome_sender);
            let mut result = Ok(());
            let mut completed = 0;
            let mut next_to_record = 0;
            let mut pending = BTreeMap::new();
            dispatcher.fill(next_to_record, events);

            while completed < dispatcher.dispatched {
                let (index, url, outcome) = outcome_receiver
                    .recv()
                    .expect("workers always report an outcome before exiting");
                completed += 1;
                dispatcher.idle += 1;

                if result.is_ok() {
                    dispatcher.cancelled |= notify_outcome(events, &url, &outcome);
                    pending.insert(index, (url, outcome));
                    while let Some((url, outcome)) = pending.remove(&next_to_record) {
                        if let Err(error) =
                            collection.record(url.clone(), outcome, Origin::Seed, None, None)
                        {
                            result = Err(error);
                            break;
                        }
                        dispatcher.cancelled |= events.event(CaptureEvent::Written { url: &url })
                            == CaptureControl::Cancel;
                        next_to_record += 1;
                    }
                    if result.is_ok() {
                        dispatcher.fill(next_to_record, events);
                    }
                }
            }

            let cancelled = dispatcher.cancelled;
            // Dropping the task sender releases the workers waiting for a URL.
            drop(dispatcher);
            result.map(|()| cancelled)
        })
    }
}
