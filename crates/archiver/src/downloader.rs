//! The capture backend interface.
//!
//! A [`Downloader`] performs one HTTP exchange and returns its exact bytes. The crate ships one
//! implementation, [`Recorder`], and [`Archiver::with_downloader`](crate::Archiver::with_downloader)
//! accepts any other. Alternative backends exist to change how bytes reach the wire, through a
//! different TLS stack or transport, not to change what is recorded: drive
//! [`ResponseCapture`](crate::recorder::ResponseCapture) so that every backend agrees on framing,
//! truncation, and content.

use std::fmt::Debug;
use std::time::Instant;

use http::{HeaderMap, Method, Uri};

use crate::recorder::{CapturedExchange, Error, Recorder};

/// Performs and records one HTTP exchange.
///
/// Implementations are shared across capture threads, so they must be `Send`, `Sync`, and cheap
/// to clone behind an `Arc`. A capture run holds one for its whole lifetime.
pub trait Downloader: Debug + Send + Sync + 'static {
    /// Perform one exchange, finishing before `deadline` when one is given.
    ///
    /// A deadline that passes before a response header section arrives is an error; one that
    /// passes afterwards truncates the response with a reason of `time`. Report failures that
    /// have no [`Error`] variant of their own as [`Error::Backend`].
    ///
    /// # Errors
    ///
    /// Fails when the target is unusable, the transport fails before a usable response header
    /// section, or the response cannot be framed.
    fn fetch_within(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error>;
}

impl Downloader for Recorder {
    fn fetch_within(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        Self::fetch_within(self, method, target, headers, body, deadline)
    }
}
