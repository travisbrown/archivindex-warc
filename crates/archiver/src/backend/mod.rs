//! The capture backend interface and the contract every backend shares.
//!
//! A [`Backend`] performs one HTTP exchange and returns its exact bytes in a
//! [`CapturedExchange`]. The crate ships one implementation,
//! [`Recorder`], and
//! [`Archiver::with_backend`](crate::Archiver::with_backend) accepts any other. Backends exist to
//! change how bytes reach the wire, through a different TLS stack or transport, not to change
//! what is recorded: drive [`ResponseCapture`] so that every backend agrees on framing,
//! truncation, and content.

use std::fmt::Debug;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use archivindex_warc::record::capture::CaptureEvent;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::record::http::ResponseMetadata;
use chrono::{DateTime, Utc};
use fluent_uri::Uri;
use http::{HeaderMap, Method, Uri as HttpUri};

use crate::recorder::Recorder;

pub(crate) mod framing;

pub use framing::{ResponseCapture, ResponseError};

/// The connection and I/O timeout a backend starts from.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The response-size bound a backend starts from, in bytes.
pub const DEFAULT_MAX_RESPONSE_LENGTH: u64 = 256 * 1024 * 1024;

/// Errors returned by a backend while performing a recorded exchange.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A backend failed in a way that has no variant of its own.
    ///
    /// The built-in [`Recorder`] never produces this variant.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The target is not an absolute HTTP or HTTPS URI.
    #[error("the target URI must be absolute, with an `http` or `https` scheme")]
    UnsupportedScheme,
    /// The target names no host.
    #[error("the target URI names no host")]
    MissingHost,
    /// The target cannot be represented as a `WARC-Target-URI`.
    #[error("the target URI is not a URI: {0}")]
    TargetUri(#[from] fluent_uri::ParseError),
    /// The host cannot name a TLS server.
    #[error("the host cannot name a TLS server: {0}")]
    ServerName(#[from] rustls::pki_types::InvalidDnsNameError),
    /// The TLS session could not be created.
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Response framing is malformed.
    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// A recorded exchange and the fields needed to build its capture records.
///
/// [`capture_event`](Self::capture_event) copies the shared fields into a [`CaptureEvent`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedExchange {
    /// Request bytes exactly as written.
    pub request: Vec<u8>,
    /// Response bytes exactly as read, from the final status line through the recorded end.
    pub response: Vec<u8>,
    /// Parsed fields and boundaries of the recorded response.
    pub response_metadata: ResponseMetadata,
    /// The requested URI.
    pub target_uri: Uri<String>,
    /// The origin IP address, when known. Proxied captures omit it because the socket peer is
    /// the proxy and the tunnel does not reliably identify the origin address.
    pub ip_address: Option<IpAddr>,
    /// When network activity began.
    pub date: DateTime<Utc>,
    /// Time from starting network activity to finishing the response.
    pub fetch_time: Duration,
    /// Why the response was truncated, if applicable.
    pub truncated: Option<TruncatedType>,
}

impl CapturedExchange {
    /// Create a capture event with this exchange's shared fields.
    #[must_use]
    pub fn capture_event(&self) -> CaptureEvent {
        let mut event =
            CaptureEvent::new(self.target_uri.clone(), self.date).fetch_time(self.fetch_time);

        if let Some(ip_address) = self.ip_address {
            event = event.ip_address(ip_address);
        }

        match self.truncated.clone() {
            Some(reason) => event.truncated(reason),
            None => event,
        }
    }

    /// Return the response entity-body with transfer coding removed and content coding preserved.
    pub fn entity_body(
        &self,
    ) -> Result<std::borrow::Cow<'_, [u8]>, archivindex_warc::record::payload::Error> {
        archivindex_warc::record::payload::entity_body(&self.response)
    }

    /// Return the recorded bytes after the response header section without transfer decoding.
    #[must_use]
    pub fn stored_body(&self) -> &[u8] {
        &self.response[self.response_metadata.body_offset..]
    }
}

/// Performs and records one HTTP exchange.
///
/// Implementations are shared across capture threads, so they must be `Send`, `Sync`, and cheap
/// to clone behind an `Arc`. A capture run holds one for its whole lifetime.
pub trait Backend: Debug + Send + Sync + 'static {
    /// Perform one exchange, finishing before `deadline` when one is given.
    ///
    /// A deadline that passes before a response header section arrives is an error; one that
    /// passes afterwards truncates the response with a reason of `time`. Report failures that
    /// have no [`Error`] variant of their own as [`Error::Other`].
    ///
    /// # Errors
    ///
    /// Fails when the target is unusable, the transport fails before a usable response header
    /// section, or the response cannot be framed.
    fn fetch_within(
        &self,
        method: &Method,
        target: &HttpUri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error>;
}

impl Backend for Recorder {
    fn fetch_within(
        &self,
        method: &Method,
        target: &HttpUri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        Self::fetch_within(self, method, target, headers, body, deadline)
    }
}
