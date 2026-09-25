//! The capture backend interface and the contract every backend shares.
//!
//! A [`Backend`] performs one HTTP exchange and returns its stored HTTP representation in a
//! [`CapturedExchange`]. The built-in [`Recorder`] captures HTTP/1 bytes exactly. Other backends
//! may reconstruct messages from a framed protocol, provided they declare the original protocol
//! and document the reconstruction. [`ResponseCapture`] defines HTTP/1 framing and truncation for
//! both wire messages and reconstructed streams.

use std::fmt::Debug;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use archivindex_warc::record::capture::CaptureEvent;
use archivindex_warc::record::header::protocol::Protocol;
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
    /// Stored request message, exact for HTTP/1 and reconstructed for framed protocols.
    pub request: Vec<u8>,
    /// Stored response message, from the final status line through the recorded end.
    ///
    /// A framed protocol may be reconstructed as HTTP/1.1; see `response_protocols`.
    pub response: Vec<u8>,
    /// Known original request protocols, emitted as repeated `WARC-Protocol` fields.
    pub request_protocols: Vec<Protocol>,
    /// Known original response protocols, independent of the stored message format.
    pub response_protocols: Vec<Protocol>,
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

        for protocol in &self.request_protocols {
            event = event.request_protocol(protocol.clone());
        }
        for protocol in &self.response_protocols {
            event = event.response_protocol(protocol.clone());
        }
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
