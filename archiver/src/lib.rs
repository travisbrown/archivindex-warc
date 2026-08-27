//! Archiving web pages over HTTP into WARC files.
//!
//! This crate provides a small client that captures URLs in WARC files, recording the exact wire
//! bytes of every HTTP request and response, including redirect hops. A response whose payload
//! duplicates an earlier capture is stored as a `revisit` record referencing the original instead
//! of repeating the payload.
//!
//! The client recognizes Sucuri `CloudProxy`, Varnish hexadecimal-prefix, and Simply.com
//! interstitial challenges. It derives answers from the challenge page without executing its
//! script, and bounds proof-of-work searches by an attempt count. Every exchange is recorded;
//! unrecognized challenges are captured unchanged.
//!
//! # Examples
//!
//! ```no_run
//! use archivindex_archiver::{Archiver, Config};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let archiver = Archiver::new(Config::default())?;
//! let summary = archiver.archive_to_path(["https://www.example.com/"], "example.warc")?;
//!
//! assert!(summary.is_complete());
//! # Ok(())
//! # }
//! ```
//!
//! The [`session`] module provides queue-driven crawls. A user-supplied processor can inspect each
//! response, discover URLs, request recaptures, and propose titles for optional metadata. Sessions
//! retry transient network failures, archiving the exchanges of every attempt, and can use a
//! persistent revisit index to deduplicate captures and reuse HTTP validators across runs. A
//! `304 Not Modified` response becomes a `server-not-modified` revisit record.
//!
//! # Modules
//!
//! * [`capture`]: what a capture run reports and observes
//! * [`recorder`]: byte-exact capture of live HTTP exchanges
//! * [`session`]: queue-driven crawl sessions

pub mod capture;
mod client;
pub mod config;
mod http_date;
pub mod recorder;
pub mod session;

#[cfg(test)]
mod strategies;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use archivindex_warc::record::BlockError;
use archivindex_warc::value::Algorithm;
use config::{DigestConfig, DigestFormats, SessionConfig};
use http::header::HeaderMap;

use crate::recorder::Recorder;

/// An HTTP client that captures lists of URLs in WARC files.
///
/// Each URL is fetched synchronously over HTTP/1.1. Redirect hops, wire-format messages, and
/// capture metadata are retained. One-shot lists request every URL unconditionally; only crawl
/// sessions revalidate earlier captures.
#[derive(Clone, Debug)]
pub struct Archiver {
    recorder: Recorder,
    headers: HeaderMap,
    /// Cookies supplied for a host, or learned from a challenge it served.
    ///
    /// Clones of an archiver share one jar, so clearance obtained by one capture thread is used by
    /// the others.
    cookies: Arc<Mutex<client::cookies::CookieJar>>,
    config: Config,
    /// The digest formats the configuration resolves to, checked to be supported by this build.
    digests: DigestFormats,
}

/// Configuration for the archiving client.
///
/// A configuration can be read from and written as a document such as TOML or JSON. Every field
/// is optional, an unknown field is an error, durations are `humantime` strings such as `30s` or
/// `10m`, and a limit that is set by default is lifted by writing `"unbounded"`. The defaults,
/// as TOML, are:
///
/// ```toml
/// user_agent = "archivindex-archiver/0.1.0"  # this crate's name and version
/// timeout = "30s"
/// max_capture_time = "10m"
/// max_redirects = 10
/// gzip_warc = false
/// concurrency = 1
/// max_response_length = 268435456
///
/// [digest]
/// algorithm = "sha256"
///
/// [session]
/// request_delay = "0s"
/// titles = false
///
/// [session.retry]
/// attempts = 3
/// initial_backoff = "1s"
/// max_backoff = "30s"
/// ```
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The `User-Agent` header value sent with every request.
    ///
    /// [`Archiver::new`] rejects values that cannot be used as HTTP field values.
    pub user_agent: String,
    /// The idle timeout, applied to connecting and to each socket read and write.
    ///
    /// A fetch fails when connecting, sending the request, or reading the response header section
    /// times out. A read timing out after the header section instead truncates the response, which
    /// is recorded with a `WARC-Truncated` reason of `time`. Each operation is timed on its own,
    /// so a slow peer that keeps sending never trips it; [`max_capture_time`](Self::max_capture_time)
    /// bounds the whole capture.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// The maximum time spent capturing one URL, when set.
    ///
    /// The time covers every hop of the URL's redirect chain and every challenge answered along
    /// it, but not name resolution, which is not timed. Reaching the limit is reported as a
    /// timeout is: the capture fails when no response header section has been read on the
    /// current hop, and is otherwise truncated with a `WARC-Truncated` reason of `time`. Each
    /// attempt a session makes at a URL is given the whole time. The limit is lifted when unset.
    /// The default is [`Config::DEFAULT_MAX_CAPTURE_TIME`].
    #[serde(with = "config::bounded_duration")]
    pub max_capture_time: Option<Duration>,
    /// The maximum number of redirects followed for each URL.
    ///
    /// Every hop is captured; when a response still redirects after this many follows, it is
    /// recorded as the final response for its URL rather than treated as an error. Answering a
    /// challenge is not a redirect and is bounded separately.
    pub max_redirects: usize,
    /// Whether to gzip the WARC file (as `data.warc.gz`).
    ///
    /// Each record is compressed as an independent gzip member, following the WARC convention, so
    /// that individual records can be decompressed without reading the rest of the file.
    pub gzip_warc: bool,
    /// The number of URLs downloaded concurrently.
    ///
    /// Captures are always written to the archive in input order; raising this only allows up to
    /// this many downloads (each including its full redirect chain) to be in flight at once. At
    /// most twice this many captures are in flight or waiting to be written, so a slow download
    /// holds back a bounded number of finished ones. A value of zero is treated as one.
    pub concurrency: usize,
    /// The maximum number of response bytes stored for one fetch, when set.
    ///
    /// A response reaching the limit is truncated rather than failed: its record holds the bytes
    /// received up to the limit and carries a `WARC-Truncated` reason of `length`. Response size is
    /// unbounded when unset. The default is [`recorder::DEFAULT_MAX_RESPONSE_LENGTH`].
    #[serde(with = "config::bounded_length")]
    pub max_response_length: Option<u64>,
    /// The formats of the digests written for every record.
    ///
    /// [`Archiver::new`] rejects algorithms this build does not enable.
    pub digest: DigestConfig,
    /// The settings crawl sessions start from.
    pub session: SessionConfig,
}

/// An error type for archiving.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The archive could not be written.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An exchange could not be completed.
    #[error(transparent)]
    Fetch(#[from] recorder::Error),
    /// A URL to be archived could not be parsed.
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    /// A URL to be archived contains credentials. The displayed URL has them removed.
    #[error("URL contains credentials: {0}")]
    CredentialedUrl(String),
    /// A URL to be archived does not have a host.
    #[error("URL has no host: {0}")]
    MissingHost(String),
    /// A parsed URL cannot be represented by the HTTP request URI grammar.
    #[error("URL is not a valid URI: {url}")]
    InvalidUri {
        /// The URL as requested.
        url: String,
        /// Where the URL departs from the URI grammar.
        #[source]
        source: http::uri::InvalidUri,
    },
    /// An HTTP response status remained retryable after the configured attempts were exhausted.
    #[error("HTTP status {status} after retries for {url}")]
    HttpStatus {
        /// The URL whose response remained unsuccessful.
        url: String,
        /// The final HTTP response status.
        status: u16,
    },
    /// A capture processor could not complete its traversal.
    #[error("capture processor failed for {url}: {message}")]
    Processor {
        /// The URL being inspected.
        url: String,
        /// The processor's description of the failure.
        message: String,
    },
    /// The configuration cannot be used by an archiver.
    #[error(transparent)]
    InvalidConfig(#[from] ConfigError),
    /// A session identifier is empty or contains a non-URI-unreserved character.
    #[error(transparent)]
    InvalidSessionId(#[from] crate::session::SessionIdError),
    /// The output file name holds a control character, so it cannot be recorded as the
    /// `WARC-Filename` of the `warcinfo` record.
    #[error("output file name cannot be recorded as WARC-Filename")]
    InvalidWarcFilename(#[from] archivindex_warc::value::TextError),
    /// The output file name is not UTF-8, so it cannot be recorded as the `WARC-Filename` of the
    /// `warcinfo` record. The name is displayed with each octet that is not UTF-8 replaced.
    #[error("output file name is not UTF-8: {0:?}")]
    NonUtf8WarcFilename(String),
    /// A revisit index could not be opened.
    #[error(transparent)]
    RevisitIndexOpen(#[from] archivindex_warc_revisit_index::OpenError),
    /// A revisit index could not be queried or updated.
    #[error(transparent)]
    RevisitIndex(#[from] archivindex_warc_revisit_index::Error),
    /// A WARC content block could not be attached to its record.
    #[error(transparent)]
    WarcBlock(#[from] BlockError),
    /// A `warc-fields` value could not be written.
    #[error(transparent)]
    WarcFields(#[from] archivindex_warc::record::fields::Error),
    /// A WARC record could not be rendered.
    #[error(transparent)]
    WarcRender(#[from] archivindex_warc::record::RenderError),
    /// A WARC record could not be written.
    #[error(transparent)]
    WarcWrite(#[from] archivindex_warc::io::write::Error),
}

impl From<archivindex_warc_revisit_index::DatabaseError> for Error {
    fn from(error: archivindex_warc_revisit_index::DatabaseError) -> Self {
        Self::RevisitIndex(error.into())
    }
}

/// A cookie could not be scoped to a host, or sent as an HTTP field value.
///
/// See [`Archiver::cookie_for`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CookieError {
    /// The URL scoping the cookie could not be parsed.
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    /// The URL scoping the cookie carries credentials. The displayed URL has them removed.
    #[error("URL contains credentials: {0}")]
    CredentialedUrl(String),
    /// The URL scoping the cookie has no host, so the cookie could not be restricted to one.
    #[error("URL has no host: {0}")]
    MissingHost(String),
    /// The cookie cannot be sent as an HTTP field value.
    ///
    /// The message says where the offending byte is, not what the value was, since a cookie may
    /// be a credential.
    #[error("invalid Cookie header value: byte {index} of {length} is a control character")]
    InvalidCookie {
        /// The offset of the first control character other than a horizontal tab.
        index: usize,
        /// The length of the value in bytes.
        length: usize,
    },
}

/// The configuration cannot be used by an archiver.
///
/// See [`Archiver::new`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// The configured `User-Agent` cannot be sent or recorded safely.
    #[error(transparent)]
    InvalidUserAgent(#[from] UserAgentError),
    /// A configured digest algorithm is not enabled in this build.
    #[error("digest algorithm {0} is not enabled in this build")]
    UnsupportedDigestAlgorithm(Algorithm),
}

/// The configured `User-Agent` is not a valid HTTP field value.
///
/// Control characters are rejected, apart from the horizontal tab; a carriage return or line feed
/// would end the field early, both in the request and in the `warcinfo` record. Everything else is
/// accepted, including non-ASCII text, which RFC 9110 carries as opaque bytes without giving it a
/// meaning. The error message includes the rejected value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid User-Agent header value: {0:?}")]
pub struct UserAgentError(String);
