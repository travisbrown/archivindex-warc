//! Conditional-request resource state.

use archivindex_http_client::conditional::Variance;
use archivindex_warc::value::{LabelledDigest, WarcDate};
use fluent_uri::Uri;

/// The request identity used for conditional HTTP state.
///
/// A key represents the crawler's canonical GET representation of a target URI. One URI may still
/// have several representations selected by request header fields; [`Variance`] records which
/// fields a stored response declared as selecting, so that state is not reused across variants.
///
/// Requests carrying credentials or cookies are outside this model. A server may return different
/// content to two such requests without declaring anything in `Vary`, so callers that send them
/// must not share one index between identities.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResourceKey {
    target_uri: Uri<String>,
}

impl ResourceKey {
    /// Construct a key for the canonical GET representation of `target_uri`.
    #[must_use]
    pub const fn new(target_uri: Uri<String>) -> Self {
        Self { target_uri }
    }

    /// Return the key's target URI.
    #[must_use]
    pub const fn target_uri(&self) -> &Uri<String> {
        &self.target_uri
    }
}

impl From<Uri<String>> for ResourceKey {
    fn from(target_uri: Uri<String>) -> Self {
        Self::new(target_uri)
    }
}

/// HTTP validators and prior representation identity for one resource key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceState {
    /// The resource/request identity.
    pub key: ResourceKey,
    /// The exact `ETag` field value to use in `If-None-Match`.
    pub etag: Option<String>,
    /// The exact `Last-Modified` field value to use in `If-Modified-Since`.
    pub last_modified: Option<String>,
    /// The prior representation's payload digest, when known, spelled as the record wrote it.
    pub payload_digest: Option<LabelledDigest>,
    /// The prior representation's WARC record identity, when known.
    pub record_id: Option<Uri<String>>,
    /// The prior representation's WARC capture date, when known.
    pub warc_date: Option<WarcDate>,
    /// When this state was most recently observed.
    ///
    /// This is the date of the response or revisit that established or confirmed the state, not
    /// necessarily the date of the canonical payload-bearing record.
    pub observed_at: WarcDate,
    /// Which requests the stored representation was selected by.
    ///
    /// The validators above describe this representation alone, so they may be sent only for a
    /// request [`Variance::matches`] accepts.
    pub variance: Variance,
}

/// A resource-state transition.
///
/// Transitions older than the stored observation are ignored. At equal observation times, the
/// incoming transition is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceStateUpdate {
    /// A successful response carried a representation.
    ///
    /// Validator fields replace the previous representation's validators. In particular, an omitted
    /// validator is cleared rather than incorrectly retained for different bytes.
    Representation {
        /// `ETag`, if present.
        etag: Option<String>,
        /// `Last-Modified`, if present. The HTTP `Date` field is never substituted.
        last_modified: Option<String>,
        /// The representation payload digest, if known.
        payload_digest: Option<LabelledDigest>,
        /// The WARC record representing this capture, if known.
        record_id: Option<Uri<String>>,
        /// The WARC capture date, if known.
        warc_date: Option<WarcDate>,
        /// When this representation was observed.
        observed_at: WarcDate,
        /// Which requests this representation was selected by.
        variance: Variance,
    },
    /// A `304 Not Modified` or `server-not-modified` revisit confirmed the prior representation.
    ///
    /// Present validators replace their stored counterparts; omitted validators and all payload and
    /// WARC identity fields are retained. A supplied variance replaces the previous selection;
    /// omitting it retains the stored variance.
    NotModified {
        /// A replacement `ETag`, if the 304 supplies one.
        etag: Option<String>,
        /// A replacement `Last-Modified`, if the 304 supplies one.
        last_modified: Option<String>,
        /// When the unchanged representation was confirmed.
        observed_at: WarcDate,
        /// The selection declared by a supplied `Vary` field, or `None` if the 304 omitted it.
        ///
        /// `Some(Variance::Invariant)` clears the stored selection for an empty `Vary` value.
        variance: Option<Variance>,
    },
}
