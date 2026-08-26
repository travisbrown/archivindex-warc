//! Conditional-request resource state.

use std::borrow::Cow;

use archivindex_warc::record::http::ResponseMetadata;
use archivindex_warc::value::{LabelledDigest, WarcDate};
use fluent_uri::Uri;

use crate::Error;

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

/// Read the `Vary` field of a recorded response, combining its lines as a recipient does.
///
/// A server may send `Vary` as several field lines, which a recipient combines into one
/// comma-separated value (RFC 9110 section 5.3). Reading only the first line would drop the
/// selecting fields the later lines name, so a request differing in one of them would be taken to
/// select the stored representation and could reuse validators describing other bytes.
///
/// A line that is not readable as text names no field a later request could be matched against, so
/// the value becomes `*`, leaving the representation [`Unselectable`](Variance::Unselectable)
/// rather than silently narrowing what the server declared.
///
/// The result is the `vary` argument of [`Variance::declared`] and
/// [`Variance::declared_without_request`]; `None` means the response declared no `Vary` at all.
#[must_use]
pub fn declared_vary(metadata: &ResponseMetadata) -> Option<String> {
    metadata.headers("vary").next()?;

    Some(
        metadata
            .combined_header("vary")
            .map_or_else(|| Variance::UNSELECTABLE.to_owned(), Cow::into_owned),
    )
}

/// What a stored response declared about the request fields that select its representation.
///
/// HTTP allows one URI to have several representations chosen by request header fields, which a
/// response announces in `Vary`. Stored validators belong to the representation that was actually
/// captured, so a later request may reuse them only when it selects that same representation.
/// Without the check, a crawl configured with a different `User-Agent` could revalidate against
/// another variant's `ETag` and, on a `304 Not Modified`, record a revisit pointing at bytes it
/// never received.
///
/// A response that declares no `Vary` is treated as invariant, as an HTTP cache treats it: a server
/// that varies its representations without saying so is indistinguishable from one that does not
/// vary at all.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Variance {
    /// The response declared no `Vary` field, so every request for the URI selects it.
    #[default]
    Invariant,
    /// The stored representation cannot be selected by request header fields.
    ///
    /// Either the response declared `Vary: *`, or it named selecting fields whose values in the
    /// originating request are unknown. Neither can be matched, so state stored under this
    /// variance is never reused for revalidation.
    Unselectable,
    /// The response named selecting fields, recorded with the originating request's values.
    Selected(SelectingHeaders),
}

impl Variance {
    /// The stored marker for [`Variance::Unselectable`].
    ///
    /// An encoded selection always contains a line feed, so no selection can collide with it.
    const UNSELECTABLE: &'static str = "*";

    /// Record the variance a response declared, resolved against the request that produced it.
    ///
    /// `vary` is the response's `Vary` field value, absent when the response declares none.
    /// `field` returns the request's value for a lowercase field name, or `None` when the request
    /// sent no such field; a field that was not sent is distinct from one sent empty. A field sent
    /// as several lines is resolved as their combined value (RFC 9110 section 5.3), which is what
    /// RFC 9111 section 4.1 compares between requests. That section also permits normalizing white
    /// space and list order. This model compares values as sent, which may prevent reuse but cannot
    /// select the wrong representation.
    ///
    /// A field value containing a line break cannot have come from a real HTTP message, so it
    /// yields [`Variance::Unselectable`] rather than state that could never be matched back.
    #[must_use]
    pub fn declared<V: AsRef<str>>(
        vary: Option<&str>,
        mut field: impl FnMut(&str) -> Option<V>,
    ) -> Self {
        let Some(vary) = vary else {
            return Self::Invariant;
        };
        let mut entries = Vec::new();

        for name in vary.split(',') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if name == Self::UNSELECTABLE {
                return Self::Unselectable;
            }
            let name = name.to_ascii_lowercase();
            let value = field(&name);
            let value = value.as_ref().map(AsRef::as_ref);
            if name.contains(['\r', '\n'])
                || value.is_some_and(|value| value.contains(['\r', '\n']))
            {
                return Self::Unselectable;
            }
            entries.push((name.into_boxed_str(), value.map(Box::from)));
        }

        if entries.is_empty() {
            return Self::Invariant;
        }
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));
        entries.dedup_by(|(left, _), (right, _)| left == right);

        Self::Selected(SelectingHeaders { entries })
    }

    /// Record the variance a response declared when the originating request is unavailable.
    ///
    /// A response naming selecting fields becomes [`Variance::Unselectable`]: with no record of the
    /// request that produced it, there is nothing for a later request to match. State recovered
    /// this way therefore supports revalidation only when its response declared no `Vary`.
    #[must_use]
    pub fn declared_without_request(vary: Option<&str>) -> Self {
        match vary {
            Some(vary) if vary.split(',').any(|name| !name.trim().is_empty()) => Self::Unselectable,
            _ => Self::Invariant,
        }
    }

    /// Whether a request selects the representation this state was stored for.
    ///
    /// Validators must not be sent for a request this returns `false` for: the server would answer
    /// about a representation other than the one the request selects.
    ///
    /// `field` follows the same contract as in [`Variance::declared`].
    #[must_use]
    pub fn matches<V: AsRef<str>>(&self, mut field: impl FnMut(&str) -> Option<V>) -> bool {
        match self {
            Self::Invariant => true,
            Self::Unselectable => false,
            Self::Selected(headers) => headers
                .entries
                .iter()
                .all(|(name, value)| field(name).as_ref().map(AsRef::as_ref) == value.as_deref()),
        }
    }

    /// Encode for storage, as `None` for the invariant case that most responses fall in.
    pub(crate) fn encode(&self) -> Option<String> {
        match self {
            Self::Invariant => None,
            Self::Unselectable => Some(Self::UNSELECTABLE.to_owned()),
            Self::Selected(headers) => {
                let mut encoded = String::new();
                for (name, value) in &headers.entries {
                    encoded.push_str(name);
                    encoded.push('\n');
                    match value {
                        // A field value cannot contain a line feed, so the two are unambiguous.
                        Some(value) => {
                            encoded.push('=');
                            encoded.push_str(value);
                        }
                        None => encoded.push('!'),
                    }
                    encoded.push('\n');
                }
                Some(encoded)
            }
        }
    }

    /// Decode a stored encoding, which only [`Variance::encode`] writes.
    pub(crate) fn decode(stored: Option<String>) -> Result<Self, Error> {
        let Some(stored) = stored else {
            return Ok(Self::Invariant);
        };
        if stored == Self::UNSELECTABLE {
            return Ok(Self::Unselectable);
        }

        let malformed = || Error::MalformedVariance {
            value: stored.clone(),
        };
        let mut entries = Vec::new();
        let mut fields = stored.strip_suffix('\n').unwrap_or(&stored).split('\n');

        while let Some(name) = fields.next() {
            let value = fields.next().ok_or_else(malformed)?;
            let value = if let Some(value) = value.strip_prefix('=') {
                Some(Box::from(value))
            } else if value == "!" {
                None
            } else {
                return Err(malformed());
            };
            if name.is_empty() {
                return Err(malformed());
            }
            entries.push((Box::from(name), value));
        }

        Ok(Self::Selected(SelectingHeaders { entries }))
    }
}

/// The values a request carried for the fields a response named in `Vary`.
///
/// Names are lowercased and sorted, so one selection compares equal to another regardless of the
/// order or case the server wrote its `Vary` field in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectingHeaders {
    entries: Vec<(Box<str>, Option<Box<str>>)>,
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
    /// Validator fields replace the previous representation's validators. In particular, an
    /// omitted validator is cleared rather than incorrectly retained for different bytes.
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
    /// Present validators replace their stored counterparts; omitted validators and all payload
    /// and WARC identity fields are retained. The stored variance is retained too: a `304` answers
    /// for the representation the request already selected.
    NotModified {
        /// A replacement `ETag`, if the 304 supplies one.
        etag: Option<String>,
        /// A replacement `Last-Modified`, if the 304 supplies one.
        last_modified: Option<String>,
        /// When the unchanged representation was confirmed.
        observed_at: WarcDate,
    },
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use archivindex_warc::record::http::{RequestMetadata, ResponseMetadata};

    use super::{Variance, declared_vary};

    /// Parse a 200 response head carrying `fields`, each written as its own line.
    fn response(fields: &[(&str, &str)]) -> ResponseMetadata {
        let mut message = String::from("HTTP/1.1 200 OK\r\n");
        for (name, value) in fields {
            write!(message, "{name}: {value}\r\n").expect("writing to a String cannot fail");
        }
        message.push_str("\r\n");

        ResponseMetadata::parse(message.as_bytes()).expect("a well-formed response head parses")
    }

    /// Resolve field names against a fixed request.
    fn request<'a>(fields: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<&'a str> {
        move |name| {
            fields
                .iter()
                .find(|(field, _)| *field == name)
                .map(|(_, value)| *value)
        }
    }

    #[test]
    fn a_response_without_vary_declares_none() {
        assert_eq!(declared_vary(&response(&[("ETag", "\"v1\"")])), None);
    }

    /// A `Vary` sent as several lines selects on every field it names, not just the first line's.
    #[test]
    fn vary_sent_as_several_lines_is_combined() {
        let metadata = response(&[
            ("Vary", "Accept-Encoding"),
            ("ETag", "\"v1\""),
            ("Vary", "User-Agent"),
        ]);
        let fields = [("accept-encoding", "gzip"), ("user-agent", "Desktop")];

        assert_eq!(
            declared_vary(&metadata).as_deref(),
            Some("Accept-Encoding, User-Agent")
        );
        assert_eq!(
            Variance::declared(declared_vary(&metadata).as_deref(), request(&fields)),
            Variance::declared(Some("Accept-Encoding, User-Agent"), request(&fields))
        );
        assert!(
            !Variance::declared(declared_vary(&metadata).as_deref(), request(&fields)).matches(
                request(&[("accept-encoding", "gzip"), ("user-agent", "Mobile")])
            )
        );
    }

    /// A selecting field sent as several lines is matched as the one value they combine into.
    #[test]
    fn a_selecting_field_sent_as_several_lines_is_matched_as_one_value() {
        let sent = RequestMetadata::parse(
            b"GET / HTTP/1.1\r\nAccept-Language: en\r\nAccept-Language: de\r\n\r\n",
        )
        .expect("a well-formed request head parses");
        let variance =
            Variance::declared(Some("Accept-Language"), |name| sent.combined_header(name));

        assert_eq!(
            variance,
            Variance::declared(
                Some("Accept-Language"),
                request(&[("accept-language", "en, de")])
            )
        );
        assert!(variance.matches(request(&[("accept-language", "en, de")])));
        assert!(!variance.matches(request(&[("accept-language", "en")])));
        assert!(!variance.matches(request(&[("accept-language", "de, en")])));
    }

    /// A `Vary` line that is not text leaves the representation unselectable.
    #[test]
    fn vary_that_is_not_text_is_unselectable() {
        let metadata = ResponseMetadata::parse(b"HTTP/1.1 200 OK\r\nVary: \xff\r\n\r\n")
            .expect("a well-formed response head parses");

        assert_eq!(declared_vary(&metadata).as_deref(), Some("*"));
        assert_eq!(
            Variance::declared(declared_vary(&metadata).as_deref(), request(&[])),
            Variance::Unselectable
        );
    }

    /// A `*` on any line leaves the representation unselectable.
    #[test]
    fn vary_star_on_a_later_line_is_not_lost() {
        let metadata = response(&[("Vary", "Accept-Encoding"), ("Vary", "*")]);

        assert_eq!(
            Variance::declared(declared_vary(&metadata).as_deref(), request(&[])),
            Variance::Unselectable
        );
    }

    /// An empty first line does not hide the fields a later line names.
    #[test]
    fn an_empty_vary_line_does_not_mask_a_later_one() {
        let metadata = response(&[("Vary", ""), ("Vary", "User-Agent")]);

        assert_eq!(declared_vary(&metadata).as_deref(), Some(", User-Agent"));
        assert_eq!(
            Variance::declared_without_request(declared_vary(&metadata).as_deref()),
            Variance::Unselectable
        );
    }

    #[test]
    fn a_response_without_vary_is_invariant() {
        let variance = Variance::declared(None, request(&[("user-agent", "Desktop")]));

        assert_eq!(variance, Variance::Invariant);
        assert!(variance.matches(request(&[("user-agent", "Mobile")])));
    }

    #[test]
    fn a_differing_selecting_field_does_not_match() {
        let variance = Variance::declared(
            Some("User-Agent"),
            request(&[("user-agent", "Desktop"), ("accept", "*/*")]),
        );

        assert!(variance.matches(request(&[("user-agent", "Desktop")])));
        assert!(!variance.matches(request(&[("user-agent", "Mobile")])));
        assert!(!variance.matches(request(&[])));
    }

    #[test]
    fn vary_star_never_matches_even_an_identical_request() {
        let fields = [("user-agent", "Desktop")];
        let variance = Variance::declared(Some("User-Agent, *"), request(&fields));

        assert_eq!(variance, Variance::Unselectable);
        assert!(!variance.matches(request(&fields)));
    }

    #[test]
    fn selecting_fields_are_recorded_independently_of_their_written_form() {
        let fields = [("user-agent", "Desktop"), ("accept-encoding", "gzip")];

        assert_eq!(
            Variance::declared(Some("User-Agent, Accept-Encoding"), request(&fields)),
            Variance::declared(Some("accept-encoding ,USER-AGENT"), request(&fields))
        );
    }

    #[test]
    fn a_response_named_vary_is_unselectable_without_its_request() {
        assert_eq!(
            Variance::declared_without_request(Some("Accept-Encoding")),
            Variance::Unselectable
        );
        assert_eq!(
            Variance::declared_without_request(None),
            Variance::Invariant
        );
    }

    #[test]
    fn variances_round_trip_through_their_encoding() {
        let selected = Variance::declared(
            Some("User-Agent, Accept-Encoding"),
            request(&[("user-agent", "Desktop=!")]),
        );

        for variance in [Variance::Invariant, Variance::Unselectable, selected] {
            assert_eq!(Variance::decode(variance.encode()).ok(), Some(variance));
        }
    }
}
