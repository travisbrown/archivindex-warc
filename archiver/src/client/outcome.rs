//! HTTP capture, conditional revalidation, and redirect handling.

use std::borrow::Cow;
use std::fmt::Write as _;

use archivindex_warc::record::http::combined_field;
use archivindex_warc::value::marker::Sha256;
use archivindex_warc::value::{LabelledDigest, Supported as _, WarcDate, WarcDatePrecision};
use archivindex_warc_revisit_index::payload::RevisitTarget;
use archivindex_warc_revisit_index::resource::{ResourceKey, ResourceState, declared_vary};
use fluent_uri::Uri;
use http::StatusCode;
use http::header::{COOKIE, HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use url::{Position, Url};

use super::challenge::{self, Challenge};
use super::collection::Collection;
use crate::recorder::CapturedExchange;
use crate::{Archiver, Error};

/// The number of challenges answered for one URL before its response is recorded as it stands.
///
/// A host that challenges every request would otherwise be answered without end.
pub const MAX_CHALLENGE_ANSWERS: usize = 3;

/// Captured exchanges, with any terminal fetch failure represented explicitly.
pub enum CaptureOutcome {
    /// The redirect chain completed.
    Captured {
        /// Every exchange of the chain, in order.
        exchanges: Vec<Exchange>,
        /// The number of redirects followed. Answering a challenge is not a redirect.
        redirects: usize,
    },
    /// Fetching stopped after zero or more recorded exchanges.
    Failed {
        /// Exchanges completed before the failure.
        exchanges: Vec<Exchange>,
        /// The terminal failure.
        error: Error,
    },
}

impl CaptureOutcome {
    pub fn fail(self, error: Error) -> Self {
        match self {
            Self::Captured { exchanges, .. } | Self::Failed { exchanges, .. } => {
                Self::Failed { exchanges, error }
            }
        }
    }

    /// Put the completed exchanges of earlier attempts ahead of this outcome's.
    pub fn preceded_by(self, mut earlier: Vec<Exchange>) -> Self {
        match self {
            Self::Captured {
                exchanges,
                redirects,
            } => {
                earlier.extend(exchanges);
                Self::Captured {
                    exchanges: earlier,
                    redirects,
                }
            }
            Self::Failed { exchanges, error } => {
                earlier.extend(exchanges);
                Self::Failed {
                    exchanges: earlier,
                    error,
                }
            }
        }
    }
}

/// The precision at which `WARC-Date` fields are recorded.
pub const DATE_PRECISION: WarcDatePrecision = WarcDatePrecision::Fraction(6);

/// A single captured exchange not yet written.
pub struct Exchange {
    /// The capture date at the recorded precision, shared by the WARC records.
    pub date: WarcDate,
    pub status: u16,
    /// The decoded entity body when it differs from the stored body.
    decoded: Option<Vec<u8>>,
    /// The SHA-256 digest of the entity body, absent when transfer decoding fails.
    pub payload_digest: Option<LabelledDigest>,
    /// The earlier capture that this `304 Not Modified` response, answering a conditional request,
    /// confirms unchanged.
    pub revalidated: Option<RevisitTarget>,
    pub captured: CapturedExchange,
}

impl Exchange {
    /// Record a captured exchange, decoding and digesting its entity body once.
    pub fn new(captured: CapturedExchange, revalidated: Option<RevisitTarget>) -> Self {
        let (decoded, payload_digest) = captured.entity_body().map_or((None, None), |payload| {
            let mut hasher = Sha256::hasher();
            hasher.update(&payload);
            let decoded = match payload {
                Cow::Owned(decoded) => Some(decoded),
                // Keep a borrowed body only when it differs from the stored body.
                Cow::Borrowed(body) => {
                    (body.len() != captured.stored_body().len()).then(|| body.to_vec())
                }
            };
            (decoded, Some(hasher.finalize_labelled()))
        });

        Self {
            date: WarcDate::new(captured.date, DATE_PRECISION),
            status: captured.response_metadata.status,
            decoded,
            payload_digest,
            revalidated,
            captured,
        }
    }

    /// The digest of the stored payload this exchange revisits, making its response a `revisit`
    /// record when that payload was captured earlier: the payload a `304 Not Modified` confirmed
    /// unchanged, or this exchange's own payload, which may duplicate an earlier capture's.
    ///
    /// Exchanges without a decodable payload, with an empty payload, or with a truncated response
    /// never revisit by their own payload: the first two save nothing, and a truncated capture's
    /// digest does not describe the complete payload.
    pub fn revisit_key(&self) -> Option<LabelledDigest> {
        self.revalidated
            .as_ref()
            .map(|target| target.payload_digest.clone())
            .or_else(|| {
                self.payload_digest
                    .as_ref()
                    .filter(|_| !self.payload().is_empty() && self.captured.truncated.is_none())
                    .cloned()
            })
    }

    /// The resource key for the recorded target URI.
    pub fn resource_key(&self) -> ResourceKey {
        ResourceKey::new(self.captured.target_uri.clone())
    }

    /// The response's `Vary` field, with any several lines it was sent as combined.
    ///
    /// Reading it this way rather than through [`response_field`](Self::response_field) keeps every
    /// selecting field the server named; see
    /// [`declared_vary`](archivindex_warc_revisit_index::resource::declared_vary).
    pub fn response_vary(&self) -> Option<String> {
        declared_vary(&self.captured.response_metadata)
    }

    /// Return a readable response field value exactly as received.
    ///
    /// Only the first line is read, which is what a singleton field such as `ETag` requires. A
    /// list-valued field sent as several lines needs [`response_vary`](Self::response_vary)'s
    /// combining instead.
    pub fn response_field(&self, name: &str) -> Option<String> {
        self.captured
            .response_metadata
            .header(name)
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::to_owned)
    }

    /// The entity body, or the stored body when transfer decoding fails.
    pub fn payload(&self) -> &[u8] {
        self.decoded
            .as_deref()
            .unwrap_or_else(|| self.captured.stored_body())
    }

    /// The length of [`payload`](Self::payload).
    pub fn payload_length(&self) -> u64 {
        self.payload().len() as u64
    }
}

/// An earlier complete capture of a URL: the digest identifying its stored payload, and the
/// validators a later request sends to ask the server whether that payload is still current.
#[derive(Clone, Debug)]
pub struct Original {
    target: RevisitTarget,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

/// A request's value for `name`, as the variance model resolves a selecting field.
///
/// A field sent as several lines is combined into one value, as the recorded request resolves it
/// through
/// [`combined_header`](archivindex_warc::record::http::RequestMetadata::combined_header).
/// A field the request does not send, or whose value is not readable as text, is reported absent.
pub fn request_field<'a>(headers: &'a HeaderMap, name: &str) -> Option<Cow<'a, str>> {
    combined_field(headers.get_all(name).iter().map(HeaderValue::as_bytes))
}

/// A request's value for `name`, counting the cookie the jar adds to the configured fields.
///
/// The `Cookie` field is injected per request from the challenge jar, so a response declaring
/// `Vary: Cookie` is selected by a value the configured fields do not hold.
fn sent_field<'a>(
    headers: &'a HeaderMap,
    cookie: Option<&'a HeaderValue>,
    name: &str,
) -> Option<Cow<'a, str>> {
    cookie
        .filter(|_| name.eq_ignore_ascii_case(COOKIE.as_str()))
        .map_or_else(
            || request_field(headers, name),
            |cookie| {
                std::str::from_utf8(cookie.as_bytes())
                    .ok()
                    .map(Cow::Borrowed)
            },
        )
}

impl Original {
    /// Build a conditionally usable original from complete persisted representation state.
    ///
    /// Returns `None` when `request` does not select the representation the state was stored for:
    /// its validators describe other bytes, and a server answering `304 Not Modified` to them
    /// would have the archiver record a revisit of a payload this request never received.
    pub fn from_state(
        state: ResourceState,
        canonical: Option<RevisitTarget>,
        request: &HeaderMap,
        cookie: Option<&HeaderValue>,
    ) -> Option<Self> {
        if !state
            .variance
            .matches(|name| sent_field(request, cookie, name))
        {
            return None;
        }
        let payload_digest = state.payload_digest?;
        let target = match canonical {
            Some(target) => target,
            None => RevisitTarget {
                payload_digest,
                payload_length: None,
                record_id: state.record_id?,
                target_uri: state.key.target_uri().clone(),
                warc_date: state.warc_date?,
            },
        };
        let etag = state
            .etag
            .and_then(|value| HeaderValue::from_str(&value).ok());
        let last_modified = state
            .last_modified
            .and_then(|value| HeaderValue::from_str(&value).ok());

        (etag.is_some() || last_modified.is_some()).then_some(Self {
            target,
            etag,
            last_modified,
        })
    }

    /// The request headers extended with the preconditions under which the server may answer
    /// `304 Not Modified` instead of repeating the payload.
    fn conditional_headers(&self, headers: &HeaderMap) -> HeaderMap {
        let mut headers = headers.clone();
        if let Some(etag) = &self.etag {
            headers.insert(IF_NONE_MATCH, etag.clone());
        }
        if let Some(last_modified) = &self.last_modified {
            headers.insert(IF_MODIFIED_SINCE, last_modified.clone());
        }
        headers
    }
}

impl Archiver {
    /// Fetch a URL and every hop of its redirect chain, in order.
    ///
    /// Given a collection, a hop whose URL it already holds a complete capture of is requested
    /// conditionally on that capture's validators, so that the server may answer `304 Not
    /// Modified`, which the collection then stores as a revisit of the earlier capture.
    ///
    /// Redirects are followed up to the configured maximum and challenges are answered up to
    /// [`MAX_CHALLENGE_ANSWERS`], each counted on its own, so that answering a challenge does not
    /// spend the redirect budget.
    pub(crate) fn capture(&self, url: &str, revalidate: Option<&Collection>) -> CaptureOutcome {
        let mut exchanges = Vec::new();
        let mut redirects = 0;
        let mut answered = 0;
        let mut current = match Url::parse(url) {
            Ok(url) => url,
            Err(error) => {
                return CaptureOutcome::Failed {
                    exchanges,
                    error: error.into(),
                };
            }
        };

        loop {
            let (exchange, follow_up) = match self.fetch(&current, revalidate) {
                Ok(fetched) => fetched,
                Err(error) => return CaptureOutcome::Failed { exchanges, error },
            };
            exchanges.push(exchange);

            match follow_up {
                Some(FollowUp::Request(next)) if redirects < self.config.max_redirects => {
                    redirects += 1;
                    current = next;
                }
                Some(FollowUp::Challenge(challenge)) if answered < MAX_CHALLENGE_ANSWERS => {
                    // A challenge is answered by repeating the request that met it.
                    match self.answer(&current, challenge, &mut exchanges) {
                        Ok(true) => answered += 1,
                        Ok(false) => break,
                        Err(error) => return CaptureOutcome::Failed { exchanges, error },
                    }
                }
                Some(FollowUp::Request(_) | FollowUp::Challenge(_)) | None => break,
            }
        }

        CaptureOutcome::Captured {
            exchanges,
            redirects,
        }
    }

    /// Perform one `GET` request and return its recorded exchange and what to request next.
    fn fetch(
        &self,
        url: &Url,
        revalidate: Option<&Collection>,
    ) -> Result<(Exchange, Option<FollowUp>), Error> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::CredentialedUrl(redact_credentials(url)));
        }
        if url.host_str().is_none() {
            return Err(Error::MissingHost(url.to_string()));
        }

        let request_target = request_target(url);
        let target = request_target
            .parse::<http::Uri>()
            .map_err(|source| Error::InvalidUri {
                url: url.to_string(),
                source,
            })?;
        // The cookie is resolved first, since a response may have declared it as selecting.
        let cookie = self.cookie_jar().get(url);
        // The collection keys captures by the recorded target URI, which carries no fragment.
        let original = revalidate
            .map(|collection| {
                let target_uri = Uri::parse(request_target.as_ref())
                    .map_err(crate::recorder::Error::TargetUri)?
                    .to_owned();

                collection.original(target_uri, cookie.as_ref())
            })
            .transpose()?
            .flatten();
        let mut headers = original
            .as_ref()
            .map_or(Cow::Borrowed(&self.headers), |original| {
                Cow::Owned(original.conditional_headers(&self.headers))
            });
        if let Some(cookie) = cookie {
            headers.to_mut().insert(COOKIE, cookie);
        }
        let captured = self
            .recorder
            .fetch(&http::Method::GET, &target, &headers, None)?;
        let status = captured.response_metadata.status;
        let location = captured
            .response_metadata
            .header("location")
            .and_then(|value| std::str::from_utf8(value).ok());
        // A redirect is followed as it stands; only a response that is going nowhere is examined
        // for a challenge, which a host serves in place of the representation asked for.
        let follow_up = next_location(url, status, location).map_or_else(
            || challenge::recognize(&captured, url).map(FollowUp::Challenge),
            |next| Some(FollowUp::Request(next)),
        );
        let revalidated = original
            .filter(|_| status == StatusCode::NOT_MODIFIED.as_u16())
            .map(|original| original.target);

        Ok((Exchange::new(captured, revalidated), follow_up))
    }
}

/// What a captured exchange leaves to be requested next.
enum FollowUp {
    /// A redirect target.
    Request(Url),
    /// A challenge to answer before repeating the request that met it.
    Challenge(Challenge),
}

/// Whether a status redirects to the response's `Location`.
const fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Render an RFC 3986 request target without a fragment.
///
/// Percent-encode the characters the WHATWG serializer leaves bare but RFC 3986 forbids:
/// `|`, `^`, `[`, `]`, `{`, `}`, and `` ` ``.
fn request_target(url: &Url) -> Cow<'_, str> {
    let text = &url[..Position::AfterQuery];
    let path_start = url[..Position::BeforePath].len();
    let needs_encoding =
        |character: char| matches!(character, '|' | '^' | '[' | ']' | '{' | '}' | '`');

    if !text[path_start..].contains(needs_encoding) {
        return Cow::Borrowed(text);
    }

    let mut encoded = String::with_capacity(text.len() + 8);
    encoded.push_str(&text[..path_start]);

    for character in text[path_start..].chars() {
        if needs_encoding(character) {
            // Writing to a `String` cannot fail.
            let _ = write!(encoded, "%{:02X}", u32::from(character));
        } else {
            encoded.push(character);
        }
    }

    Cow::Owned(encoded)
}

/// The redirect target of a response, when present and followable over HTTP.
fn next_location(current: &Url, status: u16, location: Option<&str>) -> Option<Url> {
    if !is_redirect(status) {
        return None;
    }

    let next = current.join(location?).ok()?;
    (matches!(next.scheme(), "http" | "https")
        && next.username().is_empty()
        && next.password().is_none())
    .then_some(next)
}

/// Render a URL with credentials removed so errors are safe to log.
pub fn redact_credentials(url: &Url) -> String {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.to_string()
}

#[cfg(test)]
mod tests {
    use http::header::{ACCEPT_LANGUAGE, USER_AGENT};
    use proptest::prelude::*;

    use super::*;
    use crate::strategies;

    #[test_strategy::proptest]
    fn request_targets_are_uris_without_a_fragment(#[strategy(strategies::url())] url: Url) {
        let target = request_target(&url);

        let path_start = url[..Position::BeforePath].len();
        let forbidden = target[path_start..].contains(['|', '^', '[', ']', '{', '}', '`']);

        prop_assert!(Uri::parse(target.as_ref()).is_ok());
        prop_assert!(!target.contains('#'));
        prop_assert!(!forbidden);
    }

    #[test_strategy::proptest]
    fn redacted_urls_keep_no_credentials(#[strategy(strategies::url())] url: Url) {
        let redacted = redact_credentials(&url);
        let parsed = Url::parse(&redacted).unwrap();

        prop_assert!(parsed.username().is_empty());
        prop_assert_eq!(parsed.password(), None);
        prop_assert!(!redacted.contains("s3cret-token"));
    }

    #[test]
    fn request_targets_are_valid_uris() {
        let url = Url::parse("http://example.com/a|b^c[d]?x={y}`z#frag").expect("valid URL");
        let target = request_target(&url);
        assert_eq!(target, "http://example.com/a%7Cb%5Ec%5Bd%5D?x=%7By%7D%60z");
        assert!(Uri::parse(target.as_ref()).is_ok());
    }

    /// A selecting field sent as several lines resolves to their combined value, and the jar's
    /// cookie stands in for a configured one.
    #[test]
    fn request_fields_resolve_as_combined_values() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT_LANGUAGE, HeaderValue::from_static("en"));
        headers.append(ACCEPT_LANGUAGE, HeaderValue::from_static("de"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Bot/1.0"));
        headers.insert(COOKIE, HeaderValue::from_static("configured=1"));
        let cookie = HeaderValue::from_static("session=clearance");

        assert_eq!(
            request_field(&headers, "accept-language"),
            Some(Cow::Owned("en, de".to_owned()))
        );
        assert_eq!(
            request_field(&headers, "user-agent"),
            Some(Cow::Borrowed("Bot/1.0"))
        );
        assert_eq!(request_field(&headers, "accept"), None);
        assert_eq!(
            sent_field(&headers, Some(&cookie), "cookie").as_deref(),
            Some("session=clearance")
        );
        assert_eq!(
            sent_field(&headers, None, "cookie").as_deref(),
            Some("configured=1")
        );
    }

    #[test]
    fn plain_request_targets_are_borrowed() {
        let url = Url::parse("http://example.com/a?b=c#frag").expect("valid URL");
        assert!(matches!(
            request_target(&url),
            Cow::Borrowed("http://example.com/a?b=c")
        ));
    }
}
