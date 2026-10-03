//! HTTP capture, conditional revalidation, and redirect handling.

use std::borrow::Cow;
use std::time::Instant;

use archivindex_http_client::CapturedExchange;
use archivindex_http_client::conditional::{Validators, declared_vary, request_field};
use archivindex_http_client::prepare::{merged_headers, target};
use archivindex_http_client_challenge::{FetchError, Observer, RequestKind};
use archivindex_warc::value::{DigestFormat, LabelledDigest, WarcDate, WarcDatePrecision};
use archivindex_warc_revisit_index::payload::RevisitTarget;
use archivindex_warc_revisit_index::resource::{ResourceKey, ResourceState};
use fluent_uri::Uri;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use super::collection::Collection;
use crate::session::Request;
use crate::{Archiver, Error};

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
    /// The method the request was sent with.
    pub method: Method,
    pub status: u16,
    /// The decoded entity body when it differs from the stored body.
    decoded: Option<Vec<u8>>,
    /// The digest of the entity body in the configured payload format, absent when transfer
    /// decoding fails.
    pub payload_digest: Option<LabelledDigest>,
    /// The earlier capture that this `304 Not Modified` response, answering a conditional request,
    /// confirms unchanged.
    pub revalidated: Option<RevisitTarget>,
    pub captured: CapturedExchange,
}

impl Exchange {
    /// Record a captured exchange, decoding and digesting its entity body once.
    pub fn new(
        captured: CapturedExchange,
        method: &Method,
        revalidated: Option<RevisitTarget>,
        format: DigestFormat,
    ) -> Self {
        let (decoded, payload_digest) = captured.entity_body().map_or((None, None), |payload| {
            let mut hasher = format.algorithm.hasher().expect(
                "invariant violation: the payload digest algorithm is checked when the archiver is created",
            );
            hasher.update(&payload);
            let decoded = match payload {
                Cow::Owned(decoded) => Some(decoded),
                // Keep a borrowed body only when it differs from the stored body.
                Cow::Borrowed(body) => {
                    (body.len() != captured.stored_body().len()).then(|| body.to_vec())
                }
            };
            (decoded, Some(hasher.finalize_labelled_in(format.encoding)))
        });

        Self {
            date: WarcDate::new(captured.date, DATE_PRECISION),
            method: method.clone(),
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

    /// The resource key for the recorded target URI, when the request asked for a shared
    /// representation of it.
    ///
    /// Only `GET` and `HEAD` responses are eligible as conditional-request state. Other methods may
    /// return action results rather than a reusable representation of the URI.
    pub fn resource_key(&self) -> Option<ResourceKey> {
        revalidatable(&self.method).then(|| ResourceKey::new(self.captured.target_uri.clone()))
    }

    /// The response's `Vary` field, with any several lines it was sent as combined.
    ///
    /// Reading it this way rather than through [`response_field`](Self::response_field) keeps every
    /// selecting field the server named; see
    /// [`declared_vary`](archivindex_http_client::conditional::declared_vary).
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
    validators: Validators,
}

/// Whether a method asks for a shared representation of its target, which is the state a collection
/// revalidates against.
const fn revalidatable(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD)
}

impl Original {
    /// Build a conditionally usable original from complete persisted representation state.
    ///
    /// Returns `None` when `request` does not select the representation the state was stored for:
    /// its validators describe other bytes, and a server answering `304 Not Modified` to them would
    /// have the archiver record a revisit of a payload this request never received.
    ///
    /// `request` holds every field the request will send, the resolved `Cookie` included, so a
    /// field sent as several lines is selected by their combined value, as the recorded request
    /// resolves it.
    pub fn from_state(
        state: ResourceState,
        canonical: Option<RevisitTarget>,
        request: &HeaderMap,
    ) -> Option<Self> {
        if !state.variance.matches(|name| request_field(request, name)) {
            return None;
        }
        let payload_digest = state.payload_digest?;
        let target = match canonical {
            Some(target) => target,
            None => RevisitTarget {
                payload_digest,
                payload_length: None,
                identified_payload_type: None,
                record_id: state.record_id?,
                target_uri: state.key.target_uri().clone(),
                warc_date: state.warc_date?,
            },
        };
        let validators = Validators::new(state.etag.as_deref(), state.last_modified.as_deref())?;
        Some(Self { target, validators })
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
    /// [`archivindex_http_client_challenge::MAX_CHALLENGE_ANSWERS`], each counted on its own, so
    /// answering a challenge does not spend the redirect budget. The whole chain shares the
    /// configured capture time.
    pub(crate) fn capture(&self, url: &str, revalidate: Option<&Collection>) -> CaptureOutcome {
        self.capture_parts(url, &Method::GET, &HeaderMap::new(), None, revalidate)
    }

    /// Fetch a driver-supplied request and every redirect or challenge exchange it causes.
    pub(crate) fn capture_request(
        &self,
        request: &Request,
        revalidate: Option<&Collection>,
    ) -> CaptureOutcome {
        self.capture_parts(
            &request.url,
            &request.method,
            &request.headers,
            request.body.as_deref(),
            revalidate,
        )
    }

    fn capture_parts(
        &self,
        url: &str,
        method: &Method,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        revalidate: Option<&Collection>,
    ) -> CaptureOutcome {
        let deadline = self
            .config
            .max_capture_time
            .map(|limit| Instant::now() + limit);
        let prepared = Url::parse(url)
            .map_err(Error::from)
            .and_then(|url| target(&url).map_err(Error::from));
        let target = match prepared {
            Ok(target) => target,
            Err(error) => {
                return CaptureOutcome::Failed {
                    exchanges: Vec::new(),
                    error,
                };
            }
        };
        let headers = merged_headers(&self.headers, headers);
        let mut observer = CaptureObserver {
            collection: revalidate,
            original: None,
            exchanges: Vec::new(),
            format: self.digests.payload,
        };
        let result = self.client.fetch_with(
            archivindex_http_client::Request {
                method,
                target: &target,
                headers: &headers,
                body,
            },
            deadline,
            &mut observer,
        );
        match result {
            Ok(redirects) => CaptureOutcome::Captured {
                exchanges: observer.exchanges,
                redirects,
            },
            Err(error) => CaptureOutcome::Failed {
                exchanges: observer.exchanges,
                error: match error {
                    FetchError::Client(error) => error.into(),
                    FetchError::Observer(error) => error,
                },
            },
        }
    }
}

struct CaptureObserver<'a> {
    collection: Option<&'a Collection>,
    original: Option<Original>,
    exchanges: Vec<Exchange>,
    format: DigestFormat,
}

impl Observer for CaptureObserver<'_> {
    type Error = Error;

    fn prepare(
        &mut self,
        method: &Method,
        target: &http::Uri,
        headers: &mut HeaderMap,
        kind: RequestKind,
    ) -> Result<(), Error> {
        self.original = if kind == RequestKind::Resource && revalidatable(method) {
            self.collection
                .map(|collection| {
                    let target = Uri::parse(target.to_string())
                        .map_err(|(source, _)| archivindex_http_client::Error::TargetUri(source))?;
                    collection.original(target, headers)
                })
                .transpose()?
                .flatten()
        } else {
            None
        };
        if let Some(original) = &self.original {
            original.validators.apply(headers);
        }
        Ok(())
    }

    fn captured(&mut self, captured: CapturedExchange, method: &Method) {
        let revalidated = self
            .original
            .take()
            .filter(|_| captured.response_metadata.status == StatusCode::NOT_MODIFIED.as_u16())
            .map(|original| original.target);
        self.exchanges
            .push(Exchange::new(captured, method, revalidated, self.format));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use archivindex_http_client::prepare::{redact_credentials, target_uri_text};
    use archivindex_test_support::prop;
    use proptest::prelude::*;
    use url::Position;

    use super::*;

    /// An exhausted challenge deadline retains the response and reports failure. A backend's
    /// timed-out partial response is still a successful truncated capture.
    #[test]
    fn expired_challenge_deadlines_preserve_the_exchange() {
        use archivindex_http::message::ResponseMetadata;
        use archivindex_http_client::framing::Truncation;

        #[derive(Debug)]
        struct Canned(CapturedExchange);

        impl archivindex_http_client::Client for Canned {
            fn fetch_within(
                &self,
                _: archivindex_http_client::Request<'_>,
                _: Option<Instant>,
            ) -> Result<CapturedExchange, archivindex_http_client::Error> {
                std::thread::sleep(Duration::from_millis(20));
                Ok(self.0.clone())
            }
        }

        for truncated in [None, Some(Truncation::Time)] {
            let response = b"HTTP/1.1 200 OK\r\n\r\nretained".to_vec();
            let captured = CapturedExchange {
                request: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                response_metadata: ResponseMetadata::parse(&response).unwrap(),
                response,
                fidelity: archivindex_http_client::Fidelity::Exact,
                http_protocol: archivindex_http_client::HttpProtocol::Http1,
                tls_version: None,
                target_uri: Uri::parse("https://example.com/".to_owned()).unwrap(),
                ip_address: None,
                date: chrono::Utc::now(),
                fetch_time: Duration::ZERO,
                truncated,
            };
            let archiver = Archiver::with_backend(
                crate::Config {
                    max_capture_time: Some(Duration::from_millis(10)),
                    ..crate::Config::default()
                },
                Arc::new(Canned(captured.clone())),
            )
            .unwrap();
            let outcome = archiver.capture("https://example.com/", None);
            let exchanges = match (truncated, outcome) {
                (None, CaptureOutcome::Failed { exchanges, error }) => {
                    assert!(
                        matches!(error, Error::Fetch(archivindex_http_client::Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
                    );
                    exchanges
                }
                (Some(_), CaptureOutcome::Captured { exchanges, .. }) => exchanges,
                _ => panic!("unexpected capture outcome"),
            };
            assert_eq!(exchanges.len(), 1);
            assert_eq!(exchanges[0].captured, captured);
        }
    }

    #[proptest::property_test]
    fn target_uri_text_has_no_fragment(#[strategy = prop::http_url()] url: Url) {
        let target = target_uri_text(&url);

        let path_start = url[..Position::BeforePath].len();
        let forbidden = target[path_start..].contains(['|', '^', '[', ']', '{', '}', '`']);

        prop_assert!(Uri::parse(target.as_ref()).is_ok());
        prop_assert!(!target.contains('#'));
        prop_assert!(!forbidden);
    }

    #[proptest::property_test]
    fn redacted_urls_keep_no_credentials(#[strategy = prop::http_url()] url: Url) {
        let redacted = redact_credentials(&url);
        let parsed = Url::parse(&redacted).unwrap();

        prop_assert!(parsed.username().is_empty());
        prop_assert_eq!(parsed.password(), None);
        prop_assert!(!redacted.contains("s3cret-token"));
    }
}
