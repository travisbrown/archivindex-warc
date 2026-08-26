//! The cookies each host is sent, kept for the challenges some hosts guard themselves with.
//!
//! This is deliberately not a cookie store. A host issues clearance for its whole origin and
//! expects it back on every later request, so a cookie here is scoped to a host, without the
//! path, expiry, or `Domain` matching of RFC 6265 section 5.3, and is withheld from HTTP only
//! when it was issued with the `Secure` attribute or supplied for an HTTPS URL, since a supplied
//! `Cookie` field value carries no attributes. Nothing beyond that belongs here: a crawl that
//! needs a general store should use one, such as the `cookie_store` crate.

use std::collections::HashMap;
use std::sync::MutexGuard;

use http::header::HeaderValue;
use url::Url;

use crate::Archiver;

/// The cookies each host has been given, by the caller or by a recognized challenge.
#[derive(Debug, Default)]
pub struct CookieJar {
    by_host: HashMap<String, Vec<Cookie>>,
}

/// One `name=value` pair of a `Cookie` field value, and whether it may be sent only over HTTPS.
#[derive(Debug)]
struct Cookie {
    pair: Vec<u8>,
    secure: bool,
}

/// A `Cookie` field value and whether it may be sent only over HTTPS.
#[derive(Clone, Debug)]
pub struct StoredCookie {
    /// The complete field value, as it is sent.
    pub value: HeaderValue,
    /// Whether the cookie was issued with the `Secure` attribute, or supplied for an HTTPS URL.
    pub secure: bool,
}

impl Cookie {
    /// The name before the `=`, or the whole pair when it has none.
    fn name(&self) -> &[u8] {
        self.pair
            .iter()
            .position(|byte| *byte == b'=')
            .map_or(&self.pair[..], |end| &self.pair[..end])
    }
}

impl CookieJar {
    /// The `Cookie` field value to send with a request for `url`: every pair held for its host,
    /// less the secure ones when `url` is not HTTPS.
    #[must_use]
    pub fn get(&self, url: &Url) -> Option<HeaderValue> {
        let https = url.scheme() == "https";
        let mut value = Vec::new();
        for cookie in self
            .by_host
            .get(url.host_str()?)?
            .iter()
            .filter(|cookie| https || !cookie.secure)
        {
            if !value.is_empty() {
                value.extend_from_slice(b"; ");
            }
            value.extend_from_slice(&cookie.pair);
        }

        // The pairs came from field values, and the separator is the one the grammar uses.
        (!value.is_empty()).then(|| HeaderValue::from_bytes(&value).ok())?
    }

    /// Retain each pair of a `Cookie` field value for the host of `url`, replacing a pair of the
    /// same name already held.
    pub fn insert(&mut self, url: &Url, cookie: &StoredCookie) {
        let Some(host) = url.host_str() else {
            return;
        };
        let held = self.by_host.entry(host.to_owned()).or_default();
        let pairs = cookie
            .value
            .as_bytes()
            .split(|byte| *byte == b';')
            .map(<[u8]>::trim_ascii)
            .filter(|pair| !pair.is_empty());
        for pair in pairs {
            let cookie = Cookie {
                pair: pair.to_vec(),
                secure: cookie.secure,
            };
            match held
                .iter_mut()
                .find(|earlier| earlier.name() == cookie.name())
            {
                Some(earlier) => *earlier = cookie,
                None => held.push(cookie),
            }
        }
    }

    /// Retain a supplied value, restricted to HTTPS exactly when `url` is itself served over it.
    pub fn insert_header(&mut self, url: &Url, value: HeaderValue) {
        self.insert(
            url,
            &StoredCookie {
                value,
                secure: url.scheme() == "https",
            },
        );
    }
}

impl Archiver {
    /// Borrow the cookie jar shared by this archiver's clones and capture threads.
    ///
    /// A panic while the jar is held cannot leave it inconsistent, since every operation on it
    /// completes before the guard is released, so a poisoned lock is taken as it stands.
    pub(crate) fn cookie_jar(&self) -> MutexGuard<'_, CookieJar> {
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;
    use url::Url;

    use super::{CookieJar, StoredCookie};

    fn url(scheme: &str) -> Url {
        Url::parse(&format!("{scheme}://example.com/path")).expect("a URL")
    }

    fn issued(value: &'static str, secure: bool) -> StoredCookie {
        StoredCookie {
            value: HeaderValue::from_static(value),
            secure,
        }
    }

    #[test]
    fn a_challenge_cookie_joins_a_supplied_one() {
        let mut jar = CookieJar::default();
        jar.insert_header(&url("http"), HeaderValue::from_static("session=1"));
        jar.insert(&url("http"), &issued("clearance=2", false));

        assert_eq!(
            jar.get(&url("http")),
            Some("session=1; clearance=2".parse().expect("a value"))
        );
    }

    #[test]
    fn a_cookie_of_the_same_name_is_replaced_in_place() {
        let mut jar = CookieJar::default();
        jar.insert(&url("http"), &issued("pow_trace=a; pow_bypass=b", false));
        jar.insert(&url("http"), &issued("pow_trace=c", false));

        assert_eq!(
            jar.get(&url("http")),
            Some("pow_trace=c; pow_bypass=b".parse().expect("a value"))
        );
    }

    #[test]
    fn a_secure_cookie_is_withheld_from_http() {
        let mut jar = CookieJar::default();
        jar.insert_header(&url("https"), HeaderValue::from_static("session=1"));
        jar.insert(&url("http"), &issued("clearance=2", false));

        assert_eq!(
            jar.get(&url("http")),
            Some("clearance=2".parse().expect("a value"))
        );
        assert_eq!(
            jar.get(&url("https")),
            Some("session=1; clearance=2".parse().expect("a value"))
        );
    }

    #[test]
    fn a_host_holding_nothing_sendable_gets_no_field() {
        let mut jar = CookieJar::default();
        jar.insert_header(&url("https"), HeaderValue::from_static("session=1"));

        assert_eq!(jar.get(&url("http")), None);
        assert_eq!(
            jar.get(&Url::parse("http://other.example/").expect("a URL")),
            None
        );
    }
}
