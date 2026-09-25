//! Original network protocols recorded by the `WARC-Protocol` extension.
//!
//! Implements the repeated-field form of [IIPC proposal 42], also used by Browsertrix.
//! These identifiers describe the network message, independently of the block's `Content-Type`.
//! Unknown identifiers are preserved for forward compatibility. New identifiers should be
//! proposed to IIPC before use. Comma-separated lists are not part of this representation.
//!
//! [IIPC proposal 42]: https://github.com/iipc/warc-specifications/issues/42

use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// A protocol identifier, optionally followed by a slash and version.
///
/// Each component is a nonempty ASCII token. Spelling and case are preserved; known identifiers
/// use the lowercase spellings in the IIPC proposal, such as `h2` and `tls/1.3`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Protocol(Cow<'static, str>);

impl Protocol {
    /// HTTP/1.0.
    pub const HTTP_1_0: Self = Self(Cow::Borrowed("http/1.0"));
    /// HTTP/1.1.
    pub const HTTP_1_1: Self = Self(Cow::Borrowed("http/1.1"));
    /// HTTP/2 over TLS.
    pub const H2: Self = Self(Cow::Borrowed("h2"));
    /// HTTP/2 over cleartext TCP.
    pub const H2C: Self = Self(Cow::Borrowed("h2c"));

    /// The identifier as recorded.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A value is not a single protocol identifier.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("not a protocol identifier: {0}")]
pub struct Error(String);

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split('/');
        let valid = parts
            .next()
            .is_some_and(|part| crate::parsing::is_token(part.as_bytes()))
            && parts
                .next()
                .is_none_or(|part| crate::parsing::is_token(part.as_bytes()))
            && parts.next().is_none();
        if valid {
            Ok(Self(Cow::Owned(value.to_owned())))
        } else {
            Err(Error(value.to_owned()))
        }
    }
}

impl Display for Protocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Protocol;

    #[test]
    fn accepts_registered_and_future_identifiers() {
        for value in [
            "dns", "ftp", "gemini", "gopher", "http/0.9", "http/1.0", "http/1.1", "h2", "h2c",
            "h3", "quic/1", "quic/2", "spdy/1", "spdy/2", "spdy/3", "ssl/2", "ssl/3", "tls/1.0",
            "tls/1.1", "tls/1.2", "tls/1.3", "future/9",
        ] {
            assert_eq!(value.parse::<Protocol>().unwrap().as_str(), value);
        }
    }

    #[test]
    fn rejects_lists_and_malformed_identifiers() {
        for value in [
            "",
            "h2, tls/1.3",
            "h2 tls/1.3",
            "h2\r\nInjected: yes",
            " h2",
            "h2 ",
            "tls/",
            "/1.3",
            "tls/1/3",
            "h₂",
        ] {
            assert!(value.parse::<Protocol>().is_err(), "{value:?}");
        }
    }
}
