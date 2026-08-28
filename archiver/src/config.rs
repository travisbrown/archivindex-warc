//! Configuration types and defaults for the archiving client.

use std::path::PathBuf;
use std::time::Duration;

use archivindex_warc::value::{Algorithm, DigestFormat, Encoding};

use crate::Config;
use crate::recorder::{DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT};
use crate::session::RetryConfig;

/// The spelling that lifts a limit in a serialized configuration.
const UNBOUNDED: &str = "unbounded";

impl Config {
    /// The default `User-Agent` header value, identifying this crate and its version.
    pub const DEFAULT_USER_AGENT: &str =
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

    /// The default bound on the time spent capturing one URL.
    pub const DEFAULT_MAX_CAPTURE_TIME: Duration = Duration::from_secs(10 * 60);

    /// The default length below which a repeated payload is stored again rather than as a revisit.
    pub const DEFAULT_MIN_REVISIT_PAYLOAD_LENGTH: u64 = 256;
}

impl Default for Config {
    /// The default configuration: this crate's `User-Agent`, the recorder's timeout and response
    /// bound, [`Config::DEFAULT_MAX_CAPTURE_TIME`] per URL, at most ten redirects per URL, one
    /// download at a time, an uncompressed WARC file, revisits of payloads of at least
    /// [`Config::DEFAULT_MIN_REVISIT_PAYLOAD_LENGTH`] bytes, this crate as the `warcinfo`
    /// software with no operator, and the default digest and session settings.
    fn default() -> Self {
        Self {
            user_agent: Self::DEFAULT_USER_AGENT.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            max_capture_time: Some(Self::DEFAULT_MAX_CAPTURE_TIME),
            max_redirects: 10,
            gzip_warc: false,
            concurrency: 1,
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
            min_revisit_payload_length: Self::DEFAULT_MIN_REVISIT_PAYLOAD_LENGTH,
            software: Software::default(),
            operator: None,
            digest: DigestConfig::default(),
            session: SessionConfig::default(),
        }
    }
}

/// The software named in the `warcinfo` record of every WARC file, as `name/version`.
///
/// The default is this crate's own name and version. When set in a document, both parts are
/// required, since a caller's version number does not describe this crate.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Software {
    /// The software's name.
    pub name: String,
    /// The software's version.
    pub version: String,
}

impl Default for Software {
    /// This crate's own name and version.
    fn default() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// The operator named in the `warcinfo` record of every WARC file, as `name` or `name <email>`.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Operator {
    /// The operator's name.
    pub name: String,
    /// The operator's email address, when given.
    #[serde(default)]
    pub email: Option<String>,
}

/// The formats of the digests written for every record.
///
/// A digest is written for each record's block and, where WARC 1.1 determines one, for its
/// payload. The general algorithm and encoding apply to both unless the field-specific settings
/// override them, and an unset encoding is the one annotation #80 of the WARC 1.1 annotated
/// specification recommends for the algorithm. The default, SHA-256 in Base16, is what WACZ
/// tooling writes.
///
/// A revisit index matches a response to an earlier capture by payload digest, so captures under
/// a different payload algorithm do not match those an index already holds.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct DigestConfig {
    /// The algorithm of both digests. The default is [`DigestConfig::DEFAULT_ALGORITHM`].
    pub algorithm: Algorithm,
    /// The encoding of both digests, or the algorithm's recommended encoding when unset.
    pub encoding: Option<Encoding>,
    /// Settings for `WARC-Block-Digest` that take precedence over the general ones.
    pub block: DigestOverride,
    /// Settings for `WARC-Payload-Digest` that take precedence over the general ones.
    pub payload: DigestOverride,
}

impl DigestConfig {
    /// The default digest algorithm.
    pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::Sha256;

    /// The block and payload formats these settings resolve to.
    #[must_use]
    pub fn formats(&self) -> DigestFormats {
        DigestFormats {
            block: self.resolve(self.block),
            payload: self.resolve(self.payload),
        }
    }

    fn resolve(&self, specific: DigestOverride) -> DigestFormat {
        let algorithm = specific.algorithm.unwrap_or(self.algorithm);

        DigestFormat {
            algorithm,
            encoding: specific
                .encoding
                .or(self.encoding)
                .unwrap_or_else(|| algorithm.recommended_encoding()),
        }
    }
}

impl Default for DigestConfig {
    /// [`DigestConfig::DEFAULT_ALGORITHM`] in its recommended encoding for both digests.
    fn default() -> Self {
        Self {
            algorithm: Self::DEFAULT_ALGORITHM,
            encoding: None,
            block: DigestOverride::default(),
            payload: DigestOverride::default(),
        }
    }
}

/// Digest settings for one field, each taking precedence over the general setting when set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct DigestOverride {
    /// The algorithm of this field's digests.
    pub algorithm: Option<Algorithm>,
    /// The encoding of this field's digests.
    pub encoding: Option<Encoding>,
}

/// The formats a [`DigestConfig`] resolves to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DigestFormats {
    /// The format of `WARC-Block-Digest` values.
    pub block: DigestFormat,
    /// The format of `WARC-Payload-Digest` values.
    pub payload: DigestFormat,
}

/// The settings a crawl session starts from.
///
/// The builder methods of [`Session`](crate::session::Session) override these for one session.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct SessionConfig {
    /// The policy for retrying transient failures.
    pub retry: RetryConfig,
    /// The wait between successive queued capture requests.
    #[serde(with = "humantime_serde")]
    pub request_delay: Duration,
    /// The persistent revisit and resource-state database consulted by sessions, when set.
    pub revisit_index: Option<PathBuf>,
    /// Whether a discovered URL that repeats one already given or discovered is skipped.
    pub dedupe_discoveries: bool,
}

impl Default for SessionConfig {
    /// The default retry policy, no request delay, no revisit index, and deduplicated
    /// discoveries.
    fn default() -> Self {
        Self {
            retry: RetryConfig::default(),
            request_delay: Duration::ZERO,
            revisit_index: None,
            dedupe_discoveries: true,
        }
    }
}

/// Serde functions for a time limit written as a `humantime` duration or as `"unbounded"`.
pub mod bounded_duration {
    use std::time::Duration;

    /// Write the limit as a duration, or as `"unbounded"` when unset.
    // Serde passes a reference to the field.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: serde::ser::Serializer>(
        limit: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match limit {
            Some(limit) => humantime_serde::serialize(limit, serializer),
            None => serializer.serialize_str(super::UNBOUNDED),
        }
    }

    /// Read a duration as the limit, or `"unbounded"` as none.
    pub fn deserialize<'de, D: serde::de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        struct LimitVisitor;

        impl serde::de::Visitor<'_> for LimitVisitor {
            type Value = Option<Duration>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a duration such as \"10m\", or \"unbounded\"")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == super::UNBOUNDED {
                    return Ok(None);
                }

                humantime_serde::re::humantime::parse_duration(value)
                    .map(Some)
                    .map_err(E::custom)
            }
        }

        deserializer.deserialize_str(LimitVisitor)
    }
}

/// Serde functions for a byte count limit written as an integer or as `"unbounded"`.
pub mod bounded_length {
    use serde::de::Unexpected;

    /// Write the limit as an integer, or as `"unbounded"` when unset.
    // Serde passes a reference to the field.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: serde::ser::Serializer>(
        limit: &Option<u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match limit {
            Some(limit) => serializer.serialize_u64(*limit),
            None => serializer.serialize_str(super::UNBOUNDED),
        }
    }

    /// Read an integer as the limit, or `"unbounded"` as none.
    pub fn deserialize<'de, D: serde::de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        struct LimitVisitor;

        impl serde::de::Visitor<'_> for LimitVisitor {
            type Value = Option<u64>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte count, or \"unbounded\"")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Some(value))
            }

            // TOML reads every integer as signed.
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                u64::try_from(value)
                    .map(Some)
                    .map_err(|_| E::invalid_value(Unexpected::Signed(value), &self))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == super::UNBOUNDED {
                    Ok(None)
                } else {
                    Err(E::invalid_value(Unexpected::Str(value), &self))
                }
            }
        }

        deserializer.deserialize_any(LimitVisitor)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use archivindex_warc::value::{Algorithm, DigestFormat, Encoding};

    use super::{DigestConfig, DigestFormats, DigestOverride, Operator, Software};
    use crate::Config;
    use crate::recorder::{DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT};

    #[test]
    fn warc_is_uncompressed_by_default() {
        assert!(!Config::default().gzip_warc);
    }

    #[test]
    fn default_limits_are_the_recorders() {
        let config = Config::default();

        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(
            config.max_response_length,
            Some(DEFAULT_MAX_RESPONSE_LENGTH)
        );
    }

    #[test]
    fn short_payloads_are_not_revisited_by_default() {
        assert_eq!(
            Config::default().min_revisit_payload_length,
            Config::DEFAULT_MIN_REVISIT_PAYLOAD_LENGTH
        );
    }

    #[test]
    fn captures_are_bounded_in_time_by_default() {
        assert_eq!(
            Config::default().max_capture_time,
            Some(Config::DEFAULT_MAX_CAPTURE_TIME)
        );
    }

    #[test]
    fn the_software_is_this_crate_by_default_and_no_operator_is_named() {
        let config = Config::default();

        assert_eq!(config.software.name, "archivindex-archiver");
        assert_eq!(config.software.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(config.operator, None);
    }

    #[test]
    fn digests_default_to_sha_256_in_base16() {
        let sha256 = DigestFormat {
            algorithm: Algorithm::Sha256,
            encoding: Encoding::Base16,
        };

        assert_eq!(
            DigestConfig::default().formats(),
            DigestFormats {
                block: sha256,
                payload: sha256,
            }
        );
    }

    #[test]
    fn specific_digest_settings_take_precedence_over_general_ones() {
        let config = DigestConfig {
            algorithm: Algorithm::Sha256,
            encoding: Some(Encoding::Base64),
            block: DigestOverride {
                algorithm: Some(Algorithm::Sha1),
                encoding: None,
            },
            payload: DigestOverride {
                algorithm: None,
                encoding: Some(Encoding::Base32),
            },
        };

        assert_eq!(
            config.formats(),
            DigestFormats {
                block: DigestFormat {
                    algorithm: Algorithm::Sha1,
                    encoding: Encoding::Base64,
                },
                payload: DigestFormat {
                    algorithm: Algorithm::Sha256,
                    encoding: Encoding::Base32,
                },
            }
        );
    }

    #[test]
    fn an_unset_encoding_is_the_algorithms_recommended_one() {
        let config = DigestConfig {
            algorithm: Algorithm::Sha1,
            ..DigestConfig::default()
        };

        assert_eq!(config.formats().block.encoding, Encoding::Base32);
    }

    #[test]
    fn an_empty_document_is_the_default_configuration() {
        let config = serde_json::from_str::<Config>("{}").expect("a configuration");

        assert_eq!(config, Config::default());
    }

    #[test]
    fn a_configuration_serializes_with_kebab_case_and_round_trips() {
        let config = Config {
            max_capture_time: None,
            max_response_length: None,
            ..Config::default()
        };

        let written = serde_json::to_string(&config).expect("a JSON document");
        let read = serde_json::from_str::<Config>(&written).expect("a configuration");

        for key in [
            "user-agent",
            "max-capture-time",
            "max-redirects",
            "gzip-warc",
            "max-response-length",
            "min-revisit-payload-length",
            "request-delay",
            "revisit-index",
            "initial-backoff",
            "max-backoff",
        ] {
            assert!(written.contains(&format!("\"{key}\":")), "missing {key}");
        }
        assert!(written.contains("\"max-capture-time\":\"unbounded\""));
        assert!(written.contains("\"max-response-length\":\"unbounded\""));
        assert!(written.contains("\"timeout\":\"30s\""));
        assert_eq!(read, config);
    }

    #[test]
    fn a_document_sets_every_section() {
        let document = r#"{
            "user-agent": "example/1.0",
            "timeout": "1m 30s",
            "max-capture-time": "unbounded",
            "max-response-length": 1024,
            "min-revisit-payload-length": 0,
            "software": {"name": "example-crawler", "version": "2.0"},
            "operator": {"name": "Example Operator", "email": "operator@example.com"},
            "digest": {"algorithm": "SHA-1", "payload": {"encoding": "base16"}},
            "session": {
                "retry": {"attempts": 1},
                "request-delay": "250ms",
                "revisit-index": "revisits.sqlite3"
            }
        }"#;

        let config = serde_json::from_str::<Config>(document).expect("a configuration");

        assert_eq!(config.user_agent, "example/1.0");
        assert_eq!(config.timeout, Duration::from_secs(90));
        assert_eq!(config.max_capture_time, None);
        assert_eq!(config.max_response_length, Some(1024));
        assert_eq!(config.min_revisit_payload_length, 0);
        assert_eq!(
            config.software,
            Software {
                name: "example-crawler".to_owned(),
                version: "2.0".to_owned(),
            }
        );
        assert_eq!(
            config.operator,
            Some(Operator {
                name: "Example Operator".to_owned(),
                email: Some("operator@example.com".to_owned()),
            })
        );
        assert_eq!(
            config.digest.formats(),
            DigestFormats {
                block: DigestFormat {
                    algorithm: Algorithm::Sha1,
                    encoding: Encoding::Base32,
                },
                payload: DigestFormat {
                    algorithm: Algorithm::Sha1,
                    encoding: Encoding::Base16,
                },
            }
        );
        assert_eq!(config.session.retry.attempts, 1);
        assert_eq!(config.session.request_delay, Duration::from_millis(250));
        assert_eq!(
            config.session.revisit_index,
            Some(PathBuf::from("revisits.sqlite3"))
        );
    }

    #[test]
    fn an_operator_may_be_named_without_an_email() {
        let config = serde_json::from_str::<Config>(r#"{"operator": {"name": "Solo"}}"#)
            .expect("a configuration");

        assert_eq!(
            config.operator,
            Some(Operator {
                name: "Solo".to_owned(),
                email: None,
            })
        );
    }

    #[test]
    fn a_document_cannot_hold_an_unknown_field_or_a_negative_limit() {
        assert!(serde_json::from_str::<Config>(r#"{"timeout-seconds": 30}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"max-response-length": -1}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"min-revisit-payload-length": -1}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"max-capture-time": "forever"}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"session": {"limit": 5}}"#).is_err());
    }

    #[test]
    fn software_needs_both_its_parts_and_an_operator_needs_a_name() {
        assert!(serde_json::from_str::<Config>(r#"{"software": {"name": "example"}}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"software": {"version": "1.0"}}"#).is_err());
        assert!(
            serde_json::from_str::<Config>(r#"{"operator": {"email": "operator@example.com"}}"#)
                .is_err()
        );
    }
}
