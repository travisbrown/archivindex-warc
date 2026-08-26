//! The default configuration of the archiving client.

use std::time::Duration;

use crate::Config;
use crate::recorder::{DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT};

impl Config {
    /// The default `User-Agent` header value, identifying this crate and its version.
    pub const DEFAULT_USER_AGENT: &str =
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

    /// The default bound on the time spent capturing one URL.
    pub const DEFAULT_MAX_CAPTURE_TIME: Duration = Duration::from_secs(10 * 60);
}

impl Default for Config {
    /// The default configuration: this crate's `User-Agent`, the recorder's timeout and response
    /// bound, [`Config::DEFAULT_MAX_CAPTURE_TIME`] per URL, at most ten redirects per URL, one
    /// download at a time, and an uncompressed WARC file.
    fn default() -> Self {
        Self {
            user_agent: Self::DEFAULT_USER_AGENT.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            max_capture_time: Some(Self::DEFAULT_MAX_CAPTURE_TIME),
            max_redirects: 10,
            gzip_warc: false,
            concurrency: 1,
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn captures_are_bounded_in_time_by_default() {
        assert_eq!(
            Config::default().max_capture_time,
            Some(Config::DEFAULT_MAX_CAPTURE_TIME)
        );
    }
}
