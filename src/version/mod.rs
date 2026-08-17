//! The versions of the WARC standard that this crate can read and write.
//!
//! [`WarcVersion`] is the usual runtime representation. [`marker`] provides type-level versions.

use std::fmt::Display;
use std::str::FromStr;

pub mod marker;

/// A version number that names no supported WARC version.
///
/// Only the number is captured here, without the `WARC/` a version line spells it after.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Malformed version: {0}")]
pub struct Error(pub String);

/// A version of the WARC standard supported by this crate.
#[derive(Clone, Copy, Debug, Default, Hash, Eq, PartialEq)]
pub enum WarcVersion {
    /// WARC 1.0, defined by ISO 28500:2009.
    V1_0,
    /// WARC 1.1, defined by ISO 28500:2017.
    #[default]
    V1_1,
}

impl WarcVersion {
    /// The version number as it appears after `WARC/`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1_0 => "1.0",
            Self::V1_1 => "1.1",
        }
    }
}

impl Display for WarcVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WarcVersion {
    type Err = Error;

    fn from_str(version: &str) -> Result<Self, Self::Err> {
        match version {
            "1.0" => Ok(Self::V1_0),
            "1.1" => Ok(Self::V1_1),
            _ => Err(Error(version.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, WarcVersion};

    #[test]
    fn supported_versions_round_trip() {
        for version in [WarcVersion::V1_0, WarcVersion::V1_1] {
            assert!(matches!(
                version.to_string().parse::<WarcVersion>(),
                Ok(parsed) if parsed == version
            ));
        }
    }

    #[test]
    fn unsupported_version_is_malformed() {
        assert!(matches!(
            "2.0".parse::<WarcVersion>(),
            Err(Error(version)) if version == "2.0"
        ));
    }
}
