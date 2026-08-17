use std::fmt::Display;
use std::str::FromStr;

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
    /// Return the version number as it appears after `WARC/` in a record.
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
    type Err = crate::Error;

    fn from_str(version: &str) -> Result<Self, Self::Err> {
        match version {
            "1.0" => Ok(Self::V1_0),
            "1.1" => Ok(Self::V1_1),
            _ => Err(crate::Error::MalformedVersion(version.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WarcVersion;
    use crate::Error;

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
            Err(Error::MalformedVersion(version)) if version == "2.0"
        ));
    }
}
