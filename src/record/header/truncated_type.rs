//! The reason a record reports for holding less of a resource than was captured.

use std::fmt::{Display, Formatter};

use crate::record::extension::{ExtensionTruncatedReason, Never};

/// Why a record contains less data than the captured resource.
///
/// The type parameter supplies reasons defined by an extension and defaults to [`Never`]. Tokens
/// recognized by neither the standard nor the extension are preserved in [`Self::Unknown`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TruncatedType<R = Never> {
    /// `length`: the capture exceeded a configured maximum length.
    Length,
    /// `time`: the capture exceeded a configured maximum time.
    Time,
    /// `disconnect`: the network connection carrying the capture was lost.
    Disconnect,
    /// `unspecified`: some other or unknown reason.
    Unspecified,
    /// A reason the extension in force defines.
    Extension(R),
    /// An unrecognized reason, normalized to lowercase.
    Unknown(String),
}

impl<R: ExtensionTruncatedReason> TruncatedType<R> {
    /// The reasons defined by the standard.
    const KNOWN_TYPES: [Self; 4] = [
        Self::Length,
        Self::Time,
        Self::Disconnect,
        Self::Unspecified,
    ];

    /// The token used to serialize this value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Length => "length",
            Self::Time => "time",
            Self::Disconnect => "disconnect",
            Self::Unspecified => "unspecified",
            Self::Extension(reason) => reason.reason_token(),
            Self::Unknown(token) => token,
        }
    }
}

impl<R: ExtensionTruncatedReason> Display for TruncatedType<R> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Parse a reason without regard to case, checking standard reasons before extension reasons.
impl<R: ExtensionTruncatedReason, S: AsRef<str>> From<S> for TruncatedType<R> {
    fn from(string: S) -> Self {
        let string = string.as_ref();
        Self::KNOWN_TYPES
            .iter()
            .find(|truncated_type| string.eq_ignore_ascii_case(truncated_type.as_str()))
            .cloned()
            .or_else(|| R::from_reason_token(string).map(Self::Extension))
            .unwrap_or_else(|| Self::Unknown(string.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::TruncatedType;
    use crate::record::extension::{ExtensionTruncatedReason, Never};

    /// An extension reason used to test recognition and attempted redefinition.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum TestReason {
        Refused,
    }

    impl ExtensionTruncatedReason for TestReason {
        fn reason_token(&self) -> &str {
            match self {
                Self::Refused => "refused",
            }
        }

        fn from_reason_token(token: &str) -> Option<Self> {
            (token.eq_ignore_ascii_case("refused") || token.eq_ignore_ascii_case("length"))
                .then_some(Self::Refused)
        }
    }

    /// Standard reasons are parsed without regard to case.
    #[test]
    fn every_standard_reason_round_trips_through_its_token() {
        for truncated_type in TruncatedType::<Never>::KNOWN_TYPES {
            assert_eq!(
                TruncatedType::from(truncated_type.as_str().to_uppercase()),
                truncated_type
            );
        }
    }

    /// Extension reasons cannot redefine standard reasons.
    #[test]
    fn an_extension_defines_reasons_the_standard_does_not() {
        assert_eq!(
            TruncatedType::from("Refused"),
            TruncatedType::Extension(TestReason::Refused)
        );
        assert_eq!(
            TruncatedType::Extension(TestReason::Refused).to_string(),
            "refused"
        );
        assert_eq!(
            TruncatedType::<TestReason>::from("length"),
            TruncatedType::Length
        );
    }

    /// Unrecognized reasons are preserved in normalized form.
    #[test]
    fn an_unrecognized_reason_is_kept() {
        let truncated_type = TruncatedType::<Never>::from("Refused");
        assert_eq!(truncated_type, TruncatedType::Unknown("refused".to_owned()));
        assert_eq!(truncated_type.to_string(), "refused");
    }
}
