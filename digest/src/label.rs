//! Algorithm labels, preserved as read.

use std::borrow::Cow;

use crate::algorithm::Algorithm;

/// The spelling of a known algorithm label.
///
/// Bit zero records the compatibility spelling. Each following bit records whether the
/// corresponding alphabetic character was uppercase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LabelFlags(u8);

impl LabelFlags {
    const COMPATIBILITY: u8 = 1;

    fn from_label(label: &str, compatibility: bool) -> Self {
        let mut flags = u8::from(compatibility);
        let mut uppercase = 2;

        for byte in label.bytes().filter(u8::is_ascii_alphabetic) {
            if byte.is_ascii_uppercase() {
                flags |= uppercase;
            }
            uppercase <<= 1;
        }

        Self(flags)
    }

    const fn is_compatibility(self) -> bool {
        self.0 & Self::COMPATIBILITY != 0
    }

    const fn is_uppercase(self, alphabetic_index: usize) -> bool {
        self.0 & (2 << alphabetic_index) != 0
    }
}

/// An algorithm label, normalized when it names a known algorithm and otherwise kept verbatim.
///
/// Equality compares the named algorithm rather than its spelling. Custom labels ignore ASCII
/// case; known labels also ignore compatibility spelling.
#[derive(Clone, Debug)]
pub enum AlgorithmLabel {
    Known {
        algorithm: Algorithm,
        flags: LabelFlags,
    },
    Custom(Box<str>),
}

impl AlgorithmLabel {
    pub fn new(label: &str) -> Self {
        match algorithm(label) {
            Some((algorithm, compatibility)) => Self::Known {
                algorithm,
                flags: LabelFlags::from_label(label, compatibility),
            },
            None => Self::Custom(label.into()),
        }
    }

    pub const fn from_algorithm(algorithm: Algorithm) -> Self {
        Self::Known {
            algorithm,
            flags: LabelFlags(0),
        }
    }

    pub const fn algorithm(&self) -> Option<Algorithm> {
        match self {
            Self::Known { algorithm, .. } => Some(*algorithm),
            Self::Custom(_) => None,
        }
    }

    pub fn as_read(&self) -> Cow<'_, str> {
        match self {
            Self::Known { .. } => {
                let mut label = String::new();
                self.write_to(&mut label)
                    .expect("invariant violation: writing to a string cannot fail");
                Cow::Owned(label)
            }
            Self::Custom(label) => Cow::Borrowed(label),
        }
    }

    pub fn write_to<W: std::fmt::Write>(&self, writer: &mut W) -> std::fmt::Result {
        match self {
            Self::Known { algorithm, flags } => {
                let label = if flags.is_compatibility() {
                    compatibility_label(*algorithm)
                        .expect("invariant violation: only compatibility labels carry the flag")
                } else {
                    algorithm.label()
                };
                let mut alphabetic_index = 0;

                for mut byte in label.bytes() {
                    if byte.is_ascii_alphabetic() {
                        if flags.is_uppercase(alphabetic_index) {
                            byte.make_ascii_uppercase();
                        }
                        alphabetic_index += 1;
                    }
                    writer.write_char(char::from(byte))?;
                }

                Ok(())
            }
            Self::Custom(label) => writer.write_str(label),
        }
    }
}

impl PartialEq for AlgorithmLabel {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Known {
                    algorithm: left, ..
                },
                Self::Known {
                    algorithm: right, ..
                },
            ) => left == right,
            (Self::Custom(left), Self::Custom(right)) => left.eq_ignore_ascii_case(right),
            (Self::Known { .. }, Self::Custom(_)) | (Self::Custom(_), Self::Known { .. }) => false,
        }
    }
}

impl Eq for AlgorithmLabel {}

impl std::hash::Hash for AlgorithmLabel {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Known { algorithm, .. } => {
                state.write_u8(0);
                algorithm.hash(state);
            }
            Self::Custom(label) => {
                state.write_u8(1);
                for byte in label.bytes() {
                    state.write_u8(byte.to_ascii_lowercase());
                }
                // The label is hashed byte by byte, so it needs an end of its own.
                state.write_u8(b':');
            }
        }
    }
}

impl Algorithm {
    /// The algorithm a label names, compared without regard to case.
    ///
    /// Both the recommended spelling and the compatibility spelling annotation #80 gives some
    /// algorithms resolve here.
    ///
    /// # Examples
    ///
    /// ```
    /// use archivindex_warc_digest::algorithm::Algorithm;
    ///
    /// assert_eq!(Algorithm::from_label("SHA-256"), Some(Algorithm::Sha256));
    /// assert_eq!(Algorithm::from_label("crc32"), None);
    /// ```
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        algorithm(label).map(|(algorithm, _)| algorithm)
    }
}

/// The compatibility label annotation #80 recognizes for an algorithm, if it has one.
pub const fn compatibility_label(algorithm: Algorithm) -> Option<&'static str> {
    match algorithm {
        Algorithm::Sha1 => Some("sha-1"),
        Algorithm::Sha224 => Some("sha-224"),
        Algorithm::Sha256 => Some("sha-256"),
        Algorithm::Sha384 => Some("sha-384"),
        Algorithm::Sha512 => Some("sha-512"),
        _ => None,
    }
}

/// Resolve a known label and whether it uses a compatibility spelling.
fn algorithm(label: &str) -> Option<(Algorithm, bool)> {
    if label.eq_ignore_ascii_case("sha256") {
        Some((Algorithm::Sha256, false))
    } else if label.eq_ignore_ascii_case("sha1") {
        Some((Algorithm::Sha1, false))
    } else if label.eq_ignore_ascii_case("md5") {
        Some((Algorithm::Md5, false))
    } else if label.eq_ignore_ascii_case("sha-1") {
        Some((Algorithm::Sha1, true))
    } else if label.eq_ignore_ascii_case("xxh3") {
        Some((Algorithm::Xxh3, false))
    } else if label.eq_ignore_ascii_case("xxh128") {
        Some((Algorithm::Xxh128, false))
    } else if label.eq_ignore_ascii_case("sha224") {
        Some((Algorithm::Sha224, false))
    } else if label.eq_ignore_ascii_case("sha-224") {
        Some((Algorithm::Sha224, true))
    } else if label.eq_ignore_ascii_case("sha-256") {
        Some((Algorithm::Sha256, true))
    } else if label.eq_ignore_ascii_case("sha384") {
        Some((Algorithm::Sha384, false))
    } else if label.eq_ignore_ascii_case("sha-384") {
        Some((Algorithm::Sha384, true))
    } else if label.eq_ignore_ascii_case("sha512") {
        Some((Algorithm::Sha512, false))
    } else if label.eq_ignore_ascii_case("sha-512") {
        Some((Algorithm::Sha512, true))
    } else if label.eq_ignore_ascii_case("sha512-224") {
        Some((Algorithm::Sha512_224, false))
    } else if label.eq_ignore_ascii_case("sha512-256") {
        Some((Algorithm::Sha512_256, false))
    } else if label.eq_ignore_ascii_case("sha3-224") {
        Some((Algorithm::Sha3_224, false))
    } else if label.eq_ignore_ascii_case("sha3-256") {
        Some((Algorithm::Sha3_256, false))
    } else if label.eq_ignore_ascii_case("sha3-384") {
        Some((Algorithm::Sha3_384, false))
    } else if label.eq_ignore_ascii_case("sha3-512") {
        Some((Algorithm::Sha3_512, false))
    } else if label.eq_ignore_ascii_case("blake2s") {
        Some((Algorithm::Blake2s, false))
    } else if label.eq_ignore_ascii_case("blake2b") {
        Some((Algorithm::Blake2b, false))
    } else if label.eq_ignore_ascii_case("blake3") {
        Some((Algorithm::Blake3, false))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_strategy::proptest;

    use super::{Algorithm, AlgorithmLabel};
    use crate::strategies;

    /// A known label names its algorithm in any spelling and case, and renders exactly as read.
    #[proptest]
    fn round_trips_a_known_label_in_any_case(
        #[strategy(strategies::known_label())] input: (Algorithm, String),
    ) {
        let (algorithm, spelling) = input;
        let label = AlgorithmLabel::new(&spelling);

        prop_assert_eq!(label.algorithm(), Some(algorithm));
        prop_assert_eq!(label.as_read(), spelling);
    }

    /// Every valid algorithm label renders exactly as read, whether known or custom.
    #[proptest]
    fn round_trips_any_valid_label(#[strategy(strategies::token())] spelling: String) {
        let label = AlgorithmLabel::new(&spelling);

        prop_assert_eq!(label.as_read(), spelling);
    }

    #[test]
    fn records_compatibility_spelling_and_uppercase_letters_as_flags() {
        let label = AlgorithmLabel::new("ShA-256");
        let AlgorithmLabel::Known { algorithm, flags } = &label else {
            panic!("not a known algorithm")
        };

        assert_eq!(*algorithm, Algorithm::Sha256);
        assert!(flags.is_compatibility());
        assert!(flags.is_uppercase(0));
        assert!(!flags.is_uppercase(1));
        assert!(flags.is_uppercase(2));
        assert_eq!(label.as_read(), "ShA-256");
    }

    /// Every spelling of a known label resolves to its algorithm.
    #[proptest]
    fn resolves_a_known_label_in_any_case(
        #[strategy(strategies::known_label())] input: (Algorithm, String),
    ) {
        let (algorithm, spelling) = input;

        prop_assert_eq!(Algorithm::from_label(&spelling), Some(algorithm));
    }
}
