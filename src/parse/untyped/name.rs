//! Standard and extension field names.

use std::fmt::Display;
use std::hash::{Hash, Hasher};

use crate::version::WarcVersion;

/// A field the WARC standard defines.
///
/// Any other valid name is an extension field.
///
/// The variants are declared in the conventional order of a header block, which is the order a
/// rendered block puts them in. Nothing else depends on the order, since the `serde` derives write
/// a variant's name rather than its position.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Field {
    WarcType,
    TargetURI,
    Date,
    Profile,
    RecordID,
    WarcinfoID,
    Filename,
    RefersTo,
    RefersToTargetURI,
    RefersToDate,
    BlockDigest,
    PayloadDigest,
    SegmentNumber,
    SegmentOriginID,
    SegmentTotalLength,
    IPAddress,
    ConcurrentTo,
    ContentType,
    IdentifiedPayloadType,
    ContentLength,
    Truncated,
}

impl Field {
    /// The field's name, lower-cased.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.names().0
    }

    /// The field's name as printed by the standard.
    #[must_use]
    pub const fn standard_name(self) -> &'static str {
        self.names().1
    }

    /// The lowercase and standard spellings.
    const fn names(self) -> (&'static str, &'static str) {
        match self {
            Self::WarcType => ("warc-type", "WARC-Type"),
            Self::TargetURI => ("warc-target-uri", "WARC-Target-URI"),
            Self::Date => ("warc-date", "WARC-Date"),
            Self::Profile => ("warc-profile", "WARC-Profile"),
            Self::RecordID => ("warc-record-id", "WARC-Record-ID"),
            Self::WarcinfoID => ("warc-warcinfo-id", "WARC-Warcinfo-ID"),
            Self::Filename => ("warc-filename", "WARC-Filename"),
            Self::RefersTo => ("warc-refers-to", "WARC-Refers-To"),
            Self::RefersToTargetURI => ("warc-refers-to-target-uri", "WARC-Refers-To-Target-URI"),
            Self::RefersToDate => ("warc-refers-to-date", "WARC-Refers-To-Date"),
            Self::BlockDigest => ("warc-block-digest", "WARC-Block-Digest"),
            Self::PayloadDigest => ("warc-payload-digest", "WARC-Payload-Digest"),
            Self::SegmentNumber => ("warc-segment-number", "WARC-Segment-Number"),
            Self::SegmentOriginID => ("warc-segment-origin-id", "WARC-Segment-Origin-ID"),
            Self::SegmentTotalLength => ("warc-segment-total-length", "WARC-Segment-Total-Length"),
            Self::IPAddress => ("warc-ip-address", "WARC-IP-Address"),
            Self::ConcurrentTo => ("warc-concurrent-to", "WARC-Concurrent-To"),
            Self::ContentType => ("content-type", "Content-Type"),
            Self::IdentifiedPayloadType => (
                "warc-identified-payload-type",
                "WARC-Identified-Payload-Type",
            ),
            Self::ContentLength => ("content-length", "Content-Length"),
            Self::Truncated => ("warc-truncated", "WARC-Truncated"),
        }
    }

    /// The field this name denotes, compared case-insensitively, or `None` for a name no version
    /// of the standard defines.
    ///
    /// This runs once per header line, so the name's length picks the candidates before anything
    /// is compared. No length is shared by more than four of the standard's fields.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        // Names are compared without regard to case, so this cannot be a `match` on the name
        // itself. The lengths are of the lower-case spellings, but a name differing only in case
        // is the same length, so a name of any other length defines no field. The test below
        // holds this table to the spellings above.
        let candidates: &[Self] = match name.len() {
            9 => &[Self::WarcType, Self::Date],
            12 => &[Self::Profile, Self::ContentType],
            13 => &[Self::Filename],
            14 => &[
                Self::RecordID,
                Self::RefersTo,
                Self::ContentLength,
                Self::Truncated,
            ],
            15 => &[Self::TargetURI, Self::IPAddress],
            16 => &[Self::WarcinfoID],
            17 => &[Self::BlockDigest],
            18 => &[Self::ConcurrentTo],
            19 => &[Self::RefersToDate, Self::PayloadDigest, Self::SegmentNumber],
            22 => &[Self::SegmentOriginID],
            25 => &[Self::RefersToTargetURI, Self::SegmentTotalLength],
            28 => &[Self::IdentifiedPayloadType],
            _ => return None,
        };

        candidates
            .iter()
            .copied()
            .find(|field| name.eq_ignore_ascii_case(field.name()))
    }

    /// Whether the given version of the standard defines this field.
    ///
    /// WARC 1.1 added `WARC-Refers-To-Date` and `WARC-Refers-To-Target-URI`.
    #[must_use]
    pub const fn defined_in(self, version: WarcVersion) -> bool {
        !matches!(
            (version, self),
            (
                WarcVersion::V1_0,
                Self::RefersToDate | Self::RefersToTargetURI
            )
        )
    }

    /// This field's position in the conventional ordering of a header block.
    ///
    /// The variants are declared in that order, so a field's discriminant is its position.
    pub(crate) const fn canonical_rank(self) -> usize {
        self as usize
    }
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How a standard field name was spelled in the source record.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Spelling {
    /// The lower-case name, as [`Field::name`] renders it.
    Lower,
    /// The name as the standard prints it, as [`Field::standard_name`] renders it.
    Standard,
    /// Anything else, held as it was read. An extension name is always held this way, since its
    /// spelling is the only one it has.
    Other(Box<str>),
}

/// A field name as it appeared in a record's header block.
///
/// Names are compared without regard to case, while their original spelling is preserved for
/// byte-exact round-tripping.
///
/// ```
/// use archivindex_warc::parse::untyped::name::{Field, HeaderName};
///
/// let as_read = HeaderName::as_read("warc-target-uri");
/// assert_eq!(as_read.field(), Some(Field::TargetURI));
/// assert_eq!(as_read.name(), "warc-target-uri");
///
/// // The two spell the same field, so they are the same name.
/// assert_eq!(as_read, HeaderName::new(Field::TargetURI));
/// assert_eq!(HeaderName::new(Field::TargetURI).name(), "WARC-Target-URI");
///
/// // A name no version of the standard defines.
/// let extension = HeaderName::as_read("X-Crawler-Note");
/// assert_eq!(extension.field(), None);
/// assert!(extension.is_extension());
/// ```
#[derive(Clone, Debug, Eq)]
pub struct HeaderName {
    /// The field this name denotes, or `None` for an extension name.
    field: Option<Field>,
    // An extension name always uses `Spelling::Other`.
    spelling: Spelling,
}

impl HeaderName {
    /// A defined field's name, in the spelling the standard prints it with.
    #[must_use]
    pub const fn new(field: Field) -> Self {
        Self {
            field: Some(field),
            spelling: Spelling::Standard,
        }
    }

    /// A field name spelled as it appeared in an archive.
    #[must_use]
    pub fn as_read(name: &str) -> Self {
        let Some(field) = Field::from_name(name) else {
            return Self {
                field: None,
                spelling: Spelling::Other(Box::from(name)),
            };
        };

        let (lower, standard) = field.names();
        let spelling = if name == lower {
            Spelling::Lower
        } else if name == standard {
            Spelling::Standard
        } else {
            Spelling::Other(Box::from(name))
        };

        Self {
            field: Some(field),
            spelling,
        }
    }

    /// The field this name denotes, or `None` when no version of the standard defines it.
    #[must_use]
    pub const fn field(&self) -> Option<Field> {
        self.field
    }

    /// Whether this is a name no version of the standard defines.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        self.field.is_none()
    }

    /// The name as it will be written: the spelling it was read with, or the standard's own
    /// spelling for a name built from its field.
    #[must_use]
    pub fn name(&self) -> &str {
        match (&self.spelling, self.field) {
            (Spelling::Lower, Some(field)) => field.name(),
            (Spelling::Standard, Some(field)) => field.standard_name(),
            (Spelling::Other(name), _) => name,
            // The invariant above rules this out: an extension name is always `Other`.
            (Spelling::Lower | Spelling::Standard, None) => {
                unreachable!("invariant violation: an extension name has no standard spelling")
            }
        }
    }

    /// The name, as it will be written, taking ownership of it.
    #[must_use]
    pub fn into_name(self) -> String {
        match (self.spelling, self.field) {
            (Spelling::Lower, Some(field)) => field.name().to_owned(),
            (Spelling::Standard, Some(field)) => field.standard_name().to_owned(),
            (Spelling::Other(name), _) => name.into_string(),
            (Spelling::Lower | Spelling::Standard, None) => {
                unreachable!("invariant violation: an extension name has no standard spelling")
            }
        }
    }

    /// Respell this name the way the standard prints it.
    ///
    /// An extension name is left alone, since the spelling it was read with is the only one it
    /// has.
    pub fn canonicalize(&mut self) {
        if self.field.is_some() {
            self.spelling = Spelling::Standard;
        }
    }
}

/// Names are compared by the field they denote, since WARC field names are case-insensitive.
impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        match (self.field, other.field) {
            (Some(field), Some(other)) => field == other,
            (None, None) => self.name().eq_ignore_ascii_case(other.name()),
            _ => false,
        }
    }
}

/// Hash names without regard to case, matching [`PartialEq`].
impl Hash for HeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.name().bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
        state.write_u8(0xff);
    }
}

impl From<Field> for HeaderName {
    fn from(field: Field) -> Self {
        Self::new(field)
    }
}

impl Display for HeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use super::{Field, HeaderName};
    use crate::version::WarcVersion;

    /// Every standard field, in the conventional order of a header block.
    ///
    /// This is written out rather than derived from the enum, so that the declaration order the
    /// ranking relies on is checked here rather than assumed.
    const CANONICAL_ORDER: [Field; 21] = [
        Field::WarcType,
        Field::TargetURI,
        Field::Date,
        Field::Profile,
        Field::RecordID,
        Field::WarcinfoID,
        Field::Filename,
        Field::RefersTo,
        Field::RefersToTargetURI,
        Field::RefersToDate,
        Field::BlockDigest,
        Field::PayloadDigest,
        Field::SegmentNumber,
        Field::SegmentOriginID,
        Field::SegmentTotalLength,
        Field::IPAddress,
        Field::ConcurrentTo,
        Field::ContentType,
        Field::IdentifiedPayloadType,
        Field::ContentLength,
        Field::Truncated,
    ];

    fn hash_of(name: &HeaderName) -> u64 {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        hasher.finish()
    }

    /// The lower-case spelling of every defined field is the ASCII lower-casing of the standard
    /// one, and both spellings are found by lookup, which also holds the lengths
    /// [`Field::from_name`] dispatches on to the spellings themselves.
    #[test]
    fn the_two_spellings_agree() {
        for field in CANONICAL_ORDER {
            assert_eq!(field.name(), field.standard_name().to_ascii_lowercase());
            assert_eq!(Field::from_name(field.standard_name()), Some(field));
            assert_eq!(Field::from_name(field.name()), Some(field));
        }
    }

    /// Each field ranks at its place in the conventional order, which also proves the array above
    /// holds all twenty-one fields, one apiece.
    #[test]
    fn every_field_is_ranked() {
        for (position, field) in CANONICAL_ORDER.into_iter().enumerate() {
            assert_eq!(field.canonical_rank(), position, "{field}");
        }
    }

    #[test]
    fn recognizes_names_in_any_case() {
        assert_eq!(
            HeaderName::as_read("WaRc-TyPe").field(),
            Some(Field::WarcType)
        );
        assert_eq!(HeaderName::as_read("X-Note").field(), None);
        assert!(HeaderName::as_read("X-Note").is_extension());
    }

    #[test]
    fn keeps_the_spelling_it_was_read_with() {
        for spelling in ["WARC-Type", "warc-type", "WaRc-TyPe"] {
            assert_eq!(HeaderName::as_read(spelling).name(), spelling);
        }
        // An extension name keeps its case.
        assert_eq!(HeaderName::as_read("X-Note").name(), "X-Note");
        assert_eq!(HeaderName::new(Field::WarcType).name(), "WARC-Type");
    }

    #[test]
    fn compares_and_hashes_case_insensitively() {
        let read = HeaderName::as_read("wArC-tYpE");
        let built = HeaderName::new(Field::WarcType);

        assert_eq!(read, built);
        assert_eq!(hash_of(&read), hash_of(&built));

        let extension = HeaderName::as_read("X-NOTE");
        let same = HeaderName::as_read("x-note");

        assert_eq!(extension, same);
        assert_eq!(hash_of(&extension), hash_of(&same));

        assert_ne!(extension, HeaderName::as_read("x-other"));
        assert_ne!(built, HeaderName::new(Field::Date));
    }

    /// The hash terminator distinguishes a name from its prefix.
    #[test]
    fn hashes_distinguish_a_shared_prefix() {
        assert_ne!(
            hash_of(&HeaderName::as_read("x-ab")),
            hash_of(&HeaderName::as_read("x-a"))
        );
    }

    #[test]
    fn canonicalizes_only_what_it_can() {
        let mut defined = HeaderName::as_read("wArC-tYpE");
        defined.canonicalize();
        assert_eq!(defined.name(), "WARC-Type");

        let mut extension = HeaderName::as_read("X-NoTe");
        extension.canonicalize();
        assert_eq!(extension.name(), "X-NoTe");
    }

    /// The `serde` derives round-trip every defined field.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip() {
        for field in CANONICAL_ORDER {
            let encoded = serde_json::to_string(&field).unwrap();
            assert_eq!(serde_json::from_str::<Field>(&encoded).unwrap(), field);
        }

        // The derive encodes the variant rather than either spelling of the name, so a field
        // is written the same way whatever an archive spells it.
        assert_eq!(
            serde_json::to_string(&Field::ContentLength).unwrap(),
            "\"ContentLength\""
        );
    }

    /// The two fields WARC 1.1 introduced are the only ones 1.0 does not define.
    #[test]
    fn reports_which_version_defines_a_field() {
        for field in CANONICAL_ORDER {
            assert!(field.defined_in(WarcVersion::V1_1));
            assert_eq!(
                field.defined_in(WarcVersion::V1_0),
                !matches!(field, Field::RefersToDate | Field::RefersToTargetURI)
            );
        }
    }
}
