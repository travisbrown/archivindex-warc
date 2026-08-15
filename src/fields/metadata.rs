//! The body of a `metadata` record: what a capture says about another record.
//!
//! A `metadata` record holds content created to further describe, explain, or accompany a
//! harvested resource in ways no other record type covers, and it almost always refers to a
//! record of another type through `WARC-Concurrent-To` or `WARC-Refers-To`. Its block may take
//! any format, but `application/warc-fields` may be used, and the standard says allowable
//! fields then include "all \[DCMI\]" terms plus three of its own. Every field is optional.
//!
//! This is the same shape as a `warcinfo` body, so it is the same [`Body`] over a different
//! vocabulary: see [`crate::fields::warcinfo`] for what the two have in common.
//!
//! ```
//! use archivindex_warc::fields::metadata::MetadataBody;
//!
//! let body = MetadataBody::parse(
//!     b"via: http://www.archive.org/\r\n\
//!       hopsFromSeed: E\r\n\
//!       fetchTimeMs: 565\r\n",
//! )?;
//!
//! assert_eq!(body.via(), Some("http://www.archive.org/"));
//! assert_eq!(body.hops_from_seed(), Some("E"));
//! assert_eq!(body.fetch_time_ms(), Some(565));
//! # Ok::<(), archivindex_warc::fields::Error>(())
//! ```

use std::fmt::Display;
use std::str::FromStr;

use crate::fields::dcmi::DcmiTerm;
use crate::fields::{Body, Field};

/// A field of a `metadata` record's body.
///
/// The three variants the standard names itself come first, any DCMI metadata term is a
/// [`Dcmi`](Self::Dcmi), and anything else is an [`Other`](Self::Other), since the standard
/// leaves the format of a `metadata` block open.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum MetadataField {
    /// `via`: the referring URI from which the archived URI was discovered.
    Via,
    /// `hopsFromSeed`: a symbolic string describing the type of each hop from a starting seed
    /// URI to the current URI, one character per hop, empty for a seed itself. See [`Hop`] for
    /// the characters it is usually written with and [`HopsFromSeed`] for reading a value as
    /// them.
    HopsFromSeed,
    /// `fetchTimeMs`: the time in milliseconds it took to collect the archived URI, starting
    /// from the initiation of network traffic.
    FetchTimeMs,
    /// A metadata term from the DCMI vocabulary, all of which are allowed here.
    Dcmi(DcmiTerm),
    /// Any other field, held under the lower-cased spelling of its name.
    Other(String),
}

impl Field for MetadataField {
    const KNOWN: &'static [Self] = &[Self::Via, Self::HopsFromSeed, Self::FetchTimeMs];

    fn name(&self) -> &str {
        match self {
            Self::Via => "via",
            Self::HopsFromSeed => "hopsFromSeed",
            Self::FetchTimeMs => "fetchTimeMs",
            Self::Dcmi(term) => term.name(),
            Self::Other(name) => name,
        }
    }

    fn dcmi(term: DcmiTerm) -> Self {
        Self::Dcmi(term)
    }

    fn other(name: String) -> Self {
        Self::Other(name)
    }
}

impl Display for MetadataField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl<S: AsRef<str>> From<S> for MetadataField {
    fn from(string: S) -> Self {
        Self::from_name(string.as_ref())
    }
}

/// The body of a `metadata` record, read as `application/warc-fields`.
pub type MetadataBody = Body<MetadataField>;

impl MetadataBody {
    /// The referring URI from which the archived URI was discovered.
    #[must_use]
    pub fn via(&self) -> Option<&str> {
        self.get(&MetadataField::Via)
    }

    /// The type of each hop from a starting seed URI to the archived one, one character per
    /// hop. A seed is an empty string rather than an absent field, so this reports `Some("")`
    /// for one.
    ///
    /// The value is reported as it was written, since the standard fixes no alphabet for it.
    /// Parse it as [`HopsFromSeed`] to read it as the hops it names.
    #[must_use]
    pub fn hops_from_seed(&self) -> Option<&str> {
        self.get(&MetadataField::HopsFromSeed)
    }

    /// How long collecting the archived URI took, in milliseconds, or `None` if the field is
    /// absent or holds something that is not a count of them.
    #[must_use]
    pub fn fetch_time_ms(&self) -> Option<u64> {
        self.get(&MetadataField::FetchTimeMs)?.parse().ok()
    }
}

/// One hop of the path a `hopsFromSeed` value describes.
///
/// The standard calls the value "a symbolic string" and fixes no alphabet for it. These are
/// the characters the annotated standard records as a community recommendation, taken from the
/// discovery path of the Heritrix crawler, and a value written by another harvester may well
/// use others. That is why a `hopsFromSeed` value is reported as written and read as hops only
/// on request: see [`HopsFromSeed`].
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum Hop {
    /// `L`: a link, such as `<a href=...>`.
    Link,
    /// `E`: an embedded resource, such as `<img src=...>` or `<script src=...>`.
    Embed,
    /// `X`: a speculative embed, a URL guessed at from the content of a script such as
    /// `<script>var url = 'http://example.org/foo.js';</script>`.
    SpeculativeEmbed,
    /// `R`: a redirect, such as the `Location` of an HTTP 302 response.
    Redirect,
    /// `P`: a prerequisite, such as `robots.txt` or a DNS lookup.
    Prerequisite,
    /// `I`: something implied, such as `favicon.ico`.
    Implied,
    /// `M`: a URL listed in a manifest, such as a sitemap file.
    Manifest,
    /// `S`: a form submission, such as `<form action=...>`.
    FormSubmission,
}

impl Hop {
    /// The character this hop is written as.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Link => 'L',
            Self::Embed => 'E',
            Self::SpeculativeEmbed => 'X',
            Self::Redirect => 'R',
            Self::Prerequisite => 'P',
            Self::Implied => 'I',
            Self::Manifest => 'M',
            Self::FormSubmission => 'S',
        }
    }

    /// The hop a character names, if it names one of these.
    #[must_use]
    pub const fn from_symbol(symbol: char) -> Option<Self> {
        match symbol {
            'L' => Some(Self::Link),
            'E' => Some(Self::Embed),
            'X' => Some(Self::SpeculativeEmbed),
            'R' => Some(Self::Redirect),
            'P' => Some(Self::Prerequisite),
            'I' => Some(Self::Implied),
            'M' => Some(Self::Manifest),
            'S' => Some(Self::FormSubmission),
            _ => None,
        }
    }
}

impl Display for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

/// A `hopsFromSeed` value read as the path it describes.
///
/// One hop per character, nearest the seed first, so `"LLE"` is an embedded resource on a page
/// two links from the seed. A seed URI itself is the empty path.
#[derive(Clone, Debug, Default, Hash, Eq, PartialEq)]
pub struct HopsFromSeed(Box<[Hop]>);

impl HopsFromSeed {
    /// The hops, in the order they were followed, nearest the seed first.
    #[must_use]
    pub fn hops(&self) -> &[Hop] {
        &self.0
    }

    /// Whether this is the empty path, which is what a seed URI itself is written with.
    #[must_use]
    pub fn is_seed(&self) -> bool {
        self.0.is_empty()
    }
}

/// A `hopsFromSeed` value is read strictly, since a character outside the recommended alphabet
/// means the value came from a harvester describing its hops some other way, and guessing at
/// what it meant would be worse than saying so.
impl FromStr for HopsFromSeed {
    type Err = UnknownHop;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .char_indices()
            .map(|(offset, symbol)| Hop::from_symbol(symbol).ok_or(UnknownHop { symbol, offset }))
            .collect::<Result<Box<[Hop]>, Self::Err>>()
            .map(Self)
    }
}

impl Display for HopsFromSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for hop in &self.0 {
            write!(f, "{hop}")?;
        }

        Ok(())
    }
}

/// An error returned by reading a `hopsFromSeed` value as [`HopsFromSeed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("`{symbol}` at byte {offset} of the value names no hop.")]
pub struct UnknownHop {
    /// The character that names no hop.
    pub symbol: char,
    /// Where in the value it appeared, as a byte offset.
    pub offset: usize,
}

#[cfg(test)]
mod tests {
    use super::{Hop, HopsFromSeed, MetadataBody, MetadataField, UnknownHop};
    use crate::fields::Field;
    use crate::fields::dcmi::DcmiTerm;

    /// Every hop the annotated standard recommends a character for.
    const KNOWN_HOPS: [Hop; 8] = [
        Hop::Link,
        Hop::Embed,
        Hop::SpeculativeEmbed,
        Hop::Redirect,
        Hop::Prerequisite,
        Hop::Implied,
        Hop::Manifest,
        Hop::FormSubmission,
    ];

    /// The `metadata` record of Annex B.5 of the standard.
    const ANNEX_EXAMPLE: &[u8] =
        b"via: http://www.archive.org/\r\nhopsFromSeed: E\r\nfetchTimeMs: 565\r\n";

    /// Each of the example's fields is recognized as the field it names, and the block is
    /// written back as it was read.
    #[test]
    fn the_annex_example_reads_as_its_fields() {
        let body = MetadataBody::parse(ANNEX_EXAMPLE).expect("annex example");

        assert_eq!(body.len(), 3);
        assert_eq!(body.via(), Some("http://www.archive.org/"));
        assert_eq!(body.hops_from_seed(), Some("E"));
        assert_eq!(body.fetch_time_ms(), Some(565));

        // Reading the hops the value names is the caller's to ask for, and this one names one.
        let hops = body.hops_from_seed().expect("hops").parse::<HopsFromSeed>();
        assert_eq!(hops.expect("hops").hops(), [Hop::Embed]);

        assert_eq!(body.to_string().as_bytes(), ANNEX_EXAMPLE);
    }

    /// A seed is written as an empty `hopsFromSeed`, which is a value rather than an absent
    /// field, and a fetch time that is not a count of milliseconds is reported as absent.
    #[test]
    fn a_seed_and_an_unreadable_fetch_time() {
        let body = MetadataBody::parse(b"hopsFromSeed:\r\nfetchTimeMs: quick\r\n").expect("seed");

        assert_eq!(body.hops_from_seed(), Some(""));
        assert_eq!(body.fetch_time_ms(), None);
        assert_eq!(body.via(), None);
    }

    /// Field names are not case-sensitive, DCMI terms are allowed alongside the standard's own
    /// fields, and an unrecognized name is kept lower-cased.
    #[test]
    fn names_are_matched_case_insensitively() {
        let body = MetadataBody::parse(
            b"VIA: one\r\nhopsfromseed: two\r\nIsPartOf: three\r\nX-Custom: four\r\n",
        )
        .expect("mixed spellings");

        assert_eq!(body.via(), Some("one"));
        assert_eq!(body.hops_from_seed(), Some("two"));
        assert_eq!(
            body.get(&MetadataField::Dcmi(DcmiTerm::IsPartOf)),
            Some("three")
        );
        assert_eq!(body.get(&MetadataField::from("x-custom")), Some("four"));
    }

    /// Each hop is written as its own character, and no two of them share one.
    #[test]
    fn every_hop_round_trips_through_its_symbol() {
        for hop in KNOWN_HOPS {
            assert_eq!(Hop::from_symbol(hop.symbol()), Some(hop));
            assert_eq!(hop.to_string(), hop.symbol().to_string());
        }

        let symbols = KNOWN_HOPS.iter().map(|hop| hop.symbol());
        assert_eq!(symbols.collect::<std::collections::HashSet<_>>().len(), 8);
    }

    /// A path is read as one hop per character, nearest the seed first, and is written back as
    /// the value it was read from. A seed is the empty path.
    #[test]
    fn a_path_round_trips_through_its_value() {
        let path = "LLE".parse::<HopsFromSeed>().expect("a path");

        assert_eq!(path.hops(), [Hop::Link, Hop::Link, Hop::Embed]);
        assert!(!path.is_seed());
        assert_eq!(path.to_string(), "LLE");

        let seed = "".parse::<HopsFromSeed>().expect("a seed");

        assert!(seed.is_seed());
        assert_eq!(seed.hops(), []);
        assert_eq!(seed.to_string(), "");
        assert_eq!(seed, HopsFromSeed::default());
    }

    /// A character outside the recommended alphabet is reported rather than guessed at, and
    /// the offset it is reported at counts bytes, as offsets into a value do elsewhere.
    #[test]
    fn a_character_that_names_no_hop_is_rejected() {
        assert_eq!(
            "LLZ".parse::<HopsFromSeed>(),
            Err(UnknownHop {
                symbol: 'Z',
                offset: 2
            })
        );

        // Values are UTF-8, so a hop path may hold characters wider than the alphabet's.
        assert_eq!(
            "L\u{00e9}L".parse::<HopsFromSeed>(),
            Err(UnknownHop {
                symbol: '\u{00e9}',
                offset: 1
            })
        );

        // Case matters: the alphabet is upper case.
        assert!("lle".parse::<HopsFromSeed>().is_err());
    }

    /// Every field the standard names for a `metadata` record is reached by its own name.
    #[test]
    fn the_standards_own_fields_are_recognized() {
        for field in MetadataField::KNOWN {
            assert_eq!(&MetadataField::from(field.name()), field);
            assert_eq!(&MetadataField::from(field.name().to_uppercase()), field);
        }
    }
}
