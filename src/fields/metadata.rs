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
    /// URI to the current URI, one character per hop, empty for a seed itself. The characters
    /// come from the discovery path of the Heritrix crawler: `L` for a link, `E` for an
    /// embed, `X` for a speculative embed, `R` for a redirect, `P` for a prerequisite such as
    /// `robots.txt`, `I` for something implied such as `favicon.ico`, `M` for a URL listed in
    /// a manifest such as a sitemap, and `S` for a form submission.
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

#[cfg(test)]
mod tests {
    use super::{MetadataBody, MetadataField};
    use crate::fields::Field;
    use crate::fields::dcmi::DcmiTerm;

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

    /// Every field the standard names for a `metadata` record is reached by its own name.
    #[test]
    fn the_standards_own_fields_are_recognized() {
        for field in MetadataField::KNOWN {
            assert_eq!(&MetadataField::from(field.name()), field);
            assert_eq!(&MetadataField::from(field.name().to_uppercase()), field);
        }
    }
}
