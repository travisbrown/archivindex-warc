//! The metadata properties of the DCMI Metadata Terms vocabulary.
//!
//! WARC fields may use properties from [DCMI Metadata Terms]. This module provides their names and
//! URIs.
//!
//! Fifteen of the 55 terms also belong to the older Dublin Core Metadata Element Set.
//! [`DcmiTerm::is_element`] identifies them.
//!
//! [DCMI Metadata Terms]: https://www.dublincore.org/specifications/dublin-core/dcmi-terms/

use std::fmt::Display;

/// The namespace the 55 DCMI Metadata Terms properties are published in.
pub const TERMS_NAMESPACE: &str = "http://purl.org/dc/terms/";

/// The namespace the 15 legacy Dublin Core Metadata Element Set properties are published in.
///
/// Terms for which [`DcmiTerm::is_element`] is true also have a URI in this namespace.
pub const ELEMENTS_NAMESPACE: &str = "http://purl.org/dc/elements/1.1/";

/// A property of the DCMI Metadata Terms vocabulary.
///
/// Each variant uses the name published by DCMI. Names outside this closed vocabulary are extension
/// fields.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum DcmiTerm {
    Abstract,
    AccessRights,
    AccrualMethod,
    AccrualPeriodicity,
    AccrualPolicy,
    Alternative,
    Audience,
    Available,
    BibliographicCitation,
    ConformsTo,
    Contributor,
    Coverage,
    Created,
    Creator,
    Date,
    DateAccepted,
    DateCopyrighted,
    DateSubmitted,
    Description,
    EducationLevel,
    Extent,
    Format,
    HasFormat,
    HasPart,
    HasVersion,
    Identifier,
    InstructionalMethod,
    IsFormatOf,
    IsPartOf,
    IsReferencedBy,
    IsReplacedBy,
    IsRequiredBy,
    IsVersionOf,
    Issued,
    Language,
    License,
    Mediator,
    Medium,
    Modified,
    Provenance,
    Publisher,
    References,
    Relation,
    Replaces,
    Requires,
    Rights,
    RightsHolder,
    Source,
    Spatial,
    Subject,
    TableOfContents,
    Temporal,
    Title,
    Type,
    Valid,
}

impl DcmiTerm {
    /// The property's name, which is both the last segment of its URI and the field name it is
    /// written under in a `warcinfo` record.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Abstract => "abstract",
            Self::AccessRights => "accessRights",
            Self::AccrualMethod => "accrualMethod",
            Self::AccrualPeriodicity => "accrualPeriodicity",
            Self::AccrualPolicy => "accrualPolicy",
            Self::Alternative => "alternative",
            Self::Audience => "audience",
            Self::Available => "available",
            Self::BibliographicCitation => "bibliographicCitation",
            Self::ConformsTo => "conformsTo",
            Self::Contributor => "contributor",
            Self::Coverage => "coverage",
            Self::Created => "created",
            Self::Creator => "creator",
            Self::Date => "date",
            Self::DateAccepted => "dateAccepted",
            Self::DateCopyrighted => "dateCopyrighted",
            Self::DateSubmitted => "dateSubmitted",
            Self::Description => "description",
            Self::EducationLevel => "educationLevel",
            Self::Extent => "extent",
            Self::Format => "format",
            Self::HasFormat => "hasFormat",
            Self::HasPart => "hasPart",
            Self::HasVersion => "hasVersion",
            Self::Identifier => "identifier",
            Self::InstructionalMethod => "instructionalMethod",
            Self::IsFormatOf => "isFormatOf",
            Self::IsPartOf => "isPartOf",
            Self::IsReferencedBy => "isReferencedBy",
            Self::IsReplacedBy => "isReplacedBy",
            Self::IsRequiredBy => "isRequiredBy",
            Self::IsVersionOf => "isVersionOf",
            Self::Issued => "issued",
            Self::Language => "language",
            Self::License => "license",
            Self::Mediator => "mediator",
            Self::Medium => "medium",
            Self::Modified => "modified",
            Self::Provenance => "provenance",
            Self::Publisher => "publisher",
            Self::References => "references",
            Self::Relation => "relation",
            Self::Replaces => "replaces",
            Self::Requires => "requires",
            Self::Rights => "rights",
            Self::RightsHolder => "rightsHolder",
            Self::Source => "source",
            Self::Spatial => "spatial",
            Self::Subject => "subject",
            Self::TableOfContents => "tableOfContents",
            Self::Temporal => "temporal",
            Self::Title => "title",
            Self::Type => "type",
            Self::Valid => "valid",
        }
    }

    /// The property's URI in the DCMI Metadata Terms namespace.
    ///
    /// A term for which [`is_element`](Self::is_element) holds has a second URI, built the same
    /// way from [`ELEMENTS_NAMESPACE`].
    #[must_use]
    pub fn uri(&self) -> String {
        format!("{TERMS_NAMESPACE}{}", self.name())
    }

    /// Whether this property is one of the 15 that make up the Dublin Core Metadata Element
    /// Set, the older and much more widely used vocabulary that DCMI Metadata Terms subsumes.
    #[must_use]
    pub const fn is_element(&self) -> bool {
        matches!(
            self,
            Self::Contributor
                | Self::Coverage
                | Self::Creator
                | Self::Date
                | Self::Description
                | Self::Format
                | Self::Identifier
                | Self::Language
                | Self::Publisher
                | Self::Relation
                | Self::Rights
                | Self::Source
                | Self::Subject
                | Self::Title
                | Self::Type
        )
    }

    /// The term written under this field name, if the name is one DCMI defines.
    ///
    /// Field names in a `warcinfo` record are not case-sensitive, so the comparison is not either,
    /// and a name matched in any spelling is returned in its canonical one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        KNOWN_TERMS
            .iter()
            .copied()
            .find(|term| name.eq_ignore_ascii_case(term.name()))
    }
}

impl Display for DcmiTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Every property DCMI defines, in the alphabetical order the specification lists them in.
///
/// This is the table [`DcmiTerm::from_name`] looks a name up in.
const KNOWN_TERMS: [DcmiTerm; 55] = [
    DcmiTerm::Abstract,
    DcmiTerm::AccessRights,
    DcmiTerm::AccrualMethod,
    DcmiTerm::AccrualPeriodicity,
    DcmiTerm::AccrualPolicy,
    DcmiTerm::Alternative,
    DcmiTerm::Audience,
    DcmiTerm::Available,
    DcmiTerm::BibliographicCitation,
    DcmiTerm::ConformsTo,
    DcmiTerm::Contributor,
    DcmiTerm::Coverage,
    DcmiTerm::Created,
    DcmiTerm::Creator,
    DcmiTerm::Date,
    DcmiTerm::DateAccepted,
    DcmiTerm::DateCopyrighted,
    DcmiTerm::DateSubmitted,
    DcmiTerm::Description,
    DcmiTerm::EducationLevel,
    DcmiTerm::Extent,
    DcmiTerm::Format,
    DcmiTerm::HasFormat,
    DcmiTerm::HasPart,
    DcmiTerm::HasVersion,
    DcmiTerm::Identifier,
    DcmiTerm::InstructionalMethod,
    DcmiTerm::IsFormatOf,
    DcmiTerm::IsPartOf,
    DcmiTerm::IsReferencedBy,
    DcmiTerm::IsReplacedBy,
    DcmiTerm::IsRequiredBy,
    DcmiTerm::IsVersionOf,
    DcmiTerm::Issued,
    DcmiTerm::Language,
    DcmiTerm::License,
    DcmiTerm::Mediator,
    DcmiTerm::Medium,
    DcmiTerm::Modified,
    DcmiTerm::Provenance,
    DcmiTerm::Publisher,
    DcmiTerm::References,
    DcmiTerm::Relation,
    DcmiTerm::Replaces,
    DcmiTerm::Requires,
    DcmiTerm::Rights,
    DcmiTerm::RightsHolder,
    DcmiTerm::Source,
    DcmiTerm::Spatial,
    DcmiTerm::Subject,
    DcmiTerm::TableOfContents,
    DcmiTerm::Temporal,
    DcmiTerm::Title,
    DcmiTerm::Type,
    DcmiTerm::Valid,
];

#[cfg(test)]
mod tests {
    use super::{DcmiTerm, ELEMENTS_NAMESPACE, KNOWN_TERMS, TERMS_NAMESPACE};

    /// Every term is reachable by its own name.
    #[test]
    fn every_term_round_trips_through_its_name() {
        for term in KNOWN_TERMS {
            assert_eq!(DcmiTerm::from_name(term.name()), Some(term), "{term}");
        }
    }

    /// No two terms share a name.
    #[test]
    fn term_names_are_distinct() {
        let mut names: Vec<&str> = KNOWN_TERMS.iter().map(DcmiTerm::name).collect();
        names.sort_unstable();
        let distinct = names.len();
        names.dedup();

        assert_eq!(names.len(), distinct);
    }

    /// Field names are not case-sensitive, so a term is found however it was spelled, and it
    /// comes back in the canonical spelling.
    #[test]
    fn names_are_matched_case_insensitively() {
        for name in ["isPartOf", "ispartof", "ISPARTOF", "IsPartOf"] {
            assert_eq!(
                DcmiTerm::from_name(name),
                Some(DcmiTerm::IsPartOf),
                "{name}"
            );
        }

        assert_eq!(DcmiTerm::IsPartOf.name(), "isPartOf");
    }

    /// A name outside the vocabulary is not a term.
    #[test]
    fn names_outside_the_vocabulary_are_not_terms() {
        for name in [
            "",
            "software",
            "is-part-of",
            "isPartOfSomething",
            "x-custom",
        ] {
            assert_eq!(DcmiTerm::from_name(name), None, "{name}");
        }
    }

    /// Exactly the 15 properties of the Dublin Core Metadata Element Set are elements.
    #[test]
    fn the_fifteen_legacy_elements_are_marked() {
        let elements: Vec<&str> = KNOWN_TERMS
            .iter()
            .filter(|term| term.is_element())
            .map(DcmiTerm::name)
            .collect();

        assert_eq!(
            elements,
            [
                "contributor",
                "coverage",
                "creator",
                "date",
                "description",
                "format",
                "identifier",
                "language",
                "publisher",
                "relation",
                "rights",
                "source",
                "subject",
                "title",
                "type",
            ]
        );
    }

    /// A term's URI is its name in the terms namespace, and an element has a second one in the
    /// legacy namespace built the same way.
    #[test]
    fn uris_are_built_from_the_namespaces() {
        assert_eq!(
            DcmiTerm::ConformsTo.uri(),
            "http://purl.org/dc/terms/conformsTo"
        );
        assert_eq!(DcmiTerm::Title.uri(), format!("{TERMS_NAMESPACE}title"));
        assert_eq!(
            format!("{ELEMENTS_NAMESPACE}{}", DcmiTerm::Title),
            "http://purl.org/dc/elements/1.1/title"
        );
    }
}
