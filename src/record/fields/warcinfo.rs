//! The body of a `warcinfo` record, read as `application/warc-fields`.
//!
//! A `warcinfo` record opens a WARC file and describes the file or the crawl that produced it.
//! Its body is recommended to be `application/warc-fields`, and the standard says its allowable
//! fields "include, but are not limited to, all \[DCMI\]" terms plus seven of its own. Every field
//! is optional and may repeat, so [`WarcinfoBody`] keeps the fields in the order they were written
//! and lets a name appear more than once. It also retains the source block for byte-exact
//! round-tripping, which keeps any digest over the block verifiable.
//!
//! ```
//! use archivindex_warc::record::fields::dcmi::DcmiTerm;
//! use archivindex_warc::record::fields::warcinfo::{WarcinfoBody, WarcinfoField};
//!
//! let body = WarcinfoBody::parse(
//!     b"software: Heritrix 1.12.0 http://crawler.archive.org\r\n\
//!       ip: 207.241.227.234\r\n\
//!       isPartOf: testcrawl-20050708\r\n",
//! )?;
//!
//! assert_eq!(body.software(), Some("Heritrix 1.12.0 http://crawler.archive.org"));
//! assert_eq!(body.ip(), "207.241.227.234".parse().ok());
//! assert_eq!(
//!     body.get(&WarcinfoField::Dcmi(DcmiTerm::IsPartOf)),
//!     Some("testcrawl-20050708")
//! );
//! # Ok::<(), archivindex_warc::record::fields::Error>(())
//! ```

use std::fmt::Display;
use std::net::IpAddr;

use crate::record::fields::dcmi::DcmiTerm;
use crate::record::fields::{Body, Field};

/// A field of a `warcinfo` record's body.
///
/// The seven variants defined for `warcinfo` come first. Any DCMI metadata term is a
/// [`Dcmi`](Self::Dcmi), and anything else is an [`Other`](Self::Other). The standard invites
/// further fields, naming "technical information such as base encoding of the digests used in
/// named fields" as an example.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum WarcinfoField {
    /// `operator`: contact information for the operator who created this WARC resource. A name
    /// or a name and email address is recommended.
    Operator,
    /// `software`: the software and software version used to create this WARC resource, such
    /// as `heritrix/1.12.0`.
    Software,
    /// `robots`: the robots policy followed by the harvester creating this WARC resource. The
    /// value `classic` means the 1994 web robots exclusion standard rules are being obeyed.
    Robots,
    /// `hostname`: the hostname of the machine that created this WARC resource, such as
    /// `crawling17.archive.org`.
    Hostname,
    /// `ip`: the IP address of the machine that created this WARC resource.
    Ip,
    /// `http-header-user-agent`: the HTTP `user-agent` header the harvester usually sent with
    /// each request. A `request` or `metadata` record reporting a different one for a specific
    /// request is the more reliable of the two.
    HttpHeaderUserAgent,
    /// `http-header-from`: the HTTP `from` header the harvester usually sent with each
    /// request, subject to the same caveat as the `user-agent` above.
    HttpHeaderFrom,
    /// A metadata term from the DCMI vocabulary, all of which are allowed here.
    Dcmi(DcmiTerm),
    /// Any other field, held under the lower-cased spelling of its name.
    Other(String),
}

impl Field for WarcinfoField {
    const KNOWN: &'static [Self] = &[
        Self::Operator,
        Self::Software,
        Self::Robots,
        Self::Hostname,
        Self::Ip,
        Self::HttpHeaderUserAgent,
        Self::HttpHeaderFrom,
    ];

    fn name(&self) -> &str {
        match self {
            Self::Operator => "operator",
            Self::Software => "software",
            Self::Robots => "robots",
            Self::Hostname => "hostname",
            Self::Ip => "ip",
            Self::HttpHeaderUserAgent => "http-header-user-agent",
            Self::HttpHeaderFrom => "http-header-from",
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

impl Display for WarcinfoField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl<S: AsRef<str>> From<S> for WarcinfoField {
    fn from(string: S) -> Self {
        Self::from_name(string.as_ref())
    }
}

/// The body of a `warcinfo` record, read as `application/warc-fields`.
pub type WarcinfoBody = Body<WarcinfoField>;

impl WarcinfoBody {
    /// Contact information for the operator who created this WARC resource.
    #[must_use]
    pub fn operator(&self) -> Option<&str> {
        self.get(&WarcinfoField::Operator)
    }

    /// The software and software version used to create this WARC resource.
    #[must_use]
    pub fn software(&self) -> Option<&str> {
        self.get(&WarcinfoField::Software)
    }

    /// The robots policy followed by the harvester, where `classic` means the 1994 web robots
    /// exclusion standard rules are being obeyed.
    #[must_use]
    pub fn robots(&self) -> Option<&str> {
        self.get(&WarcinfoField::Robots)
    }

    /// The hostname of the machine that created this WARC resource.
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.get(&WarcinfoField::Hostname)
    }

    /// The IP address of the machine that created this WARC resource, or `None` if the field
    /// is absent or holds something that is not an address.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.get(&WarcinfoField::Ip)?.parse().ok()
    }

    /// The HTTP `user-agent` header the harvester usually sent with each request.
    #[must_use]
    pub fn http_header_user_agent(&self) -> Option<&str> {
        self.get(&WarcinfoField::HttpHeaderUserAgent)
    }

    /// The HTTP `from` header the harvester usually sent with each request.
    #[must_use]
    pub fn http_header_from(&self) -> Option<&str> {
        self.get(&WarcinfoField::HttpHeaderFrom)
    }
}

#[cfg(test)]
mod tests {
    use super::{WarcinfoBody, WarcinfoField};
    use crate::record::fields::Field;
    use crate::record::fields::dcmi::DcmiTerm;

    /// The `warcinfo` example from Annex B.1 of the standard.
    const ANNEX_EXAMPLE: &[u8] = b"software: Heritrix 1.12.0 http://crawler.archive.org\r\n\
        hostname: crawling017.archive.org\r\n\
        ip: 207.241.227.234\r\n\
        isPartOf: testcrawl-20050708\r\n\
        description: testcrawl with WARC output\r\n\
        operator: IA_Admin\r\n\
        http-header-user-agent:\r\n\
        \x20Mozilla/5.0 (compatible; heritrix/1.4.0 +http://crawler.archive.org)\r\n\
        format: WARC file version 1.1\r\n\
        conformsTo:\r\n\
        \x20http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/\r\n";

    /// Each of the example's fields is recognized as the field it names, each folded value is
    /// joined with the single space a fold stands for, and the block is written back as it was
    /// read.
    #[test]
    fn the_annex_example_reads_as_its_fields() {
        let body = WarcinfoBody::parse(ANNEX_EXAMPLE).expect("annex example");

        assert_eq!(body.len(), 9);
        assert_eq!(
            body.software(),
            Some("Heritrix 1.12.0 http://crawler.archive.org")
        );
        assert_eq!(body.hostname(), Some("crawling017.archive.org"));
        assert_eq!(body.ip(), "207.241.227.234".parse().ok());
        assert_eq!(body.operator(), Some("IA_Admin"));
        assert_eq!(
            body.http_header_user_agent(),
            Some("Mozilla/5.0 (compatible; heritrix/1.4.0 +http://crawler.archive.org)")
        );
        assert_eq!(
            body.get(&WarcinfoField::Dcmi(DcmiTerm::IsPartOf)),
            Some("testcrawl-20050708")
        );
        assert_eq!(
            body.get(&WarcinfoField::Dcmi(DcmiTerm::Format)),
            Some("WARC file version 1.1")
        );
        assert_eq!(
            body.get(&WarcinfoField::Dcmi(DcmiTerm::ConformsTo)),
            Some("http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/")
        );

        // Nothing the example does not write is reported as present.
        assert_eq!(body.robots(), None);
        assert_eq!(body.http_header_from(), None);

        assert_eq!(body.to_string().as_bytes(), ANNEX_EXAMPLE);
    }

    /// Field names are not case-sensitive, and an unrecognized name is kept lower-cased so
    /// that two spellings of one extension field are still the same field.
    #[test]
    fn names_are_matched_case_insensitively() {
        let body = WarcinfoBody::parse(
            b"SOFTWARE: one\r\nIsPartOf: two\r\nHTTP-Header-From: three\r\nX-Custom: four\r\n",
        )
        .expect("mixed spellings");

        assert_eq!(body.software(), Some("one"));
        assert_eq!(
            body.get(&WarcinfoField::Dcmi(DcmiTerm::IsPartOf)),
            Some("two")
        );
        assert_eq!(body.http_header_from(), Some("three"));
        assert_eq!(body.get(&WarcinfoField::from("x-custom")), Some("four"));
        assert_eq!(
            body.iter().map(|(field, _)| field.name()).last(),
            Some("x-custom")
        );
    }

    /// Every field the standard names for a `warcinfo` record is reached by its own name, and
    /// no two of them share one.
    #[test]
    fn the_standards_own_fields_are_recognized() {
        for field in WarcinfoField::KNOWN {
            assert_eq!(&WarcinfoField::from(field.name()), field);
            assert_eq!(&WarcinfoField::from(field.name().to_uppercase()), field);
        }
    }
}
