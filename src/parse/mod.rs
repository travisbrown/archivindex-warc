//! Shared types for the raw and untyped record representations.

pub mod raw;
pub mod untyped;

use crate::version::WarcVersion;

/// A record's header block: the version it declares, and the field lines that follow.
///
/// `N` and `V` are the types that represent the field names and values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordHeader<N, V> {
    /// The WARC standard version declared by this record header.
    pub version: WarcVersion,
    /// Every field line, in the order it appeared, as a name and the value written for it.
    ///
    /// A sequence preserves repeated fields and supports byte-exact round-tripping.
    pub headers: Vec<(N, V)>,
}

impl<N, V> RecordHeader<N, V> {
    /// A header block declaring the given version, with no fields.
    #[must_use]
    pub const fn new(version: WarcVersion) -> Self {
        Self {
            version,
            headers: Vec::new(),
        }
    }

    /// Attach a body, giving a record.
    #[must_use]
    pub fn with_body<B: Into<Vec<u8>>>(self, body: B) -> Record<N, V> {
        Record {
            header: self,
            body: body.into(),
        }
    }

    /// The value of the first field whose name the predicate accepts.
    pub fn find(&self, matches: impl FnMut(&N) -> bool) -> Option<&V> {
        self.find_all(matches).next()
    }

    /// The values of every field whose name the predicate accepts, in the order they appear.
    pub fn find_all<F: FnMut(&N) -> bool>(&self, mut matches: F) -> impl Iterator<Item = &V> {
        self.headers
            .iter()
            .filter_map(move |(name, value)| matches(name).then_some(value))
    }
}

/// A WARC record: a header block, and the block of octets it frames.
///
/// `N` and `V` are the types that represent the field names and values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record<N, V> {
    /// The record header.
    pub header: RecordHeader<N, V>,
    /// The record's content block, read in full.
    pub body: Vec<u8>,
}

impl<N, V> Record<N, V> {
    /// The length of the record's content block.
    ///
    /// This measures the block itself. [`raw::Record::validate`] compares it with the declared
    /// `Content-Length`.
    #[must_use]
    pub fn content_length(&self) -> u64 {
        self.body.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::RecordHeader;
    use crate::version::WarcVersion;

    /// A generic header used to test the shared lookup methods.
    fn header() -> RecordHeader<u8, u8> {
        let mut header = RecordHeader::new(WarcVersion::V1_1);
        header.headers = vec![(1, 10), (2, 20), (1, 30)];

        header
    }

    #[test]
    fn finds_the_first_matching_field() {
        let header = header();

        assert_eq!(header.find(|name| *name == 1), Some(&10));
        assert_eq!(header.find(|name| *name == 2), Some(&20));
        assert_eq!(header.find(|name| *name == 3), None);
    }

    #[test]
    fn finds_every_matching_field_in_order() {
        let header = header();

        assert_eq!(
            header.find_all(|name| *name == 1).collect::<Vec<_>>(),
            [&10, &30]
        );
        assert_eq!(header.find_all(|name| *name == 3).count(), 0);
    }

    #[test]
    fn measures_the_body_it_is_given() {
        assert_eq!(header().with_body(b"12345".to_vec()).content_length(), 5);
    }
}
