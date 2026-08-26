//! Rule 1: header fields appear in canonical order.

use archivindex_warc::parse::untyped;
use archivindex_warc::parse::untyped::name::Field;

use crate::lint::Violation;

/// Report the first adjacent pair whose ranks descend.
pub fn canonical_order_violation(header: &untyped::RecordHeader) -> Option<Violation> {
    header.headers.windows(2).find_map(|pair| {
        let preceding = &pair[0].0;
        let following = &pair[1].0;
        let rank = |field: Option<Field>| field.map_or(usize::MAX, Field::canonical_rank);
        (rank(preceding.field()) > rank(following.field())).then(|| {
            Violation::NonCanonicalHeaderOrder {
                preceding: preceding.name().to_owned(),
                following: following.name().to_owned(),
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    #[test]
    fn header_fields_are_in_canonical_order() {
        let records = [warcinfo(), resource(OTHER_ID).in_written_order()];

        assert_eq!(
            findings(&records),
            [(
                1,
                Violation::NonCanonicalHeaderOrder {
                    preceding: "WARC-Record-ID".to_owned(),
                    following: "WARC-Date".to_owned(),
                }
            )]
        );
    }
}
