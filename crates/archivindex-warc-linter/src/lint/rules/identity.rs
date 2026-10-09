//! Rule 10: a record identifier is a UUID URN or the one the Archivindex identity scheme derives
//! from its record.

use std::io::BufRead;

use archivindex_warc::record::Record;
use archivindex_warc_identifier::{IdentityV1, RECORD_ID_PREFIX};

use crate::lint::{Linter, Violation};

const UUID_URN_PREFIX: &str = "urn:uuid:";

impl<R: BufRead> Linter<'_, R> {
    /// Check that a record's identifier is the one the Archivindex identity scheme derives from the
    /// record, or a UUID URN if the pass accepts one.
    pub(crate) fn check_identity(&mut self, index: usize, record: &Record) {
        if let Some(violation) = identity_violation(record, self.require_archivindex_ids) {
            self.fault(index, record, violation);
        }
    }
}

/// What is wrong with a record's identifier, if anything is.
///
/// An identifier does not name the version of the scheme it was derived under, so it is compared
/// with the one version 1 derives. Version 1 is the scheme's only version.
fn identity_violation(record: &Record, require_archivindex_id: bool) -> Option<Violation> {
    let record_id = &record.core().record_id;

    if require_archivindex_id || record_id.as_str().starts_with(RECORD_ID_PREFIX) {
        match IdentityV1::from_record(record) {
            Ok(identity) => {
                let computed = identity.uri();

                (computed != *record_id).then_some(Violation::RecordIdMismatch { computed })
            }
            Err(error) => Some(Violation::UnderivableRecordId {
                reason: error.to_string(),
            }),
        }
    } else {
        (!is_uuid_urn(record_id.as_str())).then_some(Violation::UnrecognizedRecordId)
    }
}

/// Whether `id` is a UUID in the URN form RFC 9562 gives it. The form is not case-sensitive.
fn is_uuid_urn(id: &str) -> bool {
    id.split_at_checked(UUID_URN_PREFIX.len())
        .is_some_and(|(prefix, uuid)| {
            prefix.eq_ignore_ascii_case(UUID_URN_PREFIX)
                && uuid.len() == 36
                && uuid.bytes().enumerate().all(|(index, byte)| match index {
                    8 | 13 | 18 | 23 => byte == b'-',
                    _ => byte.is_ascii_hexdigit(),
                })
        })
}

#[cfg(test)]
mod tests {
    use archivindex_warc::io::read::WarcReader;
    use archivindex_warc_identifier::Error;

    use super::*;
    use crate::lint::fixtures::*;

    /// The findings of a pass that requires Archivindex identifiers.
    fn strict_findings(records: &[TestRecord]) -> Vec<(usize, Violation)> {
        faults(
            Linter::new(WarcReader::new(&render(records)[..]))
                .require_archivindex_ids(true)
                .collect::<Result<_, _>>()
                .expect("every record reads"),
        )
    }

    /// The fixture derives each identifier from the record as written and the linter from the
    /// record as parsed, so a clean pass also shows that the two derivations agree for every record
    /// type a capture holds.
    #[test]
    fn identifiers_the_scheme_derives_are_clean() {
        let records = identified(&capture());

        assert_eq!(
            lint(&records),
            records
                .iter()
                .map(|record| Ok(derived_id(record)))
                .collect::<Vec<_>>()
        );
        assert_eq!(strict_findings(&records), []);
    }

    /// An identifier is stale once the record it was derived from changes, here in the fetch time
    /// its block states.
    #[test]
    fn an_identifier_the_scheme_does_not_derive_is_reported() {
        let mut records = identified(&capture());
        records[3].body = "fetchTimeMs: 13\r\n".to_owned();

        assert_eq!(
            findings(&records),
            [(
                3,
                Violation::RecordIdMismatch {
                    computed: derived_id(&records[3]),
                }
            )]
        );
    }

    /// The scheme identifies no `resource` record, so no identifier under it can be right for one,
    /// and no identifier satisfies a pass that requires the scheme's.
    #[test]
    fn a_record_the_scheme_cannot_identify_is_reported() {
        let violation = Violation::UnderivableRecordId {
            reason: Error::UnsupportedRecordType("resource".to_owned()).to_string(),
        };
        let scheme_id = format!("{RECORD_ID_PREFIX}{}", "0".repeat(64));
        let records = [warcinfo(), resource(OTHER_ID)];

        assert_eq!(
            findings(&[warcinfo(), resource(&scheme_id)]),
            [(1, violation.clone())]
        );
        assert_eq!(
            strict_findings(&records),
            [
                (
                    0,
                    Violation::RecordIdMismatch {
                        computed: derived_id(&records[0]),
                    }
                ),
                (1, violation)
            ]
        );
    }

    /// A UUID does not claim to be derived from its record, so it is accepted unless the pass
    /// requires the scheme's identifiers. A pass that does reports the identifier each record
    /// should carry instead.
    #[test]
    fn a_uuid_is_accepted_unless_archivindex_identifiers_are_required() {
        let records = capture();

        assert_eq!(findings(&records), []);
        assert_eq!(
            strict_findings(&records),
            records
                .iter()
                .enumerate()
                .map(|(index, record)| (
                    index,
                    Violation::RecordIdMismatch {
                        computed: derived_id(record),
                    }
                ))
                .collect::<Vec<_>>()
        );
    }

    /// The first two identifiers are UUIDs in spellings other than the lowercase one the fixtures
    /// use. The rest are not UUID URNs: a UUID that is too short, one without its hyphens, one
    /// under another URN namespace, and a URI resembling the scheme's.
    #[test]
    fn an_identifier_of_neither_kind_is_reported() {
        let rule = |id: &str| findings(&[warcinfo(), resource(id)]);

        for id in [
            "urn:uuid:EEEEEEEE-0000-4000-8000-000000000000",
            "URN:UUID:eeeeeeee-0000-4000-8000-000000000000",
        ] {
            assert_eq!(rule(id), [], "{id}");
        }
        for id in [
            "urn:uuid:eeeeeeee-0000-4000-8000-00000000000",
            "urn:uuid:eeeeeeee000040008000000000000000",
            "urn:isbn:eeeeeeee-0000-4000-8000-000000000000",
            "https://archivindex.org/records/1",
        ] {
            assert_eq!(rule(id), [(1, Violation::UnrecognizedRecordId)], "{id}");
        }
    }
}
