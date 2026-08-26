//! Rules 2, 3, 8, and 9: the `warcinfo` record that opens a file, the one each record names, the
//! collection a `warcinfo` record names, and the host the requests under it target.

use std::io::BufRead;

use archivindex_warc::record::fields::dcmi::DcmiTerm;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::record::header::WarcinfoHeader;
use archivindex_warc::record::{FieldsBlock, Record};
use archivindex_warc::value::Text;
use fluent_uri::Uri;

use crate::lint::{Linter, Violation};

impl<R: BufRead> Linter<R> {
    /// Check that the file opens with a `warcinfo` record and that every other record names the
    /// closest one, that a `warcinfo` record names its collection and is in the file named for
    /// it, and that a `request` record targets the collection's host.
    pub(crate) fn check_warcinfo(&mut self, index: usize, record: &Record) {
        let record_id = &record.core().record_id;

        if index == 0 && !matches!(record, Record::Warcinfo { .. }) {
            self.report(
                index,
                record_id,
                Violation::FirstRecordNotWarcinfo {
                    found: record.type_name().to_owned(),
                },
            );
        }

        if let Record::Warcinfo { header, body } = record {
            self.warcinfo_id = Some(record_id.clone());
            self.check_collection(index, header, body);
        } else {
            match record.warcinfo_id() {
                None => self.report(index, record_id, Violation::MissingWarcinfoId),
                Some(found) if Some(found) != self.warcinfo_id.as_ref() => self.report(
                    index,
                    record_id,
                    Violation::WrongWarcinfoId {
                        expected: self.warcinfo_id.clone(),
                        found: found.clone(),
                    },
                ),
                Some(_) => {}
            }
        }

        if let Record::Request { header, .. } = record
            && let Some(violation) = self
                .collection_host
                .as_deref()
                .and_then(|expected| wrong_host(expected, &header.target_uri))
        {
            self.report(index, record_id, violation);
        }
    }

    /// Check that a `warcinfo` record names a well-formed collection and is in the file named for
    /// it, and remember the collection's host for the requests that follow.
    fn check_collection(
        &mut self,
        index: usize,
        header: &WarcinfoHeader,
        body: &FieldsBlock<WarcinfoField>,
    ) {
        let collection = match body {
            FieldsBlock::Fields(fields) => fields.get(&WarcinfoField::Dcmi(DcmiTerm::IsPartOf)),
            FieldsBlock::Raw(_) => None,
        };
        self.collection_host = None;
        let Some(collection) = collection else {
            self.report(
                index,
                &header.core.record_id,
                Violation::MissingCollectionId,
            );
            return;
        };

        match collection_host(collection) {
            Some(host) => self.collection_host = Some(host.to_owned()),
            None => self.report(
                index,
                &header.core.record_id,
                Violation::MalformedCollectionId {
                    found: collection.to_owned(),
                },
            ),
        }

        let named_for_collection = header
            .filename
            .as_ref()
            .and_then(Text::to_str)
            .and_then(|name| name.strip_suffix(".warc.gz"))
            == Some(collection);
        if !named_for_collection {
            self.report(
                index,
                &header.core.record_id,
                Violation::WrongFilename {
                    expected: format!("{collection}.warc.gz"),
                    found: header.filename.clone(),
                },
            );
        }
    }
}

/// The host of a collection identifier, which is a host, any number of path parts, and a timestamp
/// of digits, all joined by `-`.
///
/// A path part holds no `.`, which tells it from the host. Returns `None` for an identifier not of
/// that form.
fn collection_host(collection: &str) -> Option<&str> {
    let (mut host, timestamp) = collection.rsplit_once('-')?;
    if timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    while let Some((head, part)) = host.rsplit_once('-')
        && !part.contains('.')
    {
        if part.is_empty() {
            return None;
        }
        host = head;
    }

    (!host.is_empty()).then_some(host)
}

/// Report a target URI whose host is not the expected one, which RFC 3986 clause 3.2.2 compares
/// without regard to ASCII case.
fn wrong_host(expected: &str, target_uri: &Uri<String>) -> Option<Violation> {
    let host = target_uri.authority().map(|authority| authority.host());
    host.is_none_or(|host| !host.eq_ignore_ascii_case(expected))
        .then(|| Violation::WrongRequestHost {
            expected: expected.to_owned(),
            found: host.map(ToOwned::to_owned),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::fixtures::*;

    #[test]
    fn the_first_record_must_be_a_warcinfo_record() {
        let records = capture()[1..].to_vec();

        assert_eq!(
            findings(&records),
            [
                (
                    0,
                    Violation::FirstRecordNotWarcinfo {
                        found: "request".to_owned()
                    }
                ),
                (
                    0,
                    Violation::WrongWarcinfoId {
                        expected: None,
                        found: uri(WARCINFO_ID)
                    }
                ),
                (
                    1,
                    Violation::WrongWarcinfoId {
                        expected: None,
                        found: uri(WARCINFO_ID)
                    }
                ),
                (
                    2,
                    Violation::WrongWarcinfoId {
                        expected: None,
                        found: uri(WARCINFO_ID)
                    }
                ),
            ]
        );
    }

    #[test]
    fn every_record_names_the_closest_preceding_warcinfo_record() {
        let mut records = capture();
        records[1] = records[1].clone().without("WARC-Warcinfo-ID");
        records[2] = records[2]
            .clone()
            .set("WARC-Warcinfo-ID", &format!("<{OTHER_ID}>"));
        records.push(warcinfo_with_id(OTHER_ID));
        records.push(resource(&other_id(1)));

        assert_eq!(
            findings(&records),
            [
                (1, Violation::MissingWarcinfoId),
                (
                    2,
                    Violation::WrongWarcinfoId {
                        expected: Some(uri(WARCINFO_ID)),
                        found: uri(OTHER_ID)
                    }
                ),
                (
                    5,
                    Violation::WrongWarcinfoId {
                        expected: Some(uri(OTHER_ID)),
                        found: uri(WARCINFO_ID)
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_warcinfo_record_names_its_collection_and_its_file() {
        let mut records = capture();
        records[0].body = "software: test\r\n".to_owned();
        records.push(warcinfo_with_id(OTHER_ID).without("WARC-Filename"));
        records.push(warcinfo_with_id(&other_id(1)).set("WARC-Filename", "other.warc"));

        assert_eq!(
            findings(&records),
            [
                (0, Violation::MissingCollectionId),
                (
                    4,
                    Violation::WrongFilename {
                        expected: FILENAME.to_owned(),
                        found: None
                    }
                ),
                (
                    5,
                    Violation::WrongFilename {
                        expected: FILENAME.to_owned(),
                        found: Text::parse(b"other.warc").ok()
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_collection_id_is_a_host_path_parts_and_a_timestamp() {
        for (collection, host) in [
            ("example.com-en-20240401120000", Some("example.com")),
            ("example.com-en-mobile-20240401120000", Some("example.com")),
            ("my-site.com-en-20240401120000", Some("my-site.com")),
            ("localhost-20240401120000", Some("localhost")),
            ("example.com--20240401120000", None),
            ("-en-20240401120000", None),
        ] {
            assert_eq!(collection_host(collection), host, "{collection}");
        }

        let malformed = [HOST, "example.com-", "-20240401120000", "example.com-today"];
        let mut records = capture();
        for (index, collection) in malformed.into_iter().enumerate() {
            let identifier = other_id(index);
            let mut warcinfo = warcinfo_with_id(&identifier);
            warcinfo.body = format!("software: test\r\nisPartOf: {collection}\r\n");
            records.push(warcinfo.set("WARC-Filename", &format!("{collection}.warc.gz")));
            if index == 0 {
                records.extend(copies(&capture()[1..], 1).iter().map(|record| {
                    record
                        .clone()
                        .set("WARC-Warcinfo-ID", &format!("<{identifier}>"))
                        .set("WARC-Target-URI", "https://www.example.com/")
                }));
            }
        }

        assert_eq!(
            findings(&records),
            [4, 8, 9, 10]
                .into_iter()
                .zip(malformed)
                .map(|(index, found)| {
                    (
                        index,
                        Violation::MalformedCollectionId {
                            found: found.to_owned(),
                        },
                    )
                })
                .collect::<Vec<_>>()
        );
    }

    /// A host is compared without regard to case, so the first capture's differently spelled one
    /// is not a finding.
    #[test]
    fn requests_target_the_collection_host() {
        let mut records = capture();
        for record in &mut records[1..] {
            *record = record
                .clone()
                .set("WARC-Target-URI", "https://Example.COM/");
        }
        let mut other = copies(&capture()[1..], 1);
        for record in &mut other {
            *record = record
                .clone()
                .set("WARC-Target-URI", "https://www.example.com/");
        }
        records.extend(other);
        let mut hostless = copies(&capture()[1..], 2);
        for record in &mut hostless {
            *record = record
                .clone()
                .set("WARC-Target-URI", "urn:isbn:0451450523")
                .without("WARC-Payload-Digest");
        }
        records.extend(hostless);

        assert_eq!(
            findings(&records),
            [
                (
                    4,
                    Violation::WrongRequestHost {
                        expected: HOST.to_owned(),
                        found: Some("www.example.com".to_owned())
                    }
                ),
                (
                    7,
                    Violation::WrongRequestHost {
                        expected: HOST.to_owned(),
                        found: None
                    }
                ),
            ]
        );
    }

    #[test]
    fn requests_outside_a_collection_are_unconstrained() {
        let mut records = capture();
        records[0].body = "software: test\r\n".to_owned();
        records[1] = records[1]
            .clone()
            .set("WARC-Target-URI", "https://www.example.com/");

        assert!(
            findings(&records)
                .iter()
                .all(|(_, violation)| !matches!(violation, Violation::WrongRequestHost { .. }))
        );
    }
}
