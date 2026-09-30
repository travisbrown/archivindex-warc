//! Plan identifier changes before writing, retaining only identifiers between passes.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use archivindex_archiver::id::raw_record_id;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc_ops::file::open;
use archivindex_warc_ops::header::normalize_id;
use fluent_uri::Uri;

use super::{Error, Result};

struct Node {
    written: Option<Vec<u8>>,
    derived: Option<Uri<String>>,
}

pub(super) fn redirects(input: &Path) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    let mut nodes = Vec::new();
    let mut written_ids = HashSet::new();
    for result in open(input)?.iter_raw_records().records() {
        let record = result.map_err(|source| archivindex_warc_ops::Error::Read {
            path: input.to_owned(),
            source,
        })?;
        let written = record
            .header
            .get(Field::RecordID.standard_name())
            .map(normalize_id)
            .filter(|id| !id.is_empty())
            .map(<[u8]>::to_vec);
        if let Some(id) = &written
            && !written_ids.insert(id.clone())
        {
            return Err(Error::RepeatedRecordId {
                id: String::from_utf8_lossy(id).into_owned(),
            });
        }
        nodes.push(Node {
            written,
            derived: raw_record_id(&record).ok(),
        });
    }

    let mut destinations = HashSet::new();
    let mut redirects = HashMap::new();
    for node in &nodes {
        let Some(destination) = node
            .derived
            .as_ref()
            .map(|id| id.as_str().as_bytes())
            .or(node.written.as_deref())
        else {
            continue;
        };
        // Each input record must have its own output identifier, even when it started unnamed.
        if !destinations.insert(destination.to_vec()) {
            return Err(Error::CollidingRecordIds {
                id: String::from_utf8_lossy(destination).into_owned(),
            });
        }
        if let Some(written) = &node.written
            && written != destination
        {
            redirects.insert(
                written.clone(),
                [b" <".as_slice(), destination, b">"].concat(),
            );
        }
    }
    log::info!("changing {} record identifiers", redirects.len());
    Ok(redirects)
}
