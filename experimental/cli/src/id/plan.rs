//! Resolve references before checking output IDs, retaining only identity data between passes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use archivindex_archiver::id::Identity;
use archivindex_warc::parse::untyped::name::Field;
use archivindex_warc_ops::file::open;
use archivindex_warc_ops::header::normalize_id;
use fluent_uri::Uri;

use super::{Error, Result};

struct Node {
    written: Option<Vec<u8>>,
    identity: Option<Identity>,
}

pub(super) fn redirects(input: &Path) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    let mut nodes = Vec::new();
    let mut by_id = HashMap::new();
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
            && by_id.insert(id.clone(), nodes.len()).is_some()
        {
            return Err(Error::RepeatedRecordId {
                id: String::from_utf8_lossy(id).into_owned(),
            });
        }
        nodes.push(Node {
            written,
            identity: Identity::from_raw(&record).ok(),
        });
    }

    let identifiers = resolve(&nodes, &by_id)?;
    let mut destinations = HashSet::new();
    let mut redirects = HashMap::new();
    for (node, derived) in nodes.iter().zip(&identifiers) {
        let Some(destination) = derived
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

/// Kahn's algorithm avoids recursion even for long reference chains. Unidentifiable records are
/// fixed endpoints: their IDs are retained, so dependents need not wait for their references.
fn resolve(nodes: &[Node], by_id: &HashMap<Vec<u8>, usize>) -> Result<Vec<Option<Uri<String>>>> {
    let mut dependents = vec![Vec::new(); nodes.len()];
    let mut pending = vec![0; nodes.len()];
    let mut ready = VecDeque::new();
    for (index, node) in nodes.iter().enumerate() {
        if let Some(identity) = &node.identity {
            let mut dependencies = identity
                .references()
                .filter_map(|id| by_id.get(id.as_bytes()).copied())
                .filter(|&index| nodes[index].identity.is_some())
                .collect::<Vec<_>>();
            dependencies.sort_unstable();
            dependencies.dedup();
            pending[index] = dependencies.len();
            for dependency in dependencies {
                dependents[dependency].push(index);
            }
            if pending[index] == 0 {
                ready.push_back(index);
            }
        }
    }
    let mut identifiers: Vec<Option<Uri<String>>> = vec![None; nodes.len()];
    while let Some(index) = ready.pop_front() {
        if let Some(identity) = &nodes[index].identity {
            identifiers[index] = Some(identity.record_id_with_references(|id| {
                by_id
                    .get(id.as_bytes())
                    .and_then(|&index| identifiers[index].as_ref())
                    .map(Uri::as_str)
            }));
        }
        for &dependent in &dependents[index] {
            pending[dependent] -= 1;
            if pending[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }
    if let Some(record) = pending.iter().position(|&count| count > 0) {
        return Err(Error::CyclicReferences { record });
    }
    Ok(identifiers)
}
