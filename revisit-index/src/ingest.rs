//! Convenience ingestion from semantic WARC records.

use std::borrow::Cow;

use archivindex_warc::record::Record;
use archivindex_warc::record::extension::Extension;
use archivindex_warc::record::header::{RevisitHeader, RevisitProfile};
use archivindex_warc::record::http::ResponseMetadata;
use archivindex_warc::value::LabelledDigest;
use rusqlite::Connection;

use crate::db::{
    Handle, indexable_digest, insert_payload, lookup_payload, lookup_resource, update_resource,
};
use crate::payload::RevisitTarget;
use crate::resource::{ResourceKey, ResourceStateUpdate, Variance, declared_vary};
use crate::{IndexRecordOutcome, IngestError, Store};

impl<C: Handle> Store<C> {
    /// Index one semantic WARC record.
    ///
    /// Payload-bearing HTTP `response` records establish canonical payloads, and HTTP 200
    /// responses update resource state. Revisit records never become canonical payloads.
    /// `identical-payload-digest` revisits resolve to an existing canonical source or to their
    /// explicit `WARC-Refers-To` fields. When the digest matches stored resource state, omitted
    /// metadata is retained. `server-not-modified` revisits retain the representation identity and
    /// update only its validators.
    ///
    /// A record whose own `WARC-Payload-Digest` names an algorithm this crate does not know, holds
    /// a value that does not decode to that algorithm's digest length, or differs from the digest
    /// of the payload it is declared over, is skipped. The index is derived state, so an
    /// unindexable digest costs its record rather than the whole file. A digest under an
    /// algorithm this build cannot compute is trusted as declared.
    ///
    /// A record carries no trace of the request that produced it, so a response declaring `Vary`
    /// yields state that is never reused for revalidation (see
    /// [`Variance::declared_without_request`](crate::resource::Variance::declared_without_request)).
    /// Its payload still enters the canonical payload table and remains available for deduplication.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::MalformedHttpResponse`] or [`IngestError::MalformedWarcPayload`]
    /// for unreadable record metadata, and [`IngestError::Index`] for malformed persisted state or
    /// a SQLite failure.
    pub fn index_record<E: Extension>(
        &self,
        record: &Record<E>,
    ) -> Result<IndexRecordOutcome, IngestError> {
        index_record(self.connection(), record)
    }
}

fn index_record<E: Extension>(
    connection: &Connection,
    record: &Record<E>,
) -> Result<IndexRecordOutcome, IngestError> {
    match record {
        Record::Response { header, body } if body.starts_with(b"HTTP/") => {
            if is_unindexable(header.payload.payload_digest.as_ref()) {
                return Ok(IndexRecordOutcome::default());
            }

            index_response(connection, record)
        }
        Record::Revisit { header, body } => {
            if is_unindexable(header.payload.payload_digest.as_ref()) {
                return Ok(IndexRecordOutcome::default());
            }

            index_revisit(connection, header, body)
        }
        _ => Ok(IndexRecordOutcome::default()),
    }
}

/// Whether a record declares a digest the index cannot store.
fn is_unindexable(payload_digest: Option<&LabelledDigest>) -> bool {
    payload_digest.is_some_and(|digest| !indexable_digest(digest))
}

fn index_response<E: Extension>(
    connection: &Connection,
    record: &Record<E>,
) -> Result<IndexRecordOutcome, IngestError> {
    let Record::Response { header, body } = record else {
        unreachable!("index_response is only called for response records");
    };

    // A truncated body is neither a representation nor a revisit target.
    if header.core.truncated.is_some() {
        return Ok(IndexRecordOutcome::default());
    }
    let metadata = http_metadata(body)?;
    let payload_digest = header.payload.payload_digest.clone();
    // Decode only transfer-coded bodies; otherwise the stored body is the payload.
    let payload = if metadata.transfer_encoded {
        record
            .payload_bytes()
            .map_err(IngestError::MalformedWarcPayload)?
    } else {
        Some(Cow::Borrowed(&body[metadata.body_offset..]))
    };
    // A digest the payload does not bear would seed a key later revisits refer back to.
    if let (Some(declared), Some(payload)) = (&payload_digest, &payload)
        && misdeclares(declared, payload)
    {
        return Ok(IndexRecordOutcome::default());
    }
    let payload_length = payload.map(|payload| payload.len() as u64);

    let payload_inserted = if let (Some(payload_digest), Some(payload_length)) =
        (payload_digest.as_ref(), payload_length)
    {
        insert_payload(
            connection,
            &RevisitTarget {
                payload_digest: payload_digest.clone(),
                payload_length: Some(payload_length),
                identified_payload_type: header.payload.identified_payload_type.clone(),
                record_id: header.core.record_id.clone(),
                target_uri: header.target_uri.clone(),
                warc_date: header.core.date,
            },
        )?
    } else {
        false
    };

    let resource_updated = if metadata.status == 200 {
        let key = ResourceKey::new(header.target_uri.clone());
        update_resource(
            connection,
            &key,
            ResourceStateUpdate::Representation {
                etag: metadata.etag,
                last_modified: metadata.last_modified,
                payload_digest,
                record_id: Some(header.core.record_id.clone()),
                warc_date: Some(header.core.date),
                observed_at: header.core.date,
                variance: Variance::declared_without_request(metadata.vary.as_deref()),
            },
        )?
    } else {
        false
    };

    Ok(IndexRecordOutcome {
        payload_inserted,
        resource_updated,
    })
}

/// Whether a declared digest differs from the digest of the payload it is declared over.
///
/// A digest under an algorithm this build cannot compute is trusted.
fn misdeclares(declared: &LabelledDigest, payload: &[u8]) -> bool {
    declared
        .algorithm()
        .and_then(|algorithm| algorithm.digest(payload))
        .is_some_and(|computed| declared.decoded().as_deref() != Some(&*computed))
}

fn index_revisit<E: Extension>(
    connection: &Connection,
    header: &RevisitHeader<E>,
    body: &[u8],
) -> Result<IndexRecordOutcome, IngestError> {
    let metadata = if body.is_empty() {
        HttpMetadata::default()
    } else if body.starts_with(b"HTTP/") {
        http_metadata(body)?
    } else {
        return Err(IngestError::MalformedHttpResponse(
            "revisit block is not an HTTP response head",
        ));
    };
    let key = ResourceKey::new(header.target_uri.clone());

    let resource_updated = match &header.profile {
        RevisitProfile::IdenticalPayloadDigest(_) => {
            let digest = header.payload.payload_digest.as_ref().ok_or(
                IngestError::MalformedHttpResponse(
                    "identical-payload-digest revisit has no payload digest",
                ),
            )?;
            let canonical = lookup_payload(connection, digest)?;
            // A revisit without a canonical payload record cannot itself become the original.
            let (mut record_id, mut warc_date) = canonical.as_ref().map_or_else(
                || (header.refers_to.clone(), header.refers_to_date),
                |target| (Some(target.record_id.clone()), Some(target.warc_date)),
            );
            let mut etag = metadata.etag;
            let mut last_modified = metadata.last_modified;
            let mut variance = Variance::declared_without_request(metadata.vary.as_deref());

            // Agreeing digests make this the representation already stored, so the revisit
            // confirms it rather than replacing it and whatever its block leaves unsaid, which
            // for the usual empty block is everything, is kept.
            if let Some(stored) = lookup_resource(connection, &key)?
                .filter(|stored| stored.payload_digest.as_ref() == Some(digest))
            {
                etag = etag.or(stored.etag);
                last_modified = last_modified.or(stored.last_modified);
                record_id = record_id.or(stored.record_id);
                warc_date = warc_date.or(stored.warc_date);
                if body.is_empty() {
                    variance = stored.variance;
                }
            }

            update_resource(
                connection,
                &key,
                ResourceStateUpdate::Representation {
                    etag,
                    last_modified,
                    payload_digest: Some(digest.clone()),
                    record_id,
                    warc_date,
                    observed_at: header.core.date,
                    variance,
                },
            )?
        }
        RevisitProfile::ServerNotModified(_) => {
            if lookup_resource(connection, &key)?.is_some() {
                update_resource(
                    connection,
                    &key,
                    ResourceStateUpdate::NotModified {
                        etag: metadata.etag,
                        last_modified: metadata.last_modified,
                        observed_at: header.core.date,
                    },
                )?
            } else if header.refers_to.is_some() && header.refers_to_date.is_some() {
                update_resource(
                    connection,
                    &key,
                    ResourceStateUpdate::Representation {
                        etag: metadata.etag,
                        last_modified: metadata.last_modified,
                        payload_digest: header.payload.payload_digest.clone(),
                        record_id: header.refers_to.clone(),
                        warc_date: header.refers_to_date,
                        observed_at: header.core.date,
                        variance: Variance::declared_without_request(metadata.vary.as_deref()),
                    },
                )?
            } else {
                false
            }
        }
        RevisitProfile::Other(_) => false,
    };

    Ok(IndexRecordOutcome {
        payload_inserted: false,
        resource_updated,
    })
}

#[derive(Default)]
struct HttpMetadata {
    status: u16,
    etag: Option<String>,
    last_modified: Option<String>,
    /// The `Vary` field, naming the request fields that select the representation, with any
    /// several lines the response sent it as already combined by [`declared_vary`].
    vary: Option<String>,
    /// Where the stored body begins.
    body_offset: usize,
    /// Whether the head declares a `Transfer-Encoding`.
    transfer_encoded: bool,
}

fn http_metadata(message: &[u8]) -> Result<HttpMetadata, IngestError> {
    let metadata = ResponseMetadata::parse(message).ok_or(IngestError::MalformedHttpResponse(
        "invalid HTTP response head",
    ))?;
    Ok(HttpMetadata {
        status: metadata.status,
        etag: metadata
            .header("etag")
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::to_owned),
        last_modified: metadata
            .header("last-modified")
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::to_owned),
        vary: declared_vary(&metadata),
        body_offset: metadata.body_offset,
        transfer_encoded: metadata.header("transfer-encoding").is_some(),
    })
}
