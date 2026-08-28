//! Indexing and lookup checks for the revisit index over records built in memory.

use std::error::Error as StdError;

use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::header::RevisitProfile;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::value::{Algorithm, Encoding, LabelledDigest, MediaType, WarcDate};
use archivindex_warc_revisit_index::payload::RevisitTarget;
use archivindex_warc_revisit_index::resource::{ResourceKey, ResourceStateUpdate, Variance};
use archivindex_warc_revisit_index::{Error, Index, IngestError, OpenError};
use fluent_uri::Uri;
use sha2::Digest as _;

const URI_A: &str = "https://example.com/a";
const URI_B: &str = "https://example.com/b";
const RECORD_A: &str = "urn:uuid:00000000-0000-4000-8000-00000000000a";
const RECORD_B: &str = "urn:uuid:00000000-0000-4000-8000-00000000000b";

fn uri(value: &str) -> Uri<String> {
    Uri::parse(value).expect("test URI").to_owned()
}

fn date(value: &str) -> WarcDate {
    WarcDate::parse(value, archivindex_warc::version::WarcVersion::V1_1).expect("test WARC date")
}

fn sha256(bytes: &[u8]) -> LabelledDigest {
    LabelledDigest::from_digest(Algorithm::Sha256, &sha2::Sha256::digest(bytes))
}

fn target(
    digest: LabelledDigest,
    record_id: &str,
    target_uri: &str,
    warc_date: &str,
    payload_length: Option<u64>,
) -> RevisitTarget {
    RevisitTarget {
        payload_digest: digest,
        payload_length,
        identified_payload_type: None,
        record_id: uri(record_id),
        target_uri: uri(target_uri),
        warc_date: date(warc_date),
    }
}

fn key(value: &str) -> ResourceKey {
    ResourceKey::new(uri(value))
}

fn response(
    target_uri: &str,
    record_id: &str,
    warc_date: &str,
    headers: &str,
    payload: &[u8],
) -> Result<Record, Box<dyn StdError>> {
    let mut message = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{headers}\r\n",
        payload.len()
    )
    .into_bytes();
    message.extend_from_slice(payload);

    Ok(
        Record::<NoExtension>::response(target_uri, date(warc_date))?
            .record_id(uri(record_id))
            .payload_digest(sha256(payload))
            .body(message)?,
    )
}

#[test]
fn payload_round_trips_every_field_and_missing_is_none() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let digest = LabelledDigest::from_digest(Algorithm::Sha256, &[0xa5; 32]);
    let expected = RevisitTarget {
        identified_payload_type: Some(MediaType::TEXT_PLAIN),
        ..target(
            digest.clone(),
            RECORD_A,
            URI_A,
            "2025-02-03T04:05:06.123Z",
            Some(4_294_967_300),
        )
    };

    assert!(index.lookup_payload(&sha256(b"missing"))?.is_none());
    assert!(index.insert_payload(&expected)?);
    assert_eq!(index.lookup_payload(&digest)?, Some(expected));
    Ok(())
}

#[test]
fn payload_persists_across_reopening() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("crawl-state.sqlite3");
    let expected = target(
        sha256(b"persistent"),
        RECORD_A,
        URI_A,
        "2025-01-01T00:00:00Z",
        Some(10),
    );
    Index::open(&path)?.insert_payload(&expected)?;

    assert_eq!(
        Index::open(&path)?.lookup_payload(&expected.payload_digest)?,
        Some(expected)
    );
    Ok(())
}

#[test]
fn duplicate_payload_insert_is_idempotent_and_preserves_canonical_source()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let digest = sha256(b"same");
    let canonical = target(
        digest.clone(),
        RECORD_A,
        URI_A,
        "2025-01-01T00:00:00Z",
        Some(4),
    );
    let later = target(
        digest.clone(),
        RECORD_B,
        URI_B,
        "2026-01-01T00:00:00Z",
        Some(4),
    );

    assert!(index.insert_payload(&canonical)?);
    assert!(!index.insert_payload(&later)?);
    assert!(!index.insert_payload(&later)?);
    assert_eq!(index.lookup_payload(&digest)?, Some(canonical));
    Ok(())
}

#[test]
fn digest_algorithm_is_part_of_the_payload_key() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let md5 = LabelledDigest::from_digest(Algorithm::Md5, &[7; 16]);
    let sha1 = LabelledDigest::from_digest(Algorithm::Sha1, &[7; 20]);
    let md5_target = target(md5.clone(), RECORD_A, URI_A, "2025-01-01", None);
    let sha1_target = target(sha1.clone(), RECORD_B, URI_B, "2025-01-02", None);

    assert!(index.insert_payload(&md5_target)?);
    assert!(index.insert_payload(&sha1_target)?);
    assert_eq!(index.lookup_payload(&md5)?, Some(md5_target));
    assert_eq!(index.lookup_payload(&sha1)?, Some(sha1_target));
    Ok(())
}

#[test]
fn resource_validators_digest_and_warc_identity_round_trip() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let resource_key = key(URI_A);
    let digest = sha256(b"representation");
    index.update_resource(
        &resource_key,
        ResourceStateUpdate::Representation {
            etag: Some("W/\"opaque, value\"".to_owned()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_owned()),
            payload_digest: Some(digest.clone()),
            record_id: Some(uri(RECORD_A)),
            warc_date: Some(date("2025-01-01T01:02:03.456789Z")),
            observed_at: date("2025-01-01T01:02:03.456789Z"),
            variance: Variance::Invariant,
        },
    )?;

    let state = index.lookup_resource(&resource_key)?.expect("stored state");
    assert_eq!(state.etag.as_deref(), Some("W/\"opaque, value\""));
    assert_eq!(
        state.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(state.payload_digest, Some(digest));
    assert_eq!(state.record_id, Some(uri(RECORD_A)));
    assert_eq!(state.warc_date, Some(date("2025-01-01T01:02:03.456789Z")));
    assert_eq!(state.observed_at, date("2025-01-01T01:02:03.456789Z"));
    Ok(())
}

#[test]
fn new_representation_replaces_state_and_clears_omitted_validators() -> Result<(), Box<dyn StdError>>
{
    let index = Index::open_in_memory()?;
    let resource_key = key(URI_A);
    index.update_resource(
        &resource_key,
        ResourceStateUpdate::Representation {
            etag: Some("\"old\"".to_owned()),
            last_modified: Some("old date".to_owned()),
            payload_digest: Some(sha256(b"old")),
            record_id: Some(uri(RECORD_A)),
            warc_date: Some(date("2025-01-01T00:00:00Z")),
            observed_at: date("2025-01-01T00:00:00Z"),
            variance: Variance::Invariant,
        },
    )?;
    index.update_resource(
        &resource_key,
        ResourceStateUpdate::Representation {
            etag: None,
            last_modified: None,
            payload_digest: Some(sha256(b"new")),
            record_id: Some(uri(RECORD_B)),
            warc_date: Some(date("2025-01-02T00:00:00Z")),
            observed_at: date("2025-01-02T00:00:00Z"),
            variance: Variance::Invariant,
        },
    )?;

    let state = index.lookup_resource(&resource_key)?.expect("stored state");
    assert_eq!(state.etag, None);
    assert_eq!(state.last_modified, None);
    assert_eq!(state.payload_digest, Some(sha256(b"new")));
    assert_eq!(state.record_id, Some(uri(RECORD_B)));
    Ok(())
}

#[test]
fn not_modified_merges_validators_and_preserves_representation_identity()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let resource_key = key(URI_A);
    let digest = sha256(b"body");
    let original_date = date("2025-01-01T00:00:00Z");
    index.update_resource(
        &resource_key,
        ResourceStateUpdate::Representation {
            etag: Some("\"old\"".to_owned()),
            last_modified: Some("old date".to_owned()),
            payload_digest: Some(digest.clone()),
            record_id: Some(uri(RECORD_A)),
            warc_date: Some(original_date),
            observed_at: original_date,
            variance: Variance::Invariant,
        },
    )?;
    index.update_resource(
        &resource_key,
        ResourceStateUpdate::NotModified {
            etag: Some("\"new\"".to_owned()),
            last_modified: None,
            observed_at: date("2025-01-02T00:00:00Z"),
        },
    )?;

    let state = index.lookup_resource(&resource_key)?.expect("stored state");
    assert_eq!(state.etag.as_deref(), Some("\"new\""));
    assert_eq!(state.last_modified.as_deref(), Some("old date"));
    assert_eq!(state.payload_digest, Some(digest));
    assert_eq!(state.record_id, Some(uri(RECORD_A)));
    assert_eq!(state.warc_date, Some(original_date));
    assert!(!index.update_resource(
        &key(URI_B),
        ResourceStateUpdate::NotModified {
            etag: None,
            last_modified: None,
            observed_at: date("2025-01-02T00:00:00Z"),
        },
    )?);
    Ok(())
}

#[test]
fn older_resource_updates_are_ignored() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let resource_key = key(URI_A);
    index.update_resource(
        &resource_key,
        ResourceStateUpdate::Representation {
            etag: Some("\"new\"".to_owned()),
            last_modified: None,
            payload_digest: Some(sha256(b"new")),
            record_id: Some(uri(RECORD_B)),
            warc_date: Some(date("2025-03-01T00:00:00Z")),
            observed_at: date("2025-03-01T00:00:00Z"),
            variance: Variance::Invariant,
        },
    )?;

    assert!(!index.update_resource(
        &resource_key,
        ResourceStateUpdate::Representation {
            etag: Some("\"old\"".to_owned()),
            last_modified: None,
            payload_digest: Some(sha256(b"old")),
            record_id: Some(uri(RECORD_A)),
            warc_date: Some(date("2025-02-01T00:00:00Z")),
            observed_at: date("2025-02-01T00:00:00Z"),
            variance: Variance::Invariant,
        },
    )?);
    assert!(!index.update_resource(
        &resource_key,
        ResourceStateUpdate::NotModified {
            etag: Some("\"stale\"".to_owned()),
            last_modified: None,
            observed_at: date("2025-02-15T00:00:00Z"),
        },
    )?);

    let state = index.lookup_resource(&resource_key)?.expect("new state");
    assert_eq!(state.etag.as_deref(), Some("\"new\""));
    assert_eq!(state.payload_digest, Some(sha256(b"new")));
    assert_eq!(state.record_id, Some(uri(RECORD_B)));
    assert_eq!(state.observed_at, date("2025-03-01T00:00:00Z"));
    Ok(())
}

#[test]
fn two_resources_share_a_payload_but_keep_independent_state() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let digest = sha256(b"shared");
    index.insert_payload(&target(
        digest.clone(),
        RECORD_A,
        URI_A,
        "2025-01-01T00:00:00Z",
        Some(6),
    ))?;
    for (resource, etag, record) in [(URI_A, "\"a\"", RECORD_A), (URI_B, "\"b\"", RECORD_B)] {
        index.update_resource(
            &key(resource),
            ResourceStateUpdate::Representation {
                etag: Some(etag.to_owned()),
                last_modified: None,
                payload_digest: Some(digest.clone()),
                record_id: Some(uri(record)),
                warc_date: Some(date("2025-01-01T00:00:00Z")),
                observed_at: date("2025-01-01T00:00:00Z"),
                variance: Variance::Invariant,
            },
        )?;
    }

    assert_eq!(
        index.lookup_resource(&key(URI_A))?.unwrap().etag.as_deref(),
        Some("\"a\"")
    );
    assert_eq!(
        index.lookup_resource(&key(URI_B))?.unwrap().etag.as_deref(),
        Some("\"b\"")
    );
    assert_eq!(
        index.lookup_payload(&digest)?.unwrap().target_uri,
        uri(URI_A)
    );
    Ok(())
}

#[test]
fn a_digest_comes_back_in_the_spelling_it_was_stored_in() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let bytes = sha2::Sha256::digest(b"body");
    let mut base32 = String::new();
    Encoding::Base32.encode(&bytes, &mut base32)?;
    let as_written = LabelledDigest::new("sha256", &base32)?;
    let recommended = LabelledDigest::from_digest(Algorithm::Sha256, &bytes);

    assert_ne!(as_written.to_string(), recommended.to_string());
    assert!(index.insert_payload(&target(
        as_written.clone(),
        RECORD_A,
        URI_A,
        "2025-01-01T00:00:00Z",
        Some(4),
    ))?);
    index.update_resource(
        &key(URI_A),
        ResourceStateUpdate::Representation {
            etag: None,
            last_modified: None,
            payload_digest: Some(as_written.clone()),
            record_id: Some(uri(RECORD_A)),
            warc_date: Some(date("2025-01-01T00:00:00Z")),
            observed_at: date("2025-01-01T00:00:00Z"),
            variance: Variance::Invariant,
        },
    )?;

    // A digest matches whatever encoding either side wrote it in, and comes back as stored.
    let found = index.lookup_payload(&recommended)?.expect("stored payload");
    let resource = index
        .lookup_resource(&key(URI_A))?
        .expect("stored resource");

    assert_eq!(found.payload_digest.to_string(), as_written.to_string());
    assert_eq!(
        resource
            .payload_digest
            .map(|digest| digest.to_string())
            .as_deref(),
        Some(as_written.to_string().as_str())
    );
    Ok(())
}

#[test]
fn malformed_persisted_state_returns_an_error() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("corrupt.sqlite3");
    let index = Index::open(&path)?;
    index.insert_payload(&RevisitTarget {
        identified_payload_type: Some(MediaType::TEXT_PLAIN),
        ..target(sha256(b"body"), RECORD_A, URI_A, "2025-01-01", Some(4))
    })?;
    index.update_resource(
        &key(URI_A),
        ResourceStateUpdate::Representation {
            etag: None,
            last_modified: None,
            payload_digest: Some(sha256(b"body")),
            record_id: Some(uri(RECORD_A)),
            warc_date: Some(date("2025-01-01T00:00:00Z")),
            observed_at: date("2025-01-01T00:00:00Z"),
            variance: Variance::Invariant,
        },
    )?;
    drop(index);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE payloads SET identified_payload_type = 'bogus' WHERE target_uri = ?1",
        [URI_A],
    )?;
    connection.execute(
        "UPDATE resource_state SET digest_text = 'bogus' WHERE target_uri = ?1",
        [URI_A],
    )?;
    drop(connection);

    assert!(matches!(
        Index::open(&path)?.lookup_payload(&sha256(b"body")),
        Err(Error::MalformedMediaType { .. })
    ));
    assert!(matches!(
        Index::open(&path)?.lookup_resource(&key(URI_A)),
        Err(Error::MalformedDigest { .. })
    ));
    Ok(())
}

#[test]
fn incompatible_schema_version_is_rejected_clearly() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("future.sqlite3");
    let connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "user_version", 99)?;
    drop(connection);

    assert!(matches!(
        Index::open(path),
        Err(OpenError::SchemaVersion {
            expected: 6,
            found: 99
        })
    ));
    Ok(())
}

#[test]
fn bulk_transaction_commits_records_together() -> Result<(), Box<dyn StdError>> {
    let mut index = Index::open_in_memory()?;
    let one = target(sha256(b"one"), RECORD_A, URI_A, "2025-01-01", Some(3));
    let two = target(sha256(b"two"), RECORD_B, URI_B, "2025-01-02", Some(3));
    let transaction = index.begin()?;
    transaction.insert_payload(&one)?;
    transaction.insert_payload(&two)?;
    transaction.commit()?;

    assert_eq!(index.lookup_payload(&one.payload_digest)?, Some(one));
    assert_eq!(index.lookup_payload(&two.payload_digest)?, Some(two));
    Ok(())
}

#[test]
fn response_ingestion_creates_payload_and_resource_state_but_ignores_http_date()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let record = response(
        URI_A,
        RECORD_A,
        "2025-01-01T00:00:00Z",
        "ETag: \"v1\"\r\nDate: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        b"hello",
    )?;

    let outcome = index.index_record(&record)?;
    assert!(outcome.payload_inserted);
    assert!(outcome.resource_updated);
    let payload = index.lookup_payload(&sha256(b"hello"))?.unwrap();
    assert_eq!(payload.payload_length, Some(5));
    assert_eq!(payload.record_id, uri(RECORD_A));
    let state = index.lookup_resource(&key(URI_A))?.unwrap();
    assert_eq!(state.etag.as_deref(), Some("\"v1\""));
    assert_eq!(state.last_modified, None);
    Ok(())
}

#[test]
fn response_ingestion_keeps_the_identified_payload_type() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let record = Record::<NoExtension>::response(URI_A, date("2025-01-01T00:00:00Z"))?
        .record_id(uri(RECORD_A))
        .payload_digest(sha256(b"hello"))
        .identified_payload_type(MediaType::TEXT_PLAIN)
        .body(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec())?;

    assert!(index.index_record(&record)?.payload_inserted);
    let payload = index.lookup_payload(&sha256(b"hello"))?.unwrap();
    assert_eq!(payload.identified_payload_type, Some(MediaType::TEXT_PLAIN));
    Ok(())
}

#[test]
fn identical_revisit_does_not_replace_payload_bearing_canonical_source()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let original = response(
        URI_A,
        RECORD_A,
        "2025-01-01T00:00:00Z",
        "ETag: \"a\"\r\n",
        b"shared",
    )?;
    index.index_record(&original)?;
    let digest = sha256(b"shared");
    let revisit = Record::<NoExtension>::revisit(
        URI_B,
        date("2025-01-02T00:00:00Z"),
        RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
    )?
    .record_id(uri(RECORD_B))
    .payload_digest(digest.clone())
    .refers_to(uri(RECORD_A))
    .refers_to_target_uri(uri(URI_A))
    .refers_to_date(date("2025-01-01T00:00:00Z"))
    .body(Vec::new())?;

    let outcome = index.index_record(&revisit)?;
    assert!(!outcome.payload_inserted);
    assert_eq!(
        index.lookup_payload(&digest)?.unwrap().record_id,
        uri(RECORD_A)
    );
    assert_eq!(
        index.lookup_resource(&key(URI_B))?.unwrap().record_id,
        Some(uri(RECORD_A))
    );
    Ok(())
}

/// An `identical-payload-digest` revisit of the payload already stored confirms it, so the
/// validators its block omits, as an empty block omits all of them, survive.
#[test]
fn identical_revisit_of_the_stored_payload_keeps_the_resource_validators()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let original = response(
        URI_A,
        RECORD_A,
        "2025-01-01T00:00:00Z",
        "ETag: \"v1\"\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        b"version one",
    )?;
    index.index_record(&original)?;

    let before = index.lookup_resource(&key(URI_A))?.unwrap();
    let revisit = Record::<NoExtension>::revisit(
        URI_A,
        date("2025-01-02T00:00:00Z"),
        RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
    )?
    .record_id(uri(RECORD_B))
    .payload_digest(sha256(b"version one"))
    .refers_to(uri(RECORD_A))
    .refers_to_target_uri(uri(URI_A))
    .refers_to_date(date("2025-01-01T00:00:00Z"))
    .body(Vec::new())?;
    index.index_record(&revisit)?;

    let after = index.lookup_resource(&key(URI_A))?.unwrap();
    assert_eq!(after.etag, before.etag);
    assert_eq!(after.last_modified, before.last_modified);
    assert_eq!(after.payload_digest, before.payload_digest);
    assert_eq!(after.record_id, Some(uri(RECORD_A)));
    assert_eq!(after.warc_date, Some(date("2025-01-01T00:00:00Z")));
    assert_eq!(after.observed_at, date("2025-01-02T00:00:00Z"));
    Ok(())
}

#[test]
fn conditional_304_flow_preserves_enough_state_for_server_not_modified_revisit()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let first = response(
        URI_A,
        RECORD_A,
        "2025-01-01T00:00:00Z",
        "ETag: \"v1\"\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        b"version one",
    )?;
    index.index_record(&first)?;

    let before = index.lookup_resource(&key(URI_A))?.unwrap();
    assert_eq!(before.etag.as_deref(), Some("\"v1\""));
    let revisit = Record::<NoExtension>::revisit(
        URI_A,
        date("2025-01-02T00:00:00Z"),
        RevisitProfile::SERVER_NOT_MODIFIED,
    )?
    .record_id(uri(RECORD_B))
    .refers_to(uri(RECORD_A))
    .refers_to_target_uri(uri(URI_A))
    .refers_to_date(date("2025-01-01T00:00:00Z"))
    .body(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1-refreshed\"\r\n\r\n".to_vec())?;
    index.index_record(&revisit)?;

    let after = index.lookup_resource(&key(URI_A))?.unwrap();
    assert_eq!(after.etag.as_deref(), Some("\"v1-refreshed\""));
    assert_eq!(after.last_modified, before.last_modified);
    assert_eq!(after.payload_digest, before.payload_digest);
    assert_eq!(after.record_id, Some(uri(RECORD_A)));
    assert_eq!(after.warc_date, Some(date("2025-01-01T00:00:00Z")));
    assert_eq!(after.observed_at, date("2025-01-02T00:00:00Z"));
    Ok(())
}

#[test]
fn matching_payload_at_a_second_uri_reuses_first_target_but_keeps_resource_keys_separate()
-> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let first = response(
        URI_A,
        RECORD_A,
        "2025-01-01T00:00:00Z",
        "ETag: \"a\"\r\n",
        b"shared body",
    )?;
    let second = response(
        URI_B,
        RECORD_B,
        "2025-01-02T00:00:00Z",
        "ETag: \"b\"\r\n",
        b"shared body",
    )?;
    index.index_record(&first)?;
    let second_outcome = index.index_record(&second)?;

    assert!(!second_outcome.payload_inserted);
    assert_eq!(
        index
            .lookup_payload(&sha256(b"shared body"))?
            .unwrap()
            .record_id,
        uri(RECORD_A)
    );
    assert_eq!(
        index.lookup_resource(&key(URI_A))?.unwrap().etag.as_deref(),
        Some("\"a\"")
    );
    assert_eq!(
        index.lookup_resource(&key(URI_B))?.unwrap().etag.as_deref(),
        Some("\"b\"")
    );
    Ok(())
}

#[test]
fn truncated_response_is_not_indexed() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let payload = b"hel";
    let mut message = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\n\r\n".to_vec();
    message.extend_from_slice(payload);
    let record = Record::<NoExtension>::response(URI_A, date("2025-01-01T00:00:00Z"))?
        .record_id(uri(RECORD_A))
        .payload_digest(sha256(payload))
        .truncated(TruncatedType::Length)
        .body(message)?;

    let outcome = index.index_record(&record)?;

    // A partial body is neither a revisit target nor the resource's representation.
    assert!(!outcome.payload_inserted);
    assert!(!outcome.resource_updated);
    assert!(index.lookup_payload(&sha256(payload))?.is_none());
    assert!(index.lookup_resource(&key(URI_A))?.is_none());
    Ok(())
}

#[test]
fn a_digest_the_index_cannot_store_skips_only_its_own_record() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let payload = b"vendor digest";
    let mut message = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    message.extend_from_slice(payload);

    let unknown = Record::<NoExtension>::response(URI_A, date("2024-01-01T00:00:00Z"))?
        .record_id(uri(RECORD_A))
        .payload_digest(LabelledDigest::parse(b"xxh64:0011223344556677")?)
        .body(message)?;

    let outcome = index.index_record(&unknown)?;

    assert!(!outcome.payload_inserted);
    assert!(!outcome.resource_updated);
    assert!(index.lookup_resource(&key(URI_A))?.is_none());

    // The next record is indexed as though the odd one had not been read.
    let known = response(URI_B, RECORD_B, "2024-01-01T00:00:01Z", "", b"indexed")?;

    assert!(index.index_record(&known)?.payload_inserted);
    Ok(())
}

/// A declared digest the payload does not bear would seed a key that every later
/// `identical-payload-digest` revisit refers back to, so the record is skipped instead.
#[test]
fn a_digest_the_payload_does_not_bear_skips_only_its_own_record() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let payload = b"as stored";
    let mut message = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    message.extend_from_slice(payload);
    let declared = sha256(b"as declared");

    let misdeclared = Record::<NoExtension>::response(URI_A, date("2024-01-01T00:00:00Z"))?
        .record_id(uri(RECORD_A))
        .payload_digest(declared.clone())
        .body(message)?;

    let outcome = index.index_record(&misdeclared)?;

    assert!(!outcome.payload_inserted);
    assert!(!outcome.resource_updated);
    assert!(index.lookup_payload(&declared)?.is_none());
    assert!(index.lookup_payload(&sha256(payload))?.is_none());
    assert!(index.lookup_resource(&key(URI_A))?.is_none());

    // The next record is indexed as though the odd one had not been read.
    let known = response(URI_B, RECORD_B, "2024-01-01T00:00:01Z", "", b"indexed")?;

    assert!(index.index_record(&known)?.payload_inserted);
    Ok(())
}

/// The digest of a transfer-coded response is declared over its entity-body, which is what the
/// index checks it against and measures.
#[test]
fn a_chunked_response_is_checked_and_measured_as_its_entity_body() -> Result<(), Box<dyn StdError>>
{
    let index = Index::open_in_memory()?;
    let payload = b"decoded";
    let message =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ndec\r\n4\r\noded\r\n0\r\n\r\n";

    let record = Record::<NoExtension>::response(URI_A, date("2024-01-01T00:00:00Z"))?
        .record_id(uri(RECORD_A))
        .payload_digest(sha256(payload))
        .body(message.to_vec())?;

    let outcome = index.index_record(&record)?;

    assert!(outcome.payload_inserted);
    assert!(outcome.resource_updated);
    let stored = index
        .lookup_payload(&sha256(payload))?
        .expect("the entity-body's digest");
    assert_eq!(stored.payload_length, Some(payload.len() as u64));
    Ok(())
}

#[test]
fn payload_less_revisit_never_becomes_the_resource_record() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let digest = sha256(b"never indexed");
    let revisit = |record_id: &str, warc_date: &str| {
        Record::<NoExtension>::revisit(
            URI_A,
            date(warc_date),
            RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
        )
        .map(|builder| {
            builder
                .record_id(uri(record_id))
                .payload_digest(digest.clone())
        })
    };

    // WARC 1.1 permits an identical-payload-digest revisit without `WARC-Refers-To`. The
    // revisit's own identity must not be recorded as the resource's representation.
    index.index_record(&revisit(RECORD_A, "2025-01-01T00:00:00Z")?.body(Vec::new())?)?;
    let state = index.lookup_resource(&key(URI_A))?.expect("resource state");
    assert_eq!(state.payload_digest, Some(digest.clone()));
    assert_eq!(state.record_id, None);
    assert_eq!(state.warc_date, None);

    // When the revisit names its original, that identity is stored even without a payload row.
    index.index_record(
        &revisit(RECORD_B, "2025-01-02T00:00:00Z")?
            .refers_to(uri(RECORD_A))
            .refers_to_target_uri(uri(URI_A))
            .refers_to_date(date("2024-12-31T00:00:00Z"))
            .body(Vec::new())?,
    )?;
    let state = index.lookup_resource(&key(URI_A))?.expect("resource state");
    assert_eq!(state.record_id, Some(uri(RECORD_A)));
    assert_eq!(state.warc_date, Some(date("2024-12-31T00:00:00Z")));
    assert!(index.lookup_payload(&digest)?.is_none());
    Ok(())
}

/// Ingest reads `Vary` across every line the response sent it on.
///
/// An empty first line would otherwise be the whole field, leaving state that a later request
/// could revalidate against even though the server named a selecting field.
#[test]
fn ingest_reads_vary_from_every_line_the_response_sent() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let record = response(
        URI_A,
        RECORD_A,
        "2025-01-01T00:00:00Z",
        "Vary: \r\nVary: User-Agent\r\n",
        b"page",
    )?;

    assert!(index.index_record(&record)?.resource_updated);
    assert_eq!(
        index
            .lookup_resource(&key(URI_A))?
            .map(|state| state.variance),
        Some(Variance::Unselectable)
    );
    Ok(())
}

#[test]
fn non_200_response_registers_its_payload_but_not_the_resource() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let payload = b"missing";
    let mut message =
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nETag: \"gone\"\r\n\r\n".to_vec();
    message.extend_from_slice(payload);
    let record = Record::<NoExtension>::response(URI_A, date("2025-01-01T00:00:00Z"))?
        .record_id(uri(RECORD_A))
        .payload_digest(sha256(payload))
        .body(message)?;

    let outcome = index.index_record(&record)?;

    // An error page may still be revisited by digest, but it is not the resource's
    // representation, so its validators must not drive conditional requests.
    assert!(outcome.payload_inserted);
    assert!(!outcome.resource_updated);
    assert_eq!(
        index
            .lookup_payload(&sha256(payload))?
            .map(|target| target.payload_length),
        Some(Some(7))
    );
    assert!(index.lookup_resource(&key(URI_A))?.is_none());
    Ok(())
}

#[test]
fn revisit_with_a_non_http_block_is_rejected() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let record = Record::<NoExtension>::revisit(
        URI_A,
        date("2025-01-01T00:00:00Z"),
        RevisitProfile::Other("urn:example:profile".to_owned()),
    )?
    .record_id(uri(RECORD_A))
    .body(b"not an HTTP response head".to_vec())?;

    let error = index
        .index_record(&record)
        .expect_err("a non-HTTP revisit block is malformed");

    assert!(matches!(error, IngestError::MalformedHttpResponse(_)));
    Ok(())
}

#[test]
fn foreign_profile_revisit_changes_nothing() -> Result<(), Box<dyn StdError>> {
    let index = Index::open_in_memory()?;
    let digest = sha256(b"foreign");
    let record = Record::<NoExtension>::revisit(
        URI_A,
        date("2025-01-02T00:00:00Z"),
        RevisitProfile::Other("urn:example:profile".to_owned()),
    )?
    .record_id(uri(RECORD_A))
    .payload_digest(digest.clone())
    .refers_to(uri(RECORD_B))
    .refers_to_date(date("2025-01-01T00:00:00Z"))
    .body(Vec::new())?;

    let outcome = index.index_record(&record)?;

    assert!(!outcome.payload_inserted);
    assert!(!outcome.resource_updated);
    assert!(index.lookup_payload(&digest)?.is_none());
    assert!(index.lookup_resource(&key(URI_A))?.is_none());
    Ok(())
}

#[test]
fn dropped_transaction_rolls_back() -> Result<(), Box<dyn StdError>> {
    let mut index = Index::open_in_memory()?;
    let one = target(sha256(b"one"), RECORD_A, URI_A, "2025-01-01", Some(3));

    {
        let transaction = index.begin()?;
        transaction.insert_payload(&one)?;
    }

    assert!(index.lookup_payload(&one.payload_digest)?.is_none());
    Ok(())
}
