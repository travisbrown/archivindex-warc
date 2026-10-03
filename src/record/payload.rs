//! WARC payload extraction from stored HTTP messages.
//!
//! WARC payload digests use the entity-body, accepting capture tools that kept transfer headers
//! after dechunking and records ending immediately after the final zero-size chunk.

use std::borrow::Cow;

use archivindex_http::body::{Decoding, Error};

/// Extract a WARC HTTP payload with content coding preserved and stored-message tolerance.
///
/// Unsupported transfer codings and incomplete chunk data are errors.
pub fn entity_body(message: &[u8]) -> Result<Cow<'_, [u8]>, Error> {
    archivindex_http::body::entity_body_with(message, Decoding::Stored)
}
