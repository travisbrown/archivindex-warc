//! Media-type identification for `WARC-Identified-Payload-Type`.
//!
//! Clause 5.19 of the WARC 1.1 standard requires this field to carry a type determined by
//! examining the payload, not one copied from a declaration in the block. [`payload_type`]
//! identifies payload bytes, and [`http_payload_type`] applies it to an archived HTTP message's
//! entity-body.
//!
//! Identification is opt-in. A capture enables it with
//! [`CaptureEvent::identify_payload_type`](crate::record::capture::CaptureEvent::identify_payload_type),
//! and a directly built record can pass the result to
//! [`identified_payload_type`](crate::record::builder::ResponseBuilder::identified_payload_type).

use file_format::FileFormat;

use crate::parsing::{is_lws, next_line, split_field_line};
use crate::record::payload;
use crate::value::MediaType;

const CONTENT_TYPE: &[u8] = b"content-type";

/// Identify the media type of a payload by examining its bytes.
///
/// If the declared type names JSON (a `json` subtype or `+json` suffix) and the payload parses as
/// JSON, the result is `application/json`. Every other payload is identified by content alone.
///
/// Returns `None` for an empty or unidentified payload instead of falling back to
/// `application/octet-stream`.
#[must_use]
pub fn payload_type(payload: &[u8], declared: Option<&MediaType>) -> Option<MediaType> {
    if payload.is_empty() {
        return None;
    }

    if declared.is_some_and(declares_json)
        && serde_json::from_slice::<serde::de::IgnoredAny>(payload).is_ok()
    {
        return Some(MediaType::JSON);
    }

    let format = FileFormat::from_bytes(payload);
    if format == FileFormat::ArbitraryBinaryData {
        return None;
    }

    MediaType::parse(format.media_type().as_bytes()).ok()
}

/// Identify the entity-body of an archived HTTP message.
///
/// The message's `Content-Type` is passed to [`payload_type`] as its declared type. Returns `None`
/// when the entity-body cannot be extracted or identified. A truncated message is identified from
/// the recorded bytes.
#[must_use]
pub fn http_payload_type(message: &[u8]) -> Option<MediaType> {
    let body = payload::entity_body(message).ok()?;

    payload_type(&body, declared_content_type(message).as_ref())
}

/// Whether a declared media type names JSON.
fn declares_json(declared: &MediaType) -> bool {
    let subtype = declared.subtype().as_bytes();

    subtype.eq_ignore_ascii_case(b"json")
        || subtype
            .len()
            .checked_sub(5)
            .is_some_and(|start| subtype[start..].eq_ignore_ascii_case(b"+json"))
}

/// The media type an HTTP message's first `Content-Type` field declares.
///
/// A value that does not parse yields no type, and a later field is not read.
fn declared_content_type(message: &[u8]) -> Option<MediaType> {
    // Skip the HTTP start line.
    let mut offset = next_line(message, 0)?.next;
    let mut value: Option<Vec<u8>> = None;
    let mut folding = false;

    loop {
        let line = next_line(message, offset)?;
        let content = &message[offset..line.end];
        offset = line.next;

        if content.is_empty() {
            break;
        }

        if content.first().copied().is_some_and(is_lws) {
            // A fold represents whitespace; media-type parsing decides whether it is valid here.
            if folding {
                if let Some(value) = &mut value {
                    value.push(b' ');
                    value.extend_from_slice(content.trim_ascii());
                }
            }
            continue;
        }

        folding = false;
        if value.is_none() {
            if let Some((name, colon)) = split_field_line(content) {
                if name.eq_ignore_ascii_case(CONTENT_TYPE) {
                    value = Some(content[colon + 1..].trim_ascii().to_vec());
                    folding = true;
                }
            }
        }
    }

    MediaType::parse(&value?).ok()
}

#[cfg(test)]
mod tests {
    use super::{declared_content_type, http_payload_type, payload_type};
    use crate::value::MediaType;

    const JSON_PAYLOAD: &[u8] = br#"{"key": [1, 2]}"#;

    /// The eight-byte PNG signature, padded so the payload is more than a bare signature.
    const PNG_PAYLOAD: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01";

    fn media_type(value: &str) -> MediaType {
        MediaType::parse(value.as_bytes()).expect("a media type")
    }

    /// Valid JSON is identified as `application/json`, whatever JSON type was declared.
    #[test]
    fn a_declared_json_payload_that_parses_is_identified_as_json() {
        for declared in ["application/json", "application/ld+json", "text/json"] {
            assert_eq!(
                payload_type(JSON_PAYLOAD, Some(&media_type(declared))),
                Some(MediaType::JSON),
                "{declared}"
            );
        }
    }

    /// Invalid declared JSON is identified from its content instead.
    #[test]
    fn a_declared_json_payload_that_does_not_parse_is_identified_by_content() {
        assert_eq!(
            payload_type(b"not json at all", Some(&MediaType::JSON)),
            Some(MediaType::TEXT_PLAIN)
        );
    }

    /// Without a JSON declaration, JSON is identified as plain text because it has no signature.
    #[test]
    fn json_is_identified_only_against_a_declaration() {
        assert_eq!(
            payload_type(JSON_PAYLOAD, None),
            Some(MediaType::TEXT_PLAIN)
        );
        assert_eq!(
            payload_type(JSON_PAYLOAD, Some(&MediaType::TEXT_PLAIN)),
            Some(MediaType::TEXT_PLAIN)
        );
    }

    /// A signature outranks the declaration, since identification examines the payload.
    #[test]
    fn a_signature_identifies_the_payload_whatever_was_declared() {
        assert_eq!(
            payload_type(PNG_PAYLOAD, Some(&MediaType::TEXT_PLAIN)),
            Some(media_type("image/png"))
        );
        assert_eq!(
            payload_type(PNG_PAYLOAD, None),
            Some(media_type("image/png"))
        );
    }

    /// Empty and unrecognized payloads are not identified as `application/octet-stream`.
    #[test]
    fn an_unidentifiable_payload_has_no_type() {
        assert_eq!(payload_type(b"", None), None);
        assert_eq!(payload_type(&[0u8; 32], None), None);
        assert_eq!(payload_type(&[0u8; 32], Some(&MediaType::JSON)), None);
    }

    /// Chunk framing is removed and the declared `Content-Type` is used during identification.
    #[test]
    fn the_entity_body_of_a_chunked_message_is_identified() {
        let message = b"HTTP/1.1 200 OK\r\n\
            Content-Type: application/json\r\n\
            Transfer-Encoding: chunked\r\n\
            \r\n\
            7\r\n{\"key\":\r\n8\r\n [1, 2]}\r\n0\r\n\r\n";

        assert_eq!(http_payload_type(message), Some(MediaType::JSON));
    }

    /// A message whose entity-body cannot be extracted is not identified.
    #[test]
    fn a_message_without_a_readable_body_is_not_identified() {
        for message in [
            // A transfer-coding this crate cannot remove.
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n\x1f\x8b\x08"[..],
            // No body at all.
            &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
            // No terminated header section.
            &b"HTTP/1.1 200 OK\r\n"[..],
        ] {
            assert_eq!(http_payload_type(message), None, "{message:?}");
        }
    }

    /// The declaration is the first `Content-Type` when it is well-formed, with folds joined.
    #[test]
    fn the_declared_content_type_is_read_from_the_header_section() {
        assert_eq!(
            declared_content_type(
                b"HTTP/1.1 200 OK\r\nSERVER: test\r\nCONTENT-TYPE: application/json\r\n\r\n"
            ),
            Some(MediaType::JSON)
        );
        assert_eq!(
            declared_content_type(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n ;charset=utf-8\r\n\r\n"
            ),
            Some(media_type("text/plain ;charset=utf-8"))
        );
        assert_eq!(
            declared_content_type(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            None
        );
        assert_eq!(
            declared_content_type(b"HTTP/1.1 200 OK\r\nContent-Type: not a media type\r\n\r\n"),
            None
        );
    }
}
