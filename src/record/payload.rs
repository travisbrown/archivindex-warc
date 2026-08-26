//! HTTP entity-body extraction.
//!
//! For an `application/http` block, WARC 1.1 defines the payload as the HTTP entity-body: the
//! message body after transfer-coding has been removed.

use std::borrow::Cow;

use crate::parsing::{is_lws, lossy, next_line, split_field_line};

const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";

const CHUNKED: &[u8] = b"chunked";

const IDENTITY: &[u8] = b"identity";

/// Errors returned while extracting an HTTP entity-body.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The header section has no terminating empty line.
    #[error("The HTTP message does not end its header section with an empty line.")]
    UnterminatedHeaders,
    /// The message uses an unsupported transfer-coding.
    #[error("The HTTP message declares the transfer-coding `{0}`, which this crate cannot remove.")]
    UnsupportedTransferCoding(String),
    /// A chunk has an invalid size line.
    #[error("The chunked message declares `{0}` where a chunk size belongs.")]
    MalformedChunkSize(String),
    /// The chunked body is incomplete.
    #[error("The chunked message ends before the chunk that closes it.")]
    IncompleteChunkedBody,
}

/// Extract the HTTP entity-body defined by RFC 2616 section 7.2.
///
/// Chunk framing and trailers are removed. `identity` is ignored, while content-coding is
/// preserved. The record's `Content-Length` frames `message`, so the HTTP `Content-Length` is not
/// read. If no decoding is needed, the returned value borrows from `message`.
///
/// # Errors
///
/// Returns an error if the header section is malformed, if a body that opens as a chunked message
/// is framed badly from there on, or if the message uses an unsupported transfer-coding.
pub fn entity_body(message: &[u8]) -> Result<Cow<'_, [u8]>, Error> {
    let (body, transfer_encoding) = split_message(message)?;

    if is_chunked(&transfer_encoding)? && opens_chunked(body) {
        Ok(Cow::Owned(dechunk(body)?))
    } else {
        Ok(Cow::Borrowed(body))
    }
}

/// Whether a body opens with a chunk size line.
///
/// Capturing tools commonly store a body they have already dechunked while keeping the
/// `Transfer-Encoding` field it arrived with, so a body declared chunked that does not begin as
/// one is the entity-body as stored.
fn opens_chunked(body: &[u8]) -> bool {
    next_line(body, 0).is_some_and(|line| chunk_size(&body[..line.end]).is_ok())
}

/// Split an HTTP message into its body and combined `Transfer-Encoding` value.
///
/// Repeated and folded fields are combined into one comma-separated value.
fn split_message(message: &[u8]) -> Result<(&[u8], Vec<u8>), Error> {
    // Skip the HTTP start line.
    let mut offset = next_line(message, 0)
        .ok_or(Error::UnterminatedHeaders)?
        .next;
    let mut transfer_encoding = Vec::new();
    let mut folding = false;

    loop {
        let line = next_line(message, offset).ok_or(Error::UnterminatedHeaders)?;
        let content = &message[offset..line.end];
        offset = line.next;

        if content.is_empty() {
            return Ok((&message[offset..], transfer_encoding));
        }

        if content.first().copied().is_some_and(is_lws) {
            // Folded lines continue the preceding field.
            if folding {
                transfer_encoding.push(b' ');
                transfer_encoding.extend_from_slice(content);
            }
            continue;
        }

        folding = false;
        if let Some((name, colon)) = split_field_line(content)
            && name.eq_ignore_ascii_case(TRANSFER_ENCODING)
        {
            if !transfer_encoding.is_empty() {
                transfer_encoding.push(b',');
            }
            transfer_encoding.extend_from_slice(&content[colon + 1..]);
            folding = true;
        }
    }
}

/// Check whether `Transfer-Encoding` requests chunk decoding.
///
/// Empty elements and `identity` are ignored. No coding may follow `chunked`.
fn is_chunked(transfer_encoding: &[u8]) -> Result<bool, Error> {
    let mut chunked = false;

    for coding in transfer_encoding.split(|&byte| byte == b',') {
        let coding = coding.trim_ascii();
        if coding.is_empty() || coding.eq_ignore_ascii_case(IDENTITY) {
            continue;
        }
        if chunked || !coding.eq_ignore_ascii_case(CHUNKED) {
            return Err(Error::UnsupportedTransferCoding(lossy(
                transfer_encoding.trim_ascii(),
            )));
        }
        chunked = true;
    }

    Ok(chunked)
}

/// Decode a chunked body as defined by RFC 2616 section 3.6.1.
///
/// Chunk extensions, framing, and trailers are omitted from the result.
fn dechunk(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::with_capacity(body.len());
    let mut offset = 0;

    loop {
        let line = next_line(body, offset).ok_or(Error::IncompleteChunkedBody)?;
        let size = chunk_size(&body[offset..line.end])?;
        offset = line.next;

        if size == 0 {
            return Ok(decoded);
        }

        let end = offset
            .checked_add(size)
            .filter(|end| *end <= body.len())
            .ok_or(Error::IncompleteChunkedBody)?;
        decoded.extend_from_slice(&body[offset..end]);

        // The chunk data must be followed immediately by a line ending.
        let line = next_line(body, end).ok_or(Error::IncompleteChunkedBody)?;
        if line.end != end {
            return Err(Error::IncompleteChunkedBody);
        }
        offset = line.next;
    }
}

/// Parse a hexadecimal chunk size, ignoring extensions.
fn chunk_size(line: &[u8]) -> Result<usize, Error> {
    let digits = line
        .iter()
        .position(|&byte| byte == b';')
        .map_or(line, |extensions| &line[..extensions])
        .trim_ascii();

    std::str::from_utf8(digits)
        .ok()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|digits| usize::from_str_radix(digits, 16).ok())
        .ok_or_else(|| Error::MalformedChunkSize(lossy(line)))
}

#[cfg(test)]
mod tests {
    use super::{Error, entity_body};

    /// Without transfer-coding, the bytes after the header section are the entity-body.
    #[test]
    fn body_of_an_unencoded_message() {
        let message = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

        assert_eq!(entity_body(message).unwrap().as_ref(), b"hello");
    }

    /// A message ending after its headers has an empty entity-body.
    #[test]
    fn body_of_a_message_without_one() {
        let message = b"HTTP/1.1 204 No Content\r\n\r\n";

        assert_eq!(entity_body(message).unwrap().as_ref(), b"");
    }

    /// Bare `LF` line endings are accepted, as elsewhere in this crate.
    #[test]
    fn body_of_a_message_written_with_bare_line_feeds() {
        let message = b"HTTP/1.1 200 OK\nContent-Length: 5\n\nhello";

        assert_eq!(entity_body(message).unwrap().as_ref(), b"hello");
    }

    /// A header section without a closing empty line has no identifiable body.
    #[test]
    fn unterminated_headers() {
        for message in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(
                entity_body(message).unwrap_err(),
                Error::UnterminatedHeaders,
                "{message:?}"
            );
        }
    }

    /// Chunk sizes, extensions, and trailers are framing and are removed.
    #[test]
    fn chunked_body_is_joined() {
        let message = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5;name=value\r\n",
            "hello\r\n",
            "2\r\n",
            " w\r\n",
            "5\r\n",
            "orld!\r\n",
            "0\r\n",
            "Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n",
            "\r\n",
        );

        assert_eq!(
            entity_body(message.as_bytes()).unwrap().as_ref(),
            b"hello world!"
        );
    }

    /// A chunked body may end immediately after its zero-length chunk.
    #[test]
    fn chunked_body_ending_at_its_last_chunk() {
        let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";

        assert_eq!(entity_body(message).unwrap().as_ref(), b"abc");
    }

    /// The `identity` coding leaves the body unchanged.
    #[test]
    fn identity_coding_is_dropped() {
        let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Identity\r\n\r\nhello";

        assert_eq!(entity_body(message).unwrap().as_ref(), b"hello");
    }

    /// Repeated and folded `Transfer-Encoding` fields form one comma-separated list.
    #[test]
    fn transfer_encoding_is_read_as_one_list() {
        let message = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: identity,\r\n",
            "\tchunked\r\n",
            "Transfer-Encoding: identity\r\n",
            "\r\n",
            "3\r\nabc\r\n0\r\n\r\n",
        );

        assert_eq!(entity_body(message.as_bytes()).unwrap().as_ref(), b"abc");
    }

    /// An unsupported coding is reported with the complete value that named it.
    #[test]
    fn unsupported_transfer_coding() {
        let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\nhello";

        assert_eq!(
            entity_body(message).unwrap_err(),
            Error::UnsupportedTransferCoding("gzip, chunked".to_owned())
        );
    }

    /// Content-coding is part of the entity-body and remains unchanged.
    #[test]
    fn content_coding_is_left_in_place() {
        let message = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b\x08";

        assert_eq!(entity_body(message).unwrap().as_ref(), b"\x1f\x8b\x08");
    }

    #[test]
    fn malformed_chunked_bodies() {
        let prefix = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

        for (body, expected) in [
            // A chunk after the first declares a size that is not one.
            (
                "3\r\nabc\r\nzz\r\ndef\r\n0\r\n\r\n",
                Error::MalformedChunkSize("zz".to_owned()),
            ),
            // The body ends inside the data of a chunk.
            ("5\r\nabc", Error::IncompleteChunkedBody),
            // The data of a chunk is not closed by a line ending.
            ("3\r\nabcdef\r\n0\r\n\r\n", Error::IncompleteChunkedBody),
            // No chunk closes the body.
            ("3\r\nabc\r\n", Error::IncompleteChunkedBody),
        ] {
            let message = [prefix.as_bytes(), body.as_bytes()].concat();

            assert_eq!(entity_body(&message).unwrap_err(), expected, "{body:?}");
        }
    }

    /// Capturing tools store dechunked bodies under the `Transfer-Encoding` the response carried,
    /// which the payload digests of such records are computed over.
    #[test]
    fn body_declared_chunked_that_does_not_open_as_one_is_read_as_stored() {
        let prefix = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: -1\r\n\r\n";

        for body in [
            "<!doctype html>\r\n<title>a</title>",
            "zz\r\nabc\r\n0\r\n\r\n",
            "",
        ] {
            let message = [prefix.as_bytes(), body.as_bytes()].concat();

            assert_eq!(
                entity_body(&message).unwrap().as_ref(),
                body.as_bytes(),
                "{body:?}"
            );
        }
    }
}
