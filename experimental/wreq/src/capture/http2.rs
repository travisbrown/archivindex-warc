//! HTTP/2 reconstruction and observation at the codec's finalized-header hook.

use archivindex_warc::record::http::reconstruct_response;
use http::{HeaderMap, HeaderValue, StatusCode, Version, header};
use wreq::header::OrigHeaderMap;
use wreq_proto::ext::{OnPreserveHeaderCallback, on_preserve_header};

use super::{Arc, Error, Instant, Tap, io};

pub(super) fn observe_headers(
    request: &mut http::Request<wreq::Body>,
    profile: OrigHeaderMap,
    tap: Arc<Tap>,
) {
    on_preserve_header(request, Headers { profile, tap });
}

struct Headers {
    profile: OrigHeaderMap,
    tap: Arc<Tap>,
}

impl OnPreserveHeaderCallback for Headers {
    fn call(&self, headers: &mut HeaderMap) {
        self.profile.call(headers);
        let mut state = self.tap.state();
        let repeated = state.http2 && state.request_headers.replace(headers.clone()).is_some();
        if repeated {
            state.error = Some(io::Error::other("unexpected additional HTTP/2 request").into());
        }
        drop(state);
        if repeated {
            self.tap.done.notify_one();
        }
    }

    fn call_visit(
        &self,
        headers: &mut HeaderMap,
        dst: &mut dyn FnMut(&dyn AsRef<[u8]>, &HeaderValue),
    ) {
        // Only the HTTP/1 serializer calls this method. HTTP/2 must not send Connection.
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        self.profile.call_visit(headers, dst);
    }
}

impl Tap {
    pub(super) fn h2_head(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        head: bool,
    ) -> Result<(), Error> {
        let mut headers = headers.clone();
        if !head
            && !status.is_informational()
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::NOT_MODIFIED
        {
            // Chunked storage permits streaming limits and trailers without changing content coding.
            headers.remove(header::CONTENT_LENGTH);
            headers.insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
        }
        let bytes = reconstruct_response(Version::HTTP_2, status, &headers, None)
            .map_err(|error| Error::Other(Box::new(error)))?;
        self.h2_push(&bytes)?;
        self.state().h2_response_started = true;
        Ok(())
    }

    pub(super) fn h2_data(&self, data: &[u8]) -> Result<(), Error> {
        if !data.is_empty() {
            self.h2_push(format!("{:x}\r\n", data.len()).as_bytes())?;
            self.h2_push(data)?;
            self.h2_push(b"\r\n")?;
        }
        Ok(())
    }

    pub(super) fn h2_trailers(&self, trailers: &HeaderMap) -> Result<(), Error> {
        if self.state().response.is_done() {
            return Ok(());
        }
        let mut bytes = Vec::from(&b"0\r\n"[..]);
        for (name, value) in trailers {
            if bytes
                .len()
                .saturating_add(name.as_str().len())
                .saturating_add(value.len())
                > 64 * 1024 - 6
            {
                return Err(io::Error::other("HTTP/2 trailers exceed capture limit").into());
            }
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        self.h2_push(&bytes)
    }

    fn h2_push(&self, bytes: &[u8]) -> Result<(), Error> {
        let mut state = self.state();
        if !state.response.is_done() {
            state.response.push(bytes)?;
            state.last_activity = Some(Instant::now());
            self.activity.notify_one();
        }
        let done = state.response.is_done();
        drop(state);
        if done {
            self.done.notify_one();
        }
        Ok(())
    }
}

/// Track completed outbound request frames without decoding HPACK or retaining connection bytes.
/// The codec callback supplies headers; `END_STREAM` proves the fixed request body was submitted.
/// This catches hidden retries and refuses to archive a complete request after a partial write.
#[derive(Default)]
pub(super) struct RequestCapture {
    preface: usize,
    header: [u8; 9],
    header_length: usize,
    remaining: usize,
    stream: Option<u32>,
    headers_complete: bool,
    end_stream: bool,
}

impl RequestCapture {
    pub(super) const fn is_complete(&self) -> bool {
        self.headers_complete && self.end_stream
    }

    /// Return whether the write advances the target request rather than connection control.
    pub(super) fn push(&mut self, mut bytes: &[u8]) -> io::Result<bool> {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let mut progress = false;
        while !bytes.is_empty() {
            if self.preface < PREFACE.len() {
                let count = bytes.len().min(PREFACE.len() - self.preface);
                if bytes[..count] != PREFACE[self.preface..self.preface + count] {
                    return Err(io::Error::other("invalid HTTP/2 client preface"));
                }
                self.preface += count;
                bytes = &bytes[count..];
                continue;
            }
            if self.header_length < 9 {
                let count = bytes.len().min(9 - self.header_length);
                self.header[self.header_length..self.header_length + count]
                    .copy_from_slice(&bytes[..count]);
                self.header_length += count;
                bytes = &bytes[count..];
                if self.header_length < 9 {
                    continue;
                }
                self.remaining = (usize::from(self.header[0]) << 16)
                    | (usize::from(self.header[1]) << 8)
                    | usize::from(self.header[2]);
                let stream = u32::from_be_bytes(self.header[5..9].try_into().expect("four bytes"))
                    & 0x7fff_ffff;
                if matches!(self.header[3], 0 | 1 | 9) {
                    if stream == 0 || self.stream.is_some_and(|id| id != stream) {
                        return Err(io::Error::other("unexpected HTTP/2 request stream"));
                    }
                    self.stream = Some(stream);
                    if self.end_stream && self.headers_complete {
                        return Err(io::Error::other("request frames after HTTP/2 END_STREAM"));
                    }
                }
            }
            let count = bytes.len().min(self.remaining);
            self.remaining -= count;
            bytes = &bytes[count..];
            progress |= matches!(self.header[3], 0 | 1 | 9);
            if self.remaining == 0 {
                if matches!(self.header[3], 1 | 9) && self.header[4] & 4 != 0 {
                    self.headers_complete = true;
                }
                if matches!(self.header[3], 0 | 1) && self.header[4] & 1 != 0 {
                    self.end_stream = true;
                }
                self.header_length = 0;
            }
        }
        Ok(progress)
    }
}

#[cfg(test)]
mod tests {
    use super::RequestCapture;

    #[test]
    fn request_completion_requires_fully_written_frames() {
        let mut capture = RequestCapture::default();
        capture.push(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        // A HEADERS frame with END_HEADERS, then a DATA frame with END_STREAM.
        let frames = [
            0, 0, 1, 1, 4, 0, 0, 0, 1, 0x82, 0, 0, 3, 0, 1, 0, 0, 0, 1, b'a', b'b', b'c',
        ];
        for byte in &frames[..frames.len() - 1] {
            capture.push(&[*byte]).unwrap();
            assert!(!capture.is_complete());
        }
        capture.push(&frames[frames.len() - 1..]).unwrap();
        assert!(capture.is_complete());
        // A request on another stream must not be silently attributed to this capture.
        assert!(capture.push(&[0, 0, 0, 1, 5, 0, 0, 0, 3]).is_err());
    }

    #[test]
    fn continuation_and_control_frames_do_not_end_a_request_early() {
        let mut capture = RequestCapture::default();
        capture.push(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        capture.push(&[0, 0, 0, 1, 1, 0, 0, 0, 1]).unwrap();
        assert!(!capture.is_complete());
        capture.push(&[0, 0, 0, 9, 4, 0, 0, 0, 1]).unwrap();
        assert!(capture.is_complete());
        assert!(!capture.push(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).unwrap());
    }
}
