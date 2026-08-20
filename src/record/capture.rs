//! Records of a single capture event.
//!
//! A capture produces linked `request` and `response` records and, when a fetch time is set, a
//! `metadata` record. [`CaptureEvent`] holds their shared fields and
//! [`exchange`](CaptureEvent::exchange) returns them in write order.

use std::marker::PhantomData;
use std::net::IpAddr;
use std::time::Duration;

use fluent_uri::Uri;

use crate::record::extension::{Extension, NoExtension};
use crate::record::header::truncated_type::TruncatedType;
use crate::record::{BlockError, Record};
use crate::value::{LabelledDigest, WarcDate};

/// Fields shared by the records of one target capture.
///
/// Set optional capture fields, then call [`exchange`](Self::exchange) with the captured request
/// and response messages.
#[derive(Clone, Debug)]
pub struct CaptureEvent<E: Extension = NoExtension> {
    target_uri: Uri<String>,
    date: WarcDate,
    warcinfo_id: Option<Uri<String>>,
    ip_address: Option<IpAddr>,
    payload_digest: Option<LabelledDigest>,
    truncated: Option<TruncatedType<E::TruncatedReasons>>,
    fetch_time: Option<Duration>,
    #[cfg(feature = "payload-identification")]
    identify_payload_type: bool,
    extension: PhantomData<E>,
}

impl<E: Extension> CaptureEvent<E> {
    /// Create a capture event for a target URI and date.
    #[must_use]
    pub fn new(target_uri: Uri<String>, date: impl Into<WarcDate>) -> Self {
        Self {
            target_uri,
            date: date.into(),
            warcinfo_id: None,
            ip_address: None,
            payload_digest: None,
            truncated: None,
            fetch_time: None,
            #[cfg(feature = "payload-identification")]
            identify_payload_type: false,
            extension: PhantomData,
        }
    }

    /// Set the `WARC-Warcinfo-ID` shared by the capture records.
    #[must_use]
    pub fn warcinfo_id(mut self, record_id: Uri<String>) -> Self {
        self.warcinfo_id = Some(record_id);

        self
    }

    /// Set the response record's `WARC-IP-Address`.
    #[must_use]
    pub const fn ip_address(mut self, ip_address: IpAddr) -> Self {
        self.ip_address = Some(ip_address);

        self
    }

    /// Set `WARC-Payload-Digest` for the response entity body.
    ///
    /// The digest is checked against the response block when the record is rendered.
    #[must_use]
    pub fn payload_digest(mut self, digest: LabelledDigest) -> Self {
        self.payload_digest = Some(digest);

        self
    }

    /// Set the response record's `WARC-Truncated` reason.
    ///
    /// A truncated record's payload digest is not checked when the record is rendered.
    #[must_use]
    pub fn truncated(mut self, reason: TruncatedType<E::TruncatedReasons>) -> Self {
        self.truncated = Some(reason);

        self
    }

    /// Set the time from initiating network traffic to completing the capture.
    ///
    /// Setting a fetch time adds a `metadata` record containing `fetchTimeMs`.
    #[must_use]
    pub const fn fetch_time(mut self, fetch_time: Duration) -> Self {
        self.fetch_time = Some(fetch_time);

        self
    }

    /// Identify the response payload and set `WARC-Identified-Payload-Type`.
    ///
    /// Uses [`identify::http_payload_type`](crate::record::identify::http_payload_type), which
    /// examines the payload instead of copying the response's `Content-Type`. The field is omitted
    /// when no type can be determined.
    #[cfg(feature = "payload-identification")]
    #[cfg_attr(docsrs, doc(cfg(feature = "payload-identification")))]
    #[must_use]
    pub const fn identify_payload_type(mut self) -> Self {
        self.identify_payload_type = true;

        self
    }

    /// Build the capture records in write order from the captured messages.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if a message cannot be paired with its record header. Any declared
    /// payload digest is checked later, when the response record is rendered.
    // The target URI has already been parsed, so parsing it again cannot fail.
    #[allow(clippy::missing_panics_doc)]
    pub fn exchange(
        self,
        request: impl Into<Vec<u8>>,
        response: impl Into<Vec<u8>>,
    ) -> Result<CaptureRecords<E>, BlockError>
    where
        E::RequestFields: Default,
        E::ResponseFields: Default,
        E::MetadataFields: Default,
    {
        let mut request_builder = Record::request(self.target_uri.as_str(), self.date)
            .expect("invariant violation: a parsed URI failed to reparse");
        if let Some(warcinfo_id) = &self.warcinfo_id {
            request_builder = request_builder.warcinfo_id(warcinfo_id.clone());
        }
        let request = request_builder.body(request)?;

        let response = response.into();
        let mut response_builder = Record::response(self.target_uri.as_str(), self.date)
            .expect("invariant violation: a parsed URI failed to reparse")
            .concurrent_to(request.core().record_id.clone());
        #[cfg(feature = "payload-identification")]
        if self.identify_payload_type
            && let Some(media_type) = crate::record::identify::http_payload_type(&response)
        {
            response_builder = response_builder.identified_payload_type(media_type);
        }
        if let Some(digest) = self.payload_digest {
            response_builder = response_builder.payload_digest(digest);
        }
        if let Some(warcinfo_id) = &self.warcinfo_id {
            response_builder = response_builder.warcinfo_id(warcinfo_id.clone());
        }
        if let Some(ip_address) = self.ip_address {
            response_builder = response_builder.ip_address(ip_address);
        }
        if let Some(reason) = self.truncated {
            response_builder = response_builder.truncated(reason);
        }
        let response = response_builder.body(response)?;

        let metadata = self.fetch_time.map(|fetch_time| {
            let mut metadata_builder = Record::metadata(self.date)
                .target_uri(self.target_uri)
                .concurrent_to(response.core().record_id.clone())
                .fetch_time_ms(fetch_time);
            if let Some(warcinfo_id) = self.warcinfo_id {
                metadata_builder = metadata_builder.warcinfo_id(warcinfo_id);
            }

            metadata_builder.build()
        });

        Ok(CaptureRecords {
            request,
            response,
            metadata,
        })
    }
}

/// The records of one capture, in write order.
///
/// The response names the request with `WARC-Concurrent-To`, and the optional metadata record
/// names the response. Thus every reference points backward when the fields are written in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRecords<E: Extension = NoExtension> {
    /// The captured request.
    pub request: Record<E>,
    /// The captured response, linked to [`request`](Self::request).
    pub response: Record<E>,
    /// Optional fetch metadata linked to [`response`](Self::response).
    pub metadata: Option<Record<E>>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::Utc;
    use sha2::Digest as _;

    use super::*;
    use crate::record::RenderError;
    use crate::value::DigestAlgorithm;

    const REQUEST_BLOCK: &[u8] = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
    const RESPONSE_BLOCK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";

    fn target_uri() -> Uri<String> {
        Uri::parse("https://example.com/")
            .expect("a URI")
            .to_owned()
    }

    fn warcinfo_id() -> Uri<String> {
        Uri::parse("urn:uuid:5d472f79-4d95-4bcd-9b7f-b06d9ff68e33")
            .expect("a URI")
            .to_owned()
    }

    fn entity_body_digest(entity_body: &[u8]) -> LabelledDigest {
        LabelledDigest::from_digest(DigestAlgorithm::Sha256, &sha2::Sha256::digest(entity_body))
    }

    #[test]
    fn the_records_share_the_capture_fields_and_link_in_write_order() {
        let ip_address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .warcinfo_id(warcinfo_id())
            .ip_address(ip_address)
            .payload_digest(entity_body_digest(b"hello"))
            .fetch_time(Duration::from_millis(1500))
            .exchange(REQUEST_BLOCK, RESPONSE_BLOCK)
            .expect("a capture");

        let Record::Request {
            header: request,
            body: request_body,
        } = &records.request
        else {
            panic!("not a request record");
        };
        let Record::Response {
            header: response,
            body: response_body,
        } = &records.response
        else {
            panic!("not a response record");
        };
        let Record::Metadata {
            header: metadata, ..
        } = records.metadata.as_ref().expect("a metadata record")
        else {
            panic!("not a metadata record");
        };

        assert_eq!(request_body, REQUEST_BLOCK);
        assert_eq!(response_body, RESPONSE_BLOCK);

        assert_eq!(request.core.date, response.core.date);
        assert_eq!(request.core.date, metadata.core.date);
        assert_eq!(request.target_uri, target_uri());
        assert_eq!(response.target_uri, target_uri());
        assert_eq!(metadata.target_uri, Some(target_uri()));

        assert_eq!(request.concurrent_to, [] as [fluent_uri::Uri<String>; 0]);
        assert_eq!(
            response.concurrent_to,
            std::slice::from_ref(&request.core.record_id)
        );
        assert_eq!(
            metadata.concurrent_to,
            std::slice::from_ref(&response.core.record_id)
        );
        assert_ne!(request.core.record_id, response.core.record_id);

        assert_eq!(request.warcinfo_id, Some(warcinfo_id()));
        assert_eq!(response.warcinfo_id, Some(warcinfo_id()));
        assert_eq!(metadata.warcinfo_id, Some(warcinfo_id()));

        assert_eq!(request.ip_address, None);
        assert_eq!(response.ip_address, Some(ip_address));
        assert_eq!(
            response.payload.payload_digest,
            Some(entity_body_digest(b"hello"))
        );

        records.request.into_raw().expect("a renderable request");
        records.response.into_raw().expect("a renderable response");
    }

    /// Identification is opt-in and applies only to the response record.
    #[cfg(feature = "payload-identification")]
    #[test]
    fn a_capture_identifies_the_response_payload_only_when_told_to() {
        use crate::value::MediaType;

        let response_block: &[u8] = b"HTTP/1.1 200 OK\r\n\
            content-type: application/json\r\n\
            content-length: 15\r\n\
            \r\n\
            {\"key\": [1, 2]}";
        let identified_type = |record: &Record| {
            record
                .payload()
                .and_then(|headers| headers.identified_payload_type.clone())
        };

        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .identify_payload_type()
            .exchange(REQUEST_BLOCK, response_block)
            .expect("a capture");

        assert_eq!(identified_type(&records.response), Some(MediaType::JSON));
        assert_eq!(identified_type(&records.request), None);
        records.response.into_raw().expect("a renderable response");

        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .exchange(REQUEST_BLOCK, response_block)
            .expect("a capture");

        assert_eq!(identified_type(&records.response), None);
    }

    /// An unidentified payload leaves the field off rather than failing the capture.
    #[cfg(feature = "payload-identification")]
    #[test]
    fn a_capture_told_to_identify_omits_the_field_it_cannot_fill() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .identify_payload_type()
            .exchange(
                REQUEST_BLOCK,
                b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\n\0\0\0\0".to_vec(),
            )
            .expect("a capture");

        assert_eq!(
            records
                .response
                .payload()
                .and_then(|headers| headers.identified_payload_type.clone()),
            None
        );
    }

    #[test]
    fn a_capture_without_a_fetch_time_has_no_metadata_record() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .exchange(REQUEST_BLOCK, RESPONSE_BLOCK)
            .expect("a capture");

        assert!(records.metadata.is_none());
    }

    #[test]
    fn a_truncation_reason_lands_on_the_response_record_alone() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .payload_digest(entity_body_digest(b"other"))
            .truncated(TruncatedType::Length)
            .exchange(REQUEST_BLOCK, RESPONSE_BLOCK)
            .expect("a capture");

        assert_eq!(records.request.core().truncated, None);
        assert_eq!(
            records.response.core().truncated,
            Some(TruncatedType::Length)
        );

        records
            .response
            .into_raw()
            .expect("a renderable truncated response despite the mismatched digest");
    }

    #[test]
    fn a_mismatched_payload_digest_fails_rendering_the_response() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .payload_digest(entity_body_digest(b"other"))
            .exchange(REQUEST_BLOCK, RESPONSE_BLOCK)
            .expect("a capture");

        assert!(matches!(
            records.response.into_raw(),
            Err(RenderError::Block(BlockError::PayloadDigestMismatch { .. }))
        ));
    }
}
