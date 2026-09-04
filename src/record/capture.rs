//! Records of a single capture event.
//!
//! A capture produces linked `request` and `response` records and, when a fetch time is set, a
//! `metadata` record. [`CaptureEvent`] holds their shared fields, and
//! [`exchange`](CaptureEvent::exchange) returns the records in write order.
//! [`revisit_exchange`](CaptureEvent::revisit_exchange) substitutes a `revisit` record that refers
//! to previously archived content.

use std::marker::PhantomData;
use std::net::IpAddr;
use std::time::Duration;

use fluent_uri::Uri;

use crate::record::builder::{MetadataBuilder, RequestBuilder};
use crate::record::extension::{Extension, NoExtension};
use crate::record::header::RevisitProfile;
use crate::record::header::truncated_type::TruncatedType;
use crate::record::{BlockError, Record};
use crate::value::{LabelledDigest, MediaType, WarcDate};

/// Fields shared by the records of one target capture.
///
/// Set optional fields, then call [`exchange`](Self::exchange) or
/// [`revisit_exchange`](Self::revisit_exchange) with the captured messages.
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

    /// Set `WARC-Payload-Digest` for the captured or revisited payload.
    ///
    /// A response record checks the digest when rendered. A `revisit` record uses it to identify
    /// the payload of the original record.
    #[must_use]
    pub fn payload_digest(mut self, digest: LabelledDigest) -> Self {
        self.payload_digest = Some(digest);

        self
    }

    /// Set the response or `revisit` record's `WARC-Truncated` reason.
    ///
    /// An `identical-payload-digest` revisit ignores this reason; a non-empty response head uses
    /// `length`. A truncated record's payload digest is not checked when rendered.
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
    #[expect(
        clippy::missing_panics_doc,
        reason = "the target URI has already been parsed, so parsing it again cannot fail"
    )]
    pub fn exchange(
        mut self,
        request: impl Into<Vec<u8>>,
        response: impl Into<Vec<u8>>,
    ) -> Result<CaptureRecords<E>, BlockError>
    where
        E::RequestFields: Default,
        E::ResponseFields: Default,
        E::MetadataFields: Default,
    {
        let request = self.request_builder().body(request)?;

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
        if let Some(digest) = self.payload_digest.take() {
            response_builder = response_builder.payload_digest(digest);
        }
        if let Some(warcinfo_id) = &self.warcinfo_id {
            response_builder = response_builder.warcinfo_id(warcinfo_id.clone());
        }
        if let Some(ip_address) = self.ip_address {
            response_builder = response_builder.ip_address(ip_address);
        }
        if let Some(reason) = self.truncated.take() {
            response_builder = response_builder.truncated(reason);
        }
        let response = response_builder.body(response)?;
        let metadata = self.metadata_record(response.core().record_id.clone());

        Ok(CaptureRecords {
            request,
            response,
            metadata,
        })
    }

    /// Build capture records with a `revisit` record in place of the response.
    ///
    /// `profile` determines what `response` contains. For `identical-payload-digest`, it is an
    /// optional response head. A non-empty head is marked `WARC-Truncated: length`, as WARC 1.1
    /// clause 6.7.2 requires; this profile ignores any truncation reason set on the event. For
    /// `server-not-modified`, it is the received `304 Not Modified` response and keeps the event's
    /// truncation reason. Any non-empty block is typed `application/http; msgtype=response`.
    ///
    /// The event's payload digest describes the revisited payload. The `identical-payload-digest`
    /// profile requires it. Payload identification is skipped because a revisit has no payload of
    /// its own; the original's identified payload type is repeated instead.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if a message cannot be paired with its record header.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the target URI has already been parsed, so parsing it again cannot fail"
    )]
    pub fn revisit_exchange(
        mut self,
        request: impl Into<Vec<u8>>,
        response: impl Into<Vec<u8>>,
        profile: RevisitProfile,
        original: RevisitOriginal,
    ) -> Result<CaptureRecords<E>, BlockError>
    where
        E::RequestFields: Default,
        E::RevisitFields: Default,
        E::MetadataFields: Default,
    {
        let request = self.request_builder().body(request)?;

        let response = response.into();
        let truncated = if matches!(profile, RevisitProfile::IdenticalPayloadDigest(_)) {
            (!response.is_empty()).then_some(TruncatedType::Length)
        } else {
            self.truncated.take()
        };
        let mut revisit_builder = Record::revisit(self.target_uri.as_str(), self.date, profile)
            .expect("invariant violation: a parsed URI failed to reparse")
            .concurrent_to(request.core().record_id.clone())
            .refers_to(original.record_id)
            .refers_to_target_uri(original.target_uri)
            .refers_to_date(original.date);
        if !response.is_empty() {
            revisit_builder = revisit_builder.content_type(MediaType::HTTP_RESPONSE);
        }
        if let Some(digest) = self.payload_digest.take() {
            revisit_builder = revisit_builder.payload_digest(digest);
        }
        if let Some(media_type) = original.identified_payload_type {
            revisit_builder = revisit_builder.identified_payload_type(media_type);
        }
        if let Some(warcinfo_id) = &self.warcinfo_id {
            revisit_builder = revisit_builder.warcinfo_id(warcinfo_id.clone());
        }
        if let Some(ip_address) = self.ip_address {
            revisit_builder = revisit_builder.ip_address(ip_address);
        }
        if let Some(reason) = truncated {
            revisit_builder = revisit_builder.truncated(reason);
        }
        let revisit = revisit_builder.body(response)?;
        let metadata = self.metadata_record(revisit.core().record_id.clone());

        Ok(CaptureRecords {
            request,
            response: revisit,
            metadata,
        })
    }

    /// Build the `request` record with the capture's shared fields.
    // The target URI has already been parsed, so parsing it again cannot fail.
    fn request_builder(&self) -> RequestBuilder<E>
    where
        E::RequestFields: Default,
    {
        let mut builder = Record::request(self.target_uri.as_str(), self.date)
            .expect("invariant violation: a parsed URI failed to reparse");
        if let Some(warcinfo_id) = &self.warcinfo_id {
            builder = builder.warcinfo_id(warcinfo_id.clone());
        }

        builder
    }

    /// Build metadata for `record_id` when a fetch time is set.
    fn metadata_record(self, record_id: Uri<String>) -> Option<Record<E>>
    where
        E::MetadataFields: Default,
    {
        self.fetch_time.map(|fetch_time| {
            let mut builder: MetadataBuilder<E> = Record::metadata(self.date)
                .target_uri(self.target_uri)
                .concurrent_to(record_id)
                .fetch_time_ms(fetch_time);
            if let Some(warcinfo_id) = self.warcinfo_id {
                builder = builder.warcinfo_id(warcinfo_id);
            }

            builder.build()
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
    /// The captured response, or its `revisit` substitute, linked to [`request`](Self::request).
    pub response: Record<E>,
    /// Optional fetch metadata linked to [`response`](Self::response).
    pub metadata: Option<Record<E>>,
}

impl<E: Extension> CaptureRecords<E> {
    /// Return the response identity needed by
    /// [`revisit_exchange`](CaptureEvent::revisit_exchange).
    #[expect(
        clippy::missing_panics_doc,
        reason = "a response or revisit record always names its target URI"
    )]
    #[must_use]
    pub fn revisit_original(&self) -> RevisitOriginal {
        RevisitOriginal {
            record_id: self.response.core().record_id.clone(),
            target_uri: self
                .response
                .target_uri()
                .expect("invariant violation: a capture's response record names its target URI")
                .clone(),
            date: self.response.core().date,
            identified_payload_type: self
                .response
                .payload()
                .and_then(|headers| headers.identified_payload_type.clone()),
        }
    }
}

/// The identity of the record a `revisit` refers to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisitOriginal {
    /// The original record's `WARC-Record-ID`, named by `WARC-Refers-To`.
    pub record_id: Uri<String>,
    /// The original record's target URI, named by `WARC-Refers-To-Target-URI`.
    pub target_uri: Uri<String>,
    /// The original record's `WARC-Date`, named by `WARC-Refers-To-Date`.
    pub date: WarcDate,
    /// The original record's `WARC-Identified-Payload-Type`, which the revisit repeats since it
    /// stands for the same payload.
    pub identified_payload_type: Option<MediaType>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::Utc;

    use super::*;
    use crate::record::RenderError;
    use crate::value::Algorithm;

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
        LabelledDigest::compute(Algorithm::Sha256, entity_body).unwrap()
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
        assert_eq!(
            records.revisit_original().identified_payload_type,
            Some(MediaType::JSON)
        );
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

    const NOT_MODIFIED_BLOCK: &[u8] = b"HTTP/1.1 304 Not Modified\r\netag: \"1\"\r\n\r\n";

    fn original() -> CaptureRecords {
        CaptureEvent::new(target_uri(), Utc::now())
            .payload_digest(entity_body_digest(b"hello"))
            .exchange(REQUEST_BLOCK, RESPONSE_BLOCK)
            .expect("a capture")
    }

    fn revisit_header(records: &CaptureRecords) -> &crate::record::header::RevisitHeader {
        let Record::Revisit { header, .. } = &records.response else {
            panic!("not a revisit record");
        };

        header
    }

    #[test]
    fn a_capture_names_the_original_later_revisits_refer_to() {
        let records = original();

        assert_eq!(
            records.revisit_original(),
            RevisitOriginal {
                record_id: records.response.core().record_id.clone(),
                target_uri: target_uri(),
                date: records.response.core().date,
                identified_payload_type: None,
            }
        );
    }

    #[test]
    fn a_revisit_repeats_the_identified_payload_type_of_its_original() {
        let mut original = original().revisit_original();
        original.identified_payload_type = Some(MediaType::TEXT_PLAIN);
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .payload_digest(entity_body_digest(b"hello"))
            .revisit_exchange(
                REQUEST_BLOCK,
                Vec::new(),
                RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
                original,
            )
            .expect("a revisit capture");

        assert_eq!(
            revisit_header(&records).payload.identified_payload_type,
            Some(MediaType::TEXT_PLAIN)
        );
        records.response.into_raw().expect("a renderable revisit");
    }

    #[test]
    fn an_identical_payload_revisit_stores_a_truncated_head_referring_to_the_original() {
        let original = original();
        let ip_address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let head = &RESPONSE_BLOCK[..RESPONSE_BLOCK.len() - b"hello".len()];
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .warcinfo_id(warcinfo_id())
            .ip_address(ip_address)
            .payload_digest(entity_body_digest(b"hello"))
            .truncated(TruncatedType::Disconnect)
            .fetch_time(Duration::from_millis(20))
            .revisit_exchange(
                REQUEST_BLOCK,
                head,
                RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
                original.revisit_original(),
            )
            .expect("a revisit capture");

        let revisit = revisit_header(&records);
        let Record::Metadata {
            header: metadata, ..
        } = records.metadata.as_ref().expect("a metadata record")
        else {
            panic!("not a metadata record");
        };

        assert_eq!(revisit.profile, RevisitProfile::IDENTICAL_PAYLOAD_DIGEST);
        assert_eq!(revisit.target_uri, target_uri());
        assert_eq!(
            revisit.refers_to.as_ref(),
            Some(&original.response.core().record_id)
        );
        assert_eq!(revisit.refers_to_target_uri, Some(target_uri()));
        assert_eq!(revisit.refers_to_date, Some(original.response.core().date));
        assert_eq!(
            revisit.payload.payload_digest,
            Some(entity_body_digest(b"hello"))
        );
        assert_eq!(revisit.core.content_type, Some(MediaType::HTTP_RESPONSE));
        assert_eq!(revisit.core.truncated, Some(TruncatedType::Length));
        assert_eq!(revisit.warcinfo_id, Some(warcinfo_id()));
        assert_eq!(revisit.ip_address, Some(ip_address));
        assert_eq!(
            revisit.concurrent_to,
            std::slice::from_ref(&records.request.core().record_id)
        );
        assert_eq!(
            metadata.concurrent_to,
            std::slice::from_ref(&revisit.core.record_id)
        );
        assert_eq!(records.response.body_bytes().as_ref(), head);

        records.request.into_raw().expect("a renderable request");
        records.response.into_raw().expect("a renderable revisit");
    }

    #[test]
    fn an_identical_payload_revisit_without_a_block_is_not_truncated() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .payload_digest(entity_body_digest(b"hello"))
            .truncated(TruncatedType::Disconnect)
            .revisit_exchange(
                REQUEST_BLOCK,
                Vec::new(),
                RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
                original().revisit_original(),
            )
            .expect("a revisit capture");

        let revisit = revisit_header(&records);
        assert_eq!(revisit.core.truncated, None);
        assert_eq!(revisit.core.content_type, None);
        records.response.into_raw().expect("a renderable revisit");
    }

    #[test]
    fn a_server_not_modified_revisit_stores_the_response_as_received() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .payload_digest(entity_body_digest(b"hello"))
            .revisit_exchange(
                REQUEST_BLOCK,
                NOT_MODIFIED_BLOCK,
                RevisitProfile::SERVER_NOT_MODIFIED,
                original().revisit_original(),
            )
            .expect("a revisit capture");

        let revisit = revisit_header(&records);
        assert_eq!(revisit.profile, RevisitProfile::SERVER_NOT_MODIFIED);
        assert_eq!(revisit.core.truncated, None);
        assert_eq!(revisit.core.content_type, Some(MediaType::HTTP_RESPONSE));
        assert_eq!(
            revisit.payload.payload_digest,
            Some(entity_body_digest(b"hello"))
        );
        assert_eq!(records.response.body_bytes().as_ref(), NOT_MODIFIED_BLOCK);
        assert!(records.metadata.is_none());

        records.response.into_raw().expect("a renderable revisit");
    }

    #[test]
    fn a_server_not_modified_revisit_keeps_the_event_truncation_reason() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .truncated(TruncatedType::Disconnect)
            .revisit_exchange(
                REQUEST_BLOCK,
                NOT_MODIFIED_BLOCK,
                RevisitProfile::SERVER_NOT_MODIFIED,
                original().revisit_original(),
            )
            .expect("a revisit capture");

        assert_eq!(
            revisit_header(&records).core.truncated,
            Some(TruncatedType::Disconnect)
        );
    }

    #[test]
    fn an_identical_payload_revisit_without_a_digest_fails_rendering() {
        let records: CaptureRecords = CaptureEvent::new(target_uri(), Utc::now())
            .revisit_exchange(
                REQUEST_BLOCK,
                Vec::new(),
                RevisitProfile::IDENTICAL_PAYLOAD_DIGEST,
                original().revisit_original(),
            )
            .expect("a revisit capture");

        assert!(matches!(
            records.response.into_raw(),
            Err(RenderError::MissingProfileField(_))
        ));
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
