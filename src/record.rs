use chrono::prelude::*;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;

use uuid::Uuid;

use crate::header::WarcHeader;
use crate::record_type::RecordType;
use crate::truncated_type::TruncatedType;
use crate::Error as WarcError;

use streaming_trait::BodyKind;
pub use streaming_trait::{BufferedBody, EmptyBody, StreamingBody};

mod streaming_trait {
    use std::io::Read;

    /// An associated type indicating how the body of a record is represented.
    pub trait BodyKind {
        fn content_length(&self) -> u64;
    }

    #[derive(Clone, Debug, PartialEq)]
    /// An associated type indicating the body is buffered within the record.
    pub struct BufferedBody(pub Vec<u8>);
    impl BodyKind for BufferedBody {
        fn content_length(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// An associated type indicating the body is streamed from a reader.
    pub struct StreamingBody<'t, T: Read + 't> {
        stream: &'t mut T,
        /// The declared `Content-Length`, unaffected by reads.
        declared_content_len: u64,
        /// The unread portion of the body, shared with the iterator that handed it out.
        remaining_len: &'t mut u64,
    }
    impl<'t, T: Read + 't> StreamingBody<'t, T> {
        pub(crate) fn new(stream: &'t mut T, remaining_len: &'t mut u64) -> StreamingBody<'t, T> {
            StreamingBody {
                stream,
                declared_content_len: *remaining_len,
                remaining_len,
            }
        }

        /// The unread portion of the body, shrinking as the stream is consumed.
        pub(crate) fn remaining_len(&self) -> u64 {
            *self.remaining_len
        }
    }
    impl<'t, T: Read + 't> BodyKind for StreamingBody<'t, T> {
        fn content_length(&self) -> u64 {
            self.declared_content_len
        }
    }

    impl<'t, T: Read + 't> Read for StreamingBody<'t, T> {
        fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
            let max_read = std::cmp::min(data.len(), *self.remaining_len as usize);
            self.stream.read(&mut data[..max_read]).inspect(|&n| {
                *self.remaining_len -= n as u64;
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    /// An associated type indicated the record has a zero-length body.
    pub struct EmptyBody();
    impl BodyKind for EmptyBody {
        fn content_length(&self) -> u64 {
            0
        }
    }
}

/// A header block of a single WARC record as parsed from a data stream.
///
/// It is guaranteed to be well-formed, but may not be valid according to the specification.
///
/// Use the `Display` trait to generate the formatted representation.
#[derive(Clone, Debug, PartialEq)]
pub struct RawRecordHeader {
    /// The WARC standard version this record reports conformance to.
    pub version: String,
    /// All headers that are part of this record.
    pub headers: HashMap<WarcHeader, Vec<u8>>,
}

impl AsRef<HashMap<WarcHeader, Vec<u8>>> for RawRecordHeader {
    fn as_ref(&self) -> &HashMap<WarcHeader, Vec<u8>> {
        &self.headers
    }
}

impl AsMut<HashMap<WarcHeader, Vec<u8>>> for RawRecordHeader {
    fn as_mut(&mut self) -> &mut HashMap<WarcHeader, Vec<u8>> {
        &mut self.headers
    }
}

impl std::convert::TryFrom<RawRecordHeader> for Record<EmptyBody> {
    type Error = WarcError;
    fn try_from(mut headers: RawRecordHeader) -> Result<Self, WarcError> {
        headers
            .as_mut()
            .remove(&WarcHeader::ContentLength)
            .ok_or(WarcError::MissingHeader(WarcHeader::ContentLength))
            .and_then(|vec| {
                String::from_utf8(vec).map_err(|_| {
                    WarcError::MalformedHeader(
                        WarcHeader::ContentLength,
                        "not a UTF-8 string".to_string(),
                    )
                })
            })
            .and_then(|len| Record::<EmptyBody>::parse_content_length(&len))?;

        let record_type = headers
            .as_mut()
            .remove(&WarcHeader::WarcType)
            .ok_or(WarcError::MissingHeader(WarcHeader::WarcType))
            .and_then(|vec| {
                String::from_utf8(vec).map_err(|_| {
                    WarcError::MalformedHeader(
                        WarcHeader::WarcType,
                        "not a UTF-8 string".to_string(),
                    )
                })
            })
            .map(|rtype| rtype.into())?;

        let record_id = headers
            .as_mut()
            .remove(&WarcHeader::RecordID)
            .ok_or(WarcError::MissingHeader(WarcHeader::RecordID))
            .and_then(|vec| {
                String::from_utf8(vec).map_err(|_| {
                    WarcError::MalformedHeader(
                        WarcHeader::RecordID,
                        "not a UTF-8 string".to_string(),
                    )
                })
            })?;

        let record_date = headers
            .as_mut()
            .remove(&WarcHeader::Date)
            .ok_or(WarcError::MissingHeader(WarcHeader::Date))
            .and_then(|vec| {
                String::from_utf8(vec).map_err(|_| {
                    WarcError::MalformedHeader(WarcHeader::Date, "not a UTF-8 string".to_string())
                })
            })
            .and_then(|date| Record::<BufferedBody>::parse_record_date(&date))?;

        let truncated_type = headers
            .as_mut()
            .remove(&WarcHeader::Truncated)
            .map(|vec| {
                String::from_utf8(vec).map_err(|_| {
                    WarcError::MalformedHeader(
                        WarcHeader::Truncated,
                        "not a UTF-8 string".to_string(),
                    )
                })
            })
            .transpose()?
            .map(|value| TruncatedType::from(&value));

        // `Record` guarantees UTF-8 header values; reject the record otherwise.
        for (header, value) in headers.as_ref().iter() {
            if std::str::from_utf8(value).is_err() {
                return Err(WarcError::MalformedHeader(
                    header.clone(),
                    "not a UTF-8 string".to_string(),
                ));
            }
        }

        Ok(Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: EmptyBody(),
        })
    }
}

impl std::fmt::Display for RawRecordHeader {
    fn fmt(&self, w: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(w, "WARC/{}", self.version)?;
        for (key, value) in self.as_ref().iter() {
            writeln!(w, "{}: {}", key, String::from_utf8_lossy(value))?;
        }
        writeln!(w)?;

        Ok(())
    }
}

/// A builder for WARC records from data.
#[derive(Clone, Default)]
pub struct RecordBuilder {
    value: Record<BufferedBody>,
    broken_headers: HashMap<WarcHeader, Vec<u8>>,
}

/// A single WARC record.
///
/// A record can be constructed by a `RecordBuilder`, or by reading from a stream.
///
/// The associated type `T` indicates the representation of this record's body.
///
/// A record is guaranteed to be valid according to the specification it conforms to, except:
/// * The validity of the WARC-Record-ID header is not checked
/// * Date information not in the UTC timezone will be silently converted to UTC
///
/// All header values in a record are guaranteed to be valid UTF-8: converting a
/// `RawRecordHeader` containing a non-UTF-8 header value fails with
/// `Error::MalformedHeader` naming the offending header. Use the raw record APIs to work
/// with records whose header values are arbitrary bytes.
///
/// Use the `Display` trait to generate the formatted representation.
#[derive(Debug, PartialEq)]
pub struct Record<T: BodyKind> {
    // NB: invariant: does not contain the headers stored in the struct
    headers: RawRecordHeader,
    record_date: DateTime<Utc>,
    record_id: String,
    record_type: RecordType,
    truncated_type: Option<TruncatedType>,
    body: T,
}

impl<T: BodyKind> Record<T> {
    /// Create a new empty record with default values.
    ///
    /// Using a `RecordBuilder` is more efficient when creating records from known data.
    ///
    /// The record returned contains an empty body, and the following fields:
    /// * WARC-Record-ID: generated by `generate_record_id()`
    /// * WARC-Date: the current moment in time
    /// * WARC-Type: resource
    /// * WARC-Content-Length: 0
    pub fn new() -> Record<EmptyBody> {
        Record::default()
    }

    /// Create a new empty record with a known body.
    ///
    /// Using a `RecordBuilder` is more efficient when creating records from known data.
    ///
    /// The record returned contains the passed body buffer, and the following fields:
    /// * WARC-Record-ID: generated by `generate_record_id()`
    /// * WARC-Date: the current moment in time
    /// * WARC-Type: resource
    /// * WARC-Content-Length: `body.len()`
    pub fn with_body<B: Into<Vec<u8>>>(body: B) -> Record<BufferedBody> {
        Record {
            body: BufferedBody(body.into()),
            ..Record::default()
        }
    }

    /// Generate and return a new value suitable for use in the WARC-Record-ID header.
    ///
    /// # Compatibility
    /// The standard only places a small number of constraints on this field:
    /// 1. This value is globally unique "for its period of use"
    /// 1. This value is a valid URI
    /// 1. This value "clearly indicate\[s\] a documented and registered scheme to which it conforms."
    ///
    /// These guarantees will be upheld by all generated outputs, where the "period of use" is
    /// presumed to be indefinite and unlimited.
    ///
    /// However, any *specific algorithm* used to generate values is **not** part of the crate's
    /// public API for purposes of semantic versioning.
    ///
    /// # Implementation
    /// The current implementation generates random values based on UUID version 4.
    ///
    pub fn generate_record_id() -> String {
        format!("<{}>", Uuid::new_v4().to_urn())
    }

    fn parse_content_length(len: &str) -> Result<u64, WarcError> {
        crate::parse_content_length(len).ok_or_else(|| {
            WarcError::MalformedHeader(
                WarcHeader::ContentLength,
                "not a digit sequence between 0 and 2^64-1".to_string(),
            )
        })
    }

    fn parse_record_date(date: &str) -> Result<DateTime<Utc>, WarcError> {
        DateTime::parse_from_rfc3339(date)
            .map_err(|_| {
                WarcError::MalformedHeader(
                    WarcHeader::Date,
                    "not an ISO 8601 datestamp".to_string(),
                )
            })
            .map(|date| date.into())
    }

    /// Return the WARC version string of this record.
    pub fn warc_version(&self) -> &str {
        &self.headers.version
    }

    /// Set the WARC version string of this record.
    pub fn set_warc_version<S: Into<String>>(&mut self, id: S) {
        self.headers.version = id.into();
    }

    /// Return the WARC-Record-ID header for this record.
    pub fn warc_id(&self) -> &str {
        &self.record_id
    }

    /// Set the WARC-Record-ID header for this record.
    ///
    /// Note that this value is **not** checked for validity.
    pub fn set_warc_id<S: Into<String>>(&mut self, id: S) {
        self.record_id = id.into();
    }

    /// Return the WARC-Type header for this record.
    pub fn warc_type(&self) -> &RecordType {
        &self.record_type
    }

    /// Set the WARC-Type header for this record.
    pub fn set_warc_type(&mut self, type_: RecordType) {
        self.record_type = type_;
    }

    /// Return the WARC-Date header for this record.
    pub fn date(&self) -> &DateTime<Utc> {
        &self.record_date
    }

    /// Set the WARC-Date header for this record.
    pub fn set_date(&mut self, date: DateTime<Utc>) {
        self.record_date = date;
    }

    /// Return the WARC-Truncated header for this record.
    pub fn truncated_type(&self) -> &Option<TruncatedType> {
        &self.truncated_type
    }

    /// Set the WARC-Truncated header for this record.
    pub fn set_truncated_type(&mut self, truncated_type: TruncatedType) {
        self.truncated_type = Some(truncated_type);
    }

    /// Remove the WARC-Truncated header for this record.
    pub fn clear_truncated_type(&mut self) {
        self.truncated_type = None;
    }

    /// Return the WARC header requested if present in this record, or `None`.
    pub fn header(&self, header: WarcHeader) -> Option<Cow<'_, str>> {
        match &header {
            WarcHeader::ContentLength => {
                Some(Cow::Owned(format!("{}", self.body.content_length())))
            }
            WarcHeader::RecordID => Some(Cow::Borrowed(self.warc_id())),
            WarcHeader::WarcType => Some(Cow::Owned(self.record_type.to_string())),
            WarcHeader::Date => Some(Cow::Owned(
                self.date().to_rfc3339_opts(SecondsFormat::Secs, true),
            )),
            WarcHeader::Truncated => self
                .truncated_type
                .as_ref()
                .map(|truncated_type| Cow::Owned(truncated_type.to_string())),
            _ => self.headers.as_ref().get(&header).map(|value| {
                Cow::Borrowed(
                    std::str::from_utf8(value)
                        .expect("invariant violation: record header value is not UTF-8"),
                )
            }),
        }
    }

    /// Set a WARC header in this record, returning the previous value if present.
    ///
    /// # Errors
    ///
    /// If setting a header whose value has a well-formedness test, an error is returned if the
    /// value is not well-formed.
    pub fn set_header<V>(
        &mut self,
        header: WarcHeader,
        value: V,
    ) -> Result<Option<Cow<'_, str>>, WarcError>
    where
        V: Into<String>,
    {
        let value = value.into();
        match &header {
            WarcHeader::Date => {
                let old_date = std::mem::replace(
                    &mut self.record_date,
                    Record::<T>::parse_record_date(&value)?,
                );
                Ok(Some(Cow::Owned(
                    old_date.to_rfc3339_opts(SecondsFormat::Secs, true),
                )))
            }
            WarcHeader::RecordID => {
                let old_id = std::mem::replace(&mut self.record_id, value);
                Ok(Some(Cow::Owned(old_id)))
            }
            WarcHeader::WarcType => {
                let old_type = std::mem::replace(&mut self.record_type, RecordType::from(&value));
                Ok(Some(Cow::Owned(old_type.to_string())))
            }
            WarcHeader::Truncated => {
                let old_type = self.truncated_type.take();
                self.truncated_type = Some(TruncatedType::from(&value));
                Ok(old_type.map(|old| (Cow::Owned(old.to_string()))))
            }
            WarcHeader::ContentLength => {
                if Record::<T>::parse_content_length(&value)? != self.body.content_length() {
                    Err(WarcError::MalformedHeader(
                        WarcHeader::ContentLength,
                        "content length != body size".to_string(),
                    ))
                } else {
                    Ok(Some(Cow::Owned(value)))
                }
            }
            _ => Ok(self
                .headers
                .as_mut()
                .insert(header, Vec::from(value))
                .map(|v| {
                    Cow::Owned(
                        String::from_utf8(v)
                            .expect("invariant violation: record header value is not UTF-8"),
                    )
                })),
        }
    }

    /// Return the Content-Length header for this record.
    ///
    /// For buffered and empty bodies this is the actual length of the body. For streaming
    /// bodies it is the declared `Content-Length`, unaffected by how much of the body has
    /// been read (though the actual stream may still turn out shorter or longer than
    /// declared).
    pub fn content_length(&self) -> u64 {
        self.body.content_length()
    }
}

impl Record<EmptyBody> {
    /// Add a known body to this record, transforming it into a buffered body record.
    pub fn add_body<B: Into<Vec<u8>>>(self, body: B) -> Record<BufferedBody> {
        let Self {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: _,
        } = self;
        Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: BufferedBody(body.into()),
        }
    }

    /// Add a streaming body to this record, whose expected size may not match the actual stream
    /// length.
    pub fn add_fixed_stream<'r, R: Read + 'r>(
        self,
        stream: &'r mut R,
        len: &'r mut u64,
    ) -> std::io::Result<Record<StreamingBody<'r, R>>> {
        let Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            ..
        } = self;

        Ok(Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: StreamingBody::new(stream, len),
        })
    }
}

impl Record<BufferedBody> {
    /// Strip the body from this record.
    pub fn strip_body(self) -> Record<EmptyBody> {
        let Self {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: _,
        } = self;
        Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: EmptyBody(),
        }
    }

    /// Return the body of this record.
    pub fn body(&self) -> &[u8] {
        self.body.0.as_slice()
    }

    /// Return a reference to mutate the body of this record, but without changing its length.
    ///
    /// To update the body of the record or change its length, use the `replace_body` method
    /// instead.
    pub fn body_mut(&mut self) -> &mut [u8] {
        self.body.0.as_mut_slice()
    }

    /// Replace the body of this record with the given body.
    pub fn replace_body<V: Into<Vec<u8>>>(&mut self, new_body: V) {
        let _: Vec<u8> = std::mem::replace(&mut self.body.0, new_body.into());
    }

    /// Transform this record into a raw record containing the same data.
    pub fn into_raw_parts(self) -> (RawRecordHeader, Vec<u8>) {
        let Record {
            mut headers,
            record_date,
            record_id,
            record_type,
            body,
            ..
        } = self;
        let insert1 = headers.as_mut().insert(
            WarcHeader::ContentLength,
            format!("{}", body.0.len()).into(),
        );
        let insert2 = headers
            .as_mut()
            .insert(WarcHeader::WarcType, record_type.to_string().into());
        let insert3 = headers
            .as_mut()
            .insert(WarcHeader::RecordID, record_id.into());
        let insert4 = if let Some(ref truncated_type) = self.truncated_type {
            headers
                .as_mut()
                .insert(WarcHeader::Truncated, truncated_type.to_string().into())
        } else {
            None
        };
        let insert5 = headers.as_mut().insert(
            WarcHeader::Date,
            record_date
                .to_rfc3339_opts(SecondsFormat::Secs, true)
                .into(),
        );

        debug_assert!(
            insert1.is_none()
                && insert2.is_none()
                && insert3.is_none()
                && insert4.is_none()
                && insert5.is_none(),
            "invariant violation: raw struct contains externally stored fields"
        );

        (headers, body.0)
    }
}

impl<'t, T: Read + 't> Record<StreamingBody<'t, T>> {
    /// Returns a record with a buffered body by collecting the streaming body.
    ///
    /// # Errors
    ///
    /// This method can fail if the underlying stream returns an error. If this happens, the
    /// state of the stream is not guaranteed.
    pub fn into_buffered(self) -> std::io::Result<Record<BufferedBody>> {
        let Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            mut body,
        } = self;

        let buf = {
            let mut body_vec = Vec::with_capacity(body.remaining_len() as usize);
            body.read_to_end(&mut body_vec)?;
            body_vec
        };

        let empty_record = Record {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            ..Default::default()
        };

        Ok(empty_record.add_body(buf))
    }
}

impl<'t, T: Read + 't> Read for Record<StreamingBody<'t, T>> {
    fn read(&mut self, dst: &mut [u8]) -> Result<usize, std::io::Error> {
        self.body.read(dst)
    }
}

impl Default for Record<BufferedBody> {
    fn default() -> Record<BufferedBody> {
        Record {
            headers: RawRecordHeader {
                version: "1.0".to_string(),
                headers: HashMap::new(),
            },
            record_date: Utc::now(),
            record_id: Record::<BufferedBody>::generate_record_id(),
            record_type: RecordType::Resource,
            truncated_type: None,
            body: BufferedBody(vec![]),
        }
    }
}

impl Default for Record<EmptyBody> {
    fn default() -> Record<EmptyBody> {
        Record {
            headers: RawRecordHeader {
                version: "1.0".to_string(),
                headers: HashMap::new(),
            },
            record_date: Utc::now(),
            record_id: Record::<EmptyBody>::generate_record_id(),
            record_type: RecordType::Resource,
            truncated_type: None,
            body: EmptyBody(),
        }
    }
}

impl fmt::Display for Record<BufferedBody> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (headers, body) = self.clone().into_raw_parts();
        write!(f, "Record({}, {:?})", headers, body)
    }
}
impl fmt::Display for Record<EmptyBody> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Giving the record an empty body reuses the header rendering the buffered
        // implementation gets from `into_raw_parts`, which puts back the headers this type
        // stores outside the map.
        let (headers, _) = self.clone().add_body(Vec::new()).into_raw_parts();
        write!(f, "Record({}, Empty)", headers)
    }
}

impl Clone for Record<EmptyBody> {
    fn clone(&self) -> Self {
        Record {
            headers: self.headers.clone(),
            record_type: self.record_type.clone(),
            record_date: self.record_date,
            record_id: self.record_id.clone(),
            truncated_type: self.truncated_type.clone(),
            body: self.body,
        }
    }
}

impl Clone for Record<BufferedBody> {
    fn clone(&self) -> Self {
        Record {
            headers: self.headers.clone(),
            record_type: self.record_type.clone(),
            record_date: self.record_date,
            record_id: self.record_id.clone(),
            truncated_type: self.truncated_type.clone(),
            body: self.body.clone(),
        }
    }
}

impl RecordBuilder {
    /// Set the body of the record under construction.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.value.replace_body(body);

        self
    }

    /// Set the record date header of the record under construction.
    pub fn date(mut self, date: DateTime<Utc>) -> Self {
        self.value.set_date(date);

        self
    }

    /// Set the record ID header of the record under construction.
    pub fn warc_id<S: Into<String>>(mut self, id: S) -> Self {
        self.value.set_warc_id(id);

        self
    }

    /// Set the WARC version of the record under construction.
    pub fn version(mut self, version: String) -> Self {
        self.value.set_warc_version(version);

        self
    }

    /// Set the WARC record type header field of the record under construction.
    pub fn warc_type(mut self, warc_type: RecordType) -> Self {
        self.value.set_warc_type(warc_type);

        self
    }

    /// Set the truncated type header of the record under construction.
    pub fn truncated_type(mut self, trunc_type: TruncatedType) -> Self {
        self.value.set_truncated_type(trunc_type);

        self
    }

    /// Apply a raw header value to a record, first checking that it is UTF-8.
    fn set_raw_header(
        record: &mut Record<BufferedBody>,
        key: WarcHeader,
        value: &[u8],
    ) -> Result<(), WarcError> {
        match std::str::from_utf8(value) {
            Ok(string) => record.set_header(key, string).map(|_| ()),
            Err(_) => Err(WarcError::MalformedHeader(
                key,
                "not a UTF-8 string".to_string(),
            )),
        }
    }

    /// Create or replace an arbitrary header of the record under construction.
    ///
    /// A value that is not valid for the record as built so far is kept aside and retried
    /// against the finished record when `build` runs, so an error that a later call cures
    /// (for example a `Content-Length` set before the body it describes) does not fail the
    /// build.
    pub fn header<V: Into<Vec<u8>>>(mut self, key: WarcHeader, value: V) -> Self {
        let value = value.into();
        match Self::set_raw_header(&mut self.value, key.clone(), &value) {
            Ok(()) => {
                self.broken_headers.remove(&key);
            }
            Err(_) => {
                self.broken_headers.insert(key, value);
            }
        }

        self
    }

    /// Build a raw record header from the data collected in this builder.
    ///
    /// A body set in this builder will be returned raw.
    pub fn build_raw(self) -> (RawRecordHeader, Vec<u8>) {
        let RecordBuilder {
            value,
            broken_headers,
        } = self;
        let (mut headers, body) = value.into_raw_parts();
        headers.as_mut().extend(broken_headers);

        (headers, body)
    }

    /// Build a record from the data collected in this builder.
    ///
    /// Header values that were not valid when they were set are retried here against the
    /// finished record.
    ///
    /// # Errors
    ///
    /// Returns the error for a header value that is still not valid for the finished
    /// record.
    pub fn build(self) -> Result<Record<BufferedBody>, WarcError> {
        let RecordBuilder {
            mut value,
            broken_headers,
        } = self;

        for (key, raw_value) in broken_headers {
            Self::set_raw_header(&mut value, key, &raw_value)?;
        }

        Ok(value)
    }
}

#[cfg(test)]
mod record_tests {
    use crate::header::WarcHeader;
    use crate::{BufferedBody, EmptyBody, Error, Record, RecordType, TruncatedType};

    use chrono::prelude::*;

    #[test]
    fn default() {
        let before = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let record = Record::<BufferedBody>::default();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let after = Utc::now();
        assert_eq!(record.content_length(), 0);
        assert_eq!(record.warc_version(), "1.0");
        assert_eq!(record.warc_type(), &RecordType::Resource);
        assert!(record.date() > &before);
        assert!(record.date() < &after);
    }

    #[test]
    fn impl_eq() {
        let record1 = Record::<BufferedBody>::default();
        let record2 = record1.clone();
        assert_eq!(record1, record2);
    }

    #[test]
    fn body() {
        let mut record = Record::<BufferedBody>::default();
        assert_eq!(record.content_length(), 0);
        assert_eq!(record.body(), &[]);
        record.replace_body(b"hello!!".to_vec());
        assert_eq!(record.content_length(), 7);
        assert_eq!(record.body(), b"hello!!");
        record.body_mut().copy_from_slice(b"goodbye");
        assert_eq!(record.content_length(), 7);
        assert_eq!(record.body(), b"goodbye");
    }

    #[test]
    fn add_header() {
        let mut record = Record::<BufferedBody>::default();
        assert!(record.header(WarcHeader::TargetURI).is_none());
        assert!(record
            .set_header(WarcHeader::TargetURI, "https://www.rust-lang.org")
            .unwrap()
            .is_none());
        assert_eq!(
            record.header(WarcHeader::TargetURI).unwrap(),
            "https://www.rust-lang.org"
        );
        assert_eq!(
            record
                .set_header(WarcHeader::TargetURI, "https://docs.rs")
                .unwrap()
                .unwrap(),
            "https://www.rust-lang.org"
        );
        assert_eq!(
            record.header(WarcHeader::TargetURI).unwrap(),
            "https://docs.rs"
        );
    }

    /// The truncation reason is a header like any other, so it is readable through the
    /// untyped accessor as well as the typed one.
    #[test]
    fn get_header_truncated() {
        let mut record = Record::<BufferedBody>::default();
        assert!(record.header(WarcHeader::Truncated).is_none());

        record.set_truncated_type(TruncatedType::Length);
        assert_eq!(record.header(WarcHeader::Truncated).unwrap(), "length");

        record
            .set_header(WarcHeader::Truncated, "disconnect")
            .unwrap();
        assert_eq!(record.header(WarcHeader::Truncated).unwrap(), "disconnect");

        record.clear_truncated_type();
        assert!(record.header(WarcHeader::Truncated).is_none());
    }

    /// Values that would inject header lines, or end the header block early, are rejected.
    #[test]
    #[ignore = "known bug (RECORD-009: header injection)"]
    fn set_header_rejects_values_with_line_breaks() {
        let mut record = Record::<BufferedBody>::default();

        for value in ["a\r\nwarc-type: evil", "a\rb", "a\nb"] {
            assert!(
                matches!(
                    record.set_header(WarcHeader::TargetURI, value),
                    Err(Error::MalformedHeader(WarcHeader::TargetURI, _))
                ),
                "{:?}",
                value
            );
        }

        // Headers backed by typed record fields go through the same validation.
        assert!(matches!(
            record.set_header(WarcHeader::RecordID, "<urn:a>\r\nevil: x"),
            Err(Error::MalformedHeader(WarcHeader::RecordID, _))
        ));
    }

    /// Unknown header names outside the parser's token grammar are rejected.
    #[test]
    #[ignore = "known bug (RECORD-009: header injection)"]
    fn set_header_rejects_invalid_unknown_names() {
        let mut record = Record::<BufferedBody>::default();

        for name in ["", "evil name", "evil:name", "evil\r\nname"] {
            let header = WarcHeader::Unknown(name.to_string());
            assert!(
                matches!(
                    record.set_header(header, "value"),
                    Err(Error::MalformedHeader(WarcHeader::Unknown(_), _))
                ),
                "{:?}",
                name
            );
        }

        assert!(record
            .set_header(WarcHeader::Unknown("x-custom".to_string()), "value")
            .is_ok());
    }

    /// DEL is a control character, so it cannot appear in an extension field-name token.
    #[test]
    #[ignore = "known bug (PARSE-004: DEL accepted in field names)"]
    fn set_header_rejects_del_in_unknown_name() {
        let mut record = Record::<BufferedBody>::default();
        let header = WarcHeader::Unknown("evil\u{7f}name".to_string());

        assert!(matches!(
            record.set_header(header, "value"),
            Err(Error::MalformedHeader(WarcHeader::Unknown(_), _))
        ));
    }

    /// An `Unknown` spelling of a well-known name is folded into its variant, so it cannot
    /// bypass the interception that keeps derived fields out of the stored header map.
    #[test]
    #[ignore = "known bug (RECORD-008: unknown spellings bypass typed handling)"]
    fn set_header_normalizes_unknown_spellings() {
        let mut record = Record::<BufferedBody>::default();

        record
            .set_header(
                WarcHeader::Unknown("WARC-Date".to_string()),
                "2020-07-08T02:52:55Z",
            )
            .unwrap();
        assert_eq!(
            record.header(WarcHeader::Date).unwrap(),
            "2020-07-08T02:52:55Z"
        );

        record
            .set_header(WarcHeader::Unknown("warc-type".to_string()), "revisit")
            .unwrap();
        assert_eq!(record.warc_type(), &RecordType::Revisit);

        // Lookups normalize the same way, and genuinely unknown names are lower-cased.
        assert_eq!(
            record
                .header(WarcHeader::Unknown("content-length".to_string()))
                .unwrap(),
            "0"
        );
        record
            .set_header(WarcHeader::Unknown("X-Custom".to_string()), "value")
            .unwrap();
        assert_eq!(
            record
                .header(WarcHeader::Unknown("x-custom".to_string()))
                .unwrap(),
            "value"
        );
    }

    /// The record serializes a single `warc-date` line, so its own reader accepts it again;
    /// the unnormalized spelling used to produce a duplicate line the reader rejected.
    #[test]
    #[ignore = "known bug (RECORD-008: unknown spellings bypass typed handling)"]
    fn unknown_spelling_of_known_header_round_trips() {
        let mut record = Record::<BufferedBody>::default();
        record
            .set_header(
                WarcHeader::Unknown("WARC-Date".to_string()),
                "2020-07-08T02:52:55Z",
            )
            .unwrap();

        let mut writer = crate::WarcWriter::new(std::io::BufWriter::new(Vec::new()));
        writer.write(&record).unwrap();
        let bytes = writer.into_inner().unwrap();

        let block = String::from_utf8(bytes).unwrap();
        assert_eq!(
            block.to_lowercase().matches("warc-date:").count(),
            1,
            "{}",
            block
        );

        let reader = crate::WarcReader::new(std::io::Cursor::new(block.into_bytes()));
        let records = reader
            .iter_records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].header(WarcHeader::Date).unwrap(),
            "2020-07-08T02:52:55Z"
        );
    }

    /// `Display` for an empty-bodied record renders the same header block a buffered record
    /// does, not a debug view of the stored extra headers.
    #[test]
    fn display_empty_record_renders_full_header_block() {
        let mut record = Record::<EmptyBody>::new();
        record
            .set_header(WarcHeader::TargetURI, "https://example.com/")
            .unwrap();

        let rendered = record.to_string();

        assert!(rendered.starts_with("Record(WARC/1.0"), "{}", rendered);
        for expected in [
            "warc-type: resource",
            &format!("warc-record-id: {}", record.warc_id()),
            "warc-date: ",
            "warc-target-uri: https://example.com/",
            "content-length: 0",
        ] {
            assert!(
                rendered.contains(expected),
                "{:?} in {}",
                expected,
                rendered
            );
        }
        assert!(rendered.ends_with(", Empty)"), "{}", rendered);
    }

    /// `Content-Length` values follow the `1*DIGIT` grammar at the record entry points too:
    /// linear whitespace around the digits is tolerated, a sign is not.
    #[test]
    fn set_header_content_length_grammar() {
        let mut record = Record::<BufferedBody>::default();

        assert!(record.set_header(WarcHeader::ContentLength, "0 ").is_ok());
        assert!(record
            .set_header(WarcHeader::ContentLength, "\t0\t")
            .is_ok());

        // A sign is rejected even when the value would match the body size.
        assert!(matches!(
            record.set_header(WarcHeader::ContentLength, "+0"),
            Err(Error::MalformedHeader(WarcHeader::ContentLength, _))
        ));
    }

    /// Setting the derived content length returns its canonical previous value, not the
    /// caller's alternate but equivalent spelling.
    #[test]
    #[ignore = "known bug (RECORD-006: set_header returns the new content length)"]
    fn set_header_content_length_returns_canonical_previous_value() {
        let mut record = Record::<EmptyBody>::default();

        let previous = record
            .set_header(WarcHeader::ContentLength, "\t0\t")
            .unwrap();

        assert_eq!(previous.as_deref(), Some("0"));
        assert_eq!(
            record.header(WarcHeader::ContentLength).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn set_header_override_content_length() {
        let mut record = Record::<BufferedBody>::default();
        assert_eq!(record.header(WarcHeader::ContentLength).unwrap(), "0");
        assert!(record
            .set_header(WarcHeader::ContentLength, "really short")
            .is_err());
        assert!(record.set_header(WarcHeader::ContentLength, "50").is_err());
        assert_eq!(
            record
                .set_header(WarcHeader::ContentLength, "0")
                .unwrap()
                .unwrap(),
            "0"
        );
    }

    #[test]
    fn set_header_override_warc_date() {
        let mut record = Record::<BufferedBody>::default();
        let old_date = record.date().to_rfc3339_opts(SecondsFormat::Secs, true);
        assert_eq!(record.header(WarcHeader::Date).unwrap(), old_date);
        assert!(record.set_header(WarcHeader::Date, "yesterday").is_err());
        assert_eq!(
            record
                .set_header(WarcHeader::Date, "2020-07-21T22:00:00Z")
                .unwrap()
                .unwrap(),
            old_date
        );
        assert_eq!(
            record.header(WarcHeader::Date).unwrap(),
            "2020-07-21T22:00:00Z"
        );
    }

    #[test]
    fn set_header_override_warc_record_id() {
        let mut record = Record::<BufferedBody>::default();
        let old_id = record.warc_id().to_string();
        assert_eq!(
            record.header(WarcHeader::RecordID).unwrap(),
            old_id.as_str()
        );
        assert_eq!(
            record
                .set_header(WarcHeader::RecordID, "urn:http:www.rust-lang.org")
                .unwrap()
                .unwrap(),
            old_id.as_str()
        );
        assert_eq!(
            record.header(WarcHeader::RecordID).unwrap(),
            "urn:http:www.rust-lang.org"
        );
    }

    #[test]
    fn set_header_override_warc_type() {
        let mut record = Record::<BufferedBody>::default();
        assert_eq!(record.header(WarcHeader::WarcType).unwrap(), "resource");
        assert_eq!(
            record
                .set_header(WarcHeader::WarcType, "revisit")
                .unwrap()
                .unwrap(),
            "resource"
        );
        assert_eq!(record.header(WarcHeader::WarcType).unwrap(), "revisit");
    }
}

#[cfg(test)]
mod raw_tests {
    use crate::header::WarcHeader;
    use crate::{EmptyBody, Error, RawRecordHeader, Record, RecordType, TruncatedType};

    use std::collections::HashMap;
    use std::convert::TryFrom;

    #[test]
    fn create() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: HashMap::new(),
        };

        assert_eq!(headers.as_ref().len(), 0);
    }

    #[test]
    fn create_with_headers() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![(
                WarcHeader::WarcType,
                RecordType::WarcInfo.to_string().into_bytes(),
            )]
            .into_iter()
            .collect(),
        };

        assert_eq!(headers.as_ref().len(), 1);
    }

    #[test]
    fn verify_ok() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_ok());
    }

    #[test]
    fn verify_missing_type() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    #[test]
    fn verify_missing_content_length() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    #[test]
    fn verify_missing_record_id() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    #[test]
    fn verify_missing_date() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
            ]
            .into_iter()
            .collect(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    /// A block that converts cleanly, with one field replaced by the given value.
    fn headers_with(header: WarcHeader, value: Vec<u8>) -> RawRecordHeader {
        let mut headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };
        headers.as_mut().insert(header, value);
        headers
    }

    #[test]
    fn verify_malformed_content_length_blames_content_length() {
        for bad_value in [&b"not-a-number"[..], &[0xff, 0xfe][..]] {
            let headers = headers_with(WarcHeader::ContentLength, bad_value.to_vec());
            match Record::<EmptyBody>::try_from(headers) {
                Err(Error::MalformedHeader(WarcHeader::ContentLength, _)) => {}
                other => panic!("expected malformed content-length error, got {:?}", other),
            }
        }
    }

    #[test]
    fn verify_malformed_record_id_blames_record_id() {
        let headers = headers_with(WarcHeader::RecordID, vec![0xff, 0xfe]);
        match Record::<EmptyBody>::try_from(headers) {
            Err(Error::MalformedHeader(WarcHeader::RecordID, _)) => {}
            other => panic!("expected malformed record-id error, got {:?}", other),
        }
    }

    #[test]
    fn verify_truncated_type_is_extracted() {
        let headers = headers_with(WarcHeader::Truncated, b"length".to_vec());
        let record = Record::<EmptyBody>::try_from(headers).unwrap();
        assert_eq!(record.truncated_type(), &Some(TruncatedType::Length));
        assert_eq!(record.header(WarcHeader::Truncated).unwrap(), "length");
    }

    #[test]
    fn verify_non_utf8_header_value_is_rejected() {
        let headers = headers_with(WarcHeader::TargetURI, vec![0xff, 0xfe]);
        match Record::<EmptyBody>::try_from(headers) {
            Err(Error::MalformedHeader(WarcHeader::TargetURI, _)) => {}
            other => panic!("expected malformed target-uri error, got {:?}", other),
        }
    }

    /// A hand-built raw block may spell a well-known field as `Unknown`; conversion folds it
    /// into the typed field.
    #[test]
    #[ignore = "known bug (RECORD-008: unknown spellings bypass typed handling)"]
    fn verify_unknown_spelling_is_normalized() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (
                    WarcHeader::Unknown("Warc-Type".to_string()),
                    b"dunno".to_vec(),
                ),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:unknown-spelling:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };

        let record = Record::<EmptyBody>::try_from(headers).unwrap();
        assert_eq!(
            record.warc_type(),
            &RecordType::Unknown("dunno".to_string())
        );
    }

    /// An `Unknown` spelling that collides with a field already present is a duplicate, and
    /// a duplicate of a field the record can hold only once is rejected.
    #[test]
    #[ignore = "known bug (RECORD-008: unknown spellings bypass typed handling)"]
    fn verify_unknown_spelling_collision_is_rejected() {
        let headers = headers_with(
            WarcHeader::Unknown("WARC-Date".to_string()),
            b"2021-01-01T00:00:00Z".to_vec(),
        );

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    /// The formatted header block is terminated by CRLF throughout, as the grammar requires.
    #[test]
    #[ignore = "known bug (PARSE-002: WARC field grammar divergence)"]
    fn display_uses_crlf_line_endings() {
        let headers = RawRecordHeader {
            version: "1.1".to_owned(),
            headers: vec![(WarcHeader::WarcType, b"resource".to_vec())]
                .into_iter()
                .collect(),
        };

        assert_eq!(
            headers.to_string(),
            "WARC/1.1\r\nwarc-type: resource\r\n\r\n"
        );
    }

    #[test]
    fn verify_display() {
        let header_entries = vec![
            (WarcHeader::WarcType, b"dunno".to_vec()),
            (WarcHeader::Date, b"2024-01-01T00:00:00Z".to_vec()),
        ];

        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: header_entries.into_iter().collect(),
        };

        let output = headers.to_string();

        let expected_lines = [
            "WARC/1.0",
            "warc-type: dunno",
            "warc-date: 2024-01-01T00:00:00Z",
            "",
        ];
        let actual_lines: Vec<_> = output.lines().collect();

        let mut expected_headers: Vec<_> = expected_lines[1..expected_lines.len() - 1].to_vec();
        expected_headers.sort();

        let mut actual_headers: Vec<_> = actual_lines[1..actual_lines.len() - 1].to_vec();
        actual_headers.sort();

        // verify parts
        assert_eq!(actual_lines[0], expected_lines[0]); // WARC version
        assert_eq!(actual_headers, expected_headers); // headers (sorted)
        assert_eq!(actual_lines.last(), expected_lines.last()); // empty line
    }
}

#[cfg(test)]
mod builder_tests {
    use crate::header::WarcHeader;
    use crate::{
        BufferedBody, EmptyBody, Error, RawRecordHeader, Record, RecordBuilder, RecordType,
        TruncatedType,
    };

    use std::convert::TryFrom;

    #[test]
    fn default() {
        let (headers, body) = RecordBuilder::default().build_raw();
        assert_eq!(headers.version, "1.0".to_string());
        assert_eq!(
            headers.as_ref().get(&WarcHeader::ContentLength).unwrap(),
            &b"0".to_vec()
        );
        assert!(body.is_empty());
        assert_eq!(
            RecordBuilder::default().build().unwrap().content_length(),
            0
        );
    }

    #[test]
    fn default_with_body() {
        let (headers, body) = RecordBuilder::default()
            .body(b"abcdef".to_vec())
            .build_raw();
        assert_eq!(headers.version, "1.0".to_string());
        assert_eq!(
            headers.as_ref().get(&WarcHeader::ContentLength).unwrap(),
            &b"6".to_vec()
        );
        assert_eq!(body.as_slice(), b"abcdef");
        assert_eq!(
            RecordBuilder::default()
                .body(b"abcdef".to_vec())
                .build()
                .unwrap()
                .content_length(),
            6
        );
    }

    #[test]
    fn impl_eq_raw() {
        let builder = RecordBuilder::default();
        let raw1 = builder.clone().build_raw();

        let raw2 = builder.build_raw();
        assert_eq!(raw1, raw2);
    }

    #[test]
    fn impl_eq_record() {
        let builder = RecordBuilder::default();
        let record1 = builder.clone().build().unwrap();

        let record2 = builder.build().unwrap();
        assert_eq!(record1, record2);
    }

    #[test]
    fn create_with_headers() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![(
                WarcHeader::WarcType,
                RecordType::WarcInfo.to_string().into_bytes(),
            )]
            .into_iter()
            .collect(),
        };

        assert_eq!(headers.as_ref().len(), 1);
    }

    #[test]
    fn verify_ok() {
        let headers = RawRecordHeader {
            version: "1.0".to_owned(),
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (
                    WarcHeader::RecordID,
                    b"<urn:test:basic-record:record-0>".to_vec(),
                ),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_ok());
    }

    #[test]
    fn verify_content_length() {
        let mut builder = RecordBuilder::default().body(b"12345".to_vec());

        assert_eq!(
            builder
                .clone()
                .build()
                .unwrap()
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::ContentLength)
                .unwrap(),
            &b"5".to_vec()
        );

        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::ContentLength)
                .unwrap(),
            &b"5".to_vec()
        );

        builder = builder.header(WarcHeader::ContentLength, "1");
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::ContentLength)
                .unwrap(),
            &b"1".to_vec()
        );

        assert!(builder.build().is_err());
    }

    /// A rejected header value no longer fails the build once a later call replaces it with
    /// a valid one.
    #[test]
    fn broken_header_is_cured_by_a_later_set() {
        let record = RecordBuilder::default()
            .header(WarcHeader::Date, "not-a-dayTor:a:time")
            .header(WarcHeader::Date, "2020-07-08T02:52:55Z")
            .build()
            .unwrap();

        assert_eq!(
            record.header(WarcHeader::Date).unwrap(),
            "2020-07-08T02:52:55Z"
        );
    }

    /// A `Content-Length` set before the body it describes is retried against the finished
    /// record, so the order of the two calls does not matter.
    #[test]
    fn content_length_before_body_is_cured() {
        let record = RecordBuilder::default()
            .header(WarcHeader::ContentLength, "5")
            .body(b"12345".to_vec())
            .build()
            .unwrap();

        assert_eq!(record.content_length(), 5);
    }

    /// The build error blames a header that is still broken, not one that was broken and
    /// later fixed.
    #[test]
    fn build_error_blames_a_still_broken_header() {
        let builder = RecordBuilder::default()
            .header(WarcHeader::ContentLength, "9")
            .header(WarcHeader::Date, "not-a-dayTor:a:time")
            .header(WarcHeader::Date, "2020-07-08T02:52:55Z");

        match builder.build() {
            Err(Error::MalformedHeader(WarcHeader::ContentLength, _)) => {}
            other => panic!("expected an error blaming content-length, got {:?}", other),
        }
    }

    #[test]
    fn verify_build_record_type() {
        let builder1 = RecordBuilder::default().header(WarcHeader::WarcType, "request");
        let builder2 = builder1.clone().warc_type(RecordType::Request);

        let record1 = builder1.build().unwrap();
        let record2 = builder2.build().unwrap();

        assert_eq!(record1, record2);
        assert_eq!(
            record1
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::WarcType),
            Some(&b"request".to_vec())
        );
    }

    #[test]
    fn verify_build_date() {
        const DATE_STRING_0: &str = "2020-07-08T02:52:55Z";
        const DATE_STRING_1: &[u8] = b"2020-07-18T02:12:45Z";

        let mut builder = RecordBuilder::default();
        builder = builder.date(Record::<BufferedBody>::parse_record_date(DATE_STRING_0).unwrap());

        let record = builder.clone().build().unwrap();
        assert_eq!(
            record
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::Date)
                .unwrap(),
            &DATE_STRING_0.as_bytes()
        );
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::Date)
                .unwrap(),
            &DATE_STRING_0.as_bytes()
        );

        builder = builder.header(WarcHeader::Date, DATE_STRING_1.to_vec());
        let record = builder.clone().build().unwrap();
        assert_eq!(
            record
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::Date)
                .unwrap(),
            &DATE_STRING_1.to_vec()
        );
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::Date)
                .unwrap(),
            &DATE_STRING_1.to_vec()
        );

        let builder = builder.header(WarcHeader::Date, b"not-a-dayTor:a:time".to_vec());
        assert!(builder.build().is_err());
    }

    #[test]
    fn verify_build_record_id() {
        const RECORD_ID_0: &[u8] = b"<urn:test:verify-build-id:record-0>";
        const RECORD_ID_1: &[u8] = b"<urn:test:verify-build-id:record-1>";

        let mut builder = RecordBuilder::default();
        builder = builder.warc_id(std::str::from_utf8(RECORD_ID_0).unwrap());

        let record = builder.clone().build().unwrap();
        assert_eq!(
            record
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::RecordID)
                .unwrap(),
            &RECORD_ID_0.to_vec()
        );
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::RecordID)
                .unwrap(),
            &RECORD_ID_0.to_vec()
        );

        let builder = builder.header(WarcHeader::RecordID, RECORD_ID_1.to_vec());
        let record = builder.clone().build().unwrap();
        assert_eq!(
            record
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::RecordID)
                .unwrap(),
            &RECORD_ID_1.to_vec()
        );
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::RecordID)
                .unwrap(),
            &RECORD_ID_1.to_vec()
        );
    }

    #[test]
    fn verify_build_truncated_type() {
        const TRUNCATED_TYPE_0: &[u8] = b"length";
        const TRUNCATED_TYPE_1: &[u8] = b"disconnect";

        let mut builder = RecordBuilder::default();
        builder = builder.truncated_type(TruncatedType::Length);

        let record = builder.clone().build().unwrap();
        assert_eq!(
            record
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::Truncated)
                .unwrap(),
            &TRUNCATED_TYPE_0.to_vec()
        );
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::Truncated)
                .unwrap(),
            &TRUNCATED_TYPE_0.to_vec()
        );

        builder = builder.header(WarcHeader::Truncated, "disconnect");
        let record = builder.clone().build().unwrap();
        assert_eq!(
            record
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::Truncated)
                .unwrap(),
            &TRUNCATED_TYPE_1.to_vec()
        );
        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::Truncated)
                .unwrap(),
            &TRUNCATED_TYPE_1.to_vec()
        );

        builder = builder.header(WarcHeader::Truncated, "foreign-intervention");
        assert_eq!(
            builder
                .clone()
                .build()
                .unwrap()
                .into_raw_parts()
                .0
                .as_ref()
                .get(&WarcHeader::Truncated)
                .unwrap()
                .as_slice(),
            &b"foreign-intervention"[..]
        );

        assert_eq!(
            builder
                .clone()
                .build_raw()
                .0
                .as_ref()
                .get(&WarcHeader::Truncated)
                .unwrap()
                .as_slice(),
            &b"foreign-intervention"[..]
        );
    }
}
