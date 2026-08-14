use chrono::Utc;
use indexmap::IndexMap;
use std::borrow::Cow;
use std::fmt;
use std::io::Read;

use uuid::Uuid;

use crate::Error as WarcError;
use crate::header::WarcHeader;
use crate::record_type::RecordType;
use crate::truncated_type::TruncatedType;
use crate::version::WarcVersion;
use crate::warc_date::WarcDate;

use streaming_trait::BodyKind;
pub use streaming_trait::{BufferedBody, EmptyBody, StreamingBody};

mod streaming_trait {
    use std::io::Read;

    /// An associated type indicating how the body of a record is represented.
    pub trait BodyKind {
        fn content_length(&self) -> u64;
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    /// An associated type indicating the body is buffered within the record.
    pub struct BufferedBody(pub Vec<u8>);
    impl BodyKind for BufferedBody {
        fn content_length(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// An associated type indicating the body is streamed from a reader.
    pub struct StreamingBody<'t, T: Read> {
        stream: &'t mut T,
        /// The declared `Content-Length`, unaffected by reads.
        declared_content_len: u64,
        /// The unread portion of the body, shared with the iterator that handed it out.
        remaining_len: &'t mut u64,
        /// Set once the record's `\r\n\r\n` terminator has been consumed and verified, so that
        /// the owning `StreamingIter` does not read it a second time. `None` for bodies built
        /// over external streams, which carry no terminator contract.
        terminator_consumed: Option<&'t mut bool>,
    }
    impl<'t, T: Read> StreamingBody<'t, T> {
        pub(crate) const fn new(stream: &'t mut T, remaining_len: &'t mut u64) -> Self {
            Self {
                declared_content_len: *remaining_len,
                stream,
                remaining_len,
                terminator_consumed: None,
            }
        }

        /// A body whose record terminator is managed jointly with the owning iterator through
        /// the given flag.
        pub(crate) const fn with_terminator_flag(
            stream: &'t mut T,
            remaining_len: &'t mut u64,
            terminator_consumed: &'t mut bool,
        ) -> Self {
            Self {
                declared_content_len: *remaining_len,
                stream,
                remaining_len,
                terminator_consumed: Some(terminator_consumed),
            }
        }

        /// The unread portion of the body, shrinking as the stream is consumed.
        pub(crate) const fn remaining_len(&self) -> u64 {
            *self.remaining_len
        }

        /// Read and verify the record's `\r\n\r\n` terminator, recording the consumption for
        /// the owning iterator. Bodies over external streams are left untouched.
        pub(crate) fn consume_terminator(&mut self) -> Result<(), crate::Error> {
            let Some(flag) = self.terminator_consumed.as_deref_mut() else {
                return Ok(());
            };

            let mut crlfs = [0; 4];
            match self.stream.read_exact(&mut crlfs) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(crate::Error::UnexpectedEOB);
                }
                Err(io) => return Err(crate::Error::ReadData(io)),
            }

            if &crlfs != b"\r\n\r\n" {
                return Err(crate::Error::MalformedRecordTerminator);
            }

            *flag = true;
            Ok(())
        }
    }
    impl<T: Read> BodyKind for StreamingBody<'_, T> {
        fn content_length(&self) -> u64 {
            self.declared_content_len
        }
    }

    impl<T: Read> Read for StreamingBody<'_, T> {
        fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
            // `try_from` fails only when the remaining length exceeds the address space, in
            // which case the read is capped at `data.len()` anyway.
            let max_read = usize::try_from(*self.remaining_len)
                .map_or(data.len(), |remaining| data.len().min(remaining));
            self.stream.read(&mut data[..max_read]).inspect(|&n| {
                *self.remaining_len -= n as u64;
            })
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    /// An associated type indicated the record has a zero-length body.
    pub struct EmptyBody;
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
/// Each named field is held at most once in `headers`: parsing a record that repeats a field
/// fails with `Error::DuplicateHeader`. The one exception is `WARC-Concurrent-To`, the only
/// field the specification allows to repeat: all of its values are held in `concurrent_to`.
///
/// Use the `Display` trait to generate the formatted representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRecordHeader {
    /// The WARC standard version this record reports conformance to.
    pub version: WarcVersion,
    /// All headers other than `WARC-Concurrent-To` that are part of this record, in insertion
    /// order.
    pub headers: IndexMap<WarcHeader, Vec<u8>>,
    /// The values of the repeatable `WARC-Concurrent-To` header, in order of appearance.
    pub concurrent_to: Vec<Vec<u8>>,
}

impl AsRef<IndexMap<WarcHeader, Vec<u8>>> for RawRecordHeader {
    fn as_ref(&self) -> &IndexMap<WarcHeader, Vec<u8>> {
        &self.headers
    }
}

impl AsMut<IndexMap<WarcHeader, Vec<u8>>> for RawRecordHeader {
    fn as_mut(&mut self) -> &mut IndexMap<WarcHeader, Vec<u8>> {
        &mut self.headers
    }
}

/// Fold `Unknown` spellings of well-known field names in a hand-built raw header block into
/// their variants, so that the typed extraction in `try_from` sees them; a spelling that
/// collides with a field already present is exactly the duplicate the reader would reject.
///
/// Header blocks built by the parser never contain such spellings, so the rebuild only runs
/// when an `Unknown` key is present.
fn normalize_raw_headers(headers: &mut RawRecordHeader) -> Result<(), WarcError> {
    let needs_normalizing = headers
        .as_ref()
        .keys()
        .any(|header| matches!(header, WarcHeader::Unknown(_)));

    if needs_normalizing {
        let mut normalized = IndexMap::with_capacity(headers.as_ref().len());
        for (header, value) in std::mem::take(headers.as_mut()) {
            let header = header.normalized();
            if normalized.insert(header.clone(), value).is_some() {
                return Err(WarcError::MalformedHeader(
                    header,
                    "duplicate header".to_string(),
                ));
            }
        }
        *headers.as_mut() = normalized;
    }

    Ok(())
}

/// Reject a header whose name or value would serialize to a record no reader could parse
/// back: an unknown name outside the parser's token grammar, or a value containing the bare
/// `\r` or `\n` that would inject header lines or terminate the block early.
///
/// # Errors
///
/// Returns `Error::MalformedHeader` naming the header at fault.
pub fn validate_header(header: &WarcHeader, value: &[u8]) -> Result<(), WarcError> {
    if let WarcHeader::Unknown(name) = header {
        let valid_token = !name.is_empty() && name.bytes().all(crate::is_header_token_char);
        if !valid_token {
            return Err(WarcError::MalformedHeader(
                header.clone(),
                "name is not a valid header token".to_string(),
            ));
        }
    }

    if value.contains(&b'\r') || value.contains(&b'\n') {
        return Err(WarcError::MalformedHeader(
            header.clone(),
            "value contains a line break".to_string(),
        ));
    }

    Ok(())
}

/// Remove `header` from the raw headers, decoding its value as UTF-8.
fn take_utf8_header(
    headers: &mut RawRecordHeader,
    header: &WarcHeader,
) -> Result<Option<String>, WarcError> {
    headers
        .as_mut()
        .shift_remove(header)
        .map(|value| {
            String::from_utf8(value).map_err(|_| {
                WarcError::MalformedHeader(header.clone(), "not a UTF-8 string".to_string())
            })
        })
        .transpose()
}

/// Like `take_utf8_header`, but fail if `header` is missing.
fn take_required_utf8_header(
    headers: &mut RawRecordHeader,
    header: &WarcHeader,
) -> Result<String, WarcError> {
    take_utf8_header(headers, header)?.ok_or_else(|| WarcError::MissingHeader(header.clone()))
}

impl std::convert::TryFrom<RawRecordHeader> for Record<EmptyBody> {
    type Error = WarcError;
    fn try_from(mut headers: RawRecordHeader) -> Result<Self, WarcError> {
        normalize_raw_headers(&mut headers)?;
        take_required_utf8_header(&mut headers, &WarcHeader::ContentLength)
            .and_then(|len| Self::parse_content_length(&len))?;

        Self::from_validated_raw(headers)
    }
}

impl Record<EmptyBody> {
    /// Build a record from a raw header block whose `Content-Length` has already been parsed
    /// and validated — by the stream parser for records read from input, or by `try_from`
    /// above — so that the parsed value flows through instead of being parsed a second time
    /// from the stored bytes.
    pub(crate) fn from_validated_raw(mut headers: RawRecordHeader) -> Result<Self, WarcError> {
        headers.as_mut().shift_remove(&WarcHeader::ContentLength);

        let record_type: RecordType =
            take_required_utf8_header(&mut headers, &WarcHeader::WarcType)?.into();

        let record_id = take_required_utf8_header(&mut headers, &WarcHeader::RecordID)?;

        let record_date = take_required_utf8_header(&mut headers, &WarcHeader::Date)
            .and_then(|date| Self::parse_record_date(headers.version, &date))?;

        let truncated_type = take_utf8_header(&mut headers, &WarcHeader::Truncated)?
            .map(|value| TruncatedType::from(&value));

        // Tolerate raw headers constructed by hand with `WARC-Concurrent-To` in the map: all
        // values of the repeatable field belong in `concurrent_to`.
        if let Some(value) = headers.as_mut().shift_remove(&WarcHeader::ConcurrentTo) {
            headers.concurrent_to.insert(0, value);
        }

        // `Record` guarantees UTF-8 header values; reject the record otherwise.
        for (header, value) in headers.as_ref() {
            if std::str::from_utf8(value).is_err() {
                return Err(WarcError::MalformedHeader(
                    header.clone(),
                    "not a UTF-8 string".to_string(),
                ));
            }
        }
        for value in &headers.concurrent_to {
            if std::str::from_utf8(value).is_err() {
                return Err(WarcError::MalformedHeader(
                    WarcHeader::ConcurrentTo,
                    "not a UTF-8 string".to_string(),
                ));
            }
        }

        Ok(Self {
            headers,
            record_date,
            record_id,
            record_type,
            truncated_type,
            body: EmptyBody,
        })
    }
}

impl std::fmt::Display for RawRecordHeader {
    // The WARC grammar terminates the version line, every header line, and the block itself
    // with CRLF, so this cannot use `writeln!` (which emits a bare LF).
    fn fmt(&self, w: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(w, "WARC/{}\r\n", self.version)?;
        for (key, value) in self.as_ref() {
            write!(w, "{}: {}\r\n", key, String::from_utf8_lossy(value))?;
        }
        for value in &self.concurrent_to {
            write!(
                w,
                "{}: {}\r\n",
                WarcHeader::ConcurrentTo,
                String::from_utf8_lossy(value)
            )?;
        }
        write!(w, "\r\n")?;

        Ok(())
    }
}

/// A builder for WARC records from data.
#[derive(Clone, Default)]
pub struct RecordBuilder {
    value: Record<BufferedBody>,
    broken_headers: IndexMap<WarcHeader, Vec<u8>>,
}

/// A single WARC record.
///
/// A record can be constructed by a `RecordBuilder`, or by reading from a stream.
///
/// The associated type `T` indicates the representation of this record's body.
///
/// A record is guaranteed to be valid according to the specification it conforms to, except:
/// * The validity of the WARC-Record-ID header is not checked
/// * WARC 1.1 date information not in the UTC timezone will be silently converted to UTC
///
/// All header values in a record are guaranteed to be valid UTF-8: converting a
/// `RawRecordHeader` containing a non-UTF-8 header value fails with
/// `Error::MalformedHeader` naming the offending header. Use the raw record APIs to work
/// with records whose header values are arbitrary bytes.
///
/// Use the `Display` trait to generate the formatted representation.
#[derive(Clone, Debug, PartialEq, Eq)]
// The `record_` prefix distinguishes the parsed fields from the raw `headers`, and `type` alone
// is a keyword.
#[allow(clippy::struct_field_names)]
pub struct Record<T: BodyKind> {
    // NB: invariant: does not contain the headers stored in the struct
    headers: RawRecordHeader,
    record_date: WarcDate,
    record_id: String,
    record_type: RecordType,
    truncated_type: Option<TruncatedType>,
    body: T,
}

impl Record<EmptyBody> {
    /// Create a new empty record with default values.
    ///
    /// Using a `RecordBuilder` is more efficient when creating records from known data.
    ///
    /// The record returned contains an empty body, and the following fields:
    /// * WARC-Record-ID: generated by `generate_record_id()`
    /// * WARC-Date: the current moment in time
    /// * WARC-Type: resource
    /// * WARC-Content-Length: 0
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Record<BufferedBody> {
    /// Create a new record with a known body.
    ///
    /// Using a `RecordBuilder` is more efficient when creating records from known data.
    ///
    /// The record returned contains the passed body buffer, and the following fields:
    /// * WARC-Record-ID: generated by `generate_record_id()`
    /// * WARC-Date: the current moment in time
    /// * WARC-Type: resource
    /// * WARC-Content-Length: `body.len()`
    pub fn with_body<B: Into<Vec<u8>>>(body: B) -> Self {
        Self {
            body: BufferedBody(body.into()),
            ..Self::default()
        }
    }
}

impl Record<EmptyBody> {
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
    #[must_use]
    pub fn generate_record_id() -> String {
        format!("<{}>", Uuid::new_v4().urn())
    }

    fn parse_content_length(len: &str) -> Result<u64, WarcError> {
        crate::parse_content_length(len).ok_or_else(|| {
            WarcError::MalformedHeader(
                WarcHeader::ContentLength,
                "not a digit sequence between 0 and 2^64-1".to_string(),
            )
        })
    }

    fn parse_record_date(version: WarcVersion, date: &str) -> Result<WarcDate, WarcError> {
        WarcDate::parse(date, version)
    }
}

impl<T: BodyKind> Record<T> {
    /// Return the WARC version of this record.
    pub const fn warc_version(&self) -> WarcVersion {
        self.headers.version
    }

    /// Set the WARC version of this record.
    pub const fn set_warc_version(&mut self, version: WarcVersion) {
        self.headers.version = version;
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
    pub const fn warc_type(&self) -> &RecordType {
        &self.record_type
    }

    /// Set the WARC-Type header for this record.
    pub fn set_warc_type(&mut self, type_: RecordType) {
        self.record_type = type_;
    }

    /// Return this record's WARC date, including its declared precision.
    ///
    /// Use [`header`](Self::header) to obtain the value as rendered for this record's WARC
    /// version.
    pub const fn date(&self) -> WarcDate {
        self.record_date
    }

    /// Set this record's WARC date.
    ///
    /// A [`chrono::DateTime<Utc>`] is accepted directly and converted to a [`WarcDate`].
    pub fn set_date<D: Into<WarcDate>>(&mut self, date: D) {
        self.record_date = date.into();
    }

    /// Return the WARC-Truncated header for this record.
    pub const fn truncated_type(&self) -> &Option<TruncatedType> {
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
    ///
    /// # Panics
    ///
    /// Panics if the stored header value is not UTF-8, which construction of the record
    /// prevents.
    // Taking `WarcHeader` by value keeps call sites like `record.header(WarcHeader::Date)`
    // free of borrows; every variant but `Unknown` is a unit.
    #[allow(clippy::needless_pass_by_value)]
    pub fn header(&self, header: WarcHeader) -> Option<Cow<'_, str>> {
        let header = header.normalized();
        match &header {
            WarcHeader::ContentLength => Some(Cow::Owned(self.body.content_length().to_string())),
            WarcHeader::RecordID => Some(Cow::Borrowed(self.warc_id())),
            WarcHeader::WarcType => Some(Cow::Owned(self.record_type.to_string())),
            WarcHeader::Date => Some(Cow::Owned(
                self.date().to_string_for_version(self.warc_version()),
            )),
            WarcHeader::Truncated => self
                .truncated_type
                .as_ref()
                .map(|truncated_type| Cow::Owned(truncated_type.to_string())),
            WarcHeader::ConcurrentTo => self.headers.concurrent_to.first().map(|value| {
                Cow::Borrowed(
                    std::str::from_utf8(value)
                        .expect("invariant violation: record header value is not UTF-8"),
                )
            }),
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
    /// `Content-Length` is derived from the body and cannot be changed here: an equivalent
    /// value is accepted and returns the canonical previous value, while a mismatch is an
    /// error.
    ///
    /// Setting `WARC-Concurrent-To` replaces every value of the repeatable field, returning
    /// the first previous value; to append a value instead, use `add_concurrent_to`.
    ///
    /// # Errors
    ///
    /// If setting a header whose value has a well-formedness test, an error is returned if the
    /// value is not well-formed.
    ///
    /// # Panics
    ///
    /// Panics if the stored header value being replaced is not UTF-8, which construction of
    /// the record prevents.
    pub fn set_header<V>(
        &mut self,
        header: WarcHeader,
        value: V,
    ) -> Result<Option<Cow<'_, str>>, WarcError>
    where
        V: Into<String>,
    {
        let value = value.into();
        let header = header.normalized();
        validate_header(&header, value.as_bytes())?;
        match &header {
            WarcHeader::Date => {
                let version = self.warc_version();
                let new_date = Record::parse_record_date(version, &value)?;
                let old_date = std::mem::replace(&mut self.record_date, new_date);
                Ok(Some(Cow::Owned(old_date.to_string_for_version(version))))
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
                Ok(old_type.map(|old| Cow::Owned(old.to_string())))
            }
            WarcHeader::ConcurrentTo => {
                let old_values =
                    std::mem::replace(&mut self.headers.concurrent_to, vec![value.into_bytes()]);
                Ok(old_values.into_iter().next().map(|old| {
                    Cow::Owned(
                        String::from_utf8(old)
                            .expect("invariant violation: record header value is not UTF-8"),
                    )
                }))
            }
            WarcHeader::ContentLength => {
                let content_length = self.body.content_length();
                if Record::<EmptyBody>::parse_content_length(&value)? == content_length {
                    Ok(Some(Cow::Owned(content_length.to_string())))
                } else {
                    Err(WarcError::MalformedHeader(
                        WarcHeader::ContentLength,
                        "content length != body size".to_string(),
                    ))
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

    /// Return all values of the repeatable `WARC-Concurrent-To` header, in order of appearance.
    ///
    /// # Panics
    ///
    /// Panics if a stored header value is not UTF-8, which construction of the record
    /// prevents.
    pub fn concurrent_to(&self) -> impl Iterator<Item = &str> {
        self.headers.concurrent_to.iter().map(|value| {
            std::str::from_utf8(value)
                .expect("invariant violation: record header value is not UTF-8")
        })
    }

    /// Add a `WARC-Concurrent-To` header to this record, keeping any values already present.
    ///
    /// `WARC-Concurrent-To` is the only header the specification allows to repeat. To replace
    /// the existing values instead, use `set_header`.
    pub fn add_concurrent_to<S: Into<String>>(&mut self, id: S) {
        self.headers.concurrent_to.push(id.into().into_bytes());
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

    /// Replace this record's body representation, keeping all other fields.
    fn with_body_kind<U: BodyKind>(self, body: U) -> Record<U> {
        Record {
            headers: self.headers,
            record_date: self.record_date,
            record_id: self.record_id,
            record_type: self.record_type,
            truncated_type: self.truncated_type,
            body,
        }
    }

    /// Visit every header line of this record as a `(name, value)` pair, in the same
    /// serialization order [`to_raw_header`](Self::to_raw_header) produces, borrowing stored
    /// header values instead of cloning them into a raw block.
    ///
    /// The derived `WARC-Date` and `Content-Length` values are materialized once per call;
    /// every other name and value is borrowed from the record.
    pub(crate) fn visit_header_lines<E, F>(&self, mut visit: F) -> Result<(), E>
    where
        F: FnMut(&WarcHeader, &[u8]) -> Result<(), E>,
    {
        let date = self.record_date.to_string_for_version(self.warc_version());
        let content_length = self.body.content_length().to_string();

        visit(&WarcHeader::WarcType, self.record_type.as_str().as_bytes())?;
        visit(&WarcHeader::RecordID, self.record_id.as_bytes())?;
        visit(&WarcHeader::Date, date.as_bytes())?;
        if let Some(truncated_type) = &self.truncated_type {
            visit(&WarcHeader::Truncated, truncated_type.as_str().as_bytes())?;
        }
        for (header, value) in self.headers.as_ref() {
            visit(header, value)?;
        }
        visit(&WarcHeader::ContentLength, content_length.as_bytes())?;
        for value in &self.headers.concurrent_to {
            visit(&WarcHeader::ConcurrentTo, value)?;
        }

        Ok(())
    }

    /// Build the raw header block for this record without consuming it.
    ///
    /// Headers appear in conventional WARC order: record-level headers first,
    /// `Content-Length` last.
    pub fn to_raw_header(&self) -> RawRecordHeader {
        let stored_headers = self.headers.as_ref();
        let mut headers: IndexMap<WarcHeader, Vec<u8>> =
            IndexMap::with_capacity(stored_headers.len() + 5);
        headers.insert(WarcHeader::WarcType, self.record_type.to_string().into());
        headers.insert(WarcHeader::RecordID, self.record_id.clone().into());
        headers.insert(
            WarcHeader::Date,
            self.record_date
                .to_string_for_version(self.warc_version())
                .into(),
        );
        if let Some(truncated_type) = &self.truncated_type {
            headers.insert(WarcHeader::Truncated, truncated_type.to_string().into());
        }
        headers.extend(
            stored_headers
                .iter()
                .map(|(header, value)| (header.clone(), value.clone())),
        );
        headers.insert(
            WarcHeader::ContentLength,
            self.body.content_length().to_string().into(),
        );

        debug_assert_eq!(
            headers.len(),
            stored_headers.len() + 4 + usize::from(self.truncated_type.is_some()),
            "invariant violation: raw struct contains externally stored fields"
        );

        RawRecordHeader {
            version: self.headers.version,
            headers,
            concurrent_to: self.headers.concurrent_to.clone(),
        }
    }
}

impl Record<EmptyBody> {
    /// Add a known body to this record, transforming it into a buffered body record.
    pub fn add_body<B: Into<Vec<u8>>>(self, body: B) -> Record<BufferedBody> {
        self.with_body_kind(BufferedBody(body.into()))
    }

    /// Add a streaming body to this record, whose expected size may not match the actual stream
    /// length.
    ///
    /// The stream is treated as a bare body source: unlike records produced by
    /// `WarcReader::stream_records`, no `\r\n\r\n` record terminator is expected after it.
    #[must_use]
    pub fn add_fixed_stream<'r, R: Read>(
        self,
        stream: &'r mut R,
        len: &'r mut u64,
    ) -> Record<StreamingBody<'r, R>> {
        self.with_body_kind(StreamingBody::new(stream, len))
    }

    /// Add a streaming body positioned within a WARC stream, coordinating consumption of the
    /// record's `\r\n\r\n` terminator with the owning iterator through the given flag.
    pub(crate) fn add_managed_stream<'r, R: Read>(
        self,
        stream: &'r mut R,
        len: &'r mut u64,
        terminator_consumed: &'r mut bool,
    ) -> Record<StreamingBody<'r, R>> {
        self.with_body_kind(StreamingBody::with_terminator_flag(
            stream,
            len,
            terminator_consumed,
        ))
    }
}

impl Record<BufferedBody> {
    /// Strip the body from this record.
    #[must_use]
    pub fn strip_body(self) -> Record<EmptyBody> {
        self.with_body_kind(EmptyBody)
    }

    /// Return the body of this record.
    #[must_use]
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
    #[must_use]
    pub fn into_raw_parts(self) -> (RawRecordHeader, Vec<u8>) {
        (self.to_raw_header(), self.body.0)
    }
}

impl<T: Read> Record<StreamingBody<'_, T>> {
    /// Returns a record with a buffered body by collecting the streaming body.
    ///
    /// The body must be complete: a stream that ends before `Content-Length` bytes have been
    /// read fails with [`Error::UnexpectedEOB`](crate::Error::UnexpectedEOB) instead of
    /// yielding a silently truncated record. For records produced by
    /// `WarcReader::stream_records`, the record's `\r\n\r\n` terminator is also read and
    /// verified.
    ///
    /// # Errors
    ///
    /// Fails if the underlying stream returns an error, ends before the declared body length,
    /// or (for streamed WARC records) is not followed by a well-formed record terminator. On
    /// failure, the state of the stream is not guaranteed.
    pub fn into_buffered(mut self) -> Result<Record<BufferedBody>, WarcError> {
        // Size the buffer to the body, but cap the speculative allocation at `MB` so a bogus
        // `Content-Length` cannot force a huge up-front allocation.
        let capacity = usize::try_from(self.body.remaining_len())
            .unwrap_or(usize::MAX)
            .min(crate::MB);
        let mut buf = Vec::with_capacity(capacity);
        self.body
            .read_to_end(&mut buf)
            .map_err(WarcError::ReadData)?;

        // `read_to_end` stops early only when the underlying stream is exhausted.
        if self.body.remaining_len() > 0 {
            return Err(WarcError::UnexpectedEOB);
        }

        self.body.consume_terminator()?;

        Ok(self.with_body_kind(BufferedBody(buf)))
    }
}

impl<T: Read> Read for Record<StreamingBody<'_, T>> {
    fn read(&mut self, dst: &mut [u8]) -> Result<usize, std::io::Error> {
        self.body.read(dst)
    }
}

impl<T: BodyKind + Default> Default for Record<T> {
    fn default() -> Self {
        Self {
            headers: RawRecordHeader {
                version: WarcVersion::V1_1,
                headers: IndexMap::new(),
                concurrent_to: Vec::new(),
            },
            record_date: Utc::now().into(),
            record_id: Record::generate_record_id(),
            record_type: RecordType::Resource,
            truncated_type: None,
            body: T::default(),
        }
    }
}

impl fmt::Display for Record<BufferedBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Record({}, {:?})", self.to_raw_header(), self.body.0)
    }
}
impl fmt::Display for Record<EmptyBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Record({}, Empty)", self.to_raw_header())
    }
}

impl RecordBuilder {
    /// Set the body of the record under construction.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.value.replace_body(body);

        self
    }

    /// Set the WARC date of the record under construction.
    ///
    /// A [`chrono::DateTime<Utc>`] is accepted directly and converted to a [`WarcDate`].
    #[must_use]
    pub fn date<D: Into<WarcDate>>(mut self, date: D) -> Self {
        self.value.set_date(date);

        self
    }

    /// Set the record ID header of the record under construction.
    #[must_use]
    pub fn warc_id<S: Into<String>>(mut self, id: S) -> Self {
        self.value.set_warc_id(id);

        self
    }

    /// Set the WARC version of the record under construction.
    #[must_use]
    pub const fn version(mut self, version: WarcVersion) -> Self {
        self.value.set_warc_version(version);

        self
    }

    /// Set the WARC record type header field of the record under construction.
    #[must_use]
    pub fn warc_type(mut self, warc_type: RecordType) -> Self {
        self.value.set_warc_type(warc_type);

        self
    }

    /// Set the truncated type header of the record under construction.
    #[must_use]
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
    #[must_use]
    pub fn header<V: Into<Vec<u8>>>(mut self, key: WarcHeader, value: V) -> Self {
        let value = value.into();
        match Self::set_raw_header(&mut self.value, key.clone(), &value) {
            Ok(()) => {
                self.broken_headers.shift_remove(&key);
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
    #[must_use]
    pub fn build_raw(self) -> (RawRecordHeader, Vec<u8>) {
        let Self {
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
        let Self {
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

    /// Stripping the body keeps every other field of the record and zeroes its length.
    #[test]
    fn strip_body_preserves_fields() {
        let mut record = Record::<BufferedBody>::default();
        record.replace_body(b"hello".to_vec());
        record
            .set_header(WarcHeader::TargetURI, "https://example.com/")
            .unwrap();
        record.set_truncated_type(TruncatedType::Length);

        let record_id = record.warc_id().to_owned();
        let date = record.date();

        let stripped = record.strip_body();

        assert_eq!(stripped.content_length(), 0);
        assert_eq!(stripped.warc_id(), record_id);
        assert_eq!(stripped.date(), date);
        assert_eq!(stripped.warc_type(), &RecordType::Resource);
        assert_eq!(stripped.truncated_type(), &Some(TruncatedType::Length));
        assert_eq!(
            stripped.header(WarcHeader::TargetURI).as_deref(),
            Some("https://example.com/")
        );
    }

    /// `Display` for a buffered record renders the full header block (version line and derived
    /// fields included) followed by the body bytes.
    #[test]
    fn display_buffered_record_renders_full_header_block() {
        let mut record = Record::<BufferedBody>::default();
        record.replace_body(b"hello".to_vec());
        record
            .set_header(WarcHeader::TargetURI, "https://example.com/")
            .unwrap();
        let rendered = record.to_string();
        assert!(rendered.starts_with("Record(WARC/1.1\r\n"), "{rendered}");
        for expected in [
            "warc-type: resource\r\n",
            &format!("warc-record-id: {}\r\n", record.warc_id()),
            "warc-date: ",
            "warc-target-uri: https://example.com/\r\n",
            "content-length: 5\r\n",
        ] {
            assert!(rendered.contains(expected), "{expected:?} in {rendered}");
        }
        assert!(
            rendered.ends_with(&format!("{:?})", b"hello")),
            "{rendered}"
        );
    }

    #[test]
    fn default() {
        let before = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let record = Record::<BufferedBody>::default();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let after = Utc::now();
        assert_eq!(record.content_length(), 0);
        assert_eq!(record.warc_version(), crate::WarcVersion::V1_1);
        assert_eq!(record.warc_type(), &RecordType::Resource);
        assert!(record.date().date_time() > before);
        assert!(record.date().date_time() < after);
    }

    #[test]
    fn impl_eq() {
        let record1 = Record::<BufferedBody>::default();
        let record2 = record1.clone();
        assert_eq!(record1, record2);
    }

    #[test]
    fn impl_eq_empty_body() {
        let record1 = Record::<EmptyBody>::default();
        let record2 = record1.clone();
        assert_eq!(record1, record2);
    }

    #[test]
    fn body() {
        let mut record = Record::<BufferedBody>::default();
        assert_eq!(record.content_length(), 0);
        assert_eq!(record.body(), b"");
        record.replace_body(b"hello!!".to_vec());
        assert_eq!(record.content_length(), 7);
        assert_eq!(record.body(), b"hello!!");
        record.body_mut().copy_from_slice(b"goodbye");
        assert_eq!(record.content_length(), 7);
        assert_eq!(record.body(), b"goodbye");
    }

    #[test]
    fn into_raw_parts_header_order() {
        let mut record = Record::<BufferedBody>::default();
        record.replace_body(b"hello".to_vec());
        record
            .set_header(WarcHeader::TargetURI, "https://example.com/")
            .unwrap();

        let (headers, _) = record.into_raw_parts();
        let keys: Vec<&WarcHeader> = headers.as_ref().keys().collect();
        assert_eq!(
            keys,
            vec![
                &WarcHeader::WarcType,
                &WarcHeader::RecordID,
                &WarcHeader::Date,
                &WarcHeader::TargetURI,
                &WarcHeader::ContentLength,
            ]
        );
    }

    #[test]
    fn add_header() {
        let mut record = Record::<BufferedBody>::default();
        assert!(record.header(WarcHeader::TargetURI).is_none());
        assert!(
            record
                .set_header(WarcHeader::TargetURI, "https://www.rust-lang.org")
                .unwrap()
                .is_none()
        );
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

    /// WARC 1.1 permits `WARC-Date` at any W3C-DTF granularity, which survives parsing.
    #[test]
    fn parse_record_date_granularities() {
        let expectations = [
            ("2020", "2020"),
            ("2020-07", "2020-07"),
            ("2020-07-08", "2020-07-08"),
            ("2020-07-08T02:52Z", "2020-07-08T02:52Z"),
            ("2020-07-08T02:52+01:00", "2020-07-08T01:52Z"),
            ("2020-07-08T02:52:55Z", "2020-07-08T02:52:55Z"),
            (
                "2020-07-08T02:52:55.123456789Z",
                "2020-07-08T02:52:55.123456789Z",
            ),
        ];

        for (value, expected) in expectations {
            let parsed = Record::parse_record_date(crate::WarcVersion::V1_1, value).expect(value);
            assert_eq!(
                parsed.to_string_for_version(crate::WarcVersion::V1_1),
                expected,
                "{value}"
            );
        }

        for invalid in ["yesterday", "202", "2020-7", "2020-07-08T02Z", "20200708"] {
            assert!(
                Record::parse_record_date(crate::WarcVersion::V1_1, invalid).is_err(),
                "{invalid}"
            );
        }
    }

    /// Generated record ids satisfy the `WARC-Record-ID` requirements: a bracketed URI in a
    /// registered scheme, with no internal whitespace.
    #[test]
    fn generated_record_id_is_a_bracketed_urn() {
        let id = Record::generate_record_id();
        let uri = id
            .strip_prefix('<')
            .and_then(|id| id.strip_suffix('>'))
            .expect("record id should be enclosed in angle brackets");
        assert!(uri.starts_with("urn:uuid:"));
        assert!(!uri.contains(char::is_whitespace));
    }

    /// Emitted `WARC-Date` values are ISO 8601 UTC timestamps: non-UTC offsets are converted, and
    /// a decimal fraction (at most nine digits) appears only when the moment requires one.
    #[test]
    fn emitted_date_is_iso_8601_utc() {
        let mut record = Record::<BufferedBody>::default();
        for (input, expected) in [
            ("2020-07-08T02:52:55Z", "2020-07-08T02:52:55Z"),
            ("2020-07-08T02:52:55.123Z", "2020-07-08T02:52:55.123Z"),
            (
                "2020-07-08T03:52:55.123456789+01:00",
                "2020-07-08T02:52:55.123456789Z",
            ),
        ] {
            record.set_header(WarcHeader::Date, input).unwrap();
            assert_eq!(
                record.header(WarcHeader::Date).unwrap(),
                expected,
                "{input}"
            );
        }
    }

    /// A sub-second `WARC-Date` survives a set/get round trip unchanged.
    #[test]
    fn set_header_preserves_subsecond_date() {
        let mut record = Record::<BufferedBody>::default();
        record
            .set_header(WarcHeader::Date, "2020-07-08T02:52:55.123456Z")
            .unwrap();
        assert_eq!(
            record.header(WarcHeader::Date).unwrap(),
            "2020-07-08T02:52:55.123456Z"
        );
    }

    /// `WARC-Concurrent-To` is the one repeatable header: `add_concurrent_to` appends,
    /// `header` reads the first value, and `set_header` replaces every value.
    #[test]
    fn concurrent_to_repeats() {
        let mut record = Record::<BufferedBody>::default();
        assert!(record.header(WarcHeader::ConcurrentTo).is_none());

        record.add_concurrent_to("<urn:test:concurrent:record-1>");
        record.add_concurrent_to("<urn:test:concurrent:record-2>");
        assert_eq!(
            record.concurrent_to().collect::<Vec<_>>(),
            vec![
                "<urn:test:concurrent:record-1>",
                "<urn:test:concurrent:record-2>",
            ]
        );
        assert_eq!(
            record.header(WarcHeader::ConcurrentTo).unwrap(),
            "<urn:test:concurrent:record-1>"
        );

        assert_eq!(
            record
                .set_header(WarcHeader::ConcurrentTo, "<urn:test:concurrent:record-3>")
                .unwrap()
                .unwrap(),
            "<urn:test:concurrent:record-1>"
        );
        assert_eq!(
            record.concurrent_to().collect::<Vec<_>>(),
            vec!["<urn:test:concurrent:record-3>"]
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
    fn set_header_rejects_values_with_line_breaks() {
        let mut record = Record::<BufferedBody>::default();

        for value in ["a\r\nwarc-type: evil", "a\rb", "a\nb"] {
            assert!(
                matches!(
                    record.set_header(WarcHeader::TargetURI, value),
                    Err(Error::MalformedHeader(WarcHeader::TargetURI, _))
                ),
                "{value:?}"
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
    fn set_header_rejects_invalid_unknown_names() {
        let mut record = Record::<BufferedBody>::default();

        for name in ["", "evil name", "evil:name", "evil\r\nname"] {
            let header = WarcHeader::Unknown(name.to_string());
            assert!(
                matches!(
                    record.set_header(header, "value"),
                    Err(Error::MalformedHeader(WarcHeader::Unknown(_), _))
                ),
                "{name:?}"
            );
        }

        assert!(
            record
                .set_header(WarcHeader::Unknown("x-custom".to_string()), "value")
                .is_ok()
        );
    }

    /// DEL is a control character, so it cannot appear in an extension field-name token.
    #[test]
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
            "{block}"
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

        assert!(rendered.starts_with("Record(WARC/1.1"), "{}", rendered);
        for expected in [
            "warc-type: resource",
            &format!("warc-record-id: {}", record.warc_id()),
            "warc-date: ",
            "warc-target-uri: https://example.com/",
            "content-length: 0",
        ] {
            assert!(rendered.contains(expected), "{expected:?} in {rendered}");
        }
        assert!(rendered.ends_with(", Empty)"), "{}", rendered);
    }

    /// `Content-Length` values follow the `1*DIGIT` grammar at the record entry points too:
    /// linear whitespace around the digits is tolerated, a sign is not.
    #[test]
    fn set_header_content_length_grammar() {
        let mut record = Record::<BufferedBody>::default();

        assert!(record.set_header(WarcHeader::ContentLength, "0 ").is_ok());
        assert!(
            record
                .set_header(WarcHeader::ContentLength, "\t0\t")
                .is_ok()
        );

        // A sign is rejected even when the value would match the body size.
        assert!(matches!(
            record.set_header(WarcHeader::ContentLength, "+0"),
            Err(Error::MalformedHeader(WarcHeader::ContentLength, _))
        ));
    }

    /// Setting the derived content length returns its canonical previous value, not the
    /// caller's alternate but equivalent spelling.
    #[test]
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
        assert!(
            record
                .set_header(WarcHeader::ContentLength, "really short")
                .is_err()
        );
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
        let old_date = record.header(WarcHeader::Date).unwrap().into_owned();
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

    use indexmap::IndexMap;
    use std::convert::TryFrom;

    #[test]
    fn create() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
            headers: IndexMap::new(),
            concurrent_to: Vec::new(),
        };

        assert_eq!(headers.as_ref().len(), 0);
    }

    #[test]
    fn create_with_headers() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
            headers: vec![(
                WarcHeader::WarcType,
                RecordType::WarcInfo.to_string().into_bytes(),
            )]
            .into_iter()
            .collect(),
            concurrent_to: Vec::new(),
        };

        assert_eq!(headers.as_ref().len(), 1);
    }

    #[test]
    fn verify_ok() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_ok());
    }

    #[test]
    fn verify_missing_type() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    #[test]
    fn verify_missing_content_length() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    #[test]
    fn verify_missing_record_id() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
            headers: vec![
                (WarcHeader::WarcType, b"dunno".to_vec()),
                (WarcHeader::ContentLength, b"5".to_vec()),
                (WarcHeader::Date, b"2020-07-08T02:52:55Z".to_vec()),
            ]
            .into_iter()
            .collect(),
            concurrent_to: Vec::new(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    #[test]
    fn verify_missing_date() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
        };

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    /// A block that converts cleanly, with one field replaced by the given value.
    fn headers_with(header: WarcHeader, value: Vec<u8>) -> RawRecordHeader {
        let mut headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
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
                other => panic!("expected malformed content-length error, got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_malformed_record_id_blames_record_id() {
        let headers = headers_with(WarcHeader::RecordID, vec![0xff, 0xfe]);
        match Record::<EmptyBody>::try_from(headers) {
            Err(Error::MalformedHeader(WarcHeader::RecordID, _)) => {}
            other => panic!("expected malformed record-id error, got {other:?}"),
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
            other => panic!("expected malformed target-uri error, got {other:?}"),
        }
    }

    /// A hand-built raw block may spell a well-known field as `Unknown`; conversion folds it
    /// into the typed field.
    #[test]
    fn verify_unknown_spelling_is_normalized() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
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
    fn verify_unknown_spelling_collision_is_rejected() {
        let headers = headers_with(
            WarcHeader::Unknown("WARC-Date".to_string()),
            b"2021-01-01T00:00:00Z".to_vec(),
        );

        assert!(Record::<EmptyBody>::try_from(headers).is_err());
    }

    /// The formatted header block is terminated by CRLF throughout, as the grammar requires.
    #[test]
    fn display_uses_crlf_line_endings() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_1,
            headers: vec![(WarcHeader::WarcType, b"resource".to_vec())]
                .into_iter()
                .collect(),
            concurrent_to: Vec::new(),
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
            version: crate::WarcVersion::V1_0,
            headers: header_entries.into_iter().collect(),
            concurrent_to: Vec::new(),
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
        expected_headers.sort_unstable();

        let mut actual_headers: Vec<_> = actual_lines[1..actual_lines.len() - 1].to_vec();
        actual_headers.sort_unstable();

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
        EmptyBody, Error, RawRecordHeader, Record, RecordBuilder, RecordType, TruncatedType,
    };

    use std::convert::TryFrom;

    #[test]
    fn default() {
        let (headers, body) = RecordBuilder::default().build_raw();
        assert_eq!(headers.version, crate::WarcVersion::V1_1);
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
        assert_eq!(headers.version, crate::WarcVersion::V1_1);
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
            version: crate::WarcVersion::V1_0,
            headers: vec![(
                WarcHeader::WarcType,
                RecordType::WarcInfo.to_string().into_bytes(),
            )]
            .into_iter()
            .collect(),
            concurrent_to: Vec::new(),
        };

        assert_eq!(headers.as_ref().len(), 1);
    }

    #[test]
    fn verify_ok() {
        let headers = RawRecordHeader {
            version: crate::WarcVersion::V1_0,
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
            concurrent_to: Vec::new(),
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
            other => panic!("expected an error blaming content-length, got {other:?}"),
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
        builder = builder
            .date(Record::parse_record_date(crate::WarcVersion::V1_1, DATE_STRING_0).unwrap());

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
