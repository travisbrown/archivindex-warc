//! Mapping captured HTTP exchanges to WARC records.

use std::io::{BufWriter, Write};

use archivindex_warc::io::write::WarcWriter;
use archivindex_warc::record::Record;
use archivindex_warc::record::capture::{CaptureEvent, CaptureRecords, RevisitOriginal};
use archivindex_warc::record::header::RevisitProfile;
use archivindex_warc::value::{LabelledDigest, WarcDate};
use archivindex_warc_revisit_index::payload::RevisitTarget;
use fluent_uri::Uri;

use super::outcome::Exchange;
use super::warc_fields::{MetadataValues, metadata_record};
use crate::Error;
use crate::config::DigestFormats;
use crate::recorder::CapturedExchange;

/// Optional fields added to the metadata record accompanying an exchange.
#[derive(Clone, Copy)]
pub struct MetadataOptions<'a> {
    pub via: Option<&'a str>,
    pub title: Option<&'a str>,
}

/// A WARC writer that adds the configured digests to every record it writes.
pub struct RecordWriter<W: Write> {
    warc: WarcWriter<W>,
    digests: DigestFormats,
}

impl<W: Write> RecordWriter<W> {
    pub const fn new(warc: WarcWriter<W>, digests: DigestFormats) -> Self {
        Self { warc, digests }
    }

    /// Write a record with its digests, under whatever compression the writer was configured with.
    pub fn write(&mut self, record: Record) -> Result<(), Error> {
        self.warc
            .write(&record.into_raw_with_digests_in(self.digests.block, self.digests.payload)?)?;

        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.warc.flush()
    }
}

impl<W: Write> RecordWriter<BufWriter<W>> {
    pub fn finish(self) -> Result<W, std::io::IntoInnerError<BufWriter<W>>> {
        self.warc.finish()
    }
}

/// Write one exchange's request, response, and metadata records.
///
/// A `304 Not Modified` to a conditional request is written as a `server-not-modified` revisit
/// of the capture it revalidated; otherwise a match in `revisit_of` is written as an
/// `identical-payload-digest` revisit; otherwise the full response is written.
///
/// Returns the new response as a revisit target, or `None` when writing a revisit or when the
/// response has no payload digest.
pub fn write_exchange<W: Write>(
    writer: &mut RecordWriter<W>,
    exchange: Exchange,
    warcinfo_id: &Uri<String>,
    metadata: MetadataOptions<'_>,
    revisit_of: Option<&RevisitTarget>,
) -> Result<Option<RevisitTarget>, Error> {
    let payload_length = exchange.payload_length();
    let Exchange {
        date,
        status: _,
        payload_digest,
        revalidated,
        captured,
        ..
    } = exchange;

    let revisit_of = revalidated.as_ref().or(revisit_of);
    let revisit = revisit_of.map(|original| {
        let profile = if revalidated.is_some() {
            RevisitProfile::SERVER_NOT_MODIFIED
        } else {
            RevisitProfile::IDENTICAL_PAYLOAD_DIGEST
        };

        (original, profile)
    });
    let (records, target_uri) = capture_records(
        captured,
        date,
        payload_digest.as_ref(),
        CaptureContext {
            warcinfo_id,
            metadata,
        },
        revisit,
    )?;

    // A revisit's payload is the original's, whatever the revisiting response itself carried.
    let digest = revisit_of
        .map(|original| original.payload_digest.clone())
        .or(payload_digest);
    let target = revisit_of
        .is_none()
        .then_some(digest)
        .flatten()
        .map(|payload_digest| RevisitTarget {
            record_id: records.response.core().record_id.clone(),
            target_uri: target_uri.clone(),
            warc_date: date,
            payload_digest,
            payload_length: Some(payload_length),
        });
    writer.write(records.request)?;
    writer.write(records.response)?;
    if let Some(metadata) = records.metadata {
        writer.write(metadata)?;
    }

    Ok(target)
}

/// What every record of one capture shares.
#[derive(Clone, Copy)]
struct CaptureContext<'a> {
    /// The `warcinfo` record every record of the capture names.
    warcinfo_id: &'a Uri<String>,
    /// The fields added to the capture's metadata record.
    metadata: MetadataOptions<'a>,
}

/// Build a capture's request, response, and metadata records, returning its target URI.
///
/// With a revisit target, the response is replaced by a `revisit` record written under `profile`,
/// carrying the response head alone and naming the target's payload digest as its own.
fn capture_records(
    captured: CapturedExchange,
    date: WarcDate,
    payload_digest: Option<&LabelledDigest>,
    context: CaptureContext<'_>,
    revisit: Option<(&RevisitTarget, RevisitProfile)>,
) -> Result<(CaptureRecords, Uri<String>), Error> {
    let body_offset = captured.response_metadata.body_offset;
    let CapturedExchange {
        request,
        mut response,
        target_uri,
        ip_address,
        date: _,
        fetch_time,
        truncated,
        response_metadata: _,
    } = captured;
    // A revisit does not repeat the payload, so the original's digest describes what it stands for.
    let payload_digest = revisit
        .as_ref()
        .map(|(original, _)| &original.payload_digest)
        .or(payload_digest);
    let mut event = CaptureEvent::new(target_uri.clone(), date)
        .warcinfo_id(context.warcinfo_id.clone())
        .ip_address(ip_address)
        .identify_payload_type();

    if let Some(digest) = payload_digest {
        event = event.payload_digest(digest.clone());
    }
    if let Some(reason) = truncated {
        event = event.truncated(reason);
    }

    let mut records = match revisit {
        Some((original, profile)) => {
            response.truncate(body_offset.min(response.len()));

            event.revisit_exchange(
                request,
                response,
                profile,
                RevisitOriginal {
                    record_id: original.record_id.clone(),
                    target_uri: original.target_uri.clone(),
                    date: original.warc_date,
                },
            )?
        }
        None => event.exchange(request, response)?,
    };
    records.metadata = Some(metadata_record(
        date,
        target_uri.clone(),
        records.response.core().record_id.clone(),
        context.warcinfo_id,
        MetadataValues {
            fetch_time,
            via: context.metadata.via,
            title: context.metadata.title,
        },
    )?);

    Ok((records, target_uri))
}
