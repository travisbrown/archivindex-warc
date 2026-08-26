//! WARC spooling and revisit-state accumulation.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use archivindex_warc::io::write::{Compression, WarcWriter};
use archivindex_warc::record::Record;
use archivindex_warc::record::header::truncated_type::TruncatedType;
use archivindex_warc::record::http::RequestMetadata;
use archivindex_warc_revisit_index::Index;
use archivindex_warc_revisit_index::payload::RevisitTarget;
use archivindex_warc_revisit_index::resource::{
    ResourceKey, ResourceState, ResourceStateUpdate, Variance,
};
use fluent_uri::Uri;
use http::header::{HeaderMap, HeaderValue};
use tempfile::{NamedTempFile, TempPath};

use super::outcome::{CaptureOutcome, Exchange, Original, request_field};
use super::warc_fields::{WarcinfoOptions, warcinfo_record};
use super::warc_mapping::{MetadataOptions, write_exchange, write_record};
use crate::Error;
use crate::capture::{ArchiveSummary, CaptureSummary, Failure};

/// Files accumulated while captures are written to a spooled WARC file.
pub struct Collection {
    warc: WarcWriter<BufWriter<File>>,
    spool_path: Option<TempPath>,
    warcinfo_id: Uri<String>,
    summary: ArchiveSummary,
    /// Payload and conditional-request state created by this collection.
    session_index: Index,
    /// Earlier durable crawl state, published to only after the WARC is durable.
    persistent_index: Option<Index>,
    /// The header fields every request carries, which decide which stored state applies to them.
    request_headers: HeaderMap,
}

/// What a collection writes, and the requests whose revisit state it records.
pub struct CollectionOptions<'a> {
    /// The WARC file name recorded in `warcinfo`.
    pub warc_name: &'a str,
    /// Whether each record is written as an independent gzip member.
    pub gzip: bool,
    /// The `warcinfo` fields describing the capture run.
    pub warcinfo: WarcinfoOptions<'a>,
    /// The header fields every request carries.
    ///
    /// A response declaring `Vary` is stored with this request's values for the fields it names,
    /// so that a later run configured differently does not revalidate against another variant.
    pub request_headers: HeaderMap,
    /// Earlier durable crawl state, published to only after the WARC is durable.
    pub persistent_index: Option<Index>,
}

impl Collection {
    /// Start a collection by writing its initial `warcinfo` record.
    pub fn new(options: CollectionOptions<'_>) -> Result<Self, Error> {
        let warcinfo = warcinfo_record(options.warc_name, &options.warcinfo)?;
        Self::with_spool(tempfile::tempfile()?, None, warcinfo, options)
    }

    /// Start a collection in `<output>.partial` so its growth is visible while it is written.
    ///
    /// The `warcinfo` record is built before `<output>.partial` is created, so an unrecordable
    /// WARC file name leaves nothing on disk.
    pub fn new_for_path(output: &Path, options: CollectionOptions<'_>) -> Result<Self, Error> {
        let warcinfo = warcinfo_record(options.warc_name, &options.warcinfo)?;
        if output.try_exists()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("output already exists: {}", output.display()),
            )
            .into());
        }

        let partial_path = std::path::absolute(partial_path(output))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial_path)?;
        let spool_path = TempPath::try_from_path(&partial_path)?;

        Self::with_spool(file, Some(spool_path), warcinfo, options)
    }

    fn with_spool(
        file: File,
        spool_path: Option<TempPath>,
        warcinfo: Record,
        options: CollectionOptions<'_>,
    ) -> Result<Self, Error> {
        let CollectionOptions {
            warc_name: _,
            gzip,
            warcinfo: _,
            request_headers,
            persistent_index,
        } = options;
        let compression = if gzip {
            Compression::gzip()
        } else {
            Compression::NONE
        };
        let mut warc = WarcWriter::new(BufWriter::new(file)).with_compression(compression);
        let warcinfo_id = warcinfo.core().record_id.clone();
        write_record(&mut warc, warcinfo)?;
        if spool_path.is_some() {
            warc.flush()?;
        }

        Ok(Self {
            warc,
            spool_path,
            warcinfo_id,
            summary: ArchiveSummary::default(),
            session_index: Index::open_in_memory()?,
            persistent_index,
            request_headers,
        })
    }

    /// The earlier capture of a target URI that a new capture may ask the server to revalidate.
    ///
    /// `cookie` is the value the request will carry, which the configured fields do not hold.
    pub fn original(
        &self,
        target_uri: Uri<String>,
        cookie: Option<&HeaderValue>,
    ) -> Result<Option<Original>, Error> {
        let key = ResourceKey::new(target_uri);

        if let Some(state) = self.session_index.lookup_resource(&key)? {
            return self.original_from_state(state, cookie);
        }
        let Some(state) = self
            .persistent_index
            .as_ref()
            .map(|index| index.lookup_resource(&key))
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        self.session_index.update_resource(
            &key,
            ResourceStateUpdate::Representation {
                etag: state.etag.clone(),
                last_modified: state.last_modified.clone(),
                payload_digest: state.payload_digest.clone(),
                record_id: state.record_id.clone(),
                warc_date: state.warc_date,
                observed_at: state.observed_at,
                variance: state.variance.clone(),
            },
        )?;

        self.original_from_state(state, cookie)
    }

    /// Resolve a resource state's canonical payload target across the session overlay and durable
    /// index.
    fn original_from_state(
        &self,
        state: ResourceState,
        cookie: Option<&HeaderValue>,
    ) -> Result<Option<Original>, Error> {
        let canonical = state
            .payload_digest
            .as_ref()
            .map(|digest| self.lookup_payload(digest))
            .transpose()?
            .flatten();

        Ok(Original::from_state(
            state,
            canonical,
            &self.request_headers,
            cookie,
        ))
    }

    /// Look up a payload created in this collection before consulting earlier durable state.
    fn lookup_payload(
        &self,
        digest: &archivindex_warc::value::LabelledDigest,
    ) -> Result<Option<RevisitTarget>, Error> {
        if let Some(target) = self.session_index.lookup_payload(digest)? {
            return Ok(Some(target));
        }

        self.persistent_index
            .as_ref()
            .map(|index| index.lookup_payload(digest))
            .transpose()
            .map(Option::flatten)
            .map_err(Error::from)
    }

    /// Record every captured hop and add either a page summary or failure.
    ///
    /// A hop whose payload digest matches an earlier capture in this collection, or whose `304 Not
    /// Modified` confirms an earlier capture's payload unchanged, is stored as a `revisit` record
    /// referencing the original, instead of repeating the payload.
    pub fn record(
        &mut self,
        url: String,
        outcome: CaptureOutcome,
        title: Option<&str>,
        via: Option<&str>,
    ) -> Result<(), Error> {
        match outcome {
            CaptureOutcome::Captured {
                exchanges,
                redirects,
            } => {
                let last = self.record_exchanges(exchanges, title, via)?;
                let FinalHop {
                    date,
                    status,
                    size,
                    truncated,
                } = last.expect("a successful capture has at least one exchange");
                self.summary.captures.push(CaptureSummary {
                    url,
                    date,
                    status,
                    size,
                    redirects,
                    truncated,
                });
            }
            CaptureOutcome::Failed { exchanges, error } => {
                self.record_exchanges(exchanges, title, via)?;
                self.summary.failures.push(Failure { url, error });
            }
        }

        self.flush_spool()
    }

    /// Record the completed hops of a capture that was cancelled before it finished.
    ///
    /// The summary does not describe the capture, since it neither completed nor failed.
    pub fn record_abandoned(
        &mut self,
        exchanges: Vec<Exchange>,
        via: Option<&str>,
    ) -> Result<(), Error> {
        self.record_exchanges(exchanges, None, via)?;
        self.flush_spool()
    }

    /// Flush a spooled WARC so that its partial file holds every completed capture.
    fn flush_spool(&mut self) -> Result<(), Error> {
        if self.spool_path.is_some() {
            self.warc.flush()?;
        }

        Ok(())
    }

    fn record_exchanges(
        &mut self,
        exchanges: Vec<Exchange>,
        title: Option<&str>,
        via: Option<&str>,
    ) -> Result<Option<FinalHop>, Error> {
        let mut last = None;
        let hops = exchanges.len();

        for (hop, exchange) in exchanges.into_iter().enumerate() {
            last = Some(FinalHop {
                date: exchange.date.date_time(),
                status: exchange.status,
                size: exchange.payload_length(),
                truncated: exchange.captured.truncated.clone(),
            });
            let key = exchange.revisit_key();
            let resource_key = exchange.resource_key();
            let observed_at = exchange.date;
            let etag = exchange.response_field("etag");
            let last_modified = exchange.response_field("last-modified");
            // The request as sent carries fields the configuration does not, in particular the
            // cookie a challenge issued, so a declared `Vary` is resolved against it.
            let sent = RequestMetadata::parse(&exchange.captured.request);
            let variance =
                Variance::declared(exchange.response_vary().as_deref(), |name| match &sent {
                    Some(sent) => sent.combined_header(name),
                    None => request_field(&self.request_headers, name),
                });
            let status = exchange.status;
            let revalidated = exchange.revalidated.is_some();
            let looked_up = if revalidated {
                None
            } else {
                key.as_ref()
                    .map(|digest| self.lookup_payload(digest))
                    .transpose()?
                    .flatten()
            };
            let target = write_exchange(
                &mut self.warc,
                exchange,
                &self.warcinfo_id,
                MetadataOptions {
                    via: via.filter(|_| hop == 0),
                    title: title.filter(|_| hop + 1 == hops),
                },
                looked_up.as_ref(),
            )?;

            if key.is_some()
                && let Some(target) = &target
            {
                self.session_index.insert_payload(target)?;
            }

            if status == 304 && revalidated {
                self.session_index.update_resource(
                    &resource_key,
                    ResourceStateUpdate::NotModified {
                        etag,
                        last_modified,
                        observed_at,
                    },
                )?;
            } else if status == 200
                && key.is_some()
                && let Some(original) = looked_up.as_ref().or(target.as_ref())
            {
                self.session_index.update_resource(
                    &resource_key,
                    ResourceStateUpdate::Representation {
                        etag,
                        last_modified,
                        payload_digest: Some(original.payload_digest.clone()),
                        record_id: Some(original.record_id.clone()),
                        warc_date: Some(original.warc_date),
                        observed_at,
                        variance,
                    },
                )?;
            }
        }

        Ok(last)
    }

    /// Copy the completed WARC to `output`.
    pub fn finish<W: Write>(self, mut output: W) -> Result<ArchiveSummary, Error> {
        let Self {
            warc,
            spool_path: _,
            warcinfo_id: _,
            summary,
            persistent_index: _,
            session_index: _,
            request_headers: _,
        } = self;
        let mut file = warc.finish().map_err(std::io::IntoInnerError::into_error)?;
        file.rewind()?;
        std::io::copy(&mut file, &mut output)?;
        output.flush()?;
        Ok(summary)
    }

    /// Atomically publish the completed WARC at `path`, then update durable revisit state.
    ///
    /// The WARC and its directory entry are synced before the index is updated, so the index
    /// never refers to a file a crash can lose. A failure updating the index leaves the WARC
    /// published, and indexing it again repairs the index.
    pub fn finish_to_path(self, path: &Path) -> Result<ArchiveSummary, Error> {
        let Self {
            warc,
            spool_path,
            warcinfo_id: _,
            summary,
            mut persistent_index,
            session_index,
            request_headers: _,
        } = self;
        let mut source = warc.finish().map_err(std::io::IntoInnerError::into_error)?;
        source.rewind()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        if let Some(spool_path) = spool_path {
            source.sync_all()?;
            NamedTempFile::from_parts(source, spool_path)
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        } else {
            let mut temporary = NamedTempFile::new_in(parent)?;
            std::io::copy(&mut source, &mut temporary)?;
            temporary.flush()?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        }
        sync_directory(parent)?;

        // The session index already contains the state derived from the completed WARC.
        if let Some(index) = &mut persistent_index {
            let transaction = index.begin()?;
            transaction.merge_from(&session_index)?;
            transaction.commit()?;
        }
        Ok(summary)
    }
}

/// Make the renames in `directory` durable.
///
/// On Unix a rename is durable only once the directory holding it is synced. Windows does not
/// open directories, and its renames need no such step.
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    if cfg!(unix) {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

fn partial_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".partial");
    path.into()
}

/// What a capture's summary takes from its final hop.
struct FinalHop {
    date: chrono::DateTime<chrono::Utc>,
    status: u16,
    size: u64,
    truncated: Option<TruncatedType>,
}
