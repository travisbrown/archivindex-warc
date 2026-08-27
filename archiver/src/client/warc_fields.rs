//! The `warcinfo` and `metadata` records authored by the archiver.

use std::time::Duration;

use archivindex_warc::record::Record;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc::record::fields::Error as FieldsError;
use archivindex_warc::record::fields::dcmi::DcmiTerm;
use archivindex_warc::record::fields::metadata::MetadataField;
use archivindex_warc::record::fields::warcinfo::WarcinfoField;
use archivindex_warc::value::WarcDate;
use chrono::Utc;
use fluent_uri::Uri;

use super::outcome::DATE_PRECISION;
use crate::config::{Operator, Software};
use crate::{Config, Error};

/// Information recorded in the WARC file's initial `warcinfo` record.
pub struct WarcinfoOptions<'a> {
    pub user_agent: &'a str,
    pub software: &'a Software,
    pub operator: Option<&'a Operator>,
    pub session_id: Option<&'a str>,
    pub title: Option<&'a str>,
}

impl<'a> WarcinfoOptions<'a> {
    /// Options for a one-shot run: the configured software and operator, with no session.
    pub fn archiver(config: &'a Config) -> Self {
        Self {
            user_agent: &config.user_agent,
            software: &config.software,
            operator: config.operator.as_ref(),
            session_id: None,
            title: None,
        }
    }
}

/// Check that the configured software and operator can be written as `warc-fields` values.
pub fn check_warcinfo_fields(config: &Config) -> Result<(), FieldsError> {
    let builder = Record::<NoExtension>::warcinfo(WarcDate::new(Utc::now(), DATE_PRECISION))
        .software(&config.software.name, &config.software.version)?;
    if let Some(operator) = &config.operator {
        builder.operator(&operator.name, operator.email.as_deref())?;
    }

    Ok(())
}

/// Values recorded in the `warc-fields` metadata accompanying one capture.
#[derive(Clone, Copy)]
pub struct MetadataValues<'a> {
    pub fetch_time: Duration,
    pub via: Option<&'a str>,
    pub title: Option<&'a str>,
}

/// Build the `warcinfo` record at the start of a WARC file.
///
/// `software` and `http-header-user-agent` are always included.
pub fn warcinfo_record(warc_name: &str, options: &WarcinfoOptions<'_>) -> Result<Record, Error> {
    let mut builder = Record::warcinfo(WarcDate::new(Utc::now(), DATE_PRECISION))
        .filename(warc_name)?
        .software(&options.software.name, &options.software.version)?;
    if let Some(operator) = options.operator {
        builder = builder.operator(&operator.name, operator.email.as_deref())?;
    }
    builder = builder.http_header_user_agent(options.user_agent)?;
    if let Some(session_id) = options.session_id {
        builder = builder.is_part_of(session_id)?;
    }
    if let Some(title) = options.title {
        builder = builder.field(WarcinfoField::Dcmi(DcmiTerm::Title), title)?;
    }

    Ok(builder.build())
}

/// Build the metadata record linked to one captured response or revisit.
pub fn metadata_record(
    date: WarcDate,
    target_uri: Uri<String>,
    record_id: Uri<String>,
    warcinfo_id: &Uri<String>,
    values: MetadataValues<'_>,
) -> Result<Record, Error> {
    let mut builder = Record::metadata(date)
        .target_uri(target_uri)
        .concurrent_to(record_id)
        .warcinfo_id(warcinfo_id.clone());
    if let Some(via) = values.via {
        builder = builder.via(via)?;
    }
    builder = builder.fetch_time_ms(values.fetch_time);
    if let Some(title) = values.title {
        builder = builder.field(MetadataField::Dcmi(DcmiTerm::Title), title)?;
    }

    Ok(builder.build())
}
