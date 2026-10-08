//! The `warcinfo` and `metadata` records authored by the archiver.

use std::time::Duration;

use archivindex_http_client::Engine;
use archivindex_http_client::prepare::redact_credentials;
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
use super::record_id::assign_record_id;
use crate::config::{Operator, Software};
use crate::{Config, ConfigError, Error};

/// Information recorded in the WARC file's initial `warcinfo` record.
pub struct WarcinfoOptions<'a> {
    pub user_agent: &'a str,
    pub software: &'a Software,
    pub engine: Engine,
    pub operator: Option<&'a Operator>,
    pub session_id: Option<&'a str>,
    pub proxy: Option<&'a str>,
}

impl<'a> WarcinfoOptions<'a> {
    /// Options for a one-shot run: the configured software and operator, with no session.
    pub fn archiver(config: &'a Config, engine: Engine) -> Self {
        Self {
            user_agent: &config.user_agent,
            software: &config.software,
            engine,
            operator: config.operator.as_ref(),
            session_id: None,
            proxy: config.proxy.as_deref(),
        }
    }
}

/// The `software` value: the software as `name/version`, followed by the engine of the capture
/// backend unless that is the built-in recorder.
fn software_value(software: &Software, engine: Engine) -> String {
    let Software { name, version } = software;

    if engine == Engine::RECORDER {
        format!("{name}/{version}")
    } else {
        format!("{name}/{version} {engine}")
    }
}

/// Check that the configured software and operator, and the backend's engine, can be written as
/// `warc-fields` values.
pub fn check_warcinfo_fields(config: &Config, engine: Engine) -> Result<(), FieldsError> {
    let builder = Record::<NoExtension>::warcinfo(WarcDate::new(Utc::now(), DATE_PRECISION))
        .field(
            WarcinfoField::Software,
            &software_value(&config.software, engine),
        )?;
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
        .field(
            WarcinfoField::Software,
            &software_value(options.software, options.engine),
        )?;
    if let Some(operator) = options.operator {
        builder = builder.operator(&operator.name, operator.email.as_deref())?;
    }
    if let Some(proxy) = options.proxy {
        let proxy = url::Url::parse(proxy)
            .map_err(archivindex_http_client::InvalidProxy::from)
            .map_err(ConfigError::from)?;
        builder = builder.field(
            WarcinfoField::from("archivindex-proxy"),
            &redact_credentials(&proxy),
        )?;
    }
    builder = builder.http_header_user_agent(options.user_agent)?;
    if let Some(session_id) = options.session_id {
        builder = builder.is_part_of(session_id)?;
    }

    let mut record = builder.build();
    assign_record_id(&mut record)?;
    Ok(record)
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

    let mut record = builder.build();
    assign_record_id(&mut record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorder is the archiver's own backend, so the software field names only the
    /// software. Any other engine follows the software as a second product, with the version and
    /// profile it has.
    #[test]
    fn the_software_value_names_an_engine_other_than_the_recorder() {
        let software = Software {
            name: "example-crawler".to_owned(),
            version: "2.0".to_owned(),
        };
        let engine = Engine {
            name: "example-engine",
            version: Some("1.2.3"),
            profile: Some("chrome_136"),
        };

        assert_eq!(
            software_value(&software, Engine::RECORDER),
            "example-crawler/2.0"
        );
        assert_eq!(
            software_value(&software, engine),
            "example-crawler/2.0 example-engine/1.2.3 (chrome_136)"
        );
    }

    /// A malformed proxy URL retains its parse error when preparing the archive metadata.
    #[test]
    fn malformed_proxy_metadata_preserves_the_parse_error() {
        let config = Config {
            proxy: Some("socks5h://[invalid".to_owned()),
            ..Config::default()
        };
        let result = warcinfo_record(
            "capture.warc",
            &WarcinfoOptions::archiver(&config, Engine::RECORDER),
        );
        assert!(matches!(
            result,
            Err(Error::InvalidConfig(ConfigError::InvalidProxy(
                archivindex_http_client::InvalidProxy::InvalidUrl(
                    url::ParseError::InvalidIpv6Address
                )
            )))
        ));
    }
}
