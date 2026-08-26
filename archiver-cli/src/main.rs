//! A command-line front end for archiving URLs into WARC files.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use archivindex_archiver::capture::{CaptureControl, CaptureEvent};
use archivindex_archiver::{Archiver, Config};
use archivindex_cli_support::{CommandOutcome, Verbosity, exit_code, plural};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

fn main() -> ExitCode {
    let cli = Cli::parse();
    cli.verbosity.init_logging();

    exit_code(run(cli))
}

fn run(cli: Cli) -> Result<CommandOutcome> {
    let quiet = cli.verbosity.is_quiet();

    match cli.command {
        Command::Archive(options) => archive(options, quiet),
    }
}

/// Archive a list of URLs read from standard input.
fn archive(options: ArchiveOptions, quiet: bool) -> Result<CommandOutcome> {
    let config = options.config.into_config(options.concurrency);
    let archiver = Archiver::new(config).context("cannot configure the archiver")?;
    let mut input_error = None;
    let urls = read_urls(std::io::stdin().lock(), &mut input_error);
    let progress = progress_spinner("Archiving", "URLs");
    let mut events = |event: CaptureEvent<'_>| {
        if matches!(event, CaptureEvent::Written { .. }) {
            progress.inc(1);
        }
        CaptureControl::Continue
    };
    let result = archiver.archive_to_path_with_events(urls, &options.output, &mut events);
    progress.finish_and_clear();
    let summary =
        result.with_context(|| format!("cannot archive to {}", options.output.display()))?;
    if let Some(error) = &input_error {
        log::warn!("stopped reading input early: {error}");
    }

    for failure in &summary.failures {
        log::warn!("failed to capture {}: {}", failure.url, failure.error);
    }
    for capture in &summary.captures {
        if capture.is_partial() {
            log::warn!(
                "captured {} only in part: {}",
                capture.url,
                capture
                    .truncated
                    .as_ref()
                    .expect("invariant violation: a partial capture was truncated")
            );
        }
    }

    if !quiet {
        println!(
            "Archived {} of {} to {}.",
            summary.captures.len(),
            plural(
                summary.captures.len() + summary.failures.len(),
                "requested URL"
            ),
            options.output.display()
        );
    }

    if summary.is_complete() && input_error.is_none() {
        Ok(CommandOutcome::Success)
    } else {
        log::warn!(
            "a partial archive was published at {}",
            options.output.display()
        );

        Ok(CommandOutcome::ReportedProblems)
    }
}

/// Read one URL per line, trimming surrounding whitespace and skipping blank lines.
///
/// A read failure ends iteration and is stored in `error`.
fn read_urls<'a, R: BufRead + 'a>(
    reader: R,
    error: &'a mut Option<std::io::Error>,
) -> impl Iterator<Item = String> + 'a {
    reader
        .lines()
        .map_while(move |line| match line {
            Ok(line) => {
                let url = line.trim();
                Some((!url.is_empty()).then(|| url.to_owned()))
            }
            Err(source) => {
                *error = Some(source);
                None
            }
        })
        .flatten()
}

fn progress_spinner(message: &'static str, unit: &str) -> ProgressBar {
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::with_template(&format!("{{msg}} {{human_pos}} {unit} {{spinner}}"))
            .expect("valid progress spinner template"),
    );
    progress.set_message(message);
    progress
}

#[derive(Debug, Parser)]
#[command(name = "archivindex-archiver", version, about)]
struct Cli {
    #[command(flatten)]
    verbosity: Verbosity,

    #[command(subcommand)]
    command: Command,
}

/// The archiving workflow to run.
#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Archive URLs read one per line from standard input.
    Archive(ArchiveOptions),
}

/// Options for archiving URLs read from standard input.
#[derive(Debug, clap::Args)]
struct ArchiveOptions {
    #[command(flatten)]
    config: ConfigOptions,

    /// The WARC file to write; an existing file is not overwritten.
    #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    output: PathBuf,

    /// The number of URLs downloaded concurrently (defaults to 1).
    #[arg(long, value_name = "COUNT")]
    concurrency: Option<usize>,
}

/// Capture settings for the archiving workflow.
#[derive(Debug, clap::Args)]
struct ConfigOptions {
    /// Compress each WARC record as an independent gzip member.
    #[arg(long)]
    gzip: bool,

    /// The User-Agent header value sent with every request (defaults to the archiver's own).
    #[arg(long, value_name = "VALUE")]
    user_agent: Option<String>,

    /// The idle timeout in seconds for connecting and for each socket read or write (defaults to
    /// 30).
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// The maximum time in seconds spent capturing one URL, including its redirect hops (defaults
    /// to 600; a response still arriving at the limit is archived truncated rather than failed).
    #[arg(long, value_name = "SECONDS")]
    max_capture_time: Option<u64>,

    /// Capture every URL to completion, however long it takes.
    #[arg(long, conflicts_with = "max_capture_time")]
    unbounded_capture_time: bool,

    /// The maximum number of redirects followed for each URL (defaults to 10). Answering a
    /// challenge is not a redirect.
    #[arg(long, value_name = "COUNT")]
    max_redirects: Option<usize>,

    /// The maximum number of response bytes stored for one fetch (defaults to 256 MiB; a response
    /// reaching the limit is archived truncated rather than failed).
    #[arg(long, value_name = "BYTES")]
    max_response_length: Option<u64>,

    /// Store every response whole, however large.
    #[arg(long, conflicts_with = "max_response_length")]
    unbounded_response_length: bool,
}

impl ConfigOptions {
    /// Build an archiver configuration, optionally overriding its concurrency.
    fn into_config(self, concurrency: Option<usize>) -> Config {
        let defaults = Config::default();

        Config {
            user_agent: self.user_agent.unwrap_or(defaults.user_agent),
            timeout: self.timeout.map_or(defaults.timeout, Duration::from_secs),
            max_capture_time: if self.unbounded_capture_time {
                None
            } else {
                self.max_capture_time
                    .map_or(defaults.max_capture_time, |seconds| {
                        Some(Duration::from_secs(seconds))
                    })
            },
            max_redirects: self.max_redirects.unwrap_or(defaults.max_redirects),
            concurrency: concurrency.unwrap_or(defaults.concurrency),
            max_response_length: if self.unbounded_response_length {
                None
            } else {
                self.max_response_length.or(defaults.max_response_length)
            },
            gzip_warc: self.gzip,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command, Config};

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn read_urls_trims_and_skips_blank_lines() {
        let input = "https://example.com/\n\n  https://example.org/  \n";

        let mut error = None;
        let urls = super::read_urls(input.as_bytes(), &mut error).collect::<Vec<_>>();

        assert_eq!(urls, ["https://example.com/", "https://example.org/"]);
        assert!(error.is_none());
    }

    #[test]
    fn archive_defaults_to_an_uncompressed_warc() {
        let cli = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--output",
            "capture.warc",
        ])
        .expect("valid options");

        let Command::Archive(options) = cli.command;

        assert!(!options.config.gzip);
    }

    #[test]
    fn archive_bounds_captures_by_default() {
        let cli = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--output",
            "capture.warc",
        ])
        .expect("valid options");

        let Command::Archive(options) = cli.command;
        let config = options.config.into_config(None);

        assert_eq!(
            config.max_response_length,
            Some(archivindex_archiver::recorder::DEFAULT_MAX_RESPONSE_LENGTH)
        );
        assert_eq!(
            config.max_capture_time,
            Some(Config::DEFAULT_MAX_CAPTURE_TIME)
        );
    }

    #[test]
    fn archive_lifts_the_capture_time_bound_on_request() {
        let cli = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--output",
            "capture.warc",
            "--unbounded-capture-time",
        ])
        .expect("valid options");

        let Command::Archive(options) = cli.command;

        assert_eq!(options.config.into_config(None).max_capture_time, None);
    }

    #[test]
    fn archive_can_lift_the_response_bound() {
        let cli = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--output",
            "capture.warc",
            "--unbounded-response-length",
        ])
        .expect("valid options");

        let Command::Archive(options) = cli.command;
        let config = options.config.into_config(None);

        assert_eq!(config.max_response_length, None);
    }

    #[test]
    fn archive_refuses_a_bound_that_is_also_lifted() {
        let result = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--output",
            "capture.warc",
            "--max-response-length",
            "1024",
            "--unbounded-response-length",
        ]);

        assert!(result.is_err());
    }
}
