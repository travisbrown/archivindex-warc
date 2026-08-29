//! A command-line front end for archiving URLs into WARC files.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use archivindex_archiver::Archiver;
use archivindex_archiver::capture::{CaptureControl, CaptureEvent};
use archivindex_cli_support::{
    CommandOutcome, Verbosity, exit_code, interrupt_flag, load_config, plural, spinner,
};
use clap::Parser;

fn main() -> ExitCode {
    let cli = Cli::parse();
    cli.verbosity.init_logging();

    exit_code(run(cli))
}

fn run(cli: Cli) -> Result<CommandOutcome> {
    let quiet = cli.verbosity.is_quiet();

    match cli.command {
        Command::Archive(options) => archive(&options, quiet),
    }
}

/// Archive a list of URLs read from standard input.
fn archive(options: &ArchiveOptions, quiet: bool) -> Result<CommandOutcome> {
    let config = load_config(options.config.as_deref())?;
    let archiver = Archiver::new(config).context("cannot configure the archiver")?;
    let mut input_error = None;
    let urls = read_urls(std::io::stdin().lock(), &mut input_error);
    let progress = spinner("Archiving", Some("URLs"));
    let interrupted = interrupt_flag();
    let mut events = |event: CaptureEvent<'_>| {
        if matches!(event, CaptureEvent::Written { .. }) {
            progress.inc(1);
        }
        if interrupted.load(Ordering::Relaxed) {
            CaptureControl::Cancel
        } else {
            CaptureControl::Continue
        }
    };
    let result = archiver.archive_to_path_with_events(urls, &options.output, &mut events);
    progress.finish_and_clear();
    let summary =
        result.with_context(|| format!("cannot archive to {}", options.output.display()))?;
    if let Some(error) = &input_error {
        log::warn!("stopped reading input early: {error}");
    }
    if summary.cancelled {
        log::warn!("stopped archiving at an interrupt");
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
    /// A TOML or JSON configuration file, recognized by its extension; every key is optional and
    /// takes its default when absent (see default-config.toml).
    #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    config: Option<PathBuf>,

    /// The WARC file to write; an existing file is not overwritten.
    #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    output: PathBuf,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use archivindex_archiver::Config;
    use archivindex_cli_support::ConfigFormat;
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};

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
    fn archive_takes_an_optional_configuration_file() {
        let without = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--output",
            "capture.warc",
        ])
        .expect("valid options");
        let with = Cli::try_parse_from([
            "archivindex-archiver",
            "archive",
            "--config",
            "capture.toml",
            "--output",
            "capture.warc",
        ])
        .expect("valid options");

        let Command::Archive(without) = without.command;
        let Command::Archive(with) = with.command;

        assert_eq!(without.config, None);
        assert_eq!(with.config.as_deref(), Some(Path::new("capture.toml")));
    }

    #[test]
    fn the_default_configuration_file_is_the_default_configuration() {
        let config = ConfigFormat::Toml
            .parse::<Config>(include_str!("../default-config.toml"))
            .expect("a configuration");

        assert_eq!(config, Config::default());
    }

    #[test]
    fn a_configuration_file_sets_paths_bounds_and_flags() {
        let toml = ConfigFormat::Toml
            .parse::<Config>(
                "max-capture-time = \"unbounded\"\ngzip-warc = true\n\
                 [session]\nrevisit-index = \"revisits.sqlite3\"\n",
            )
            .expect("a configuration");
        let json = ConfigFormat::Json
            .parse::<Config>(r#"{"max-response-length": "unbounded", "concurrency": 4}"#)
            .expect("a configuration");

        assert_eq!(toml.max_capture_time, None);
        assert!(toml.gzip_warc);
        assert_eq!(
            toml.session.revisit_index.as_deref(),
            Some(Path::new("revisits.sqlite3"))
        );
        assert_eq!(json.max_response_length, None);
        assert_eq!(json.concurrency, 4);
    }

    #[test]
    fn a_configuration_file_names_the_software_and_operator() {
        let config = ConfigFormat::Toml
            .parse::<Config>(
                "[software]\nname = \"example-crawler\"\nversion = \"2.0\"\n\n\
                 [operator]\nname = \"Example Operator\"\nemail = \"operator@example.com\"\n",
            )
            .expect("a configuration");

        assert_eq!(config.software.name, "example-crawler");
        assert_eq!(config.software.version, "2.0");
        let operator = config.operator.expect("a configured operator");
        assert_eq!(operator.name, "Example Operator");
        assert_eq!(operator.email.as_deref(), Some("operator@example.com"));
    }

    #[test]
    fn a_configuration_file_cannot_hold_an_unknown_key() {
        assert!(ConfigFormat::Toml.parse::<Config>("gzip = true\n").is_err());
    }
}
