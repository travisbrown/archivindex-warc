//! Command-line tools for working with WARC files.

mod export;
mod graph;

use std::fmt::Display;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use archivindex_cli_support::{CommandOutcome, Verbosity, exit_code, plural};
use archivindex_warc::io::write::{DEFAULT_GZIP_COMPRESSION_LEVEL, MAX_GZIP_COMPRESSION_LEVEL};
use archivindex_warc::value::{Text, TextError};
use archivindex_warc_ops::lint::{Finding, Linter};
use archivindex_warc_ops::rewrite::WarcinfoValues;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    verbosity: Verbosity,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Canonicalize standard header spelling and order across a WARC file.
    Canonicalize {
        /// The WARC file to canonicalize; a .gz extension selects gzip decompression.
        #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Compress a WARC file record by record, one gzip member per record.
    Compress {
        /// The uncompressed WARC file to compress.
        #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The gzip compression level, from 0 (none) through 9 (best).
        #[arg(
            short,
            long,
            value_name = "LEVEL",
            default_value_t = DEFAULT_GZIP_COMPRESSION_LEVEL,
            value_parser = clap::value_parser!(u32).range(..=i64::from(MAX_GZIP_COMPRESSION_LEVEL)),
        )]
        level: u32,

        /// The file to write.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Write the records of a WARC file to standard output in a chosen format.
    Export {
        /// The WARC file to export; a .gz extension selects gzip decompression.
        #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        #[command(subcommand)]
        format: ExportFormat,
    },

    /// Draw the records and their relationships as an SVG graph.
    Graph {
        /// The WARC file to graph; a .gz extension selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The SVG file to write; without this option, open the graph in a window.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Check a WARC file against rules stricter than the standard, printing each finding.
    ///
    /// Exits 1 when the file has findings, and 2, as every command does, when it cannot be read.
    Lint {
        /// The WARC file to lint; a .gz extension selects gzip decompression.
        #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// How to write the findings.
        #[arg(long, value_name = "FORMAT", default_value_t = LintFormat::Text)]
        format: LintFormat,
    },

    /// Merge the records of two WARC files, dropping duplicate warcinfo records.
    Merge {
        /// The WARC file whose records come first.
        #[arg(value_name = "FIRST", value_hint = clap::ValueHint::FilePath)]
        first: PathBuf,

        /// The WARC file whose records follow.
        #[arg(value_name = "SECOND", value_hint = clap::ValueHint::FilePath)]
        second: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Rewrite part of a WARC file, copying every other record as read.
    Rewrite {
        /// The WARC file to rewrite; a .gz extension selects gzip decompression.
        #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,

        #[command(subcommand)]
        target: RewriteTarget,
    },
}

/// What the `rewrite` command rewrites.
#[derive(Debug, Subcommand)]
enum RewriteTarget {
    /// Set fields of every warcinfo record, keeping what is not given here.
    ///
    /// The software field is written as `NAME/VERSION` and the operator field as `NAME <EMAIL>`.
    /// A name given alone keeps the version or email address the record has; a version or
    /// email address given alone replaces the one the record has, and fails when there is
    /// none.
    #[command(group = clap::ArgGroup::new("values").required(true).multiple(true))]
    Warcinfo {
        /// The WARC-Filename header field: the name of the file holding the record.
        #[arg(long, value_name = "NAME", group = "values", value_parser = parse_text)]
        filename: Option<Text>,

        /// The software name.
        #[arg(long, value_name = "NAME", group = "values")]
        software_name: Option<String>,

        /// The software version.
        #[arg(long, value_name = "VERSION", group = "values")]
        software_version: Option<String>,

        /// The operator's name.
        #[arg(long, value_name = "NAME", group = "values")]
        operator_name: Option<String>,

        /// The operator's email address.
        #[arg(long, value_name = "EMAIL", group = "values")]
        operator_email: Option<String>,

        /// The collection the file belongs to, written to the isPartOf field.
        #[arg(long, value_name = "ID", group = "values")]
        collection_id: Option<String>,
    },
}

/// The formats the `lint` command writes findings in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum LintFormat {
    /// One line of prose per finding.
    Text,

    /// One JSON object per finding, and per record that could not be read.
    Json,
}

impl Display for LintFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => formatter.write_str("text"),
            Self::Json => formatter.write_str("json"),
        }
    }
}

/// A record the linter could not read, as the JSON format writes it.
#[derive(serde::Serialize)]
struct Unreadable {
    /// The record's zero-based position in the file.
    index: usize,
    /// Why it could not be read.
    error: String,
}

/// The formats the `export` command writes.
#[derive(Debug, Subcommand)]
enum ExportFormat {
    /// One CSV row per record: its type, date, record identifier, and target URI.
    Csv,

    /// One JSON line per record whose identified payload type is JSON.
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    cli.verbosity.init_logging();

    exit_code(run(cli))
}

fn run(cli: Cli) -> Result<CommandOutcome> {
    let quiet = cli.verbosity.is_quiet();

    match cli.command {
        Command::Canonicalize { input, output } => {
            let summary = archivindex_warc_ops::canonicalize::canonicalize(&input, &output)?;
            if !quiet {
                println!(
                    "Wrote {} with canonical headers to {}.",
                    plural(summary.records, "record"),
                    output.display(),
                );
            }
        }
        Command::Compress {
            input,
            level,
            output,
        } => compress(&input, level, &output, quiet)?,
        Command::Export { input, format } => {
            let reader = archivindex_warc_ops::file::read(&input)?;
            let stdout = std::io::stdout().lock();
            let records = match format {
                ExportFormat::Csv => export::csv::export(reader, stdout),
                ExportFormat::Json => export::json::export(reader, BufWriter::new(stdout)),
            }
            .with_context(|| format!("cannot export {}", input.display()))?;
            log::info!("exported {}", plural(records, "record"));
        }
        Command::Graph { input, output } => {
            let summary = graph::graph(&input, output.as_deref())?;
            if !quiet {
                let description = format!(
                    "a graph of {}, including {}",
                    plural(summary.records, "record"),
                    plural(summary.references, "reference")
                );
                if let Some(output) = output {
                    println!("Wrote {description} to {}.", output.display());
                } else {
                    println!("Opened {description}.");
                }
            }
        }
        Command::Lint { input, format } => return lint(&input, format, quiet),
        Command::Merge {
            first,
            second,
            output,
        } => {
            let summary = archivindex_warc_ops::merge::merge(&first, &second, &output)?;
            if !quiet {
                println!(
                    "Wrote {} to {}, merging {}.",
                    plural(summary.records, "record"),
                    output.display(),
                    plural(summary.merged, "duplicate warcinfo record"),
                );
            }
        }
        Command::Rewrite {
            input,
            output,
            target:
                RewriteTarget::Warcinfo {
                    filename,
                    software_name,
                    software_version,
                    operator_name,
                    operator_email,
                    collection_id,
                },
        } => {
            let values = WarcinfoValues {
                filename,
                software_name,
                software_version,
                operator_name,
                operator_email,
                collection_id,
            };
            let summary = archivindex_warc_ops::rewrite::warcinfo(&input, &output, &values)?;
            if !quiet {
                println!(
                    "Wrote {} to {}, rewriting {}.",
                    plural(summary.records, "record"),
                    output.display(),
                    plural(summary.rewritten, "warcinfo record"),
                );
            }
        }
    }

    Ok(CommandOutcome::Success)
}

/// Compress `input` record by record into the gzip WARC at `output`.
fn compress(input: &Path, level: u32, output: &Path, quiet: bool) -> Result<()> {
    if input == output {
        bail!(
            "input and output must be different files: {}",
            input.display()
        );
    }

    let reader = BufReader::new(
        File::open(input).with_context(|| format!("cannot open {}", input.display()))?,
    );
    let writer = BufWriter::new(
        File::create(output).with_context(|| format!("cannot create {}", output.display()))?,
    );
    let summary = archivindex_warc_ops::compress::compress(reader, level, writer)
        .with_context(|| format!("cannot compress {}", input.display()))?;

    if !quiet {
        println!(
            "Wrote {} ({} compressed) to {}.",
            plural(summary.records, "record"),
            plural(summary.bytes, "byte"),
            output.display(),
        );
    }

    Ok(())
}

/// Report every finding in `input`, returning the outcome the findings call for.
fn lint(input: &Path, format: LintFormat, quiet: bool) -> Result<CommandOutcome> {
    let mut linter = Linter::new(archivindex_warc_ops::file::read(input)?);
    let mut problems = 0;

    while let Some(item) = linter.next() {
        match item {
            Ok(Ok(_)) => continue,
            Ok(Err(finding)) => report_finding(format, &finding)?,
            Err(error) => {
                report_unreadable(format, linter.position() - 1, &anyhow::Error::from(error))?;
            }
        }
        problems += 1;
    }

    if problems > 0 {
        log::warn!(
            "found {} in {}",
            plural(problems, "problem"),
            input.display()
        );

        return Ok(CommandOutcome::ReportedProblems);
    }
    if !quiet && format == LintFormat::Text {
        println!(
            "Found no problems in {} of {}.",
            plural(linter.position(), "record"),
            input.display()
        );
    }

    Ok(CommandOutcome::Success)
}

/// Write one finding in the chosen format.
fn report_finding(format: LintFormat, finding: &Finding) -> Result<()> {
    match format {
        LintFormat::Text => println!("{finding}"),
        LintFormat::Json => println!("{}", as_json(finding)?),
    }

    Ok(())
}

/// Write one unreadable record in the chosen format.
fn report_unreadable(format: LintFormat, index: usize, error: &anyhow::Error) -> Result<()> {
    match format {
        LintFormat::Text => println!("record {index}: {error:#}"),
        LintFormat::Json => println!(
            "{}",
            as_json(&Unreadable {
                index,
                error: format!("{error:#}"),
            })?
        ),
    }

    Ok(())
}

/// One line of JSON.
fn as_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("cannot serialize JSON output")
}

/// Read a `TEXT` command-line value, such as a `WARC-Filename`.
fn parse_text(value: &str) -> Result<Text, TextError> {
    Text::parse(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::CommandFactory;

    use super::*;

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn graph_accepts_an_optional_output() {
        let with_output = Cli::try_parse_from([
            "archivindex-warc-cli",
            "graph",
            "--input",
            "a.warc.gz",
            "--output",
            "a.svg",
        ])
        .unwrap();
        let without_output =
            Cli::try_parse_from(["archivindex-warc-cli", "graph", "-i", "a.warc"]).unwrap();

        assert!(matches!(
            with_output.command,
            Command::Graph {
                input,
                output: Some(output)
            } if input.as_path() == std::path::Path::new("a.warc.gz")
                && output.as_path() == std::path::Path::new("a.svg")
        ));
        assert!(matches!(
            without_output.command,
            Command::Graph { output: None, .. }
        ));
    }

    #[test]
    fn canonicalize_accepts_an_input_and_output() {
        let cli = Cli::try_parse_from([
            "archivindex-warc-cli",
            "canonicalize",
            "input.warc.gz",
            "--output",
            "output.warc",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Canonicalize { input, output }
                if input.as_path() == std::path::Path::new("input.warc.gz")
                    && output.as_path() == std::path::Path::new("output.warc")
        ));
    }

    #[test]
    fn compress_defaults_its_level_and_bounds_it() {
        let default = Cli::try_parse_from([
            "archivindex-warc-cli",
            "compress",
            "input.warc",
            "-o",
            "output.warc.gz",
        ])
        .unwrap();
        let chosen = Cli::try_parse_from([
            "archivindex-warc-cli",
            "compress",
            "input.warc",
            "--level",
            "0",
            "-o",
            "output.warc.gz",
        ])
        .unwrap();

        assert!(matches!(
            default.command,
            Command::Compress { level: 6, .. }
        ));
        assert!(matches!(chosen.command, Command::Compress { level: 0, .. }));
        assert!(
            Cli::try_parse_from([
                "archivindex-warc-cli",
                "compress",
                "input.warc",
                "-l",
                "10",
                "-o",
                "output.warc.gz",
            ])
            .is_err()
        );
    }

    #[test]
    fn export_takes_an_input_and_a_format() {
        let csv = Cli::try_parse_from(["archivindex-warc-cli", "export", "input.warc.gz", "csv"])
            .unwrap();
        let json =
            Cli::try_parse_from(["archivindex-warc-cli", "export", "input.warc", "json"]).unwrap();

        assert!(matches!(
            csv.command,
            Command::Export { input, format: ExportFormat::Csv }
                if input.as_path() == Path::new("input.warc.gz")
        ));
        assert!(matches!(
            json.command,
            Command::Export {
                format: ExportFormat::Json,
                ..
            }
        ));
        assert!(Cli::try_parse_from(["archivindex-warc-cli", "export", "input.warc"]).is_err());
    }

    #[test]
    fn lint_accepts_an_input_and_defaults_to_text() {
        let cli = Cli::try_parse_from(["archivindex-warc-cli", "lint", "input.warc.gz"]).unwrap();
        let json = Cli::try_parse_from([
            "archivindex-warc-cli",
            "lint",
            "input.warc",
            "--format",
            "json",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Lint {
                input,
                format: LintFormat::Text
            } if input.as_path() == Path::new("input.warc.gz")
        ));
        assert!(matches!(
            json.command,
            Command::Lint {
                format: LintFormat::Json,
                ..
            }
        ));
    }

    #[test]
    fn rewrite_warcinfo_needs_at_least_one_value() {
        let parse = |values: &[&str]| {
            let mut args = vec![
                "archivindex-warc-cli",
                "rewrite",
                "input.warc",
                "-o",
                "output.warc.gz",
                "warcinfo",
            ];
            args.extend_from_slice(values);

            Cli::try_parse_from(args)
        };

        assert!(matches!(
            parse(&[
                "--software-version",
                "1.2",
                "--operator-email",
                "operator@example.com",
                "--filename",
                "crawl.warc.gz",
            ])
            .unwrap()
            .command,
            Command::Rewrite {
                input,
                output,
                target: RewriteTarget::Warcinfo {
                    filename: Some(filename),
                    software_name: None,
                    software_version: Some(version),
                    operator_name: None,
                    operator_email: Some(email),
                    collection_id: None,
                },
            } if input.as_path() == Path::new("input.warc")
                && output.as_path() == Path::new("output.warc.gz")
                && version == "1.2"
                && email == "operator@example.com"
                && filename.to_str() == Some("crawl.warc.gz")
        ));
        assert!(parse(&["--collection-id", "crawl-2026"]).is_ok());
        assert!(parse(&[]).is_err());
        assert!(parse(&["--filename", "two\nlines"]).is_err());
    }

    /// A lint run that has findings is told apart from one that could not read the file.
    #[test]
    fn lint_reserves_one_for_findings() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.warc");
        std::fs::write(
            &input,
            "WARC/1.1\r\nWARC-Type: resource\r\nWARC-Record-ID: <urn:uuid:1>\r\n\
             WARC-Date: 2024-01-02T03:04:05Z\r\nWARC-Target-URI: https://example.com/\r\n\
             Content-Length: 0\r\n\r\n\r\n\r\n",
        )
        .unwrap();
        let lint = |path: &Path| {
            let arguments = ["archivindex-warc-cli", "lint", path.to_str().unwrap()];

            run(Cli::try_parse_from(arguments).unwrap())
        };

        assert_eq!(lint(&input).unwrap(), CommandOutcome::ReportedProblems);
        assert!(lint(&directory.path().join("missing.warc")).is_err());
    }
}
