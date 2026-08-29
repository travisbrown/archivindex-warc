//! Command-line tools for working with WARC files.

mod export;
mod graph;
mod index;

use std::fmt::Display;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use archivindex_cli_support::{CommandOutcome, Verbosity, exit_code, plural};
use archivindex_warc::io::write::{DEFAULT_GZIP_COMPRESSION_LEVEL, MAX_GZIP_COMPRESSION_LEVEL};
use archivindex_warc::value::{Text, TextError};
use archivindex_warc_ops::lint::{Finding, Linter};
use archivindex_warc_ops::merge::WarcinfoDifference;
use archivindex_warc_ops::rewrite::WarcinfoValues;
use archivindex_warc_revisit_index::{Index, LoadSummary};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "archivindex-warc", version, about)]
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
        /// The WARC file to canonicalize, or - for standard input; a .gz extension, or the gzip
        /// magic number on standard input, selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Compress a WARC file record by record, one gzip member per record.
    Compress {
        /// The WARC file to compress, or - for standard input; a .gz extension, or the gzip magic
        /// number on standard input, selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The gzip compression level, from 0 (none) through 9 (best).
        #[arg(
            long,
            value_name = "LEVEL",
            default_value_t = DEFAULT_GZIP_COMPRESSION_LEVEL,
            value_parser = clap::value_parser!(u32).range(..=i64::from(MAX_GZIP_COMPRESSION_LEVEL)),
        )]
        level: u32,

        /// The file to write, which must have a .gz extension.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Rewrite payload digests over HTTP message bodies as framed, transfer-coding included.
    ///
    /// WARC 1.1 makes the payload of an HTTP message its entity-body, which is the message body
    /// with any transfer-coding removed. Several other tools digest the body as it was framed,
    /// chunk sizes and trailers included. Each request or response record capturing an HTTP
    /// exchange that declares WARC-Payload-Digest has it recomputed that way under the algorithm
    /// and encoding it declares, so that those tools accept the output. Every other record is
    /// copied as read.
    DigestFramedPayloads {
        /// The WARC file to read, or - for standard input; a .gz extension, or the gzip magic
        /// number on standard input, selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Write the records of a WARC file to standard output in a chosen format.
    Export {
        /// The WARC file to export, or - for standard input; a .gz extension, or the gzip magic
        /// number on standard input, selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        #[command(subcommand)]
        format: ExportFormat,
    },

    /// Draw the records and their relationships as an SVG graph.
    Graph {
        /// The WARC file to graph, or - for standard input; a .gz extension, or the gzip magic
        /// number on standard input, selects gzip decompression.
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
        /// The WARC file to lint, or - for standard input; a .gz extension, or the gzip magic
        /// number on standard input, selects gzip decompression, whose member framing is checked
        /// as well.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// How to write the findings.
        #[arg(long, value_name = "FORMAT", default_value_t = LintFormat::Text)]
        format: LintFormat,
    },

    /// Load the records of WARC files into a revisit index.
    ///
    /// Each file is indexed in one transaction, so a file that cannot be read leaves the index as
    /// it was before that file. A record whose HTTP head or WARC payload is malformed is skipped
    /// with a warning.
    LoadRevisitIndex {
        /// The WARC file to index, or - for standard input, or a directory whose .warc and
        /// .warc.gz files are indexed in file-name order.
        #[arg(short, long, value_name = "PATH", value_hint = clap::ValueHint::AnyPath)]
        input: PathBuf,

        /// The SQLite revisit index to load into, created when it does not exist.
        #[arg(long = "db", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        database: PathBuf,
    },

    /// Merge the records of two WARC files, dropping duplicate warcinfo records.
    Merge {
        /// The WARC file whose records come first; merge reads its inputs twice, so neither can be
        /// standard input.
        #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        first: PathBuf,

        /// The WARC file whose records follow.
        #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        second: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,

        /// A warcinfo body field allowed to vary; may be repeated and matches case-insensitively.
        #[arg(long, value_name = "NAME")]
        ignore_field: Vec<String>,
    },

    /// Give each revisit record the identified payload type of the response it refers to.
    ///
    /// A revisit record lacking WARC-Identified-Payload-Type receives the value of the response
    /// record its WARC-Refers-To names, when that response is in the file and declares one. Every
    /// other record is copied as read.
    PropagateIdentifiedPayloadType {
        /// The WARC file to read, which is read twice, so it cannot be standard input. A .gz
        /// extension selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Remove each revisit record whose target URI is that of the response it refers to.
    ///
    /// A revisit is removed when its WARC-Target-URI equals that of the response record its
    /// WARC-Refers-To names, when that response is in the file. The rest of its capture is
    /// removed with it: every record WARC-Concurrent-To links to the revisit, in either direction
    /// and through any number of records. Every other record is copied as read.
    RemoveSameTargetRevisits {
        /// The WARC file to read, which is read twice, so it cannot be standard input. A .gz
        /// extension selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,

        /// The file to write; a .gz extension selects record-at-a-time gzip compression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,
    },

    /// Rewrite part of a WARC file, copying every other record as read.
    Rewrite {
        /// The WARC file to rewrite, or - for standard input; a .gz extension, or the gzip magic
        /// number on standard input, selects gzip decompression.
        #[arg(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
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
            canonicalize(&input, &output, quiet)?;
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
        Command::LoadRevisitIndex { input, database } => {
            load_revisit_index(&database, &input, quiet)?;
        }
        Command::Merge {
            first,
            second,
            output,
            ignore_field,
        } => merge(&first, &second, &output, &ignore_field, quiet)?,
        Command::DigestFramedPayloads { input, output } => {
            digest_framed_payloads(&input, &output, quiet)?;
        }
        Command::PropagateIdentifiedPayloadType { input, output } => {
            propagate_identified_payload_type(&input, &output, quiet)?;
        }
        Command::RemoveSameTargetRevisits { input, output } => {
            remove_same_target_revisits(&input, &output, quiet)?;
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

/// Merge `first` and `second`, allowing selected warcinfo body fields to vary.
fn merge(
    first: &Path,
    second: &Path,
    output: &Path,
    ignored_fields: &[String],
    quiet: bool,
) -> Result<()> {
    let summary = archivindex_warc_ops::merge::merge_ignoring_warcinfo_fields(
        first,
        second,
        output,
        ignored_fields,
    )?;
    if !quiet {
        println!(
            "Wrote {} to {}, merging {}.",
            plural(summary.records, "record"),
            output.display(),
            plural(summary.merged, "duplicate warcinfo record"),
        );
        if summary.distinct_warcinfo > 1 {
            println!(
                "Kept {} separate because {}.",
                plural(summary.distinct_warcinfo, "warcinfo record"),
                describe_warcinfo_differences(&summary.warcinfo_differences),
            );
        }
    }

    Ok(())
}

/// Describe every way the merge's distinct warcinfo records differ.
fn describe_warcinfo_differences(differences: &[WarcinfoDifference]) -> String {
    let reasons: Vec<_> = differences
        .iter()
        .map(|difference| match difference {
            WarcinfoDifference::Version => "the WARC versions differ",
            WarcinfoDifference::HeaderFields => "the non-incidental header fields differ",
            WarcinfoDifference::Body => "the bodies differ after ignoring allowed fields",
        })
        .collect();

    match reasons.as_slice() {
        [] => "they do not match".to_owned(),
        [reason] => (*reason).to_owned(),
        [first, second] => format!("{first} and {second}"),
        [first, middle @ .., last] => format!("{first}, {}, and {last}", middle.join(", ")),
    }
}

/// Canonicalize the record headers of `input`, writing the records to `output`.
fn canonicalize(input: &Path, output: &Path, quiet: bool) -> Result<()> {
    let summary = archivindex_warc_ops::canonicalize::canonicalize(input, output)?;

    if !quiet {
        println!(
            "Wrote {} with canonical headers to {}.",
            plural(summary.records, "record"),
            output.display(),
        );
    }

    Ok(())
}

/// Rewrite the payload digests of `input` over HTTP message bodies as framed, writing the records
/// to `output`.
fn digest_framed_payloads(input: &Path, output: &Path, quiet: bool) -> Result<()> {
    let summary = archivindex_warc_ops::digest::framed_payloads(input, output)?;

    if !quiet {
        println!(
            "Wrote {} to {}, rewriting {}.",
            plural(summary.records, "record"),
            output.display(),
            plural(summary.rewritten, "payload digest"),
        );
    }

    Ok(())
}

/// Propagate identified payload types from the responses of `input` to its revisits, writing the
/// records to `output`.
fn propagate_identified_payload_type(input: &Path, output: &Path, quiet: bool) -> Result<()> {
    let summary = archivindex_warc_ops::propagate::identified_payload_type(input, output)?;

    if !quiet {
        println!(
            "Wrote {} to {}, giving {} an identified payload type.",
            plural(summary.records, "record"),
            output.display(),
            plural(summary.propagated, "revisit record"),
        );
    }

    Ok(())
}

/// Remove the revisits of `input` whose target URI is their original's, with the rest of their
/// captures, writing the other records to `output`.
fn remove_same_target_revisits(input: &Path, output: &Path, quiet: bool) -> Result<()> {
    let summary = archivindex_warc_ops::remove::same_target_revisits(input, output)?;

    if !quiet {
        println!(
            "Wrote {} to {}, removing {} and {} captured with them.",
            plural(summary.records, "record"),
            output.display(),
            plural(summary.revisits, "revisit record"),
            plural(summary.captured, "record"),
        );
    }

    Ok(())
}

/// Index the WARC file at `input`, or every WARC file in the directory there, into `database`.
fn load_revisit_index(database: &Path, input: &Path, quiet: bool) -> Result<()> {
    let files = index::warc_files(input)?;
    let mut index = Index::open(database)
        .with_context(|| format!("cannot open revisit index {}", database.display()))?;
    let mut total = LoadSummary::default();

    for file in &files {
        let summary = index::load(&mut index, file)?;
        if !quiet {
            println!(
                "Indexed {} of {}: {}.",
                plural(summary.records, "record"),
                file.display(),
                index::describe(&summary)
            );
        }
        total += summary;
    }
    if !quiet && files.len() != 1 {
        println!(
            "Indexed {} of {} into {}: {}.",
            plural(total.records, "record"),
            plural(files.len(), "WARC file"),
            database.display(),
            index::describe(&total)
        );
    }

    Ok(())
}

/// Compress `input` record by record into the gzip WARC at `output`.
fn compress(input: &Path, level: u32, output: &Path, quiet: bool) -> Result<()> {
    if !archivindex_warc_ops::file::is_gzip(output) {
        bail!(
            "a compressed output must be named with a .gz extension: {}",
            output.display()
        );
    }

    let summary = archivindex_warc_ops::compress::compress_path(input, level, output)?;

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
    let mut linter = Linter::new(archivindex_warc_ops::file::open(input)?);
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
            "archivindex-warc",
            "graph",
            "-i",
            "a.warc.gz",
            "--output",
            "a.svg",
        ])
        .unwrap();
        let without_output =
            Cli::try_parse_from(["archivindex-warc", "graph", "--input", "a.warc"]).unwrap();

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
            "archivindex-warc",
            "canonicalize",
            "--input",
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
            "archivindex-warc",
            "compress",
            "-i",
            "input.warc",
            "-o",
            "output.warc.gz",
        ])
        .unwrap();
        let chosen = Cli::try_parse_from([
            "archivindex-warc",
            "compress",
            "-i",
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
                "archivindex-warc",
                "compress",
                "-i",
                "input.warc",
                "--level",
                "10",
                "-o",
                "output.warc.gz",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "archivindex-warc",
                "compress",
                "-i",
                "input.warc",
                "-l",
                "0",
                "-o",
                "output.warc.gz",
            ])
            .is_err()
        );
    }

    #[test]
    fn export_takes_an_input_and_a_format() {
        let csv = Cli::try_parse_from(["archivindex-warc", "export", "-i", "input.warc.gz", "csv"])
            .unwrap();
        let json = Cli::try_parse_from(["archivindex-warc", "export", "-i", "input.warc", "json"])
            .unwrap();

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
        assert!(Cli::try_parse_from(["archivindex-warc", "export", "-i", "input.warc"]).is_err());
    }

    #[test]
    fn lint_accepts_an_input_and_defaults_to_text() {
        let cli = Cli::try_parse_from(["archivindex-warc", "lint", "-i", "input.warc.gz"]).unwrap();
        let json = Cli::try_parse_from([
            "archivindex-warc",
            "lint",
            "-i",
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
    fn merge_takes_two_inputs_and_an_output() {
        let cli = Cli::try_parse_from([
            "archivindex-warc",
            "merge",
            "--first",
            "a.warc.gz",
            "--second",
            "b.warc.gz",
            "-o",
            "merged.warc.gz",
            "--ignore-field",
            "http-header-user-agent",
            "--ignore-field",
            "operator",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Merge { first, second, output, ignore_field }
                if first.as_path() == Path::new("a.warc.gz")
                    && second.as_path() == Path::new("b.warc.gz")
                    && output.as_path() == Path::new("merged.warc.gz")
                    && ignore_field == ["http-header-user-agent", "operator"]
        ));
        assert!(
            Cli::try_parse_from([
                "archivindex-warc",
                "merge",
                "a.warc",
                "b.warc",
                "-o",
                "c.warc"
            ])
            .is_err()
        );
    }

    #[test]
    fn describes_why_warcinfo_records_remain_separate() {
        assert_eq!(
            describe_warcinfo_differences(&[WarcinfoDifference::Body]),
            "the bodies differ after ignoring allowed fields"
        );
    }

    #[test]
    fn digest_framed_payloads_takes_an_input_and_output() {
        let cli = Cli::try_parse_from([
            "archivindex-warc",
            "digest-framed-payloads",
            "-i",
            "input.warc.gz",
            "-o",
            "output.warc",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::DigestFramedPayloads { input, output }
                if input.as_path() == Path::new("input.warc.gz")
                    && output.as_path() == Path::new("output.warc")
        ));
    }

    #[test]
    fn propagate_identified_payload_type_takes_an_input_and_output() {
        let cli = Cli::try_parse_from([
            "archivindex-warc",
            "propagate-identified-payload-type",
            "-i",
            "input.warc.gz",
            "-o",
            "output.warc",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::PropagateIdentifiedPayloadType { input, output }
                if input.as_path() == Path::new("input.warc.gz")
                    && output.as_path() == Path::new("output.warc")
        ));
    }

    #[test]
    fn load_revisit_index_takes_an_input_and_a_database() {
        let cli = Cli::try_parse_from([
            "archivindex-warc",
            "load-revisit-index",
            "-i",
            "captures",
            "--db",
            "revisits.db",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::LoadRevisitIndex { input, database }
                if input.as_path() == Path::new("captures")
                    && database.as_path() == Path::new("revisits.db")
        ));
        assert!(
            Cli::try_parse_from(["archivindex-warc", "load-revisit-index", "-i", "captures"])
                .is_err()
        );
    }

    #[test]
    fn remove_same_target_revisits_takes_an_input_and_output() {
        let cli = Cli::try_parse_from([
            "archivindex-warc",
            "remove-same-target-revisits",
            "-i",
            "input.warc.gz",
            "-o",
            "output.warc",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::RemoveSameTargetRevisits { input, output }
                if input.as_path() == Path::new("input.warc.gz")
                    && output.as_path() == Path::new("output.warc")
        ));
    }

    #[test]
    fn rewrite_warcinfo_needs_at_least_one_value() {
        let parse = |values: &[&str]| {
            let mut args = vec![
                "archivindex-warc",
                "rewrite",
                "-i",
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
            let arguments = ["archivindex-warc", "lint", "-i", path.to_str().unwrap()];

            run(Cli::try_parse_from(arguments).unwrap())
        };

        assert_eq!(lint(&input).unwrap(), CommandOutcome::ReportedProblems);
        assert!(lint(&directory.path().join("missing.warc")).is_err());
    }
}
