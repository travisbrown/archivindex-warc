mod export;
mod graph;

use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use archivindex_warc::io::write::{DEFAULT_GZIP_COMPRESSION_LEVEL, MAX_GZIP_COMPRESSION_LEVEL};
use archivindex_warc_ops::lint::Linter;
use clap::{Parser, Subcommand};
use flate2::bufread::MultiGzDecoder;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    verbosity: Verbosity,

    #[command(subcommand)]
    command: Command,
}

/// Logging detail: errors only with `--quiet`, warnings by default, and informational, debug,
/// and trace diagnostics with each repetition of `-v`.
#[derive(Debug, clap::Args)]
struct Verbosity {
    /// Log errors only.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    /// Log informational diagnostics; repeat for debug and trace.
    #[arg(short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl Verbosity {
    /// The most detailed level to log.
    fn level(&self) -> log::LevelFilter {
        if self.quiet {
            log::LevelFilter::Error
        } else {
            match self.verbose {
                0 => log::LevelFilter::Warn,
                1 => log::LevelFilter::Info,
                2 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            }
        }
    }

    /// Start logging to standard error at the selected level.
    fn init_logging(&self) {
        let config = simplelog::ConfigBuilder::new()
            .set_time_level(log::LevelFilter::Off)
            .build();

        simplelog::TermLogger::init(
            self.level(),
            config,
            simplelog::TerminalMode::Stderr,
            simplelog::ColorChoice::Auto,
        )
        .expect("invariant violation: the logger is initialized once");
    }
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
    Lint {
        /// The WARC file to lint; a .gz extension selects gzip decompression.
        #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,
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

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let quiet = cli.verbosity.quiet;

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
        } => {
            if input == output {
                bail!(
                    "input and output must be different files: {}",
                    input.display()
                );
            }
            let reader = BufReader::new(
                File::open(&input).with_context(|| format!("cannot open {}", input.display()))?,
            );
            let writer = BufWriter::new(
                File::create(&output)
                    .with_context(|| format!("cannot create {}", output.display()))?,
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
        }
        Command::Export { input, format } => {
            let reader = open_input(&input)?;
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
        Command::Lint { input } => {
            let mut linter = Linter::new(open_input(&input)?);
            let mut problems = 0;
            while let Some(item) = linter.next() {
                match item {
                    Ok(Ok(_)) => continue,
                    Ok(Err(finding)) => println!("{finding}"),
                    Err(error) => println!(
                        "record {}: {:#}",
                        linter.position() - 1,
                        anyhow::Error::from(error)
                    ),
                }
                problems += 1;
            }
            if problems > 0 {
                bail!(
                    "found {} in {}",
                    plural(problems, "problem"),
                    input.display()
                );
            }
            if !quiet {
                println!(
                    "Found no problems in {} of {}.",
                    plural(linter.position(), "record"),
                    input.display()
                );
            }
        }
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
    }

    Ok(())
}

/// Open a WARC file for reading, decompressing a path ending in `.gz`.
fn open_input(path: &Path) -> Result<Box<dyn BufRead>> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let file = BufReader::new(file);
    let reader: Box<dyn BufRead> = if is_gzip(path) {
        Box::new(BufReader::new(MultiGzDecoder::new(file)))
    } else {
        Box::new(file)
    };

    Ok(reader)
}

/// Whether a path names a gzip-compressed WARC file.
fn is_gzip(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}

/// A count and its noun, pluralized by the count.
fn plural<N: Display + From<u8> + PartialEq>(count: N, noun: &str) -> String {
    let suffix = if count == N::from(1) { "" } else { "s" };
    format!("{count} {noun}{suffix}")
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn verbosity_selects_the_documented_levels() {
        let level = |flags: &[&str]| {
            let mut args = vec![
                "archivindex-warc-cli",
                "merge",
                "a.warc",
                "b.warc",
                "-o",
                "c",
            ];
            args.extend_from_slice(flags);

            Cli::try_parse_from(args).unwrap().verbosity.level()
        };

        assert_eq!(level(&[]), log::LevelFilter::Warn);
        assert_eq!(level(&["--quiet"]), log::LevelFilter::Error);
        assert_eq!(level(&["-v"]), log::LevelFilter::Info);
        assert_eq!(level(&["-vv"]), log::LevelFilter::Debug);
        assert_eq!(level(&["-vvv"]), log::LevelFilter::Trace);
        assert_eq!(level(&["-vvvv"]), log::LevelFilter::Trace);
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
    fn lint_accepts_an_input() {
        let cli = Cli::try_parse_from(["archivindex-warc-cli", "lint", "input.warc.gz"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Lint { input } if input.as_path() == Path::new("input.warc.gz")
        ));
    }

    #[test]
    fn quiet_and_verbose_conflict() {
        assert!(
            Cli::try_parse_from([
                "archivindex-warc-cli",
                "merge",
                "a.warc",
                "b.warc",
                "-o",
                "c",
                "-q",
                "-v"
            ])
            .is_err()
        );
    }
}
