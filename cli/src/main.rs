mod merge;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        Command::Merge {
            first,
            second,
            output,
        } => {
            let summary = merge::merge(&first, &second, &output)?;
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

/// A count and its noun, pluralized by the count.
fn plural(count: usize, noun: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
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
