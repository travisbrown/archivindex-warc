mod archivindex_validator;
mod external;
mod install;
mod model;
mod warc_validator;
mod warcat_validator;

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use directories::ProjectDirs;

use crate::archivindex_validator::{Layer, run_archivindex};
use crate::external::{run_jwat_tools, run_warchaeology, run_warcio};
use crate::install::ToolResolver;
use crate::model::{Status, ValidationResult};
use crate::warc_validator::run_warc;
use crate::warcat_validator::run_warcat;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// WARC file to validate.
    #[arg(value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    file: PathBuf,

    /// Run only this validator; may be supplied more than once.
    #[arg(long, value_enum)]
    validator: Vec<ValidatorName>,

    /// Do not try to install missing external validators locally.
    #[arg(long)]
    no_install: bool,

    /// Directory used for locally installed validator tools.
    #[arg(long, value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    tools_dir: Option<PathBuf>,

    #[command(flatten)]
    verbosity: Verbosity,
}

/// Logging detail: errors only with `--quiet`, warnings by default, and informational, debug,
/// and trace diagnostics with each repetition of `-v`. Informational and above also shows
/// captured validator output and warcat-rs problem details.
#[derive(Debug, clap::Args)]
struct Verbosity {
    /// Log errors only.
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Log informational diagnostics; repeat for debug and trace.
    #[arg(short, action = clap::ArgAction::Count)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
enum ValidatorName {
    ArchivindexRaw,
    ArchivindexUntyped,
    ArchivindexRecord,
    Warc,
    #[value(name = "warcat-rs")]
    WarcatRs,
    #[value(alias = "warcheology")]
    Warchaeology,
    #[value(name = "jwat-tools")]
    JwatTools,
    Warcio,
}

/// Validators in execution order, with the local crate first.
const ALL_VALIDATORS: [ValidatorName; 8] = [
    ValidatorName::ArchivindexRaw,
    ValidatorName::ArchivindexUntyped,
    ValidatorName::ArchivindexRecord,
    ValidatorName::Warc,
    ValidatorName::WarcatRs,
    ValidatorName::Warchaeology,
    ValidatorName::JwatTools,
    ValidatorName::Warcio,
];

fn main() -> ExitCode {
    let cli = Cli::parse();
    cli.verbosity.init_logging();

    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            log::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    let file = cli
        .file
        .canonicalize()
        .with_context(|| format!("cannot open {}", cli.file.display()))?;
    if !file.is_file() {
        anyhow::bail!("{} is not a regular file", file.display());
    }

    let selected: HashSet<_> = if cli.validator.is_empty() {
        ALL_VALIDATORS.into_iter().collect()
    } else {
        cli.validator.into_iter().collect()
    };

    let tools_dir = cli.tools_dir.map(Ok).unwrap_or_else(default_tools_dir)?;
    let resolver = ToolResolver::new(tools_dir, !cli.no_install);
    let mut results = Vec::new();

    for validator in ALL_VALIDATORS {
        if !selected.contains(&validator) {
            continue;
        }

        log::info!("running the {validator:?} validator");
        let result = match validator {
            ValidatorName::ArchivindexRaw => run_archivindex(&file, Layer::Raw),
            ValidatorName::ArchivindexUntyped => run_archivindex(&file, Layer::Untyped),
            ValidatorName::ArchivindexRecord => run_archivindex(&file, Layer::Record),
            ValidatorName::Warc => run_warc(&file),
            ValidatorName::WarcatRs => run_warcat(&file),
            ValidatorName::Warchaeology => run_warchaeology(&file, &resolver),
            ValidatorName::JwatTools => run_jwat_tools(&file, &resolver),
            ValidatorName::Warcio => run_warcio(&file, &resolver),
        };
        results.push(result);
    }

    if !cli.verbosity.quiet {
        print_summary(&file, &results, cli.verbosity.verbose > 0);
    }
    Ok(results.iter().all(ValidationResult::is_success))
}

fn default_tools_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("org", "archivindex", "archivindex-warc-validator")
        .context("cannot determine the platform cache directory; use --tools-dir")?;
    Ok(dirs.cache_dir().join("tools"))
}

fn print_summary(file: &std::path::Path, results: &[ValidationResult], verbose: bool) {
    println!("{}", file.display());
    println!();
    println!("{:<20} {:<12} Summary", "Validator", "Status");
    println!("{:-<20} {:-<12} {:-<40}", "", "", "");

    for result in results {
        println!(
            "{:<20} {:<12} {}",
            result.validator,
            result.status.label(),
            result.summary
        );
    }

    let passed = results
        .iter()
        .filter(|result| result.status == Status::Passed)
        .count();
    let failed = results.len() - passed;
    println!();
    println!("Result: {passed} passed, {failed} failed or unavailable");

    if verbose {
        for result in results.iter().filter(|result| !result.details.is_empty()) {
            println!();
            println!("--- {} details ---", result.validator);
            println!("{}", result.details.trim_end());
        }
    }
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
    fn validator_names_match_commands() {
        assert_eq!(
            ValidatorName::WarcatRs
                .to_possible_value()
                .unwrap()
                .get_name(),
            "warcat-rs"
        );
        assert_eq!(
            ValidatorName::JwatTools
                .to_possible_value()
                .unwrap()
                .get_name(),
            "jwat-tools"
        );
    }

    #[test]
    fn accepts_the_common_warcheology_spelling() {
        let cli = Cli::try_parse_from(["warc-validator", "--validator", "warcheology", "x.warc"])
            .unwrap();
        assert_eq!(cli.validator, vec![ValidatorName::Warchaeology]);
    }

    #[test]
    fn verbosity_selects_the_documented_levels() {
        let level = |flags: &[&str]| {
            let mut args = vec!["warc-validator", "x.warc"];
            args.extend_from_slice(flags);

            Cli::try_parse_from(args).unwrap().verbosity.level()
        };

        assert_eq!(level(&[]), log::LevelFilter::Warn);
        assert_eq!(level(&["--quiet"]), log::LevelFilter::Error);
        assert_eq!(level(&["-v"]), log::LevelFilter::Info);
        assert_eq!(level(&["-vv"]), log::LevelFilter::Debug);
        assert_eq!(level(&["-vvv"]), log::LevelFilter::Trace);
        assert_eq!(level(&["-vvvv"]), log::LevelFilter::Trace);
        assert!(Cli::try_parse_from(["warc-validator", "x.warc", "-q", "-v"]).is_err());
    }
}
