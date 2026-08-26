use std::path::Path;
use std::process::Output;

use archivindex_cli_support::plural;
use tempfile::tempdir;

use crate::install::ToolResolver;
use crate::model::ValidationResult;

pub fn run_warchaeology(file: &Path, resolver: &ToolResolver) -> ValidationResult {
    const NAME: &str = "Warchaeology";
    let program = match resolver.warchaeology() {
        Ok(program) => program,
        Err(error) => return ValidationResult::unavailable(NAME, format!("{error:#}")),
    };
    let scratch = match tempdir() {
        Ok(dir) => dir,
        Err(error) => return ValidationResult::error(NAME, error),
    };
    let index_dir = scratch.path().join("index");

    let output = match program
        .command()
        .arg("validate")
        .arg("--log-format")
        .arg("json")
        .arg("--index-dir")
        .arg(index_dir)
        .arg("--tmp-dir")
        .arg(scratch.path())
        .arg(file)
        .output()
    {
        Ok(output) => output,
        Err(error) => return ValidationResult::error(NAME, error),
    };

    let details = combined_output(&output);
    let log = parse_warchaeology_log(&details);
    if log.payload_mismatches > 0
        && log.other_errors == 0
        && log.total_errors == Some(log.payload_mismatches)
    {
        return payload_mismatches_ignored(NAME, log.payload_mismatches);
    }
    if output.status.success() && log.total_errors.unwrap_or_default() == 0 {
        ValidationResult::passed(
            NAME,
            summary_count(log.total_errors, "validation error"),
            details,
        )
    } else {
        ValidationResult::failed(
            NAME,
            log.total_errors.map_or_else(
                || exit_summary(&output),
                |count| plural(count, "validation error"),
            ),
            details,
        )
    }
}

pub fn run_jwat_tools(file: &Path, resolver: &ToolResolver) -> ValidationResult {
    const NAME: &str = "JWAT-Tools";
    let program = match resolver.jwat_tools() {
        Ok(program) => program,
        Err(error) => return ValidationResult::unavailable(NAME, format!("{error:#}")),
    };
    let scratch = match tempdir() {
        Ok(dir) => dir,
        Err(error) => return ValidationResult::error(NAME, error),
    };

    let output = match program
        .command()
        .env("JAVA_OPTS", "-Xms64m -Xmx1024m")
        .current_dir(scratch.path())
        .arg("test")
        .arg("-e")
        .arg(file)
        .output()
    {
        Ok(output) => output,
        Err(error) => return ValidationResult::error(NAME, error),
    };
    let details = combined_output(&output);

    if !output.status.success() {
        return ValidationResult::error_with_details(NAME, exit_summary(&output), details);
    }

    let Some(summary) = parse_jwat_summary(&details) else {
        return ValidationResult::error(NAME, "could not parse the JWAT-Tools job summary");
    };
    let line = format!(
        "{}, {}, {}",
        plural(summary.errors, "error"),
        plural(summary.warnings, "warning"),
        plural(summary.runtime_errors, "runtime error")
    );
    let payload_mismatches = jwat_payload_mismatch_count(&details).unwrap_or(0);
    if payload_mismatches > 0 && payload_mismatches == summary.errors && summary.runtime_errors == 0
    {
        return payload_mismatches_ignored(NAME, payload_mismatches);
    }
    if summary.errors == 0 && summary.runtime_errors == 0 {
        ValidationResult::passed(NAME, line, details)
    } else {
        ValidationResult::failed(NAME, line, details)
    }
}

pub fn run_warcio(file: &Path, resolver: &ToolResolver) -> ValidationResult {
    const NAME: &str = "warcio";
    let program = match resolver.warcio() {
        Ok(program) => program,
        Err(error) => return ValidationResult::unavailable(NAME, format!("{error:#}")),
    };

    let output = match program.command().arg("check").arg(file).output() {
        Ok(output) => output,
        Err(error) => return ValidationResult::error(NAME, error),
    };
    let details = combined_output(&output);
    let payload_mismatches = warcio_payload_mismatch_count(&details);
    if payload_mismatches > 0 && warcio_only_reported_payload_mismatches(&details) {
        return payload_mismatches_ignored(NAME, payload_mismatches);
    }
    let findings = details
        .lines()
        .filter(|line| line.trim_start().starts_with("offset "))
        .count();
    if output.status.success() {
        ValidationResult::passed(NAME, "check completed successfully", details)
    } else {
        ValidationResult::failed(NAME, plural(findings, "reported finding"), details)
    }
}

fn jwat_payload_mismatch_count(output: &str) -> Option<usize> {
    summary_value(output, "Incorrect payload digest")
}

/// A pass for a validator whose only findings were payload digest mismatches on HTTP payloads
/// it did not dechunk.
fn payload_mismatches_ignored(name: &'static str, count: usize) -> ValidationResult {
    let suffix = if count == 1 { "" } else { "es" };
    ValidationResult::passed(
        name,
        format!(
            "{count} payload digest mismatch{suffix} ignored (validator does not dechunk HTTP payloads)"
        ),
        String::new(),
    )
}

fn warcio_payload_mismatch_count(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.trim_start().starts_with("payload digest failed "))
        .count()
}

/// Warcio prints the filename, then a record line and an indented finding for each mismatch.
fn warcio_only_reported_payload_mismatches(output: &str) -> bool {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let Some(first) = lines.next() else {
        return false;
    };
    if first.starts_with(char::is_whitespace) {
        return false;
    }

    let mut expecting_finding = false;
    for line in lines {
        let trimmed = line.trim_start();
        if expecting_finding {
            if !trimmed.starts_with("payload digest failed ") {
                return false;
            }
            expecting_finding = false;
        } else {
            if !trimmed.starts_with("offset ") {
                return false;
            }
            expecting_finding = true;
        }
    }
    !expecting_finding
}

fn combined_output(output: &Output) -> String {
    let mut result = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !result.is_empty() && !stderr.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&stderr);
    result
}

fn exit_summary(output: &Output) -> String {
    output.status.code().map_or_else(
        || "validator was terminated by a signal".to_owned(),
        |code| format!("validator exited with status {code}"),
    )
}

fn summary_count(count: Option<usize>, noun: &str) -> String {
    count.map_or_else(
        || "validation completed".to_owned(),
        |count| plural(count, noun),
    )
}

/// What Warchaeology's JSON log reported.
#[derive(Debug, Default, PartialEq, Eq)]
struct WarchaeologyLog {
    /// The error count of the closing `Total` line, if the run reached it.
    total_errors: Option<usize>,
    /// Validation errors reporting a wrong payload digest.
    payload_mismatches: usize,
    /// Every other error-level line.
    other_errors: usize,
}

fn parse_warchaeology_log(output: &str) -> WarchaeologyLog {
    let mut log = WarchaeologyLog::default();
    for value in output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
    {
        let field = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
        match (field("level"), field("msg")) {
            (_, Some("Total")) => {
                log.total_errors = value
                    .get("errors")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|count| count.try_into().ok());
            }
            (Some("ERROR"), Some("Validation error"))
                if field("error")
                    .is_some_and(|error| error.starts_with("payload: wrong digest")) =>
            {
                log.payload_mismatches += 1;
            }
            (Some("ERROR"), _) => log.other_errors += 1,
            _ => {}
        }
    }
    log
}

#[derive(Debug, PartialEq, Eq)]
struct JwatSummary {
    errors: usize,
    warnings: usize,
    runtime_errors: usize,
}

fn parse_jwat_summary(output: &str) -> Option<JwatSummary> {
    Some(JwatSummary {
        errors: summary_value(output, "Errors")?,
        warnings: summary_value(output, "Warnings")?,
        runtime_errors: summary_value(output, "RuntimeErr")?,
    })
}

fn summary_value(output: &str, name: &str) -> Option<usize> {
    output.lines().rev().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name)
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jwat_job_summary() {
        let output = "# Job summary\nWarc files: 1\n    Errors: 2\n  Warnings: 3\nRuntimeErr: 4\n";
        assert_eq!(
            parse_jwat_summary(output),
            Some(JwatSummary {
                errors: 2,
                warnings: 3,
                runtime_errors: 4,
            })
        );
    }

    #[test]
    fn parses_warchaeology_json_log() {
        let output = concat!(
            "{\"level\":\"ERROR\",\"msg\":\"Validation error\",",
            "\"error\":\"payload: wrong digest: expected sha256:a, computed: sha256:b\"}\n",
            "{\"level\":\"ERROR\",\"msg\":\"Validation error\",",
            "\"error\":\"block: wrong digest: expected sha256:a, computed: sha256:b\"}\n",
            "{\"level\":\"INFO\",\"msg\":\"Validated file\",\"errors\":2}\n",
            "{\"level\":\"INFO\",\"msg\":\"Total\",\"files\":1,\"errors\":2}\n",
        );
        assert_eq!(
            parse_warchaeology_log(output),
            WarchaeologyLog {
                total_errors: Some(2),
                payload_mismatches: 1,
                other_errors: 1,
            }
        );
    }

    #[test]
    fn recognizes_jwat_payload_mismatch_total() {
        let output = "Errors: 12\nIncorrect payload digest: 12\n";
        assert_eq!(jwat_payload_mismatch_count(output), Some(12));
    }

    #[test]
    fn recognizes_warcio_payload_mismatch_only_output() {
        let output = concat!(
            "/tmp/example.warc\n",
            "  offset 42 WARC-Record-ID <urn:uuid:x> response\n",
            "    payload digest failed sha256:abc\n",
            "  offset 84 WARC-Record-ID <urn:uuid:y> response\n",
            "    payload digest failed sha256:def\n",
        );
        assert!(warcio_only_reported_payload_mismatches(output));
        assert_eq!(warcio_payload_mismatch_count(output), 2);
    }

    #[test]
    fn does_not_hide_other_warcio_findings() {
        let output = concat!(
            "/tmp/example.warc\n",
            "  offset 42 WARC-Record-ID <urn:uuid:x> response\n",
            "    block digest failed sha256:abc\n",
        );
        assert!(!warcio_only_reported_payload_mismatches(output));
    }
}
