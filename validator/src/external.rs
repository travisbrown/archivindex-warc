use std::path::Path;
use std::process::Output;

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
    let error_count = warchaeology_error_count(&details);
    if output.status.success() && error_count.unwrap_or_default() == 0 {
        ValidationResult::passed(
            NAME,
            summary_count(error_count, "validation error"),
            details,
        )
    } else {
        ValidationResult::failed(
            NAME,
            error_count
                .map(|count| plural(count, "validation error"))
                .unwrap_or_else(|| exit_summary(&output)),
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
    let findings = details
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    if output.status.success() {
        ValidationResult::passed(NAME, "check completed successfully", details)
    } else {
        ValidationResult::failed(NAME, plural(findings, "reported finding"), details)
    }
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
    output
        .status
        .code()
        .map(|code| format!("validator exited with status {code}"))
        .unwrap_or_else(|| "validator was terminated by a signal".to_owned())
}

fn plural(count: usize, noun: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} {noun}{suffix}")
}

fn summary_count(count: Option<usize>, noun: &str) -> String {
    count
        .map(|count| plural(count, noun))
        .unwrap_or_else(|| "validation completed".to_owned())
}

fn warchaeology_error_count(output: &str) -> Option<usize> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|value| {
            (value.get("msg")?.as_str()? == "Total")
                .then(|| value.get("errors")?.as_u64()?.try_into().ok())
                .flatten()
        })
}

#[derive(Debug, PartialEq, Eq)]
struct JwatSummary {
    errors: usize,
    warnings: usize,
    runtime_errors: usize,
}

fn parse_jwat_summary(output: &str) -> Option<JwatSummary> {
    fn value(output: &str, name: &str) -> Option<usize> {
        output.lines().rev().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name)
                .then(|| value.trim().parse().ok())
                .flatten()
        })
    }

    Some(JwatSummary {
        errors: value(output, "Errors")?,
        warnings: value(output, "Warnings")?,
        runtime_errors: value(output, "RuntimeErr")?,
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
    fn parses_warchaeology_json_total() {
        let output = concat!(
            "{\"level\":\"INFO\",\"msg\":\"Validated file\",\"errors\":2}\n",
            "{\"level\":\"INFO\",\"msg\":\"Total\",\"files\":1,\"errors\":2}\n",
        );
        assert_eq!(warchaeology_error_count(output), Some(2));
    }
}
