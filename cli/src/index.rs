//! The `load-revisit-index` command.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use archivindex_cli_support::plural;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc_revisit_index::{Index, LoadSummary};

/// What a load changed, for the console.
pub fn describe(summary: &LoadSummary) -> String {
    format!(
        "{} inserted, {} updated, {} skipped",
        plural(summary.payloads, "payload"),
        plural(summary.resources, "resource"),
        plural(summary.skipped, "malformed record")
    )
}

/// The WARC files `path` names.
///
/// A directory names the regular files directly in it whose names end in `.warc` or `.warc.gz`,
/// sorted by file name; anything else, including `-` for standard input, names itself.
///
/// # Errors
///
/// Returns an error when the directory cannot be listed.
pub fn warc_files(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("cannot list directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("cannot list directory {}", path.display()))?;
        let name = entry.file_name();
        if is_warc(Path::new(&name)) && entry.path().is_file() {
            files.push((name, entry.path()));
        }
    }
    files.sort_unstable();
    if files.is_empty() {
        log::warn!("no .warc or .warc.gz files in {}", path.display());
    }

    Ok(files.into_iter().map(|(_, path)| path).collect())
}

/// Whether a file name ends in `.warc` or `.warc.gz`.
fn is_warc(name: &Path) -> bool {
    match name.extension().and_then(OsStr::to_str) {
        Some("warc") => true,
        Some("gz") => name
            .file_stem()
            .is_some_and(|stem| Path::new(stem).extension() == Some(OsStr::new("warc"))),
        _ => false,
    }
}

/// Index every record of the WARC file at `input` into `index` in one transaction.
///
/// # Errors
///
/// Returns an error when the file cannot be opened or read, or when the index fails; the
/// transaction is then rolled back. A record with a malformed HTTP head or WARC payload is
/// logged and counted as skipped rather than failing the load.
pub fn load(index: &mut Index, input: &Path) -> Result<LoadSummary> {
    let reader = archivindex_warc_ops::file::open(input)?;

    index
        .load_records(reader.iter_records::<NoExtension>(), |record, error| {
            log::warn!(
                "skipping record {} of {}: {error}",
                record.core().record_id,
                input.display()
            );
        })
        .with_context(|| format!("cannot index {}", input.display()))
}

#[cfg(test)]
mod tests {
    use archivindex_test_support::warc::render;

    use super::*;

    const RESPONSE: &[(&str, &str)] = &[
        ("WARC-Type", "response"),
        (
            "WARC-Record-ID",
            "<urn:uuid:00000000-0000-0000-0000-000000000001>",
        ),
        ("WARC-Date", "2024-01-01T00:00:00Z"),
        ("WARC-Target-URI", "https://example.com/"),
        ("Content-Type", "application/http;msgtype=response"),
        (
            "WARC-Payload-Digest",
            "sha1:YIVV7ELYGQTASQUNN5I3FRNPJQF542SC",
        ),
    ];

    /// An HTTP response whose body is `hi`, matching the digest above.
    const BODY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    #[test]
    fn warc_files_lists_a_directorys_warc_files_by_name() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["b.warc", "a.warc.gz", "c.txt", "d.warc.gz.bak"] {
            std::fs::write(directory.path().join(name), b"").unwrap();
        }
        std::fs::create_dir(directory.path().join("0.warc")).unwrap();

        let files = warc_files(directory.path()).unwrap();

        assert_eq!(
            files,
            [
                directory.path().join("a.warc.gz"),
                directory.path().join("b.warc")
            ]
        );
    }

    #[test]
    fn warc_files_names_a_file_itself() {
        assert_eq!(
            warc_files(Path::new("archive.warc.gz")).unwrap(),
            [PathBuf::from("archive.warc.gz")]
        );
    }

    #[test]
    fn load_indexes_each_record_and_skips_malformed_ones() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive.warc");
        let mut malformed = RESPONSE.to_vec();
        malformed[1].1 = "<urn:uuid:00000000-0000-0000-0000-000000000002>";
        let mut file = render(RESPONSE, BODY);
        file.extend(render(&malformed, "HTTP/1.1 200\r\nno colon\r\n\r\n"));
        std::fs::write(&path, file).unwrap();
        let mut index = Index::open_in_memory().unwrap();

        let summary = load(&mut index, &path).unwrap();

        assert_eq!(
            summary,
            LoadSummary {
                records: 2,
                payloads: 1,
                resources: 1,
                skipped: 1,
            }
        );
    }

    #[test]
    fn load_reports_an_unreadable_file() {
        let mut index = Index::open_in_memory().unwrap();

        let error = load(&mut index, Path::new("/nonexistent/archive.warc")).unwrap_err();

        assert!(error.to_string().contains("archive.warc"), "{error:#}");
    }
}
