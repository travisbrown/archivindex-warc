use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use warcat::compress::{DecompressorConfig, Dictionary, Format};
use warcat::verify::{Problem, Verifier, VerifyStatus};
use warcat::warc::{Decoder, DecoderConfig};

use crate::model::ValidationResult;

pub fn run_warcat(file: &Path) -> ValidationResult {
    const NAME: &str = "warcat-rs";
    match validate(file) {
        Ok(problems) if problems.is_empty() => {
            ValidationResult::passed(NAME, "no problems", String::new())
        }
        Ok(problems) => {
            let details = problems
                .iter()
                .filter_map(|problem| serde_json::to_string(problem).ok())
                .collect::<Vec<_>>()
                .join("\n");
            let suffix = if problems.len() == 1 { "" } else { "s" };
            ValidationResult::failed(NAME, format!("{} problem{suffix}", problems.len()), details)
        }
        Err(error) => ValidationResult::error(NAME, format!("{error:#}")),
    }
}

fn validate(file: &Path) -> Result<Vec<Problem>> {
    let input = BufReader::new(
        File::open(file).with_context(|| format!("could not open {}", file.display()))?,
    );
    let mut config = DecoderConfig::default();
    config.decompressor = DecompressorConfig::default();
    config.decompressor.format = compression_format(file);
    config.decompressor.dictionary = Dictionary::WarcZstd(Vec::new());
    let mut decoder = Decoder::new(input, config).context("could not initialize WARC decoder")?;
    let mut verifier = Verifier::new();
    let mut problems = Vec::new();
    let mut record_count = 0usize;
    let mut buffer = vec![0; 64 * 1024];

    while decoder
        .has_next_record()
        .context("could not read WARC input")?
    {
        record_count += 1;
        let (header, mut block) = decoder.read_header().context("invalid WARC header")?;
        verifier.begin_record(&header)?;

        loop {
            let count = block.read(&mut buffer).context("invalid WARC block")?;
            if count == 0 {
                break;
            }
            verifier.block_data(&buffer[..count]);
        }
        verifier.end_record();
        drain_problems(&mut verifier, &mut problems);
        decoder = block
            .finish_block()
            .context("invalid WARC record terminator")?;
    }

    if record_count == 0 {
        anyhow::bail!("file contains no WARC records");
    }
    if decoder.has_record_at_time_compression_fault() {
        verifier.add_not_record_at_time_compression();
    }

    loop {
        let status = verifier.verify_end()?;
        drain_problems(&mut verifier, &mut problems);
        if status == VerifyStatus::Done {
            break;
        }
    }

    Ok(problems)
}

fn drain_problems(verifier: &mut Verifier, destination: &mut Vec<Problem>) {
    destination.append(verifier.problems_mut());
}

fn compression_format(file: &Path) -> Format {
    let name = file
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".gz") {
        Format::Gzip
    } else if name.ends_with(".zst") || name.ends_with(".zstd") {
        Format::Zstandard
    } else {
        Format::Identity
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    const VALID_WARC: &[u8] = concat!(
        "WARC/1.1\r\n",
        "WARC-Type: resource\r\n",
        "WARC-Record-ID: <urn:uuid:12345678-1234-1234-1234-123456789abc>\r\n",
        "WARC-Date: 2026-08-14T12:00:00Z\r\n",
        "WARC-Target-URI: https://example.com/\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
        "\r\n\r\n",
    )
    .as_bytes();

    #[test]
    fn detects_compression_from_filename() {
        assert_eq!(compression_format(Path::new("a.warc")), Format::Identity);
        assert_eq!(compression_format(Path::new("a.WARC.GZ")), Format::Gzip);
        assert_eq!(
            compression_format(Path::new("a.warc.zst")),
            Format::Zstandard
        );
    }

    #[test]
    fn validates_a_minimal_warc() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), VALID_WARC).unwrap();
        assert!(validate(file.path()).unwrap().is_empty());
    }

    #[test]
    fn rejects_an_empty_file() {
        let file = NamedTempFile::new().unwrap();
        assert!(validate(file.path()).is_err());
    }
}
