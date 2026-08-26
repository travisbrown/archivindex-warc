use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use flate2::bufread::{GzDecoder, MultiGzDecoder};
use warcat::compress::{DecompressorConfig, Dictionary, Format};
use warcat::verify::{Problem, Verifier, VerifyStatus};
use warcat::warc::{Decoder, DecoderConfig};

use crate::model::ValidationResult;

pub fn run_warcat(file: &Path) -> ValidationResult {
    const NAME: &str = "warcat-rs";
    match known_hang(file) {
        Ok(None) => {}
        Ok(Some(reason)) => {
            return ValidationResult::error(
                NAME,
                format!("not run: the decoder never returns on {reason}"),
            );
        }
        Err(error) => return ValidationResult::error(NAME, format!("{error:#}")),
    }
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

const BARE_CR: &str = "a CR that no LF follows in a header block";

const TRUNCATED_RECORD: &str = "input that ends inside a record";

const MEMBER_BOUNDARY: &str = "a gzip member that ends inside a record";

/// Why warcat 0.3.4 would never return from `file`, when it would not.
///
/// Its decoder loops forever on a CR that no LF follows anywhere in a header block, on input
/// that ends inside a record (in a header line, in the body, or in the four bytes of the record
/// terminator), and on a gzip member that ends inside a record. Only gzip is decompressed here;
/// other formats go to the decoder unscanned.
fn known_hang(file: &Path) -> Result<Option<&'static str>> {
    let mut input = BufReader::new(
        File::open(file).with_context(|| format!("could not open {}", file.display()))?,
    );
    match compression_format(file) {
        Format::Identity => scan_for_hang(input, &[]),
        Format::Gzip => gzip_member_ends(&mut input).map_or(Ok(None), |member_ends| {
            input.seek(SeekFrom::Start(0))?;
            scan_for_hang(BufReader::new(MultiGzDecoder::new(input)), &member_ends)
        }),
        _ => Ok(None),
    }
    .with_context(|| format!("could not read {}", file.display()))
}

/// The decompressed offset at which each gzip member of `input` ends, or `None` when the members
/// cannot all be read, which the decoder reports itself.
fn gzip_member_ends<R: BufRead>(mut input: R) -> Option<Vec<u64>> {
    let mut ends = Vec::new();
    let mut offset = 0;

    while !input.fill_buf().ok()?.is_empty() {
        let mut decoder = GzDecoder::new(input);
        offset += io::copy(&mut decoder, &mut io::sink()).ok()?;
        ends.push(offset);
        input = decoder.into_inner();
    }

    Some(ends)
}

/// Walk the records of `input` as the decoder frames them, stopping with `None` at the first
/// thing the decoder would reject rather than loop on.
///
/// A record's body is framed by its last `Content-Length`, whose value the decoder accepts only
/// as digits after a single space; a line is accepted with or without a CR before its LF.
/// `member_ends` holds the ascending offsets at which gzip members end, and is empty for input
/// that is not gzip.
fn scan_for_hang<R: BufRead>(
    mut input: R,
    member_ends: &[u64],
) -> io::Result<Option<&'static str>> {
    let mut line = Vec::new();
    let mut offset = 0;
    let mut next_member_end = 0;

    while !input.fill_buf()?.is_empty() {
        let record_start = offset;
        let mut content_length = None;
        let mut version_line = true;

        loop {
            line.clear();
            offset += input.read_until(b'\n', &mut line)? as u64;
            let Some(text) = line.strip_suffix(b"\n") else {
                return Ok(Some(if line.contains(&b'\r') {
                    BARE_CR
                } else {
                    TRUNCATED_RECORD
                }));
            };
            let text = text.strip_suffix(b"\r").unwrap_or(text);
            if text.contains(&b'\r') {
                return Ok(Some(BARE_CR));
            }
            if version_line {
                if !text.starts_with(b"WARC/") {
                    return Ok(None);
                }
                version_line = false;
            } else if text.is_empty() {
                break;
            } else if let Some((name, value)) = split_field(text)
                && name.eq_ignore_ascii_case(b"content-length")
            {
                content_length = parse_length(value);
            }
        }

        let Some(content_length) = content_length else {
            return Ok(None);
        };
        let body = io::copy(&mut input.by_ref().take(content_length), &mut io::sink())?;
        offset += body;
        if body < content_length {
            return Ok(Some(TRUNCATED_RECORD));
        }

        let mut terminator = Vec::with_capacity(4);
        offset += input.by_ref().take(4).read_to_end(&mut terminator)? as u64;
        if terminator.len() < 4 {
            return Ok(Some(TRUNCATED_RECORD));
        }
        while member_ends
            .get(next_member_end)
            .is_some_and(|&end| end <= record_start)
        {
            next_member_end += 1;
        }
        if member_ends
            .get(next_member_end)
            .is_some_and(|&end| end < offset)
        {
            return Ok(Some(MEMBER_BOUNDARY));
        }
        if terminator != b"\r\n\r\n" {
            return Ok(None);
        }
    }

    Ok(None)
}

fn split_field(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&byte| byte == b':')?;

    Some((&line[..colon], &line[colon + 1..]))
}

/// A `Content-Length` value as the decoder reads it: digits after at most one space.
fn parse_length(value: &[u8]) -> Option<u64> {
    let digits = value.strip_prefix(b" ").unwrap_or(value);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }

    std::str::from_utf8(digits).ok()?.parse().ok()
}

fn drain_problems(verifier: &mut Verifier, destination: &mut Vec<Problem>) {
    destination.append(verifier.problems_mut());
}

fn compression_format(file: &Path) -> Format {
    let extension = file
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();

    if extension.eq_ignore_ascii_case("gz") {
        Format::Gzip
    } else if extension.eq_ignore_ascii_case("zst") || extension.eq_ignore_ascii_case("zstd") {
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

    const RECORD: &str = concat!(
        "WARC/1.0\r\n",
        "WARC-Type: resource\r\n",
        "WARC-Record-ID: <urn:uuid:a>\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "ab\rcd\r\n\r\n",
    );

    fn scan(bytes: &[u8]) -> Option<&'static str> {
        scan_for_hang(bytes, &[]).unwrap()
    }

    /// Consecutive gzip members holding `chunks`, written to a `.warc.gz` file.
    fn gzip_members(chunks: &[&[u8]]) -> NamedTempFile {
        let mut bytes = Vec::new();
        for chunk in chunks {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            std::io::Write::write_all(&mut encoder, chunk).unwrap();
            bytes.extend(encoder.finish().unwrap());
        }
        let file = NamedTempFile::with_suffix(".warc.gz").unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        file
    }

    #[test]
    fn scan_passes_input_the_decoder_returns_on() {
        assert_eq!(scan(b""), None);
        assert_eq!(scan(RECORD.as_bytes()), None);
        assert_eq!(scan(format!("{RECORD}{RECORD}").as_bytes()), None);
        assert_eq!(
            scan(RECORD.replacen("5\r\n\r\n", "5\r\n\n", 1).as_bytes()),
            None
        );
        assert_eq!(scan(format!("{RECORD}\r\n").as_bytes()), None);
        assert_eq!(scan(format!("{RECORD}xyz\r\n{RECORD}").as_bytes()), None);
        assert_eq!(
            scan(RECORD.replacen("WARC/1.0", "warc/1.0", 1).as_bytes()),
            None
        );
        assert_eq!(
            scan(RECORD.replacen("Length: 5", "Length:  5", 1).as_bytes()),
            None
        );
        assert_eq!(
            scan(RECORD.replacen("Length: 5", "Length: +5", 1).as_bytes()),
            None
        );
        assert_eq!(
            scan(RECORD.replacen("Content-Length: 5\r\n", "", 1).as_bytes()),
            None
        );
        assert_eq!(
            scan(format!("{RECORD}{RECORD}").replace("\r\n", "\n").as_bytes()),
            None
        );
    }

    #[test]
    fn scan_finds_a_bare_cr_in_a_header_block() {
        assert_eq!(
            scan(
                RECORD
                    .replacen("WARC/1.0\r\n", "WARC/1.0\r\r\n", 1)
                    .as_bytes()
            ),
            Some(BARE_CR)
        );
        assert_eq!(
            scan(RECORD.replacen("resource", "reso\rurce", 1).as_bytes()),
            Some(BARE_CR)
        );
        assert_eq!(
            scan(RECORD.replacen("5\r\n\r\n", "5\r\n\r\r\n", 1).as_bytes()),
            Some(BARE_CR)
        );
        assert_eq!(scan(b"\r"), Some(BARE_CR));
        let second = RECORD.replacen("resource\r\n", "resource\r\r\n", 1);
        assert_eq!(scan(format!("{RECORD}{second}").as_bytes()), Some(BARE_CR));
    }

    #[test]
    fn scan_finds_input_that_ends_inside_a_record() {
        assert_eq!(scan(b"WARC/1.0\r\n"), Some(TRUNCATED_RECORD));
        assert_eq!(scan(b"WARC/1.0\r\nWARC-Type: res"), Some(TRUNCATED_RECORD));
        assert_eq!(
            scan(&RECORD.as_bytes()[..RECORD.len() - 6]),
            Some(TRUNCATED_RECORD)
        );
        assert_eq!(
            scan(&RECORD.as_bytes()[..RECORD.len() - 4]),
            Some(TRUNCATED_RECORD)
        );
        assert_eq!(
            scan(&RECORD.as_bytes()[..RECORD.len() - 2]),
            Some(TRUNCATED_RECORD)
        );
        assert_eq!(
            scan(format!("{RECORD}xyz").as_bytes()),
            Some(TRUNCATED_RECORD)
        );
        assert_eq!(
            scan(RECORD.replacen("Length: 5", "Length: 50", 1).as_bytes()),
            Some(TRUNCATED_RECORD)
        );
        assert_eq!(
            scan(RECORD.replace("\r\n", "\n").as_bytes()),
            Some(TRUNCATED_RECORD)
        );
        let lengths = RECORD.replacen(
            "Content-Length: 5\r\n",
            "Content-Length: 5\r\nContent-Length: 7\r\n",
            1,
        );
        assert_eq!(scan(lengths.as_bytes()), Some(TRUNCATED_RECORD));
    }

    #[test]
    fn scan_reads_gzip() {
        let file = gzip_members(&[b"WARC/1.0\r\n"]);

        assert_eq!(known_hang(file.path()).unwrap(), Some(TRUNCATED_RECORD));
    }

    #[test]
    fn scan_passes_gzip_members_ending_at_record_boundaries() {
        let record = RECORD.as_bytes();
        let two = format!("{RECORD}{RECORD}");

        assert_eq!(
            known_hang(gzip_members(&[two.as_bytes()]).path()).unwrap(),
            None
        );
        assert_eq!(
            known_hang(gzip_members(&[record, record]).path()).unwrap(),
            None
        );
        assert_eq!(
            known_hang(gzip_members(&[record, b"", record]).path()).unwrap(),
            None
        );
        assert_eq!(
            known_hang(gzip_members(&[record, record, b""]).path()).unwrap(),
            None
        );
        let trailing = format!("{RECORD}\r\n");
        assert_eq!(
            known_hang(gzip_members(&[trailing.as_bytes(), record]).path()).unwrap(),
            None
        );
    }

    #[test]
    fn scan_finds_a_gzip_member_ending_inside_a_record() {
        let record = RECORD.as_bytes();
        for split in [20, record.len() - 7, record.len() - 4, record.len() - 2] {
            let file = gzip_members(&[&record[..split], &record[split..], record]);
            assert_eq!(
                known_hang(file.path()).unwrap(),
                Some(MEMBER_BOUNDARY),
                "{split}"
            );
        }
    }

    #[test]
    fn scan_leaves_unreadable_gzip_to_the_decoder() {
        let file = gzip_members(&[RECORD.as_bytes()]);
        let mut bytes = std::fs::read(file.path()).unwrap();
        bytes.extend_from_slice(b"xyz");
        std::fs::write(file.path(), &bytes).unwrap();
        assert_eq!(known_hang(file.path()).unwrap(), None);

        bytes.truncate(10);
        std::fs::write(file.path(), &bytes).unwrap();
        assert_eq!(known_hang(file.path()).unwrap(), None);
    }

    #[test]
    fn does_not_run_the_decoder_on_a_known_hang() {
        let result = run_warcat(Path::new("../tests/data/pywb/missing-status-text.warc"));
        assert_eq!(result.status, crate::model::Status::Error);
        assert!(result.summary.contains(BARE_CR), "{}", result.summary);

        let result = run_warcat(Path::new(
            "../tests/data/warcio/example-wrong-chunks.warc.gz",
        ));
        assert_eq!(result.status, crate::model::Status::Error);
        assert!(
            result.summary.contains(MEMBER_BOUNDARY),
            "{}",
            result.summary
        );
    }
}
