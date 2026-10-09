# archivindex-warc-linter

A Rust library for checking WARC files against standard requirements and additional conventions,
built on [`archivindex-warc`](../../README.md). It checks header order, record identifiers and
dates, content types, digests, warcinfo fields, capture relationships, revisit references, and gzip
framing.

## Usage

```rust,no_run
use archivindex_warc::io::read::WarcReader;
use archivindex_warc_linter::Linter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = WarcReader::from_path_gzip("archive.warc.gz")?;
    for checked in Linter::new(reader) {
        match checked? {
            Ok(record_id) => println!("{record_id}: no findings"),
            Err(finding) => println!("{finding}"),
        }
    }
    Ok(())
}
```

Use `WarcReader::from_path` for uncompressed input. A reader created with `from_path_gzip` or
`from_gzip` tracks gzip members so the linter can check that each record occupies its own member.
Read errors are returned separately from lint findings. A malformed record is skipped, while a
stream or framing error ends the pass.

A record identifier must be a UUID URN or the one the Archivindex identity scheme derives from its
record. `Linter::require_archivindex_ids` refuses the UUID.

Add project-specific checks with `Linter::with_rule` and the `Rule` trait. Findings implement
`Display` for text output and `serde::Serialize` for JSON output. The
[`archivindex-warc` CLI](../../tools/archivindex-warc-cli/README.md#lint) uses this library for its
`lint` command.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
