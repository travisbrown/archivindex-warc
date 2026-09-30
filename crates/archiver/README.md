# archivindex-archiver

A Rust library for archiving web pages over HTTP into WARC files, built on
[`archivindex-warc`](../../README.md). It captures the wire bytes of HTTP/1.1 requests and
responses, including redirect hops, and records capture metadata. Eligible duplicate payloads can be
stored as `revisit` records referring to an earlier capture.

## Usage

```rust,no_run
use archivindex_archiver::{Archiver, Config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let archiver = Archiver::new(Config::default())?;
    let summary = archiver.archive_to_path(["https://www.example.com/"], "example.warc")?;
    assert!(summary.is_complete());
    Ok(())
}
```

The `session` module supports driver-steered crawls, retries, and a persistent revisit index for
deduplication and HTTP revalidation across runs. For a command-line interface, see
[`archivindex-archiver-cli`](../../tools/archiver-cli/README.md).

## Benchmarks

Run the response-framing benchmarks from the workspace root:

```sh
cargo bench -p archivindex-archiver --bench response_capture
```

The cases cover small responses, long headers, and long chunk extensions, each delivered in
1-byte, 16-byte, and 8 KiB fragments. They use in-memory messages and make no network requests.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
