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
[`archivindex-archiver-cli`](../../experimental/cli/README.md).

## Record IDs

The archiver assigns content-derived IDs to the records it writes. This is the archiver's identity
policy, not a generic fingerprint of every WARC property. The WARC library's standalone builders
retain their UUID defaults.

### Identity policy

A record's identity includes its type, capture date, stored content block, target URI, and
relationships to other records. Segment numbers, origins, and total lengths distinguish pieces of a
segmented record. A revisit's profile and original capture URI and date distinguish what its stored
block represents.

Dates use signed Unix **microseconds**, matching the archiver's capture precision. Finer input
precision is truncated toward the earlier microsecond. Date spelling and declared precision do not
affect identity: `.123Z` and `.123000Z` identify the same instant, and a reduced-precision date uses
the beginning of its period. The same rule applies to `WARC-Refers-To-Date`.

References use the final IDs of the records they name. The archiver assigns the warcinfo ID first,
then each request, response or revisit, and associated metadata in dependency order.
`WARC-Warcinfo-ID` is part of identity, so changing a capture's collection context changes its ID.
External references are taken as supplied. Renaming the old IDs within a file does not change the
IDs derived when all their targets are reidentified together.

The block hash is always SHA-256 of the complete stored WARC content block. A revisit hashes its own
stored block. Declared block and payload digests are excluded, so changing digest algorithms or
encodings does not change identity. The record's old ID, filename, IP address, content-type
annotations, truncation annotations, and extension fields are also excluded. This deliberately
identifies captures under the properties listed here rather than every possible difference between
WARC records.

### Version 1 byte format

An ID is `https://archivindex.org/record/<hash>`, where `<hash>` is the lowercase hexadecimal
SHA-256 of the following prefix followed by the present fields in the second table. All integers use
big-endian byte order, without padding between fields.

| Prefix component | Encoding                                  |
| ---------------- | ----------------------------------------- |
| Version          | `u8`, currently 1                         |
| Record type      | `u8`, canonical rank plus one             |
| Capture date     | `i64`, Unix microseconds from `WARC-Date` |
| Block hash       | 32 bytes, SHA-256 of the stored block     |

Record type bytes are warcinfo = 1, request = 2, response = 3, metadata = 4, revisit = 5, resource =
6, conversion = 7, continuation = 8. Extension record types are refused.

Each present field is encoded as its `u8` tag, a `u64` byte length, and that many value bytes.
Absent fields contribute no bytes. Fields appear in ascending tag order. References under tag 8 are
sorted by their exact URI bytes; duplicates are retained. No field count or terminator is added.

| Tag | Field                       | Value encoding                                     |
| --- | --------------------------- | -------------------------------------------------- |
| 1   | `WARC-Target-URI`           | Exact URI bytes                                    |
| 2   | `WARC-Segment-Number`       | `u64`                                              |
| 3   | `WARC-Segment-Total-Length` | `u64`                                              |
| 4   | `WARC-Profile`              | Exact URI bytes                                    |
| 5   | `WARC-Refers-To-Target-URI` | Exact URI bytes                                    |
| 6   | `WARC-Refers-To-Date`       | `i64`, Unix microseconds                           |
| 7   | `WARC-Warcinfo-ID`          | Final record ID URI bytes                          |
| 8   | `WARC-Concurrent-To`        | Final record ID URI bytes, one field per reference |
| 9   | `WARC-Refers-To`            | Final record ID URI bytes                          |
| 10  | `WARC-Segment-Origin-ID`    | Final record ID URI bytes                          |

URI brackets and surrounding header whitespace are excluded. URI spelling is otherwise exact,
including percent escapes. Decimal leading zeros in segment fields are insignificant. Header name
case and header order do not affect identity. A malformed or repeated identity field is refused,
except that `WARC-Concurrent-To` may repeat. These bytes define version 1 of the scheme.

## Benchmarks

Run the response-framing benchmarks from the workspace root:

```sh
cargo bench -p archivindex-archiver --bench response_capture
```

The cases cover small responses, long headers, and long chunk extensions, each delivered in
1-byte, 16-byte, and 8 KiB fragments. They use in-memory messages and make no network requests.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
