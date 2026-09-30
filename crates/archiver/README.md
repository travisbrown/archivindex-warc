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

## Proxies

Set `Config::proxy` to route every request through a SOCKS5 proxy, including redirects, challenge
responses, and session retries:

```rust,no_run
use archivindex_archiver::{Archiver, Config};

let archiver = Archiver::new(Config {
    proxy: Some("socks5h://127.0.0.1:1080".to_owned()),
    ..Config::default()
})?;
# Ok::<(), archivindex_archiver::ConfigError>(())
```

Use `socks5h://` to resolve destination hostnames through the proxy, or `socks5://` for local DNS.
The default proxy port is 1080. Username/password authentication is supported with
`socks5h://user:password@host:port`; percent-encode reserved characters in credentials. The recorder
rejects other proxy schemes. No proxy is used by default, and environment proxy settings are
ignored.
A proxy failure never falls back to a direct connection. Socket timeouts and capture deadlines also
bound SOCKS negotiation; local DNS resolution remains outside those bounds.

Proxied captures omit `WARC-IP-Address`: the socket peer is the proxy, and SOCKS does not reliably
identify the origin IP. `CapturedExchange::ip_address` is therefore optional. HTTP capture bytes
exclude proxy negotiation and authentication. The `warcinfo` body records the configured proxy URI
as `archivindex-proxy`, with username and password removed. This custom field preserves the proxy
scheme, host, and port when specified, and is absent when no proxy is configured. It describes the
configured endpoint, not the proxy's public exit address.

For standalone captures, set `Recorder::proxy` and call the `Backend` trait's `fetch` or
`fetch_by`. When supplying another backend with `Archiver::with_backend`, apply the same proxy to
that backend and `Config::proxy` so the recorded configuration matches the transport. A backend can
validate proxy URIs with `recorder::check_proxy` to accept exactly the URIs the recorder accepts.
The experimental CLI applies its configuration and `--proxy` option to either supported backend.

## Record IDs

The archiver assigns content-derived IDs to the records it writes. This is the archiver's identity
policy, not a generic fingerprint of every WARC property. The WARC library's standalone builders
retain their UUID defaults.

### Identity policy

A record's identity is its type, capture date, target URI, and stored content block. A revisit's
block stands for content stored elsewhere, so its identity also includes the capture date and target
URI of its original, which it must declare in `WARC-Refers-To-Date` and `WARC-Refers-To-Target-URI`.
A revisit's profile is excluded: the archiver uses `server-not-modified` exactly when the response
is a `304`, and the block keeps that response's head.

Dates use unsigned Unix **microseconds**, matching the archiver's capture precision. The archiver
never writes a date before 1970, so such dates are refused. Finer input precision is truncated
toward the earlier microsecond. Date spelling and declared precision do not affect identity: `.123Z`
and `.123000Z` identify the same instant, and a reduced-precision date uses the beginning of its
period. The same rules apply to `WARC-Refers-To-Date`.

An ID depends only on its own record. References to other records (`WARC-Refers-To`,
`WARC-Warcinfo-ID`, and `WARC-Concurrent-To`) are excluded. The capture date, target URI, and block
already distinguish captures, and a revisit names its original by capture date and target URI.
Excluding references means IDs can be derived in any order, a record keeps its ID when it is
rewritten under a different `warcinfo` record or when the records it names are reidentified, and
records may name each other without forming a cycle.

The block hash is always SHA-256 of the complete stored WARC content block. A revisit hashes its own
stored block. Declared block and payload digests are excluded, so changing digest algorithms or
encodings does not change identity. The record's old ID, filename, IP address, content-type
annotations, truncation annotations, and extension fields are also excluded. This deliberately
identifies captures under the properties listed here rather than every possible difference between
WARC records.

### Version 1 byte format

An ID is `https://archivindex.org/record/<hash>`, where `<hash>` is the lowercase hexadecimal
SHA-256 of the following fields in order, with no tags, padding, field count, or terminator.
Integers are big-endian. A URI is encoded as its `u64` byte length followed by its exact bytes.

| Field        | Encoding                                                       |
| ------------ | -------------------------------------------------------------- |
| Version      | `u8`, currently 1                                              |
| Record type  | `u8`, canonical rank plus one                                  |
| Capture date | `u64`, Unix microseconds from `WARC-Date`                      |
| Target URI   | `WARC-Target-URI` as a URI, or a zero length when it is absent |
| Block hash   | 32 bytes, SHA-256 of the stored block                          |

A URI always has a scheme, so an absent target URI cannot be confused with a present one. These five
fields are the whole pre-image of every record except a revisit, which continues with its original
capture:

| Field                 | Encoding                                            |
| --------------------- | --------------------------------------------------- |
| Original capture date | `u64`, Unix microseconds from `WARC-Refers-To-Date` |
| Original target URI   | `WARC-Refers-To-Target-URI` as a URI                |

Record type bytes are `warcinfo` = 1, `request` = 2, `response` = 3, `metadata` = 4, `revisit` = 5.
The archiver writes no other record types, so `resource`, `conversion`, `continuation`, and
extension records are refused. It also never writes segmented records, so any record carrying
`WARC-Segment-Number`, `WARC-Segment-Origin-ID`, or `WARC-Segment-Total-Length` is refused.

URI brackets and surrounding header whitespace are excluded. URI spelling is otherwise exact,
including percent escapes. Header name case and header order do not affect identity. A malformed or
repeated identity field is refused. These bytes define version 1 of the scheme.

## Benchmarks

Run the response-framing benchmarks from the workspace root:

```sh
cargo bench -p archivindex-archiver --bench response_capture
```

The cases cover small responses, long headers, and long chunk extensions, each delivered in
1-byte, 16-byte, and 8 KiB fragments. They use in-memory messages and make no network requests.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
