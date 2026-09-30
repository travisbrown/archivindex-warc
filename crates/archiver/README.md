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

## Benchmarks

Run the response-framing benchmarks from the workspace root:

```sh
cargo bench -p archivindex-archiver --bench response_capture
```

The cases cover small responses, long headers, and long chunk extensions, each delivered in
1-byte, 16-byte, and 8 KiB fragments. They use in-memory messages and make no network requests.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
