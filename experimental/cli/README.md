# archivindex-archiver

A command-line tool for archiving URLs into WARC files.

## Usage

URLs are read one per line from standard input and captured, in order, into the WARC file named by
`--output`:

```sh
archivindex-archiver archive --output capture.warc < urls.txt
```

An existing output file is not overwritten.

## Capture backends

By default URLs are captured with the archiver's built-in recorder backend, which needs
nothing extra. Building with the `wreq` feature adds a second backend that uses
BoringSSL with browser-derived TLS emulation:

```sh
archivindex-archiver archive --backend wreq --profile chrome_136 \
  --output capture.warc < urls.txt
```

`--profile` names the browser the backend emulates and defaults to `chrome_136`. It is refused
without `--backend wreq`.

The configured `user-agent` replaces the profile's own `User-Agent` header. By default it names this
tool, so the header contradicts the browser that the TLS and HTTP/2 settings imitate, which a site
checking for consistency may treat as suspicious. To send a browser's user agent, set `user-agent`
in the configuration file to that value; the `warcinfo` record then also describes the request
actually sent.

Every other setting applies to whichever backend is chosen. Both record HTTP/1
exchanges exactly. The `wreq` backend also negotiates HTTP/2, which it records as
reconstructed HTTP/1.1 messages marked with `WARC-Protocol: h2`. It compiles
BoringSSL from source and needs an unpublished fork of `wreq`; see
[its notes](../wreq/README.md).

## Configuration

Capture settings are read from a TOML or JSON file named by `--config`, recognized by its `.toml` or
`.json` extension:

```sh
archivindex-archiver archive --config capture.toml --output capture.warc < urls.txt
```

Top-level keys are optional and use defaults when absent. An empty TOML file or an empty JSON object
uses the default configuration. Unknown keys are errors. Set `gzip-warc = true` to compress records;
the output filename does not select compression. [default-config.toml](default-config.toml) lists
every key with its default value and meaning. Durations are humantime strings such as `30s` or
`10m`, and the limits `max-capture-time` and `max-response-length` are lifted by writing
`"unbounded"`.

Use `--proxy` to route requests through a SOCKS5 proxy:

```sh
archivindex-archiver archive --proxy socks5h://127.0.0.1:1080 \
  --output capture.warc < urls.txt
```

This works with both backends. Alternatively, set the top-level `proxy` key in the configuration
file; `--proxy` takes precedence. `socks5h://` resolves destination hostnames through the proxy,
while `socks5://` resolves them locally. Both support `user:password@host:port` authentication.
No proxy is used by default, and environment proxy settings are ignored. Redirects, challenge
responses, and retries use the same proxy. Failed proxy connections never fall back to direct
connections. Proxied captures omit `WARC-IP-Address` because the origin IP is not known reliably.
The `warcinfo` body records the proxy URI in `archivindex-proxy`, with username and password
removed.

The `warcinfo` record of every WARC file names the software that wrote it and, when configured, its
operator:

```toml
[software]
name = "example-crawler"
version = "2.0"

[operator]
name = "Example Operator"
email = "operator@example.com"
```

The software defaults to this tool's name and version, and no operator is named by default.

A response whose payload duplicates an earlier capture is stored as a `revisit` record unless the
payload is shorter than `min-revisit-payload-length`, 256 bytes by default. Library crawl sessions
can consult a persistent revisit and resource-state database by setting `session.revisit-index` to
its path. New captures are not added to it; `archivindex-warc load-revisit-index` adds a published
WARC. No revisit index is configured by default. This CLI runs one-shot archives and does not use
the `session` settings.
