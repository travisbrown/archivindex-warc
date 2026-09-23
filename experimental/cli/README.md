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

Every other setting applies to whichever backend is chosen, and both record
byte-identical HTTP framing. That backend compiles BoringSSL from source and
needs an unpublished fork of `wreq`; see [its notes](../wreq/README.md).

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

## reidentify

```sh
archivindex-archiver reidentify --input input.warc.gz --output output.warc.gz
```

Replaces each identifiable record's `WARC-Record-ID` with the identifier the
[Archivindex scheme](../../crates/archiver/README.md#record-ids) assigns. Identity includes the
capture date at microsecond precision, stored block, target URI, record relationships, and segment
and revisit context. Applying the command to its own output preserves the record IDs and references.

Every `WARC-Warcinfo-ID`, `WARC-Refers-To`, `WARC-Concurrent-To`, and `WARC-Segment-Origin-ID`
naming a record in the file is updated to that record's final ID. Forward references are supported.
The command resolves dependencies before writing, so the new IDs describe the references actually
written. A reference to a record outside the file remains unchanged and contributes its existing ID
to identity.

A record carrying no `WARC-Record-ID` is given one. A record with an extension type or an unreadable
or repeated identity field keeps its ID with a warning. References in these records are still
updated. Every other field, every body, and the record order are preserved.

The input is read twice and must remain unchanged during the operation; it cannot be standard input.
The first pass retains identity data and reference dependencies, not content blocks. A `.gz`
extension selects gzip compression for either path; output uses one gzip member per record.

The command refuses duplicate input IDs, colliding output IDs, and cycles among records whose IDs
would be derived (including self-references). Hashing a cycle would require each ID to be known
before itself, so these files cannot be reidentified under this scheme. The archiver writes
dependencies without cycles. Records whose IDs are retained provide fixed reference targets. All
these checks run before the output is created or replaced.

References from other files and entries in revisit indexes are not updated. Because reference IDs
contribute to identity, changing an external reference also changes the referring record's ID and
potentially its dependents. Process related records together where possible. Rebuild affected
indexes and update external dependents before replacing archives they name.
