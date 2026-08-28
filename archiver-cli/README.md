# archivindex-archiver

A command-line tool for archiving URLs into WARC files.

## Usage

URLs are read one per line from standard input and captured, in order, into
the WARC file named by `--output`:

```sh
archivindex-archiver archive --output capture.warc < urls.txt
```

An existing output file is not overwritten.

## Configuration

Capture settings are read from a TOML or JSON file named by `--config`,
recognized by its `.toml` or `.json` extension:

```sh
archivindex-archiver archive --config capture.toml --output capture.warc.gz < urls.txt
```

Every key is optional and takes its default when absent, so an empty file and
no file at all are the same configuration. An unknown key is an error.
[default-config.toml](default-config.toml) lists every key with its default
value and meaning. Durations are humantime strings such as `30s` or `10m`, and
the limits `max-capture-time` and `max-response-length` are lifted by writing
`"unbounded"`.

The `warcinfo` record of every WARC file names the software that wrote it and,
when configured, its operator:

```toml
[software]
name = "example-crawler"
version = "2.0"

[operator]
name = "Example Operator"
email = "operator@example.com"
```

The software defaults to this tool's name and version, and no operator is named
by default.

A response whose payload duplicates an earlier capture is stored as a `revisit`
record unless the payload is shorter than `min-revisit-payload-length`, 256
bytes by default. Sessions can consult a persistent revisit and resource-state
database by setting `session.revisit-index` to its path. New captures are not
added to it; `archivindex-warc load-revisit-index` adds a published WARC. No
revisit index is configured by default.
