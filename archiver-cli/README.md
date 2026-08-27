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
the limits `max_capture_time` and `max_response_length` are lifted by writing
`"unbounded"`.
