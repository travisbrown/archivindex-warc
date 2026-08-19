# WARC command-line tools

This standalone Rust application provides commands for working with WARC files, built on
[`archivindex-warc`][archivindex-warc] taken from this repository's source tree.

A path with a `.gz` extension names a gzip-compressed file, for inputs and outputs alike. A
compressed output holds one gzip member per record.

`-q` logs errors only, the default adds warnings and normal program output, and `-v`, `-vv`,
and `-vvv` raise the diagnostic level to informational, debug, and trace.

## graph

```console
cargo run --manifest-path cli/Cargo.toml -- graph --input archive.warc.gz --output archive.svg
```

Draws every record as a color-coded node and record-ID relationships as directed arrows. The graph
includes a key for the record-type colors. `WARC-Concurrent-To`, `WARC-Warcinfo-ID`,
`WARC-Refers-To`, and `WARC-Segment-Origin-ID` are drawn when they point to a record in the input.
UUID record IDs are labeled with a short, distinguishing prefix from the part after `urn:uuid:`.
Other long IDs retain shortened forms of both ends.

Without `--output`, the command writes the SVG to a temporary file and opens it in a separate
Firefox window when Firefox is available, falling back to the platform's default SVG viewer.

## merge

```console
cargo run --manifest-path cli/Cargo.toml -- merge first.warc.gz second.warc.gz -o merged.warc.gz
```

Writes every record of the first file followed by every record of the second, dropping duplicate
warcinfo records. Two warcinfo records are duplicates when they declare the same WARC version,
carry the same body, and carry the same fields other than `WARC-Record-ID`, `WARC-Date`,
`WARC-Filename`, `WARC-Block-Digest`, and `WARC-Payload-Digest`. The duplicate with the earliest
`WARC-Date` is written where the first of them stood, and every reference to a dropped record
(`WARC-Warcinfo-ID`, `WARC-Refers-To`, `WARC-Concurrent-To`, and `WARC-Segment-Origin-ID`) is
redirected to it. All other records are written byte for byte as they were read.

[archivindex-warc]: https://github.com/travisbrown/archivindex-warc
