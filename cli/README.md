# WARC command-line tools

This standalone Rust application provides commands for working with WARC files, built on
[`archivindex-warc`][archivindex-warc] taken from this repository's source tree.

A path with a `.gz` extension names a gzip-compressed file, for inputs and outputs alike. A
compressed output holds one gzip member per record.

`-q` logs errors only, the default adds warnings and normal program output, and `-v`, `-vv`,
and `-vvv` raise the diagnostic level to informational, debug, and trace.

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
