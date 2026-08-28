# WARC command-line tools

This standalone application provides commands for inspecting and transforming WARC files. It uses
the version of [`archivindex-warc`][archivindex-warc] in this repository.

A path with a `.gz` extension names a gzip-compressed file, for inputs and outputs alike. A
compressed output holds one gzip member per record. An input of `-` is standard input, which is
decompressed when it begins with the gzip magic number; `merge`,
`propagate-identified-payload-type`, and `remove-same-target-revisits` read each of their inputs
twice, so they take files only.

`-q` logs errors only, the default adds warnings and normal program output, and `-v`, `-vv`,
and `-vvv` raise the diagnostic level to informational, debug, and trace.

## canonicalize

```console
cargo run --manifest-path cli/Cargo.toml -- canonicalize -i input.warc.gz -o output.warc.gz
```

Respells standard header fields as the WARC standard prints them and puts them in conventional
order in every record. Extension fields follow the standard fields and keep their spelling and
relative order. Field values, bodies, record order, and the relative order of repeated fields are
preserved.

## compress

```console
cargo run --manifest-path cli/Cargo.toml -- compress -i input.warc -o output.warc.gz
```

Compresses each record as a separate gzip member. The output name must end in `.gz`; use
`--level` to choose a compression level from 0 through 9.

## digest-framed-payloads

```console
cargo run --manifest-path cli/Cargo.toml -- \
  digest-framed-payloads -i input.warc.gz -o output.warc.gz
```

WARC 1.1 makes the payload of an HTTP message its entity-body, which is the message body with any
transfer-coding removed. Several other tools digest the message body as it was framed, chunk sizes
and trailers included, and expect the same of the files they validate. Each `request` or
`response` record with an HTTP or HTTPS target and a `Content-Type` of `application/http` or none
that declares `WARC-Payload-Digest` has it recomputed over the framed body under the algorithm and
encoding it declares, keeping the label as read. A segmented or truncated record, a record whose
digest is malformed or names an algorithm this build does not compute, and a record whose message
has no end of header section are copied as read, the last three with a warning. Every other record
is copied as read.

## export

```console
cargo run --manifest-path cli/Cargo.toml -- export -i archive.warc.gz csv
cargo run --manifest-path cli/Cargo.toml -- export -i archive.warc.gz json
```

`csv` writes the type, date, record identifier, and target URI of each record. `json` writes each
payload identified as JSON, one value per line.

## graph

```console
cargo run --manifest-path cli/Cargo.toml -- graph -i archive.warc.gz -o archive.svg
```

Draws every record as a color-coded node and record-ID relationships as directed arrows. The graph
includes a key for the record-type colors. `WARC-Concurrent-To`, `WARC-Warcinfo-ID`,
`WARC-Refers-To`, and `WARC-Segment-Origin-ID` are drawn when they point to a record in the input.
UUID record IDs are labeled with a short, distinguishing prefix from the part after `urn:uuid:`.
Other long IDs retain shortened forms of both ends.

Without `--output`, the command writes the SVG to `archivindex-warc-graph.svg` in the runtime
directory (`$XDG_RUNTIME_DIR`, or the temporary directory without one), replacing the previous
graph, and opens it in a separate Firefox window when Firefox is available, falling back to the
platform's default SVG viewer.

## lint

```console
cargo run --manifest-path cli/Cargo.toml -- lint -i archive.warc.gz
```

Checks conventions stricter than the WARC standard, including header order, capture-record
relationships, digests, and record-at-a-time gzip framing. Use `--format json` for JSON Lines
output. The command exits with status 1 when it finds problems.

## load-revisit-index

```console
cargo run --manifest-path cli/Cargo.toml -- load-revisit-index -i archive.warc.gz --db revisits.db
cargo run --manifest-path cli/Cargo.toml -- load-revisit-index -i captures/ --db revisits.db
```

Indexes every record of a WARC file into the SQLite revisit index named by `--db`, creating the
index when it does not exist. A directory stands for the `.warc` and `.warc.gz` files directly in
it, taken in file-name order. Each file is indexed in one transaction, so a file that cannot be
read leaves the index as it was before that file. A record whose HTTP head or WARC payload is
malformed is skipped with a warning.

## merge

```console
cargo run --manifest-path cli/Cargo.toml -- \
  merge --first first.warc.gz --second second.warc.gz -o merged.warc.gz
```

Writes every record of the first file followed by every record of the second, dropping duplicate
warcinfo records. Two warcinfo records are duplicates when they declare the same WARC version,
carry the same body, and carry the same fields other than `WARC-Record-ID`, `WARC-Date`,
`WARC-Filename`, `WARC-Block-Digest`, and `WARC-Payload-Digest`. The duplicate with the earliest
`WARC-Date` is written where the first of them stood, and every reference to a dropped record
(`WARC-Warcinfo-ID`, `WARC-Refers-To`, `WARC-Concurrent-To`, and `WARC-Segment-Origin-ID`) is
redirected to it. All other records are written byte for byte as they were read.

## propagate-identified-payload-type

```console
cargo run --manifest-path cli/Cargo.toml -- \
  propagate-identified-payload-type -i input.warc.gz -o output.warc.gz
```

Gives each `revisit` record lacking `WARC-Identified-Payload-Type` the value declared by the
`response` record its `WARC-Refers-To` names, when that response is in the file. The field is
placed where the conventional header order puts it among the fields the revisit has. Every other
record, and every revisit whose original is not such a response, is copied as read.

## remove-same-target-revisits

```console
cargo run --manifest-path cli/Cargo.toml -- \
  remove-same-target-revisits -i input.warc.gz -o output.warc.gz
```

Removes each `revisit` record whose `WARC-Target-URI` equals that of the `response` record its
`WARC-Refers-To` names, when that response is in the file, together with the rest of its capture.

## rewrite

```console
cargo run --manifest-path cli/Cargo.toml -- \
  rewrite -i input.warc.gz -o output.warc.gz warcinfo --filename output.warc.gz
```

Sets selected fields on every `warcinfo` record and copies all other records as read. Run
`rewrite warcinfo --help` for the available fields.

[archivindex-warc]: https://github.com/travisbrown/archivindex-warc
