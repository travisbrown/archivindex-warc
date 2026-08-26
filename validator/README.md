# WARC validator

This standalone Rust application runs a WARC file through several independent validators and
prints one summary. It is not a member of the repository's workspace: it builds on its own, with
its own lock file, so that its dependency tree cannot constrain the other packages.

The application depends on `archivindex-warc` by path, so `validator/Cargo.lock` also pins the
library's dependencies. Continuous integration builds the validator with `--locked`. After
changing a workspace dependency, regenerate this lock file with
`cargo check --manifest-path validator/Cargo.toml`.

```console
cargo run --manifest-path validator/Cargo.toml -- example.warc.gz
```

The file is first read with this repository's version of
[`archivindex-warc`][archivindex-warc], once at each of its three representation levels:

- `archivindex raw` frames every record and checks nothing else.
- `archivindex untyped` reads each field value against its grammar.
- `archivindex record` checks each record against the standard's rules for its type and declared
  version, and checks any `WARC-Block-Digest` it declares against the block it carries and any
  `WARC-Payload-Digest` against the payload that block frames.

A layer reports one line per record it could not read, numbered by the record's position in the
file. Framing and stream failures stop a read, so a file the raw layer refuses is reported as
refused at all three.

The following external validators then run:

- The [warc][warc-crate] crate parses every record using its typed reader.
- The [warcat-rs][warcat-rs-crate] crate checks WARC structure, required fields, references,
  segments, digests, and compression.
- [Warchaeology][warcheology] is run as `warc validate`.
- [JWAT-Tools][jwat-tools] is run as `jwattools test -e`.
- [warcio] is run as `warcio check` and is primarily a digest checker.

Warchaeology, JWAT-Tools, and warcio do not remove HTTP transfer coding before checking payload
digests, even though the WARC standard specifically requires this. When one of these tools reports
only payload-digest mismatches, the validator summarizes and ignores those findings (unrelated or
mixed findings still fail and retain their detailed output).

By default the application attempts a local installation when an external validator is not on
`PATH`. Warchaeology release archives, JWAT-Tools, and a Python virtual environment for warcio
are stored below the platform cache directory (for example,
`~/.cache/archivindex-warc-validator/tools` on Linux). Nothing is installed globally. Use
`--no-install` to disable this behavior or `--tools-dir` to choose another directory.

The local installers use Warchaeology 5.0.0, JWAT-Tools 0.7.1, and warcio 1.8.1. Each download
is checked against a SHA-256 digest recorded in the source before it is unpacked or run: the
Warchaeology release archive for the current platform against the digest its release publishes,
the JWAT-Tools archive against the digest of the Maven Central artifact, and the warcio and `six`
distributions through pip's `--require-hashes`.

An external validator is killed after `--timeout` seconds, 600 by default, and reported as
unable to run.

JWAT-Tools installation requires `java`. Warcio installation requires a Python interpreter with
`venv` support. Warchaeology can be installed automatically only on platforms for which its
project publishes release archives.

An explicit executable can be supplied with these environment variables:

- `WARC_VALIDATOR_WARCHAEOLOGY`
- `WARC_VALIDATOR_JWAT_TOOLS`
- `WARC_VALIDATOR_WARCIO`

Use `--validator` more than once to select a subset (`archivindex-raw`, `archivindex-untyped`,
`archivindex-record`, `warc`, `warcat-rs`, `warchaeology`, `jwat-tools`, or `warcio`), and
`-v` to print the errors each `archivindex-warc` layer found, captured subprocess output, and
`warcat-rs` problem data. `-q` logs errors only, the default adds warnings and the summary, and
`-v`, `-vv`, and `-vvv` raise the diagnostic level to informational, debug, and trace.

The process exits with status 0 only when every selected validator completes successfully, with
status 1 when one of them rejects the file or cannot run, and with status 2 when the command
itself cannot do its work, such as when the file cannot be opened. The repository's other
command-line applications use the same three statuses.

[archivindex-warc]: https://github.com/travisbrown/archivindex-warc
[jWAT-Tools]: https://github.com/netarchivesuite/jwat-tools
[warc-crate]: https://crates.io/crates/warc/0.4.0
[warcat-rs-crate]: https://github.com/chfoo/warcat-rs
[warchaeology]: https://github.com/NationalLibraryOfNorway/warchaeology
[warcio]: https://github.com/webrecorder/warcio
