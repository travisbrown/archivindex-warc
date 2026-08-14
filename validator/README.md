# WARC validator

This standalone Rust application runs a WARC file through several independent validators and
prints one summary.

```console
cargo run --manifest-path validator/Cargo.toml -- example.warc.gz
```

The following validators are provided:

- The [warc][warc-crate] crate parses every record using its typed reader.
- The [warcat-rs][warcat-rs-crate] crate checks WARC structure, required fields, references,
  segments, digests, and compression.
- [Warchaeology][warcheology] is run as `warc validate`.
- [JWAT-Tools][jwat-tools] is run as `jwattools test -e`.
- [warcio] is run as `warcio check` and is primarily a digest checker.

By default the application attempts a local installation when an external validator is not on
`PATH`. Warchaeology release archives, JWAT-Tools, and a Python virtual environment for warcio
are stored below the platform cache directory (for example,
`~/.cache/archivindex-warc-validator/tools` on Linux). Nothing is installed globally. Use
`--no-install` to disable this behavior or `--tools-dir` to choose another directory.

The local installers currently use JWAT-Tools 0.7.1 and warcio 1.8.1; Warchaeology is selected
from the latest published GitHub release for the current platform.

JWAT-Tools installation requires `java`. Warcio installation requires a Python interpreter with
`venv` support. Warchaeology can be installed automatically only on platforms for which its
project publishes release archives.

An explicit executable can be supplied with these environment variables:

- `WARC_VALIDATOR_WARCHAEOLOGY`
- `WARC_VALIDATOR_JWAT_TOOLS`
- `WARC_VALIDATOR_WARCIO`

Use `--validator` more than once to select a subset, and `--verbose` to print captured subprocess
output and `warcat-rs` problem data.

The process exits with status 1 if a validator rejects the file or cannot run, and with status 0
only when every selected validator completes successfully.

[jWAT-Tools]: https://github.com/netarchivesuite/jwat-tools
[warc-crate]: https://crates.io/crates/warc/0.4.0
[warcat-rs-crate]: https://github.com/chfoo/warcat-rs
[warchaeology]: https://github.com/NationalLibraryOfNorway/warchaeology
[warcio]: https://github.com/webrecorder/warcio
