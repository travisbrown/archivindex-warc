# archivindex-warc

![GitHub last commit](https://img.shields.io/github/last-commit/travisbrown/archivindex-warc)
[![build](https://github.com/travisbrown/archivindex-warc/actions/workflows/ci.yml/badge.svg)](https://github.com/travisbrown/archivindex-warc/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/travisbrown/archivindex-warc/branch/main/graph/badge.svg)](https://codecov.io/gh/travisbrown/archivindex-warc)
[![license](https://img.shields.io/github/license/travisbrown/archivindex-warc)](https://github.com/travisbrown/archivindex-warc/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/archivindex-warc.svg)](https://crates.io/crates/archivindex-warc/)
[![crates.io](https://img.shields.io/crates/d/archivindex-warc)](https://crates.io/crates/archivindex-warc/)
[![API Docs](https://docs.rs/archivindex-warc/badge.svg)](https://docs.rs/archivindex-warc/)

A Rust library for reading and writing WARC 1.0 and 1.1 files. It provides raw, grammar-checked,
and semantic record representations, with support for record-at-a-time gzip compression.

## Status

This project began as a fork of [Reza Akhavan][jedireza]'s [`warc` crate][warc-crate], which is
[no longer maintained][warc-unmaintained]. It now has a substantially different API and
implementation, including WARC 1.1 support, layered validation, semantic record builders, and
record framing for indexed access.

## Repository

The workspace also contains crates for labelled digests, higher-level WARC operations, revisit
indexes, web capture, and command-line applications. The [`validator`](validator/) is a separate
Rust project so that its dependency tree does not constrain the workspace.

## Development

The workspace requires Rust 1.88 or later. Run its tests and build its documentation with:

```console
cargo test --locked --workspace --features archivindex-warc-revisit-index/bundled
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps \
  --features archivindex-warc-revisit-index/bundled
```

The first iteration of the Archivindex project was [supported][archivindex-prototype-fund] by [the
Prototype Fund][prototype-fund].

## License

This project is licensed under the [MIT License](https://opensource.org/license/mit). See
[LICENSE](LICENSE) for the full text.

[archivindex-prototype-fund]: https://www.prototypefund.de/en/projects/archivindex-builder
[jedireza]: https://github.com/jedireza
[prototype-fund]: https://www.prototypefund.de/en/
[warc-crate]: https://crates.io/crates/warc/
[warc-unmaintained]: https://github.com/jedireza/warc/issues/54
