# archivindex-warc

![GitHub last commit][last-commit-badge]
[![build][build-badge]][build]
[![codecov][codecov-badge]][codecov]
[![license][license-badge]][gpl-3.0]
[![crates.io][crates-version-badge]][crates]
[![crates.io][crates-downloads-badge]][crates]
[![API Docs][docs-badge]][docs]

A Rust library for reading and writing WARC 1.0 and 1.1 files. It provides raw, grammar-checked,
and semantic record representations, with support for record-at-a-time gzip compression.

## Status

This project began as a fork of [Reza Akhavan][jedireza]'s [`warc` crate][warc-crate], which is
[no longer maintained][warc-unmaintained]. It now has a substantially different API and
implementation, including WARC 1.1 support, layered validation, semantic record builders, and
record framing for indexed access.

## Repository

The workspace's supporting library crates live under [`crates`](crates/), and its command-line
applications live under [`tools`](tools/). The [`validator`](validator/) is a separate Rust project
so that its dependency tree does not constrain the workspace.

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

The `archivindex-warc` library and the `archivindex-warc-digest` crate it depends on are licensed
under the [MIT License][mit]; see [LICENSE][license] and
[crates/digest/LICENSE][digest-license] for the full text. Every other package in this repository
is licensed under the [GNU General Public License, version 3][gpl-3.0]; see the `LICENSE` file in
each package's directory for the full text.

[archivindex-prototype-fund]: https://www.prototypefund.de/en/projects/archivindex-builder
[build]: https://github.com/travisbrown/archivindex-warc/actions/workflows/ci.yml
[build-badge]: https://github.com/travisbrown/archivindex-warc/actions/workflows/ci.yml/badge.svg
[codecov]: https://codecov.io/gh/travisbrown/archivindex-warc
[digest-license]: crates/digest/LICENSE
[codecov-badge]: https://codecov.io/gh/travisbrown/archivindex-warc/branch/main/graph/badge.svg
[crates]: https://crates.io/crates/archivindex-warc/
[crates-downloads-badge]: https://img.shields.io/crates/d/archivindex-warc
[crates-version-badge]: https://img.shields.io/crates/v/archivindex-warc.svg
[docs]: https://docs.rs/archivindex-warc/
[docs-badge]: https://docs.rs/archivindex-warc/badge.svg
[gpl-3.0]: https://www.gnu.org/licenses/gpl-3.0.html
[jedireza]: https://github.com/jedireza
[last-commit-badge]: https://img.shields.io/github/last-commit/travisbrown/archivindex-warc
[license]: LICENSE
[license-badge]: https://img.shields.io/badge/license-GPL--v3-blue
[mit]: https://opensource.org/license/mit
[prototype-fund]: https://www.prototypefund.de/en/
[warc-crate]: https://crates.io/crates/warc/
[warc-unmaintained]: https://github.com/jedireza/warc/issues/54
