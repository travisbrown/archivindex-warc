# archivindex-warc

![GitHub last commit](https://img.shields.io/github/last-commit/travisbrown/archivindex-warc)
[![build](https://github.com/travisbrown/archivindex-warc/actions/workflows/ci.yml/badge.svg)](https://github.com/travisbrown/archivindex-warc/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/travisbrown/archivindex-warc/branch/main/graph/badge.svg)](https://codecov.io/gh/travisbrown/archivindex-warc)
[![license](https://img.shields.io/github/license/travisbrown/archivindex-warc)](https://github.com/travisbrown/archivindex-warc/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/archivindex-warc.svg)](https://crates.io/crates/archivindex-warc/)
[![crates.io](https://img.shields.io/crates/d/archivindex-warc)](https://crates.io/crates/archivindex-warc/)
[![API Docs](https://docs.rs/archivindex-warc/badge.svg)](https://docs.rs/archivindex-warc/)

A Rust library for reading and writing WARC files.

## Status

This project is a fork of [Reza Akhavan][jedireza]'s [`warc`][warc-repo] [crate][warc-crate], which
seems to be [unmaintained][warc-unmaintained]. It merges several open pull requests from the `warc`
repository, but also includes many other changes, including the following:

- Migration from [`libflate`][libflate] to [`flate2`][flate2]
- Updates for all dependencies (including [`nom`][nom], from 7 to 8)
- [WARC 1.1][warc-1.1] support
- Many minor bug fixes, mostly related to edge cases
- A separate [`validator`](validator/) Rust project providing an easy way to compare several
  independent WARC validators

The first iteration of the Archivindex project was [supported][archivindex-prototype-fund] by [the
Prototype Fund][prototype-fund].

## License

This project is licensed under the [MIT License](https://opensource.org/license/mit). See
[LICENSE](LICENSE) for the full text.

[archivindex-prototype-fund]: https://www.prototypefund.de/en/projects/archivindex-builder
[flate2]: https://crates.io/crates/flate2
[jedireza]: https://github.com/jedireza
[libflate]: https://crates.io/crates/libflate
[nom]: https://crates.io/crates/nom
[prototype-fund]: https://www.prototypefund.de/en/
[warc-1.1]: https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/
[warc-crate]: https://crates.io/crates/warc/
[warc-repo]: https://github.com/jedireza/warc
[warc-unmaintained]: https://github.com/jedireza/warc/issues/54
