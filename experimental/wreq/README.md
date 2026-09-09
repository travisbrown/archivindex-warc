# Exact HTTP/1 capture with wreq

An experimental [`archivindex-archiver`](../../crates/archiver) capture backend that performs
byte-exact HTTP/1 exchanges through BoringSSL with browser-derived TLS emulation. It is
unpublished and lives outside the repository's root workspace, so its dependency tree cannot
constrain the published library crates. Building it needs Rust 1.98 and a native BoringSSL
toolchain: a C and C++ compiler, CMake, and libclang for bindgen.

```rust
use std::sync::Arc;

use archivindex_archiver::{Archiver, Config};
use archivindex_archiver_backend_wreq::{Profile, WreqRecorder};

let backend = WreqRecorder::new(Profile::Chrome136);
let archiver = Archiver::with_downloader(Config::default(), Arc::new(backend))?;
```

All existing limits, headers, cookies, redirects, challenges, digests, and session settings still
apply. `WreqRecorder` also provides standalone `fetch` and `fetch_by` methods and a custom
certificate-store setter. There is no public arbitrary-client setter: supplying a client with
redirects, retries, pooling, or incompatible protocol settings would invalidate attribution.

From the command-line tool in [`../cli`](../cli), built with its `wreq` feature:

```console
archivindex-archiver archive --backend wreq --profile chrome_136 --output out.warc
```

Profile names are validated with `parse_profile`; an unknown name is an error. The archiver's own
configuration selects only backends it builds itself, so choosing this one is the application's
concern rather than a key in the archiver's config file.

## The wreq fork

This crate needs an observer API that upstream `wreq` has not released, so the workspace manifest
patches `wreq` to a fork branch:

```toml
[patch.crates-io]
wreq = { git = "https://github.com/travisbrown/wreq", branch = "topic/archivindex-observer" }
```

Cargo pins the exact commit in this workspace's lockfile, so builds are reproducible and no local
checkout is needed. A patch rather than a plain dependency, because it must also redirect the copy
of `wreq` reached through `wreq-util`; with two `wreq` crates in the graph the build does not even
compile. The root workspace has no `wreq` dependency and is unaffected.

The fork branch is based on `63429b4229f88adf6f1a71d7c3ffa62b5947f38c`, the source commit of
published `wreq 0.16.1`. Its newer original branch needs unpublished BoringSSL APIs and was
deliberately left unchanged. An upstream release containing the observer is the preferred
endpoint; until then, a patch in this workspace does not reach anyone depending on this crate, so
this crate stays unpublished.

The fork adds a public `connection_observer` module, a `ClientBuilder::connection_observer`
setter, and an internal `conn::observe` layer that the connector installs only when a client
supplies an observer. The existing verbose tracing wrapper is untouched, so unobserved
connections and all trace output are exactly what upstream produces; against upstream the patch
changes four existing lines and adds new files.

`ConnectionObserver::observe` receives connection ID, available socket addresses, HTTP/2
negotiation, newly read bytes, successful writes, EOF, read, write, flush and shutdown errors, and
wrapper disposal. Callbacks borrow their data, must not block or panic, and can run concurrently
across connections. The read wrapper excludes prefilled `ReadBuf` bytes and reports nothing if a
reader shrinks the filled region; vectored writes report only the successfully accepted prefix. A
panic from the final `Closed` callback is contained so a drop during unwinding cannot abort the
process. Observation works independently of tracing and does not log secrets. Proxy tunnel setup
and TLS handshakes are below the hook.

A failed write or flush fails an unfinished capture here, because the request never reached the
peer in full. A failed shutdown does not: closing the write half can fail after a complete
response, and a connection that is genuinely gone reports that again on the read side.

## Capture contract and costs

Each fetch owns one client, observer, and current-thread Tokio runtime on a scoped OS thread.
HTTP tasks and connections are disposed before the synchronous call returns. An already-running
system DNS lookup may finish in the background; runtime shutdown does not wait for it and undo
the timeout. The extra thread permits use inside
an existing Tokio runtime; this deliberately favors isolation over client/runtime reuse.

The profile is applied first, then HTTP/1 is forced. This changes ALPN and does not reproduce a
browser's complete fingerprint. Configured request headers, including the default archiver
`User-Agent`, override profile values. Browser emulation may improve access but is not guaranteed
to make a site accept the request.

Redirects, retries, pooling, automatic proxies, decompression, and the wreq cookie store are off.
The archiver owns application-level follow-ups, including proof-of-work submissions. Every
completed exchange goes through the existing outcome and WARC mapping paths. Request blocks
contain observed writes, including emulation/framing headers. A supplied byte body's framing is
normalized, and `Connection: close` is forced.

The archiver's `recorder::ResponseCapture` owns message framing for every backend:

- Discard interim responses; retain only the final HTTP response.
- Preserve reason phrases, header formatting/duplicates, chunks/extensions, and trailers.
- Bound stored wire bytes, not transfer-decoded body bytes; fail if the head cannot be retained.
- Distinguish complete-at-cap responses from length truncation. Chunked and close-delimited
  responses may need one further read as evidence when the retained prefix reaches the cap.
- Retain a partial body with `length`, `time`, or `disconnect` truncation as appropriate.
- Signal completion and cancel the wreq operation; discard its connection and subsequent bytes.

The wreq HTTP codec still parses the stream to drive I/O. Its decoded frames are discarded, never
reconstructed into archive blocks. A codec error fails an unfinished capture unless the observer
already found the wire boundary or truncation. Some malformed responses accepted by the default
recorder may therefore fail under wreq. No HTTP/2 or normalized capture mode is provided.

Connect timeout includes DNS and TLS. Once connected, an idle timer is reset by observed plaintext
reads/writes. The overall capture deadline includes DNS, unlike the default recorder. Transport
failures before a usable head fail; timeouts after it preserve a time-truncated prefix. Concurrent
captures cannot share observer state or connections.

This crate requires Rust 1.98 and native BoringSSL tooling (C/C++ compiler, CMake,
and libclang for bindgen). The root workspace keeps its own lower MSRV, which this
workspace does not affect.
The first native build is substantially heavier; no performance/access-improvement benchmark has
been claimed.

## Validation

The archiver's exactness contract lives in
[`recorder_conformance.rs`](../../crates/archiver/tests/support/recorder_conformance.rs) and is
included by both the default recorder's loopback suite and this crate's, so both backends are
held to identical framing, truncation, and bytes. It covers trusted HTTPS, request equality,
chunk and trailer framing, interim and duplicate headers, cap edges, cancellation, timeouts,
disconnects, and concurrency. Additional tests here cover invocation inside Tokio, the absence of
hidden redirects and retries, profile-name validation, and byte-for-byte WARC readback of a
redirect followed by a Sucuri challenge and answer. The fork carries its own unit and integration
tests for observation itself.

CI runs this workspace as its own job, the way it runs the validator. Run it locally with:

```sh
cargo +nightly fmt --manifest-path experimental/Cargo.toml --all -- --check
cargo +stable clippy --locked --manifest-path experimental/Cargo.toml --workspace --all-targets --features archivindex-archiver-cli/wreq -- -D warnings
cargo +stable test --locked --manifest-path experimental/Cargo.toml --workspace --features archivindex-archiver-cli/wreq
RUSTDOCFLAGS='-D warnings' cargo +stable doc --locked --manifest-path experimental/Cargo.toml -p archivindex-archiver-backend-wreq --no-deps
cargo deny --manifest-path experimental/Cargo.toml --config ../deny.toml check
```

Validation on 2026-09-09 (macOS ARM64, Rust 1.98 stable; nightly rustfmt):

- This workspace's tests with the backend enabled: **28 passed**.
- Root workspace tests with bundled SQLite: **839 passed**, with no `wreq` in its lockfile.
- Resolution of a tracked-files-only checkout with no local fork present, using
  `cargo metadata --locked`: **succeeded** for both workspaces.
- Stable Clippy with `-D warnings`, rustdoc with `-D warnings`, Rust formatting, TOML
  formatting and lint, and dependency policy: **passed** for both workspaces.

Test runs used `CARGO_INCREMENTAL=0`. Nightly Clippy encounters an existing unrelated
`empty_enums` lint in the root crate's `src/record/extension.rs`; the repository-standard stable
Clippy check passes. Loopback tests and dependency-cache updates need execution outside the
filesystem and network sandbox.
