# HTTP/1 and HTTP/2 capture with wreq

An experimental [`archivindex-archiver`](../../crates/archiver) capture backend that performs
byte-exact HTTP/1 capture and reconstructed HTTP/2 capture through BoringSSL with browser-derived
TLS emulation. It is unpublished and lives outside the repository's root workspace, so its
dependency tree cannot constrain the published library crates. Building it needs the Rust version
specified in the [workspace manifest](../Cargo.toml) and a native BoringSSL toolchain: a C and C++
compiler, CMake, and libclang for bindgen.

```rust
use std::sync::Arc;

use archivindex_archiver::{Archiver, Config};
use archivindex_archiver_wreq::WreqBackend;
use wreq_util::Profile;

let backend = WreqBackend::new(Profile::Chrome136);
let archiver = Archiver::with_backend(Config::default(), Arc::new(backend))?;
```

Profiles are wreq-util's `Profile` type, so applications also depend on `wreq-util` at the exact
version this crate pins.

All existing limits, headers, cookies, redirects, challenges, digests, and session settings still
apply. The archiver's `Backend` trait also provides standalone `fetch` and `fetch_by` methods, and
`WreqBackend` has a custom certificate-store setter. Call
`.proxy(Some("socks5h://127.0.0.1:1080"))?` on the backend to use a SOCKS5 proxy with remote DNS.
`socks5://` uses local DNS; both accept username/password authentication. Environment proxy settings
remain disabled. Proxied captures omit the origin IP because the socket peer identifies the proxy.
There is no public arbitrary-client setter: supplying a client with redirects, retries, pooling, or
incompatible protocol settings would invalidate attribution.

From the command-line tool in [`../cli`](../cli), built with its `wreq` feature:

```console
archivindex-archiver archive --backend wreq --profile chrome_136 --output out.warc
```

Profile names are validated with `parse_profile`; an unknown name is an error. The archiver's own
configuration selects only backends it builds itself, so choosing this one is the application's
concern rather than a key in the archiver's config file.

## The wreq fork

This backend uses a `wreq` fork to observe plaintext connection traffic and negotiated TLS versions.
The [workspace manifest](../Cargo.toml) declares the required `wreq` and `btls` patches, and the
[lockfile](../Cargo.lock) pins their revisions. No local checkout is needed.

Applications using this backend in another workspace must copy the manifest's `[patch.crates-io]`
entries into their own workspace manifest. Cargo does not propagate dependency patches, and
`wreq-util` must resolve to the same patched `wreq` as this backend.

## Capture contract and costs

Each fetch owns one client, observer, and current-thread Tokio runtime on a scoped OS thread.
HTTP tasks and connections are disposed before the synchronous call returns. An already-running
system DNS lookup may finish in the background; runtime shutdown does not wait for it and undo
the timeout. The extra thread permits use inside an existing Tokio runtime; this deliberately favors
isolation over client/runtime reuse.

The profile supplies TLS, ALPN, and HTTP/2 settings. HTTPS negotiates HTTP/2 when the server
supports it and otherwise falls back to HTTP/1. Configured request headers, including the default
archiver `User-Agent`, override profile values. Applications that require the profile's user-agent
should use that value in the archiver configuration too, so `warcinfo` describes the actual request.
Browser emulation may improve access but is not guaranteed to make a site accept the request.

Redirects, retries, pooling, automatic proxies, decompression, and the wreq cookie store are off.
The archiver owns application-level follow-ups, including proof-of-work submissions. Every
completed exchange goes through the existing outcome and WARC mapping paths. A supplied byte
body's framing is normalized. `Connection: close` is added only when serializing HTTP/1, and only
when the request has no `Connection` header, as with the built-in recorder.

HTTP/1 request and response blocks retain observed wire bytes, including reason phrases, header
formatting, duplicates, chunk extensions, and trailers. The shared `backend::ResponseCapture`
parser discards interim responses and retains only the final response. A codec error fails an
unfinished capture unless the observer already found the wire boundary or truncation. A failed
write or flush also fails an unfinished capture; a failed shutdown does not invalidate a complete
response.

HTTP/2 records follow the repeated-field form of
[IIPC proposal 42](https://github.com/iipc/warc-specifications/issues/42), also adopted by
[Browsertrix](https://github.com/webrecorder/browsertrix-crawler/pull/715):

- Request and response records carry `WARC-Protocol: h2`. Both HTTP/1 and HTTP/2 captures also
  record the observed TLS version, such as `WARC-Protocol: tls/1.3`, when available. Revisits
  retain the protocols of the current exchange. Plaintext captures omit TLS metadata, and the
  backend never guesses a version from the URI or profile.
- Blocks remain `application/http` with HTTP/1.1 start lines. Pseudo-headers become request method,
  target, and authority (`Host`) or response status. This representation is reconstructed, not a
  transcript of binary HTTP/2 frames. Header ordering and reason phrases in response blocks are
  produced by reconstruction.
- Requests use finalized headers from the codec's header-preservation callback, after defaults,
  framing, and removal of connection-specific headers. The callback delegates ordering and casing
  to the profile. Observed outgoing frame boundaries must show a complete request; another stream
  or connection is rejected rather than silently attributed to the first exchange.
- Responses retain content-encoded data and repeated headers. Body-bearing responses use generated
  chunked framing, replacing the original `Content-Length`, so trailers can be retained separately
  from initial headers. `HEAD`, `204`, and `304` preserve their bodyless semantics and appropriate
  representation lengths. Interim responses are not archived.
- Block digests describe the stored reconstruction. Payload digests describe the retained entity
  bytes with transfer framing removed and content coding preserved. Original HTTP/2 frame bytes,
  HPACK state, and original response framing declarations are not retained.

For either protocol, the response limit counts stored message bytes, including headers and transfer
framing. For HTTP/2 this means reconstructed bytes, not connection traffic or just payload bytes.
A header that cannot fit fails the capture. Exact completion at the cap is distinguished from
truncation; incomplete captures retain `length`, `time`, or `disconnect` reasons. The codec applies
its configured header-list bound to HTTP/2 headers and trailers before reconstruction.

Connect timeout includes DNS and TLS. The overall capture deadline includes DNS too. After
connecting, HTTP/1 idle time tracks plaintext I/O. HTTP/2 idle time tracks outgoing request frames
and decoded response progress, so connection control traffic cannot keep a stalled response alive.
Failures before usable headers fail; timeouts or disconnects after them preserve a truncated
prefix. Completion or a capture limit cancels the operation and disposes its connection. Concurrent
captures cannot share observer state or connections.

## Validation

The built-in recorder and this backend share an
[HTTP/1 conformance suite](../../crates/archiver/tests/support/backend_conformance.rs) covering
framing, truncation, timeouts, proxies, and concurrency. Tests here also cover HTTP/2 reconstruction,
negotiated TLS versions, and WARC output. The fork tests connection observation itself.

CI runs this workspace as its own job, the way it runs the validator. Run it locally with:

```sh
cargo +nightly fmt --manifest-path experimental/Cargo.toml --all -- --check
cargo +stable clippy --locked --manifest-path experimental/Cargo.toml --workspace --all-targets --features archivindex-archiver-cli/wreq -- -D warnings
cargo +stable test --locked --manifest-path experimental/Cargo.toml --workspace --features archivindex-archiver-cli/wreq
RUSTDOCFLAGS='-D warnings' cargo +stable doc --locked --manifest-path experimental/Cargo.toml -p archivindex-archiver-wreq --no-deps
cargo deny --manifest-path experimental/Cargo.toml --config ../deny.toml check
```
