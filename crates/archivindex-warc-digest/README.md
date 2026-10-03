# archivindex-warc-digest

WARC labelled digests: parsing, encoding, comparison, and computation. The crate can be used
independently of the WARC reader and writer.

## Usage

```toml
[dependencies]
archivindex-warc-digest = "0.1"
```

Parsing preserves the original spelling. Equality compares normalized algorithm labels and decoded
digest bytes, so equivalent encodings compare equal. Unknown labels remain available as text.

```rust
use archivindex_warc_digest::LabelledDigest;
use archivindex_warc_digest::algorithm::Algorithm;

fn main() -> Result<(), archivindex_warc_digest::Error> {
    let digest = LabelledDigest::parse(
        b"SHA-256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )?;
    assert_eq!(digest.algorithm(), Some(Algorithm::Sha256));
    assert_eq!(digest.decoded().unwrap().len(), 32);
    Ok(())
}
```

`Algorithm::digest` computes a digest when its algorithm is enabled and returns `None` otherwise.
`Algorithm::hasher` supports incremental computation. Use `LabelledDigest::from_digest` to format
computed bytes, or `from_digest_in` to choose an encoding explicitly. Parsing checks the labelled
value's grammar; `decoded()` additionally requires an unambiguous encoding and the correct length
for a known algorithm.

## Features

The default features enable `md5`, `sha1`, and `sha2`. Optional algorithm features are `sha3`,
`blake2`, `blake3`, and `xxh3`; `all-digests` enables all of them. The `serde` feature serializes
algorithms by their labels and encodings by their names.

Parsing, formatting, and comparison remain available with `default-features = false`. Disabling an
algorithm only disables computation, so existing archives can still be inspected.

## License

Licensed under the MIT License. See [LICENSE][license].

[license]: https://github.com/travisbrown/archivindex-warc/blob/main/crates/archivindex-warc-digest/LICENSE
