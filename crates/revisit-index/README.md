# archivindex-warc-revisit-index

A SQLite index for WARC payload deduplication and conditional HTTP requests. It stores payload
sources and resource validators; the WARC files remain the archive of record.

## Usage

```toml
[dependencies]
archivindex-warc = "0.1"
archivindex-warc-revisit-index = { version = "0.1", features = ["bundled"] }
```

The optional `bundled` feature compiles SQLite from source. Without it, the build links to a system
SQLite library.

```rust,no_run
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::record::extension::NoExtension;
use archivindex_warc_revisit_index::Index;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut index = Index::open("revisits.sqlite3")?;
    let reader = WarcReader::from_path_gzip("archive.warc.gz")?;
    let summary = index.load_records(reader.iter_records::<NoExtension>(), |record, error| {
        eprintln!("skipping {}: {error}", record.value.core().record_id);
    })?;
    println!("{} payload sources added", summary.payloads);
    Ok(())
}
```

`load_records` uses one transaction and rolls it back on a read or database error. Malformed HTTP
heads or undecodable payloads are reported through the callback and counted as skipped. Records
without indexable payloads or resource state, including unsupported or mismatched digests, can
produce no changes without invoking the callback.

For direct access, use `lookup_payload` and `insert_payload` with `payload::RevisitTarget`, and
`lookup_resource` and `update_resource` with the types in `resource`. `begin` groups these
operations in a transaction; dropping it without `commit` rolls it back.

## Scope

Payload lookup normalizes known algorithm labels and digest encodings. The first indexed source for
a digest remains canonical. Truncated and segmented responses cannot establish payload sources.
Digests are verified when their algorithm is enabled; disabled algorithms are trusted as declared.

Resource state holds one representation per target URI, for conditional GET requests. `Variance`
tracks the request fields named by `Vary`. Bulk loading updates resource state only for captures
linked to an earlier complete GET request for the same target. Unresolved requests, HEAD, and other
methods do not establish GET state; response payloads remain eligible for deduplication. The
single-record `index_record` method requires the caller to establish suitability for GET. A declared
nonempty `Vary` prevents reuse because ingestion does not retain selecting field values. Callers
must keep authorization and cookie identities in separate indexes, since servers need not declare
those fields in `Vary`.

The index is derived state. Incompatible schema versions require rebuilding it from the archives;
there is no schema migration. Version 7 also requires rebuilding older indexes that could have
accepted HEAD or POST responses as GET representations. It stores record identities, not file paths
or byte offsets, so retrieving the referenced payload remains the caller's responsibility.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE][license].

[license]: https://github.com/travisbrown/archivindex-warc/blob/main/crates/revisit-index/LICENSE
