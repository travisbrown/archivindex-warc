# archivindex-warc-identifier

Versioned content-derived WARC record identifiers under the Archivindex identity scheme.

## Usage

```rust,no_run
use archivindex_warc::io::read::WarcReader;
use archivindex_warc_identifier::IdentityV1;

let reader = WarcReader::from_path("archive.warc")?;
for record in reader.iter_raw_records().records() {
    let record = record?;
    let identity = IdentityV1::new(&record)?;
    let preimage = identity.preimage();
    println!("{} ({} preimage bytes)", identity.uri(), preimage.len());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`IdentityV1::new` validates identity fields and hashes the stored block once. The identity borrows
URI text from the record. `preimage()` returns the bytes used to derive the identifier, and `uri()`
returns the identifier as a `fluent_uri::Uri<String>`. Both methods are infallible after
construction. `IdentityV1::from_record` accepts a typed `archivindex_warc::record::Record` and uses
its rendered block without first converting the whole record to raw form.

Use `record_id(&record)` to generate a URI directly from a raw record under version 1 of the scheme.

## Identity policy

A record's identity is its type, capture date, target URI, and stored content block. A revisit's
block stands for content stored elsewhere, so its identity also includes the capture date and target
URI of its original, which it must declare in `WARC-Refers-To-Date` and `WARC-Refers-To-Target-URI`.
A revisit's profile is excluded: the archiver uses `server-not-modified` exactly when the response
is a `304`, and the block keeps that response's head.

Dates use unsigned Unix **microseconds**, matching the archiver's capture precision. The archiver
never writes a date before 1970, so such dates are refused. Finer input precision is truncated
toward the earlier microsecond. Date spelling and declared precision do not affect identity: `.123Z`
and `.123000Z` identify the same instant, and a reduced-precision date uses the beginning of its
period. The same rules apply to `WARC-Refers-To-Date`.

An ID depends only on its own record. References to other records (`WARC-Refers-To`,
`WARC-Warcinfo-ID`, and `WARC-Concurrent-To`) are excluded. The capture date, target URI, and block
already distinguish captures, and a revisit names its original by capture date and target URI.
Excluding references means IDs can be derived in any order, a record keeps its ID when it is
rewritten under a different `warcinfo` record or when the records it names are reidentified, and
records may name each other without forming a cycle.

The block hash is always SHA-256 of the complete stored WARC content block. A revisit hashes its own
stored block. Declared block and payload digests are excluded, so changing digest algorithms or
encodings does not change identity. The record's old ID, filename, IP address, content-type
annotations, truncation annotations, and extension fields are also excluded. This deliberately
identifies captures under the properties listed here rather than every possible difference between
WARC records.

## Version 1 byte format

An ID is `https://archivindex.org/record/<hash>`, where `<hash>` is the lowercase hexadecimal
SHA-256 of the following fields in order, with no tags, padding, field count, or terminator.
Integers are big-endian. A URI is encoded as its `u64` byte length followed by its exact bytes.

| Field        | Encoding                                                       |
| ------------ | -------------------------------------------------------------- |
| Version      | `u8`, currently 1                                              |
| Record type  | `u8`, assigned below                                           |
| Capture date | `u64`, Unix microseconds from `WARC-Date`                      |
| Target URI   | `WARC-Target-URI` as a URI, or a zero length when it is absent |
| Block hash   | 32 bytes, SHA-256 of the stored block                          |

A URI always has a scheme, so an absent target URI cannot be confused with a present one. These five
fields are the whole preimage of every record except a revisit, which continues with its original
capture:

| Field                 | Encoding                                            |
| --------------------- | --------------------------------------------------- |
| Original capture date | `u64`, Unix microseconds from `WARC-Refers-To-Date` |
| Original target URI   | `WARC-Refers-To-Target-URI` as a URI                |

Record type bytes are `warcinfo` = 1, `request` = 2, `response` = 3, `metadata` = 4, `revisit` = 5.
The archiver writes no other record types, so `resource`, `conversion`, `continuation`, and
extension records are refused. It also never writes segmented records, so any record carrying
`WARC-Segment-Number`, `WARC-Segment-Origin-ID`, or `WARC-Segment-Total-Length` is refused.

URI brackets and surrounding header whitespace are excluded. URI spelling is otherwise exact,
including percent escapes. Header name case and header order do not affect identity. A malformed or
repeated identity field is refused. These bytes define version 1 of the scheme.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
