//! The lint rules, one module per family. The module documentation lists the rules in the order
//! they run.

pub(super) mod block;
pub(super) mod capture;
pub(super) mod digest;
pub(super) mod framing;
pub(super) mod header;
pub(super) mod revisit;
pub(super) mod warcinfo;

use archivindex_warc::record::Record;

/// Whether a record captures an exchange in a protocol whose messages this crate reads.
fn has_http_target(record: &Record) -> bool {
    record.target_uri().is_some_and(|target_uri| {
        let scheme = target_uri.scheme().as_str();
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    })
}
