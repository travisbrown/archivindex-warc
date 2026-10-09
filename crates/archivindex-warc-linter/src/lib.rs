//! Lint a WARC file against standard requirements and additional conventions.
//!
//! [`Linter`] reads a file at the semantic level and checks every successfully parsed record
//! against these rules:
//!
//! 1. Each record occupies one gzip member. This check requires a reader that tracks members.
//! 2. No extra blank lines appear before, between, or after records.
//! 3. Standard headers use canonical order, followed by extension fields. Repeated and extension
//!    fields retain their relative order.
//! 4. Record identifiers are unique within the file, as clause 5.2 of the standard requires.
//! 5. Record dates are nondecreasing.
//! 6. Nonempty blocks declare the `Content-Type` their record type calls for:
//!    `application/warc-fields` for `warcinfo` and `metadata`,
//!    `application/http;msgtype=request` for an HTTP `request`, and
//!    `application/http;msgtype=response` for an HTTP `response` or `revisit`. Continuations omit
//!    the field.
//! 7. Every record declares a block digest.
//! 8. Resources, conversions, and HTTP requests and responses declare payload digests.
//! 9. Each `WARC-Block-Digest` is the digest of the record's block, and each
//!    `WARC-Payload-Digest` the digest of the payload that block determines. A digest under an
//!    algorithm this build does not compute is not checked, and neither is the payload digest of a
//!    segment or a truncated record whose payload cannot be extracted.
//! 10. A record identifier is a UUID URN, or is the one the
//!     [Archivindex identity scheme](archivindex_warc_identifier) derives from the record under
//!     version 1, its only version. [`Linter::require_archivindex_ids`] refuses the UUID.
//! 11. The first record is warcinfo.
//! 12. Each other record references the most recent warcinfo in `WARC-Warcinfo-ID`.
//! 13. Each warcinfo body has an `isPartOf` collection identifier: host, optional path parts, and
//!     a numeric timestamp joined by `-`. Path parts contain no dots. `WARC-Filename` is that
//!     identifier plus `.warc` or `.warc.gz`, matching the input compression.
//! 14. Request target hosts match the host in the current collection identifier, when valid.
//! 15. Captures contain consecutive request, response (or revisit), and metadata records. The
//!     latter two link to their predecessors with `WARC-Concurrent-To` and repeat the request's
//!     target URI. Capture metadata includes `fetchTimeMs`.
//! 16. Records outside the response and metadata positions of a capture omit `WARC-Concurrent-To`.
//! 17. Nonempty identical-payload-digest revisit blocks declare `WARC-Truncated: length`, as
//!     clause 6.7.2 of the standard asks of the writer.
//! 18. Revisits carry `WARC-Refers-To`, `WARC-Refers-To-Target-URI`, and `WARC-Refers-To-Date`.
//! 19. Revisit references point to earlier records in this file, even if external references
//!     would be valid under the standard.
//!
//! The rules go from the shape of the file, through what each record's header and block hold, to
//! how records relate: to the `warcinfo` record governing them, within a capture, and to the record
//! a `revisit` stands for. A record's findings come in that order.
//!
//! Each rule a record breaks is one [`Finding`]. A record that breaks none is reported by its
//! identifier alone.
//!
//! Add project-specific checks with [`Linter::with_rule`]. Custom rules can report record or file
//! findings as errors or warnings.

mod lint;

pub use lint::{Checked, Custom, Finding, Findings, Linter, Rule, Severity, Subject, Violation};
