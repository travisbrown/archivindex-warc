//! The rules, one module for each rule or family of rules the [`lint`](crate::lint) module
//! documentation lists.

pub(super) mod block;
pub(super) mod capture;
pub(super) mod date;
pub(super) mod digest;
pub(super) mod framing;
pub(super) mod header;
pub(super) mod record_id;
pub(super) mod revisit;
pub(super) mod warcinfo;
