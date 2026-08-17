//! The type-level WARC version.
//!
//! Most code uses [`WarcVersion`](super::WarcVersion) as a value. A marker lets a type signature
//! select a version at compile time, so that a value only one version defines can be asked for
//! only where that version is the one declared.
//!
//! A marker names a version without holding one. [`WarcVersion::VALUE`] is how code generic
//! over a marker gets the value back:
//!
//! ```
//! use archivindex_warc::version;
//! use archivindex_warc::version::marker;
//!
//! fn declared<V: marker::WarcVersion>() -> version::WarcVersion {
//!     V::VALUE
//! }
//!
//! assert_eq!(declared::<marker::V1_0>(), version::WarcVersion::V1_0);
//! assert_eq!(declared::<marker::V1_1>(), version::WarcVersion::V1_1);
//! ```

/// A WARC version selected at compile time.
///
/// This trait is sealed. Only [`V1_0`] and [`V1_1`] implement it.
pub trait WarcVersion: sealed::Sealed {
    /// The version this type names.
    const VALUE: super::WarcVersion;
}

/// Marker type for WARC 1.0, defined by ISO 28500:2009.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct V1_0;

/// Marker type for WARC 1.1, defined by ISO 28500:2017.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct V1_1;

impl WarcVersion for V1_0 {
    const VALUE: super::WarcVersion = super::WarcVersion::V1_0;
}

impl WarcVersion for V1_1 {
    const VALUE: super::WarcVersion = super::WarcVersion::V1_1;
}

/// Prevent downstream implementations of [`WarcVersion`].
mod sealed {
    /// The bound that cannot be met outside this module.
    pub trait Sealed {}

    impl Sealed for super::V1_0 {}
    impl Sealed for super::V1_1 {}
}

#[cfg(test)]
mod tests {
    use super::{V1_0, V1_1, WarcVersion};

    /// Each marker provides its corresponding runtime version.
    #[test]
    fn each_marker_names_its_version() {
        assert_eq!(V1_0::VALUE, crate::version::WarcVersion::V1_0);
        assert_eq!(V1_1::VALUE, crate::version::WarcVersion::V1_1);
    }
}
