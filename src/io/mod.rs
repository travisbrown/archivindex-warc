//! Reading and writing WARC files.
//!
//! [`read::WarcReader`] reads a byte stream at any record representation level.
//! [`write::WarcWriter`] writes records back to a byte stream.

pub mod read;
pub mod write;

/// One binary megabyte, used for reader and writer buffers.
const MB: usize = 1_048_576;

/// Build a test record with the given field lines and body.
#[cfg(test)]
pub(crate) fn test_record(
    version: crate::version::WarcVersion,
    lines: &[(&str, &str)],
    body: &[u8],
) -> crate::parse::raw::Record {
    let mut headers: Vec<(String, Vec<u8>)> = lines
        .iter()
        .map(|(name, value)| ((*name).to_owned(), format!(" {value}").into_bytes()))
        .collect();
    headers.push((
        "Content-Length".to_owned(),
        format!(" {}", body.len()).into_bytes(),
    ));

    crate::parse::raw::RecordHeader { version, headers }.with_body(body.to_vec())
}
