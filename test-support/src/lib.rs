//! Test fixtures shared by this repository's packages.

/// A WARC 1.1 record with the given fields, framed by the body's length.
#[must_use]
pub fn render(fields: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut record = b"WARC/1.1\r\n".to_vec();
    for (name, value) in fields {
        record.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    record.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    record.extend_from_slice(body.as_bytes());
    record.extend_from_slice(b"\r\n\r\n");

    record
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn frames_the_body_by_its_length() {
        assert_eq!(
            render(&[("WARC-Type", "resource")], "body"),
            b"WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: 4\r\n\r\nbody\r\n\r\n"
        );
    }
}
