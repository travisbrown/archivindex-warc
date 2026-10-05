//! The revisit index's persisted representation selection encoding.

use archivindex_http_client::conditional::{SelectingHeaders, Variance};

use crate::Error;

/// Encode for storage, using `None` for invariant responses.
pub fn encode(variance: &Variance) -> Option<String> {
    match variance {
        Variance::Invariant => None,
        Variance::Unselectable => Some("*".to_owned()),
        Variance::Selected(headers) => {
            let mut encoded = String::new();
            for (name, value) in headers.iter() {
                encoded.push_str(name);
                encoded.push('\n');
                match value {
                    // A field value cannot contain a line feed, so the two are unambiguous.
                    Some(value) => {
                        encoded.push('=');
                        encoded.push_str(value);
                    }
                    None => encoded.push('!'),
                }
                encoded.push('\n');
            }
            Some(encoded)
        }
    }
}

/// Decode a stored encoding, which only [`encode`] writes.
pub fn decode(stored: Option<String>) -> Result<Variance, Error> {
    let Some(stored) = stored else {
        return Ok(Variance::Invariant);
    };
    if stored == "*" {
        return Ok(Variance::Unselectable);
    }

    let malformed = || Error::MalformedVariance {
        value: stored.clone(),
    };
    let mut entries = Vec::new();
    let mut fields = stored.strip_suffix('\n').unwrap_or(&stored).split('\n');

    while let Some(name) = fields.next() {
        let value = fields.next().ok_or_else(malformed)?;
        let value = if let Some(value) = value.strip_prefix('=') {
            Some(Box::from(value))
        } else if value == "!" {
            None
        } else {
            return Err(malformed());
        };
        if name.is_empty() {
            return Err(malformed());
        }
        entries.push((Box::from(name), value));
    }

    Ok(Variance::Selected(SelectingHeaders::from_entries(entries)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn variances_round_trip_through_their_encoding() {
        let selected = Variance::declared(Some("User-Agent, Accept-Encoding"), |name| {
            Ok((name == "user-agent").then_some("Desktop=!"))
        });

        for variance in [Variance::Invariant, Variance::Unselectable, selected] {
            assert_eq!(decode(encode(&variance)).ok(), Some(variance));
        }
    }
}
