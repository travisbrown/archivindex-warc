//! The bounded SHA-256 search the proof-of-work challenges share.

use std::time::Instant;

use sha2::{Digest, Sha256};

/// The maximum number of candidates tested per challenge.
const MAX_ATTEMPTS: u64 = 10_000_000;

/// Search for a candidate whose digest `accepts`, hashing its decimal digits after `prefix`.
///
/// Each attempt resumes from the prefix state and renders the candidate into one buffer, so the
/// search allocates nothing. Check the deadline before each batch of 256 attempts.
pub fn solve(
    prefix: &Sha256,
    deadline: Option<Instant>,
    accepts: impl Fn(&[u8]) -> bool,
) -> Option<(u64, [u8; 32])> {
    let mut buffer = [0; 20];

    (1..=MAX_ATTEMPTS)
        .take_while(|candidate| {
            (candidate - 1) % 256 != 0 || deadline.is_none_or(|deadline| Instant::now() < deadline)
        })
        .find_map(|candidate| {
            let mut hasher = prefix.clone();
            hasher.update(decimal(candidate, &mut buffer));
            let digest = hasher.finalize();
            accepts(&digest).then(|| (candidate, digest.into()))
        })
}

/// Write a decimal integer into a reused buffer, which is wide enough for any `u64`.
fn decimal(value: u64, buffer: &mut [u8; 20]) -> &[u8] {
    let mut index = buffer.len();
    let mut remaining = value;

    loop {
        index -= 1;
        buffer[index] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            return &buffer[index..];
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use sha2::{Digest, Sha256};

    use super::{decimal, solve};

    #[test]
    fn expired_deadlines_prevent_work_and_running_searches_stop() {
        let prefix = Sha256::new();
        assert!(
            solve(&prefix, Some(Instant::now()), |_| panic!(
                "expired search ran"
            ))
            .is_none()
        );
        let deadline = Instant::now() + Duration::from_millis(2);
        let attempts = std::cell::Cell::new(0);
        assert!(
            solve(&prefix, Some(deadline), |_| {
                attempts.set(attempts.get() + 1);
                false
            })
            .is_none()
        );
        assert!(attempts.get() < super::MAX_ATTEMPTS);
        assert!(Instant::now() >= deadline);
    }

    #[test]
    fn decimals_are_rendered_without_allocating() {
        let mut buffer = [0; 20];

        assert_eq!(decimal(0, &mut buffer), b"0");
        assert_eq!(decimal(1, &mut buffer), b"1");
        assert_eq!(decimal(u64::MAX, &mut buffer), b"18446744073709551615");
    }

    #[test]
    fn the_first_accepted_candidate_is_returned_with_its_digest() {
        let mut prefix = Sha256::new();
        prefix.update(b"prefix:");

        let (candidate, digest) =
            solve(&prefix, None, |digest| digest[0] == 0).expect("a bounded solution");

        assert_eq!(digest[0], 0);
        assert_eq!(
            digest.as_slice(),
            Sha256::digest(format!("prefix:{candidate}")).as_slice()
        );
        assert!(
            (1..candidate).all(|earlier| { Sha256::digest(format!("prefix:{earlier}"))[0] != 0 })
        );
    }
}
