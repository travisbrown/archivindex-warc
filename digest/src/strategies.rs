//! Proptest strategies derived from the crate's grammars and type tables.

use proptest::prelude::*;
use proptest::sample::select;

use crate::label::compatibility_label;
use crate::token::is_token_char;
use crate::{Algorithm, Encoding};

/// A string of one to `max` characters drawn from the given set.
fn string_of(chars: Vec<char>, max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(select(chars), 1..=max).prop_map(|chars| chars.into_iter().collect())
}

/// The characters the `token` grammar allows.
fn token_chars() -> Vec<char> {
    (0..=u8::MAX)
        .filter(|&byte| is_token_char(byte))
        .map(char::from)
        .collect()
}

/// A `token`, the grammar of an algorithm label.
pub fn token() -> impl Strategy<Value = String> {
    string_of(token_chars(), 32)
}

/// A `digest-value` as annotation #48 relaxes it: `token` characters plus `=` and `/`.
pub fn digest_value() -> impl Strategy<Value = String> {
    let mut chars = token_chars();
    chars.extend(['=', '/']);

    string_of(chars, 64)
}

/// Any algorithm annotation #80 names.
pub fn algorithm() -> impl Strategy<Value = Algorithm> {
    select(Algorithm::ALL.as_slice())
}

/// Any encoding a digest value may be written in.
pub fn encoding() -> impl Strategy<Value = Encoding> {
    select(Encoding::ALL.as_slice())
}

/// A known algorithm and one of its labels, with each letter in an arbitrary case.
pub fn known_label() -> impl Strategy<Value = (Algorithm, String)> {
    (
        algorithm(),
        any::<bool>(),
        // One case choice per letter; no label has more than six.
        proptest::collection::vec(any::<bool>(), 6),
    )
        .prop_map(|(algorithm, compatibility, uppercase)| {
            let label = if compatibility {
                compatibility_label(algorithm).unwrap_or_else(|| algorithm.label())
            } else {
                algorithm.label()
            };
            let mut uppercase = uppercase.into_iter();
            let spelling = label
                .chars()
                .map(|c| {
                    if c.is_ascii_alphabetic() && uppercase.next().unwrap_or(false) {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();

            (algorithm, spelling)
        })
}

/// A known algorithm and a digest of the length it produces.
pub fn algorithm_and_digest() -> impl Strategy<Value = (Algorithm, Vec<u8>)> {
    algorithm().prop_flat_map(|algorithm| {
        (
            Just(algorithm),
            proptest::collection::vec(any::<u8>(), algorithm.digest_length()),
        )
    })
}
