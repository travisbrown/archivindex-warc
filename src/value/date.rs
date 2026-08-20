//! The `WARC-Date` value type.
//!
//! The standard gives the field a different grammar in each of its versions, so a value is parsed
//! and serialized against a [`WarcVersion`] rather than on its own.

use std::fmt::{Display, Formatter};

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc};

use crate::version::WarcVersion;

/// The precision carried by a [`WarcDate`].
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum WarcDatePrecision {
    /// Year precision, serialized as `YYYY` in WARC 1.1.
    Year,
    /// Month precision, serialized as `YYYY-MM` in WARC 1.1.
    Month,
    /// Day precision, serialized as `YYYY-MM-DD` in WARC 1.1.
    Day,
    /// Minute precision, serialized as `YYYY-MM-DDThh:mmZ` in WARC 1.1.
    Minute,
    /// Second precision, serialized as `YYYY-MM-DDThh:mm:ssZ`.
    Second,
    /// Fractional-second precision with the given number of decimal digits, from one to nine.
    Fraction(u8),
}

/// A WARC date and the precision of its serialized representation.
///
/// WARC 1.0 always serializes this value at second precision. WARC 1.1 preserves the
/// precision of parsed values. Converting from [`DateTime<Utc>`] uses the shortest fractional
/// representation that preserves the instant; [`new`](Self::new) accepts an explicit precision.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct WarcDate {
    date_time: DateTime<Utc>,
    precision: WarcDatePrecision,
}

impl WarcDate {
    /// Parse a date using the grammar of the given WARC version.
    ///
    /// WARC 1.0 accepts only `YYYY-MM-DDThh:mm:ssZ`. WARC 1.1 accepts every W3C-DTF granularity
    /// from a year through a decimal fraction of a second. Both read `w3c-iso8601` as the UTC
    /// timestamp the field definition calls for, so a value carrying a zone offset is refused
    /// rather than converted.
    ///
    /// Returns `None` when `value` does not match the grammar of `version`.
    #[must_use]
    pub fn parse(value: &str, version: WarcVersion) -> Option<Self> {
        match version {
            WarcVersion::V1_0 => Self::parse_v1_0(value),
            WarcVersion::V1_1 => Self::parse_v1_1(value),
        }
    }

    /// Create a date from an instant at the requested serialized precision.
    ///
    /// The instant is truncated to the requested precision. `Fraction` digit counts are clamped
    /// to the range one through nine.
    #[must_use]
    // Every component written here comes from a valid date or is a truncation of one, so nothing
    // here can panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn new(date_time: DateTime<Utc>, precision: WarcDatePrecision) -> Self {
        const TRUNCATED: &str = "invariant violation: a truncated date component is out of range";

        let (date_time, precision) = match precision {
            WarcDatePrecision::Year => (
                NaiveDate::from_ymd_opt(date_time.year(), 1, 1)
                    .expect(TRUNCATED)
                    .and_time(NaiveTime::MIN)
                    .and_utc(),
                precision,
            ),
            WarcDatePrecision::Month => (
                NaiveDate::from_ymd_opt(date_time.year(), date_time.month(), 1)
                    .expect(TRUNCATED)
                    .and_time(NaiveTime::MIN)
                    .and_utc(),
                precision,
            ),
            WarcDatePrecision::Day => (
                date_time.date_naive().and_time(NaiveTime::MIN).and_utc(),
                precision,
            ),
            WarcDatePrecision::Minute => (
                date_time
                    .with_second(0)
                    .and_then(|date_time| date_time.with_nanosecond(0))
                    .expect(TRUNCATED),
                precision,
            ),
            WarcDatePrecision::Second => {
                (date_time.with_nanosecond(0).expect(TRUNCATED), precision)
            }
            WarcDatePrecision::Fraction(digits) => {
                let digits = digits.clamp(1, 9);
                let scale = 10_u32.pow(9 - u32::from(digits));
                (
                    date_time
                        .with_nanosecond(date_time.nanosecond() / scale * scale)
                        .expect(TRUNCATED),
                    WarcDatePrecision::Fraction(digits),
                )
            }
        };

        Self {
            date_time,
            precision,
        }
    }

    /// Return the UTC instant represented by this date.
    ///
    /// For a reduced-precision WARC 1.1 value, this is the earliest instant denoted by the
    /// serialized date.
    #[must_use]
    pub const fn date_time(self) -> DateTime<Utc> {
        self.date_time
    }

    /// Return the precision declared by this date.
    #[must_use]
    pub const fn precision(self) -> WarcDatePrecision {
        self.precision
    }

    /// Format this date using the grammar of the given WARC version.
    ///
    /// WARC 1.0 output always has second precision. WARC 1.1 output preserves this value's
    /// declared precision.
    #[must_use]
    pub fn to_string_for_version(self, version: WarcVersion) -> String {
        match version {
            WarcVersion::V1_0 => self.format_seconds(),
            WarcVersion::V1_1 => match self.precision {
                WarcDatePrecision::Year => format!("{:04}", self.date_time.year()),
                WarcDatePrecision::Month => {
                    format!("{:04}-{:02}", self.date_time.year(), self.date_time.month())
                }
                WarcDatePrecision::Day => format!(
                    "{:04}-{:02}-{:02}",
                    self.date_time.year(),
                    self.date_time.month(),
                    self.date_time.day()
                ),
                WarcDatePrecision::Minute => self.date_time.format("%Y-%m-%dT%H:%MZ").to_string(),
                WarcDatePrecision::Second => self.format_seconds(),
                WarcDatePrecision::Fraction(digits) => {
                    let fraction = format!("{:09}", self.date_time.nanosecond());
                    format!(
                        "{}.{}Z",
                        self.date_time.format("%Y-%m-%dT%H:%M:%S"),
                        &fraction[..usize::from(digits)]
                    )
                }
            },
        }
    }

    fn format_seconds(self) -> String {
        self.date_time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn parse_v1_0(value: &str) -> Option<Self> {
        let body = value.strip_suffix('Z')?;
        if !valid_date_time_layout(body, true) {
            return None;
        }

        let date_time = NaiveDateTime::parse_from_str(body, "%Y-%m-%dT%H:%M:%S")
            .ok()?
            .and_utc();
        Some(Self {
            date_time,
            precision: WarcDatePrecision::Second,
        })
    }

    fn parse_v1_1(value: &str) -> Option<Self> {
        let reduced = match value.len() {
            4 if ascii_digits(value) => Some((
                NaiveDate::from_ymd_opt(value.parse().ok()?, 1, 1)?,
                WarcDatePrecision::Year,
            )),
            7 if value.as_bytes()[4] == b'-'
                && value.get(..4).is_some_and(ascii_digits)
                && value.get(5..).is_some_and(ascii_digits) =>
            {
                Some((
                    NaiveDate::from_ymd_opt(
                        value.get(..4)?.parse().ok()?,
                        value.get(5..)?.parse().ok()?,
                        1,
                    )?,
                    WarcDatePrecision::Month,
                ))
            }
            10 if valid_date_layout(value) => Some((
                NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()?,
                WarcDatePrecision::Day,
            )),
            _ => None,
        };
        if let Some((date, precision)) = reduced {
            return Some(Self {
                date_time: date.and_time(NaiveTime::MIN).and_utc(),
                precision,
            });
        }

        let body = value.strip_suffix('Z')?;
        let precision = match body.len() {
            16 if valid_date_time_layout(body, false) => WarcDatePrecision::Minute,
            19 if valid_date_time_layout(body, true) => WarcDatePrecision::Second,
            21..=29
                if body.as_bytes()[19] == b'.'
                    && body
                        .get(..19)
                        .is_some_and(|value| valid_date_time_layout(value, true))
                    && body.get(20..).is_some_and(ascii_digits) =>
            {
                WarcDatePrecision::Fraction(u8::try_from(body.len() - 20).ok()?)
            }
            _ => return None,
        };

        let layout = match precision {
            WarcDatePrecision::Minute => "%Y-%m-%dT%H:%M",
            WarcDatePrecision::Second => "%Y-%m-%dT%H:%M:%S",
            WarcDatePrecision::Fraction(_) => "%Y-%m-%dT%H:%M:%S%.f",
            _ => unreachable!("reduced precisions returned above"),
        };
        let date_time = NaiveDateTime::parse_from_str(body, layout).ok()?.and_utc();

        Some(Self {
            date_time,
            precision,
        })
    }
}

impl From<DateTime<Utc>> for WarcDate {
    fn from(date_time: DateTime<Utc>) -> Self {
        let nanoseconds = date_time.nanosecond();
        let precision = if nanoseconds == 0 {
            WarcDatePrecision::Second
        } else {
            let mut fraction = nanoseconds;
            let mut digits = 9;
            while fraction.is_multiple_of(10) {
                fraction /= 10;
                digits -= 1;
            }
            WarcDatePrecision::Fraction(digits)
        };

        Self::new(date_time, precision)
    }
}

impl From<WarcDate> for DateTime<Utc> {
    fn from(date: WarcDate) -> Self {
        date.date_time
    }
}

impl Display for WarcDate {
    /// Display using the WARC 1.1 grammar, which can represent every supported precision.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_string_for_version(WarcVersion::V1_1))
    }
}

fn ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_date_layout(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.get(..4).is_some_and(ascii_digits)
        && value.get(5..7).is_some_and(ascii_digits)
        && value.get(8..).is_some_and(ascii_digits)
}

fn valid_date_time_layout(value: &str, seconds: bool) -> bool {
    let expected_len = if seconds { 19 } else { 16 };
    value.len() == expected_len
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && (!seconds || value.as_bytes()[16] == b':')
        && value.get(..10).is_some_and(valid_date_layout)
        && value.get(11..13).is_some_and(ascii_digits)
        && value.get(14..16).is_some_and(ascii_digits)
        && (!seconds
            || (value.get(17..).is_some_and(ascii_digits)
                && value
                    .get(17..)
                    .and_then(|value| value.parse::<u8>().ok())
                    .is_some_and(|second| second <= 59)))
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::{WarcDate, WarcDatePrecision};
    use crate::version::WarcVersion;

    /// An instant with nonzero values at every supported precision.
    fn instant() -> DateTime<Utc> {
        "2020-07-08T02:52:55.123456789Z"
            .parse()
            .expect("an instant")
    }

    #[test]
    fn new_truncates_the_instant_to_the_requested_precision() {
        for (precision, expected) in [
            (WarcDatePrecision::Year, "2020"),
            (WarcDatePrecision::Month, "2020-07"),
            (WarcDatePrecision::Day, "2020-07-08"),
            (WarcDatePrecision::Minute, "2020-07-08T02:52Z"),
            (WarcDatePrecision::Second, "2020-07-08T02:52:55Z"),
            (WarcDatePrecision::Fraction(3), "2020-07-08T02:52:55.123Z"),
            (
                WarcDatePrecision::Fraction(9),
                "2020-07-08T02:52:55.123456789Z",
            ),
        ] {
            let date = WarcDate::new(instant(), precision);

            assert_eq!(date.to_string(), expected, "{precision:?}");
            // The truncated instant and the kept precision are what parsing the rendering gives.
            assert_eq!(
                date,
                WarcDate::parse(expected, WarcVersion::V1_1).expect("a parseable date"),
                "{precision:?}"
            );
        }
    }

    #[test]
    fn new_clamps_a_fraction_digit_count_the_grammar_does_not_have() {
        assert_eq!(
            WarcDate::new(instant(), WarcDatePrecision::Fraction(0)).to_string(),
            "2020-07-08T02:52:55.1Z"
        );
        assert_eq!(
            WarcDate::new(instant(), WarcDatePrecision::Fraction(12)).to_string(),
            "2020-07-08T02:52:55.123456789Z"
        );
    }

    #[test]
    fn warc_1_0_accepts_only_second_precision() {
        let valid = WarcDate::parse("2020-07-08T02:52:55Z", WarcVersion::V1_0).unwrap();
        assert_eq!(valid.precision(), WarcDatePrecision::Second);

        for invalid in [
            "2020",
            "2020-07",
            "2020-07-08",
            "2020-07-08T02:52Z",
            "2020-07-08T02:52:55.1Z",
            "2020-07-08T03:52:55+01:00",
        ] {
            assert_eq!(
                WarcDate::parse(invalid, WarcVersion::V1_0),
                None,
                "{invalid}"
            );
        }
    }

    #[test]
    fn warc_1_1_preserves_granularity() {
        for (value, expected) in [
            ("2020", "2020"),
            ("2020-07", "2020-07"),
            ("2020-07-08", "2020-07-08"),
            ("2020-07-08T02:52Z", "2020-07-08T02:52Z"),
            ("2020-07-08T02:52:55Z", "2020-07-08T02:52:55Z"),
            ("2020-07-08T02:52:55.100Z", "2020-07-08T02:52:55.100Z"),
            (
                "2020-07-08T02:52:55.123456789Z",
                "2020-07-08T02:52:55.123456789Z",
            ),
        ] {
            assert_eq!(
                WarcDate::parse(value, WarcVersion::V1_1)
                    .unwrap()
                    .to_string(),
                expected,
                "{value}"
            );
        }

        for invalid in ["2020-07-08T02:52:55.1234567890Z", "éabcde"] {
            assert_eq!(
                WarcDate::parse(invalid, WarcVersion::V1_1),
                None,
                "{invalid}"
            );
        }
    }

    /// `w3c-iso8601` is a UTC timestamp, so a zone designator other than `Z` is outside the field's
    /// grammar even though [W3CDTF] admits one.
    ///
    /// [W3CDTF]: https://www.w3.org/TR/NOTE-datetime
    #[test]
    fn warc_1_1_requires_utc() {
        for invalid in [
            "2020-07-08T02:52+01:00",
            "2020-07-08T02:52:55+01:00",
            "2020-07-08T02:52:55.100-05:00",
            "2020-07-08T02:52:55",
        ] {
            assert_eq!(
                WarcDate::parse(invalid, WarcVersion::V1_1),
                None,
                "{invalid}"
            );
        }
    }

    #[test]
    fn warc_1_0_formatting_uses_seconds() {
        let date = WarcDate::parse("2020-07-08T02:52:55.123456Z", WarcVersion::V1_1).unwrap();
        assert_eq!(
            date.to_string_for_version(WarcVersion::V1_0),
            "2020-07-08T02:52:55Z"
        );
    }
}
