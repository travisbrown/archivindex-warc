//! The `WARC-Date` value type.
//!
//! Date syntax depends on the declared [`WarcVersion`].

use std::fmt::{Display, Formatter};

use jiff::Timestamp;
use jiff::civil::{Date, DateTime, Time};
use jiff::tz::Offset;

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
/// WARC 1.0 always serializes this value at second precision. WARC 1.1 preserves the precision of
/// parsed values. Converting from [`Timestamp`] or a UTC [`DateTime`] uses the shortest fraction
/// that preserves the instant; [`new`](Self::new) accepts an explicit precision.
///
/// Civil datetimes are interpreted as UTC. This preserves W3C-DTF's full range, including the end
/// of year 9999, which [`Timestamp`] cannot represent. Constructors clamp negative years to the
/// start of year zero so every value can be rendered in the field's grammar.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct WarcDate {
    date_time: DateTime,
    precision: WarcDatePrecision,
}

impl WarcDate {
    /// Parse a date using the grammar of the given WARC version.
    ///
    /// WARC 1.0 accepts only `YYYY-MM-DDThh:mm:ssZ`. For WARC 1.1, this parser accepts precision
    /// from years through fractional seconds, with at most nine fractional digits. Times must use
    /// `Z`; numeric UTC offsets are rejected.
    ///
    /// Returns `None` when `value` does not match the grammar of `version`.
    #[must_use]
    pub fn parse(value: &str, version: WarcVersion) -> Option<Self> {
        match version {
            WarcVersion::V1_0 => Self::parse_v1_0(value),
            WarcVersion::V1_1 => Self::parse_v1_1(value),
        }
    }

    /// Create a date from a UTC civil datetime at the requested serialized precision.
    ///
    /// Negative years saturate to the start of year zero. The datetime is then truncated to the
    /// requested precision. `Fraction` digit counts are clamped to the range one through nine.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "every component comes from a valid date or a truncation of one"
    )]
    pub fn new(date_time: DateTime, precision: WarcDatePrecision) -> Self {
        const TRUNCATED: &str = "invariant violation: a truncated date component is out of range";

        let date_time = date_time.max(jiff::civil::date(0, 1, 1).at(0, 0, 0, 0));
        let (date_time, precision) = match precision {
            WarcDatePrecision::Year => (
                Date::new(date_time.year(), 1, 1)
                    .expect(TRUNCATED)
                    .to_datetime(Time::midnight()),
                precision,
            ),
            WarcDatePrecision::Month => (
                Date::new(date_time.year(), date_time.month(), 1)
                    .expect(TRUNCATED)
                    .to_datetime(Time::midnight()),
                precision,
            ),
            WarcDatePrecision::Day => (date_time.date().to_datetime(Time::midnight()), precision),
            WarcDatePrecision::Minute => (
                date_time
                    .with()
                    .second(0)
                    .subsec_nanosecond(0)
                    .build()
                    .expect(TRUNCATED),
                precision,
            ),
            WarcDatePrecision::Second => (
                date_time
                    .with()
                    .subsec_nanosecond(0)
                    .build()
                    .expect(TRUNCATED),
                precision,
            ),
            WarcDatePrecision::Fraction(digits) => {
                let digits = digits.clamp(1, 9);
                let scale = 10_i32.pow(9 - u32::from(digits));
                (
                    date_time
                        .with()
                        .subsec_nanosecond(date_time.subsec_nanosecond() / scale * scale)
                        .build()
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

    /// Return the UTC civil datetime represented by this date.
    ///
    /// For a reduced-precision WARC 1.1 value, this is the earliest instant denoted by the
    /// serialized date.
    #[must_use]
    pub const fn date_time(self) -> DateTime {
        self.date_time
    }

    /// Return the precision declared by this date.
    #[must_use]
    pub const fn precision(self) -> WarcDatePrecision {
        self.precision
    }

    /// Format this date using the grammar of the given WARC version.
    ///
    /// WARC 1.0 output always has second precision. WARC 1.1 output preserves this value's declared
    /// precision.
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
                WarcDatePrecision::Minute => self.date_time.strftime("%Y-%m-%dT%H:%MZ").to_string(),
                WarcDatePrecision::Second => self.format_seconds(),
                WarcDatePrecision::Fraction(digits) => {
                    let fraction = format!("{:09}", self.date_time.subsec_nanosecond());
                    format!(
                        "{}.{}Z",
                        self.date_time.strftime("%Y-%m-%dT%H:%M:%S"),
                        &fraction[..usize::from(digits)]
                    )
                }
            },
        }
    }

    fn format_seconds(self) -> String {
        self.date_time.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn parse_v1_0(value: &str) -> Option<Self> {
        let body = value.strip_suffix('Z')?;
        if !valid_date_time_layout(body, true) {
            return None;
        }

        let date_time = body.parse().ok()?;
        Some(Self {
            date_time,
            precision: WarcDatePrecision::Second,
        })
    }

    fn parse_v1_1(value: &str) -> Option<Self> {
        let reduced = match value.len() {
            4 if ascii_digits(value) => Some((
                Date::new(value.parse().ok()?, 1, 1).ok()?,
                WarcDatePrecision::Year,
            )),
            7 if value.as_bytes()[4] == b'-'
                && value.get(..4).is_some_and(ascii_digits)
                && value.get(5..).is_some_and(ascii_digits) =>
            {
                Some((
                    Date::new(
                        value.get(..4)?.parse().ok()?,
                        value.get(5..)?.parse().ok()?,
                        1,
                    )
                    .ok()?,
                    WarcDatePrecision::Month,
                ))
            }
            10 if valid_date_layout(value) => Some((value.parse().ok()?, WarcDatePrecision::Day)),
            _ => None,
        };
        if let Some((date, precision)) = reduced {
            return Some(Self {
                date_time: date.to_datetime(Time::midnight()),
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

        let date_time = body.parse().ok()?;

        Some(Self {
            date_time,
            precision,
        })
    }
}

impl From<DateTime> for WarcDate {
    fn from(date_time: DateTime) -> Self {
        let date = Self::new(date_time, WarcDatePrecision::Fraction(9));
        let nanoseconds = date.date_time.subsec_nanosecond();
        let precision = if nanoseconds == 0 {
            WarcDatePrecision::Second
        } else {
            let mut fraction = nanoseconds;
            let mut digits = 9;
            while fraction % 10 == 0 {
                fraction /= 10;
                digits -= 1;
            }
            WarcDatePrecision::Fraction(digits)
        };

        Self { precision, ..date }
    }
}

impl From<Timestamp> for WarcDate {
    fn from(timestamp: Timestamp) -> Self {
        Self::from(Offset::UTC.to_datetime(timestamp))
    }
}

impl From<WarcDate> for DateTime {
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
mod tests;
