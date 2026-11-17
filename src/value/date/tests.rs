use jiff::civil::{Date, DateTime};
use proptest::prelude::*;
use proptest::property_test;

use super::{WarcDate, WarcDatePrecision};
use crate::prop;
use crate::version::WarcVersion;

fn version_and_date() -> impl Strategy<Value = (WarcVersion, WarcDate)> {
    prop::warc_version().prop_flat_map(|version| (Just(version), prop::warc_date(version)))
}

/// An instant with nonzero values at every supported precision.
fn instant() -> DateTime {
    "2020-07-08T02:52:55.123456789".parse().expect("an instant")
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

/// A year the grammar cannot write saturates to the nearest instant it can.
#[test]
fn new_saturates_a_year_outside_the_range_the_grammar_writes() {
    for (year, precision, expected) in [
        (-40, WarcDatePrecision::Second, "0000-01-01T00:00:00Z"),
        (-40, WarcDatePrecision::Year, "0000"),
    ] {
        let date_time = Date::new(year, 6, 7).expect("a date").at(8, 9, 10, 0);
        let date = WarcDate::new(date_time, precision);

        assert_eq!(date.to_string(), expected, "{year} {precision:?}");
        assert_eq!(
            date,
            WarcDate::parse(expected, WarcVersion::V1_1).expect("a parseable date")
        );
    }

    let negative_year = Date::new(-40, 6, 7).unwrap().at(8, 9, 10, 123);
    assert_eq!(
        WarcDate::from(negative_year).to_string(),
        "0000-01-01T00:00:00Z"
    );
}

/// The WARC grammar includes UTC instants beyond Jiff's timestamp range.
#[test]
fn preserves_the_full_four_digit_year_range() {
    for value in ["0000-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z"] {
        let date = WarcDate::parse(value, WarcVersion::V1_1).unwrap();
        assert_eq!(date.to_string(), value);
        assert_eq!(WarcDate::from(date.date_time()), date);
    }
}

#[test]
fn timestamp_conversion_preserves_fractions_before_the_epoch() {
    let timestamp = "1969-12-31T23:59:59.123456789Z"
        .parse::<jiff::Timestamp>()
        .unwrap();
    let date = WarcDate::from(timestamp);
    assert_eq!(date.to_string(), "1969-12-31T23:59:59.123456789Z");
    assert_eq!(
        jiff::tz::Offset::UTC
            .to_timestamp(date.date_time())
            .unwrap(),
        timestamp
    );
}

/// Jiff accepts leap seconds by constraining them, but WARC's grammar forbids them.
#[test]
fn rejects_leap_seconds() {
    for version in [WarcVersion::V1_0, WarcVersion::V1_1] {
        for value in ["2016-12-31T23:59:60Z", "2016-12-31T23:59:60.5Z"] {
            assert_eq!(WarcDate::parse(value, version), None);
        }
    }
}

#[test]
fn rejects_invalid_calendar_and_clock_components() {
    for version in [WarcVersion::V1_0, WarcVersion::V1_1] {
        for value in [
            "2021-02-29T00:00:00Z",
            "2020-13-01T00:00:00Z",
            "2020-04-31T00:00:00Z",
            "2020-01-01T24:00:00Z",
            "2020-01-01T23:60:00Z",
            "2020-01-01t00:00:00Z",
            "2020-01-01T00:00:00z",
        ] {
            assert_eq!(WarcDate::parse(value, version), None, "{value}");
        }
        assert!(WarcDate::parse("2020-02-29T00:00:00Z", version).is_some());
    }
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

/// A date reads back at the instant and precision it was written with.
#[property_test]
fn round_trips_a_date_the_version_can_spell(
    #[strategy = version_and_date()] (version, date): (WarcVersion, WarcDate),
) {
    let written = date.to_string_for_version(version);

    prop_assert_eq!(WarcDate::parse(&written, version), Some(date));
}
