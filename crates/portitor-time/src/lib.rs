// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Dates and times as XML Schema writes them (`xsd:date`, `xsd:dateTime`),
//! which both ODRL policies (DSP) and verifiable credentials (DCP) use.
//! Pure functions, no dependencies.

/// A time as the half-open interval it covers, in nanoseconds since
/// 1970-01-01T00:00:00Z: one nanosecond for a date and time, a whole day
/// for a date. Comparing against an interval gives `xsd:date` its natural
/// meaning (`lteq 2030-12-31` includes that whole day).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// First nanosecond covered.
    pub start: i128,
    /// First nanosecond after it.
    pub end: i128,
}

/// Nanoseconds in a second.
pub const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Parses `YYYY-MM-DD` (an `xsd:date`, time zone optional, UTC if absent)
/// or `YYYY-MM-DDThh:mm[:ss[.fraction]]` followed by a time zone (`Z` or
/// `+hh:mm`/`-hh:mm`). A date and time without a time zone is refused: it
/// names a different instant in every time zone. Minutes without seconds
/// are accepted, as in the DSP 2025-1 examples (`2023-12-31T06:00Z`).
#[must_use]
pub fn parse(s: &str) -> Option<Span> {
    let (date, rest) = s.split_at_checked(10)?;
    let days = parse_date(date)?;
    let day_start = i128::from(days) * 86_400 * NANOS_PER_SEC;
    let Some(time) = rest.strip_prefix('T') else {
        // a date, with an optional time zone
        let offset = if rest.is_empty() {
            0
        } else {
            parse_zone(rest)?
        };
        let start = day_start - i128::from(offset) * NANOS_PER_SEC;
        return Some(Span {
            start,
            end: start + 86_400 * NANOS_PER_SEC,
        });
    };
    let zone_at = time.find(['Z', '+', '-'])?;
    let (clock, zone) = time.split_at(zone_at);
    let offset = parse_zone(zone)?;
    let (hm, sec) = match clock.len() {
        5 => (clock, "00"),
        n if n >= 8 && clock.as_bytes()[5] == b':' => (&clock[..5], &clock[6..]),
        _ => return None,
    };
    let hour = number(hm.get(0..2)?, 0, 23)?;
    if hm.as_bytes().get(2) != Some(&b':') {
        return None;
    }
    let minute = number(hm.get(3..5)?, 0, 59)?;
    let (whole, fraction) = sec.split_once('.').unwrap_or((sec, ""));
    if whole.len() != 2 || (sec.contains('.') && fraction.is_empty()) {
        return None;
    }
    let second = number(whole, 0, 59)?;
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // nanoseconds from up to nine fraction digits; more precision is dropped
    let nanos = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(9)
        .fold(0i128, |n, b| n * 10 + i128::from(b - b'0'));
    let start = day_start
        + i128::from(hour * 3_600 + minute * 60 + second - offset) * NANOS_PER_SEC
        + nanos;
    Some(Span {
        start,
        end: start + 1,
    })
}

/// `YYYY-MM-DD` as days since 1970-01-01 (civil-to-days, H. Hinnant).
/// Years 0001 to 9999 only.
fn parse_date(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = number(&text[0..4], 1, 9999)?;
    let month = number(&text[5..7], 1, 12)?;
    let day = number(&text[8..10], 1, 31)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > days_in_month {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// `Z`, `+hh:mm` or `-hh:mm` as seconds east of UTC (at most 14 hours).
fn parse_zone(s: &str) -> Option<i64> {
    if s == "Z" {
        return Some(0);
    }
    let sign = match s.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    if s.len() != 6 || s.as_bytes()[3] != b':' {
        return None;
    }
    let h = number(&s[1..3], 0, 14)?;
    let m = number(&s[4..6], 0, 59)?;
    if h == 14 && m != 0 {
        return None;
    }
    Some(sign * (h * 3_600 + m * 60))
}

/// Decimal digits only (no sign), within `min..=max`.
fn number(s: &str, min: i64, max: i64) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| (min..=max).contains(n))
}

/// A date and time with a time zone (`xsd:dateTimeStamp`, as
/// `validFrom` and `validUntil` of a verifiable credential), as whole
/// seconds since 1970-01-01T00:00:00Z, rounded down. A date alone, or a
/// date and time without a time zone, gives `None`.
#[must_use]
pub fn timestamp_seconds(s: &str) -> Option<i64> {
    let span = parse(s)?;
    if span.end - span.start != 1 {
        return None;
    }
    i64::try_from(span.start.div_euclid(NANOS_PER_SEC)).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(timestamp_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(timestamp_seconds("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(
            timestamp_seconds("2026-11-13T17:00:00.123456Z"),
            Some(1_794_589_200)
        );
        assert_eq!(timestamp_seconds("1969-12-31T23:59:59.5Z"), Some(-1));
        assert_eq!(timestamp_seconds("2026-11-13"), None);
        assert_eq!(timestamp_seconds("2026-11-13T17:00:00"), None);
        assert_eq!(timestamp_seconds("2026-02-30T00:00:00Z"), None);
    }

    #[test]
    fn dates_cover_a_whole_day() {
        let day = parse("2030-12-31").unwrap();
        assert_eq!(day.end - day.start, 86_400 * NANOS_PER_SEC);
    }
}
