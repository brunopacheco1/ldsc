// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Lexical forms of common XML Schema datatypes, for `sh:datatype`.
//!
//! SHACL 4.1.2: a literal whose datatype matches but whose text is not a
//! valid lexical form ("ill-formed", such as `"eighteen"^^xsd:integer`)
//! does not conform. The patterns follow XML Schema 1.1 Part 2
//! (<https://www.w3.org/TR/xmlschema11-2/>), section 3.3 for the
//! primitive types and 3.4 for the integer family. Datatypes not listed
//! here are checked by IRI only.

use regex::Regex;
use std::sync::LazyLock;

/// XSD 1.1 date and time pieces shared by the patterns below.
const YEAR: &str = r"-?([1-9][0-9]{3,}|0[0-9]{3})";
const MONTH: &str = r"(0[1-9]|1[0-2])";
const DAY: &str = r"(0[1-9]|[12][0-9]|3[01])";
const TIME: &str = r"(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?|24:00:00(\.0+)?)";
const ZONE: &str = r"(Z|[+-]((0[0-9]|1[0-3]):[0-5][0-9]|14:00))";

/// Compiles a pattern built from the fixed pieces above, anchored at
/// both ends. They are constants, so `None` would be a bug in this file
/// (a unit test checks that each one compiles); `matches` then refuses
/// every literal of that type instead of stopping the program.
fn anchored(pattern: &str) -> Option<Regex> {
    Regex::new(&format!("^(?:{pattern})$")).ok()
}

/// A compiled lexical pattern, made the first time it is used.
type Pattern = LazyLock<Option<Regex>>;

/// Whether `text` matches the lexical pattern.
fn matches(pattern: &Pattern, text: &str) -> bool {
    match pattern.as_ref() {
        Some(regex) => regex.is_match(text),
        None => false,
    }
}

static BOOLEAN: Pattern = LazyLock::new(|| anchored("true|false|1|0"));
static INTEGER: Pattern = LazyLock::new(|| anchored(r"[+-]?[0-9]+"));
static DECIMAL: Pattern = LazyLock::new(|| anchored(r"[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)"));
static DOUBLE: Pattern =
    LazyLock::new(|| anchored(r"[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([Ee][+-]?[0-9]+)?|[+-]?INF|NaN"));
static DATE: Pattern = LazyLock::new(|| anchored(&format!("{YEAR}-{MONTH}-{DAY}{ZONE}?")));
static DATE_TIME: Pattern =
    LazyLock::new(|| anchored(&format!("{YEAR}-{MONTH}-{DAY}T{TIME}{ZONE}?")));
static DATE_TIME_STAMP: Pattern =
    LazyLock::new(|| anchored(&format!("{YEAR}-{MONTH}-{DAY}T{TIME}{ZONE}")));
static TIME_OF_DAY: Pattern = LazyLock::new(|| anchored(&format!("{TIME}{ZONE}?")));
static G_YEAR: Pattern = LazyLock::new(|| anchored(&format!("{YEAR}{ZONE}?")));
static G_YEAR_MONTH: Pattern = LazyLock::new(|| anchored(&format!("{YEAR}-{MONTH}{ZONE}?")));
static DURATION: Pattern = LazyLock::new(|| {
    anchored(r"-?P([0-9]+Y)?([0-9]+M)?([0-9]+D)?(T([0-9]+H)?([0-9]+M)?([0-9]+(\.[0-9]+)?S)?)?")
});
static HEX_BINARY: Pattern = LazyLock::new(|| anchored("([0-9a-fA-F]{2})*"));

/// Whether `text` is a valid lexical form of the XSD datatype `datatype`
/// (its local name, such as `integer`). `None` if this module does not
/// know the datatype, so the caller checks the datatype IRI only.
pub fn is_valid(datatype: &str, text: &str) -> Option<bool> {
    let valid = match datatype {
        "string" => true,
        "boolean" => matches(&BOOLEAN, text),
        "decimal" => matches(&DECIMAL, text),
        "double" | "float" => matches(&DOUBLE, text),
        "date" => matches(&DATE, text) && day_exists(text),
        "dateTime" => matches(&DATE_TIME, text) && day_exists(text),
        "dateTimeStamp" => matches(&DATE_TIME_STAMP, text) && day_exists(text),
        "time" => matches(&TIME_OF_DAY, text),
        "gYear" => matches(&G_YEAR, text),
        "gYearMonth" => matches(&G_YEAR_MONTH, text),
        "duration" => is_duration(text),
        "anyURI" => is_any_uri(text),
        "hexBinary" => matches(&HEX_BINARY, text),
        integer_type => return integer_in_range(integer_type, text),
    };
    Some(valid)
}

/// The integer family (XSD 1.1 section 3.4): the form of `xsd:integer`
/// plus the range of the derived type. `None` for any other datatype.
fn integer_in_range(datatype: &str, text: &str) -> Option<bool> {
    // (lowest, highest) allowed value; `None` is "no limit"
    let (lowest, highest): (Option<i128>, Option<i128>) = match datatype {
        "integer" => (None, None),
        "nonNegativeInteger" => (Some(0), None),
        "positiveInteger" => (Some(1), None),
        "nonPositiveInteger" => (None, Some(0)),
        "negativeInteger" => (None, Some(-1)),
        "long" => (Some(i128::from(i64::MIN)), Some(i128::from(i64::MAX))),
        "int" => (Some(i128::from(i32::MIN)), Some(i128::from(i32::MAX))),
        "short" => (Some(i128::from(i16::MIN)), Some(i128::from(i16::MAX))),
        "byte" => (Some(i128::from(i8::MIN)), Some(i128::from(i8::MAX))),
        "unsignedLong" => (Some(0), Some(i128::from(u64::MAX))),
        "unsignedInt" => (Some(0), Some(i128::from(u32::MAX))),
        "unsignedShort" => (Some(0), Some(i128::from(u16::MAX))),
        "unsignedByte" => (Some(0), Some(i128::from(u8::MAX))),
        _ => return None,
    };
    if !matches(&INTEGER, text) {
        return Some(false);
    }
    if let Ok(value) = text.parse::<i128>() {
        let above_lowest = lowest.is_none_or(|low| value >= low);
        let below_highest = highest.is_none_or(|high| value <= high);
        return Some(above_lowest && below_highest);
    }
    // more digits than an i128 holds: only an unbounded side can take it
    if text.starts_with('-') {
        Some(lowest.is_none())
    } else {
        Some(highest.is_none())
    }
}

/// The day of a date that matched the patterns above exists in its
/// month: no 30 February, and 29 February only in a leap year.
fn day_exists(text: &str) -> bool {
    // the year may start with '-', so find the month after the year's digits
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let Some((year, rest)) = unsigned.split_once('-') else {
        return false;
    };
    let (Some(month), Some(day)) = (rest.get(0..2), rest.get(3..5)) else {
        return false;
    };
    let (Ok(month), Ok(day)) = (month.parse::<u32>(), day.parse::<u32>()) else {
        return false;
    };
    // the last four digits decide a leap year: 400 divides 10 000
    let last_digits = &year[year.len().saturating_sub(4)..];
    let Ok(year_end) = last_digits.parse::<u32>() else {
        return false;
    };
    let leap = year_end % 4 == 0 && (year_end % 100 != 0 || year_end % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= days_in_month
}

/// `xsd:duration`: the pattern, plus at least one number, and no `T`
/// without a time part after it (XSD 1.1 section 3.3.6.2).
fn is_duration(text: &str) -> bool {
    if !matches(&DURATION, text) || text.ends_with('T') {
        return false;
    }
    text.bytes().any(|byte| byte.is_ascii_digit())
}

/// `xsd:anyURI`. XSD 1.1 accepts almost any text here; the engine
/// refuses spaces and control characters, which no URI reference has.
fn is_any_uri(text: &str) -> bool {
    !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    #[test]
    fn every_pattern_compiles() {
        let patterns = [
            &super::BOOLEAN,
            &super::INTEGER,
            &super::DECIMAL,
            &super::DOUBLE,
            &super::DATE,
            &super::DATE_TIME,
            &super::DATE_TIME_STAMP,
            &super::TIME_OF_DAY,
            &super::G_YEAR,
            &super::G_YEAR_MONTH,
            &super::DURATION,
            &super::HEX_BINARY,
        ];
        for pattern in patterns {
            assert!(pattern.is_some());
        }
    }

    #[test]
    fn integers_and_ranges() {
        assert_eq!(is_valid("integer", "-0012"), Some(true));
        assert_eq!(is_valid("integer", "1.0"), Some(false));
        assert_eq!(is_valid("nonNegativeInteger", "18"), Some(true));
        assert_eq!(is_valid("nonNegativeInteger", "-1"), Some(false));
        assert_eq!(is_valid("nonNegativeInteger", "-0"), Some(true));
        assert_eq!(is_valid("nonNegativeInteger", "eighteen"), Some(false));
        assert_eq!(is_valid("byte", "127"), Some(true));
        assert_eq!(is_valid("byte", "300"), Some(false));
        assert_eq!(is_valid("positiveInteger", "0"), Some(false));
        assert_eq!(
            is_valid(
                "nonNegativeInteger",
                "123456789012345678901234567890123456789012"
            ),
            Some(true)
        );
        assert_eq!(
            is_valid("long", "123456789012345678901234567890123456789012"),
            Some(false)
        );
    }

    #[test]
    fn dates_and_times() {
        assert_eq!(is_valid("date", "2024-02-29"), Some(true));
        assert_eq!(is_valid("date", "2023-02-29"), Some(false));
        assert_eq!(is_valid("date", "2000-02-29Z"), Some(true));
        assert_eq!(is_valid("date", "1900-02-29"), Some(false));
        assert_eq!(is_valid("date", "2024-13-01"), Some(false));
        assert_eq!(is_valid("date", "24-01-01"), Some(false));
        assert_eq!(is_valid("dateTime", "2024-01-01T10:00:00"), Some(true));
        assert_eq!(
            is_valid("dateTime", "2024-01-01T10:00:00.5+02:00"),
            Some(true)
        );
        assert_eq!(is_valid("dateTime", "2024-01-01T10:00"), Some(false));
        assert_eq!(is_valid("dateTime", "2024-01-01"), Some(false));
        assert_eq!(
            is_valid("dateTimeStamp", "2024-01-01T10:00:00"),
            Some(false)
        );
        assert_eq!(
            is_valid("dateTimeStamp", "2024-01-01T10:00:00Z"),
            Some(true)
        );
        assert_eq!(is_valid("gYear", "2024"), Some(true));
        assert_eq!(is_valid("gYear", "-0044"), Some(true));
        assert_eq!(is_valid("gYear", "24"), Some(false));
        assert_eq!(is_valid("gYearMonth", "2024-05"), Some(true));
        assert_eq!(is_valid("time", "24:00:00"), Some(true));
    }

    #[test]
    fn other_types() {
        assert_eq!(is_valid("boolean", "true"), Some(true));
        assert_eq!(is_valid("boolean", "TRUE"), Some(false));
        assert_eq!(is_valid("decimal", "-1.5"), Some(true));
        assert_eq!(is_valid("decimal", "1e3"), Some(false));
        assert_eq!(is_valid("double", "1e3"), Some(true));
        assert_eq!(is_valid("double", "-INF"), Some(true));
        assert_eq!(is_valid("double", "inf"), Some(false));
        assert_eq!(is_valid("duration", "P1Y2M"), Some(true));
        assert_eq!(is_valid("duration", "PT1.5S"), Some(true));
        assert_eq!(is_valid("duration", "P"), Some(false));
        assert_eq!(is_valid("duration", "P1YT"), Some(false));
        assert_eq!(is_valid("duration", "1Y"), Some(false));
        assert_eq!(is_valid("anyURI", "https://example.org/a b"), Some(false));
        assert_eq!(is_valid("anyURI", "relative/path"), Some(true));
        assert_eq!(is_valid("hexBinary", "0FA1"), Some(true));
        assert_eq!(is_valid("hexBinary", "0FA"), Some(false));
        assert_eq!(is_valid("string", "anything"), Some(true));
        assert_eq!(is_valid("gDay", "---01"), None);
    }
}
