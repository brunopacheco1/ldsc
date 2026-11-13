// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the connector takes from the operating system: random ids and the
//! current time.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use portitor_dsp::negotiation::provider::Environment;

/// Adapter: identifiers from the OS random generator, time from the clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn new_id(&self) -> String {
        new_uuid()
    }

    fn now(&self) -> String {
        xsd_date_time(now_secs())
    }
}

/// The current time in seconds since 1970 (0 if the clock is set before
/// 1970).
pub(crate) fn now_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since_1970) => since_1970.as_secs(),
        Err(_) => 0,
    }
}

/// `bytes` as lower-case hexadecimal, two characters per byte.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // writing to a String cannot fail
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// A random (version 4) UUID as `urn:uuid:...`.
#[must_use]
pub fn new_uuid() -> String {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    // the OS generator only fails if the OS cannot provide randomness at
    // all; an all-zero id is then still unique enough to be refused later
    // by the store, rather than crashing the connector
    let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
    // RFC 9562: the version (4) in the high bits of byte 6, the variant
    // (binary 10) in the high bits of byte 8
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = hex(&bytes);
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Seconds since 1970 as XSD dateTime in UTC, for example
/// `2026-11-12T12:00:00Z`.
///
/// The date uses Howard Hinnant's `civil_from_days` algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>),
/// with his variable names: it counts in 400-year "eras" (146 097 days
/// each) of years that start on 1 March, so the leap day is the last day
/// of a year.
#[must_use]
pub fn xsd_date_time(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let seconds_today = secs % 86_400;
    let z = days + 719_468; // days since 0000-03-01
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era, 0..=146096
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // year of era
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, from 1 March
    let mp = (5 * doy + 2) / 153; // month, 0 = March
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_today / 3_600,
        seconds_today % 3_600 / 60,
        seconds_today % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_xsd_utc() {
        assert_eq!(xsd_date_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(xsd_date_time(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(xsd_date_time(1_700_000_000), "2023-11-14T22:13:20Z");
        assert!(SystemEnvironment.now().ends_with('Z'));
    }

    #[test]
    fn ids_are_random_v4_uuids() {
        let a = SystemEnvironment.new_id();
        let b = new_uuid();
        assert_ne!(a, b);
        assert_eq!(a.len(), "urn:uuid:".len() + 36);
        assert_eq!(&a[9 + 14..9 + 15], "4");
        assert!(matches!(&a[9 + 19..9 + 20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab]), "000fab");
    }
}
