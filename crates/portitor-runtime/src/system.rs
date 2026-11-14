// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What a Portitor process takes from the operating system: random ids
//! and the current time.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current time in seconds since 1970 (0 if the clock is set before
/// 1970).
#[must_use]
pub fn now_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since_1970) => since_1970.as_secs(),
        Err(_) => 0,
    }
}

/// `bytes` as lower-case hexadecimal, two characters per byte.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
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

/// A random number in `0..bound` from the operating system's generator,
/// each value equally likely (`bound` 0 gives 0). Used to pick status
/// list positions: W3C Bitstring Status List v1.0, `statusListIndex`,
/// "implementations SHOULD assign indexes randomly".
#[must_use]
pub fn random_below(bound: u64) -> u64 {
    use ring::rand::SecureRandom as _;
    if bound == 0 {
        return 0;
    }
    // numbers at or above the largest multiple of `bound` are drawn
    // again, so that `% bound` favours no value
    let limit = u64::MAX - u64::MAX % bound;
    let generator = ring::rand::SystemRandom::new();
    loop {
        let mut bytes = [0u8; 8];
        // as in `new_uuid`: if the OS has no randomness, zeros are used
        let _ = generator.fill(&mut bytes);
        let drawn = u64::from_le_bytes(bytes);
        if drawn < limit {
            return drawn % bound;
        }
    }
}

/// Seconds since 1970 as XSD dateTime in UTC, for example
/// `2026-11-12T12:00:00Z` (the pure function lives in `portitor-time`, so
/// the domain crates can use it too).
#[must_use]
pub fn xsd_date_time(secs: u64) -> String {
    portitor_time::xsd_date_time(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_xsd_utc() {
        assert_eq!(xsd_date_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(xsd_date_time(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(xsd_date_time(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn ids_are_random_v4_uuids() {
        let a = new_uuid();
        let b = new_uuid();
        assert_ne!(a, b);
        assert_eq!(a.len(), "urn:uuid:".len() + 36);
        assert_eq!(&a[9 + 14..9 + 15], "4");
        assert!(matches!(&a[9 + 19..9 + 20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn random_numbers_stay_below_the_bound() {
        assert_eq!(random_below(0), 0);
        assert_eq!(random_below(1), 0);
        let mut seen = [false; 4];
        for _ in 0..200 {
            let drawn = random_below(4);
            assert!(drawn < 4);
            seen[usize::try_from(drawn).unwrap_or_default()] = true;
        }
        assert_eq!(seen, [true; 4], "200 draws reach every value");
    }

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab]), "000fab");
    }
}
