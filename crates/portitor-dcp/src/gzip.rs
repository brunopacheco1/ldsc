// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reads a GZIP stream (RFC 1952), for status lists.
//!
//! The DEFLATE data itself is decompressed by `miniz_oxide`, which
//! forbids unsafe code. This file only reads the GZIP frame around it:
//! the header, and the CRC-32 and length at the end. `flate2` would do the
//! same, but it turns on `miniz_oxide`'s unsafe SIMD checksum code, which
//! Portitor avoids, as it does for `base64` (see `deny.toml`).

/// Why a GZIP stream cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GzipError {
    /// Not a GZIP stream, or it is cut short or damaged.
    Invalid,
    /// It expands past the limit.
    TooLarge,
}

// header flags (RFC 1952, section 2.3.1)
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

/// Decompresses one GZIP member. Fails when the data would expand past
/// `limit` bytes, or when the CRC-32 or length at the end do not match.
pub(crate) fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, GzipError> {
    let body = skip_header(data).ok_or(GzipError::Invalid)?;
    let (deflate, trailer) = body
        .split_at_checked(body.len().checked_sub(8).ok_or(GzipError::Invalid)?)
        .ok_or(GzipError::Invalid)?;
    let out =
        miniz_oxide::inflate::decompress_to_vec_with_limit(deflate, limit).map_err(|e| match e
            .status
        {
            miniz_oxide::inflate::TINFLStatus::HasMoreOutput => GzipError::TooLarge,
            _ => GzipError::Invalid,
        })?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    // ISIZE is the length modulo 2^32 (RFC 1952, section 2.3.1)
    #[allow(clippy::cast_possible_truncation)]
    let expected_size = out.len() as u32;
    if crc32(&out) != crc || size != expected_size {
        return Err(GzipError::Invalid);
    }
    Ok(out)
}

/// The data after the GZIP header, or `None` if the header is invalid.
fn skip_header(data: &[u8]) -> Option<&[u8]> {
    // ID1 ID2 CM FLG MTIME(4) XFL OS; CM 8 is DEFLATE, the only method
    let (header, mut rest) = data.split_at_checked(10)?;
    if header[0..3] != [0x1f, 0x8b, 8] {
        return None;
    }
    let flags = header[3];
    if flags & FEXTRA != 0 {
        let (len, after) = rest.split_at_checked(2)?;
        let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
        rest = after.get(len..)?;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            // a zero-terminated string
            let end = rest.iter().position(|&b| b == 0)?;
            rest = &rest[end + 1..];
        }
    }
    if flags & FHCRC != 0 {
        rest = rest.get(2..)?;
    }
    Some(rest)
}

/// CRC-32 as GZIP uses it (polynomial 0xEDB88320, reflected), one byte at
/// a time with a 256-entry table.
fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            #[allow(clippy::cast_possible_truncation)]
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 == 1 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    let mut crc = !0u32;
    for &byte in data {
        let low_byte = crc.to_le_bytes()[0];
        crc = TABLE[usize::from(low_byte ^ byte)] ^ (crc >> 8);
    }
    !crc
}

/// Compresses `data` as one GZIP member (for status lists an issuer
/// publishes, and for tests).
pub(crate) fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend(crc32(data).to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend((data.len() as u32).to_le_bytes());
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `gzip -n` of the text "hello\n".
    const HELLO: [u8; 26] = [
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0xe7, 0x02, 0x00, 0x20, 0x30, 0x3a, 0x36, 0x06, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn round_trip() {
        let data = vec![7u8; 100_000];
        assert_eq!(decompress(&compress(&data), 100_000).unwrap(), data);
    }

    #[test]
    fn crc32_check_value() {
        // the standard check value of CRC-32
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn reads_gzip() {
        assert_eq!(decompress(&HELLO, 100).unwrap(), b"hello\n");
        assert_eq!(decompress(&HELLO, 3), Err(GzipError::TooLarge));
    }

    #[test]
    fn reads_optional_header_fields() {
        // FEXTRA (2 bytes), FNAME "a", FCOMMENT "b", FHCRC
        let mut data = HELLO[..10].to_vec();
        data[3] = FEXTRA | FNAME | FCOMMENT | FHCRC;
        data.extend([2, 0, 9, 9, b'a', 0, b'b', 0, 0x12, 0x34]);
        data.extend(&HELLO[10..]);
        assert_eq!(decompress(&data, 100).unwrap(), b"hello\n");
    }

    #[test]
    fn refuses_damaged_streams() {
        for cut in [0, 5, 10, 20, 25] {
            assert_eq!(
                decompress(&HELLO[..cut], 100),
                Err(GzipError::Invalid),
                "cut at {cut}"
            );
        }
        let mut bad_crc = HELLO;
        bad_crc[18] ^= 1;
        assert_eq!(decompress(&bad_crc, 100), Err(GzipError::Invalid));
        let mut bad_magic = HELLO;
        bad_magic[0] = 0;
        assert_eq!(decompress(&bad_magic, 100), Err(GzipError::Invalid));
    }
}
