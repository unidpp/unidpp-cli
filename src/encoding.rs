//! Byte-text codecs for pack payloads: lowercase hex and standard
//! base64 (RFC 4648, with padding). Hand-rolled to keep the CLI's
//! dependency surface at `serde_json` — packs are short, so a
//! table-driven implementation is both exact and cheap.

/// Encode `bytes` as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode hex (whitespace-tolerant, case-insensitive).
pub fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex input has an odd number of digits".to_string());
    }
    let bytes = cleaned
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16);
            let lo = (pair[1] as char).to_digit(16);
            match (hi, lo) {
                (Some(hi), Some(lo)) => Ok(((hi << 4) | lo) as u8),
                _ => Err(format!(
                    "not a hexadecimal string near `{}`",
                    String::from_utf8_lossy(pair)
                )),
            }
        })
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(bytes)
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes` as standard base64 with `=` padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some(26 + (c - b'a') as u32),
        b'0'..=b'9' => Some(52 + (c - b'0') as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64 (padding optional, whitespace-tolerant).
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.len() % 4 == 1 {
        return Err("base64 input length is impossible (4n+1)".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks(4) {
        let mut vals = [0u32; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                // '=' is legal only in the last two positions of a group.
                if i < 2 {
                    return Err("misplaced base64 padding `=`".to_string());
                }
                pad += 1;
            } else {
                if pad > 0 {
                    return Err("base64 data after padding".to_string());
                }
                vals[i] = b64_value(c).ok_or_else(|| {
                    format!(
                        "not base64 near `{}`",
                        String::from_utf8_lossy(&chunk[i..i + 1])
                    )
                })?;
            }
        }
        if pad > 0 && chunk.len() < 4 {
            return Err("truncated base64 group".to_string());
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        // Bytes emitted by this group: 3 for a full unpadded group,
        // minus the padding; a short trailing group carries 2 (3 chars)
        // or 1 (2 chars).
        let emit = (chunk.len() * 3 / 4).min(3 - pad);
        if emit >= 1 {
            out.push((n >> 16) as u8);
        }
        if emit >= 2 {
            out.push((n >> 8) as u8);
        }
        if emit >= 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// A payload text encoding selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Lowercase hex (the default).
    Hex,
    /// Standard base64 with padding.
    Base64,
}

impl Encoding {
    /// Canonical token.
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Hex => "hex",
            Encoding::Base64 => "base64",
        }
    }

    /// Parse an `--encoding` value (case-insensitive).
    pub fn parse(s: &str) -> Result<Encoding, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hex" => Ok(Encoding::Hex),
            "base64" | "b64" => Ok(Encoding::Base64),
            other => Err(format!(
                "unknown encoding `{other}` (expected hex or base64)"
            )),
        }
    }

    /// Encode bytes in this encoding.
    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Encoding::Hex => hex_encode(bytes),
            Encoding::Base64 => base64_encode(bytes),
        }
    }

    /// Decode text in this encoding.
    pub fn decode(self, text: &str) -> Result<Vec<u8>, String> {
        match self {
            Encoding::Hex => hex_decode(text),
            Encoding::Base64 => base64_decode(text),
        }
    }
}

/// Auto-detect the encoding of a pack payload: hex when every
/// non-whitespace character is a hex digit (and the digit count is
/// even), base64 otherwise.
pub fn auto_decode(text: &str) -> Result<(Vec<u8>, Encoding), String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let looks_hex = !cleaned.is_empty()
        && cleaned.len() % 2 == 0
        && cleaned.bytes().all(|b| b.is_ascii_hexdigit());
    if looks_hex {
        let bytes = hex_decode(&cleaned)?;
        Ok((bytes, Encoding::Hex))
    } else {
        let bytes = base64_decode(&cleaned)?;
        Ok((bytes, Encoding::Base64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00u8, 0x0f, 0xff, 0xa5];
        assert_eq!(hex_encode(&bytes), "000fffa5");
        assert_eq!(hex_decode("000FFFA5").unwrap(), bytes);
        assert_eq!(hex_decode("00 0f\nffa5").unwrap(), bytes);
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("").unwrap().is_empty());
    }

    #[test]
    fn base64_round_trip_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        for input in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x00\xff\x10\x80",
        ] {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode(&encoded).unwrap(), input);
            // Padding is optional on decode.
            let trimmed = encoded.trim_end_matches('=');
            assert_eq!(base64_decode(trimmed).unwrap(), input);
        }
        assert!(base64_decode("A").is_err());
        assert!(base64_decode("A===").is_err());
        assert!(base64_decode("=AAA").is_err());
        assert!(base64_decode("AB=C").is_err());
    }

    #[test]
    fn auto_detection_prefers_hex() {
        let bytes = [0xdeu8, 0xad, 0xbe, 0xef];
        let (decoded, enc) = auto_decode("deadbeef").unwrap();
        assert_eq!((decoded, enc), (bytes.to_vec(), Encoding::Hex));
        let (decoded, enc) = auto_decode("3q2+7w==").unwrap();
        assert_eq!((decoded, enc), (bytes.to_vec(), Encoding::Base64));
        assert!(auto_decode("!!!").is_err());
    }

    #[test]
    fn encoding_tokens() {
        assert_eq!(Encoding::parse("HEX").unwrap(), Encoding::Hex);
        assert_eq!(Encoding::parse("b64").unwrap(), Encoding::Base64);
        assert!(Encoding::parse("hex32").is_err());
    }
}
