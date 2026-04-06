//! Minimal Bech32m encoding/decoding (BIP-350).
//!
//! Encodes arbitrary bytes as a human-readable string with error detection.
//! Used for Seal addresses: `seal1<bech32m-encoded-hash>`

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32m constant (differs from bech32 by this value).
const BECH32M_CONST: u32 = 0x2bc830a3;

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, gen) in [
            0x3b6a57b2u32,
            0x26508e6d,
            0x1ea119fa,
            0x3d4233dd,
            0x2a1462b3,
        ]
        .iter()
        .enumerate()
        {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut ret: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    ret.push(0);
    ret.extend(hrp.bytes().map(|b| b & 31));
    ret
}

fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let pm = polymod(&values) ^ BECH32M_CONST;
    (0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8).collect()
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == BECH32M_CONST
}

/// Convert 8-bit bytes to 5-bit groups (for bech32 encoding).
fn convert_bits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    for &value in data {
        acc = (acc << 8) | (value as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            ret.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        ret.push(((acc << (5 - bits)) & 31) as u8);
    }
    ret
}

/// Convert 5-bit groups back to 8-bit bytes.
fn convert_bits_5_to_8(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    for &value in data {
        acc = (acc << 5) | (value as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            ret.push(((acc >> bits) & 255) as u8);
        }
    }
    ret
}

/// Encode bytes as a bech32m string with the given human-readable prefix.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let data5 = convert_bits_8_to_5(data);
    let checksum = create_checksum(hrp, &data5);
    let mut result = format!("{}1", hrp);
    for &d in data5.iter().chain(checksum.iter()) {
        result.push(CHARSET[d as usize] as char);
    }
    result
}

/// Decode a bech32m string. Returns (hrp, data_bytes).
pub fn decode(s: &str) -> Result<(String, Vec<u8>), String> {
    let s_lower = s.to_lowercase();
    let pos = s_lower
        .rfind('1')
        .ok_or_else(|| "no separator found".to_string())?;
    let hrp = &s_lower[..pos];
    let data_part = &s_lower[pos + 1..];

    if data_part.len() < 6 {
        return Err("data part too short".into());
    }

    let mut data5 = Vec::new();
    for c in data_part.chars() {
        let idx = CHARSET
            .iter()
            .position(|&ch| ch == c as u8)
            .ok_or_else(|| format!("invalid character: {}", c))?;
        data5.push(idx as u8);
    }

    if !verify_checksum(hrp, &data5) {
        return Err("invalid checksum".into());
    }

    // Remove checksum (last 6 chars)
    let data5 = &data5[..data5.len() - 6];
    let data8 = convert_bits_5_to_8(data5);

    Ok((hrp.to_string(), data8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = encode("seal", &data);
        assert!(encoded.starts_with("seal1"));

        let (hrp, decoded) = decode(&encoded).unwrap();
        assert_eq!(hrp, "seal");
        assert_eq!(&decoded[..data.len()], &data);
    }

    #[test]
    fn test_encode_32_bytes() {
        let data = [42u8; 32]; // Typical address hash
        let encoded = encode("seal", &data);
        assert!(encoded.starts_with("seal1"));
        assert!(encoded.len() > 10);

        let (hrp, decoded) = decode(&encoded).unwrap();
        assert_eq!(hrp, "seal");
        assert_eq!(&decoded[..32], &data);
    }

    #[test]
    fn test_testnet_prefix() {
        let data = [0xab; 32];
        let encoded = encode("sealt", &data);
        assert!(encoded.starts_with("sealt1"));

        let (hrp, _) = decode(&encoded).unwrap();
        assert_eq!(hrp, "sealt");
    }

    #[test]
    fn test_invalid_checksum() {
        let data = [1u8; 32];
        let mut encoded = encode("seal", &data);
        // Corrupt last character
        let len = encoded.len();
        encoded.replace_range(len - 1..len, "q");
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn test_case_insensitive() {
        let data = [0x55; 16];
        let encoded = encode("seal", &data);
        let upper = encoded.to_uppercase();
        // Bech32m decodes case-insensitively
        let (hrp, decoded) = decode(&upper).unwrap();
        assert_eq!(hrp, "seal");
        assert_eq!(&decoded[..16], &data);
    }
}
