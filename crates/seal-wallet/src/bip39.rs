//! BIP-39 mnemonic encoding — 24 words for 256 bits of entropy.
//!
//! Standard BIP-39 encoding:
//! 1. Take 256 bits of entropy (32 bytes)
//! 2. Compute checksum: first byte of SHA3-256(entropy) (8 bits)
//! 3. Concatenate: 256 + 8 = 264 bits
//! 4. Split into 24 groups of 11 bits each
//! 5. Each 11-bit value indexes into the 2048-word list
//!
//! We use SHA3-256 for the checksum (BIP-39 uses SHA-256, but
//! we use SHA3 consistently throughout Seal for PQC alignment).

use seal_crypto::hash::sha3_256;

include!("bip39_words.rs");

/// Encode 32 bytes as 24 BIP-39 mnemonic words.
pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> Vec<String> {
    // Checksum: first byte of SHA3-256(entropy)
    let checksum = sha3_256(entropy).0[0];

    // Build 264-bit value: 256 bits entropy + 8 bits checksum
    let mut bits = Vec::with_capacity(264);
    for byte in entropy {
        for bit in (0..8).rev() {
            bits.push((byte >> bit) & 1);
        }
    }
    for bit in (0..8).rev() {
        bits.push((checksum >> bit) & 1);
    }

    // Split into 24 groups of 11 bits → word indices
    let mut words = Vec::with_capacity(24);
    for chunk in bits.chunks(11) {
        let mut index: usize = 0;
        for &bit in chunk {
            index = (index << 1) | (bit as usize);
        }
        words.push(BIP39_ENGLISH[index].to_string());
    }
    words
}

/// Decode 24 BIP-39 mnemonic words back to 32 bytes of entropy.
pub fn mnemonic_to_entropy(words: &[String]) -> Result<[u8; 32], String> {
    if words.len() != 24 {
        return Err(format!("expected 24 words, got {}", words.len()));
    }

    // Map words to 11-bit indices
    let mut bits = Vec::with_capacity(264);
    for word in words {
        let lower = word.to_lowercase();
        let index = BIP39_ENGLISH
            .iter()
            .position(|&w| w == lower)
            .ok_or_else(|| format!("unknown BIP-39 word: '{}'", word))?;
        for bit in (0..11).rev() {
            bits.push(((index >> bit) & 1) as u8);
        }
    }

    // Extract 256 bits of entropy + 8 bits checksum
    let mut entropy = [0u8; 32];
    for (i, byte) in entropy.iter_mut().enumerate() {
        for bit in 0..8 {
            *byte = (*byte << 1) | bits[i * 8 + bit];
        }
    }

    let mut checksum_byte = 0u8;
    for bit in 0..8 {
        checksum_byte = (checksum_byte << 1) | bits[256 + bit];
    }

    // Verify checksum
    let expected_checksum = sha3_256(&entropy).0[0];
    if checksum_byte != expected_checksum {
        return Err("invalid mnemonic checksum".into());
    }

    Ok(entropy)
}

/// Format 24 words as a human-readable mnemonic (6 words per line).
pub fn format_mnemonic_24(words: &[String]) -> String {
    words
        .chunks(6)
        .enumerate()
        .map(|(i, chunk)| format!("  {}: {}", i * 6 + 1, chunk.join(" ")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let entropy = [42u8; 32];
        let words = entropy_to_mnemonic(&entropy);
        assert_eq!(words.len(), 24);

        let decoded = mnemonic_to_entropy(&words).unwrap();
        assert_eq!(decoded, entropy);
    }

    #[test]
    fn test_all_zeros() {
        let entropy = [0u8; 32];
        let words = entropy_to_mnemonic(&entropy);
        assert_eq!(words.len(), 24);
        // First word should be "abandon" (index 0)
        assert_eq!(words[0], "abandon");

        let decoded = mnemonic_to_entropy(&words).unwrap();
        assert_eq!(decoded, entropy);
    }

    #[test]
    fn test_all_ones() {
        let entropy = [0xFF; 32];
        let words = entropy_to_mnemonic(&entropy);
        assert_eq!(words.len(), 24);
        // Last 11 bits of 0xFF... = 2047 → "zoo"
        assert_eq!(words[0], "zoo");
    }

    #[test]
    fn test_invalid_word() {
        let words: Vec<String> = (0..24).map(|_| "notaword".to_string()).collect();
        assert!(mnemonic_to_entropy(&words).is_err());
    }

    #[test]
    fn test_wrong_count() {
        let words: Vec<String> = (0..12).map(|_| "abandon".to_string()).collect();
        assert!(mnemonic_to_entropy(&words).is_err());
    }

    #[test]
    fn test_bad_checksum() {
        let entropy = [1u8; 32];
        let mut words = entropy_to_mnemonic(&entropy);
        // Tamper with last word
        words[23] = "abandon".to_string();
        assert!(mnemonic_to_entropy(&words).is_err());
    }

    #[test]
    fn test_format() {
        let entropy = [0u8; 32];
        let words = entropy_to_mnemonic(&entropy);
        let formatted = format_mnemonic_24(&words);
        assert!(formatted.contains("1:"));
        assert_eq!(formatted.lines().count(), 4); // 24 / 6 = 4 lines
    }

    #[test]
    fn test_random_entropy() {
        let mut entropy = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut entropy);
        let words = entropy_to_mnemonic(&entropy);
        let decoded = mnemonic_to_entropy(&words).unwrap();
        assert_eq!(decoded, entropy);
    }
}
