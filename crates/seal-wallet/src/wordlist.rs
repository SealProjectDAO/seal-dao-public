//! Mnemonic wordlist for seed backup.
//!
//! Uses a 256-word subset of the BIP-39 English wordlist.
//! Each word encodes 8 bits → 32 words for 256 bits of entropy.
//!
//! Security: identical to full BIP-39 (same 256 bits of entropy).
//! Tradeoff: 32 words instead of 24 (8 more words to write down).
//!
//! Future: upgrade to full 2048-word BIP-39 for 24-word mnemonics.
//! This requires 11-bit encoding + SHA-256 checksum (BIP-39 spec).

/// 256-word list: each word maps to one byte value (0-255).
/// Selected from the BIP-39 English wordlist for uniqueness + readability.
const WORDLIST: [&str; 256] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "awesome", "awful", "awkward", "axis", "baby",
    "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach",
    "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind",
    "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blow",
    "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book",
    "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket",
    "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush",
    "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunny",
    "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
    "cabin", "cable", "cactus", "cage", "cake",
];

/// Encode 32 bytes as 32 mnemonic words.
pub fn bytes_to_words(bytes: &[u8; 32]) -> Vec<String> {
    bytes
        .iter()
        .map(|&b| WORDLIST[b as usize].to_string())
        .collect()
}

/// Decode 32 mnemonic words back to 32 bytes.
pub fn words_to_bytes(words: &[String]) -> Result<[u8; 32], String> {
    if words.len() != 32 {
        return Err(format!("expected 32 words, got {}", words.len()));
    }

    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        let lower = word.to_lowercase();
        let idx = WORDLIST
            .iter()
            .position(|&w| w == lower)
            .ok_or_else(|| format!("unknown word: '{}'", word))?;
        bytes[i] = idx as u8;
    }
    Ok(bytes)
}

/// Format words as a human-readable mnemonic (4 words per line).
pub fn format_mnemonic(words: &[String]) -> String {
    words
        .chunks(4)
        .enumerate()
        .map(|(i, chunk)| format!("  {}: {}", i * 4 + 1, chunk.join(" ")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let bytes = [42u8; 32];
        let words = bytes_to_words(&bytes);
        assert_eq!(words.len(), 32);

        let decoded = words_to_bytes(&words).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_all_bytes() {
        // Every byte value should map to a unique word
        for b in 0u8..=255 {
            let bytes = [b; 32];
            let words = bytes_to_words(&bytes);
            assert_eq!(words[0], WORDLIST[b as usize]);
        }
    }

    #[test]
    fn test_unique_words() {
        // All words in the list should be unique
        let mut seen = std::collections::HashSet::new();
        for word in &WORDLIST {
            assert!(seen.insert(word), "duplicate word: {}", word);
        }
    }

    #[test]
    fn test_format() {
        let bytes = [0u8; 32];
        let words = bytes_to_words(&bytes);
        let formatted = format_mnemonic(&words);
        assert!(formatted.contains("1: abandon"));
        assert!(formatted.lines().count() == 8); // 32 words / 4 per line
    }

    #[test]
    fn test_unknown_word() {
        let words: Vec<String> = (0..32).map(|_| "notaword".to_string()).collect();
        assert!(words_to_bytes(&words).is_err());
    }

    #[test]
    fn test_wrong_count() {
        let words: Vec<String> = (0..10).map(|_| "abandon".to_string()).collect();
        assert!(words_to_bytes(&words).is_err());
    }
}
