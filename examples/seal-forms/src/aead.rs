//! AEAD wrapper around the demo's XOR stream cipher.
//!
//! The base `xor_stream` provides confidentiality only — a network
//! attacker that flips bits in `answer_ct` doesn't break the trace
//! chain (the new `trace_hash` would still be self-consistent), so
//! the form owner ends up decrypting attacker-controlled plaintext.
//!
//! This module adds an HMAC-SHA3-256 tag computed over `(kem_ct ||
//! answer_ct)` keyed by the *same* shared secret the stream cipher
//! uses. Verifying the tag before decrypting binds the answer
//! ciphertext to the KEM ciphertext under the encapsulating key, so
//! tampering with either field produces a detectable mismatch.
//!
//! Wire format (15 bytes prefix):
//!
//! ```text
//!   tag_v1 || answer_ct
//!   ^^^^^^
//!   "SEAL-FORMS-AEAD" (15 bytes ASCII)
//! ```
//!
//! Followed by 32 bytes of HMAC-SHA3-256 tag, then the XOR ciphertext.

use seal_crypto::hash::sha3_256;

/// 15-byte version tag prefixed to every AEAD-wrapped answer
/// ciphertext. Distinct from the body so unwrapping a non-AEAD blob
/// fails on the prefix check rather than producing garbage.
pub const AEAD_PREFIX: &[u8; 15] = b"SEAL-FORMS-AEAD";

/// HMAC-SHA3-256 of `(kem_ct || answer_ct)` keyed by `key`.
///
/// Standard HMAC construction: pad `key` to 64 bytes (SHA3-256 block
/// size after the absorb), XOR with IPAD/OPAD, then `H(opad || H(ipad
/// || message))`.
pub fn aead_tag(key: &[u8], kem_ct: &[u8], answer_ct: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 136; // SHA3-256 rate is 136 bytes
    let mut k_padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = sha3_256(key).0;
        k_padded[..32].copy_from_slice(&h);
    } else {
        k_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    let mut inner = Vec::with_capacity(BLOCK + kem_ct.len() + answer_ct.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(kem_ct);
    inner.extend_from_slice(answer_ct);
    let inner_h = sha3_256(&inner).0;

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_h);
    sha3_256(&outer).0
}

/// Wrap an XOR ciphertext as `AEAD_PREFIX || tag || ciphertext`.
pub fn wrap(key: &[u8], kem_ct: &[u8], answer_ct: &[u8]) -> Vec<u8> {
    let tag = aead_tag(key, kem_ct, answer_ct);
    let mut out = Vec::with_capacity(15 + 32 + answer_ct.len());
    out.extend_from_slice(AEAD_PREFIX);
    out.extend_from_slice(&tag);
    out.extend_from_slice(answer_ct);
    out
}

/// Unwrap an AEAD blob, returning the ciphertext on success or an
/// error string on tag mismatch / malformed prefix. Constant-time
/// comparison.
pub fn unwrap<'a>(
    key: &[u8],
    kem_ct: &[u8],
    blob: &'a [u8],
) -> Result<&'a [u8], String> {
    if blob.len() < 15 + 32 {
        return Err(format!("AEAD blob too short: {} bytes", blob.len()));
    }
    if &blob[..15] != &AEAD_PREFIX[..] {
        return Err("AEAD prefix mismatch".into());
    }
    let tag = &blob[15..47];
    let ct = &blob[47..];
    let expected = aead_tag(key, kem_ct, ct);
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= tag[i] ^ expected[i];
    }
    if diff != 0 {
        return Err("AEAD tag mismatch".into());
    }
    Ok(ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrips() {
        let key = b"shared-secret";
        let kem = b"kem-ciphertext";
        let ct = b"opaque answer ciphertext";
        let wrapped = wrap(key, kem, ct);
        let unwrapped = unwrap(key, kem, &wrapped).unwrap();
        assert_eq!(unwrapped, ct);
    }

    #[test]
    fn unwrap_rejects_tag_flip() {
        let key = b"k";
        let kem = b"k1";
        let ct = b"hello";
        let mut wrapped = wrap(key, kem, ct);
        // Flip a bit in the tag region (bytes 15..47).
        wrapped[20] ^= 1;
        let err = unwrap(key, kem, &wrapped).unwrap_err();
        assert!(err.contains("tag"));
    }

    #[test]
    fn unwrap_rejects_kem_swap() {
        let key = b"k";
        let kem_a = b"kem-a";
        let kem_b = b"kem-b";
        let ct = b"x";
        let wrapped = wrap(key, kem_a, ct);
        // Same `key` but the unwrapper uses kem_b, so the tag binding
        // fails (the answer wasn't authenticated for this kem_ct).
        let err = unwrap(key, kem_b, &wrapped).unwrap_err();
        assert!(err.contains("tag"));
    }

    #[test]
    fn unwrap_rejects_short_blob() {
        let err = unwrap(b"k", b"kem", &[0u8; 10]).unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn unwrap_rejects_bad_prefix() {
        let key = b"k";
        let mut blob = vec![0u8; 50];
        blob[..15].copy_from_slice(b"NOT-FORMS-AEAD!");
        let err = unwrap(key, b"kem", &blob).unwrap_err();
        assert!(err.contains("prefix"));
    }
}
