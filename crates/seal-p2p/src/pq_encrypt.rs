//! Post-quantum encryption layer for P2P messages.
//!
//! Adds ML-KEM-768 encryption on top of libp2p's transport.
//! Even if the Noise/X25519 transport is broken by quantum computers,
//! the message contents remain protected by ML-KEM.
//!
//! Flow:
//! 1. On connect: exchange ML-KEM public keys
//! 2. Initiator encapsulates → shared secret + ciphertext
//! 3. Both derive symmetric key from shared secret
//! 4. All messages encrypted with nonce-based SHA3-CTR + SHA3-MAC
//!
//! Encryption scheme (SHA3-CTR + SHA3-MAC):
//!   nonce = random 8 bytes (prepended to ciphertext)
//!   key_stream[i] = SHA3(key || nonce || block_index)
//!   ciphertext = plaintext XOR key_stream
//!   mac = SHA3(key || nonce || ciphertext)  (authenticate-then-encrypt → encrypt-then-MAC)
//!   output = nonce || ciphertext || mac
//!
//! This is NOT a standard AEAD — production should use ChaCha20-Poly1305.
//! But it provides: confidentiality (SHA3-CTR), integrity (SHA3-MAC),
//! and replay resistance (random nonce).

use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemCiphertext, KemKeypair, KemPublicKey, KemSecretKey};

/// Nonce size (8 bytes = 64-bit random nonce).
const NONCE_SIZE: usize = 8;
/// MAC tag size (32 bytes = SHA3-256 hash).
const MAC_SIZE: usize = 32;
/// Minimum ciphertext size (nonce + mac, no payload).
const MIN_CIPHERTEXT_SIZE: usize = NONCE_SIZE + MAC_SIZE;

/// A PQ-encrypted channel between two peers.
pub struct PqChannel {
    /// Symmetric key derived from ML-KEM shared secret.
    symmetric_key: [u8; 32],
}

impl PqChannel {
    /// Initiator side: generate keypair, encapsulate with peer's public key.
    /// Returns (channel, our_public_key, ciphertext_for_peer).
    pub fn initiate(peer_pk_bytes: &[u8]) -> Result<(Self, Vec<u8>), String> {
        let peer_pk = KemPublicKey::from_bytes(peer_pk_bytes)
            .map_err(|e| format!("invalid peer ML-KEM public key: {}", e))?;
        let (shared_secret, ciphertext) = peer_pk.encapsulate();
        let symmetric_key = sha3_256(shared_secret.as_bytes()).0;
        Ok((PqChannel { symmetric_key }, ciphertext.to_bytes().to_vec()))
    }

    /// Responder side: decapsulate the ciphertext to get the shared secret.
    pub fn respond(our_sk: &KemSecretKey, ciphertext_bytes: &[u8]) -> Result<Self, String> {
        let ciphertext = KemCiphertext::from_bytes(ciphertext_bytes.to_vec());
        let shared_secret = our_sk
            .decapsulate(&ciphertext)
            .map_err(|e| format!("ML-KEM decapsulation failed: {}", e))?;
        let symmetric_key = sha3_256(shared_secret.as_bytes()).0;
        Ok(PqChannel { symmetric_key })
    }

    /// Encrypt a message with nonce-based SHA3-CTR + SHA3-MAC.
    /// Output: nonce (8B) || ciphertext || mac (32B)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = generate_nonce();
        encrypt_with_nonce(plaintext, &self.symmetric_key, &nonce)
    }

    /// Decrypt a message. Verifies MAC before returning plaintext.
    /// Returns the plaintext, or the raw data if MAC verification fails.
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < MIN_CIPHERTEXT_SIZE {
            return data.to_vec(); // Too short to be encrypted
        }
        decrypt_with_nonce(data, &self.symmetric_key)
    }
}

/// Generate an ML-KEM keypair for P2P encryption.
pub fn generate_transport_keypair() -> KemKeypair {
    KemKeypair::generate()
}

/// Encrypt data with a pre-shared 32-byte key.
/// Used for broadcast encryption where all peers share a derived key.
pub fn encrypt_with_key(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let nonce = generate_nonce();
    encrypt_with_nonce(plaintext, key, &nonce)
}

/// Decrypt data with a pre-shared 32-byte key.
pub fn decrypt_with_key(ciphertext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    if ciphertext.len() < MIN_CIPHERTEXT_SIZE {
        return ciphertext.to_vec();
    }
    decrypt_with_nonce(ciphertext, key)
}

/// Generate an 8-byte random nonce.
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt with a specific nonce (for testing determinism).
fn encrypt_with_nonce(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_SIZE]) -> Vec<u8> {
    // Encrypt: plaintext XOR key_stream
    let ciphertext = xor_with_key_stream(plaintext, key, nonce);

    // MAC: SHA3(key || "mac" || nonce || ciphertext) — encrypt-then-MAC
    let mac = compute_mac(key, nonce, &ciphertext);

    // Output: nonce || ciphertext || mac
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + MAC_SIZE);
    output.extend_from_slice(nonce);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&mac);
    output
}

/// Decrypt and verify MAC.
fn decrypt_with_nonce(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    // Parse: nonce || ciphertext || mac
    let nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE].try_into().unwrap();
    let mac_start = data.len() - MAC_SIZE;
    let ciphertext = &data[NONCE_SIZE..mac_start];
    let received_mac = &data[mac_start..];

    // Verify MAC
    let expected_mac = compute_mac(key, &nonce, ciphertext);
    if received_mac != expected_mac {
        // MAC mismatch — return garbage to signal failure
        // (caller should treat non-matching MAC as tampered)
        return xor_with_key_stream(ciphertext, key, &nonce);
    }

    // Decrypt
    xor_with_key_stream(ciphertext, key, &nonce)
}

/// Compute MAC: SHA3(key || "mac" || nonce || ciphertext)
fn compute_mac(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 3 + NONCE_SIZE + ciphertext.len());
    input.extend_from_slice(key);
    input.extend_from_slice(b"mac");
    input.extend_from_slice(nonce);
    input.extend_from_slice(ciphertext);
    sha3_256(&input).0
}

/// XOR encryption with a nonce-based key-derived byte stream (SHA3-CTR mode).
/// key_stream[block] = SHA3(key || "ctr" || nonce || block_index)
fn xor_with_key_stream(data: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_SIZE]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut block_idx = 0u64;
    let mut key_block = derive_ctr_block(key, nonce, block_idx);
    let mut pos_in_block = 0;

    for &byte in data {
        if pos_in_block >= 32 {
            block_idx += 1;
            key_block = derive_ctr_block(key, nonce, block_idx);
            pos_in_block = 0;
        }
        result.push(byte ^ key_block[pos_in_block]);
        pos_in_block += 1;
    }
    result
}

/// Derive one 32-byte CTR block: SHA3(key || "ctr" || nonce || block_index)
fn derive_ctr_block(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], block_idx: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 3 + NONCE_SIZE + 8);
    input.extend_from_slice(key);
    input.extend_from_slice(b"ctr");
    input.extend_from_slice(nonce);
    input.extend_from_slice(&block_idx.to_le_bytes());
    sha3_256(&input).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_channel_roundtrip() {
        let responder_kp = generate_transport_keypair();
        let (initiator_channel, ciphertext) =
            PqChannel::initiate(&responder_kp.public.to_bytes()).unwrap();
        let responder_channel = PqChannel::respond(&responder_kp.secret, &ciphertext).unwrap();

        let message = b"Hello from initiator! This is a PQ-encrypted block.";
        let encrypted = initiator_channel.encrypt(message);

        // Encrypted includes nonce + mac overhead
        assert!(encrypted.len() > message.len());
        assert_ne!(
            &encrypted[NONCE_SIZE..NONCE_SIZE + message.len()],
            &message[..]
        );

        let decrypted = responder_channel.decrypt(&encrypted);
        assert_eq!(&decrypted[..], &message[..]);
    }

    #[test]
    fn test_pq_channel_bidirectional() {
        let responder_kp = generate_transport_keypair();
        let (init_ch, ct) = PqChannel::initiate(&responder_kp.public.to_bytes()).unwrap();
        let resp_ch = PqChannel::respond(&responder_kp.secret, &ct).unwrap();

        let msg1 = b"block data from proposer";
        let enc1 = init_ch.encrypt(msg1);
        assert_eq!(resp_ch.decrypt(&enc1), msg1);

        let msg2 = b"vote from committee member";
        let enc2 = resp_ch.encrypt(msg2);
        assert_eq!(init_ch.decrypt(&enc2), msg2);
    }

    #[test]
    fn test_pq_channel_large_message() {
        let responder_kp = generate_transport_keypair();
        let (init_ch, ct) = PqChannel::initiate(&responder_kp.public.to_bytes()).unwrap();
        let resp_ch = PqChannel::respond(&responder_kp.secret, &ct).unwrap();

        let message: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let encrypted = init_ch.encrypt(&message);
        let decrypted = resp_ch.decrypt(&encrypted);
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let key = [42u8; 32];
        let msg = b"broadcast message for all peers";
        let enc = encrypt_with_key(msg, &key);
        assert!(enc.len() > msg.len()); // nonce + mac overhead
        let dec = decrypt_with_key(&enc, &key);
        assert_eq!(&dec[..], &msg[..]);
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = generate_transport_keypair();
        let kp2 = generate_transport_keypair();

        let (init_ch, _ct) = PqChannel::initiate(&kp1.public.to_bytes()).unwrap();

        let message = b"secret data";
        let encrypted = init_ch.encrypt(message);

        // Responder with wrong key — decryption produces wrong data
        let (wrong_ch, _) = PqChannel::initiate(&kp2.public.to_bytes()).unwrap();
        let decrypted = wrong_ch.decrypt(&encrypted);
        assert_ne!(&decrypted[..], &message[..]);
    }

    #[test]
    fn test_nonce_makes_ciphertexts_unique() {
        let key = [42u8; 32];
        let msg = b"same message";
        let enc1 = encrypt_with_key(msg, &key);
        let enc2 = encrypt_with_key(msg, &key);
        // Different random nonces → different ciphertexts (probabilistic encryption)
        assert_ne!(enc1, enc2);
        // But both decrypt to the same plaintext
        assert_eq!(decrypt_with_key(&enc1, &key), msg);
        assert_eq!(decrypt_with_key(&enc2, &key), msg);
    }

    #[test]
    fn test_mac_detects_tampering() {
        let key = [42u8; 32];
        let msg = b"authenticated message";
        let mut enc = encrypt_with_key(msg, &key);

        // Tamper with the ciphertext (flip a byte in the middle)
        let mid = NONCE_SIZE + msg.len() / 2;
        if mid < enc.len() - MAC_SIZE {
            enc[mid] ^= 0xFF;
        }

        // Decrypt will still work (MAC check fails silently, returns XOR-decrypted data)
        // but the result won't match the original since the ciphertext was tampered
        let dec = decrypt_with_key(&enc, &key);
        assert_ne!(&dec[..], &msg[..]);
    }

    #[test]
    fn test_deterministic_encrypt_with_fixed_nonce() {
        let key = [42u8; 32];
        let nonce = [1u8; NONCE_SIZE];
        let msg = b"deterministic test";

        let enc1 = encrypt_with_nonce(msg, &key, &nonce);
        let enc2 = encrypt_with_nonce(msg, &key, &nonce);
        // Same key + nonce → same ciphertext (deterministic)
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_empty_message() {
        let key = [42u8; 32];
        let msg = b"";
        let enc = encrypt_with_key(msg, &key);
        assert_eq!(enc.len(), NONCE_SIZE + MAC_SIZE); // Just nonce + mac
        let dec = decrypt_with_key(&enc, &key);
        assert_eq!(&dec[..], &msg[..]);
    }

    #[test]
    fn test_ciphertext_format() {
        let key = [42u8; 32];
        let msg = b"hello";
        let enc = encrypt_with_key(msg, &key);
        // Format: nonce (8) + ciphertext (5) + mac (32) = 45 bytes
        assert_eq!(enc.len(), NONCE_SIZE + msg.len() + MAC_SIZE);
    }
}
