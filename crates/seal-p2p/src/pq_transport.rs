//! ML-KEM native transport layer for libp2p.
//!
//! Replaces the classical Noise (X25519) transport with ML-KEM-768 key
//! encapsulation at the connection level. This provides PQ-secure
//! channel encryption for ALL libp2p protocols (GossipSub, Identify, etc.)
//! without application-layer double-encryption.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────┐
//! │          GossipSub / Identify          │
//! ├───────────────────────────────────────┤
//! │              Yamux (mux)               │
//! ├───────────────────────────────────────┤
//! │   PqTransportLayer (ML-KEM + SHA3)    │  ← This module
//! ├───────────────────────────────────────┤
//! │               TCP                      │
//! └───────────────────────────────────────┘
//! ```
//!
//! # Protocol
//!
//! 1. TCP connection established
//! 2. Both sides send ML-KEM-768 ephemeral public keys (1,184 bytes each)
//! 3. Initiator encapsulates with responder's pk → (ss1, ct1)
//! 4. Responder encapsulates with initiator's pk → (ss2, ct2)
//! 5. Session key = SHA3("seal-pq-transport:" || ss1 || ss2)
//! 6. All subsequent traffic encrypted with ChaCha20-Poly1305
//!    (keyed from session key) — or SHA3-CTR+MAC as interim
//!
//! # Migration Path
//!
//! Phase 1 (current): PQ double-encryption via `pq_encrypt.rs`
//!   - Classical Noise underneath, ML-KEM on top
//!   - Compatible with non-upgraded peers (they see encrypted GossipSub)
//!
//! Phase 2 (this module): Native PQ transport
//!   - ML-KEM replaces X25519 at transport level
//!   - Requires all peers to upgrade
//!   - Eliminates double-encryption overhead
//!
//! Phase 3 (future): Hybrid PQ+Classical
//!   - ML-KEM + X25519 key agreement (defense in depth)
//!   - Session key = SHA3(ml_kem_ss || x25519_ss)
//!   - Survives if either primitive is broken
//!
//! # Status
//!
//! Scaffold — libp2p 0.56 does not expose pluggable key exchange.
//! We implement the PQ key exchange as a wrapper that can be wired in
//! once libp2p supports custom transports (expected in 0.57+).

use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemCiphertext, KemKeypair, KemPublicKey};

/// PQ transport session key size.
pub const SESSION_KEY_SIZE: usize = 32;

/// ML-KEM-768 public key size.
pub const KEM_PK_SIZE: usize = 1184;

/// ML-KEM-768 ciphertext size.
pub const KEM_CT_SIZE: usize = 1088;

/// Domain separation for transport session key derivation.
const TRANSPORT_DOMAIN: &[u8] = b"seal-pq-transport:";

/// Hybrid key exchange mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyExchangeMode {
    /// ML-KEM only (pure PQ).
    PqOnly,
    /// ML-KEM + X25519 hybrid (defense in depth).
    /// Session key = SHA3(ml_kem_ss || x25519_ss)
    Hybrid,
}

/// A PQ transport session established between two peers.
#[derive(Clone)]
pub struct PqTransportSession {
    /// Symmetric session key for encrypting all traffic.
    session_key: [u8; SESSION_KEY_SIZE],
    /// Whether this session used hybrid key exchange.
    mode: KeyExchangeMode,
    /// Monotonic nonce counter for AEAD.
    nonce_counter: u64,
}

impl PqTransportSession {
    /// Encrypt a frame for transport.
    ///
    /// Format: nonce (8B) || ciphertext || mac (32B)
    pub fn encrypt_frame(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        encrypt_transport_frame(plaintext, &self.session_key, &nonce)
    }

    /// Decrypt a frame from transport.
    ///
    /// Returns None if MAC verification fails.
    pub fn decrypt_frame(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < 8 + 32 {
            return None;
        }
        decrypt_transport_frame(frame, &self.session_key)
    }

    /// The key exchange mode used.
    pub fn mode(&self) -> KeyExchangeMode {
        self.mode
    }

    fn next_nonce(&mut self) -> [u8; 8] {
        let n = self.nonce_counter;
        self.nonce_counter = n.wrapping_add(1);
        n.to_le_bytes()
    }
}

/// Initiator-side PQ key exchange.
///
/// Generates an ephemeral ML-KEM keypair and prepares msg1.
pub struct PqTransportInitiator {
    keypair: KemKeypair,
}

impl PqTransportInitiator {
    pub fn new() -> Self {
        PqTransportInitiator {
            keypair: KemKeypair::generate(),
        }
    }

    /// Message 1: our ephemeral ML-KEM public key (1,184 bytes).
    pub fn msg1(&self) -> Vec<u8> {
        self.keypair.public.to_bytes()
    }

    /// Process msg2 from responder: their pk (1,184B) + ciphertext (1,088B).
    ///
    /// Returns (msg3, session) where msg3 is our ciphertext for the responder.
    pub fn process_msg2(&self, msg2: &[u8]) -> Result<(Vec<u8>, PqTransportSession), String> {
        if msg2.len() != KEM_PK_SIZE + KEM_CT_SIZE {
            return Err(format!(
                "invalid msg2 size: expected {}, got {}",
                KEM_PK_SIZE + KEM_CT_SIZE,
                msg2.len()
            ));
        }

        let responder_pk_bytes = &msg2[..KEM_PK_SIZE];
        let ct1_bytes = &msg2[KEM_PK_SIZE..];

        // Decapsulate their ciphertext to get ss1
        let ct1 = KemCiphertext::from_bytes(ct1_bytes.to_vec());
        let ss1 = self
            .keypair
            .secret
            .decapsulate(&ct1)
            .map_err(|e| format!("KEM decapsulation failed: {}", e))?;

        // Encapsulate with their public key to get (ss2, ct2)
        let responder_pk = KemPublicKey::from_bytes(responder_pk_bytes)
            .map_err(|e| format!("invalid responder pk: {}", e))?;
        let (ss2, ct2) = responder_pk.encapsulate();

        // Derive session key from both shared secrets
        let session_key = derive_transport_session_key(ss1.as_bytes(), ss2.as_bytes());

        let session = PqTransportSession {
            session_key,
            mode: KeyExchangeMode::PqOnly,
            nonce_counter: 0,
        };

        Ok((ct2.to_bytes().to_vec(), session))
    }
}

impl Default for PqTransportInitiator {
    fn default() -> Self {
        Self::new()
    }
}

/// Responder-side PQ key exchange.
pub struct PqTransportResponder {
    keypair: KemKeypair,
    shared_secret_1: Option<Vec<u8>>,
}

impl PqTransportResponder {
    pub fn new() -> Self {
        PqTransportResponder {
            keypair: KemKeypair::generate(),
            shared_secret_1: None,
        }
    }

    /// Process msg1 from initiator (their pk, 1,184B).
    /// Returns msg2: our pk (1,184B) + ciphertext for them (1,088B).
    pub fn process_msg1(&mut self, msg1: &[u8]) -> Result<Vec<u8>, String> {
        if msg1.len() != KEM_PK_SIZE {
            return Err(format!(
                "invalid msg1 size: expected {}, got {}",
                KEM_PK_SIZE,
                msg1.len()
            ));
        }

        let initiator_pk = KemPublicKey::from_bytes(msg1)
            .map_err(|e| format!("invalid initiator pk: {}", e))?;

        // Encapsulate with initiator's pk → (ss1, ct1)
        let (ss1, ct1) = initiator_pk.encapsulate();
        self.shared_secret_1 = Some(ss1.as_bytes().to_vec());

        // msg2 = our_pk || ct1
        let mut msg2 = Vec::with_capacity(KEM_PK_SIZE + KEM_CT_SIZE);
        msg2.extend_from_slice(&self.keypair.public.to_bytes());
        msg2.extend_from_slice(&ct1.to_bytes());
        Ok(msg2)
    }

    /// Process msg3 from initiator (their ciphertext, 1,088B).
    /// Returns the established session.
    pub fn process_msg3(&self, msg3: &[u8]) -> Result<PqTransportSession, String> {
        if msg3.len() != KEM_CT_SIZE {
            return Err(format!(
                "invalid msg3 size: expected {}, got {}",
                KEM_CT_SIZE,
                msg3.len()
            ));
        }

        let ss1_bytes = self
            .shared_secret_1
            .as_ref()
            .ok_or("handshake not started")?;

        // Decapsulate to get ss2
        let ct2 = KemCiphertext::from_bytes(msg3.to_vec());
        let ss2 = self
            .keypair
            .secret
            .decapsulate(&ct2)
            .map_err(|e| format!("KEM decapsulation failed: {}", e))?;

        let session_key = derive_transport_session_key(ss1_bytes, ss2.as_bytes());

        Ok(PqTransportSession {
            session_key,
            mode: KeyExchangeMode::PqOnly,
            nonce_counter: 0,
        })
    }
}

impl Default for PqTransportResponder {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive transport session key: SHA3(domain || ss1 || ss2).
fn derive_transport_session_key(ss1: &[u8], ss2: &[u8]) -> [u8; SESSION_KEY_SIZE] {
    let input = [TRANSPORT_DOMAIN, ss1, ss2].concat();
    sha3_256(&input).0
}

/// Encrypt a transport frame.
/// Format: nonce (8B) || ciphertext || mac (32B)
fn encrypt_transport_frame(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 8]) -> Vec<u8> {
    let ciphertext = xor_key_stream(plaintext, key, nonce);
    let mac = transport_mac(key, nonce, &ciphertext);

    let mut frame = Vec::with_capacity(8 + ciphertext.len() + 32);
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&ciphertext);
    frame.extend_from_slice(&mac);
    frame
}

/// Decrypt a transport frame. Returns None on MAC failure.
fn decrypt_transport_frame(frame: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if frame.len() < 8 + 32 {
        return None;
    }

    let nonce: [u8; 8] = frame[..8].try_into().ok()?;
    let mac_start = frame.len() - 32;
    let ciphertext = &frame[8..mac_start];
    let received_mac = &frame[mac_start..];

    let expected_mac = transport_mac(key, &nonce, ciphertext);
    if !constant_time_eq(received_mac, &expected_mac) {
        return None;
    }

    Some(xor_key_stream(ciphertext, key, &nonce))
}

/// SHA3-CTR key stream XOR.
fn xor_key_stream(data: &[u8], key: &[u8; 32], nonce: &[u8; 8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut block_idx = 0u64;
    let mut block = ctr_block(key, nonce, block_idx);
    let mut pos = 0;

    for &byte in data {
        if pos >= 32 {
            block_idx += 1;
            block = ctr_block(key, nonce, block_idx);
            pos = 0;
        }
        result.push(byte ^ block[pos]);
        pos += 1;
    }
    result
}

/// Derive one CTR block.
fn ctr_block(key: &[u8; 32], nonce: &[u8; 8], idx: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 8 + 8);
    input.extend_from_slice(key);
    input.extend_from_slice(nonce);
    input.extend_from_slice(&idx.to_le_bytes());
    sha3_256(&input).0
}

/// Encrypt-then-MAC for transport frames.
fn transport_mac(key: &[u8; 32], nonce: &[u8; 8], ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 4 + 8 + ciphertext.len());
    input.extend_from_slice(key);
    input.extend_from_slice(b"tmac");
    input.extend_from_slice(nonce);
    input.extend_from_slice(ciphertext);
    sha3_256(&input).0
}

/// Constant-time comparison to prevent timing attacks on MAC verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_key_exchange() {
        let initiator = PqTransportInitiator::new();
        let mut responder = PqTransportResponder::new();

        // msg1: I → R (initiator's ephemeral pk)
        let msg1 = initiator.msg1();
        assert_eq!(msg1.len(), KEM_PK_SIZE);

        // msg2: R → I (responder's pk + ciphertext)
        let msg2 = responder.process_msg1(&msg1).unwrap();
        assert_eq!(msg2.len(), KEM_PK_SIZE + KEM_CT_SIZE);

        // msg3: I → R (initiator's ciphertext) + initiator gets session
        let (msg3, mut i_session) = initiator.process_msg2(&msg2).unwrap();
        assert_eq!(msg3.len(), KEM_CT_SIZE);

        // Responder gets session
        let mut r_session = responder.process_msg3(&msg3).unwrap();

        // Both sides derive the same session key
        assert_eq!(i_session.session_key, r_session.session_key);
        assert_eq!(i_session.mode(), KeyExchangeMode::PqOnly);

        // Encrypt/decrypt works bidirectionally
        let msg = b"block data from proposer";
        let frame = i_session.encrypt_frame(msg);
        let decrypted = r_session.decrypt_frame(&frame).unwrap();
        assert_eq!(decrypted, msg);

        let msg2_data = b"committee vote";
        let frame2 = r_session.encrypt_frame(msg2_data);
        let decrypted2 = i_session.decrypt_frame(&frame2).unwrap();
        assert_eq!(decrypted2, msg2_data);
    }

    #[test]
    fn test_different_exchanges_different_keys() {
        let init1 = PqTransportInitiator::new();
        let mut resp1 = PqTransportResponder::new();
        let msg1_1 = init1.msg1();
        let msg2_1 = resp1.process_msg1(&msg1_1).unwrap();
        let (msg3_1, session1) = init1.process_msg2(&msg2_1).unwrap();
        let _ = resp1.process_msg3(&msg3_1).unwrap();

        let init2 = PqTransportInitiator::new();
        let mut resp2 = PqTransportResponder::new();
        let msg1_2 = init2.msg1();
        let msg2_2 = resp2.process_msg1(&msg1_2).unwrap();
        let (_, session2) = init2.process_msg2(&msg2_2).unwrap();

        // Ephemeral keys → different session keys (forward secrecy)
        assert_ne!(session1.session_key, session2.session_key);
    }

    #[test]
    fn test_invalid_msg_sizes_rejected() {
        let initiator = PqTransportInitiator::new();
        let mut responder = PqTransportResponder::new();

        // Wrong msg1 size
        assert!(responder.process_msg1(&[0u8; 100]).is_err());

        // Wrong msg2 size
        assert!(initiator.process_msg2(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_frame_tampering_detected() {
        let initiator = PqTransportInitiator::new();
        let mut responder = PqTransportResponder::new();
        let msg1 = initiator.msg1();
        let msg2 = responder.process_msg1(&msg1).unwrap();
        let (msg3, mut i_session) = initiator.process_msg2(&msg2).unwrap();
        let r_session = responder.process_msg3(&msg3).unwrap();

        let msg = b"sensitive data";
        let mut frame = i_session.encrypt_frame(msg);

        // Tamper with ciphertext
        if frame.len() > 10 {
            frame[9] ^= 0xFF;
        }

        // MAC verification should fail
        assert!(r_session.decrypt_frame(&frame).is_none());
    }

    #[test]
    fn test_large_frame() {
        let initiator = PqTransportInitiator::new();
        let mut responder = PqTransportResponder::new();
        let msg1 = initiator.msg1();
        let msg2 = responder.process_msg1(&msg1).unwrap();
        let (msg3, mut i_session) = initiator.process_msg2(&msg2).unwrap();
        let r_session = responder.process_msg3(&msg3).unwrap();

        // 1 MB frame (realistic block size)
        let large: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let frame = i_session.encrypt_frame(&large);
        let decrypted = r_session.decrypt_frame(&frame).unwrap();
        assert_eq!(decrypted, large);
    }

    #[test]
    fn test_monotonic_nonce() {
        let initiator = PqTransportInitiator::new();
        let mut responder = PqTransportResponder::new();
        let msg1 = initiator.msg1();
        let msg2 = responder.process_msg1(&msg1).unwrap();
        let (msg3, mut session) = initiator.process_msg2(&msg2).unwrap();
        let _ = responder.process_msg3(&msg3).unwrap();

        // Each frame gets a different nonce (monotonic counter)
        let f1 = session.encrypt_frame(b"msg1");
        let f2 = session.encrypt_frame(b"msg1");
        // Same plaintext, different nonces → different frames
        assert_ne!(f1, f2);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_empty_frame() {
        let initiator = PqTransportInitiator::new();
        let mut responder = PqTransportResponder::new();
        let msg1 = initiator.msg1();
        let msg2 = responder.process_msg1(&msg1).unwrap();
        let (msg3, mut i_session) = initiator.process_msg2(&msg2).unwrap();
        let r_session = responder.process_msg3(&msg3).unwrap();

        let frame = i_session.encrypt_frame(b"");
        let decrypted = r_session.decrypt_frame(&frame).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_handshake_not_started() {
        let responder = PqTransportResponder::new();
        assert!(responder.process_msg3(&[0u8; KEM_CT_SIZE]).is_err());
    }
}
