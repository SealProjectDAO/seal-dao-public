//! PQ-Noise handshake — ML-KEM key exchange + ML-DSA authentication.
//!
//! Replaces the classical Noise XX pattern (X25519 + Ed25519) with a
//! post-quantum secure handshake using NIST-standard algorithms.
//!
//! # Protocol (PQ-Noise-KEM)
//!
//! ```text
//! Initiator (I)                          Responder (R)
//! ─────────────                          ─────────────
//! Generate ML-KEM keypair (ek_I, dk_I)
//!
//!   ── msg1: ek_I (1,184 bytes) ──────►
//!
//!                              Generate ML-KEM keypair (ek_R, dk_R)
//!                              (ct, ss) = Encaps(ek_I)
//!                              sig_R = ML-DSA.sign(id_R, ek_I || ct || ek_R)
//!
//!   ◄── msg2: ek_R || ct || sig_R ────
//!        (~1,184 + 1,088 + 3,309 = ~5,581 bytes)
//!
//! ss = Decaps(dk_I, ct)
//! Verify sig_R with id_R's public key
//! (ct2, ss2) = Encaps(ek_R)
//! session_key = SHA3(ss || ss2)
//! sig_I = ML-DSA.sign(id_I, ek_R || ct2)
//!
//!   ── msg3: ct2 || sig_I ────────────►
//!        (~1,088 + 3,309 = ~4,397 bytes)
//!
//!                              ss2 = Decaps(dk_R, ct2)
//!                              session_key = SHA3(ss || ss2)
//!                              Verify sig_I with id_I's public key
//!
//! Both sides now share session_key (32 bytes).
//! All subsequent messages encrypted with session_key.
//! ```
//!
//! # Security properties
//!
//! - **Forward secrecy**: Ephemeral KEM keys per handshake
//! - **Mutual authentication**: Both sides sign with ML-DSA identity keys
//! - **PQ security**: ML-KEM-768 (NIST Level 3) + ML-DSA-65 (NIST Level 3)
//! - **Session key**: Double KEM (both sides contribute randomness)

use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemCiphertext, KemKeypair, KemPublicKey};
use seal_crypto::signature::{Signature, SigningKey, VerifyingKey};

/// Size constants for the handshake messages.
pub const KEM_PUBLIC_KEY_SIZE: usize = 1184; // ML-KEM-768
pub const KEM_CIPHERTEXT_SIZE: usize = 1088; // ML-KEM-768
pub const SIGNATURE_SIZE: usize = 3309; // ML-DSA-65
pub const SESSION_KEY_SIZE: usize = 32;

/// Handshake message 1: Initiator → Responder
/// Contains: initiator's ephemeral ML-KEM public key
pub struct HandshakeMsg1 {
    pub kem_pk: Vec<u8>,
}

/// Handshake message 2: Responder → Initiator
/// Contains: responder's ephemeral KEM pk + ciphertext + ML-DSA signature
pub struct HandshakeMsg2 {
    pub kem_pk: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Handshake message 3: Initiator → Responder
/// Contains: ciphertext for responder's KEM pk + ML-DSA signature
pub struct HandshakeMsg3 {
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Result of a completed handshake.
pub struct HandshakeResult {
    /// Shared session key (32 bytes, from double KEM).
    pub session_key: [u8; SESSION_KEY_SIZE],
    /// Remote peer's ML-DSA identity public key.
    pub remote_identity: Vec<u8>,
}

/// Domain separation prefix for handshake signatures.
const HANDSHAKE_DOMAIN: &[u8] = b"seal-pq-noise-handshake:";

/// Initiator side of the PQ-Noise handshake.
pub struct Initiator {
    /// Our ephemeral KEM keypair.
    kem_keypair: KemKeypair,
    /// Our identity signing key.
    identity_sk: Vec<u8>,
    /// Our identity verifying key (retained for future use).
    _identity_vk: Vec<u8>,
}

impl Initiator {
    /// Create a new initiator with an identity key.
    pub fn new(identity_sk: &[u8], identity_vk: &[u8]) -> Self {
        Self {
            kem_keypair: KemKeypair::generate(),
            identity_sk: identity_sk.to_vec(),
            _identity_vk: identity_vk.to_vec(),
        }
    }

    /// Generate message 1 (send our ephemeral KEM public key).
    pub fn create_msg1(&self) -> HandshakeMsg1 {
        HandshakeMsg1 {
            kem_pk: self.kem_keypair.public.to_bytes(),
        }
    }

    /// Process message 2 from responder, generate message 3.
    /// Returns (msg3, handshake_result) on success.
    pub fn process_msg2(
        &self,
        msg2: &HandshakeMsg2,
        responder_identity_vk: &[u8],
    ) -> Result<(HandshakeMsg3, HandshakeResult), String> {
        // Verify responder's signature
        let vk = VerifyingKey::from_bytes(responder_identity_vk)
            .map_err(|e| format!("invalid responder identity key: {}", e))?;

        let signed_data = [
            HANDSHAKE_DOMAIN,
            &self.kem_keypair.public.to_bytes(),
            &msg2.ciphertext,
            &msg2.kem_pk,
        ]
        .concat();

        let sig = Signature::from_bytes(msg2.signature.clone());
        vk.verify(&signed_data, &sig)
            .map_err(|_| "responder signature verification failed")?;

        // Decapsulate to get shared secret 1
        let ct = KemCiphertext::from_bytes(msg2.ciphertext.clone());
        let ss1 = self
            .kem_keypair
            .secret
            .decapsulate(&ct)
            .map_err(|e| format!("KEM decapsulation failed: {}", e))?;

        // Encapsulate with responder's ephemeral KEM public key
        let resp_pk = KemPublicKey::from_bytes(&msg2.kem_pk)
            .map_err(|e| format!("invalid responder KEM pk: {}", e))?;
        let (ss2, ct2) = resp_pk.encapsulate();

        // Derive session key from both shared secrets
        let session_key = derive_session_key(ss1.as_bytes(), ss2.as_bytes());

        // Sign our contribution
        let sk = SigningKey::from_bytes(&self.identity_sk)
            .map_err(|e| format!("invalid identity sk: {}", e))?;
        let sign_data = [HANDSHAKE_DOMAIN, &msg2.kem_pk, ct2.to_bytes()].concat();
        let our_sig = sk
            .sign(&sign_data)
            .map_err(|e| format!("signing failed: {}", e))?;

        let msg3 = HandshakeMsg3 {
            ciphertext: ct2.to_bytes().to_vec(),
            signature: our_sig.to_bytes().to_vec(),
        };

        let result = HandshakeResult {
            session_key,
            remote_identity: responder_identity_vk.to_vec(),
        };

        Ok((msg3, result))
    }
}

/// Responder side of the PQ-Noise handshake.
pub struct Responder {
    /// Our ephemeral KEM keypair.
    kem_keypair: KemKeypair,
    /// Our identity signing key.
    identity_sk: Vec<u8>,
    /// Our identity verifying key (retained for future use).
    _identity_vk: Vec<u8>,
    /// Shared secret from encapsulation (kept for msg3 processing).
    shared_secret_1: Option<Vec<u8>>,
}

impl Responder {
    /// Create a new responder with an identity key.
    pub fn new(identity_sk: &[u8], identity_vk: &[u8]) -> Self {
        Self {
            kem_keypair: KemKeypair::generate(),
            identity_sk: identity_sk.to_vec(),
            _identity_vk: identity_vk.to_vec(),
            shared_secret_1: None,
        }
    }

    /// Process message 1 from initiator, generate message 2.
    pub fn process_msg1(&mut self, msg1: &HandshakeMsg1) -> Result<HandshakeMsg2, String> {
        // Encapsulate with initiator's ephemeral KEM public key
        let init_pk = KemPublicKey::from_bytes(&msg1.kem_pk)
            .map_err(|e| format!("invalid initiator KEM pk: {}", e))?;
        let (ss1, ct) = init_pk.encapsulate();

        // Store shared secret for later
        self.shared_secret_1 = Some(ss1.as_bytes().to_vec());

        // Sign: our identity key signs (initiator_pk || ciphertext || our_pk)
        let sk = SigningKey::from_bytes(&self.identity_sk)
            .map_err(|e| format!("invalid identity sk: {}", e))?;
        let sign_data = [
            HANDSHAKE_DOMAIN,
            &msg1.kem_pk,
            ct.to_bytes(),
            &self.kem_keypair.public.to_bytes(),
        ]
        .concat();
        let sig = sk
            .sign(&sign_data)
            .map_err(|e| format!("signing failed: {}", e))?;

        Ok(HandshakeMsg2 {
            kem_pk: self.kem_keypair.public.to_bytes(),
            ciphertext: ct.to_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// Process message 3 from initiator, complete handshake.
    pub fn process_msg3(
        &self,
        msg3: &HandshakeMsg3,
        initiator_identity_vk: &[u8],
    ) -> Result<HandshakeResult, String> {
        let ss1_bytes = self
            .shared_secret_1
            .as_ref()
            .ok_or("handshake not started (no msg1 processed)")?;

        // Verify initiator's signature
        let vk = VerifyingKey::from_bytes(initiator_identity_vk)
            .map_err(|e| format!("invalid initiator identity key: {}", e))?;

        let sign_data = [
            HANDSHAKE_DOMAIN,
            &self.kem_keypair.public.to_bytes(),
            &msg3.ciphertext,
        ]
        .concat();
        let sig = Signature::from_bytes(msg3.signature.clone());
        vk.verify(&sign_data, &sig)
            .map_err(|_| "initiator signature verification failed")?;

        // Decapsulate to get shared secret 2
        let ct2 = KemCiphertext::from_bytes(msg3.ciphertext.clone());
        let ss2 = self
            .kem_keypair
            .secret
            .decapsulate(&ct2)
            .map_err(|e| format!("KEM decapsulation failed: {}", e))?;

        // Derive session key from both shared secrets
        let session_key = derive_session_key(ss1_bytes, ss2.as_bytes());

        Ok(HandshakeResult {
            session_key,
            remote_identity: initiator_identity_vk.to_vec(),
        })
    }
}

/// Derive a session key from two shared secrets (double KEM).
/// session_key = SHA3("seal-pq-session:" || ss1 || ss2)
fn derive_session_key(ss1: &[u8], ss2: &[u8]) -> [u8; SESSION_KEY_SIZE] {
    let input = [b"seal-pq-session:".as_ref(), ss1, ss2].concat();
    sha3_256(&input).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_identity() -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = SigningKey::generate();
        (sk.to_bytes(), vk.to_bytes())
    }

    #[test]
    fn test_full_handshake() {
        let (i_sk, i_vk) = generate_identity();
        let (r_sk, r_vk) = generate_identity();

        let initiator = Initiator::new(&i_sk, &i_vk);
        let mut responder = Responder::new(&r_sk, &r_vk);

        // msg1: I → R
        let msg1 = initiator.create_msg1();
        assert!(!msg1.kem_pk.is_empty());

        // msg2: R → I
        let msg2 = responder.process_msg1(&msg1).unwrap();
        assert!(!msg2.kem_pk.is_empty());
        assert!(!msg2.ciphertext.is_empty());
        assert!(!msg2.signature.is_empty());

        // msg3: I → R (+ initiator gets session key)
        let (msg3, i_result) = initiator.process_msg2(&msg2, &r_vk).unwrap();
        assert!(!msg3.ciphertext.is_empty());
        assert!(!msg3.signature.is_empty());

        // R processes msg3 (+ responder gets session key)
        let r_result = responder.process_msg3(&msg3, &i_vk).unwrap();

        // Both sides derive the same session key
        assert_eq!(
            i_result.session_key, r_result.session_key,
            "session keys must match"
        );

        // Both know each other's identity
        assert_eq!(i_result.remote_identity, r_vk);
        assert_eq!(r_result.remote_identity, i_vk);
    }

    #[test]
    fn test_wrong_identity_rejected() {
        let (i_sk, i_vk) = generate_identity();
        let (r_sk, r_vk) = generate_identity();
        let (_, wrong_vk) = generate_identity();

        let initiator = Initiator::new(&i_sk, &i_vk);
        let mut responder = Responder::new(&r_sk, &r_vk);

        let msg1 = initiator.create_msg1();
        let msg2 = responder.process_msg1(&msg1).unwrap();

        // Use wrong identity to verify — should fail
        let result = initiator.process_msg2(&msg2, &wrong_vk);
        assert!(result.is_err(), "should reject wrong responder identity");
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let (i_sk, i_vk) = generate_identity();
        let (r_sk, r_vk) = generate_identity();

        let initiator = Initiator::new(&i_sk, &i_vk);
        let mut responder = Responder::new(&r_sk, &r_vk);

        let msg1 = initiator.create_msg1();
        let mut msg2 = responder.process_msg1(&msg1).unwrap();

        // Tamper with ciphertext
        if !msg2.ciphertext.is_empty() {
            msg2.ciphertext[0] ^= 0xFF;
        }

        // Signature verification should fail (signed data changed)
        let result = initiator.process_msg2(&msg2, &r_vk);
        assert!(result.is_err(), "should reject tampered ciphertext");
    }

    #[test]
    fn test_different_handshakes_different_keys() {
        let (i_sk, i_vk) = generate_identity();
        let (r_sk, r_vk) = generate_identity();

        // Handshake 1
        let init1 = Initiator::new(&i_sk, &i_vk);
        let mut resp1 = Responder::new(&r_sk, &r_vk);
        let msg1_1 = init1.create_msg1();
        let msg2_1 = resp1.process_msg1(&msg1_1).unwrap();
        let (msg3_1, result1) = init1.process_msg2(&msg2_1, &r_vk).unwrap();
        let _ = resp1.process_msg3(&msg3_1, &i_vk).unwrap();

        // Handshake 2 (same identities, different ephemeral keys)
        let init2 = Initiator::new(&i_sk, &i_vk);
        let mut resp2 = Responder::new(&r_sk, &r_vk);
        let msg1_2 = init2.create_msg1();
        let msg2_2 = resp2.process_msg1(&msg1_2).unwrap();
        let (_, result2) = init2.process_msg2(&msg2_2, &r_vk).unwrap();

        // Different ephemeral keys → different session keys (forward secrecy)
        assert_ne!(
            result1.session_key, result2.session_key,
            "different handshakes must produce different session keys"
        );
    }

    #[test]
    fn test_handshake_message_sizes() {
        let (i_sk, i_vk) = generate_identity();
        let (r_sk, r_vk) = generate_identity();

        let initiator = Initiator::new(&i_sk, &i_vk);
        let mut responder = Responder::new(&r_sk, &r_vk);

        let msg1 = initiator.create_msg1();
        let msg2 = responder.process_msg1(&msg1).unwrap();
        let (msg3, _) = initiator.process_msg2(&msg2, &r_vk).unwrap();

        // Verify expected sizes
        assert_eq!(msg1.kem_pk.len(), KEM_PUBLIC_KEY_SIZE);
        assert_eq!(msg2.kem_pk.len(), KEM_PUBLIC_KEY_SIZE);
        assert_eq!(msg2.ciphertext.len(), KEM_CIPHERTEXT_SIZE);
        assert_eq!(msg2.signature.len(), SIGNATURE_SIZE);
        assert_eq!(msg3.ciphertext.len(), KEM_CIPHERTEXT_SIZE);
        assert_eq!(msg3.signature.len(), SIGNATURE_SIZE);
    }
}
