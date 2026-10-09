//! Post-quantum encrypted RPC transport layer.
//!
//! Wraps JSON-RPC requests in ML-KEM-768 encrypted envelopes.
//! Provides harvest-now-decrypt-later (HNDL) protection for RPC traffic.
//!
//! Protocol:
//! 1. Client sends its ML-KEM public key to /pq/handshake
//! 2. Server encapsulates a shared secret and returns ciphertext
//! 3. Both derive AES-256-GCM session key from shared secret
//! 4. Subsequent requests to /pq/rpc are encrypted with session key

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemKeypair, KemPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Session state for a PQ-encrypted RPC connection.
#[derive(Clone)]
pub struct PqRpcSession {
    /// Session ID (SHA3 of shared secret).
    pub session_id: String,
    /// Derived session key for AES-256-GCM.
    pub session_key: [u8; 32],
    /// Monotonic nonce counter (prevents replay).
    pub nonce_counter: u64,
}

impl std::fmt::Debug for PqRpcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mask the session key: only the first 4 bytes of hex are printed so
        // full key material never leaks into logs.
        f.debug_struct("PqRpcSession")
            .field("session_id", &self.session_id)
            .field("session_key", &format!("{}…", hex::encode(&self.session_key[..4])))
            .field("nonce_counter", &self.nonce_counter)
            .finish()
    }
}

/// Manages PQ-encrypted RPC sessions.
pub struct PqRpcManager {
    /// Server's ML-KEM keypair.
    server_keypair: KemKeypair,
    /// Active sessions keyed by session ID.
    sessions: Mutex<HashMap<String, PqRpcSession>>,
}

/// Handshake request from client.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Client's ML-KEM public key, hex-encoded.
    pub client_public_key: String,
}

/// Handshake response from server.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Server's ML-KEM ciphertext (encapsulated shared secret), hex-encoded.
    pub ciphertext: String,
    /// Session ID for subsequent encrypted requests.
    pub session_id: String,
    /// Server's ML-KEM public key, hex-encoded (for client to verify).
    pub server_public_key: String,
}

/// Encrypted RPC request envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRpcRequest {
    /// Session ID from handshake.
    pub session_id: String,
    /// Encrypted JSON-RPC payload, hex-encoded.
    pub encrypted_payload: String,
    /// Nonce used for this request.
    pub nonce: u64,
}

/// Encrypted RPC response envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRpcResponse {
    /// Encrypted JSON-RPC response, hex-encoded.
    pub encrypted_payload: String,
    /// Nonce used for this response.
    pub nonce: u64,
}

impl Default for PqRpcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PqRpcManager {
    /// Create a new PQ RPC manager with a fresh ML-KEM keypair.
    pub fn new() -> Self {
        PqRpcManager {
            server_keypair: KemKeypair::generate(),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Handle a handshake request. Returns the session info.
    pub fn handshake(&self, req: &HandshakeRequest) -> Result<HandshakeResponse, String> {
        let client_pk_bytes = hex::decode(&req.client_public_key)
            .map_err(|_| "invalid client public key hex".to_string())?;

        let client_pk = KemPublicKey::from_bytes(&client_pk_bytes)
            .map_err(|e| format!("invalid ML-KEM public key: {}", e))?;

        // Encapsulate a shared secret using client's public key
        let (shared_secret, ciphertext) = client_pk.encapsulate();

        // Derive session key from shared secret
        let session_key_hash = sha3_256(shared_secret.as_bytes());
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_hash.0);

        // Session ID = SHA3(shared_secret || "session")
        let session_id_input = [shared_secret.as_bytes(), b"session" as &[u8]].concat();
        let session_id = hex::encode(&sha3_256(&session_id_input).0[..16]);

        let session = PqRpcSession {
            session_id: session_id.clone(),
            session_key,
            nonce_counter: 0,
        };

        self.sessions
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?
            .insert(session_id.clone(), session);

        Ok(HandshakeResponse {
            ciphertext: hex::encode(ciphertext.to_bytes()),
            session_id,
            server_public_key: hex::encode(self.server_keypair.public.to_bytes()),
        })
    }

    /// Decrypt an encrypted RPC request.
    pub fn decrypt_request(
        &self,
        req: &EncryptedRpcRequest,
    ) -> Result<(String, PqRpcSession), String> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;

        let session = sessions
            .get_mut(&req.session_id)
            .ok_or("unknown session ID")?;

        // Check nonce monotonicity (replay protection)
        if req.nonce <= session.nonce_counter {
            return Err("nonce replay detected".into());
        }
        session.nonce_counter = req.nonce;

        // Decrypt payload with AES-256-GCM (authenticated). A tampered
        // ciphertext or wrong key/nonce fails the GCM auth-tag check and is
        // rejected rather than silently producing a corrupted plaintext —
        // the guarantee the old XOR keystream placeholder could not give.
        let encrypted = hex::decode(&req.encrypted_payload)
            .map_err(|_| "invalid encrypted payload hex".to_string())?;
        let nonce_bytes = req.nonce.to_le_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_bytes);

        let decrypted = aes_gcm_open(&encrypted, &session.session_key, &nonce12)?;
        let plaintext =
            String::from_utf8(decrypted).map_err(|_| "decrypted payload is not UTF-8")?;

        Ok((plaintext, session.clone()))
    }

    /// Encrypt an RPC response.
    ///
    /// Returns an error rather than an envelope if sealing fails (an
    /// impossible key-length mismatch for the fixed 32-byte session key), so
    /// a broken session surfaces loudly instead of emitting a degenerate
    /// ciphertext.
    pub fn encrypt_response(
        &self,
        session: &PqRpcSession,
        response_json: &str,
        nonce: u64,
    ) -> Result<EncryptedRpcResponse, String> {
        let nonce_bytes = nonce.to_le_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_bytes);

        let encrypted = aes_gcm_seal(response_json.as_bytes(), &session.session_key, &nonce12)?;

        Ok(EncryptedRpcResponse {
            encrypted_payload: hex::encode(&encrypted),
            nonce,
        })
    }

    /// Get number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// Seal `plaintext` with AES-256-GCM under the session key. Returns
/// `ciphertext || tag` (the 16-byte GCM auth tag is appended to the
/// ciphertext by the `aes-gcm` crate). This replaces the old XOR keystream
/// placeholder, which gave confidentiality but no integrity: an attacker
/// who flipped a ciphertext byte silently flipped the plaintext bit.
fn aes_gcm_seal(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "invalid AES-256 session key length".to_string())?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AES-256-GCM seal failed: {e}"))
}

/// Open an AES-256-GCM seal under the session key. Verifies the GCM auth
/// tag before returning the plaintext, so any tampering with the ciphertext
/// (or a wrong key/nonce) is rejected instead of silently decrypting to
/// garbage.
fn aes_gcm_open(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "invalid AES-256 session key length".to_string())?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| {
            "AES-256-GCM open failed: auth tag mismatch (tampered ciphertext or wrong key)"
                .to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_rpc_manager_creation() {
        let mgr = PqRpcManager::new();
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_session_debug_masks_key() {
        let full_key = [0xABu8; 32];
        let session = PqRpcSession {
            session_id: "test-session".into(),
            session_key: full_key,
            nonce_counter: 7,
        };
        let rendered = format!("{:?}", session);
        // The full 32-byte key hex must never appear in the Debug output.
        assert!(!rendered.contains(&hex::encode(full_key)));
        // Only the first 4 bytes, truncated.
        assert!(rendered.contains(&hex::encode(&full_key[..4])));
        assert!(rendered.contains("…"));
        assert!(rendered.contains("nonce_counter: 7"));
    }

    #[test]
    fn test_handshake() {
        let mgr = PqRpcManager::new();
        let client_kp = KemKeypair::generate();
        let req = HandshakeRequest {
            client_public_key: hex::encode(client_kp.public.to_bytes()),
        };
        let resp = mgr.handshake(&req).unwrap();
        assert!(!resp.session_id.is_empty());
        assert!(!resp.ciphertext.is_empty());
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mgr = PqRpcManager::new();
        let client_kp = KemKeypair::generate();

        let resp = mgr
            .handshake(&HandshakeRequest {
                client_public_key: hex::encode(client_kp.public.to_bytes()),
            })
            .unwrap();

        // Client would derive the same session key via kem_decapsulate
        // For testing, we use the server's encrypt/decrypt directly
        let session = mgr
            .sessions
            .lock()
            .unwrap()
            .get(&resp.session_id)
            .unwrap()
            .clone();

        let plaintext = r#"{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}"#;
        let encrypted_resp = mgr.encrypt_response(&session, plaintext, 1).unwrap();
        assert!(!encrypted_resp.encrypted_payload.is_empty());

        // Decrypt using the same key (authenticated — verifies the GCM tag).
        let encrypted_bytes = hex::decode(&encrypted_resp.encrypted_payload).unwrap();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&1u64.to_le_bytes());
        let decrypted = aes_gcm_open(&encrypted_bytes, &session.session_key, &nonce12).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext);

        // Tamper with a single ciphertext byte — the GCM auth tag must
        // reject it (the guarantee the old XOR keystream could not give).
        let mut tampered = encrypted_bytes.clone();
        tampered[0] ^= 0x01;
        assert!(
            aes_gcm_open(&tampered, &session.session_key, &nonce12).is_err(),
            "a tampered ciphertext must fail the GCM auth tag"
        );
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let mgr = PqRpcManager::new();
        let client_kp = KemKeypair::generate();

        let resp = mgr
            .handshake(&HandshakeRequest {
                client_public_key: hex::encode(client_kp.public.to_bytes()),
            })
            .unwrap();

        let session = mgr
            .sessions
            .lock()
            .unwrap()
            .get(&resp.session_id)
            .unwrap()
            .clone();

        let encrypted = mgr.encrypt_response(&session, "test", 1).unwrap();

        let req = EncryptedRpcRequest {
            session_id: resp.session_id.clone(),
            encrypted_payload: encrypted.encrypted_payload.clone(),
            nonce: 1,
        };

        // First request succeeds
        assert!(mgr.decrypt_request(&req).is_ok());

        // Replay with same nonce fails
        let replay = EncryptedRpcRequest {
            session_id: resp.session_id,
            encrypted_payload: encrypted.encrypted_payload,
            nonce: 1,
        };
        assert!(mgr.decrypt_request(&replay).is_err());
    }
}
