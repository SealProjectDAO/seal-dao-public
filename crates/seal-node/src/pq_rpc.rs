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

use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemKeypair, KemPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Session state for a PQ-encrypted RPC connection.
#[derive(Clone, Debug)]
pub struct PqRpcSession {
    /// Session ID (SHA3 of shared secret).
    pub session_id: String,
    /// Derived session key for AES-256-GCM.
    pub session_key: [u8; 32],
    /// Monotonic nonce counter (prevents replay).
    pub nonce_counter: u64,
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

        // Decrypt payload (XOR-based placeholder — replace with AES-256-GCM)
        let encrypted = hex::decode(&req.encrypted_payload)
            .map_err(|_| "invalid encrypted payload hex".to_string())?;
        let nonce_bytes = req.nonce.to_le_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_bytes);

        let decrypted = xor_decrypt(&encrypted, &session.session_key, &nonce12);
        let plaintext =
            String::from_utf8(decrypted).map_err(|_| "decrypted payload is not UTF-8")?;

        Ok((plaintext, session.clone()))
    }

    /// Encrypt an RPC response.
    pub fn encrypt_response(
        &self,
        session: &PqRpcSession,
        response_json: &str,
        nonce: u64,
    ) -> EncryptedRpcResponse {
        let nonce_bytes = nonce.to_le_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_bytes);

        let encrypted = xor_decrypt(response_json.as_bytes(), &session.session_key, &nonce12);

        EncryptedRpcResponse {
            encrypted_payload: hex::encode(&encrypted),
            nonce,
        }
    }

    /// Get number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// XOR-based stream cipher (placeholder for AES-256-GCM).
fn xor_decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(data.len());
    let seed: Vec<u8> = key.iter().chain(nonce.iter()).copied().collect();
    let mut hash = sha3_256(&seed);
    while keystream.len() < data.len() {
        keystream.extend_from_slice(&hash.0);
        hash = sha3_256(&hash.0);
    }
    data.iter()
        .zip(keystream.iter())
        .map(|(d, k)| d ^ k)
        .collect()
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
        let encrypted_resp = mgr.encrypt_response(&session, plaintext, 1);
        assert!(!encrypted_resp.encrypted_payload.is_empty());

        // Decrypt using the same key
        let encrypted_bytes = hex::decode(&encrypted_resp.encrypted_payload).unwrap();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&1u64.to_le_bytes());
        let decrypted = xor_decrypt(&encrypted_bytes, &session.session_key, &nonce12);
        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext);
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

        let encrypted = mgr.encrypt_response(&session, "test", 1);

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
