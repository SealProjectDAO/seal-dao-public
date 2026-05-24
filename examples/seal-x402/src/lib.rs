//! x402 payment-required HTTP demo on Seal DAO.
//!
//! HTTP 402 ("Payment Required") was specified in 1998 and never
//! given a settlement layer. This crate ships the building blocks
//! for using Seal as one:
//!
//! 1. The server returns `402` with a `WWW-Authenticate: x402-seal`
//!    header carrying a `PaymentRequest` (recipient address, amount
//!    in micro-SEAL, expiry, opaque order id).
//! 2. The client signs a `PaymentReceipt` over the request bytes
//!    using its ML-DSA wallet, attaches `Authorization: x402-seal
//!    base64(receipt)`, and retries the request.
//! 3. The server verifies the ML-DSA signature, posts the receipt to
//!    the chain via `seal_transfer`, and serves the resource.
//!
//! This crate owns the `PaymentRequest` / `PaymentReceipt` types and
//! their canonical serialisation. The HTTP wiring + node submission
//! are caller's choice.

use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Server-issued challenge attached to an HTTP 402 response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub recipient: String,
    /// Amount in micro-SEAL (1 SEAL = 1_000_000 micro-SEAL).
    pub micro_seal: u64,
    /// Unix-seconds expiry. After this, the receipt is no longer
    /// settleable on chain — server should reissue.
    pub expires_at: u64,
    /// Opaque per-resource id chosen by the server. Returned in the
    /// receipt so the server can match payment to request.
    pub order_id: String,
}

impl PaymentRequest {
    /// Canonical bytes the client signs: request + the resource's
    /// HTTP method/path + body hash, so a receipt can't be replayed
    /// against a different endpoint.
    pub fn challenge_bytes(&self, method: &str, path: &str, body_hash: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.recipient.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.micro_seal.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf.extend_from_slice(self.order_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(method.as_bytes());
        buf.push(0);
        buf.extend_from_slice(path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(body_hash);
        buf
    }
}

/// Client-signed receipt attached as `Authorization: x402-seal …`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentReceipt {
    pub request: PaymentRequest,
    /// Payer's ML-DSA verifying key (hex).
    pub payer_vk_hex: String,
    /// Detached ML-DSA signature over `challenge_bytes(...)` (hex).
    pub signature_hex: String,
}

impl PaymentReceipt {
    /// Sign a payment request with `signing_key`. The HTTP method,
    /// path, and body hash bind the receipt to one specific request
    /// so it can't be replayed against another endpoint.
    pub fn sign(
        request: PaymentRequest,
        method: &str,
        path: &str,
        body_hash: &[u8; 32],
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
    ) -> Result<Self, String> {
        let challenge = request.challenge_bytes(method, path, body_hash);
        let sig = signing_key
            .sign(&challenge)
            .map_err(|e| format!("sign failed: {}", e))?;
        Ok(Self {
            request,
            payer_vk_hex: hex::encode(verifying_key.to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
        })
    }

    /// Server-side verification. Returns `Ok(())` if the receipt is
    /// algebraically valid for the stated request + endpoint.
    /// Whether it has been *settled* on chain is a separate check.
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        body_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<(), String> {
        if now_secs > self.request.expires_at {
            return Err("receipt expired".into());
        }
        let vk_bytes = hex::decode(&self.payer_vk_hex).map_err(|e| format!("vk hex: {}", e))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|e| format!("vk decode: {}", e))?;
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| format!("sig hex: {}", e))?;
        let sig = Signature::from_bytes(sig_bytes);
        let challenge = self.request.challenge_bytes(method, path, body_hash);
        vk.verify(&challenge, &sig)
            .map_err(|e| format!("ml-dsa verify: {}", e))
    }
}

/// Convenience: SHA3-256 of an HTTP body. Server and client must
/// agree on this hash so the signed challenge matches.
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    sha3_256(body).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req() -> PaymentRequest {
        PaymentRequest {
            recipient: "seal1node".into(),
            micro_seal: 100,
            expires_at: 9_999_999_999,
            order_id: "order:42".into(),
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, vk) = SigningKey::generate();
        let body = b"GET /summary";
        let bh = body_hash(body);
        let receipt = PaymentReceipt::sign(make_req(), "GET", "/summary", &bh, &sk, &vk).unwrap();
        receipt
            .verify("GET", "/summary", &bh, 1_000_000)
            .expect("valid receipt must verify");
    }

    #[test]
    fn replay_against_different_endpoint_rejected() {
        let (sk, vk) = SigningKey::generate();
        let body = b"";
        let bh = body_hash(body);
        let receipt = PaymentReceipt::sign(make_req(), "GET", "/a", &bh, &sk, &vk).unwrap();
        let err = receipt.verify("GET", "/b", &bh, 1_000_000).unwrap_err();
        assert!(
            err.contains("ml-dsa verify"),
            "expected verify failure, got {}",
            err
        );
    }

    #[test]
    fn expired_receipt_rejected() {
        let (sk, vk) = SigningKey::generate();
        let body = b"";
        let bh = body_hash(body);
        let mut req = make_req();
        req.expires_at = 100;
        let receipt = PaymentReceipt::sign(req, "GET", "/x", &bh, &sk, &vk).unwrap();
        let err = receipt.verify("GET", "/x", &bh, 200).unwrap_err();
        assert!(err.contains("expired"));
    }
}
