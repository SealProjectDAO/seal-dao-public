//! forms.seal — encrypted surveys with iterated-hash answer traces.
//!
//! Demo app library. Implements the design notes in TODO.md /
//! TODOS.md:
//!
//! - **Per-form ML-KEM keypair.** The form owner publishes the
//!   ML-KEM-768 public key. Respondents derive a per-answer symmetric
//!   key by encapsulating against it; the answer is encrypted with
//!   that key and the ciphertext + KEM ciphertext go on-chain. Only
//!   the form owner (or an MPC committee, in the public-survey
//!   variant) can decrypt.
//!
//! - **Iterated answer trace.** Each response carries
//!   `trace_hash = SHA3(prev_trace_hash || ct_answer)`. Together
//!   these form an append-only chain rooted at the form's genesis
//!   trace, so any auditor can verify the complete answer set
//!   without learning the answers themselves. This is the structure
//!   that future ZK-provable statistics will commit to.
//!
//! - **Schema.** Two tables:
//!     * `forms`: id, owner, schema_json, mlkem_pk_hex, genesis_trace,
//!       created_at
//!     * `responses`: form_id, respondent_addr, kem_ct_hex,
//!       answer_ct_hex, trace_hash, prev_trace_hash, sig_hex
//!
//! The library deliberately keeps the symmetric cipher trivial
//! (XOR-with-derived-key) so the demo focuses on the KEM /
//! trace-chain shape rather than an AES-GCM dependency. Production
//! deployments would swap in `seal-crypto`'s AEAD layer once that
//! lands.

use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemCiphertext, KemPublicKey, KemSecretKey};
use serde::{Deserialize, Serialize};

pub mod aead;
pub mod mpc_sum;
pub mod zk_stats;

/// On-chain row for the `forms` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormRecord {
    pub id: u64,
    pub owner: String,
    pub schema_json: String,
    pub mlkem_pk_hex: String,
    pub genesis_trace_hex: String,
    pub created_at_height: u64,
}

/// On-chain row for the `responses` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub form_id: u64,
    pub respondent_addr: String,
    pub kem_ct_hex: String,
    pub answer_ct_hex: String,
    pub trace_hash_hex: String,
    pub prev_trace_hash_hex: String,
    pub sig_hex: String,
    pub block_height: u64,
}

/// The DDL that an `appstore` would deploy when first registering
/// `forms.seal`. Kept as a constant so tests and the binary can both
/// reference the same canonical schema.
pub const SCHEMA_DDL: &str = "
CREATE TABLE forms (
    id BIGINT PRIMARY KEY,
    owner TEXT NOT NULL,
    schema_json TEXT NOT NULL,
    mlkem_pk_hex TEXT NOT NULL,
    genesis_trace_hex TEXT NOT NULL,
    created_at_height BIGINT NOT NULL
);

CREATE TABLE responses (
    form_id BIGINT NOT NULL,
    respondent_addr TEXT NOT NULL,
    kem_ct_hex TEXT NOT NULL,
    answer_ct_hex TEXT NOT NULL,
    trace_hash_hex TEXT NOT NULL,
    prev_trace_hash_hex TEXT NOT NULL,
    sig_hex TEXT NOT NULL,
    block_height BIGINT NOT NULL
);
";

/// Compute the genesis trace for a new form. Pinning this on form
/// creation lets the first response chain off a deterministic value
/// so trace verification has a fixed root.
pub fn genesis_trace(form_id: u64, owner: &str, schema_json: &str) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&form_id.to_le_bytes());
    buf.extend_from_slice(owner.as_bytes());
    buf.extend_from_slice(schema_json.as_bytes());
    sha3_256(&buf).0
}

/// `trace_i = SHA3(prev_trace_i_minus_1 || answer_ct_i)`. The append-
/// only chain that future ZK statistics commit to.
pub fn next_trace(prev: &[u8; 32], answer_ct: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + answer_ct.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(answer_ct);
    sha3_256(&buf).0
}

/// Encrypt one answer for a form. Returns the on-chain payload bytes
/// (KEM ciphertext + answer ciphertext) plus the new trace hash.
///
/// `prev_trace` is the trace hash of the most recent response (or
/// the form's genesis trace, for the first respondent).
pub struct EncryptedAnswer {
    pub kem_ct: KemCiphertext,
    pub answer_ct: Vec<u8>,
    pub trace_hash: [u8; 32],
}

pub fn encrypt_answer(
    form_pk: &KemPublicKey,
    prev_trace: &[u8; 32],
    plaintext: &[u8],
) -> EncryptedAnswer {
    let (shared, kem_ct) = form_pk.encapsulate();
    let answer_ct = xor_stream(shared.as_bytes(), plaintext);
    let trace_hash = next_trace(prev_trace, &answer_ct);
    EncryptedAnswer {
        kem_ct,
        answer_ct,
        trace_hash,
    }
}

/// Decrypt one answer. Form owner runs this with their ML-KEM secret
/// key to recover the plaintext; the trace hash must be recomputable
/// from the produced ciphertext for the answer to count as valid.
pub fn decrypt_answer(
    form_sk: &KemSecretKey,
    kem_ct: &KemCiphertext,
    answer_ct: &[u8],
) -> Result<Vec<u8>, String> {
    let shared = form_sk
        .decapsulate(kem_ct)
        .map_err(|e| format!("decapsulate failed: {}", e))?;
    Ok(xor_stream(shared.as_bytes(), answer_ct))
}

/// Verify that a `(prev, answer_ct, trace)` triple matches the chain
/// rule. Auditors call this for every response to confirm the chain
/// is intact without ever needing the plaintexts.
pub fn verify_trace(prev: &[u8; 32], answer_ct: &[u8], expected: &[u8; 32]) -> bool {
    next_trace(prev, answer_ct) == *expected
}

/// Symmetric stream cipher used for the demo: XOR the plaintext with
/// SHA3-256-expanded shared secret bytes. This is intentionally a
/// stand-in for a real AEAD — the demo's purpose is the trace chain,
/// not the cipher. Production swaps in `seal-crypto`'s AEAD.
pub fn xor_stream(key_bytes: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter: u64 = 0;
    let mut block = expand_block(key_bytes, counter);
    let mut idx = 0;
    for &b in data {
        if idx == block.len() {
            counter = counter.saturating_add(1);
            block = expand_block(key_bytes, counter);
            idx = 0;
        }
        out.push(b ^ block[idx]);
        idx += 1;
    }
    out
}

fn expand_block(key: &[u8], counter: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(key.len() + 8);
    buf.extend_from_slice(key);
    buf.extend_from_slice(&counter.to_le_bytes());
    sha3_256(&buf).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::kem::KemKeypair;

    #[test]
    fn round_trip_single_answer() {
        let kp = KemKeypair::generate();
        let genesis = genesis_trace(1, "alice", "{\"q\":\"yes/no\"}");
        let plaintext = b"yes";
        let enc = encrypt_answer(&kp.public, &genesis, plaintext);

        // Trace continues the chain.
        assert!(verify_trace(&genesis, &enc.answer_ct, &enc.trace_hash));

        let recovered = decrypt_answer(&kp.secret, &enc.kem_ct, &enc.answer_ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chain_links_three_responses() {
        let kp = KemKeypair::generate();
        let genesis = genesis_trace(7, "bob", "schema");
        let mut prev = genesis;
        let mut traces = Vec::new();
        let mut cts = Vec::new();
        for body in [b"alpha".as_ref(), b"beta", b"gamma"] {
            let enc = encrypt_answer(&kp.public, &prev, body);
            assert!(verify_trace(&prev, &enc.answer_ct, &enc.trace_hash));
            prev = enc.trace_hash;
            traces.push(enc.trace_hash);
            cts.push(enc.answer_ct);
        }
        // Auditor walk: reproduce every trace from genesis.
        let mut walk = genesis;
        for (i, ct) in cts.iter().enumerate() {
            let recomputed = next_trace(&walk, ct);
            assert_eq!(recomputed, traces[i]);
            walk = traces[i];
        }
    }

    #[test]
    fn schema_ddl_parses() {
        // The DDL must be ingestible by the seal-sql parser so the
        // appstore can deploy it without a custom path.
        seal_sql::parse_sql(SCHEMA_DDL).expect("forms.seal DDL must parse");
    }

    #[test]
    fn wrong_secret_decrypt_does_not_recover_plaintext() {
        let owner = KemKeypair::generate();
        let stranger = KemKeypair::generate();
        let genesis = genesis_trace(1, "alice", "schema");
        let enc = encrypt_answer(&owner.public, &genesis, b"top secret");
        // ML-KEM decapsulate against the wrong key returns SOME bytes
        // (it's a KEM), but they're not the encapsulator's shared
        // secret — so XOR'ing them produces garbage, not "top secret".
        let bad = decrypt_answer(&stranger.secret, &enc.kem_ct, &enc.answer_ct).unwrap();
        assert_ne!(bad, b"top secret");
    }
}
