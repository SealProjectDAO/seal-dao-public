//! forms.seal — encrypted surveys with iterated-hash answer traces.
//!
//! Demo app library. Implements the design notes in TODO.md /
//! TODOS.md:
//!
//! - **Per-form ML-KEM keypair.** The form owner publishes the
//!   ML-KEM-768 public key. Respondents derive a per-answer symmetric
//!   key by HKDF-SHA3-256-expanding the encapsulated shared secret;
//!   the answer is encrypted with AES-256-GCM and the (KEM ciphertext,
//!   AES ciphertext+tag) go on-chain. Only the form owner (or an MPC
//!   committee, in the public-survey variant) can decrypt.
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
//! ## AEAD construction (2026-05-08 swap, replaces the old
//! ##  XOR-stream + bespoke HMAC wrapper)
//!
//! Per [TODOS.md PLAN #3]:
//!
//! - **Symmetric key**: `HKDF-SHA3-256(ikm = shared_secret,
//!   salt = None, info = b"forms.seal/v1/aes-key")` → 32 bytes.
//! - **Nonce**: deterministic
//!   `SHA3-256(form_id_le || respondent_addr || idx_le)[..12]`.
//!   Auditor-reconstructible; unique-per-submission by construction
//!   (the (form, respondent, idx) tuple is unique on-chain).
//! - **AAD**: `form_id_le || schema_hash || respondent_addr`. Binds
//!   the ciphertext to its form context — replaying a response under
//!   a different `respondent_addr` or `form_id` produces an AAD
//!   mismatch and the tag fails to verify.
//! - **Cipher**: `aes-gcm 0.10` (`Aes256Gcm`). 16-byte auth tag
//!   appended to the body.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemCiphertext, KemPublicKey, KemSecretKey};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

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

/// Form-context hash used to bind responses to their form. Computed
/// once at form-creation time and stored alongside the form record;
/// re-derived by respondents and auditors from `schema_json`. Cheap
/// to recompute (one SHA3-256), so we don't bother caching.
pub fn schema_hash(schema_json: &str) -> [u8; 32] {
    sha3_256(schema_json.as_bytes()).0
}

/// Per-answer context that goes into the AAD and nonce derivation.
/// All fields are public on-chain (form_id, schema_hash via the form
/// row, respondent_addr, idx via response ordering), so anyone with
/// the form record can reconstruct this for verification — the AEAD
/// auth tag is what proves the response wasn't tampered with.
#[derive(Clone, Debug)]
pub struct AnswerContext<'a> {
    pub form_id: u64,
    pub schema_hash: [u8; 32],
    pub respondent_addr: &'a str,
    pub idx: u64,
}

/// AES key derived from an ML-KEM shared secret via HKDF-SHA3-256.
/// `info` is a fixed domain separator (`b"forms.seal/v1/aes-key"`) so
/// other future uses of the shared secret derive non-overlapping
/// keys.
fn derive_aes_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"forms.seal/v1/aes-key", &mut key)
        .expect("32 bytes fits in HKDF-SHA3-256 output");
    key
}

/// 12-byte AES-GCM nonce derived deterministically from the answer
/// context. Uniqueness follows from `(form_id, respondent_addr, idx)`
/// being unique on-chain. If a respondent ever resubmits with the
/// same `idx`, the nonce repeats and AES-GCM's confidentiality
/// guarantee breaks — the protocol must enforce monotonic `idx` per
/// `(form_id, respondent_addr)`.
fn derive_nonce(ctx: &AnswerContext) -> [u8; 12] {
    let mut buf = Vec::with_capacity(8 + ctx.respondent_addr.len() + 8);
    buf.extend_from_slice(&ctx.form_id.to_le_bytes());
    buf.extend_from_slice(ctx.respondent_addr.as_bytes());
    buf.extend_from_slice(&ctx.idx.to_le_bytes());
    let h = sha3_256(&buf).0;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&h[..12]);
    nonce
}

/// AAD for AES-GCM. Encodes `form_id || schema_hash || respondent_addr`;
/// any mismatch on the recipient side fails the tag check.
fn build_aad(ctx: &AnswerContext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 32 + ctx.respondent_addr.len());
    aad.extend_from_slice(&ctx.form_id.to_le_bytes());
    aad.extend_from_slice(&ctx.schema_hash);
    aad.extend_from_slice(ctx.respondent_addr.as_bytes());
    aad
}

/// Encrypt one answer for a form. Returns the on-chain payload bytes
/// (KEM ciphertext + answer ciphertext+tag) plus the new trace hash.
///
/// `prev_trace` is the trace hash of the most recent response (or
/// the form's genesis trace, for the first respondent). The trace
/// chain hashes the AEAD-bundled `answer_ct` (which includes the
/// 16-byte auth tag) so any tampering invalidates both the tag and
/// the chain.
pub struct EncryptedAnswer {
    pub kem_ct: KemCiphertext,
    pub answer_ct: Vec<u8>,
    pub trace_hash: [u8; 32],
}

pub fn encrypt_answer(
    form_pk: &KemPublicKey,
    prev_trace: &[u8; 32],
    ctx: &AnswerContext,
    plaintext: &[u8],
) -> EncryptedAnswer {
    let (shared, kem_ct) = form_pk.encapsulate();
    let key_bytes = derive_aes_key(shared.as_bytes());
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = derive_nonce(ctx);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = build_aad(ctx);
    let answer_ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("AES-GCM encrypt cannot fail on valid 12-byte nonce");
    let trace_hash = next_trace(prev_trace, &answer_ct);
    EncryptedAnswer {
        kem_ct,
        answer_ct,
        trace_hash,
    }
}

/// Decrypt one answer. Form owner runs this with their ML-KEM secret
/// key to recover the plaintext. The auth tag (last 16 bytes of
/// `answer_ct`) is verified against the AAD derived from `ctx`; any
/// mismatch returns an error and no plaintext is exposed.
pub fn decrypt_answer(
    form_sk: &KemSecretKey,
    kem_ct: &KemCiphertext,
    ctx: &AnswerContext,
    answer_ct: &[u8],
) -> Result<Vec<u8>, String> {
    let shared = form_sk
        .decapsulate(kem_ct)
        .map_err(|e| format!("decapsulate failed: {}", e))?;
    let key_bytes = derive_aes_key(shared.as_bytes());
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = derive_nonce(ctx);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = build_aad(ctx);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: answer_ct,
                aad: &aad,
            },
        )
        .map_err(|_| "AES-GCM auth tag mismatch (or context drift)".to_string())
}

/// Verify that a `(prev, answer_ct, trace)` triple matches the chain
/// rule. Auditors call this for every response to confirm the chain
/// is intact without ever needing the plaintexts.
pub fn verify_trace(prev: &[u8; 32], answer_ct: &[u8], expected: &[u8; 32]) -> bool {
    next_trace(prev, answer_ct) == *expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::kem::KemKeypair;

    fn ctx_for<'a>(form_id: u64, respondent: &'a str, idx: u64, schema: &str) -> AnswerContext<'a> {
        AnswerContext {
            form_id,
            schema_hash: schema_hash(schema),
            respondent_addr: respondent,
            idx,
        }
    }

    #[test]
    fn round_trip_single_answer() {
        let kp = KemKeypair::generate();
        let schema = "{\"q\":\"yes/no\"}";
        let genesis = genesis_trace(1, "alice", schema);
        let plaintext = b"yes";
        let ctx = ctx_for(1, "respondent-alice", 0, schema);
        let enc = encrypt_answer(&kp.public, &genesis, &ctx, plaintext);

        // Trace continues the chain.
        assert!(verify_trace(&genesis, &enc.answer_ct, &enc.trace_hash));
        // AES-GCM appends a 16-byte tag to the ciphertext body.
        assert_eq!(enc.answer_ct.len(), plaintext.len() + 16);

        let recovered = decrypt_answer(&kp.secret, &enc.kem_ct, &ctx, &enc.answer_ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chain_links_three_responses() {
        let kp = KemKeypair::generate();
        let schema = "schema";
        let genesis = genesis_trace(7, "bob", schema);
        let mut prev = genesis;
        let mut traces = Vec::new();
        let mut cts = Vec::new();
        for (i, body) in [b"alpha".as_ref(), b"beta", b"gamma"].iter().enumerate() {
            let ctx = ctx_for(7, "respondent-x", i as u64, schema);
            let enc = encrypt_answer(&kp.public, &prev, &ctx, body);
            assert!(verify_trace(&prev, &enc.answer_ct, &enc.trace_hash));
            prev = enc.trace_hash;
            traces.push(enc.trace_hash);
            cts.push(enc.answer_ct);
        }
        // Auditor walk: reproduce every trace from genesis. The
        // auditor never decrypts — only the AEAD-bundled ciphertext
        // (body + tag) participates in the chain, so a tampered
        // tag would visibly break the chain too.
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
    fn wrong_secret_decrypt_returns_error() {
        let owner = KemKeypair::generate();
        let stranger = KemKeypair::generate();
        let schema = "schema";
        let genesis = genesis_trace(1, "alice", schema);
        let ctx = ctx_for(1, "alice", 0, schema);
        let enc = encrypt_answer(&owner.public, &genesis, &ctx, b"top secret");
        // ML-KEM decapsulate against the wrong key returns SOME bytes
        // (it's a KEM), so the HKDF derives a *different* key. AES-GCM
        // tag verification then fails — the previous XOR demo would
        // silently return garbage, but AEAD makes the failure
        // observable.
        let err = decrypt_answer(&stranger.secret, &enc.kem_ct, &ctx, &enc.answer_ct).unwrap_err();
        assert!(err.contains("auth tag mismatch") || err.contains("decapsulate"));
    }

    #[test]
    fn aad_drift_rejects_decrypt() {
        // Same key, same nonce-driving fields except respondent_addr
        // changes — AAD differs → tag mismatch.
        let kp = KemKeypair::generate();
        let schema = "schema";
        let genesis = genesis_trace(1, "owner", schema);
        let alice_ctx = ctx_for(1, "alice", 0, schema);
        let enc = encrypt_answer(&kp.public, &genesis, &alice_ctx, b"alice's answer");

        let bob_ctx = ctx_for(1, "bob", 0, schema);
        let err = decrypt_answer(&kp.secret, &enc.kem_ct, &bob_ctx, &enc.answer_ct).unwrap_err();
        assert!(err.contains("auth tag mismatch"));
    }

    #[test]
    fn schema_drift_rejects_decrypt() {
        // form_id and respondent match but schema_hash drifted (e.g.
        // form schema was changed after submission). AAD mismatch.
        let kp = KemKeypair::generate();
        let genesis = genesis_trace(1, "owner", "v1-schema");
        let v1_ctx = ctx_for(1, "alice", 0, "v1-schema");
        let enc = encrypt_answer(&kp.public, &genesis, &v1_ctx, b"answer");

        let v2_ctx = ctx_for(1, "alice", 0, "v2-schema");
        let err = decrypt_answer(&kp.secret, &enc.kem_ct, &v2_ctx, &enc.answer_ct).unwrap_err();
        assert!(err.contains("auth tag mismatch"));
    }

    #[test]
    fn ciphertext_tampering_breaks_tag_and_chain() {
        // Flipping a bit in the ciphertext body breaks both the
        // AES-GCM auth tag *and* the trace chain (because the chain
        // hashes the bundled ciphertext+tag). Either failure is
        // sufficient to detect tampering; we check both.
        let kp = KemKeypair::generate();
        let schema = "schema";
        let genesis = genesis_trace(1, "owner", schema);
        let ctx = ctx_for(1, "alice", 0, schema);
        let enc = encrypt_answer(&kp.public, &genesis, &ctx, b"answer-payload");

        let mut tampered = enc.answer_ct.clone();
        tampered[0] ^= 1;

        // Tag fails.
        let err = decrypt_answer(&kp.secret, &enc.kem_ct, &ctx, &tampered).unwrap_err();
        assert!(err.contains("auth tag mismatch"));

        // Trace also fails (the original `enc.trace_hash` was over
        // the un-tampered ciphertext).
        assert!(!verify_trace(&genesis, &tampered, &enc.trace_hash));
    }

    #[test]
    fn deterministic_nonce_matches_spec() {
        // The nonce derivation is deterministic and depends only on
        // (form_id, respondent_addr, idx) — auditors and respondents
        // both reconstruct the same 12 bytes. Sanity-check the
        // formula directly.
        let ctx = AnswerContext {
            form_id: 42,
            schema_hash: [0xAA; 32], // schema_hash isn't part of the nonce
            respondent_addr: "alice",
            idx: 7,
        };
        let mut expected_in = Vec::new();
        expected_in.extend_from_slice(&42u64.to_le_bytes());
        expected_in.extend_from_slice(b"alice");
        expected_in.extend_from_slice(&7u64.to_le_bytes());
        let expected_full = sha3_256(&expected_in).0;
        assert_eq!(&derive_nonce(&ctx), &expected_full[..12]);
    }
}
