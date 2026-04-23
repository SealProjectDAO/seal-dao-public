//! kindle.seal — encrypted-chapter ebook publishing on Seal DAO.
//!
//! # Model
//!
//! A *publisher* uploads a book as a sequence of encrypted chapters.
//! Each chapter is encrypted under a *book content key* (BCK) — a
//! 32-byte symmetric key the publisher generates once per book.
//!
//! When a *reader* purchases the book, the publisher (or a KYC-gated
//! token holder check) encapsulates the BCK against the reader's
//! ML-KEM-768 public key and posts the wrap into the
//! `book_grants` table. The reader decapsulates with their secret
//! key to recover the BCK and decrypts chapters locally.
//!
//! # Why per-chapter encryption (not per-reader)
//!
//! * Storage cost: one ciphertext per chapter, regardless of reader
//!   count. Per-reader encryption would N-multiply the storage.
//! * Reader churn: granting a new reader access is one cheap
//!   `(reader_pubkey, kem_ct)` row, not a re-encryption of every
//!   chapter.
//! * Revocation: posting a new BCK + re-encrypting future chapters
//!   under it cuts off revoked readers from new content (existing
//!   chapters they downloaded remain readable — same threat model
//!   as Kindle today).
//!
//! # What this crate ships
//!
//! Schema, RLS, the `BookContentKey` type, a deterministic
//! XOR-stream chapter cipher (placeholder for the real AEAD), and
//! the `wrap_for_reader` / `unwrap_for_reader` flow.

use seal_crypto::hash::sha3_256;
use seal_crypto::kem::{KemCiphertext, KemPublicKey, KemSecretKey};
use serde::{Deserialize, Serialize};

pub const SCHEMA_DDL: &str = "
CREATE TABLE books (
    id BIGINT PRIMARY KEY,
    publisher TEXT NOT NULL,
    title TEXT NOT NULL,
    chapter_count BIGINT NOT NULL,
    bck_fingerprint_hex TEXT NOT NULL,
    created_at_height BIGINT NOT NULL
);

CREATE TABLE chapters (
    book_id BIGINT NOT NULL,
    chapter_index BIGINT NOT NULL,
    ciphertext_hex TEXT NOT NULL,
    PRIMARY KEY (book_id, chapter_index)
);

CREATE TABLE book_grants (
    book_id BIGINT NOT NULL,
    reader TEXT NOT NULL,
    kem_ct_hex TEXT NOT NULL,
    granted_at_height BIGINT NOT NULL,
    PRIMARY KEY (book_id, reader)
);
";

pub fn rls_policies() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // Only the publisher can edit the book / its chapters.
        ("books", "INSERT_OWNER", "publisher = CURRENT_USER()"),
        ("chapters", "INSERT_OWNER", "EXISTS (SELECT 1 FROM books WHERE id = chapters.book_id AND publisher = CURRENT_USER())"),
        // Grants are written by the publisher; readers can SELECT
        // their own row (others' grants are useless without their
        // ML-KEM secret, but hiding them is good UX).
        ("book_grants", "INSERT_PUB",
         "EXISTS (SELECT 1 FROM books WHERE id = book_grants.book_id AND publisher = CURRENT_USER())"),
        ("book_grants", "SELECT_OWNER", "reader = CURRENT_USER()"),
    ]
}

/// 32-byte book content key. Held only by the publisher (and decrypted
/// per-reader via ML-KEM at grant time).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BookContentKey(pub [u8; 32]);

impl BookContentKey {
    /// Generate a fresh BCK from a CSPRNG seed (caller-supplied so
    /// tests are deterministic).
    pub fn from_seed(seed: &[u8]) -> Self {
        BookContentKey(sha3_256(seed).0)
    }

    /// 8-byte fingerprint stored in `books.bck_fingerprint_hex` so a
    /// reader can confirm they decoded the right key.
    pub fn fingerprint_hex(&self) -> String {
        let h = sha3_256(&self.0).0;
        hex::encode(&h[..8])
    }
}

/// Encrypt a chapter body using the BCK + a per-chapter index. The
/// index is mixed into the keystream so two identical chapter bodies
/// don't produce identical ciphertexts (which would leak repeated
/// content via byte equality).
pub fn encrypt_chapter(bck: &BookContentKey, chapter_index: u64, plaintext: &[u8]) -> Vec<u8> {
    xor_stream(&derive_chapter_key(bck, chapter_index), plaintext)
}

/// Decrypt a chapter body. The same keystream as `encrypt_chapter` —
/// XOR is involutive.
pub fn decrypt_chapter(bck: &BookContentKey, chapter_index: u64, ciphertext: &[u8]) -> Vec<u8> {
    xor_stream(&derive_chapter_key(bck, chapter_index), ciphertext)
}

fn derive_chapter_key(bck: &BookContentKey, chapter_index: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 8);
    buf.extend_from_slice(&bck.0);
    buf.extend_from_slice(&chapter_index.to_le_bytes());
    sha3_256(&buf).0
}

fn xor_stream(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter: u64 = 0;
    let mut block = expand_block(key, counter);
    let mut idx = 0;
    for &b in data {
        if idx == block.len() {
            counter = counter.saturating_add(1);
            block = expand_block(key, counter);
            idx = 0;
        }
        out.push(b ^ block[idx]);
        idx += 1;
    }
    out
}

fn expand_block(key: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 8);
    buf.extend_from_slice(key);
    buf.extend_from_slice(&counter.to_le_bytes());
    sha3_256(&buf).0
}

/// Wrap the BCK for one reader: encapsulate against their ML-KEM
/// public key and XOR the BCK with the resulting shared secret.
///
/// Returns the KEM ciphertext that goes into `book_grants.kem_ct_hex`.
/// The wrapped BCK is bundled with the KEM ct so the reader can
/// recover both at unwrap time.
pub struct GrantBundle {
    pub kem_ct: KemCiphertext,
    pub wrapped_bck: [u8; 32],
}

pub fn wrap_for_reader(reader_pk: &KemPublicKey, bck: &BookContentKey) -> GrantBundle {
    let (shared, kem_ct) = reader_pk.encapsulate();
    let mut wrapped = [0u8; 32];
    let s = shared.as_bytes();
    for i in 0..32 {
        wrapped[i] = bck.0[i] ^ s[i % s.len()];
    }
    GrantBundle { kem_ct, wrapped_bck: wrapped }
}

/// Reverse of `wrap_for_reader`. Reader runs this with their ML-KEM
/// secret key to recover the BCK.
pub fn unwrap_for_reader(
    reader_sk: &KemSecretKey,
    grant: &GrantBundle,
) -> Result<BookContentKey, String> {
    let shared = reader_sk
        .decapsulate(&grant.kem_ct)
        .map_err(|e| format!("decapsulate failed: {e}"))?;
    let s = shared.as_bytes();
    let mut bck = [0u8; 32];
    for i in 0..32 {
        bck[i] = grant.wrapped_bck[i] ^ s[i % s.len()];
    }
    Ok(BookContentKey(bck))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::kem::KemKeypair;

    #[test]
    fn ddl_parses() {
        seal_sql::parse_sql(SCHEMA_DDL).expect("kindle.seal DDL must parse");
    }

    #[test]
    fn policies_lock_publisher_writes() {
        let p = rls_policies();
        assert!(p.iter().any(|(t, _, e)|
            *t == "books" && e.contains("CURRENT_USER")));
    }

    #[test]
    fn chapter_round_trip() {
        let bck = BookContentKey::from_seed(b"book-1-seed");
        let pt = b"It was the best of times, it was the blurst of times.";
        let ct = encrypt_chapter(&bck, 0, pt);
        assert_ne!(ct, pt);
        let recovered = decrypt_chapter(&bck, 0, &ct);
        assert_eq!(recovered, pt);
    }

    #[test]
    fn same_plaintext_in_different_chapters_yields_different_ciphertext() {
        let bck = BookContentKey::from_seed(b"book-2");
        let pt = b"Chapter intro paragraph";
        let c1 = encrypt_chapter(&bck, 1, pt);
        let c5 = encrypt_chapter(&bck, 5, pt);
        assert_ne!(c1, c5, "per-chapter key derivation must diverge");
    }

    #[test]
    fn grant_unwrap_round_trip() {
        let kp = KemKeypair::generate();
        let bck = BookContentKey::from_seed(b"book-3-seed");
        let grant = wrap_for_reader(&kp.public, &bck);
        let recovered = unwrap_for_reader(&kp.secret, &grant).unwrap();
        assert_eq!(recovered.0, bck.0);
    }

    #[test]
    fn unwrap_with_wrong_key_does_not_recover_bck() {
        let publisher_grants_to = KemKeypair::generate();
        let stranger = KemKeypair::generate();
        let bck = BookContentKey::from_seed(b"private");
        let grant = wrap_for_reader(&publisher_grants_to.public, &bck);
        // ML-KEM decapsulate against the wrong secret returns SOME
        // bytes (it's a KEM), but they're not the publisher's shared
        // secret — so the unwrap produces garbage, not the BCK.
        let bad = unwrap_for_reader(&stranger.secret, &grant).unwrap();
        assert_ne!(bad.0, bck.0);
    }

    #[test]
    fn fingerprint_is_eight_hex_bytes() {
        let bck = BookContentKey::from_seed(b"x");
        let fp = bck.fingerprint_hex();
        assert_eq!(fp.len(), 16, "8 bytes hex-encoded = 16 chars");
    }
}
