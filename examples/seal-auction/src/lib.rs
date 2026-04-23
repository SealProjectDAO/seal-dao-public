//! Sealed-bid auction (commit / reveal) on Seal DAO.
//!
//! Two-phase protocol:
//!
//!   1. **Commit phase** — bidders submit
//!      `commitment = SHA3-256(amount_le || nonce_32)` to the
//!      `bids` table. The amount stays hidden.
//!   2. **Reveal phase** — bidders publish `(amount, nonce)`. The
//!      auctioneer (or anyone, since the recomputation is public)
//!      checks `SHA3-256(amount_le || nonce) == commitment`. The
//!      highest valid revealed bid wins; bidders who fail to reveal
//!      forfeit their deposit.
//!
//! The library here owns the commitment + verification primitives.
//! Storage / settlement / deposits live in the on-chain SQL schema
//! and the Token module respectively.

use seal_crypto::hash::sha3_256;

/// Build the commitment a bidder submits during phase 1.
pub fn commit(amount: u128, nonce: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 32);
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(nonce);
    sha3_256(&buf).0
}

/// Verify a phase-2 reveal against a phase-1 commitment.
pub fn verify_reveal(commitment: &[u8; 32], amount: u128, nonce: &[u8; 32]) -> bool {
    commit(amount, nonce) == *commitment
}

pub const SCHEMA_DDL: &str = "
CREATE TABLE auctions (
    id BIGINT PRIMARY KEY,
    seller TEXT NOT NULL,
    item TEXT NOT NULL,
    commit_phase_end_height BIGINT NOT NULL,
    reveal_phase_end_height BIGINT NOT NULL,
    deposit_amount BIGINT NOT NULL
);

CREATE TABLE bids (
    auction_id BIGINT NOT NULL,
    bidder TEXT NOT NULL,
    commitment_hex TEXT NOT NULL,
    deposit_locked BIGINT NOT NULL,
    revealed_amount BIGINT,
    revealed_nonce_hex TEXT
);
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_then_reveal_roundtrips() {
        let amount = 1_234_567_890u128;
        let nonce = [42u8; 32];
        let c = commit(amount, &nonce);
        assert!(verify_reveal(&c, amount, &nonce));
    }

    #[test]
    fn wrong_amount_fails_reveal() {
        let nonce = [9u8; 32];
        let c = commit(100, &nonce);
        assert!(!verify_reveal(&c, 101, &nonce));
    }

    #[test]
    fn wrong_nonce_fails_reveal() {
        let c = commit(100, &[1u8; 32]);
        assert!(!verify_reveal(&c, 100, &[2u8; 32]));
    }

    #[test]
    fn schema_parses() {
        seal_sql::parse_sql(SCHEMA_DDL).expect("auction DDL must parse");
    }
}
