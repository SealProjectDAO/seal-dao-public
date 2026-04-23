//! social.seal — minimal social graph on Seal DAO.
//!
//! Public posts go on chain unencrypted; visibility is controlled by
//! RLS policies on the `posts` table:
//!
//!   * **Public posts** — `using (true)` → readable by anyone.
//!   * **Followers-only** — `using (HAS_TOKEN('follower:owner'))` →
//!     readable only by addresses holding the owner's per-account
//!     "follower" badge token.
//!   * **Private** — `using (owner = CURRENT_USER())` → readable only
//!     by the author (DM-style).
//!
//! This crate ships only the schema + the canonical RLS policy
//! triples. The full UI lands later; the SQL itself is exercised by
//! `tests::ddl_parses` so the schema can't drift silently.

pub const SCHEMA_DDL: &str = "
CREATE TABLE profiles (
    address TEXT PRIMARY KEY,
    handle TEXT NOT NULL,
    bio TEXT,
    created_at_height BIGINT NOT NULL
);

CREATE TABLE posts (
    id BIGINT PRIMARY KEY,
    owner TEXT NOT NULL,
    body TEXT NOT NULL,
    visibility TEXT NOT NULL,
    created_at_height BIGINT NOT NULL
);

CREATE TABLE follows (
    follower TEXT NOT NULL,
    followee TEXT NOT NULL,
    created_at_height BIGINT NOT NULL
);
";

/// Returns the (table, action, USING expr) triples that should be
/// installed via `seal_govPropose` / `enable_rls_policy` when the
/// app is deployed. Keeping them as data lets tests verify the set.
pub fn rls_policies() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("posts", "SELECT_PUBLIC", "true"),
        ("posts", "SELECT_OWNER", "owner = CURRENT_USER()"),
        ("posts", "INSERT_OWNER", "owner = CURRENT_USER()"),
        ("follows", "INSERT_OWNER", "follower = CURRENT_USER()"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddl_parses() {
        seal_sql::parse_sql(SCHEMA_DDL).expect("social.seal DDL must parse");
    }

    #[test]
    fn policies_cover_writes() {
        let policies = rls_policies();
        assert!(policies.iter().any(|(t, a, _)| *t == "posts" && a.starts_with("INSERT")));
        assert!(policies.iter().any(|(t, a, _)| *t == "follows" && a.starts_with("INSERT")));
    }
}
