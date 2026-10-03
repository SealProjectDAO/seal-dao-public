# Seal DAO — Problems

Open issues found during development, testing, and security reviews.
Sorted by severity. Updated continuously.

---

## CRITICAL

- [x] ~~**signer_index not persisted in trust store**~~ — DONE: `seal-kms-sidecar/src/trust_store.rs` persists monotonically increasing `bridge_signer_index` via write-to-temp-then-rename
- [x] ~~**`seal-kms-sidecar` crate does not exist**~~ — DONE: full crate with Unix socket server, 8 API endpoints, trust store, secure memory, KMS client

## HIGH

- [x] ~~**`hybrid_kem.rs` does not exist**~~ — DONE: ML-KEM + X25519 hybrid KEM in `seal-crypto/src/hybrid_kem.rs` with 9 tests
- [x] ~~**`kms_client.rs` does not exist**~~ — DONE: `seal-bridge/src/kms_client.rs` with `KmsCommitteeSigner` + `KmsRingtailSigner` implementing traits, wired into `BridgeManager.compute_committee_signature` (KMS Ringtail → KMS HMAC → Legacy Ringtail → Legacy HMAC)
- [x] ~~**Bridge withdrawal has no "burn + unlock in one call"**~~ — DONE: `seal_bridgeWithdrawAndClaim` RPC handler in `seal-node/src/rpc.rs` burns wrapped tokens, creates signed withdrawal, and attempts synchronous unlock submission via `--chain-relay-solana-*` / `--chain-relay-stellar-*` CLI flags; falls back to polling relayer if chain not configured.
- [x] ~~**No KMS API timeout/retry/circuit-breaker**~~ — DONE: `KmsClient` now has `KmsClientConfig` with 10s request timeout, 3 max retries with exponential backoff (100ms base), and circuit breaker (opens after 5 consecutive failures, half-opens after 30s). New error variants: `Timeout`, `RetryExhausted`.
- [x] ~~**No VSS SHA3 commitments for Shamir shares**~~ — DONE: `seal-threshold/src/vss.rs` — `shamir_share_with_commitments` (delegates to existing `shamir_share`), `VssShare`/`VssCommitments`/`VssCommitment` types, `verify_share` + `verify_secret_against_commitments` + `verify_all_shares`, 9 tests
- [x] ~~**KMS trust store not crash-safe**~~ — DONE: write-to-temp-then-rename pattern in `trust_store.rs::save()`

## MEDIUM

- [x] ~~**No worker lifecycle protocol**~~ — DONE: `seal-provisioner` crate with `WorkerProvisioner` trait (pluggable backends) + `DockerProvisioner` implementation. Inventory persisted to disk. Supports Validator/BridgeObserver/KmsSidecar kinds with provision/start/stop/health/decommission lifecycle.
- [x] ~~**Node-to-node & worker networking** — DONE: mTLS/TLS + PQC KEM post-handshake encryption. Hybrid ML-KEM + X25519 KEM handshake (`pq_handshake.rs::HybridInitiator`/`HybridResponder`), hybrid transport (`pq_transport.rs::PqTransportInitiator::new_hybrid()`/`PqTransportResponder::new_hybrid()`), session key = SHA3(hybrid_domain || ss1 || ss2). Pure-ML-KEM transport also available as fallback.~~
- [x] ~~**seal-relayer binary does not exist**~~ — DONE: full crate with polling loop, Solana/Stellar chain submission via CLI shelling, RPC helpers, cursor persistence, Prometheus metrics
- [x] ~~**No `seal_bridgeWithdrawAndClaim` RPC**~~ — DONE: ergonomic single-call burn + unlock (same as HIGH item, implemented in this commit)
- [x] ~~**No SHARP proof support**~~ — DONE: `seal_submitProof` RPC implemented — accepts hex-encoded ZK proof + state transition public inputs (pre_state_root, post_state_root, block_height, tx_count, tx_hash), verifies via runner's `ZkVerifier` backend. Runner holds `Box<dyn ZkVerifier>` (default: `StubVerifier`), switchable via `set_prover`. Exported `StubVerifier` from `seal-zk` crate.
- [x] ~~**Genesis config has hardcoded addresses**~~ — DONE: `seal_getGenesis` RPC returns full chain_id, validators, allocations, consensus params; `ConsensusRunner.apply_genesis` stores config for later query
- [x] ~~**RLS not fully wired to SQL**~~ — DONE: `CREATE POLICY` / `DROP POLICY` SQL DDL added to `Engine` with `RlsManager` field, PostgreSQL-compatible syntax (`FOR SELECT|INSERT|UPDATE|DELETE|ALL TO role USING (expr) [WITH CHECK (expr)]`), nested paren handling for `CURRENT_USER()`, `HAS_TOKEN()` predicates. `HAS_TOKEN` token checker wired via `deploy_namespace` + `balance_mirror`.
- [x] ~~**Governance conviction voting uses SEAL amount, not staked**~~ — DONE: `GovernanceModule::vote_with_conviction` now accepts `voter_balance: Option<u64>` — when `Some(balance)`, rejects votes where `balance < stake`; RPC handler `handle_gov_vote` now reads actual available balance from `BalanceStore` before casting the vote.

## LOW

- [x] ~~**KMS sidecar binary not signed**~~ — DONE: `scripts/kms-sidecar-sign.sh` — reproducible build, SHA3-384 content hash, Ed25519 signing (Python `cryptography` lib, since OpenSSL 3.0 CLI doesn't support Ed25519 signing), self-verify + offline verify
- [x] ~~**Trust store uses plain JSON in memory, encrypted on disk** — DONE: SHA3-384 content hash in every saved file, verified on load; mismatch returns `TrustStoreCorrupted`. Legacy files without hash accepted and upgraded on next save.~~
- [x] ~~**PQ-Noise handshake domain separator differs from pairing protocol**~~ — DONE: false positive — no `b"seal-pair"` exists in codebase. Three actual domains are properly differentiated: `seal-pq-noise-handshake:` (handshake), `seal-pq-session:` (session key derivation), `seal-pq-transport:` (transport session key).
- [x] ~~**Bridge-e2e script skips rotate-back smoke test**~~ — DONE: root cause was default `rpm_admin=5` rate limit tripping on the 6th admin RPC (1× observer + 3× council-add + 2× rotate) within a 60s window. Fixed by `--rpm-admin 60` on all 3 nodes in docker-compose. MANUAL-TESTING §17.3 note is stale — test no longer skips rotate-back; env var is `SKIP_ROTATION_SMOKE=1` (not `RUN_ROTATION_SMOKE`).
- [x] ~~**Laptop KMS model is fragile**~~ — DONE: KMS sidecar now supports TCP listener (`--listen <addr>`) with auth token (`--auth-token <token>`) — operators can connect from remote machines via TCP, no Unix socket required. Generic async stream handler (`handle_connection<S: AsyncRead+AsyncWrite+Unpin+Send>`) works with both UnixStream and TcpStream.

---

*Last audit: 2026-05-27 by AI agent — all previously open items resolved.*
