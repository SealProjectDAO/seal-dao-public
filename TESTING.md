# Seal DAO — Testing Manual

> **Bridge / testnet operator testing.** For end-to-end live-chain
> testing of the bridge (deploy, flip-to-Ringtail, fund relayers,
> multi-validator smoke), see
> [`docs/RUNBOOK-TESTNET-OPERATOR.md`](docs/RUNBOOK-TESTNET-OPERATOR.md).
> For 3 / 5 / 7-validator sizing + variable bridge-committee
> thresholds, see [`docs/TESTNET-VALIDATOR-SIZES.md`](docs/TESTNET-VALIDATOR-SIZES.md).
> This file is the unit/integration test reference for the Rust
> workspace.

## Quick Start

```bash
# Run all tests (~379 tests, takes ~3 minutes)
cargo test

# Run tests for a specific crate
cargo test -p seal-crypto
cargo test -p seal-sql
cargo test -p seal-node

# Run with output (see println! in tests)
cargo test -- --nocapture

# Run a specific test
cargo test -p seal-node -- test_replay_chain

# Run benchmarks (prints timing info)
cargo test -p seal-node --lib -- bench --nocapture

# Full CI (tests + clippy + fmt + audit)
./scripts/ci.sh

# Quick CI (tests only)
./scripts/ci.sh quick
```

---

## Test Inventory

### seal-crypto (21 tests)
PQC cryptographic primitives using libcrux (formally verified).

| Test | What it verifies |
|------|-----------------|
| `test_sign_verify` | ML-DSA-65 sign then verify succeeds |
| `test_verify_wrong_message` | Verify fails with tampered message |
| `test_verify_wrong_key` | Verify fails with wrong public key |
| `test_key_serialization_roundtrip` | SK/VK bytes → deserialize → still works |
| `test_signature_sizes` | Sig=3309 bytes, VK=1952 bytes (ML-DSA-65) |
| `test_seed_deterministic_keygen` | Same seed → same keys. Different seed → different keys |
| `test_seed_deterministic_sign_verify` | Sign with wallet1, verify with wallet2 from same seed |
| `test_sign_verify_arbitrary_messages` | 7 message sizes: empty, 1B, 100B, 256B, 10KB |
| `test_sha3_256_empty` | SHA3("") matches known hash |
| `test_sha3_256_deterministic` | Same input → same hash |
| `test_sha3_256_different_inputs` | Different input → different hash |
| `test_incremental_hasher` | Sha3Hasher matches direct sha3_256 |
| `test_kem_encapsulate_decapsulate` | ML-KEM-768: encap then decap → same shared secret |
| `test_kem_shared_secret_size` | Shared secret is 32 bytes |
| `test_kem_key_sizes` | PK=1184 bytes, SK=2400 bytes |
| `test_address_from_key` | Address starts with "seal1" or "sealt1" |
| `test_address_testnet` | Testnet address starts with "sealt1" |
| `test_address_deterministic` | Same key → same address |
| `test_address_different_keys` | Different keys → different addresses |
| `test_address_roundtrip` | Encode → decode → same address |
| `test_address_invalid_prefix` | Rejects addresses without seal1/sealt1 prefix |

### seal-vrf (13 tests)
VRF for consensus leader election. PqVrf (ML-DSA, default), LavVrf
(lattice many-time), HmacVrf (test) — `VrfBackend` switchable. PqVrf
is wired into `seal-consensus` election; LaV VRF Lean 4 uniqueness
spec lives at `formal/lean/SealVerify/Basic/VRF.lean`.

| Test | What it verifies |
|------|-----------------|
| `test_keygen` | Key generation produces valid 32-byte keys |
| `test_eval_deterministic` | Same (key, input) → same output |
| `test_eval_different_inputs` | Different inputs → different outputs |
| `test_eval_different_keys` | Different keys → different outputs |
| `test_verify_valid` | Valid proof passes verification |
| `test_verify_wrong_public_key` | Wrong key → verify fails |
| `test_verify_invalid_proof_length` | Malformed proof → verify fails |
| `test_invalid_secret_key_length` | Wrong SK length → eval fails |
| `test_threshold_election` | 1000-slot simulation: ~10% election rate ±variance |
| `test_compute_threshold` | Stake-proportional threshold calculation |
| `test_compute_threshold_zero_stake` | Zero stake → zero threshold |
| `test_compute_threshold_zero_total` | Zero total → zero threshold |
| `test_vrf_output_to_u64` | Output bytes → u64 conversion correct |

### seal-merkle (35 tests)
Content-addressed Merkle B-tree for state storage.

| Test | What it verifies |
|------|-----------------|
| `test_leaf_node` | New leaf is empty and not full |
| `test_content_hash_deterministic` | Same node → same hash |
| `test_content_hash_changes_with_data` | Different data → different hash |
| `test_internal_node` | Internal node has entries + children |
| `test_find_key_pos` | Binary search finds correct position |
| `test_empty_tree` | Empty tree: root=None, get=None |
| `test_insert_and_get` | Insert then get returns the value |
| `test_insert_multiple` | 20 items all retrievable |
| `test_insert_sorted_order` | Keys returned in sorted order |
| `test_update_existing_key` | Insert same key updates value |
| `test_root_hash_changes` | Root hash changes after each insert |
| `test_deterministic_root` | Same operations → same root hash |
| `test_delete_leaf` | Delete removes key, others remain |
| `test_delete_nonexistent` | Delete of missing key returns false |
| `test_many_inserts_and_deletes` | 50 inserts, delete evens, verify odds |
| `test_insert_get_roundtrip_100` | 100 pseudo-random inserts, all found |
| `test_root_hash_after_delete` | Insert a,b,c → delete b = insert a,c (data match) |
| `test_delete_until_empty_no_corrupt_children` | Sequential delete: no Empty children in internal nodes |
| `test_delete_reverse_order_no_corrupt_children` | Reverse delete: structural integrity preserved |
| `test_interleaved_insert_delete_integrity` | 5 rounds of insert/delete, all remaining keys reachable |
| `test_insert_after_delete_to_empty` | Delete all → re-insert: tree works from empty state |
| `test_fuzz_crash_replay` | Exact replay of fuzz crash artifact (52 ops) |
| `test_memory_store_put_get` | Store: put then get returns node |
| `test_memory_store_deduplication` | Same node stored once (content-addressed) |
| `test_inclusion_proof` | Merkle proof verifies against root hash |
| `test_exclusion_proof` | Missing key proof has value=None |
| `test_proof_fails_wrong_root` | Proof fails against wrong root hash |

### seal-sql (61 tests)
PostgreSQL-compatible SQL engine with RLS and namespaces.

**Parser tests (13):** CREATE TABLE, INSERT, SELECT (with JOIN, GROUP BY),
UPDATE, DELETE, CREATE INDEX, ALTER TABLE, multiple statements, invalid SQL,
type mapping (SMALLINT through JSONB).

**Engine tests (19):** Create table, duplicate table rejected, insert+select,
WHERE filtering (=, >, <, AND, OR), column projection, UPDATE, DELETE, DROP,
NOT NULL violation, table not found, 100-row insert, boolean values, state root
changes on insert/update/delete, state root deterministic, row count.

**RLS tests (9):** Disabled allows all, enabled+no policy denies, public read
policy, owner-only write policy, ALL action policy, duplicate policy rejected,
drop policy, disable RLS, multiple policies OR semantics.

**Namespace tests (11):** Deploy app, duplicate rejected, execute SQL in
namespace, visibility (private default, public, shared), RLS in namespace,
list apps, RLS blocks SELECT/INSERT without policy, allows with policy.

**MerkleEngine tests (6):** Basic ops, state root changes, deterministic,
proof generation, proof verification, multi-table proofs.

### seal-consensus (23 tests)
VRF-based consensus: epochs, slots, validators, election.

| Test | What it verifies |
|------|-----------------|
| Config: default values, epoch duration, slot decomposition roundtrip |
| Epoch: genesis seed, next epoch deterministic, different VRF → different seed |
| Slot: genesis, next, epoch boundary, VRF input unique per slot/epoch |
| Validator: set creation, sorted by pubkey, find by pubkey, threshold proportional to stake, inactive excluded |
| Election: deterministic, different slots vary, inactive not elected, verify valid election, higher stake elected more |

### seal-threshold (66 tests)
Committee threshold signatures. Real Ringtail full-protocol path
(`round1_full` / `aggregate_commitments` / `aggregate_responses_full` /
`generate_public_params_no_error` / `sign_single_full` / `verify_signature_full`)
with NTT-accelerated arithmetic, constant-time centered reduction
(`subtle`), `RingtailParty::drop` zeroize, 5 KAT vectors, `fuzz_ringtail_sign`
+ `fuzz_ringtail_verify`. BPF cross-check
(`crates/seal-ringtail-verify/tests/crosscheck.rs`) accepts byte-exact
1-of-1 + 2-of-2 signatures. The subset below is the legacy simplified
suite (still in use for the one-shot `RingtailThreshold` trait).

| Test | What it verifies |
|------|-----------------|
| `test_partial_sign_and_aggregate` | 3-of-5: sign, aggregate, verify |
| `test_verify_threshold_signature` | 4-of-5: full verify workflow |
| `test_insufficient_signers` | 2-of-5 with threshold=3 → error |
| `test_duplicate_signer_rejected` | Same signer twice → error |
| `test_wrong_message_rejected` | Sign "correct", aggregate against "wrong" → error |
| `test_67_of_100_committee` | 67-of-100: full workflow, bitfield correct |
| `test_bitfield_basic` | Set/check bits, count |
| `test_bitfield_all_set` | 8 bits all set = 0xFF |
| `test_bitfield_size` | 100 members = 13 bytes |
| `test_bitfield_out_of_range` | Out of range returns false |

### seal-storage (9 tests)
Persistent state + block storage (sled).

| Test | What it verifies |
|------|-----------------|
| `test_put_and_get` | DiskNodeStore: store and retrieve a node |
| `test_persistence` | Data survives reopen |
| `test_merkle_tree_with_disk_store` | MerkleTree works with sled backend |
| `test_deduplication` | Same node stored once |
| `test_put_and_get_block` | BlockStore: store and retrieve a block |
| `test_latest_block` | Returns highest-height block |
| `test_height` | Chain height tracking |
| `test_get_nonexistent_block` | Missing block returns None |
| `test_block_with_transactions` | Block with 2 transactions roundtrips |

### seal-token (16 tests)
Token economics: balances, transfers, staking.

| Test | What it verifies |
|------|-----------------|
| Balance: credit/debit, insufficient balance error, overflow error, stake/unstake |
| BalanceStore: mint, burn, burn nonexistent error, supply conservation |
| Transfer: simple, insufficient, zero amount, from nonexistent, preserves supply |
| Staking: stake+unstake, insufficient balance, total staked, preserves supply |

### seal-wallet (14 tests)
Multi-chain wallet with seed-deterministic keygen.

| Test | What it verifies |
|------|-----------------|
| `test_wallet_generation` | Fresh wallet has valid address |
| `test_wallet_mainnet` | Mainnet address starts with "seal1" |
| `test_wallet_sign_verify` | Sign with wallet key, verify succeeds |
| `test_wallet_mnemonic_export` | Mnemonic is 64 hex chars |
| `test_wallet_info_serialization` | WalletInfo JSON roundtrip |
| `test_two_wallets_different` | Random wallets have different addresses |
| `test_ed25519_seed_available` | Ed25519 seed is 32 bytes |
| `test_deterministic_wallet_recovery` | Same seed → same address, same keys, cross-verify signatures |
| `test_different_seed_different_wallet` | Different seeds → different addresses |
| Mnemonic: generation, hex roundtrip, deterministic derivation, different paths, invalid hex |

### seal-bridge (15 tests)
Cross-chain bridge: Solana/Stellar lock-and-mint + chain observers.

| Test | What it verifies |
|------|-----------------|
| `test_deposit_confirm_process` | Deposit → 3 confirmations → mint wrapped tokens |
| `test_process_before_confirmed_fails` | Unconfirmed deposit → error |
| `test_duplicate_deposit_rejected` | Same deposit ID → error |
| `test_withdrawal` | Withdraw → balance decreased, invariant holds |
| `test_withdrawal_insufficient_balance` | Withdraw > balance → error |
| `test_invariant_holds_through_operations` | 5 deposits + 2 withdrawals: minted≤locked always |
| `test_stellar_bridge` | Stellar (XLM) deposit works |
| `test_solana_observer_creates` | SolanaObserver devnet config |
| `test_stellar_observer_creates` | StellarObserver testnet config |
| `test_solana_parse_lock_event` | Parse Solana tx → BridgeDeposit |
| `test_stellar_parse_lock_event` | Parse Stellar XLM tx → BridgeDeposit |
| `test_stellar_parse_usdc_event` | Parse Stellar USDC tx → correct token |
| `test_bridge_observer_set` | Multi-chain observer polling |
| `test_solana_is_finalized` | Solana finality check (stub) |
| `test_stellar_is_finalized` | Stellar finality check (stub) |

### seal-tee (6 tests)
TEE attestation + AI inference.

| Test | What it verifies |
|------|-----------------|
| `test_register_and_query` | Register TEE node, query by ID |
| `test_nodes_for_model` | Filter nodes by supported model |
| `test_multi_vendor` | Intel TDX + AMD SEV + NVIDIA CC all registered |
| `test_attestation_freshness` | Fresh attestation passes, old one fails |
| `test_compute_cost` | input_tokens + 4×output_tokens pricing |
| `test_compute_cost_overflow_safe` | Saturating arithmetic on u64::MAX |

### seal-node (43 tests)
Integrated node: state, consensus, persistent, network, fees, governance, bench.

**State (8):** Node creation, create+insert, produce block, multiple blocks,
VRF evaluation, transaction signing, read/write separation, full workflow.

**Consensus runner (11):** Advance slots produces blocks, ZK proof on blocks,
threshold sig on blocks, state root changes, parent hash chain, epoch transition,
pending tx clearing, multi-validator, SQL in consensus, Merkle state root in
blocks, replay tests (single, chain, empty).

**Persistent (3):** Basic persistence, survives restart, empty start.

**Network node (6):** Starts, produces blocks, SQL operations, block
serialization roundtrip, verify+apply block, reject wrong height.

**Fees (5):** Fee calculation, burn/reward split, block fee processing,
insufficient balance, supply conservation.

**Governance (7):** Create+vote, tally passes, tally rejects, early tally,
execute after timelock, double vote, supermajority requirement.

**Benchmarks (6):** ML-DSA keygen/sign/verify, SHA3, block production, SQL.

### seal-p2p (13 tests)
P2P networking with PQ double-encryption.

| Test | What it verifies |
|------|-----------------|
| `test_node_starts` | Node starts with default config |
| `test_topics` | GossipSub topics match expected strings |
| `test_two_nodes_start` | Two nodes get different peer IDs |
| `test_node_broadcast_doesnt_panic` | Broadcasting without peers is safe |
| `test_pq_node_starts` | Node starts with PQ encryption enabled |
| `test_broadcast_encrypt_decrypt_roundtrip` | PQ broadcast: encrypt → decrypt == original |
| `test_no_pq_passthrough` | Without PQ, messages pass through unchanged |
| `test_pq_key_exchange_state` | PQ state initializes with ML-KEM keypair |
| `test_pq_channel_roundtrip` | ML-KEM channel: initiator→responder roundtrip |
| `test_pq_channel_bidirectional` | Both directions work on same channel |
| `test_pq_channel_large_message` | 10 KB message encrypts/decrypts correctly |
| `test_encrypt_decrypt_with_key` | Pre-shared key XOR encryption roundtrip |
| `test_wrong_key_fails` | Wrong key produces garbage (not the plaintext) |

### seal-zk (17 tests)
Zero-knowledge proof generation with batch support.

| Test | What it verifies |
|------|-----------------|
| `test_prove_and_verify` | Stub: SHA3 commitment proves and verifies |
| `test_proof_deterministic` | Same transition → same proof |
| `test_tampered_proof_fails` | Tampered proof bytes → verify fails |
| `test_wrong_public_inputs_fail` | Altered public inputs → verify fails |
| `test_different_transitions_different_proofs` | Different heights → different proofs |
| `test_invalid_proof_format` | Wrong-length proof → InvalidProofFormat |
| `test_risc0_prover_fallback` | RISC Zero prover falls back to stub |
| `test_sp1_prover_fallback` | SP1 prover falls back to stub |
| `test_batch_transition_valid` | 5-block chain: consistent roots + heights |
| `test_batch_transition_empty_fails` | Empty batch → error |
| `test_batch_transition_inconsistent_roots_fails` | Broken state root chain → error |
| `test_batch_transition_non_sequential_heights_fails` | Skipped heights → error |
| `test_batch_transition_single_block` | Single-block batch is valid |
| `test_batch_prover` | Batch of 3 blocks → single 32-byte proof |
| `test_batch_prover_deterministic` | Same batch → same proof |
| `test_batch_verifier` | Batch proof verifies |
| `test_batch_verifier_invalid_format` | Wrong-size batch proof → error |

---

## Running Specific Test Categories

```bash
# All crypto tests
cargo test -p seal-crypto

# Only signature tests
cargo test -p seal-crypto -- signature

# Only Merkle proof tests
cargo test -p seal-merkle -- proof

# Only RLS tests
cargo test -p seal-sql -- rls

# Only governance tests
cargo test -p seal-node -- governance

# Only network tests
cargo test -p seal-node -- network

# Only fee tests
cargo test -p seal-node -- fees

# Only benchmarks (with output)
cargo test -p seal-node --lib -- bench --nocapture
```

---

## Verification Tools

### Kani (Bounded Model Checking)
```bash
# Install
cargo install --locked kani-verifier && cargo kani setup

# Run on specific crates
cargo kani -p seal-crypto    # SHA3, Hash256, Sha3Hasher
cargo kani -p seal-merkle    # Insert-get roundtrip, root changes, delete
cargo kani -p seal-token     # Credit-debit roundtrip, stake, no underflow
cargo kani -p seal-bridge    # minted ≤ locked invariant
cargo kani -p seal-consensus # Slot roundtrip, threshold no overflow
```

Kani harnesses are in the Rust source under `#[cfg(kani)]` blocks.
See `formal/kani/README.md` for details.

### Fuzzing
```bash
# Install (requires nightly as default toolchain)
rustup default nightly
cargo install cargo-fuzz

# Run a fuzz target
cd fuzz
cargo fuzz run fuzz_sql_parser -- -max_total_time=60
cargo fuzz run fuzz_address_parse -- -max_total_time=60
cargo fuzz run fuzz_vrf_verify -- -max_total_time=60
cargo fuzz run fuzz_block_deserialize -- -max_total_time=60

# Switch back to stable
rustup default stable
```

### Formal Proofs
```bash
# TLA+ (install Apalache: https://apalache-mc.org/)
apalache-mc check --cinit=ConstInit --inv=Agreement formal/tlaplus/SealConsensus.tla

# Lean 4 (install elan: https://leanprover.github.io/lean4/)
# Run each command from the repo root — the subshell keeps cd local.
(cd formal/lean && lake build)

# Rocq/Coq (install: brew install coq OR opam install coq)
(cd formal/rocq && coq_makefile -f _CoqProject -o Makefile && make)
```

---

## What Each Test Level Catches

| Level | Catches | Speed | Coverage |
|-------|---------|-------|----------|
| `cargo test` | Logic bugs, regressions | 5 sec | Specific inputs |
| Kani | Panics, overflow for ALL inputs (bounded) | Minutes | Exhaustive (bounded) |
| Fuzzing | Crashes on random inputs | Hours | Millions of inputs |
| TLA+ | Protocol design bugs (forks, deadlocks) | Minutes | All executions (bounded) |
| Lean 4 | Mathematical incorrectness | N/A (proofs) | Universal |
| Rocq | State machine bugs | N/A (proofs) | Universal |

---

## Formal Verification Results (as of v0.1)

### TLA+ Model Checking (Apalache 0.55)

| Spec | Invariant | Length | Result |
|------|-----------|--------|--------|
| SealConsensus | Agreement | 5 | **VERIFIED** ✓ |
| SealConsensus | NoEquivocation | 5 | **VERIFIED** ✓ |
| SealConsensus | MonotonicHeight | 5 | **VERIFIED** ✓ |
| SealCompositeProof | Soundness | 3 | **VERIFIED** ✓ |
| SealCompositeProof | Completeness | 3 | **VERIFIED** ✓ |
| SealCompositeProof | LayerIndependence | 3 | **VERIFIED** ✓ |

### Kani Bounded Model Checking

| Crate | Harness | Checks | Result |
|-------|---------|--------|--------|
| seal-token | credit_debit_roundtrip | 173 | **VERIFIED** ✓ |
| seal-token | stake_unstake_preserves_total | — | **VERIFIED** ✓ |
| seal-token | debit_no_underflow | — | **VERIFIED** ✓ |
| seal-consensus | slot_roundtrip | — | **VERIFIED** ✓ |
| seal-consensus | inactive_threshold_zero | — | **VERIFIED** ✓ |
| seal-merkle | insert_get_roundtrip | — | FAIL (SHA3 in Kani) |
| seal-crypto | sha3_256_deterministic | — | Too slow (ML-DSA) |

### Rocq/Coq Proofs

| File | Theorems | Proven | Admitted |
|------|----------|--------|---------|
| Balance.v | 7 | **7** | 0 |
| StateMachine.v | 6 | **5** | 1 |

### Lean 4 Proofs

| File | Theorems | Proven | Sorry |
|------|----------|--------|-------|
| Hash.lean | 4 | **4** | 0 |
| MerkleTree.lean | 4 | **1** | 3 |
| VRF.lean | 3 (axioms) | — | — |
