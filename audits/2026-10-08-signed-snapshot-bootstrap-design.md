# Signed snapshot manifests + honest-majority bootstrap — design note

Date: 2026-10-08 · Status: **research-grade, design-doc + scaffold only; implementation DEFERRED.**
A node today trusts its on-disk snapshot fully (unsigned) and a fresh node has no trusted anchor to
distinguish an honest chain from a long forged fork. This note designs the signed anchor + the
honest-majority bootstrap that closes both.

## 1. Current state (validated against primary source, 2026-10-08)

- **Snapshots are unsigned, no manifest.** `Snapshot { height, timestamp, state_root: [u8;32],
  block_data: Vec<Block> }` (`crates/seal-storage/src/storage.rs:149-155`) — a full re-serialization
  of the last N blocks plus a state root. `save_snapshot` (`storage.rs:408-434`) /
  `load_latest_snapshot` (`storage.rs:452-471`) write/read via sled with **no signature, no
  manifest, no checkpoint metadata, no verification** on load. Loaded at boot (`main.rs:70-78`).
  A tampered/corrupted snapshot on disk is accepted as-is.
- **Genesis is a trusted local config, not a network anchor.** `apply_genesis`
  (`consensus_runner.rs:467-520`) mints initial SEAL balances from `genesis_config.balances`, sets
  `genesis_config = Some` (idempotent guard, `:503`), and starts the chain. `genesis_config`
  (`Option<GenesisConfig>`, `:176`) is a **config file**, not a signed/pinned artifact the network
  attests.
- **Bootstrap is pull-based with no fresh-node genesis path.** `NetworkNode::start`
  (`network_node.rs:529-660`) does P2P peer discovery + handshake (identity = a PQC
  `seal-crypto::keypair::Keypair`, peer ID from its public key) and spawns a block-sync task that
  calls `sync_blocks` (`:839-851`): **on-demand** — request blocks `[target_height+1, local_height]`
  from a random peer, verify + apply each. A fresh node with an empty chain has **no genesis to
  request and no trusted anchor** for block 0 / the genesis state root; it trusts the first peer's
  chain implicitly (it verifies each block's signature + state-root transition, but block 0 is
  self-attested with no external trust root).
- **Enrollment is trusted-by-default.** `enroll_validator` (`main.rs:161-197`) takes a 64-byte
  pubkey blob, marks it active, and stakes it (default 100_000). **No proof-of-key-ownership** (no
  sign-a-challenge), no committee approval recorded — whoever calls the RPC enrolls any pubkey.
- **State root shape** (for reference): `state_root = sha256(sql_root ‖ balance_root)`
  (`consensus_runner.rs:1060-1065`), plus the signed `tx_root` now in the block header
  (`crates/seal-storage/src/block_store.rs:41`).

## 2. Design

1. **Signed snapshot manifest.** Extend `Snapshot` (or prepend a manifest) with a signed
   `{ height, state_root, tx_root, block_hash, producer_signature, produced_at }`.
   `producer_signature` = ML-DSA over canonical manifest bytes (PQC, not ed25519).
   `load_latest_snapshot` verifies the signature before applying; a tampered snapshot is **rejected**
   (fall back to full re-sync). Optionally a **committee threshold signature** over the manifest for
   high-trust checkpoints (reuses the — currently dormant — committee machinery; see the committee
   design note).
2. **Signed genesis anchor.** Publish the genesis (block 0 hash, genesis state root, initial
   validator set) as a signed artifact — a committee-threshold-signed genesis manifest, or a fixed
   genesis hash published in a trusted channel (docs / bootstrap config). This is the **trust root**
   a fresh node pins before it trusts anything.
3. **Honest-majority bootstrap protocol.** A fresh node: (a) bootstraps its validator set from the
   signed genesis anchor; (b) fetches the chain tip + a recent **signed snapshot** from multiple
   peers; (c) requires an **honest majority** of the validator set to co-sign/attest the anchor
   (snapshot manifest + tip hash + state root); (d) only then trusts the chain and continues
   pull-based `sync_blocks`. This defeats Sybil / long-fork: a forged chain must get >honest-majority
   of *real* validators to co-sign its anchor.
4. **Proof-of-key-ownership for enrollment.** `enroll_validator` requires the enrolling key to sign
   a challenge (proving control of the private key) and/or a recorded committee-threshold approval —
   so enrollment is no longer trusted-by-default.

## 3. Failure modes / notes

- The honest-majority attestation and the committee threshold-signature wiring (item 10) are the
  **same mechanism** — both need the full-protocol threshold sig to be real before either is live.
  Land the signed snapshot + signed genesis anchor first (single-producer-signed, self-contained);
  the committee-threshold co-signing of anchors/genesis is the higher-trust layer that depends on
  item 10.
- Snapshot signature must be over the *canonical* manifest bytes (the same bincode/canonical-bytes
  discipline as the block header signature) so producer and verifier agree.
- A fresh node that cannot reach an honest-majority quorum must **refuse to join** (fail-closed), not
  trust a single peer — this is the core fix for the current implicit-first-peer trust.

## 4. Status

Research-grade; **design-doc + scaffold only, implementation deferred**. Deliverable is the corrected
framing (snapshots are unsigned and trusted fully on load; genesis is a trusted local config with no
network anchor; bootstrap is pull-based with no fresh-node genesis path; enrollment is
trusted-by-default with no proof-of-key-ownership). Revisit with a regression-first implementation of
§2: signed snapshot + signed genesis anchor first (self-contained), then the honest-majority
co-signing layer once the committee threshold path (item 10) is real.
