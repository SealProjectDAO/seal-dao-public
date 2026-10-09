# Stellar-twin multisig + KMS/relayer ed25519 — design note

Date: 2026-10-08 · Status: **research-grade, design-doc + scaffold only; implementation DEFERRED.**
The classical (ed25519) destination-chain custody is real but **unmanaged**: it lives as loose
key files outside the KMS, and the committee withdrawal authority has no modeled Stellar-side
multisig. This note scopes bringing it under the KMS trust model with an e2e path.

## 1. Current state (validated against primary source, 2026-10-08)

- **KMS sidecar is PQC-only.** `crates/seal-kms-sidecar` identity is ML-DSA-65: `NodeInfo`
  (`trust_store.rs:27-44`) is keyed by `node_id = SHA3-384(ML-DSA-65 verifying key)`, holds the
  verifying key + a hybrid ML-KEM public key, and a **monotonic `bridge_signer_index`** feeding
  Shamir share distribution. The trust store is integrity-protected by a SHA3-384 self-hash
  (fatal on mismatch, `trust_store.rs:6-13`). The API carries `node_ml_dsa_sig` (ML-DSA) and ML-KEM
  encapsulation (`api.rs:29,347,426`). **There is no ed25519 key type in the KMS.**

- **The relayer's Seal-side identity is PQC; its destination-chain keys are external ed25519.**
  `apps/seal-relayer` loads a PQC `seal_crypto::signature::SigningKey` (`main.rs:47,141`) to sign the
  Seal-side `seal_bridgeMarkExecuted` RPC (ML-DSA). But the **destination-chain custody is classical
  ed25519 and lives outside the Rust code**:
  - Solana: `--solana-wallet <path>` "funded relayer keypair JSON" (Solana keypairs are ed25519),
    submitted by shelling out to `anchor run unlock-tokens` (`main.rs:560,370`).
  - Stellar: `--stellar-source <id>` "stellar keys identity (funded G-key)" (Stellar G-keys are
    ed25519), submitted by shelling out to `stellar contract invoke ... unlock_xlm / unlock_usdc`
    against a **Soroban contract** in `bridges/stellar` (`main.rs:29-33,363-368,524`).
  - Neither key is in a workspace Rust dependency (there is **no ed25519 crate** in
    `Cargo.toml`); they are external files/CLI identities handed to the `stellar`/`anchor` CLIs.

- **"Stellar-twin" is the documented per-validator destination account.** The relayer's own doc
  comment states the custody model: *"Per-validator (decided 2026-05-16): every Seal validator runs
  its own relayer instance and holds its own funded Solana ed25519 key + Stellar G-key. The
  single-relayer alternative would be a SPOF"* (`main.rs:6-8`). So the "Stellar-twin" is the
  per-validator funded Stellar G-key destination account that mirrors the validator's Seal identity
  and pays for / receives the Stellar-side unlock.

- **Committee authority on the Seal side is a threshold sig.** A bridge withdrawal carries
  `committee_signature_hex` (Ringtail threshold over the committee, `main.rs:125,267-276`) and the
  relayer submits the destination unlock once it is set. The Stellar/Solana **on-chain** unlock is
  gated by whatever authority that chain's vault contract expects — currently not modeled as a
  Stellar multisig in this repo.

## 2. The gap

1. **Unmanaged classical custody.** The ed25519 destination keys are loose per-validator files not
   under the KMS trust store: no integrity hash, no Shamir/multisig split, no revocation record, no
   pairing handshake. Compromising one relayer host exposes its funded destination keys in the clear.
2. **No Stellar-side multisig model.** The committee's withdrawal authority is expressed as a Seal
   threshold sig, but its mapping to the Stellar vault's on-chain authority (a Stellar account
   multisig / Soroban authorization) is not designed. The "multisig migration" is this mapping.
3. **No e2e covering the ed25519 rail.** The relayer tests cover the deterministic back-off and the
   cursor (`main.rs:579-635`); nothing exercises KMS custody → relayer → destination ed25519 claim.

## 3. Design (scaffold only — to be implemented later)

All three pieces keep ed25519 **quarantined to the bridge/destination boundary** (classical crypto
never on the L1/consensus path — the CLAUDE.md "classical crypto only in bridge modules" rule):

1. **KMS ed25519 key domain (classical, PQC-exempt).** Add an ed25519 key type to the KMS
   (`seal-kms-sidecar`) as a **separate, explicitly-classical domain** — distinct from the ML-DSA
   node-identity and ML-KEM pairing domains, and refused for anything on the consensus path. It
   holds destination-chain identities (Solana keypair, Stellar G-key) under the same trust-store
   integrity (SHA3-384 self-hash) and Shamir/multisig split (`bridge_signer_index`-style monotonic
   indices) so no single host compromise reveals a full key, with per-key revocation.
2. **Stellar-twin multisig mapping.** Model the committee → Stellar authority mapping: the Seal
   committee threshold (t-of-n Ringtail) is the *off-chain* authorization; the Stellar side
   expresses it as either (a) a **Stellar account multisig** (t member G-keys at weight ≥ threshold)
   acting as the Soroban vault's authorized withdrawer, or (b) a Soroban authorization that accepts
   the Seal threshold sig verified off-chain by the relayer. Define the weight/threshold mapping,
   the member-key roster lifecycle (enroll/rotate/revoke mirrors committee membership), and which of
   (a)/(b) is chosen (recommend (b) — keep the committee threshold sig as the single source of
   authority, use the Stellar multisig only as an on-chain *recovery/guardian* rail, not a second
   authority that can double-sign).
3. **Relayer pulls ed25519 from the KMS + e2e.** Replace the external `--solana-wallet` /
   `--stellar-source` file/CLI identities with KMS-issued destination keys (or KMS-backed
   signers), keeping the shell-out to `stellar`/`anchor` for the on-chain call. Add an **e2e** that
   exercises: KMS mints a quarantined ed25519 destination key → relayer fetches it → signs a
   (dry-run) Stellar/Solana unlock → claim is well-formed, without touching a live destination chain.

## 4. Security notes

- ed25519 is **classical and post-quantum-insecure**. It is acceptable only at the destination-chain
  boundary (Stellar/Solana are classical chains); it must never back a Seal L1/consensus identity or
  the committee threshold. The KMS domain separation in §3.1 is the enforcement point.
- The per-validator model (each validator its own relayer + its own funded destination keys) is
  deliberate (SPOF avoidance, `main.rs:6-8`); the KMS Shamir split must preserve that — a key is
  reconstructable only from the committee, not from any one relayer host.
- Destination-chain replay is already guarded on-chain (Solana `AlreadyClaimed`; idempotent
  `bridge_mark_executed`, `main.rs:239-251,339-344`); the ed25519 custody work must not weaken that.

## 5. Status

Research-grade; **design-doc + scaffold only, implementation deferred**. The corrected framing (KMS is
PQC-only; the relayer's ed25519 destination keys are external loose files; the Stellar-twin is the
documented per-validator funded Stellar G-key; committee authority has no modeled Stellar-side
multisig) is the deliverable. Revisit with a regression-first implementation of §3 (KMS ed25519
domain → Stellar-twin multisig mapping → relayer KMS-backed e2e), keeping ed25519 quarantined to the
bridge boundary.
