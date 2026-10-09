# Committee threshold-signature wiring — design note (item 10)

Date: 2026-10-08 · Status: **design-first, implementation DEFERRED.** The plan scoped item 10 as
a bounded "swap `verify` → `verify_signature_full`"; primary source shows it is a **protocol
migration** (wire `PublicParams` + the signed block hash through sender → P2P → verifier). It is
safe to do *only* because the path is dormant in production (see §3).

## 1. What exists, and why it is not a swap

Three layers, all validated against primary source (2026-10-08):

1. **The verification that *would* be used is weak.** The trait impl
   `ThresholdScheme::verify` (`crates/seal-threshold/src/ringtail.rs:835`) ignores its
   `_public_keys: &[Vec<u8>]` parameter and calls `verify_signature(&ring, &sig, &[], message,
   threshold)` with an **empty key set**. `verify_signature` (`ringtail.rs:378-411`) checks only:
   (a) participant count ≥ threshold, (b) `‖z‖ < AGGREGATE_NORM_BOUND`, (c) the challenge is not
   all-zero. It takes `_public_key` and `_message` (both underscore-prefixed — **ignored**). It does
   not recompute the challenge from the message and does not check any public key. **A "valid"
   signature is any ≥threshold-participant, bounded-z, non-zero-challenge blob — the message and the
   key are irrelevant, so any message is forgeable.**

2. **The real check exists but needs `PublicParams`.** `verify_signature_full` (`ringtail.rs:420`)
   does the full algebra: recompute `D' = A·z − c·t` and check `c == H(D' ‖ message)`, taking
   `public_params: &PublicParams`. The **one-shot** `ThresholdScheme` path does not carry
   `PublicParams` (its `verify` signature is `&[Vec<u8>]` per-signer, not `&PublicParams`), so the
   one-shot path cannot use the real check. Its `partial_sign`/`aggregate`
   (`ringtail.rs:719`/`771`) are a self-consistent **simulation** — each party responds to its own
   commitment with per-signer keys — consistent only with the weak `verify`, never with
   `verify_signature_full`.

3. **The accept path never verifies at all.** `accept_committee_signature`
   (`crates/seal-node/src/consensus_runner.rs:699-709`) deserializes a **bare**
   `seal_threshold::traits::ThresholdSignature` (no block hash, no threshold, no params), logs it,
   and returns `Ok(())`. The in-code comment — *"In production: verify threshold sig, mark block as
   finalized"* — admits it does not. It is called from the P2P committee-sig topic handler
   (`network_node.rs:301`).

## 2. The real fix — wire the full-protocol path end-to-end

The non-forgeable path is the **full protocol**: `CommitteeManagerFull` (round1_full/round2_full) +
`PublicParams` + `verify_signature_full`. Making it enforceable requires threading three things that
the wire currently omits, **sender → P2P wire → verifier**:

1. **`PublicParams` for the epoch** — the matrix `A` + key `t` that `verify_signature_full` needs.
   Either derived deterministically from the epoch (identical on every node) or transmitted and bound
   by an accountable signature.
2. **The exact block hash the committee signed** — `accept_committee_signature` must verify the
   signature over the *locally-known* block hash, not an attacker-chosen one. Today the wire carries
   only the bare `ThresholdSignature`, so the verifier has no message to check against.
3. **The threshold** — the verifier must know `t` to check the participant count against the
   correct threshold (currently not in the message).

The verifier then calls `verify_signature_full(&ring, &sig, &params, &block_hash, threshold)` and
**only** marks finality on success.

**Why not a swap:** switching `verify` → `verify_signature_full` without `PublicParams` either
rejects everything or (with empty params) stays forgeable. The one-shot path cannot be made
non-forgeable in place because it was built as a simulation without `PublicParams`. The full-protocol
`CommitteeManagerFull` path is the only one that is, and it changes the wire format.

## 3. Why it is safe to defer (dormancy)

The committee threshold path is **entirely dormant in production**:
- `CommitteeManager::new` / `CommitteeManagerFull::new` are constructed **only in tests**
  (`crates/seal-node/src/committee.rs:656-866`).
- **Nothing in production publishes** to the committee-sig topic that `accept_committee_signature`
  listens on.
- **Blocks finalize via the F3-hardened shared `apply_block_transition` / state-root, not committee
  threshold sigs.** So the weak/no-verification path has zero live effect today, and there is no live
  fork surface to protect while it sits unused.

Activating it is a **protocol change**: it changes how blocks are finalized and the wire format, so it
must be coordinated across the network (a hard break if finality semantics shift). It is safe to
*build* because it is dormant; it is *not* a drop-in swap.

## 4. Regression (required once implemented)

- A **below-threshold** signature is rejected by `accept_committee_signature`.
- A signature over the **wrong block hash** (or wrong key) is rejected.
- A **valid full-protocol** signature over the correct block hash is accepted and flips the local
  finality decision.
- Two independent nodes, given the same wire message + same chain state, reach the **same**
  accept/reject decision (determinism — no wall-clock / environment dependence in the verify path).

## 5. Status

Design-first; **implementation deferred**. The corrected framing (the trait `verify` is a
count+norm+nonzero-challenge check that ignores message and key; `verify_signature_full` is the real
check but needs `PublicParams` the one-shot path lacks; the accept path returns `Ok(())`; and the
whole path is dormant) is the deliverable. Revisit with a regression-first implementation of the
full-protocol wiring (§2), coordinated as a protocol change.
