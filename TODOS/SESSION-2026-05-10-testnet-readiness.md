# Session plan — 2026-05-10 (testnet-readiness batch)

Scope locked by the user after the morning `seal_listTokensByFeeAuthority`
cascade closed the authority-current trio. This is the **plan**;
implementation will follow in the same standard 3-commit-per-item
shape (code → docs/explorer wiring where applicable → STATUS+TODOS
sync), each followed by a back-to-back quick CI run.

The user explicitly told us to ignore other red items (audits,
bug bounty, recruitment, bootstrap-node infra, registration
portal review). Only the items below are in scope.

---

## Order of operations

**Batch A — code-side testnet-readiness (yellow + the two red items the
user pulled in):**

1. **Stellar SDK / quickstart protocol skew alignment** (Tier-1 #2).
   *Lowest-risk option (a):* pin `stellar/quickstart` to a dated
   nightly running Soroban protocol 22 in
   `bridges/docker-compose.testnet.yml`; keep `soroban-sdk = "22"`
   in `bridges/stellar/Cargo.toml`. Document the pin's expiry
   risk and the migration path to (b) protocol 25 if the nightly
   ages out. Acceptance: `stellar contract install` completes,
   `scripts/bridge-testnet-demo.sh` lock side runs to mint event.
   ~1–2 commits.

2. **State-sync RPC implementation** (Tier-1 #3 step 2/6+). Four
   sub-steps, each its own 3-commit cycle and CI:
   - **2a `seal_listSnapshots`** — read-only roster of recent
     snapshots. SnapshotIndex on the runner; periodic capture at
     epoch boundaries; in-memory cap to N most recent.
   - **2b `seal_getSnapshotManifest`** — manifest = ordered chunk
     IDs + per-chunk hash + total bytes + tip block hash + tip
     Ringtail aggregate. Refuses pruned manifests.
   - **2c `seal_getSnapshotChunk`** — content-addressed slice of
     HAMT leaves. Caller re-hashes to confirm. 4 MiB cap.
   - **2d Late-joiner bootstrap path** — `seal-node
     --bootstrap-from-snapshot` wires header-sync → pick → stream
     → tip catch-up. Smoke test: a fresh node converges against a
     2-node testnet without replaying genesis.

3. **CUDA STARK bring-up runbook check** (Tier-1 #1). *Doc-only
   on this dev machine.* User confirmed (2026-05-10): **testnet
   launch does not depend on CUDA**; it's a STATUS row 7/8
   first-number, not a launch gate. Confirm
   `scripts/cuda-bringup.sh` env + deps + output path are current
   so the GPU host can run it without surprises. ~1 commit.

**Batch B — operational infra (the two red items the user pulled in):**

4. **Validator registration portal** (`apps/seal-registration`).
   New axum service. Mirrors the shape of `apps/seal-faucet`.
   POST /register accepts an ML-DSA-signed registration
   `{pubkey_hex, vrf_pubkey_hex, name, contact}`; verifies the
   signature against the supplied pubkey; dedupes on pubkey;
   persists JSONL. GET /registrations returns the public roster
   (omits `contact`). Per-IP rate limit. Companion
   `docs/TESTNET-REGISTRATION.md`. ~3 commits.

5. **Release script** (`scripts/release.sh`). Per CLAUDE.md
   "shell scripts only". Produces release artifacts for
   `v$VERSION`:
   - Linux x86_64 (cross via docker rust:slim)
   - Linux ARM64 (cross via docker rust:slim --platform=linux/arm64)
   - macOS ARM64 (host build)
   - SHA256SUMS file
   - **PQC-native** signing: ML-DSA-sign SHA256SUMS via seal-cli
     (the project is post-quantum first per CLAUDE.md; using a
     classical-only sigstore flow would contradict that)
   - Docker image tagged `ghcr.io/seal-dao/seal-node:v$VERSION`
   - Push gated behind `RELEASE_PUBLISH=1` so a dry run is the
     default and CI never accidentally publishes
   - Companion `docs/RELEASE.md`
   ~3 commits.

---

## Why this order

- **A1 first** because it's the smallest, lowest-risk item and
  unblocks Phase-3 stress testing on the bridge stack — closing
  it removes a dependency on the GPU host and on external
  reviewers.
- **A2 next** because it's the largest item (~3–5 sessions) and
  late-joining validators in Phase-2 stability need it. Its four
  sub-steps are independent enough to commit incrementally
  without leaving the tree in a half-broken state.
- **A3 deferred** to a doc-only check this session. Real
  measurement is the RTX 6000 host's job.
- **B4 + B5** after the code is in shape. The release script in
  particular will benefit from having the late-joiner bootstrap
  path landed, since the README will reference it as the
  recommended way to start a non-genesis validator.

## Out of scope this batch

The following were explicitly excluded by the user:
- Audits (Veridise PQC, protocol)
- Immunefi bug bounty
- Validator recruitment
- Bootstrap node infra (DNS, VM provision, regional spread)
- Anything not in the eight items above

These remain in the "Deferred — genuinely external" section of
`TODOS.md` and will be picked up by a separate operational push.

## Definition of done for this batch

- A1: bridge-testnet-demo.sh lock side reaches mint event on
  protocol-22 quickstart pin.
- A2a–c: three RPCs land with handler + tests + explorer
  surfacing of the snapshots roster.
- A2d: a fresh node bootstraps from a peer's snapshot, no genesis
  replay, tests confirm tip-equivalence.
- A3: cuda-bringup.sh runbook check passes a dry inspection;
  output-path schema documented.
- B4: validator registration portal accepts a signed registration
  end-to-end; rejects unsigned / dupe / malformed; roster GET
  returns the public view.
- B5: release.sh dry-runs to a populated `dist/` directory with
  three binaries + SHA256SUMS + ML-DSA signature; Docker image
  builds locally; push gated behind RELEASE_PUBLISH=1.

## Acceptance gate

Each item lands its own quick CI run (`scripts/ci.sh quick`); the
batch as a whole adds ≥10 new tests and grows the count from 1077
toward 1090. No clippy regressions; no test deletions outside of
the items themselves.
