# Local Security Inspection — 2026-09-27

Automated scan + local-model triage + manual code review of `seal-dao-master`
(HEAD `4f83cecbc`, branch `main`), run fully offline with the
`security-toolkit-public` (`appsec`) pipeline: SAST/SCA/secrets scanners →
SARIF → DuckDB findings store → local-LLM triage (Ollama) with `lh`
(le-harnais) falsification cross-check, followed by a human-grade code review
pass over every significant finding.

- **Store**: `security-toolkit-public/findings.duckdb` (2,148 findings
  ingested after fingerprint dedupe; after the §3.2 allowlist, 127 open —
  all project-owned)
- **Raw SARIF**: `security-toolkit-public/reports/seal-dao/`
- **Tooling**: appsec (Go), gosec n/a, cargo-audit v0.22.2, gitleaks v8.21.2,
  semgrep 1.178.0, trivy 0.74.0, bandit 1.7.10 (container)

## 1. Scanner results (raw)

| Tool | Kind | Findings | Note |
|------|------|----------|------|
| gitleaks | secrets | 1,626 | 1,625 in `vendor/` (crate checksums, upstream test PEMs) — noise; **1 real candidate** |
| trivy-fs | sca | 721 | 696 in `vendor/`; **25 non-vendor** (Cargo.lock + bridges/solana npm) |
| semgrep | sast | 8 | all in app/infra code, all plausible |
| cargo-audit | sca | 10 vulns + 22 warnings | dependency advisories in `Cargo.lock` |
| bandit | sast | 65 | all low, `sdks/python` |

## 2. Verified findings (manual code review)

> This section was completed by direct code reading. Verdicts below.

### 2.1 Dependency advisories (cargo-audit + trivy) — VERIFIED

Build context: `.cargo/config.toml` replaces crates.io with `vendor/`
(offline vendored build) — any `cargo update` must be followed by
`./scripts/vendor-update.sh`. All chains verified against `Cargo.lock`
(10,234 lines) + all 26 workspace manifests + vendored manifests; the
feature-gated verdicts rest on feature resolution, which `cargo tree`
cannot show.

| Dep | Advisory | Verdict | Why / fix |
|-----|----------|---------|-----------|
| crossbeam-epoch 0.9.18 | RUSTSEC-2026-0204 | **NOT-REACHABLE** | only fires on `{:p}` of Atomic/Shared; no seal crate names crossbeam-epoch (chain: sled ← seal-storage). Hygiene: `cargo update -p crossbeam-epoch --precise 0.9.20` + re-vendor |
| rand 0.8.5 + 0.9.2 | RUSTSEC-2026-0097 | **FALSE-POSITIVE** | trigger = vulnerable 0.9 `ThreadRng` + a *custom logger* calling `rand::rng()`; all 6 binaries use stock `tracing_subscriber::fmt`, seal code only uses 0.8 `thread_rng` (signing/keygen in `seal-crypto/src/signature.rs:39,65`). 0.9.2 is transitive-only (libcrux, hickory, quinn, yamux-0.13) |
| scc 2.4.0 | RUSTSEC-2026-0205 | **NOT-REACHABLE** | whole chain (serial_test ← sp1-prover ← sp1-sdk) behind disabled `seal-zk/sp1` feature (`default = []`, no member enables it) |
| hickory-proto 0.25.2 | GHSA-3v94-mw7p-v465 (HIGH) | **REACHABLE — top Rust fix** | mDNS is live in the production swarm (`seal-p2p/src/node.rs:186-188`): hickory parses every LAN multicast DNS packet — untrusted input, continuously. Discovery-only, LAN-adjacent attacker. `cargo update -p hickory-proto` + re-vendor (libp2p-mdns requires "0.25.2", in-range patch is drop-in) |
| libp2p-quic 0.13.0 | CVE-2026-61544 (HIGH, no fix) | **NOT-REACHABLE** | `quic` feature off; swarm is TCP+noise+yamux only (`node.rs:162-168`), no `.with_quic` anywhere. Keep off until upstream fixes it |
| p3-challenger 0.3.2-succinct | CVE-2026-46654 (HIGH) | **NOT-REACHABLE** | sp1 prover family behind disabled `seal-zk/sp1`; re-verify CVE status before ever enabling sp1 |
| quinn-proto 0.11.14 | GHSA-4w2j-m93h-cj5j (HIGH) | **NOT-REACHABLE** | every edge feature-gated off (libp2p `quic` off; reqwest `http3` off on both users — `default-features=false`) |
| yamux 0.12.1 | CVE-2026-32314 (HIGH, fix 0.13.x) | **NOT-REACHABLE (caveat)** | libp2p-yamux bundles 0.12.1 *and* 0.13.10; `Config::default()` (used at `node.rs:167`) resolves to the **fixed 0.13.10** path. ⚠️ any future `.set_max_num_streams()`-style 0.12-only setter silently flips the muxer back onto the vulnerable 0.12 codepath — add a review guard at that call site |
| bigint-buffer 1.1.5 (npm) | CVE-2025-3194 (HIGH) | **REACHABLE — dev/CI only** | `bridges/solana` is a private test-only package; native install-script module runs on every `npm test` box. `npm update` there; production bridge is the Rust crate + BPF program |
| stream-json 1.9.1 (npm) | CVE-2026-71429 (MED) | **REACHABLE — dev/CI only** | via jayson ← web3.js on local-validator RPC responses in the e2e suite. upgrade |
| toml 3.0.0 (npm) | (note) | **ACCEPT/PIN** | unmaintained anchor transitive; `overrides` entry or documented acceptance |

**Bottom line:** of the 11 flagged, 6 are not compiled into any binary
(feature-off / unnameable-types), 1 is a false positive, 4 are
reachable-but-bounded (LAN mDNS parser, dev-only npm deps), and the
yamux 0.12 copy is dead in the default build with a re-arming footgun.
None of the "HIGH" dependency CVEs are on a consensus or fund path in the
current build.

### 2.2 Application code (semgrep + gitleaks + bandit + manual) — VERIFIED

Every claim below was re-verified by reading the cited source lines.

| Finding | Location | Verdict | Fix |
|---------|----------|---------|-----|
| No `USER` in node Dockerfile | `Dockerfile:28-49` | **CONFIRMED-LOW** — node image runs root; ports 4001/8545 >1024, no socket mounts, nothing needs root; RCE via p2p/RPC lands as root, validator keyfile dir root-owned | add non-root user + `USER` before entrypoint; pre-chown bind mounts |
| Exported activity | `AndroidManifest.xml:12-19` | **FALSE-POSITIVE** — mandatory MAIN/LAUNCHER launcher export; `MainActivity.kt` never reads `getIntent()`, no deeplinks/extras; `allowBackup="false"` already set | none |
| postMessage w/o origin check | `content.js:22`, `inject.js:15` | **CONFIRMED-LOW** as flagged (real but not the failing control — `event.source===window` limits senders to the page's own world; authz lives in `background.js` origin list) | add `event.origin` check anyway; see §2.4 for the real holes |
| compose hardening | `docker-compose.monitoring.yml:15,27` | **CONFIRMED-LOW** — dev stack, but ports 9090/3000 bound to **all interfaces**, Grafana `admin/admin` hardcoded (lines 33-34), `:latest` floats, unauthenticated Prometheus w/ SSRF-capable scrape config | bind `127.0.0.1:`, pin images, drop default creds, `no-new-privileges` |
| gitleaks "generic-api-key" | `scripts/bridge-e2e.sh:479` | **FALSE-POSITIVE** — SHA-256 of the documented fixture key `[0x11;32]` (trivial 1-bit pattern, testnet compose only; the key is also *by design public* on-chain, see §2.4-A); only the hash is flagged | allowlist `bridges/` fixture patterns |
| bandit 65× low | `sdks/python/seal_sdk/` | **CONFIRMED-LOW (trivial)** — the whole package is an unimplemented scaffold: no HTTP, no `verify=False`, no secrets touched; nothing can upgrade above low | forward-looking: enforce TLS cert verification when RPC is implemented |

### 2.3 Issues the SCANNERS missed (verified against source)

**A. Solana bridge: the "committee signature" is forgeable — HIGH.**
`BridgeState` is a *public* Anchor account whose field `committee_key: [u8;32]`
(`programs/seal-bridge/src/lib.rs:572`) is readable by anyone on-chain.
`verify_committee_sig` (lib.rs:274-307) computes `HMAC-SHA256(committee_key, …)` —
an HMAC under a publicly readable key authenticates nothing: any attacker can
read the key from `BridgeState`, forge a valid unlock MAC for their own
recipient, and drain the vault. The effective gate on `unlock_tokens` is the
single `authority` signer hot key (lib.rs:530-540). The code comments
(lib.rs:262-273) frame the MAC as a mirror of the off-chain Ringtail verify
with per-epoch rotation bounding blast radius — but rotation requires the
`authority` key, so a forger who gets there first outpaces rotation.
**Fix:** move committee auth to a real threshold scheme with a *public*
verifying key (the planned Ringtail layer), or at minimum multisig the
`authority` and keep the MAC secret off-chain.

**B. Solana bridge: no replay protection on unlock — HIGH.**
`unlock_tokens` (lib.rs:161-235) takes a `nonce`, uses it only inside the MAC,
and never records that it was spent (no consumed-nonce set/bitmap; README TODO
unchecked). A captured valid unlock tx re-executes until the vault is drained
or the key rotates. **Fix:** consume each nonce on-chain (close a per-nonce
PDA, or bitmap in `BridgeState`) and reject repeats; bind an expiry into the MAC.

**C. Solana bridge: feature-gated Ringtail verify checks an empty message — MEDIUM.**
`verify_ringtail_sig` (lib.rs:426) calls the verify with `b""` — even with the
`ringtail-verify` feature enabled, the check is not bound to
recipient/amount/nonce, so the "defense in depth" layer authenticates nothing.
**Fix:** pass the canonical message through before ever enabling the feature.

**D. Wallet extension: silent origin self-approval + popup XSS → key compromise — HIGH.**
`background.js:116-135` handles `seal:popup:listRequests` /
`seal:popup:resolveRequest` with **no sender authentication** (unlike the
origin-gated `seal:*` paths at lines 95-114). A malicious page with the
injected content script can: (1) send `seal:requestAccounts`, (2) list pending
requests to learn the id, (3) resolve it `{approved:true}` itself — no user
interaction, origin permanently "connected". Then its `seal:signMessage`
payload's `message_hex` is rendered into the popup via `innerHTML`
(`popup.js:569-582`, e.g. `data-msg="${item.messageHex}"`) — crafted hex like
`"><img src=x onerror=…>` is XSS *inside the wallet popup*: with the vault
unlocked it becomes a signing oracle and can capture the passphrase typed into
the unlock field. **Fix:** authenticate popup-only handlers to the extension
itself (`!sender.tab && sender.id === runtime.id`), and never
`innerHTML` payload data (use `textContent` + hex allowlist).

**E. Wallet extension: content scripts injected on ALL http/https pages — MEDIUM.**
`manifest.json:18-25` matches `http://*/*` + `https://*/*` — every banking,
mail, and gov site the user visits gets the content script. Narrow to the
dApp domains the wallet actually supports.

**F. `bridges/.seal-e2e-key.json` — generated ML-DSA keypair NOT gitignored — MEDIUM.**
`scripts/bridge-e2e.sh` generates it on first run and reuses it; `.gitignore`
covers `key.json`/`mykey.json`/`kem.json` but nothing matching
`.seal-e2e-key.json`, so one `git add -A` on any dev box ships a real private
key. **Fix:** add `bridges/.seal-e2e-*` to `.gitignore`.

**G. Android wallet renders the BIP-39 mnemonic in a plain `TextView` — MEDIUM.**
`MainActivity.kt:50-52` shows the seed phrase on screen with no
screenshot/recents blur (`FLAG_SECURE`); the app's own README lists this as a
goal but it is unimplemented.

### 2.4 Rust core deep review (beyond scanners) — VERIFIED

Full production-source reads of seal-crypto, seal-token, seal-sql,
seal-consensus, seal-vrf, seal-threshold, seal-mpc, seal-node (all 6,557
lines). Items marked ✓ were re-verified by direct read during this
inspection. The **primitives layer is solid** (checked arithmetic with
Kani harnesses, zeroized core keys, SHA3-only hashing, constant-time
comparisons) — everything built *on top of it* is not.

**Axis 4 — SQL layer: CRITICAL**
- ✓ **Unauthenticated arbitrary SQL**: `seal_querySql` is absent from
  `requires_auth` (rpc.rs:862-910); the no-namespace path executes the
  full engine on the node's ledger (rpc.rs:1444-1483 →
  `sql_engine.execute`) — `SELECT/INSERT/UPDATE/DELETE/DROP/CREATE
  POLICY/CALL` with no auth. Total RLS bypass by the front door.
- `format!` injection, also unauthenticated: rpc.rs:2013-2018
  (`format!("SELECT {} FROM {}", column, table)` in `handle_mpc_aggregate`)
  and rpc.rs:2110 (`handle_zk_prove`).
- Stored-proc injection by construction: `seal-sql/src/engine.rs:170-263`
  string-substitutes args into the body and re-parses the result as
  multi-statement SQL.
- RLS is decorative: the engine never calls `rls.check_access` on
  insert/select/update/delete; the write-path check hardcodes row owner =
  caller (namespace.rs:94-97); `with_check_expr` never evaluated;
  `cross_app_query` (namespace.rs:294) bypasses RLS entirely; policy
  matching is `expr.contains(...)` substring logic (rls.rs:200-235).

**Axis 6 — consensus / crash safety: CRITICAL**
- ✓ **VRF secret key gossiped to every peer**:
  `consensus_runner.rs:153` `vrf_public_key: vrf_manager.secret_key().to_vec()`
  (comment: "VRF eval uses secret key"), re-set at each rotation (:515);
  `ValidatorInfo` is Serialize/Deserialize and shared network-wide.
  Every node holds every validator's VRF signing key. Consequence: the
  apply-path VRF gate is dead — `PqVrf::verify` needs a 1952-byte
  verifying key but receives a 4032-byte secret (pq_vrf.rs), and
  `network_node.rs:697,729-730` skips the check on empty/unknown fields.
- ✓ **Unsigned epoch transitions, grindable election**:
  `accept_epoch_transition` (consensus_runner.rs:466-480) accepts
  `{epoch, seed}` from any peer, no signature; `Slot::vrf_input` =
  `epoch_seed || slot` with no chain id/parent/domain separation. With the
  VRF secret known, an attacker grinds candidate seeds offline and pushes
  the forged transition to be deterministically elected proposer.
- No proposer signature is verified anywhere on the apply path
  (`network_node.rs:676-749`); no timestamp validation; no double-sign
  detection.
- Slashing forgeable: `slashing.rs:102-162` takes caller-supplied
  `validator_stake`, no signatures — anyone can slash anyone at a
  reporter-chosen size.
- Restart = balance reset: `replay_block` drops all token ops
  (`_ => {}`, consensus_runner.rs:929), the genesis mint re-applies on
  every restart (main.rs:872-886), and `--bootstrap-from-snapshot`
  (main.rs:850) verifies chunk hashes + state root — all supplied by the
  same peer, so a malicious bootstrap peer serves arbitrary balances.
- ✓ **Emission off-block to hardcoded addresses**:
  `consensus_runner.rs:524-525` `let _ = self.balances.mint("seal1validators", …)`
  — results ignored, minted before the epoch's first block exists.
- Fees never collected on this path: senders are 16-byte-hex truncations
  that don't match bech32m store keys; Err swallowed (consensus_runner.rs:650-659);
  mid-loop burn errors leave partial burns (fees.rs:117-151).
- Transaction "nonces" are a bare counter (consensus_runner.rs:421-424) —
  no replay prevention; mempool batch quorum is `Vec<Vec<u8>>` pubkeys,
  forgeable (mempool.rs:87); bridge ringtail aggregate accepts
  `env.signature_hex` from any gossip peer, tests use `"dummy"`
  (network_node.rs:552-582); DEX state computed into roots before matching
  (consensus_runner.rs:647-738); `governance.execute` executes nothing,
  and council gates are unsigned string lists countable against the
  publicly listed council — which ✓ `seal_bridgeCouncilAdd` (rpc.rs:4915,
  "No auth by design") lets anyone bootstrap.

**Axis 2 — money call sites: HIGH** (primitives clean, callers broken)
- `handle_transfer` (rpc.rs:2544) mutates the in-memory balance store
  directly, outside any block — invisible to other nodes, replayable.
- `cancel_order` has no ownership check; `place_order` no sufficiency
  check (orderbook.rs); `apply_balances` doubles supply if called twice
  (genesis.rs:225-243, admitted in doc); `genesis.rs` div-by-zero: ✓
  `election.rs:54` `committee_threshold / config.committee_size as u64`
  with no committee-size validation anywhere.

**Axis 3 — secrets: HIGH**
- ✓ **`PqRpcSession` derives `Debug` and prints the full 32-byte session
  key** (pq_rpc.rs:19); `VrfKeypair.secret_key` is a plain `Vec<u8>`, no
  Zeroize (vrf/traits.rs:57-60); `committee.rs:142` raw ML-DSA secret,
  never zeroized; `SpdzShare` derives `Debug` (prints value/MAC shares)
  and rpc.rs:2058 builds MPC with hardcoded seed `b"seal-mpc-seed"`;
  pq_rpc "encryption" is an unauthenticated XOR keystream (no MAC —
  bit-flip forgery), nonce monotonicity is the only replay defense.
- Core key types (SigningKey, KemSecretKey, HybridKem, VrfKeyManager
  master seed) are properly zeroized + redacted — compliant.

**Axis 1 — panics: MEDIUM**
- ✓ `balance.rs:127` `.expect()` on bincode deserialize — panics on
  corrupt/snapshot data (a reachable import path via
  `--bootstrap-from-snapshot`); `consensus_runner.rs:207`
  `panic!("this node must be in the validator set")`; `engine.rs:922`
  `unreachable!()` in policy-action parsing (user-influenced match).
  Network-message parse paths propagate errors rather than panicking —
  clean.

**Axis 5 — crypto hygiene: HIGH**
- `thread_rng` is the only entropy source in seal-crypto (keygen +
  ML-DSA signing nonce) — acceptable but single-sourced.
- ✓ PQ-encrypted p2p transport compiled in but **off by default**
  (`main.rs:805` `pq_encryption: false`); TEE attestation accepts any
  non-empty quote (documented stub); ZK "proof" is a SHA3 stub that
  returns the statement's truth value (`"satisfied": …`, rpc.rs:2139-2144);
  constant-time comparisons present where needed (good); SHA3-only
  hashing respected (good).

**Concrete default-config exploit chains** (each verified at the cited
lines):
1. `seal_querySql` (no auth) → read/write the entire ledger, including
   `DROP TABLE` and `CREATE POLICY`.
2. `seal_bridgeCouncilAdd` (no auth) ×7 → forge 2/3 council approvals →
   `seal_bridgeRotateCommitteeKey` → attacker committee MAC → forge the
   on-chain unlock (§2.3-A).
3. `seal_addBridgeObserver` (no auth, empty admin set) → attacker observer
   → single-confirmation auto-mint of wrapped tokens.
4. Capture any `seal_transfer` (plain HTTP, no nonce) → replay until the
   sender is drained.
5. Forged epoch transition + offline VRF seed grinding → self-election as
   slot proposer.

## 3. Triage (local LLM + lh falsification)

`appsec triage --model <model> --verify-with-lh` over the top-N
highest-severity findings. Per-finding: exploitability rating + suggested
patch (primary model), then three falsification lenses (reachability —
clingo-proven over the codegraph call graph, guard, controllability) via
`lh`; a finding is marked falsified only if ≥2 lenses refute at ≥medium
confidence. Falsified findings remain visible by default.

### 3.1 Run 1 — `qwen2.5:7b-instruct` (no lh), limit 50

49/50 triaged, 1 error. Because of the severity-ordering bug (§5),
`--limit 50` selected gitleaks `note`-severity vendor findings, not the
HIGH SCA advisories. Verdicts were unreliable (rated
`.cargo-checksum.json` hash files "high" exploitability, emitted nonsense
patches) and were discarded.

### 3.2 Run 2 — `qwen3.6:35b` + `--verify-with-lh`, limit 20

20/20 triaged, 0 errors (selection: same ordering bug → next 20 untriaged
gitleaks vendor `note` findings).

- Model rated all 20 **low** exploitability.
- The `lh` falsification pass (reachability / guard / controllability
  lenses over the codegraph index) **refuted 14/20** (≥2 of 2–3 lenses,
  high confidence): all `.cargo-checksum.json` hex-hash
  `generic-api-key` matches, auto-generated `linux-raw-sys` netlink
  bindings (`NL80211_KEY_MAX` …), vendored `p256` test-fixture keys.
- The 6 not refuted are also vendor noise on manual inspection:
  `ed25519-2.2.3/src/pkcs8.rs:61` (documented test key constant),
  `log-0.4.29` / `malachite-base-0.4.22` checksums, `linux-raw-sys`
  riscv32/riscv64/x32 netlink constants.

**Verdict:** the local LLM + lh pass independently confirms the manual
review — the gitleaks vendor stream is false-positive end to end. Note the
high-severity SCA advisories were *not* LLM-triaged (ordering bug); they
were manually verified per-advisory in §2.1, which is the stronger
verification.

**Allowlist applied.** `suppressions.yaml` (toolkit root; 102 items:
2× gitleaks vendor + 1× `scripts/bridge-e2e.sh` fixture + 99× Trivy
vendor rule-ids, `path_glob` vendor, expires 2027-09-27) applied with
`appsec suppress --apply`: **981 findings suppressed** (285 gitleaks,
696 Trivy). The store now holds 127 open findings, all
project-owned: 25 Trivy (root `Cargo.lock` 12, bridges/solana npm 7,
bridges/solana program 3, bridges/stellar 3), 29 cargo-audit, 8 semgrep,
65 bandit — exactly the set analyzed in §2.

## 4. Recommendations (ranked)

**P0 — seal-node RPC/consensus (this is the real trust boundary):**
0.1. Auth-gate `seal_querySql` (or restrict to read-only SELECT) and the
    two `format!`-injection endpoints (§2.4 axis 4); make the SQL engine
    actually call `rls.check_access`; stop stored-proc string
    substitution.
0.2. Fix the consensus core: sign epoch transitions and verify proposer
    signatures on apply; stop gossipping the VRF secret in the validator
    set (use the real public key + working VRF verify); bind chain id +
    parent hash into `Slot::vrf_input`; validate `committee_size > 0`.
0.3. Make restarts/replay state-consistent: `replay_block` must re-execute
    token ops, genesis mint must be idempotent, snapshot import needs an
    honest-majority quorum (state root from N independent peers), and
    replace the `expect`-on-bincode in `balance.rs:127` with an error.
0.4. Require signatures + on-chain stake on slash reports; real tx
    nonces; enforce delegation caps; make `governance.execute` either
    execute or not claim to.
0.5. Zeroize `PqRpcSession` (drop the `Debug` that prints the session
    key), `VrfKeypair`, `our_signing_key`; replace the XOR keystream with
    an authenticated cipher; turn `pq_encryption` on by default.

**P0 — Solana bridge (funds path):**
1. Stop using the on-chain `committee_key` for MAC verification
   (§2.3-A): migrate committee auth to a threshold scheme with a *public*
   verifying key (the planned Ringtail layer, with the canonical message
   actually bound — §2.3-C), or multisig the `authority` and keep the MAC
   secret off-chain. Until then treat every unlock as gated by one hot key.
2. Add on-chain nonce consumption to `unlock_tokens` (§2.3-B) — consumed
   nonce set/PDA, reject repeats; bind an expiry into the MAC payload.

**P1 — Wallet extension (key material path):**
3. Authenticate `seal:popup:*` handlers to the extension itself and stop
   `innerHTML`-ing payload data in the popup (§2.3-D) — the two together
   enable silent self-approval + popup XSS → signing oracle.
4. Narrow `content_scripts` matches from all http/https to supported dApp
   domains (§2.3-E).
5. Android: `FLAG_SECURE` on the mnemonic screen (§2.3-G).

**P2 — hygiene / cheap:**
6. `.gitignore`: add `bridges/.seal-e2e-*` (§2.3-F).
7. Node `Dockerfile`: non-root `USER` (§2.2).
8. Monitoring compose: bind `127.0.0.1:`, pin images, drop `admin/admin`,
   `no-new-privileges` (§2.2).
9. Rust deps: `cargo update -p hickory-proto` (+ re-vendor) — the only
   reachable Rust advisory (§2.1); add a review-guard comment at
   `seal-p2p/src/node.rs:167` about the yamux 0.12 re-arming footgun.
10. `bridges/solana`: `npm update bigint-buffer stream-json`; `overrides`
    for `toml`.
11. Scanner hygiene: `suppressions.yaml` allowlist for `vendor/**` and the
    bridge fixture constants (~92% of raw findings are vendor noise);
    consider `--no-vendor`-style exclusions for gitleaks/trivy.

## 5. Method notes & tooling bugs hit

- gitleaks/trivy scanned `vendor/` (the walker deny-list only applies to
  detect, not to the raw scanners) → ~92% of raw findings are vendor
  noise. Resolved: `suppressions.yaml` written and applied (see §3.2) —
  981 findings suppressed, store reduced to the 127 project-owned
  findings.
- appsec bugs: double-prefixed container images for semgrep/trivy
  (`tools.go:109,143`); `DetectRuntime` prefers podman over docker
  (bandit image is docker-only → `--runtime docker` needed);
  cargo-audit JSON is discarded on exit≠0 even though exit 1 = "findings
  present" (`scan.go:124`); cargo-audit/bandit SARIF had to be converted
  by hand for ingest.
- appsec bug: `triage`/`top` order findings with `ORDER BY severity DESC`
  as TEXT — alphabetical, so `note` sorts above `high` and `critical`
  (`triage.go:71`). `--limit N` therefore triaged note-level vendor noise
  first; the HIGH SCA advisories were never LLM-triaged.
- appsec bug: `suppress --apply` fails on any finding that has a `triage`
  child row — DuckDB executes the `UPDATE findings SET status=…` as
  delete+insert and the `triage.finding_id → findings.id` FK blocks the
  delete. Workaround used: delete the child `triage`/`triage_errors`
  rows for the suppressed set first. Side effect: the store's LLM
  verdicts for the suppressed (all vendor-noise) findings were removed;
  the 35B+lh verdicts are recorded in §3.2.
- 7B-class triage models are unreliable (misrate vendor checksums as high,
  emit nonsense patches); use ≥35B-class or treat model verdicts as
  hints, not verdicts.

## 6. Fix status appendix (implemented + validated 2026-10-05)

A "basic, local, testable fixes" pass implemented the in-scope items below
(12 dependency-ordered steps, each keeping `cargo test` green and
`seal-cli demo` working). Deep protocol/crypto work that needs design
beyond a local patch is listed in §6.2 as a documented follow-up, not
silently dropped. Commits are on local `main` (author `pc@work.seal.dao`).

### 6.1 Fixed (with commits)

**seal-node RPC / consensus (the real trust boundary, §2.4):**

- **Unauthenticated arbitrary SQL** (axis 4, CRITICAL) — `bcbea84fd`.
  Anonymous `seal_querySql` callers are now restricted to read-only
  `SELECT` by `is_read_only_sql` (first token `SELECT`, reject `;`
  multi-statement), on **both** the scoped and unscoped branches. The
  two `format!`-injection endpoints (`seal_mpcAggregate`,
  `seal_zkProve`) and all six formerly open bridge-admin methods
  (`seal_bridgeCouncilAdd/Remove`, `seal_bridgePauseChain/UnpauseChain`,
  `seal_bridgeRotateCommitteeKey`, `seal_addBridgeObserver`) are in
  `requires_auth`. Unit-tested incl. `test_is_read_only_sql`. (The
  engine-level RLS write-path evaluation is deferred, §6.2.)
- **VRF secret gossiped as "public"** (axis 6) — `9f0ca8d62`. Validator
  info now carries the real `public_key()`; `run_election` takes the
  local secret explicitly, so the apply-path `PqVrf::verify` finally
  receives a real verifying key. Regression
  `test_vrf_public_key_is_verifiable_public_key`.
- **Unsigned epoch transitions + grindable election** (axis 6) —
  `3feb26c44`. `EpochTransitionMsg{epoch, prev_seed, vrf_output, seed,
  signature}` is bincode-decoded and verified: `epoch == current+1`,
  seed recomputed via `Epoch::next_epoch(&vrf_output)`, signer ∈
  validator set, ML-DSA over the canonical byte string. Replaces the
  `try_into().unwrap()`.
- **No proposer signature on the apply path** (axis 6) — `41c664de8`.
  `BlockHeader.proposer_signature`; the producer signs the empty-sig
  header serialization, the verifier re-serializes with the sig zeroed
  and verifies. Empty and tampered sigs are rejected. **Hard break**:
  bincode is positional, so existing data dirs must be wiped on upgrade
  (replay breaks at block 1 and the chain re-seeds cleanly).
- **Forgeable slashing** (axis 6) — `8b924af8a`. `DoubleProposal` now
  carries both headers + signatures; `report_offense` takes a
  `&ValidatorSet` and verifies both header sigs against the registered
  proposer pubkey (same proposer, same slot, different hashes).
- **Restart = balance reset + double genesis mint** (axis 6) —
  `c9172c6e3` + `9cd416db9`. `replay_block` re-applies `Transfer`
  (nonce stripped); balances persist to `<data-dir>/balances.bin`
  (atomic temp+rename) after each tick with a broken-replay fallback;
  the genesis mint is gated on
  `!bootstrapped_from_snapshot && account_count() == 0`, so a restart
  does not re-mint onto restored balances. Validated: a two-run
  12-slot restart keeps `total_supply` at exactly 10^18 (genesis 1B
  SEAL), not 2×10^18.
- **No transaction nonces / replayable transfers** (axis 6) —
  `c9172c6e3`. Money txs carry an 8-byte LE nonce prefix;
  `accept_transaction` enforces the stored counter for money TxTypes;
  `handle_transfer` now emits a block-recorded money tx
  (`submit_money_tx`) rather than only mutating the in-memory store.
- **Non-deterministic on-block state root / the F3 fork** (axis 6, HIGH) —
  formal `50ba2f72b` + `647c97f10`, impl `a66b58da8`. The header
  `state_root` was computed from stores mutated **live** on the submitting
  node and only on replay elsewhere, so a non-origin proposer stamped a root
  its replayers rejected (SQL, transfer, fee burn, storage burn, and epoch
  emission all diverged — the transfer was the visible instance, but the
  divergence was systemic). Now both the producer (`produce_block_with_vrf`)
  and the replayer (`replay_block`) run the same `apply_block_transition` on
  the committed pre-state, so the state root is a pure function of the block.
  The live application is removed: `submit_sql` / `handle_transfer` write to a
  read-your-writes working set and enqueue (never the committed store), and
  the epoch emission mint moves out of `advance_slot` into the transition.
  Formally validated first (Lean4 algebra + TLA+ interleaving, wired into
  `scripts/ci-formal.sh`). **Hard break**: replayed roots now include
  fee/storage/emission, so pre-upgrade chains fail replay at the first
  affected block — wipe the data dir on upgrade.
- **`seal_bridgeCouncilAdd` no auth** (axis 6) — folded into
  `bcbea84fd` (above).

**Secrets (axis 3, HIGH):**

- **`PqRpcSession` derives `Debug` and prints the session key** —
  `9bdf11d47`. Custom `Debug` prints `session_id`, `nonce_counter`,
  and only the first 4 bytes (hex) of the session key. (Other
  zeroization/keystream items deferred, §6.2.)

**Panic-on-input paths (axis 1, MEDIUM) — `6300e977a`:**

- `balance.rs` `expect`-on-bincode → `decode_balance` returns `Result`
  (`fetch` maps a corrupt leaf to `None` + a warn); `consensus_runner`
  `panic!` ("must be in the validator set") → `with_validator_set`
  returns `Result`; `engine.rs` `unreachable!()` in RLS policy parsing →
  returns `Ok(action)`; election `committee_threshold /
  committee_size` divide-by-zero → `committee_size.max(1)` divisor
  guard (thresholds left alone: 0 correctly means "never elected").
  Each has a regression test.

**Solana bridge (funds path, §2.3):**

- **Forgeable committee MAC** (§2.3-A, HIGH) — `26f78494e`.
  Implemented as a **k-of-n committee member multisig** (a deliberate,
  user-approved deviation from the plan's single shared verifying key):
  `BridgeState{committee_members, member_count, unlock_threshold}`, and
  `unlock_tokens` requires ≥ `unlock_threshold` DISTINCT in-set members
  to have signed the transaction; each member's ed25519 signature is
  verified by the Solana runtime at zero program cost (in-BPF verify
  exceeded the pinned fork's 1.4M CU/instruction cap). The node holds
  the member signing keys and signs withdrawals with them
  (`30d2a5b74`, `--bridge-committee-ed25519-key`). The legacy HMAC
  (32-byte MAC) path is retained as a migration fallback and still
  gates the Stellar twin.
- **No replay protection on unlock** (§2.3-B, HIGH) — `26f78494e`. A
  per-nonce `UnlockedRecord` PDA is `init`-ed on the first unlock; a
  replayed nonce hits `AlreadyInUse`, rejected atomically with the
  transfer.

**Wallets (key-material path, §2.3-D/G) — `fe56b4c9e`:**

- **Silent self-approval + popup XSS → signing oracle** (§2.3-D, HIGH).
  `seal:popup:listRequests` / `seal:popup:resolveRequest` reject any
  sender with a `tab` (a web page) or a mismatched extension id;
  `seal:signMessage` validates `message_hex` as even-length hex before
  enqueuing; the content script relays only the four page-API types
  (`getAccounts`/`requestAccounts`/`signMessage`/`rpc`); the popup
  `renderRequests` builds rows with `createElement` / `textContent` /
  `setAttribute` instead of interpolating attacker-controlled
  `origin`/`messageHex` into `innerHTML`.
- **Android mnemonic without `FLAG_SECURE`** (§2.3-G, MEDIUM) —
  `MainActivity` sets `FLAG_SECURE`, excluding the mnemonic screen from
  the app-switcher thumbnail and blocking screenshots / screen
  recording.

**Hygiene (P2):**

- **`bridges/.seal-e2e-key.json` not gitignored** (§2.3-F, MEDIUM) —
  added to `.gitignore` (the on-disk generated key was untracked but a
  bare `git add -A` would have shipped it).
- **`.DS_Store` tracked** — added to `.gitignore` and removed from the
  index (kept on disk).

### 6.2 Deferred (documented follow-ups — no code in this pass)

- **Solana/bridge:** the feature-gated Ringtail verify still checks an
  empty message (§2.3-C) — the Solana path no longer depends on it
  (the multisig superseded the Ringtail layer there); the node-side
  Ringtail *aggregate* signature check is still a stub. Stellar-twin
  migration to the multisig (still HMAC), the KMS sidecar ed25519
  endpoint, and the relayer-side ed25519 e2e leg.
- **Node:** engine-level RLS policy evaluation on the write path
  (`rls.check_access`) + stop stored-proc string substitution +
  `cross_app_query` user binding (§2.4 axis 4); token/bridge state replay
  (lives in `RpcState`, not the consensus runner — the shared
  `apply_block_transition` re-applies SQL + native `Transfer` + fees +
  storage + emission on-block, but token/bridge/stake movement still has no
  runner-level replay); signed snapshot
  manifests + honest-majority bootstrap (axis 6); TEE attestation and
  ZK real implementations (axis 5); the remaining zeroization +
  `pq_rpc` XOR keystream → authenticated cipher + `pq_encryption` on
  by default (axis 3/5); `cancel_order` ownership + `place_order`
  sufficiency checks (axis 2); `apply_balances` idempotency (axis 2);
  DEX match replay/verification (axis 6).
- **Second-pass review follow-ups (§6.7 F6–F9)** — all deterministic (no
  fork), so they are economic/edge, not consensus, bugs: (F6) remove the two
  live balance mutations outside the transition (`handle_faucet` mint, gated on
  `--dev-faucet`; bridge-withdrawal fee `burn`/`mint`, gated on
  `bridge_withdrawal_fee > 0`) or route them through block transactions;
  (F7) make `process_block_fees` skip an unfunded sender and still credit the
  proposer the funded senders' share, rather than aborting the whole pass;
  (F8) align the emission with the `EmissionSchedule` rate (normalize by
  `BLOCKS_PER_EPOCH` = 128, not `config.slots_per_epoch` = 256), fire it from
  the epoch clock rather than the first-block-of-epoch, and source the schedule
  from block data rather than node-local config; (F9) advance the per-sender
  nonce counter consistently (only for money txs, on both the accept and
  apply paths) so the sender's money nonce does not desync across nodes.
- **Third-pass review follow-up (§6.8 M1)** — deterministic (no fork), so a
  correctness, not consensus, bug: (M1) key `prune_applied_txs` on the
  transaction's position in the block (or on the tx signature/hash), not just
  `(type, sender, payload)` — two distinct byte-identical txs (e.g.
  `UPDATE t SET n = n + 1` submitted twice) currently collapse, so finalizing
  one prunes both and the second is silently lost (transfers are immune
  because their payload carries the nonce). (The second-pass §6.8 M2 — lease
  expiry leaving dropped rows in the root — was re-verified as a **false
  positive**; see §6.8, `test_drop_table_is_removed_from_merkle_root`.)
- **Wallet:** narrow `content_scripts` from all `http(s)` to supported
  dApp domains (§2.3-E) — a product decision, not a local patch.
- **Deps/infra:** the one reachable Rust advisory `hickory-proto`
  (§2.1) needs `cargo update -p hickory-proto` + re-vendor;
  `bridges/solana` npm `bigint-buffer` / `stream-json` (§2.1); the
  yamux 0.12 re-arming review-guard comment at `seal-p2p/src/node.rs`;
  node `Dockerfile` non-root `USER` + monitoring-compose hardening
  (§2.2).

### 6.3 Validation sweep (2026-10-05)

- `cargo test` (full workspace): **1271 passed, 3 ignored** (74 suites).
- `cargo run -p seal-cli -- demo`: **PASS** (app deploy, RLS, cross-app
  access, block production).
- **Double-mint / restart regression:** `seal-node --data-dir <tmp>
  --slots 12` run twice back-to-back → `total_supply` **stable at 10^18**
  (genesis 1B SEAL), not doubled. The genesis seed now runs **before**
  replay (the F2 fix), so both the idle-chain and the **native-transfer**
  chain reconstruct on restart with conserved supply. Unit-level coverage
  was added for the transfer case that the earlier idle-only check
  missed: `test_restart_transfer_chain_replays_without_divergence` (a
  restarted node reaches identical balances, conserved `total_supply`,
  matching state root, and a rebuilt nonce counter) and
  `test_replay_transfer_into_empty_ledger_fails` (the pre-fix divergence,
  where replaying a transfer into an unseeded ledger breaks on the first
  debit).
- `./scripts/bridge-e2e.sh full`: docker stack up, bridge-node
  readiness (incl. the new signed `council-add` / key rotation), and
  **the Solana `seal-bridge` program (carrying the §2.3-A/B fixes)
  built and deployed cleanly** (program id `4AuiQV9F…`). The run then
  failed at the **Stellar** soroban build: `ethnum 1.5.2` does not
  compile under the installed `rustc 1.97.1` (`mem::transmute(())`
  ZST-size mismatch at `ethnum/src/error.rs:16`). This is a
  **pre-existing toolchain incompatibility in the separate Stellar
  workspace** — the ethnum pin predates this work and no commit here
  touched `bridges/stellar/Cargo.lock` — not a regression from the
  security fixes. The Solana side is independently validated by this
  run's clean build+deploy and by the 2026-10-04 fork-validator
  fresh-ledger e2e (lock → 3-of-3 unlock → nonce-replay rejection →
  quorum).
- **Wallets:** `node --check` on all three JS files; VM smoke tests
  drive the extension's `onMessage` listener, the content-script relay,
  and `renderRequests` — page `seal:popup:resolveRequest`/`listRequests`
  are ignored, a foreign extension id is ignored, the own popup reaches
  the handler, non-hex `message_hex` is rejected, and the render path
  writes **0** `innerHTML` with the attacker origin preserved verbatim
  as a text node. Android `FLAG_SECURE` verified by inspection (the
  screencap check requires a device).

### 6.4 cursor-agent review gate (2026-10-05)

`cursor-agent` reviewed the full diff of this pass as the final gate and
returned **BLOCKERS** with 7 findings (F1–F7). Each was validated against
the primary source before folding. Result: 6 real and fixed, 1 false
positive (verified, no change). (F3 was first documented as architectural;
it was then formally validated — Lean4 + TLA+ — and fixed in `a66b58da8`.)

- **F1 — CRITICAL, fixed.** A forger could mint a block debiting any funded
  account: `verify_and_apply_block` verified `proposer_signature` against
  `header.proposer` — a key the proposer *names in the header*. A forger
  names their own key, signs, leaves the VRF fields empty (which skips the
  election check), and gossips the block; every node applied it. Fix: an
  enrolled node now rejects any block whose proposer is not in its
  `validator_set` (the membership check in `verify_and_apply_block`). Gated
  on a new `ConsensusRunner.enrolled` flag: a node booted with an explicit
  set (`with_validator_set`) enforces it; a node booted isolated
  (`new`/`new_with_keypair` — the only path `main.rs` uses today, a
  single-validator self-set with no peers) keeps the legacy self-attested
  check so standalone dev does not regress. Full forger-resistance requires
  **every** peer enrolled in the same set — i.e. validator-set bootstrap,
  which is not yet built (the set is fixed at boot, never synced at
  runtime) — deferred (§6.6). Regression: `test_verify_rejects_unknown_proposer`.
- **F2 — CRITICAL, fixed.** A restart with a native-transfer chain diverged
  and then overwrote history. The genesis mint was a *local*
  `balances.mint` run **after** replay, so replay ran into an empty ledger,
  the first transfer debit failed, replay broke partway, the node resumed at
  a truncated height, and the next produced block overwrote the historical
  block at `chain.len()+1` (`DiskStore::put_block` has no exists-check).
  Fix: seed the genesis pool **before** replay so transfer debits find their
  funded source and the full chain reconstructs; `replay_block`'s `Transfer`
  arm also rebuilds the per-sender nonce counter (keyed by `tx.sender`, as
  `accept_transaction`/`submit_money_tx` key it) so a restart continues from
  the last on-chain nonce instead of re-issuing 0. Genesis is never a block
  tx, so seeding once before replay is idempotent (no double-mint).
  Regressions: `test_restart_transfer_chain_replays_without_divergence`
  (balances + conserved `total_supply` + state root + rebuilt nonce all
  match) and `test_replay_transfer_into_empty_ledger_fails` (the pre-fix
  divergence).
- **F3 — HIGH, real but architectural — now fixed (formally validated first,
  then implemented).** In a multi-node set a *gossiped* money transfer (and,
  as the fix made clear, the systemic class of it: SQL writes, fee burn,
  storage burn, and the epoch emission) forks the proposer from its
  replayers. The balance/SQL effect was applied **live** to the *submitting*
  node's store (in `handle_transfer` / `submit_sql`), but on every other node
  `accept_transaction` only *enqueues* the tx — so the effect is applied only
  during block **replay**. A node that proposes a block containing another
  node's gossiped tx therefore computes the header `state_root` from a store
  that has *not* applied those txs, while every replayer applies them on
  replay: the header state root diverges from the replayed state root and the
  proposer forks. Masked in single-node dev (proposer == submitter, so its
  store already reflects the txs).
  **Fix (formal-first):** the Lean4 algebraic model
  (`formal/lean/SealVerify/Basic/StateRoot.lean`, `50ba2f72b`) and the TLA+
  interleaving spec (`formal/tlaplus/SealStateRoot.tla`, re-validated for the
  full composite transition in `647c97f10`) lock the invariant that the state
  root is a pure function of (committed pre-state, block). Then `a66b58da8`
  routes **both** the producer (`produce_block_with_vrf`) and the replayer
  (`replay_block`) through one shared `apply_block_transition` applied to the
  committed pre-state, and removes the live application: `submit_sql` and
  `handle_transfer` now write to a read-your-writes working set and enqueue
  (never the committed store), and the epoch emission mint moves out of
  `advance_slot` into the transition. Every node that finalizes a block
  computes the same root, so the fork is gone. **Cross-node native money (and
  SQL/fee/storage/emission) consensus is now sound for the on-block state
  root; token/bridge/stake movement still lives in `RpcState` and remains a
  documented runner-level no-op (§6.2).** A second-pass `cursor-agent` review of
  this transition then found five further consensus bugs (atomicity,
  verify-before-commit, lease units, Merkle rebuild order, double-apply) — all
  fixed, §6.7 — plus four deterministic economic/edge items deferred to §6.2. A
  third-pass review of those fixes then found two more consensus defects in the
  fix's seams (a failed transition destroyed the producer's mempool; the
  restart/disk-replay path committed blocks without checking their root) — both
  fixed, §6.8 — plus one deterministic correctness item deferred to §6.2
  (M1; the other third-pass candidate M2 was re-verified as a false positive,
  §6.8).
- **F4 — HIGH, fixed.** `advance_slot` could double-advance the epoch: a
  lagging node that accepted a peer's N−1→N transition and then crossed its
  own boundary advanced a second time (to N+1), diverging the leader-election
  seed. The epoch is a pure function of the absolute slot
  (`slot / slots_per_epoch`), so it is now advanced only when
  `current_epoch.number < target_epoch` (idempotency guard); the VRF rotation
  and emission still run regardless.
- **F5 — HIGH, fixed.** `DoubleProposal` slashing accepted a forged report:
  two *identical* headers, or a header whose `block_hash` did not match its
  bytes, still slashed a validator. `report_offense` now rejects identical
  header pairs and verifies `sha3_256(header) == block_hash` for both.
  Regression:
  `test_double_proposal_identical_header_different_hashes_rejected`.
- **F6 — MEDIUM, false positive (verified, no change).** The finding claimed
  an anonymous caller could cancel any order. `seal_cancelOrder` (and
  `seal_placeOrder`) **are** in `requires_auth` (rpc.rs), so the call is
  auth-gated. No change.
- **F7 — LOW, fixed.** The per-sender nonce counter advanced with a plain
  increment that could wrap at `u64::MAX`. Now `checked_add` → error on
  overflow, in `accept_transaction`, `submit_money_tx`,
  `accept_epoch_transition`, and the replay rebuild.

### 6.5 Solana fork token-program recipe (needed to drive the Solana e2e on the local fork)

The local Seal Solana test validator is a **custom 3.1.15 fork**
(SOLBIN under `~/.local/share/solana/install/releases/stable-40a31af…/solana-release/bin`;
throwaway ledger, RPC `127.0.0.1:8899`). Its token program
`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` is **not** standard
spl-token. Proven recipe (on-chain verified 2026-10-04):

- **Enum = pre-2022 SPL Token, 24 variants (0-23), nonstandard**:
  0=InitializeMint, 1=InitializeAccount, 2=InitializeMultisig,
  3=Transfer, 4=Approve, 5=Revoke, 6=SetAuthority, 7=MintTo, 8=Burn,
  9=CloseAccount, 10=Freeze, 11=Thaw, 12=TransferChecked, 13=ApproveChecked,
  14=MintToChecked, 15=BurnChecked, 16=InitializeAccount2, 17=SyncNative,
  18=InitializeAccount3, 19=InitializeMint2, 20=GetAccountDataSize,
  21=InitializeImmutableOwner, 22=AmountToUiAmount, 23=UiAmountToAmount.
  (Derived from the ELF string pool, reversed; anchored by observed
  instruction tags.)
- **InitializeMint**: data=`[0][dec u8][authority 32][0][0]`,
  accts=`[mint(W), RENT(RO)]`. **InitializeAccount**: data=`[1]`,
  accts=`[acct(W), mint, owner, RENT(RO)]`. **MintTo**: tag **7**,
  data=`[7]+amount u64LE`, accts=`[mint(W), dest(W), authority(S)]`.
- **Fork-renamed sysvars**: rent =
  `SysvarRent111111111111111111111111111111111` (L=6960, threshold 2.0).
- **Fork Mint = exactly 82 B, nonstandard (4-byte u32 `Option` tags)**:
  `[0:4]` authority tag u32LE, `[4:36]` authority pk, `[36:44]` supply
  u64LE, `[44]` decimals u8, `[45]` is_init u8, `[46:82]` freeze
  (u32 tag + 32 B).
- **Fork TokenAccount = exactly 165 B, nonstandard (4-byte u32 `Option`
  tags)**: `[0:32]` mint pk, `[32:64]` owner, `[64:72]` amount u64LE,
  `[72:76]` delegate tag u32, `[76:108]` delegate pk, **`[108]` state
  u8** (not the standard `[105]`), `[109:121]` is_native (u32 tag +
  u64), `[121:129]` delegated_amount.
- **Fork rent funding**: `max(sysvar_min, std_min) * 2.2` → 82 B ≈ 3.2M
  lamports, 165 B ≈ 4.5M lamports.

**Runtime quirks:** top-level system-program instructions are REJECTED
(the system program works only via BPF CPI `invoke_signed` for PDA new
accounts); top-level token instructions work; `anchor_spl`
`token::transfer` CPI works (the feared discriminator mismatch did not
materialize). **The RPC serves stale account data for a window after a
write — poll until state reflects the expected change, never trust a
single read** (the seal-bridge unlock state took ~10 reads × 1.5 s to
go fresh). `tx_err()` returning `(None, [])` for both success and null
status yields false positives — use `wait_status()`.

### 6.6 Still-open items that predate or sit beside this pass

- **`seal-key.json` (repo root) is a compromised BIP-39 wallet** — now
  gitignored (commit `1ebd80f7a`) but **must be rotated by its owner**;
  ignore-only does not un-leak a key that was already committed.
- The leaked GitHub PAT referenced in origin URLs should be rotated
  (operational, outside this repo's fix scope).

### 6.7 cursor-agent second-pass review (on-block transition, 2026-10-06)

`cursor-agent` re-reviewed the F3 transition diff (§6.4-F3, `a66b58da8`) as a
second gate. The core was correct (both sides route through one shared
transition; the live transfer is gone; no new production `unwrap`/`expect`;
money arithmetic is checked/saturating), but it found **five consensus bugs
(now fixed)** and **four economic/edge bugs (deferred, §6.2)** plus one minor
note. Numbering below is local to this review (independent of §6.4's F1–F7);
each was validated against the primary source before folding.

**Consensus (fixed):**

- **F1 — CRITICAL, fixed (`53da85292`).** A failing transition left committed
  state partially mutated with the pool already drained: `produce_block_with_vrf`
  did `mem::take(&mut self.pending_txs)` and then `apply_block_transition`
  propagated SQL/transfer errors with `?`, with no rollback. `accept_transaction`
  checks only signature + nonce (no SQL parse, no solvency), so a peer could
  gossip a signed `DROP TABLE nope` (or any unparseable SQL) or an unfunded
  transfer; the producer applied the earlier txs, aborted on the bad one,
  produced no block, and never updated `state_root` — then stamped a root no
  replayer could reach on every later block. The transition now snapshots
  `sql_engine`/`balances`/`nonces`/`leases` and rolls them back on error
  (`test_f1_failing_transition_rolls_back_committed_state`).
- **F2 — CRITICAL, fixed (`53da85292`).** Rejection was not a rollback:
  `verify_and_apply_block` called `replay_block` (which mutates state and appends
  the block) *before* comparing roots, and the receive path logged the mismatch
  at `debug!`. With no `tx_root` in the header, a peer could forward a
  validly-signed block with injected or removed transactions; the forged effect
  was applied and committed, the mismatch seen only after, and swallowed.
  `apply_block_verified` now snapshots, replays, and commits only on a matching
  root, rolling back otherwise (`test_f2_rejected_block_rolls_back_node_state`).
- **F3 — HIGH, fixed (`53da85292`).** Producer-only lease pruning mutated
  committed SQL *after* the root was stamped (replay had no lease code → fork the
  next block), and the expiry compared a seconds timestamp (+ 4h) against a
  microsecond clock, so a `CREATE TABLE`'s lease was pruned in the same block.
  The grant/prune moved into the shared transition (identical on producer and
  replayer) and `paid_through` is written in microseconds to match
  `StorageLease`'s documented units.
- **F4 — HIGH, fixed (`600f3822e`).** `rebuild_merkle` re-inserted in
  `table_names()` = `schemas.keys()` order (a per-process-seeded `HashMap`); the
  Merkle B-tree root is insertion-order-sensitive once it exceeds one node, so
  the producer and replayers could rebuild the same key set to different roots on
  any CREATE/DROP/delete block. Table names are now sorted before rebuild.
- **F5 — HIGH, fixed (`53da85292`).** `replay_block` never pruned
  `pending_txs`, so a gossiped tx applied in block N was re-included (and
  re-applied, since the transition rebuilds but never checks the nonce) in block
  N+1 — double-debiting a transfer. `apply_block_verified` now prunes the
  finalized block's txs from the pool (`test_f5_applied_tx_pruned_from_pending_pool`).

**Economic / edge (deferred, §6.2 — deterministic, no fork):**

- **F6 — MEDIUM.** Two live committed-balance mutations outside the transition:
  `handle_faucet` `balances.mint` (gated on `--dev-faucet`, default off) and the
  bridge-withdrawal fee `burn`/`mint` (gated on `bridge_withdrawal_fee > 0`,
  default 0). A node configured with either forks its balance root the first time
  it fires. Same class as the live transfer the §6.4-F3 fix removed.
- **F7 — MEDIUM.** One unfunded sender voids fee collection for the whole block:
  `process_block_fees` does `balances.burn(sender, fee)?` in the loop and credits
  the proposer only after it, and the caller discards the `Result`. Deterministic
  (no fork) but a griefing/revenue bug — a gossiped tx from an unfunded address
  lets the block's funded senders ride free and the proposer earns nothing.
- **F8 — MEDIUM.** Emission mints 2× the scheduled rate: `epoch_reward =
  reward_per_block * config.slots_per_epoch` (256) while
  `EmissionSchedule::block_reward` normalizes by `BLOCKS_PER_EPOCH` (128).
  Deterministic (both sides derive the epoch from height, so no fork) but wrong
  economics; it also fires on the first block of the epoch and reads node-local
  config rather than block data.
- **F9 — LOW.** `accept_transaction` bumps the per-sender nonce counter for every
  tx type, but `apply_block_transition` advances it only for `Transfer` and local
  `submit_transaction` does not bump it at all — desyncing the sender's money
  nonce across nodes so a transfer can be rejected network-wide. Not
  state-root relevant.
- **Minor.** In `produce_block_with_vrf` the ZK transition's `tx_hash` is computed
  before the `DexMatch` tx is appended but `tx_count` after, so the public inputs
  are internally inconsistent. Not state-root relevant.

### 6.8 cursor-agent third-pass review (restart path + mempool, 2026-10-07)

`cursor-agent` re-reviewed the §6.7 fixes (`53da85292`/`600f3822e`) as a
follow-up gate, per the request to cross-check again after the fix. All five
§6.7 fixes were confirmed correct and complete against the primary source
(producer/replayer root equality, snapshot completeness, the lease units, the
absence of new production `unwrap`/`expect`, and checked/saturating money
arithmetic), but the review found **two more consensus defects in the fix's own
seams (now fixed, `8433401ac`)** and **one deterministic correctness item
(deferred, §6.2 M1) plus one re-verified false positive (M2)**. Numbering below
(B1/B2, M1/M2) is local to this pass; each was validated against the primary
source before folding.

**Consensus (fixed, `8433401ac`):**

- **B1 — CRITICAL (liveness / censorship), fixed.** A *failed* on-block
  transition silently destroyed the producer's **entire pending pool**.
  `produce_block_with_vrf` drained the pool into a local via
  `std::mem::take(&mut self.pending_txs)` and the old F1 rollback restored
  `sql_engine`/`balances`/`nonces`/`leases` but not the drained `txs` local —
  it was simply dropped on the `?` error path. Because the pre-fix
  `accept_transaction` ran the received SQL write on `preview_engine` and
  discarded the result (`let _ =`), a correctly-signed malformed write (e.g.
  `INSERT INTO nonexistent (id) VALUES (1)`) passed the signature/nonce checks,
  was accepted **and gossiped by every node**, and each node that was then
  elected proposer drained that tx, failed its transition, produced no block
  for the slot, and lost every other pending transaction with it. Confirmed
  empirically by the reviewer: one good write + one aborting write over 50
  slots → `blocks_produced=49`, `pending_after=0`, the good write never
  reached the chain, and no error surfaced to its submitter. Sustained gossip
  of such txs is network-wide censorship at zero cost. Not a state-root fork
  (committed state stayed consistent), but a remote DoS. Two-part fix:
  (a) `accept_transaction` now **rejects** a SQL write that fails its preview
  (the same outcome the transition would reach, so it cannot desync committed
  state) — a malformed write is no longer accepted or gossiped; and
  (b) the transition error now carries the offending tx's index
  (`TransitionError { failed_tx: Option<usize> }`), so the producer
  **re-queues the non-offending survivors** and drops only the poison tx, which
  fails deterministically on every node and would otherwise stall production by
  re-failing in every future slot.
  `test_f1_second_pass_pool_preserved_on_failed_transition`.
- **B2 — HIGH (self-fork), fixed.** F2's verify-before-commit was **not wired
  into the restart/disk-replay path**. `replay_block` commits unconditionally —
  it runs the transition, recomputes `state_root`, and appends to `chain`
  without ever comparing against `block.header.state_root`; only
  `apply_block_verified` (the network path) does the comparison. Two production
  callers bypassed it: `main.rs` (the restart replay loop) and `persistent.rs`
  (`PersistentNode::open`). That matters because when the restart replay breaks
  partway, `main.rs` then installed `balances.bin` into `runner.balances` even
  when `file.height != node.height()` (a warning, then continue) — leaving the
  node with `sql_engine` at the truncated replay height and `balances` at the
  snapshot's height. The next block it produced stamped
  `sha3(sql_root ‖ balance_root)` mixing two different heights, a root no peer
  can reproduce and every replayer's `apply_block_verified` rejects, with no
  way for the node to notice (the replay it just ran never checked a single
  root). Fix: both restart callers now go through the **root-checked**
  `apply_block_verified` (snapshot → replay → commit only on a matching root →
  else rollback), so a corrupted or adversarially-edited stored block stops the
  replay at the last consistent height instead of being committed; and a
  height-mismatched `balances.bin` snapshot is **refused** (the self-consistent
  partial-replay state is kept) rather than installed. `replay_block` is
  documented as the low-level unchecked primitive so a future production caller
  does not reintroduce the bug.
  `test_f2_second_pass_restart_replay_stops_on_corrupt_block`.

**Correctness / economic (deferred, §6.2 — deterministic, no fork):**

- **M1 — MEDIUM.** `prune_applied_txs` over-prunes *distinct* transactions: the
  match is on `(tx_type, sender, payload)` with no nonce, signature, or block
  position, so byte-identical transactions collapse. Submitting
  `UPDATE counters SET n = n + 1 WHERE id = 1` twice is two legitimate txs with
  identical bytes; a block containing one copy removes both from the pool and
  the second is permanently lost. Every node prunes identically, so this is
  silent transaction loss, not a fork. Transfers are immune (their payload
  carries the nonce). Fix: key the prune on the tx's position in the block or on
  its signature/hash.
- **M2 — MEDIUM, false positive (verified, no change).** The finding claimed a
  lease-expiry `DROP` routes through a *stale* `last_write_log` left by the
  previous statement, landing on `update_table_in_merkle(stale_table)` instead
  of `rebuild_merkle()` and leaving the dropped rows in the root. It does not:
  `Engine::execute` resets `self.last_write_log = None` at the top of **every**
  call (`engine.rs:101`) before dispatching, and `execute_drop` never sets it —
  so a `DROP` yields `last_write_log == None`, `extract_affected_table` returns
  `None` for a DROP, and `MerkleEngine::execute` takes the full
  `rebuild_merkle()` branch against the post-drop table set. The dropped table's
  rows are removed from the Merkle commitment. Regression guard:
  `test_drop_table_is_removed_from_merkle_root` (a `DROP` of the only table
  returns the root to the empty-state root). The lease-expiry prune in the
  transition calls the same `drop_table` → `execute("DROP TABLE …")` path.

The `cursor-agent` second/third-pass findings are tracked to completion here;
no further consensus blocker remains in the on-block transition or the
restart/replay path as of `8433401ac`.
