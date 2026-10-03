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
