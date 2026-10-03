# Bridge Testnet Readiness — TODO (2026-05)

Tracks everything needed to make both bridge chains (Solana + Stellar)
fully testnet-ready — local e2e green, public-testnet deploy working,
CLI tooling, USDC support, and complete docs.

---

## Status snapshot (2026-05-16, end-of-day)

**TL;DR — every code-side blocker is closed.** What remains is
pure-operator execution (run the deploy scripts against the live
chains, fund the keys, run the multi-validator smoke). See
[`docs/RUNBOOK-TESTNET-OPERATOR.md`](../RUNBOOK-TESTNET-OPERATOR.md)
for the step-by-step.

Confirmed-closed since the 2026-05-14 snapshot:
- **P1#5 layer 4 seal-node integration** — Arc threading, signing
  channel, envelope routing, prune timer, CLI flags, status RPC,
  CLI helper (commits `a86b14f3b` → `1a3c948f5`, `1ee5d898e`,
  `73b4d52dd`, `71f521eaf`).
- **P1#5 layer 6 multi-validator smoke** —
  `scripts/bridge-test-ringtail-multi.sh` (commit `d19a22f33`).
- **In-flight signing-session persistence** — survives restart
  (commit `362379804`).
- **P8 mainnet gates** (un-deferred 2026-05-16):
  - §4.1 per-method rate limits (`f2722d399`)
  - §4.2 withdrawal fee (`1c665f0e4` + RPC `7c0445e37` + explorer
    `182536232`)
  - §4.3 admin M-of-N multisig (`86546542c` + `seal-cli admin-{sign,
    submit,list}` `fdca53fe9`/`01d999ecf`/`5af8a88f3`)
  - §4.4 KMS key-source adapter (`aada6d5f2`)
  - SPEC §5.5 (`53dc7d395`), monitoring alerts (`6b8c29dd6`),
    `/status` + `/metrics` surface (`b91e84056`)
- **Operator bring-up automation** — `scripts/bridge-deploy-devnet.sh`,
  `scripts/bridge-redeploy-ringtail.sh`, `scripts/bridge-fund-relayer.sh`
  (commit `a928ba91e` + earlier).

## Original status matrix (2026-05-16, pre-EOD)

| Dimension | Solana | Stellar |
|---|---|---|
| Local e2e lock → observer sees deposit | ✅ `{observed:1,new:1}` | ✅ topics/startLedger fix shipped in `8faaeb585`; reverse round-trip validated end-to-end on-chain |
| Public devnet/testnet deploy | ❌ not deployed (operator-side) | ❌ not deployed (operator-side) |
| Unlock (burn → committee sig → on-chain claim) | ✅ pieces shipped — wait on Anchor v2 redeploy for live devnet round-trip | ✅ validated end-to-end via `scripts/bridge-e2e.sh reverse` |
| Auto-submission relayer (P1#3) | ✅ `seal-relayer` shipped 2026-05-16; per-validator custody; shells out to `anchor run unlock-tokens` | ✅ `seal-relayer` shipped 2026-05-16; shells out to `stellar contract invoke … unlock_xlm` / `unlock_usdc` |
| USDC support | ✅ via mint-generic `lock_tokens` + observer routing on `LockEvent.mint` | ✅ `set_usdc_sac` + `lock_usdc` + `unlock_usdc` shipped 2026-05-15 |
| Committee-key rotation | ✅ `seal_bridgeRotateCommitteeKey` (council-gated) + atomic on-disk persistence — no restart needed |  |
| Observability (`/metrics`, alerts, Grafana) | ✅ 9 bridge gauges + 6 Prometheus alerts + Grafana bridge row |  |
| Containers (5-validator + bridge stacks) | ✅ rebuilt 2026-05-16 via `scripts/rebuild-containers.sh`; healthcheck fixed (`seal health` exit codes); `.dockerignore` trim |  |
| CLI tooling (`sol-bridge`, `xlm-bridge` TS) | ❌ not created — competes with `seal-cli` (P2 deferred) | ❌ not created — same |
| Anchor scripts (`anchor run lock-sol` / `unlock-tokens` / `derive-vault-ata`) | ✅ all three exist under `bridges/solana/scripts/` | N/A |
| Faucet wrappers (sol/xlm/usdc-sol/usdc-xlm) | ✅ `scripts/bridge-faucet.sh` shipped 2026-05-16 + `scripts/spl-usdc-bootstrap.sh` for local USDC mint |  |

---

## P0 — Unblock local e2e NOW

- [x] **Rebuild containers** after `topics`/`startLedger` fix — closed 2026-05-16.
  `scripts/rebuild-containers.sh` wraps both stacks (main 5-validator monitoring
  stack at repo root + bridge-e2e stack under `bridges/`) with sensible flags
  (`--no-cache`, `--wipe`, `--logs`). The fix also exposed two stale-healthcheck
  bugs which were repaired in the same round:
    1. The old `test -f /tmp/seal-healthy` probe never passed — nothing in
       seal-node writes that file. Replaced with `seal health` exit-code
       semantics + a 30 s `start_period` grace.
    2. Validators 2–5 didn't expose internal JSON-RPC at all, so any RPC-based
       healthcheck would fail on them. Added `--rpc-port 8545` (without
       `--rpc-external`) so the in-container probe can reach the binary
       without changing the external port surface (still only node1 publishes
       :8545 to the host).
  All 6 containers (5 validators + registration portal) go Healthy on a fresh
  `docker compose up -d --force-recreate --wait`. Bloat fix to `.dockerignore`
  in the same round (testnet-data/, seal-data/, fuzz/target/,
  apps/seal-wallet-android/android/ now excluded — was ~6 GB of unnecessary
  context per service).

- [x] **Verify `startLedger` retry error format** — closed 2026-05-16 alongside
  the observer fallback work (see P7#1/P7#2). String-format + getLatestLedger
  ultimate fallbacks landed in commits `c5475e0b6` / `114cc86c0` and the
  retry path is exercised by the new observer fallback tests
  (`StellarObserver::poll_events` in `crates/seal-bridge/src/observer.rs`).

---

## P1 — Unlock flow (committee key → signature → on-chain claim)

Both chains have `unlock_tokens`/`unlock_xlm` on-chain, but the Seal-side
wiring is missing.

- [x] **Committee key propagation** — closed 2026-05-15.
  `seal_bridgeRotateCommitteeKey` (council-gated, 2/3 supermajority)
  rotates the host-side key without restart;
  `seal_bridgeGetCommitteeKeyStatus` exposes SHA-3 + SHA-256
  fingerprints so dashboards can diff against on-chain
  `committee_key_hash`. Rotation persists atomically to
  `<data_dir>/bridge-committee-key.hex` so reboots don't revert it.
  Manual `rotate_committee_key` invocation on each chain remains
  the operator's responsibility (one `stellar contract invoke` +
  one `anchor run rotate-committee-key`); auto-submission tracked
  below.

- [x] **`seal_bridgeWithdraw` → burn + queue** — closed in prior
  bridge batch. `BridgeManager::initiate_withdrawal` burns wrapped
  tokens, assigns the monotonic nonce, inserts the pending
  withdrawal, and (when committee_key is set) attaches the
  HMAC-SHA-256 MAC inline. See `compute_committee_mac` in
  `crates/seal-bridge/src/bridge.rs`. Auth-gated RPC requires a
  signed caller so the burn is bound to a real Seal address.

- [x] **Auto-submission of unlock tx** (P1#3) — **closed 2026-05-16**.
  Custody model: per-validator (every Seal validator runs its own relayer
  instance + funded destination-chain keys). Landed across 5 commits:
    - `seal-bridge: execute_withdrawal idempotent` (4f7053e96) — multiple
      relayers may race; only the first decrements total_locked.
    - `seal-node: seal_bridgeMarkExecuted RPC + matching seal-cli command`
      (d02ff2213) — validator-auth-gated, additional active-validator-set
      membership check; returns `was_already_executed` so the relayer
      log shows whether it raced.
    - `seal-relayer: scaffold the per-validator bridge unlock relayer`
      (9de11f832) — main loop, SHA3-256(vk || id) % N deterministic
      back-off, durable cursor with atomic tmp+rename.
    - `seal-relayer: Stellar chain submission via stellar-cli shell-out`
      (90d3b1a72).
    - `seal-relayer: Solana chain submission via anchor + spl-token
      shell-out` (063b86eea) — JIT recipient-ATA derivation via
      `spl-token address`, per-token (mint, vault) opt-in config.
  Open follow-ups (defer to operator-docs round):
    - Add a "fund the relayer key on each destination chain" step to
      TESTNET.md / GUIDE-OPERATOR.md. For testnet: `bridge-faucet.sh sol
      <relayer-pubkey>` + `bridge-faucet.sh xlm <G-addr>`.
    - End-to-end run of `bridge-e2e.sh reverse` with the relayer
      auto-submitting (currently the e2e script hand-rolls the
      submission step).
    - systemd unit shape so operators run the relayer as a service.
  Mainnet-only (deferred):
    - Fee reimbursement out of bridge fees or treasury for the gas the
      relayer pays.
    - Slashing on misbehavior (no-relay, double-submission spam).

- [x] **Add unlock e2e in `scripts/bridge-e2e.sh`** — closed in
  prior reverse-leg batch. `./scripts/bridge-e2e.sh reverse`
  runs the Stellar burn → committee MAC → `unlock_xlm` round-trip
  end-to-end against the local stellar/quickstart stack. The
  `reverse-solana` mode mirrors the path against an Anchor program
  with the v2 LockEvent layout (op-supplied env vars). The
  `verify_committee_key_fingerprint` smoke check added 2026-05-15
  asserts host-side key alignment in the first 5 seconds.

- [x] **Ringtail threshold signatures** (P1#5, un-deferred 2026-05-16
  — closed 2026-05-16 EOD; only the on-chain redeploy with
  `ringtail-verify` is operator-side, see
  [`docs/RUNBOOK-TESTNET-OPERATOR.md`](../RUNBOOK-TESTNET-OPERATOR.md)
  §3):
  current committee MAC is HMAC-SHA-256 (committee-of-1 placeholder).
  Replace with the Ringtail aggregate produced by
  `seal-threshold::RingtailThreshold` once the multi-validator P2P
  signing path lands. Layers, ordered by what's already done vs left:
    1. ✅ **On-chain verifier byte-compatibility** — closed pre-2026-05.
       `seal-ringtail-verify` ships `no_std + alloc` and produces
       byte-identical results to `seal-threshold::verify_signature_full`
       (cross-checks in `crates/seal-ringtail-verify/tests/crosscheck.rs`,
       5 passing). Both bridge programs gate it behind the
       `ringtail-verify` feature.
    2. ✅ **Host singleton encoder** — closed 2026-05-16 (commit
       7b1e39636). New `seal_bridge::ringtail` module behind
       `--features ringtail-singleton`: `sign_singleton(params, sk,
       message) -> Vec<u8>` produces the canonical 2088-byte wire form
       (z 2048 || challenge 32 || partcnt LE-u64 8). Cross-check tests
       round-trip through `seal_ringtail_verify::verify`.
    3. ✅ **Bridge wire-up** — closed 2026-05-16 (commits 1caf1742d +
       bf0fe0da2). `BridgeManager::set_committee_ringtail_keypair`
       installs a singleton Ringtail keypair; the priority chain in
       `compute_committee_signature` picks Ringtail over HMAC when
       set. Sign-failure surfaces as `committee_signature_hex = None`
       (no silent HMAC fallback — would mismatch on-chain).
    4. ⏳ **Multi-validator coordination** — host-side complete; only
       the seal-p2p subscription wire-up remains:
         - ✅ aggregate primitive (commit 024bdf85d)
         - ✅ gossipsub topic strings (commit 12f5a71e0): `seal/bridge-
           ringtail-{round1,round2,sigs}/1.0`
         - ✅ wire envelope structs (commit 12f5a71e0):
           BridgeRingtailRound{1,2,Aggregate}Envelope, serde-serializable
         - ✅ per-withdrawal session state machine (commit 8fd54d8ea)
         - ✅ per-validator orchestrator (commit cec594e00):
           start_signing / on_round1_envelope / on_round2_envelope /
           drop_session
         - ✅ session timeout + prune_stale_sessions (commit df24b3c71)
         - ✅ Round1 MAC verification on receive (commit 5d618c13a) —
           rejects malicious or mis-keyed peer commitments before
           aggregation
         - ✅ seal-p2p subscription + outbound channels + 3
           NetworkMessage variants + 3 broadcast helpers
           (commit 2c6fad9d7); seal-node receive arms log + drop
           pending the orchestrator wiring
         - ✅ ADR-002 design doc for the seal-node integration plan
           (commit ae8c0ddea): explicit Arc<Mutex<…>> threading,
           push-based start_signing trigger, 6 CLI flags listed
         - ✅ BridgeManager signing-signal channel (commit c4eddde05):
           push trigger fires on every initiate_withdrawal so the
           orchestrator doesn't poll
         - ✅ RingtailKeypair file I/O + bridge-ringtail-keygen
           example (commits 12e6cac62 + cb85a4ffb): operator
           workflow pinned, JSON schema established
         - ✅ seal-node integration — closed 2026-05-16. Orchestrator
           constructed at boot per ADR-002 (`1ee5d898e`), Arc threaded
           through `RpcState` + network loop (`a86b14f3b`),
           signing-signal channel + tokio task (`807cfdf7d`),
           envelope routing + periodic prune timer (`e43994013`),
           dispatch tests (`1a3c948f5`). CLI: `--bridge-ringtail-*`
           flags (`1ee5d898e`), `seal_bridgeRingtailStatus` RPC
           (`73b4d52dd`), `seal-cli bridge-ringtail-status`
           (`71f521eaf`).
         - ✅ persistence — closed 2026-05-16 (`362379804`).
           Orchestrator writes in-flight sessions to
           `<data_dir>/ringtail-sessions/` and reloads on boot.
    5. ✅ **On-chain redeploy with `ringtail-verify` feature flipped on**
       — operator script `scripts/bridge-redeploy-ringtail.sh` ships;
       running it against live devnet/testnet is the remaining
       pure-operator step. See
       [`docs/RUNBOOK-TESTNET-OPERATOR.md`](../RUNBOOK-TESTNET-OPERATOR.md)
       §3.
    6. ✅ **Tests** — `scripts/bridge-test-ringtail-multi.sh` brings up
       the 3-validator bridge stack with the Ringtail override,
       waits for `orchestrator_active=true` on every node, and
       asserts cross-validator signature convergence (commit
       `d19a22f33`). For larger committees see
       [`docs/TESTNET-VALIDATOR-SIZES.md`](../TESTNET-VALIDATOR-SIZES.md).

---

## P2 — CLI tooling (`bridges/tools/`)

Design modelled after the **license-system** chain tools (`sol-tool`,
`stellar-tool`, `evm-tool`):

```
one binary per chain       → sol-bridge, xlm-bridge  (not a monolithic "bridge" CLI)
flat subcommand dispatch   → process.argv[2] switch — no Commander/yargs/clap
env-var config             → hardcoded devnet/testnet defaults, override via env
keypair: path-or-inline    → loadKeypair(arg): try file first, then parse inline
simple printf output       → "sig:  <hash>\namount: 0.1 SOL" — no chalk, no tables
stderr for progress/labels → tx hashes / machine-readable data to stdout
fatal(msg) helper          → print "error: <msg>" to stderr, exit 1
polling with seen-set      → Map<txHash, true>, sleep 5 s between iterations
no amount floats           → parseDecimalToLamports / parseDecimalToStroops helpers
```

### 2.1 `bridges/tools/sol-bridge.ts` — Solana bridge tool

Subcommands:
```
keygen
    Generate new Solana keypair; JSON array to stdout, address to stderr

address <keypair.json>
    Derive and print the base-58 public key

balance <address>
    sol:      <amount>
    lamports: <n>

balance-usdc <address>
    usdc: <amount>  (devnet mint 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU)

faucet [address]
    Airdrop 2 SOL on devnet via $SOL_BRIDGE_RPC; address defaults to $SOL_BRIDGE_KEYPAIR

faucet-usdc [address]
    Print Circle sandbox link + steps; call API directly if $CIRCLE_API_KEY is set

lock <keypair.json> <amount_sol> <seal_hex>
    Build + sign + send lock_tokens ix
    sig:     <tx-sig>
    amount:  <n> lamports
    program: <program-id>
    seal:    <seal_hex>

lock-usdc <keypair.json> <amount_usdc> <seal_hex>
    (depends on P3)

unlock <keypair.json> <withdrawal_id>
    Fetch withdrawal from SEAL_RPC, poll until committee_signed:true, send unlock_tokens
    sig:  <tx-sig>

status
    Query SEAL_RPC: seal_listBridgeObservers, seal_pollBridges, seal_listBridgePauseState
    Print key-value summary

watch [address]
    Poll getSignaturesForAddress every 5 s; dedup with seen-set; print new lock events
```

Env vars (with defaults):
```
SOL_BRIDGE_RPC        https://api.devnet.solana.com
SOL_BRIDGE_PROGRAM    (read from bridges/.solana-devnet-program-id if present)
SOL_BRIDGE_KEYPAIR    ~/.config/solana/id.json
SEAL_RPC              http://localhost:8545
```

Keypair loading (path-or-inline, mirrors license-system sol-tool pattern):
```typescript
function loadKeypair(arg: string): Uint8Array {
  const raw = existsSync(arg) ? readFileSync(arg, 'utf8') : arg;
  return Uint8Array.from(JSON.parse(raw));  // Solana 64-byte JSON array
}
```

### 2.2 `bridges/tools/xlm-bridge.ts` — Stellar bridge tool

Subcommands:
```
keygen
    Generate Stellar keypair; G-address to stdout, S-secret to stderr

address <S-secret>
    Derive and print G-address

balance <G-address>
    xlm:     <amount>
    stroops: <n>

balance-usdc <G-address>
    usdc: <amount>

faucet [G-address]
    GET https://friendbot.stellar.org/?addr=<addr>
    funded: <addr>
    xlm:    10000

faucet-usdc [G-address]
    GET https://friendbot.stellar.org/?addr=<addr>&asset=USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5
    funded: <addr>
    usdc:   10000

lock <S-secret> <amount_xlm> <seal_hex>
    Build + sign + submit lock_xlm tx
    tx:      <hash>
    amount:  <n> stroops
    contract: <contract-id>
    seal:    <seal_hex>

lock-usdc <S-secret> <amount_usdc> <seal_hex>
    (depends on P3)

unlock <S-secret> <withdrawal_id>
    Fetch withdrawal from SEAL_RPC, poll until committee_signed:true, send unlock_xlm
    tx: <hash>

status
    Same as sol-bridge status (queries SEAL_RPC)

watch [G-address]
    Poll Soroban RPC getEvents every 5 s; dedup; print new lock events
```

Env vars (with defaults):
```
XLM_SOROBAN_RPC       https://soroban-testnet.stellar.org
XLM_HORIZON_URL       https://horizon-testnet.stellar.org
XLM_BRIDGE_CONTRACT   (read from bridges/.stellar-testnet-contract-id if present)
XLM_BRIDGE_SECRET     (no default — required for write operations)
SEAL_RPC              http://localhost:8545
```

### 2.3 Package setup

- [ ] Create `bridges/tools/package.json`:
  ```json
  {
    "name": "bridge-tools",
    "scripts": {
      "sol-bridge": "tsx sol-bridge.ts",
      "xlm-bridge": "tsx xlm-bridge.ts"
    },
    "dependencies": {
      "@coral-xyz/anchor": "^0.31.0",
      "@solana/web3.js": "^1.98.0",
      "@solana/spl-token": "^0.4.0",
      "@stellar/stellar-sdk": "^13.0.0",
      "tsx": "^4.0.0"
    }
  }
  ```
- [ ] `parseDecimalToLamports(s: string): bigint` — no float arithmetic on money
- [ ] `parseDecimalToStroops(s: string): bigint` — same pattern

### 2.4 Local vs public testnet switching

One tool = one network; env vars override for local:
```bash
# Local stack:
SOL_BRIDGE_RPC=http://localhost:8899 \
SOL_BRIDGE_PROGRAM=$(cat bridges/.solana-localnet-program-id) \
SEAL_RPC=http://localhost:8545 \
  npx tsx bridges/tools/sol-bridge.ts lock keypair.json 0.1 deadbeef...

# Public devnet (defaults apply, no env needed):
npx tsx bridges/tools/sol-bridge.ts lock keypair.json 0.1 deadbeef...
```

---

## P3 — USDC support (on-chain programs)

### 3.1 Soroban contract (`bridges/stellar/src/lib.rs`)

- [x] **Closed 2026-05-15.** `set_usdc_sac(usdc_sac: Address)`
  (admin-gated) + `lock_usdc(sender, amount, seal_address)`
  + `unlock_usdc(recipient, amount, nonce, proof)` shipped.
  USDC SAC address lives in instance storage and is installed via
  `set_usdc_sac` after `initialize` (so existing deployments don't
  need a contract upgrade to start handling USDC). Distinct
  `Symbol("lockusdc")` topic so the observer routes by topic
  rather than asset-field inspection.

### 3.2 Anchor program (`bridges/solana/programs/seal-bridge/src/lib.rs`)

- [x] **Closed by design 2026-05-15.** No separate `lock_usdc` ix
  needed — the existing `lock_tokens` is mint-generic (transfers
  via SPL `Transfer` CPI on whatever mint the vault holds) and
  `LockEvent` carries the SPL mint pubkey. Observers route by
  comparing `LockEvent.mint` against the configured `usdc_mint`
  pubkey. Operators init a per-mint vault ATA via
  `anchor run derive-vault-ata -- --mint <usdc-mint> --init`.
  No `BridgeState.usdc_vault` field needed — the vault account is
  passed in by the caller of `lock_tokens`.

### 3.3 Observer (`crates/seal-bridge/src/observer.rs`)

- [x] **Solana** — closed 2026-05-15. `SolanaObserver` routes locks
  to `WrappedToken::WUSDC` when `LockEvent.mint` matches the
  observer's configured `usdc_mint`. v2 `LockEvent` schema (with
  `mint: Pubkey`) is required; v1 events fall back to WSOL.
- [x] **Stellar** — closed 2026-05-15. `StellarObserver` detects
  the `lockusdc` topic and returns `WrappedToken::WUSDC` deposits;
  XLM uses the existing `lock_xlm` topic.

---

## P4 — Public testnet deployment

### 4.1 / 4.2 / 4.3 — all three subsections superseded by `scripts/bridge-deploy-devnet.sh`

- [x] **All twelve manual sub-steps below are replaced by one
  command.** `scripts/bridge-deploy-devnet.sh` does the Solana
  Anchor build + deploy, the Stellar Soroban build + deploy, the
  `initialize` call, the `seal_addBridgeObserver` registration for
  both chains, and writes the captured IDs to
  `bridges/.deploy-devnet.env`. See
  [`docs/RUNBOOK-TESTNET-OPERATOR.md`](../RUNBOOK-TESTNET-OPERATOR.md) §1.

  Operator commands (in order):

  ```bash
  ./scripts/bridge-faucet.sh sol $(solana address -k $HOME/.config/solana/id.json)
  ./scripts/bridge-faucet.sh xlm <G-addr>
  ./scripts/bridge-deploy-devnet.sh \
      --solana-keypair $HOME/.config/solana/id.json \
      --stellar-account <G-addr> \
      --seal-rpc http://127.0.0.1:8545
  ```

  Historical sub-step list (kept for reference — these are no
  longer manual TODOs):
    - Solana keygen + airdrop + anchor build/deploy + initialize +
      record-id
    - Stellar keygen + fund + contract build/deploy + XLM SAC +
      initialize + record-id
    - `seal_addBridgeObserver` for Solana + Stellar
    - Sanity-check with `seal_listBridgeObservers`

---

## P5 — Anchor scripts (closed)

- [x] `bridges/solana/scripts/lock-sol.ts` — exists and is the
  parametric devnet driver (`anchor run lock-sol`). Same script
  handles WUSDC by passing the canonical USDC mint via `--mint`
  since the on-chain `lock_tokens` ix is mint-generic.
- [x] `bridges/solana/scripts/unlock-tokens.ts` — exists and drives
  the reverse claim against either WSOL or WUSDC (mint-generic);
  invoked by `bridge-testnet-demo.sh reverse-sol` and by
  `seal-relayer` (chains module).
- [x] `bridges/solana/scripts/derive-vault-ata.ts` — exists; prints
  the bridge-state-PDA-owned vault ATA for a given mint, with
  `--init` to create the account if missing. Used by
  `scripts/spl-usdc-bootstrap.sh`.
- [x] All three are wired in `bridges/solana/Anchor.toml [scripts]`
  so `anchor run lock-sol` / `unlock-tokens` / `derive-vault-ata`
  resolve.

---

## P6 — Faucet script and docs (closed)

### 6.1 `scripts/bridge-faucet.sh` — closed 2026-05-16

- [x] One-shot wrapper for the four faucet flows:
  ```bash
  ./scripts/bridge-faucet.sh sol      <pubkey>   [amount_sol]
  ./scripts/bridge-faucet.sh xlm      <G-address>
  ./scripts/bridge-faucet.sh usdc-xlm <G-address>
  ./scripts/bridge-faucet.sh usdc-sol <pubkey>           # prints Circle URL + ATA snippet
  ```
  `SOLANA_DEVNET_RPC` and `STELLAR_FRIENDBOT` env knobs swap public
  endpoints for the local stack URLs.

### 6.2 USDC faucet docs — closed 2026-05-16

- [x] **Stellar USDC** wrapped by `bridge-faucet.sh usdc-xlm` after
  account funding. Documented in
  [`docs/TESTNET-FAUCETS.md`](../TESTNET-FAUCETS.md#usdc-stellar-testnet).
- [x] **Solana devnet USDC** wrapped by `bridge-faucet.sh usdc-sol`
  (interactive Circle pointer + ATA-init snippet — Circle gates
  sandbox USDC behind their dashboard).
- [x] **Local USDC** via `scripts/spl-usdc-bootstrap.sh` — fresh
  6-decimal SPL mint on the local solana-test-validator, persistent
  mint keypair across `docker compose down -v`, prints SOL_MINT /
  SOL_SENDER_ATA / SOL_VAULT_ATA env exports.

---

## P7 — Observer robustness

- [x] **`startLedger` string-format fallback** — closed 2026-05-16.
  `extract_oldest_ledger` now accepts both `error.data` as an
  object (`{"oldestLedger":N}`) AND as a string
  (`"oldestLedger is N"` / `=N` / `: N`), plus the message-regex
  shape. Three Soroban error envelopes covered without taking the
  observer down across an upgrade.

- [x] **`getLatestLedger` ultimate fallback** — closed 2026-05-16.
  `fetch_latest_ledger` calls `getLatestLedger` and retries with
  `max(2, latest - 17280)` when both the first
  `startLedger=2` attempt AND the oldest-ledger-hinted retry fail
  (e.g., a fresh chain where the lower bound jumps between calls
  because of pruning).

- [x] **Configurable poll interval** — closed 2026-05-16.
  `seal_addBridgeObserver` accepts `"poll_interval_secs": N`;
  `BridgeObserverSet::poll_due(now)` skips observers whose interval
  hasn't elapsed since their last poll. Zero = always-due (matches
  the prior unconditional `poll_all`). `seal_listBridgeObservers`
  surfaces the per-chain interval for confirmation.

- [x] **Automatic periodic polling** — closed 2026-05-16.
  `seal-node --bridge-poll-interval-secs <n>` spawns a tokio task
  that runs the same `poll_bridges_once` path the explicit
  `seal_pollBridges` RPC uses. `bridges/docker-compose.testnet.yml`
  ships with a 10 s interval. `MissedTickBehavior::Skip` so a slow
  source-chain RPC can't pile up tick backlog. The explicit RPC
  stays so `bridge-e2e.sh` can still observe at known points.

---

## P8 — Security / production gates (un-deferred 2026-05-16 — closed)

All four host-side gates landed in the 2026-05-16 EOD batch; the
on-chain redeploy that swaps the bridge programs into Ringtail-verify
mode is operator-side and tracked under
[`docs/RUNBOOK-TESTNET-OPERATOR.md`](../RUNBOOK-TESTNET-OPERATOR.md)
§3.

- [x] **§4.1 Transfer rate limits** — `f2722d399`. Per-method-group
  caps via `--bridge-rate-limit-*` flags; tripped requests get
  `429`-style `rate_limited` errors; `/metrics` exposes
  `seal_bridge_rate_limit_tripped_total{group=…}`.
- [x] **§4.2 Bridge fee** — `1c665f0e4`. Basis-point fee deducted
  inside `BridgeManager::initiate_withdrawal`; `seal_getBridgeWithdrawalFee`
  read RPC (`7c0445e37`); `seal-cli bridge-fee` query (`592902019`);
  explorer-web surfaces it in the Bridge section (`182536232`).
- [x] **§4.3 Admin M-of-N multisig** — `86546542c`. Replaces the
  single-signer admin gate with an in-protocol M-of-N envelope;
  `seal-cli admin-{sign,submit,list}` (`fdca53fe9`, `01d999ecf`,
  `5af8a88f3`).
- [x] **§4.4 KMS key-source adapter** — `aada6d5f2`. Bridge committee
  key + Ringtail key can now load from a KMS adapter instead of
  the on-disk hex file; same trait interface, file-source remains
  the testnet default.
- [x] **Monitoring + spec** — 3 new alerts for gate-config drift
  across validators (`6b8c29dd6`), SPEC §5.5.{1..4} (`53dc7d395`),
  `/status` + `/metrics` surface (`b91e84056`).
- [ ] On-chain Ringtail-verify redeploy (`scripts/bridge-redeploy-ringtail.sh`)
  — operator-side; see runbook §3.

---

## P9 — `bridge-testnet-demo.sh` completion (closed 2026-05-16 EOD)

- [x] `./scripts/bridge-testnet-demo.sh sol` — forward lock wired
  (mint-generic via `anchor run lock-sol`). Reverse-sol unlock
  exposed as `reverse-sol`.
- [x] `./scripts/bridge-testnet-demo.sh xlm` — forward lock wired
  via `stellar contract invoke … lock_xlm`. Reverse-xlm via
  `reverse-xlm`.
- [x] `./scripts/bridge-testnet-demo.sh usdc-sol` — closed
  2026-05-16 EOD. Routes through `solana_lock_usdc` which sets the
  mint to the canonical Circle devnet USDC mint
  (`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`) by default;
  override via `SOL_USDC_MINT` for the local-stack mint from
  `scripts/spl-usdc-bootstrap.sh`. Reverse:
  `reverse-usdc-sol` (alias for `reverse-sol SOL_REVERSE_TOKEN=WUSDC`).
- [x] `./scripts/bridge-testnet-demo.sh usdc-xlm` — closed
  2026-05-16 EOD. Calls `lock_usdc` on the Soroban contract
  (requires the operator to have run `set_usdc_sac` once after
  `initialize`). Reverse: `reverse-usdc-xlm`.
- [x] `./scripts/bridge-testnet-demo.sh both` — sol + xlm in
  sequence, closed in earlier batch.
- [x] `./scripts/bridge-testnet-demo.sh usdc-both` — closed
  2026-05-16 EOD. usdc-sol + usdc-xlm in sequence.

See [`docs/BRIDGE-USDC-VENUES.md`](../BRIDGE-USDC-VENUES.md) for
where wrapped USDC the bridge produces is liquid (CEX + DEX +
regional accessibility).

---

## Priority order for testnet readiness

```
P0 (now)     rebuild containers → Stellar local e2e green
P1           unlock wiring → full round-trip works
P2           bridges/tools CLI (sol-bridge, xlm-bridge) → easy operator UX
P4           public devnet/testnet deploy
P5 + P6      Anchor scripts + faucet scripts + USDC docs
P3           USDC program support (new feature)
P7           observer robustness (hardening)
P8 + P9      mainnet gates + demo polish
```

---

## Effective readiness statement (2026-05-16 EOD)

- HMAC committee-of-1 path: production-ready end-to-end (forward +
  reverse + relayer + monitoring + ops docs).
- Multi-validator Ringtail path: code-complete on the host side
  AND on-chain side; the only remaining steps are operator
  execution of `scripts/bridge-deploy-devnet.sh`,
  `scripts/bridge-redeploy-ringtail.sh`,
  `scripts/bridge-fund-relayer.sh`, and
  `scripts/bridge-test-ringtail-multi.sh` against the live VPN
  validator hosts. All four are documented in
  [`docs/RUNBOOK-TESTNET-OPERATOR.md`](../RUNBOOK-TESTNET-OPERATOR.md).
- Validator-count sizing (3 / 5 / 7) and variable bridge-committee
  shapes: see
  [`docs/TESTNET-VALIDATOR-SIZES.md`](../TESTNET-VALIDATOR-SIZES.md).

*Last updated: 2026-05-16*
