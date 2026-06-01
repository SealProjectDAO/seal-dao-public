# Bridge deployment & local-testnet playbook

Status as of 2026-04-18.

## What "deferred (external infra)" actually means

Calling item #3 in `STATUS.md` "deferred, external infra" was lazy.
Most of the work is code-gap + scripting; only a small slice genuinely
requires third-party infrastructure. This doc enumerates every
blocker and proposes a concrete path for each.

### Blocker inventory

| # | Blocker | Kind | Resolution |
|---|---|---|---|
| B1 | `SolanaObserver::poll_events` returns `Ok((vec![], ""))` | **Code gap** | Implement `getSignaturesForAddress` + `getTransaction` JSON-RPC calls. `crates/seal-bridge/src/observer.rs:99-119`. |
| B2 | `StellarObserver::poll_events` returns `Ok((vec![], ""))` | **Code gap** | Implement Horizon `/accounts/{id}/operations?cursor=…` polling. `crates/seal-bridge/src/observer.rs:188-208`. |
| B3 | Solana Anchor program's `unlock_tokens` has stubbed ML-DSA / Ringtail verification | **Code gap** | Port Ringtail verify to Solana (constrained BPF env: no std, no syscalls for SHA3 → use Solana's `sol_sha256` for chained tagged hashes). `bridges/solana/programs/seal-bridge/src/lib.rs`. |
| B4 | Stellar Soroban contract has stubbed proof verification | **Code gap** | Soroban exposes `Env::crypto().sha256(…)`; Ringtail uses 48-bit prime NTT, fits in Soroban's 128-bit arithmetic. `bridges/stellar/src/lib.rs`. |
| B5 | Stellar real XLM transfers via SAC | **Code gap** | Call the Stellar Asset Contract via `token::Client::transfer(…)`. SAC is built-in (no deploy), just need the right invocation. |
| B6 | Anchor program & Soroban contract must be compiled, deployed, IDs wired | **Scripted infra** | Scripted with `solana-test-validator` / `stellar/quickstart` docker (see "Local testnet" below). |
| B7 | Host-side needs funded dev keypairs to sign test transactions | **Scripted infra** | `solana airdrop 10` on devnet (cap: 2 SOL/req) or unlimited on local validator. Stellar friendbot funds testnet accounts. Local generate + airdrop scripts below. |
| B8 | Continuous-integration env to run end-to-end bridge tests | **Scripted infra** | `docker-compose up` brings Solana + Stellar + a 3-node Seal cluster up together. |
| B9 | Mainnet deploy authority / multisig | **Genuine external** | Requires Seal DAO governance vote, funded mainnet accounts, multisig hardware. **This** is the only real external item, and it belongs in the LAUNCH-CHECKLIST, not in ongoing development. |

**Summary**: 5 code gaps, 3 scriptable infra items, 1 real external. The
"deferred, external infra" label was hiding the fact that nearly all of
this is local work.

## Local testnet (zero external dependencies)

Both chains ship first-class local-network tooling. We can run the full
deposit → Seal mint → burn → unlock round-trip on a laptop with no
internet, no signing keys in the cloud, and no rate limits.

### Solana — `solana-test-validator`

Ships with the Solana CLI. Starts a single-node local cluster with a
pre-funded airdrop faucet in ~3 seconds.

```bash
# One-off setup
sh -c "$(curl -sSfL https://release.solana.com/v1.18.26/install)"
solana config set --url http://localhost:8899
solana-keygen new --outfile ~/.config/solana/id.json --no-bip39-passphrase

# Run each time
solana-test-validator --reset &
solana airdrop 100   # fund our wallet

# Build + deploy the Seal bridge program
cd bridges/solana
anchor build
anchor deploy --provider.cluster localnet

# Run the existing TS integration test
anchor test --skip-local-validator
```

Anchor captures the deployed program ID in `target/idl/seal_bridge.json`;
our `SolanaObserver::new(rpc_url, program_id)` picks that up.

### Stellar — `stellar/quickstart` docker (protocol-22 pinned)

Stellar's official all-in-one container: Horizon + Stellar Core +
friendbot + Postgres, all-in-one.

We pin **two** things to defend against the Stellar protocol drift
that broke `stellar contract install` in Q1 2026 (`:latest` rolled
from protocol 22 → 25 mid-quarter):

1. **Image tag** — a dated nightly (`vNNN-bMMMM.M-nightly`),
   currently `v637-b1047.1-nightly`. The plain `:latest` /
   `:nightly` floating tags are off-limits because the binary
   changes under our feet.
2. **Protocol version** — `--protocol-version 22` on the
   `/start` command line. The pinned image still ships a
   stellar-core that supports protocols up through 25 by
   default; without the explicit flag, `--local` upgrades the
   network to its newest, which mismatches our 22.x WASM ABI
   in `bridges/stellar/Cargo.toml` (`soroban-sdk = "22"`).

```bash
# Run each time (matches what bridges/docker-compose.testnet.yml does)
docker run --rm -d --name stellar -p 8000:8000 -p 8003:8003 \
    stellar/quickstart:v637-b1047.1-nightly --local --protocol-version 22

# Wait for sync (~30s first time), then:
curl localhost:8000/friendbot?addr=<OUR_TESTNET_ACCOUNT>   # free funding

# Build + deploy the Soroban contract
cd bridges/stellar
cargo build --target wasm32-unknown-unknown --release
stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/seal_bridge_stellar.wasm \
    --network local --source <KEYPAIR>
```

Local Horizon listens on `:8000`, matching
`StellarObserver::new("http://localhost:8000", contract_id)`.

**Pin expiry risk:** Stellar nightlies stop building after ~6
months. If a `docker pull` 404s the tag above, bump to a fresher
`vNNN-bMMMM.M-nightly` from
[hub.docker.com/r/stellar/quickstart/tags](https://hub.docker.com/r/stellar/quickstart/tags)
that still serves protocol 22 (Stellar Core supports the previous
N protocols, so the freshest dated nightly almost always still
accepts `--protocol-version 22`). The migration path to drop
the `--protocol-version` pin entirely lives in `TODOS.md` Tier-1
#2 option (b): coordinated bump of `bridges/stellar/Cargo.toml`
to `soroban-sdk = "25"`.

### One-shot docker-compose for the full stack

File: **`bridges/docker-compose.testnet.yml`** (landed 2026-04-19).
Runs Solana + Stellar + 3 Seal nodes on a shared Docker network.
Driver script: **`scripts/bridge-e2e.sh`** — handles preflight,
deploy, and the lock→mint→burn→unlock round-trip.

Quick use:

```bash
./scripts/bridge-e2e.sh check    # preflight only (no network)
./scripts/bridge-e2e.sh up       # bring stack up
./scripts/bridge-e2e.sh          # full round-trip (default)
./scripts/bridge-e2e.sh down     # tear down + wipe volumes
```

Compose skeleton (condensed; see the file for the full version):

```yaml
services:
  solana:
    image: solanalabs/solana:v1.18.26
    command: solana-test-validator --reset --rpc-port 8899
    ports: ["8899:8899", "8900:8900"]
    healthcheck:
      test: ["CMD", "solana", "cluster-version", "--url", "http://localhost:8899"]
      interval: 2s
      retries: 30

  stellar:
    image: stellar/quickstart:v637-b1047.1-nightly
    command: ["--local", "--protocol-version", "22"]
    ports: ["8000:8000", "8003:8003", "11626:11626"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000"]
      interval: 5s
      retries: 30

  # Bridge stack host ports are offset from the validator stack
  # (../docker-compose.yml owns 4001-4005/8545); see
  # MANUAL-TESTING.md §7.6 for the full port-allocation map.
  seal-node-1:
    build: ../
    command: seal-node --slots 0 --rpc-port 8545 --port 4001
    ports: ["8645:8545", "4101:4001"]
    depends_on:
      solana: { condition: service_healthy }
      stellar: { condition: service_healthy }

  seal-node-2:
    build: ../
    command: >
      seal-node --slots 1 --rpc-port 8545 --port 4001
      --bootstrap-peers /ip4/seal-node-1/tcp/4001
    ports: ["8646:8545"]
    depends_on: [seal-node-1]

  seal-node-3:
    build: ../
    command: >
      seal-node --slots 2 --rpc-port 8545 --port 4001
      --bootstrap-peers /ip4/seal-node-1/tcp/4001
    ports: ["8647:8545"]
    depends_on: [seal-node-1]
```

Bring the whole thing up with `docker-compose -f
bridges/docker-compose.testnet.yml up -d`; tear down with
`down -v`. An integration-test runner (`scripts/bridge-e2e.sh`) then:

1. `solana airdrop 100` → fund a sender on Solana.
2. POST a `lock_tokens` instruction to the Anchor program on localhost:8899.
3. Wait for the Seal observer to pick up the deposit (poll seal
   RPC `seal_getBridgeDeposits` until non-empty).
4. Assert the wrapped token credited to the recipient via `seal_getBalance`.
5. Burn wrapped tokens on Seal → `seal_bridgeWithdraw`.
6. Wait for the Seal committee to sign the unlock (Ringtail threshold sig).
7. Submit the unlock proof + sig to the Anchor program.
8. Verify final SOL balance back at sender.
9. Repeat the loop for Stellar (`lock_xlm` → Seal mint → burn → `unlock_xlm`).

This is a **~1-day** scripting task once B1–B5 code gaps are closed.
Nothing in it requires external infra.

## Public testnets (still no cloud accounts required)

If we want to validate against the real public networks for a smoke
test — also doable without ops work:

- **Solana devnet**: free, public RPC at `https://api.devnet.solana.com`.
  `solana airdrop 2` from anywhere; devnet resets monthly-ish so we
  should not rely on it for persistence.
- **Stellar testnet**: free, public Horizon at
  `https://horizon-testnet.stellar.org`. Friendbot grants 10 000 XLM
  per address: `curl "https://friendbot.stellar.org?addr=$ADDR"`.
  Testnet resets quarterly; same caveat.

For reproducible CI we prefer the local docker stack; public testnets
are useful as a one-off "does this work against the real chains"
smoke test during a release candidate.

## Prioritised plan to close item #3

Ordered by ROI and by what unblocks what.

1. **Implement B1 + B2** (host-side observer RPC). ~1 day. Lets us
   sink real events into `BridgeManager` without touching on-chain code.
   - Deliverables: `reqwest` JSON-RPC client for Solana, Horizon client
     for Stellar; unit tests against recorded response fixtures.

2. **Implement B5** (Stellar SAC call for XLM transfers). ~0.5 day.
   Enables the withdraw path end-to-end on Stellar once Ringtail
   verification exists.

3. **Write the docker-compose + bridge-e2e.sh** (B8). ~1 day. Unblocks
   all subsequent work with a reproducible local test loop. Can
   initially run with the existing on-chain stubs (just asserting
   event plumbing, not sig-verification) — gives us observable
   progress before we tackle B3/B4.

4. **Implement B3 + B4** (on-chain Ringtail verification). ~1–2 weeks.
   This is the non-trivial piece:
   - Solana BPF has no SHA3; use repeated SHA-256 via `sol_sha256`
     syscall (there's a SHA3 crate that works in BPF but costs
     extra compute units — benchmark first).
   - Soroban has `Env::crypto().sha256` and 128-bit-wide integer ops;
     Ringtail's 48-bit prime multiplications fit natively.
   - The on-chain circuit just checks `A·z − c·t` ∈ low-norm ball and
     recomputes the challenge hash — all linear-algebra, no MPC.
   - Reuse `seal-threshold/src/ringtail.rs::verify_signature_full`
     as the reference; translate to the target ABI.

5. **CI integration**: add `scripts/bridge-e2e.sh` to `scripts/ci.sh`
   as an opt-in nightly target. ~0.5 day.

6. **Public-testnet smoke test**: run once per release, capture the
   tx hashes in `TESTNET.md`. ~0.5 day of manual work per release.

**Total effort**: ~2.5 weeks of focused work to go from "deferred" to
"committee-signed Ringtail unlock, verified on a real local Solana
and Stellar validator, end-to-end". Mainnet deploy (B9) is then a
governance gate, not an engineering gate.

### Progress (2026-04-19)

- [x] **B1** — real `SolanaObserver::poll_events` (JSON-RPC
      `getSignaturesForAddress` + `getTransaction`, Anchor
      `LockEvent` log decode). `crates/seal-bridge/src/observer.rs`
- [x] **B2** — real `StellarObserver::poll_events` (Horizon
      `/accounts/{id}/operations`, filter `invoke_host_function`
      with function ∈ {lock, lock_xlm}). `crates/seal-bridge/src/observer.rs`
- [x] **B5** — Stellar Asset Contract (SAC) transfers in `lock_xlm`
      and `unlock_xlm`. `bridges/stellar/src/lib.rs`. `initialize`
      now takes an `xlm_sac: Address` arg.
- [x] **B6/B7/B8** — `bridges/docker-compose.testnet.yml` +
      `scripts/bridge-e2e.sh`.
- [ ] **B3** — Ringtail verify on Solana BPF (still stubbed).
- [ ] **B4** — Ringtail verify on Soroban (still stubbed).

## Recommendation

Treat this as an **internal code task, not a deferred external task**.
Split STATUS.md item #3 into:

- **#3a — Bridge host-side observers** (B1+B2): implement, unblocked.
- **#3b — Bridge on-chain Ringtail verify** (B3+B4): implement, unblocked.
- **#3c — Bridge local-testnet harness** (B6+B8): scripted, unblocked.
- **#3d — Mainnet bridge deploy** (B9): deferred, genuinely external
  (Seal DAO governance vote + mainnet multisig).

Only #3d should stay in the "deferred" column.
