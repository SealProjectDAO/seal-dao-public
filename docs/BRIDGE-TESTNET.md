# Bridge testnet runbook

End-to-end lock→mint and burn→unlock against **public** Solana
devnet and Stellar testnet, using the in-tree Anchor program
(`bridges/solana/`) and Soroban contract (`bridges/stellar/`).
The local-stack equivalent is [`scripts/bridge-e2e.sh`](../scripts/bridge-e2e.sh)
(docker-compose + solana-test-validator + stellar/quickstart);
this doc is the public-testnet variant.

> **Operator-side runbook:** for the **end-to-end "how do I actually
> run this in production" guide** (deploy + flip-to-Ringtail + fund
> relayers + multi-validator smoke + verify), use
> [`docs/RUNBOOK-TESTNET-OPERATOR.md`](RUNBOOK-TESTNET-OPERATOR.md).
> This document is the reference for the deploy and lock/unlock
> commands themselves.
> For validator-count + bridge-committee sizing (3 / 5 / 7
> validators, varying threshold), see
> [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md).

> **Status (2026-05).**
> - §1 deploys (Solana Anchor program + Soroban contract) work as
>   documented against real public testnets.
> - §2 lock direction is driven by the `anchor run lock-sol` parametric
>   driver (`bridges/solana/scripts/lock-sol.ts`); the host-side wrapper
>   is `scripts/bridge-testnet-demo.sh sol`.
> - §3 XLM lock direction works end-to-end against Stellar public
>   testnet via `stellar contract invoke … lock_xlm`
>   (`scripts/bridge-testnet-demo.sh xlm`).
> - §2.2 / §3 reverse direction (burn → committee-sign → unlock)
>   is now exposed via `seal_getBridgeWithdrawal` (returns
>   `committee_signature_hex`) and the `anchor run unlock-tokens` /
>   `stellar contract invoke … unlock_xlm` claim drivers. The
>   demo script wraps both directions:
>   `scripts/bridge-testnet-demo.sh reverse-sol|reverse-xlm`.
> - §4 USDC flows: Stellar shipped (`set_usdc_sac` + `lock_usdc` +
>   `unlock_usdc`); Solana routes through the generic `lock_tokens`
>   ix with `usdc_mint` registered on the observer.

---

## 0. Prerequisites

```
solana --version       # 1.18 or newer
anchor --version       # 0.30 or newer
stellar --version      # 25.x (the local-stack script pins 25.2.0;
                       # earlier 22.x encodes protocol-22 XDR that the
                       # protocol-25 RPC rejects)
rustup target list --installed | grep wasm32v1-none
rustup target list --installed | grep wasm32-unknown-unknown   # SBPF host build
jq --version
curl --version
```

> Note on the WASM target: the Soroban contract under
> `bridges/stellar/` builds with `--target wasm32v1-none`, not
> `wasm32-unknown-unknown`. The Anchor program under `bridges/solana/`
> is SBPF (built via `cargo build-sbf`) and not itself a wasm artifact.

Plus a running Seal testnet node with RPC enabled (see
[`docs/GUIDE-OPERATOR.md`](GUIDE-OPERATOR.md)) and the bridge
observer set wired (see §2 below).

Faucet endpoints we'll lean on (see [`TESTNET-FAUCETS.md`](TESTNET-FAUCETS.md)):

- Solana devnet airdrop: `solana airdrop 2 <pubkey> --url https://api.devnet.solana.com`
  (rate-limited to 2 SOL/request, multiple requests/day allowed)
- Stellar testnet friendbot: `curl 'https://friendbot.stellar.org/?addr=<G-addr>'`
  (10 000 XLM per address, one-shot)
- Seal testnet `seal-faucet`: `curl -X POST <faucet-url>/faucet -d '{"address":"sealt1..."}'`

All four bridge-faucet flows (sol / xlm / usdc-xlm / usdc-sol) are
wrapped by `scripts/bridge-faucet.sh <chain> <address>`, so the
faucet step in the runbook below collapses to one command per chain.

---

## 1. One-time contract deployment

Each public testnet network keeps the deployed program/contract
ID in a known on-disk location. Subsequent runs read the IDs from
those files; they don't redeploy unless the keypair JSON is wiped.

### 1.1 Solana devnet — Anchor program

```bash
solana config set --url https://api.devnet.solana.com
solana-keygen new --no-bip39-passphrase --force \
    -o ~/.config/solana/seal-bridge-deployer.json
solana airdrop 2 \
    "$(solana address -k ~/.config/solana/seal-bridge-deployer.json)"

cd bridges/solana
anchor build
# Devnet deploy (~$0.50 in real fees worth of test SOL):
anchor deploy --provider.cluster devnet \
    --provider.wallet ~/.config/solana/seal-bridge-deployer.json

# The deployed program ID is at target/deploy/seal_bridge-keypair.json:
SOL_PROGRAM_ID=$(solana address -k target/deploy/seal_bridge-keypair.json)
echo "$SOL_PROGRAM_ID" > ../.solana-devnet-program-id
```

If `anchor deploy` fails with insufficient funds, request another
airdrop and retry. Subsequent retries reuse the same program-key
so the program ID is stable.

### 1.2 Stellar testnet — Soroban contract

```bash
stellar network add testnet \
    --rpc-url https://soroban-testnet.stellar.org:443 \
    --network-passphrase 'Test SDF Network ; September 2015'
stellar keys generate seal-bridge-deployer --network testnet
stellar keys fund seal-bridge-deployer --network testnet   # friendbot

cd bridges/stellar
cargo build --target wasm32v1-none --release
WASM=target/wasm32v1-none/release/seal_bridge_stellar.wasm

XLM_CONTRACT_ID=$(stellar contract deploy \
    --wasm "$WASM" \
    --source seal-bridge-deployer \
    --network testnet)
echo "$XLM_CONTRACT_ID" > ../.stellar-testnet-contract-id

# Deploy the native XLM Stellar Asset Contract (idempotent — no-op if
# the SAC already exists on this network), then read its address to
# pass into initialize. `stellar contract id asset` computes the
# deterministic address; the deploy line ensures the contract bytecode
# is actually on-chain so lock_xlm's CPI transfer can find it.
stellar contract asset deploy --asset native \
    --source seal-bridge-deployer --network testnet \
    >/dev/null 2>&1 || true
XLM_SAC=$(stellar contract id asset --asset native --network testnet)

# Initialize with the bridge admin (same as the deployer here for
# the demo; in production this is a 2/3 Technical Council multisig).
# `seal_bridge_key` is the 32-byte hex form of the current committee
# verifying key (zeros below = "not yet rotated"; rotate via
# rotate_committee_key once Ringtail signing is wired).
stellar contract invoke --id "$XLM_CONTRACT_ID" \
    --source seal-bridge-deployer --network testnet \
    -- initialize \
    --admin "$(stellar keys address seal-bridge-deployer)" \
    --seal_bridge_key "0000000000000000000000000000000000000000000000000000000000000000" \
    --xlm_sac "$XLM_SAC"
```

The `xlm_sac` argument is the address of the deterministic SAC for
native lumens on the current network — computed from the network
passphrase rather than copy-pasted, so the same code works on
testnet and mainnet without a hardcoded constant.

### 1.3 Wire the program IDs into seal-node

```bash
# Tell the running seal-node where to look for bridge events:
SOL_PROGRAM_ID=$(cat bridges/.solana-devnet-program-id)
XLM_CONTRACT_ID=$(cat bridges/.stellar-testnet-contract-id)

curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -nc \
        --arg pid "$SOL_PROGRAM_ID" \
        --arg url 'https://api.devnet.solana.com' \
        --arg usdc 'Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr' \
        '{jsonrpc:"2.0", id:1, method:"seal_addBridgeObserver",
          params:{chain:"Solana", rpc_url:$url, program_id:$pid,
                  usdc_mint:$usdc}}')"
# `usdc_mint` is the canonical devnet USDC SPL mint. Locks of this
# mint route to WUSDC; everything else routes to WSOL. Drop the
# `usdc_mint` field if you only operate the SOL flow.

curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -nc \
        --arg cid "$XLM_CONTRACT_ID" \
        --arg url 'https://horizon-testnet.stellar.org' \
        '{jsonrpc:"2.0", id:1, method:"seal_addBridgeObserver",
          params:{chain:"Stellar", horizon_url:$url, contract_id:$cid}}')"
```

For public Stellar testnet/mainnet the observer derives the Soroban
RPC URL from the Horizon URL automatically (see
`crates/seal-bridge/src/observer.rs::derive_soroban_rpc_url`):
`horizon-testnet.stellar.org → soroban-testnet.stellar.org`,
`horizon.stellar.org → soroban-rpc.stellar.org`. For custom or
self-hosted endpoints, pass an explicit
`"soroban_rpc_url"` field in the params alongside `horizon_url`.

If the seal-node was started with `--admin-address` populated,
`seal_addBridgeObserver` requires a signed request from one of the
admins. See SPEC.md §5.5.

---

## 2. Round-trip: SPL token → wrapped-SOL → SPL token

> **Scope note.** The Anchor program's `lock_tokens` instruction takes
> an SPL token (mint + sender token account + vault token account),
> not native SOL lamports directly. The on-Seal wrapped representation
> is symbol `wSOL` regardless. A native-SOL-lock convenience path is
> tracked separately; for now testnet operators stake an SPL mint
> they control and use that as the "SOL-shaped" testnet asset.

### 2.1 Lock direction

`anchor run lock-sol` is the parametric driver
(`bridges/solana/scripts/lock-sol.ts`) for devnet locks. It needs an
SPL mint + paired sender / vault token accounts deployed up front
— the program tracks locked balances per SPL mint, there's no
native-SOL lock path.

```bash
# One-time SPL setup (skip if you already have these from §1.1):
solana config set --url https://api.devnet.solana.com
SOL_MINT=$(spl-token create-token | grep "Creating token" | awk '{print $3}')
SOL_SENDER_ATA=$(spl-token create-account "$SOL_MINT" | grep "Creating account" | awk '{print $3}')
spl-token mint "$SOL_MINT" 100 "$SOL_SENDER_ATA"  # mint 100 tokens to yourself
# Vault is owned by the bridge_state PDA — derive it offline or
# create via `spl-token create-account --owner <bridge-state-pda>`.
SOL_VAULT_ATA=…

# Lock 0.5 tokens (500_000_000 at 9 decimals).
SEAL_RECIPIENT_HEX=$(cargo run --quiet -p seal-cli -- addr-to-hex "$SEAL_RECIPIENT")
cd bridges/solana
anchor run lock-sol -- \
    --amount 500000000 \
    --seal-recipient "$SEAL_RECIPIENT_HEX" \
    --mint "$SOL_MINT" \
    --sender-ata "$SOL_SENDER_ATA" \
    --vault-ata "$SOL_VAULT_ATA" \
    --program-id "$(cat ../.solana-devnet-program-id)" \
    --provider.cluster devnet
```

`seal addr-to-hex sealt1…` converts the 56-char bech32m address to
the 32-byte hex form `lockTokens` expects. The script prints the
derived `lock_record` PDA + the updated `total_locked` / `nonce`
after the tx confirms.

Once the lock confirms, the Seal node's Solana observer polls
`getSignaturesForAddress` against the program at
`--bridge-poll-interval-secs` (default 10 s); when it sees the event
it mints wrapped-SOL to the seal recipient. Force a sweep with
`seal_pollBridges` instead of waiting:

```bash
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_pollBridges","params":{}}' | jq

# Confirm the mint by reading the per-token wrapped balance:
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$SEAL_RECIPIENT" \
       '{jsonrpc:"2.0",id:1,method:"seal_getBridgeWrappedBalance",
         params:{address:$a,token:"WSOL"}}')" | jq
# Expected: balance == the locked amount.
```

### 2.2 Reverse direction (burn → committee-sign → unlock)

Burn on Seal, fetch the committee MAC, then submit it to the
Anchor `unlock_tokens` ix on Solana. The full path drives end-to-end
under the committee-of-1 testnet committee key. (For a multi-validator
testnet the same shape applies once Ringtail-aggregated signatures
replace the host-side HMAC — the on-chain `verify_committee_sig`
already takes the aggregated bytes as opaque input.)

```bash
# 1) Burn the wrapped balance and create a withdrawal record.
#    `token` is one of WSOL, WXLM, WUSDC. `dest_address` is the
#    Solana ed25519 pubkey to unlock to.
WD=$(seal bridge-withdraw --node "$SEAL_RPC" --key "$SEAL_KEY" \
       --dest-chain Solana --dest-address <devnet-pubkey> \
       --token WSOL --amount 50000000 \
     | grep -oE 'withdrawal_id: \S+' | awk '{print $2}')
# → wd_sol_<n>

# 2) Fetch the committee MAC. With `--bridge-committee-key …` set,
#    the host attaches an HMAC-SHA-256 over `recipient(32) ‖
#    amount_le(8) ‖ nonce_le(8) ‖ "seal-bridge-solana-v1"` at burn
#    time. `committee_signature_hex` is the 64-char hex form.
JSON=$(seal bridge-get-withdrawal --node "$SEAL_RPC" --withdrawal-id "$WD")
SIG=$(echo "$JSON" | jq -r '.withdrawal.committee_signature_hex')
NONCE=$(echo "$JSON" | jq -r '.withdrawal.nonce')

# 3) Submit the claim on Solana. The Anchor `unlock_tokens` ix
#    recomputes the HMAC inside `verify_committee_sig` and rejects
#    on mismatch — so wrong bytes surface as `InvalidProof`.
cd bridges/solana
anchor run unlock-tokens -- \
  --amount 50000000 --nonce "$NONCE" --signature "$SIG" \
  --recipient <devnet-pubkey> --recipient-ata <recipient-ata> \
  --vault-ata <vault-ata> --authority <authority-pk>
```

The Stellar reverse path is mechanically identical (§3 below) and
has been validated end-to-end against the local stellar/quickstart
stack via `scripts/bridge-e2e.sh reverse`. Solana reverse uses the
same `seal bridge-withdraw` / `seal bridge-get-withdrawal` host-side
plumbing — only the on-chain claim wrapper differs.

**Per-initiator lookup** (no auth):

```bash
# Every withdrawal the caller initiated, sorted by id:
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$SEAL_WITHDRAWER_ADDR" \
       '{jsonrpc:"2.0",id:1,method:"seal_listBridgeWithdrawalsByInitiator",
         params:{address:$a}}')" | jq
```

---

## 3. Round-trip: XLM → wrapped-XLM → XLM

Same shape, Stellar version. The Soroban contract's `lock_xlm` ix
takes `sender`, `amount` (in stroops; 1 XLM = 10⁷ stroops), and
`seal_address` (32-byte hex like Solana).

```bash
LOCK_AMOUNT_XLM=10000000   # 1 XLM
SEAL_RECIPIENT_HEX=$(cargo run --quiet -p seal-cli -- addr-to-hex "$SEAL_RECIPIENT")

cd bridges/stellar
stellar contract invoke --id "$(cat ../.stellar-testnet-contract-id)" \
    --source seal-bridge-deployer --network testnet \
    -- lock_xlm \
    --sender "$(stellar keys address seal-bridge-deployer)" \
    --amount "$LOCK_AMOUNT_XLM" \
    --seal_address "$SEAL_RECIPIENT_HEX"

# Force a sweep + confirm the mint:
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_pollBridges","params":{}}' | jq
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$SEAL_RECIPIENT" \
       '{jsonrpc:"2.0",id:1,method:"seal_getBridgeWrappedBalance",
         params:{address:$a,token:"WXLM"}}')" | jq
# Expected: balance == LOCK_AMOUNT_XLM in stroops.
```

For the burn direction, `seal-cli bridge-withdraw` takes the same
shape as the Solana case (just swap `dest_chain` and `token`), and
the on-Stellar `unlock_xlm` claim is the analogue of Solana's
`unlock_tokens`. The script `scripts/bridge-e2e.sh reverse` exercises
this exact path against the containerized stack and asserts that
the host-computed committee MAC passes the Soroban contract's
`verify_proof`:

```bash
WD=$(seal bridge-withdraw --node "$SEAL_RPC" --key "$SEAL_KEY" \
       --dest-chain Stellar --dest-address <G-address> \
       --token WXLM --amount 5000000 \
     | grep -oE 'withdrawal_id: \S+' | awk '{print $2}')

JSON=$(seal bridge-get-withdrawal --node "$SEAL_RPC" --withdrawal-id "$WD")
SIG=$(echo "$JSON" | jq -r '.withdrawal.committee_signature_hex')
NONCE=$(echo "$JSON" | jq -r '.withdrawal.nonce')

cd bridges/stellar
stellar contract invoke --id "$(cat ../.stellar-testnet-contract-id)" \
  --network testnet --source seal-bridge-deployer \
  -- unlock_xlm \
  --recipient <G-address> --amount 5000000 \
  --nonce "$NONCE" --proof "$SIG"
```

Mismatched bytes (wrong XDR encoding for the recipient, or wrong
endianness on amount/nonce) surface as `InvalidProof` from the
contract.

---

## 4. USDC

USDC needs a separate code path because, unlike SOL / XLM where
operators can mint a fresh test token on demand, USDC already
exists on the source chain — the bridge has to lock the existing
Circle-issued asset rather than transfer-in / mint a wrapper.

**Status**:
- **Stellar**: `bridges/stellar/src/lib.rs` ships `set_usdc_sac`
  (admin) + `lock_usdc` + `unlock_usdc` as of 2026-05-15. The Seal
  observer recognizes the `Symbol("lockusdc")` topic and tags
  deposits as `WrappedToken::WUSDC`. The same committee MAC primitive
  drives both XLM and USDC unlock claims (the Stellar domain tag
  is asset-agnostic).
- **Solana**: `bridges/solana/programs/seal-bridge/src/lib.rs`
  handles USDC through the existing mint-generic `lock_tokens` ix —
  the program doesn't need a separate `lock_usdc` because the
  same instruction transfers any SPL token. The observer routes by
  `LockEvent.mint`: pass the canonical devnet USDC mint as
  `usdc_mint` to `seal_addBridgeObserver` and locks of that mint
  land in `WrappedToken::WUSDC`. Everything else routes to WSOL.
  Before the first USDC lock, derive + initialize the bridge vault
  ATA for the USDC mint via `anchor run derive-vault-ata --
  --mint <usdc-mint> --init`.

After `stellar contract deploy` (§1.2), install the USDC SAC:

```bash
# `USDC:GBBD47IF…` is the Stellar Foundation-issued testnet USDC.
# stellar contract id asset computes the deterministic SAC address.
USDC_SAC=$(stellar contract id asset --asset USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5 --network testnet)
stellar contract invoke --id "$XLM_CONTRACT_ID" \
    --source seal-bridge-deployer --network testnet \
    -- set_usdc_sac --usdc_sac "$USDC_SAC"
```

### 4.1 Stellar testnet USDC trustline (faucet only)

Friendbot supports an `&asset=` parameter that funds an account
with the testnet USDC issued by the Stellar Foundation. Friendbot
won't create + trustline-fund in one tx, so a fresh G-address needs
XLM first:

```bash
./scripts/bridge-faucet.sh xlm      <G-addr>   # creates the account
./scripts/bridge-faucet.sh usdc-xlm <G-addr>   # adds USDC trustline + balance
```

Raw equivalent:

```bash
curl "https://friendbot.stellar.org/?addr=<G-addr>&asset=USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
```

When `lock_usdc` lands on the Stellar bridge contract, the on-Seal
wrapped balance will show up as symbol `WUSDC`.

### 4.2 Solana USDC — two paths

**Public devnet** uses Circle's developer console (no programmatic
endpoint). `bridge-faucet.sh usdc-sol` prints the URL + the
`spl-token create-account` prep step the operator must run before
Circle can deliver:

```bash
./scripts/bridge-faucet.sh usdc-sol <pubkey>
```

USDC ATA + canonical devnet mint
(`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`) get initialized;
locks of that mint route to `WrappedToken::WUSDC` because the
observer was started with `usdc_mint=…` in §1.3.

**Local validator** (the one stood up by `scripts/bridge-e2e.sh`)
uses `scripts/spl-usdc-bootstrap.sh` — a self-serve fresh SPL mint
(6 decimals, matching real USDC) with operator-owned mint authority:

```bash
./scripts/spl-usdc-bootstrap.sh
# → exports SOL_MINT / SOL_SENDER_ATA / SOL_VAULT_ATA
```

The bootstrap script persists the mint keypair at
`bridges/.solana-local-usdc-mint.json` so the mint pubkey stays
stable across `docker compose down -v` cycles. Pass that local
`SOL_MINT` as `usdc_mint` to `seal_addBridgeObserver` in the local
stack to route locks of it to `WrappedToken::WUSDC`.

---

## 5. Status checks and troubleshooting

```bash
# Is my observer wired?
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}' | jq

# Are events being seen on the source chain? (object-param shape;
# the legacy positional ["Solana"] still works for back-compat.)
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBridgeDeposits",
       "params":{"chain":"Solana"}}' | jq

# What withdrawals has my key initiated? (Per-owner gap-closer —
# the global list isn't exposed via RPC today, see §2.2 above.)
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$SEAL_WITHDRAWER_ADDR" \
       '{jsonrpc:"2.0",id:1,method:"seal_listBridgeWithdrawalsByInitiator",
         params:{address:$a}}')" | jq

# Are any chains paused? Pause is the bridge equivalent of the
# token kill switch — both the Seal-side guard (technical council)
# and the in-program guard (admin-only set_pause) reject locks
# when set. Also surfaced inline in seal_getBridgeStatus.paused_chains.
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeListPaused","params":{}}' | jq

# What committee MAC key has seal-node installed? Returns
# {"set": bool, "fingerprint_sha3_hex": "...", "fingerprint_sha2_hex":
# "..."} — the SHA3-256 and SHA-256 fingerprints over the installed
# key, never the key itself. Use `fingerprint_sha2_hex` for the
# cross-chain diff: Solana's `sol_sha256` syscall and Stellar's
# `env.crypto().sha256()` are SHA-256, so an on-chain
# `committee_key_hash` view (added in a follow-up) returns matching
# bytes. `fingerprint_sha3_hex` is the host's PQ-native default.
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,
       "method":"seal_bridgeGetCommitteeKeyStatus","params":{}}' | jq
```

To rotate the host-side committee key without restarting `seal-node`
(e.g. after a council-coordinated key roll), call
`seal_bridgeRotateCommitteeKey` with a 2/3 Technical Council
approver list. Always follow with the matching `rotate_committee_key`
ix on each chain's bridge program in the same epoch — withdrawals
initiated between the two rotations will carry an HMAC that no chain
can yet verify.

The handler writes the new 32-byte key atomically to
`<data_dir>/bridge-committee-key.hex` (tmp file + rename) so the
rotation survives a node restart. On startup, that file overrides
`--bridge-committee-key`; the response field `persisted: true`
confirms the write succeeded. If `persisted: false` (filesystem
permission error, disk full), the in-memory rotation still works
for the current process — re-run the RPC after fixing the
underlying issue, or the next restart will revert to the CLI
flag's value.

```bash
curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
  -d "$(jq -cn --arg k "$NEW_KEY_HEX" \
       '{jsonrpc:"2.0",id:1,method:"seal_bridgeRotateCommitteeKey",
         params:{new_key_hex:$k,approvers:["pk1","pk2","pk3","pk4","pk5","pk6"]}}')" \
  | jq
```

**Common failure modes:**

| Symptom | Likely cause |
|---|---|
| `seal_pollBridges` reports 0 new events | Observer not added (run §1.3); program ID typo; observer points at the wrong RPC URL |
| Mint never lands on Seal | Committee key not propagated; observer admin-gated and the request was unsigned |
| `lock_*` transaction reverts on the source chain | Bridge in-program paused (call `set_pause(false)` from admin); insufficient source balance |
| `unlock_*` rejects with "BadSignature" | Ringtail signature in `committee_signature` is from a *different* bridge nonce than the withdrawal_id; refetch fresh via `seal_getBridgeWithdrawals` |
| `unlock_*` rejects with "AlreadyClaimed" | Replay protection — each `withdrawal_id` is one-shot per chain |

---

## 6. CI integration

This runbook is **not** wired into `scripts/ci.sh`. The test
keypairs hold real testnet balance; a CI loop would burn airdrop
quotas and could bottle up the public faucets. The bridge round-
trips that *are* exercised in CI live in `scripts/bridge-e2e.sh`
(local docker stack with unlimited airdrops).

For the rare "is the public-testnet bring-up still alive?" check,
gate the demo script behind an opt-in env var:

```bash
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh sol
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh xlm
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh both
```

The script no-ops without the env var so accidental invocations
from `scripts/ci.sh` (or a forgotten `cargo run` shortcut) don't
spend testnet funds.
