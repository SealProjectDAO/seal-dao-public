# Testnet Faucets

Faucet endpoints for every chain Seal interacts with on testnet.
The Seal faucet drips native SEAL; the others are needed for the
bridge-e2e round trips (lock→mint, burn→unlock).

## Seal testnet — `seal-faucet`

The in-tree HTTP service. Source under `apps/seal-faucet/`; full
docs in [`apps/seal-faucet/README.md`](../apps/seal-faucet/README.md).

```
cargo run -p seal-faucet -- --key faucet.json --node <node-url>
curl -X POST http://<faucet-host>:8546/faucet \
  -H 'Content-Type: application/json' \
  -d '{"address":"sealt1..."}'
```

Drips 1 SEAL (1 000 000 000 base units, since SEAL is 9-decimal)
per address per hour by default; `--drip <base-units>` and
`--interval-secs <n>` adjust both. Per-address and per-IP cooldowns;
HRP cross-network paste guard on the request side (a `seal1…`
request to a `sealt1…` faucet → 400); signed `seal_transfer` from
a dedicated keypair on the upstream side.

**Not wired into `scripts/ci.sh`** — a CI loop would burn the
faucet's balance.

## One-shot wrapper — `scripts/bridge-faucet.sh`

All four bridge-faucet flows below are wrapped in a single helper
so operators don't need to remember the chain-specific incantations:

```
./scripts/bridge-faucet.sh sol      <pubkey>     [amount_sol]
./scripts/bridge-faucet.sh xlm      <G-address>
./scripts/bridge-faucet.sh usdc-xlm <G-address>
./scripts/bridge-faucet.sh usdc-sol <pubkey>      # prints Circle URL + ATA snippet
```

Env knobs: `SOLANA_DEVNET_RPC` (default `https://api.devnet.solana.com`)
and `STELLAR_FRIENDBOT` (default `https://friendbot.stellar.org`;
point at `http://127.0.0.1:8000` for the local `stellar/quickstart`
container in `scripts/bridge-e2e.sh`).

The sections below document each underlying faucet for reference.

## Stellar (XLM)

Stellar testnet has a built-in friendbot that mints 10 000 XLM to
any provided G-address.

```
curl 'https://friendbot.stellar.org/?addr=GA...'
# or:
./scripts/bridge-faucet.sh xlm GA...
```

For the Soroban quickstart docker image (used by `scripts/bridge-e2e.sh`),
friendbot is co-hosted on `:8000`:

```
curl 'http://127.0.0.1:8000/friendbot?addr=GA...'
# or:
STELLAR_FRIENDBOT=http://127.0.0.1:8000 ./scripts/bridge-faucet.sh xlm GA...
```

The script's `stellar_keys_fund_with_retry` helper handles the
race between container readiness and the first friendbot call.

## Solana (SOL)

Solana testnet/devnet exposes airdrop via the standard CLI:

```
solana config set --url https://api.devnet.solana.com
solana airdrop 2 <pubkey>          # 2 SOL on devnet
# or:
./scripts/bridge-faucet.sh sol <pubkey> 2
```

Local validator (used in bridge-e2e):

```
solana airdrop 100 <pubkey> --url http://localhost:8899
```

## USDC (Stellar testnet)

Friendbot hands out the canonical Stellar-Foundation-issued testnet
USDC trustline via the `&asset=` parameter, but **only against an
already-funded account** (friendbot won't create + trustline-fund in
one transaction). The standard recipe is XLM-then-USDC:

```
./scripts/bridge-faucet.sh xlm      <G-address>   # creates account
./scripts/bridge-faucet.sh usdc-xlm <G-address>   # adds trustline + USDC
```

Raw equivalent:

```
curl 'https://friendbot.stellar.org/?addr=<G-addr>&asset=USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5'
```

(That's the Stellar-foundation-issued testnet USDC.)

## USDC (Solana — devnet vs. local)

There are two distinct paths depending on which validator the
operator is targeting:

### Public devnet — Circle sandbox

```
./scripts/bridge-faucet.sh usdc-sol <pubkey>
```

Prints the Circle developer-console URL
(https://developers.circle.com), the canonical devnet USDC mint
(`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`), and the
`spl-token create-account` snippet the operator must run before
Circle can deliver. Circle gates sandbox USDC behind a dashboard
flow; there is no programmatic endpoint.

### Local stack — `scripts/spl-usdc-bootstrap.sh`

For `scripts/bridge-e2e.sh` and any other local-validator test, the
`spl-usdc-bootstrap.sh` helper creates a fresh USDC-shaped SPL mint
on the local solana-test-validator (6 decimals, mint-authority owned
by the operator), seeds the sender ATA with `SUPPLY` whole tokens
(default `1000000`), and derives + initializes the bridge vault ATA
via `anchor run derive-vault-ata --init`. It prints env exports
(`SOL_MINT` / `SOL_SENDER_ATA` / `SOL_VAULT_ATA`) that paste straight
into `bridge-e2e.sh` / `bridge-testnet-demo.sh`:

```
./scripts/spl-usdc-bootstrap.sh
# → exports SOL_MINT / SOL_SENDER_ATA / SOL_VAULT_ATA
```

Idempotent across re-runs: the mint keypair persists at
`bridges/.solana-local-usdc-mint.json`, so the mint pubkey stays
stable across `docker compose down -v` cycles (the on-chain mint is
recreated on the next bootstrap call, but the public key matches).

## Local devnet override — `seal-node --dev-faucet`

For pre-bootstrap testing where no signed faucet keypair exists yet,
`cargo run -p seal-node -- --dev-faucet` exposes an unsigned
`seal_faucet` JSON-RPC method that mints arbitrary amounts to any
address. **Refused under `--mainnet`** — see the explicit guard in
`crates/seal-node/src/main.rs`. Use only on a node where
`--mainnet` is not set; the seal-faucet service above is the right
testnet-grade tool.

## Pointers

- `docs/BRIDGE-TESTNET.md` — bridge testnet bring-up runbook.
- `bridges/DEPLOYMENT.md` — bridge deployment notes.
- `apps/seal-faucet/README.md` — service-level details, flags,
  endpoint reference.
- `MANUAL-TESTING.md` §7 (Bridge) — end-to-end smoke checklist
  that uses these faucets in order; the local-stack equivalent
  lives in `scripts/bridge-e2e.sh`.
