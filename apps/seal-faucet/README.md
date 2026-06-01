# seal-faucet

Tiny axum HTTP service that drips testnet SEAL on demand. Sends an
ML-DSA-signed `seal_transfer` to a Seal-node from a dedicated faucet
keypair, gated by per-address and per-IP cooldowns.

## Usage

```
cargo run -p seal-faucet -- \
    --key faucet.json \
    --node http://localhost:8545 \
    --port 8546 \
    --drip 1000000000 \
    --interval-secs 3600
```

| Flag | Default | Description |
|---|---|---|
| `--key` | (required) | Faucet keypair JSON: `{signing_key, verifying_key, address}` (hex). Generate with `cargo run -p seal-cli -- keygen --output faucet.json [--mainnet]`. |
| `--node` | `http://localhost:8545` | Target Seal-node JSON-RPC URL. |
| `--bind` | `127.0.0.1` | Faucet HTTP bind address. |
| `--port` | `8546` | Faucet HTTP listen port. |
| `--drip` | `1_000_000_000` (= 1 SEAL @ 9 decimals) | Base units per request. |
| `--interval-secs` | `3600` (1 h) | Per-address + per-IP cooldown. |

## Endpoints

### `POST /faucet`

Request body:

```json
{ "address": "sealt1d362dssrf8nef5vyxkhgl8dweq2etdn2a4kjj3khf0e0q2xurzlqp6zzvd" }
```

Success (200):

```json
{
  "status": "ok",
  "address": "sealt1...",
  "amount": 1000000000,
  "tx_hash": "deadbeef..."
}
```

(`amount` is the per-drip base-unit amount sent — defaults to 1 SEAL
= 1 000 000 000 base units at 9 decimals; the `--drip` flag overrides.)

Errors:

| Status | Cause |
|---|---|
| 400 | malformed address, or HRP mismatch with the faucet (e.g. `seal1…` request to a `sealt1…` faucet) |
| 429 | cooldown active (per-address or per-IP); response carries `retry_after_secs` |
| 502 | upstream node unreachable or rejected the transfer |
| 500 | signing failure (probably a corrupt key file) |

### `GET /health`

Returns `200 OK` with `ok\n`. Useful for liveness probes.

## Testnet ops

- **Bootstrapping the keypair**: generate the faucet key with
  `cargo run -p seal-cli -- keygen --output faucet.json --testnet`
  (use `--mainnet` for a `seal1…`-HRP faucet). Top up the resulting
  address through testnet genesis or an admin transfer **before**
  pointing the faucet at a live node — the first
  `POST /faucet` will fail with insufficient balance otherwise.
- **HRP cross-network paste guard**: a faucet keyed with a `sealt1…`
  address rejects `seal1…` requests with 400 before the cooldown is
  bumped. Stops a misconfigured client from burning the rate-limit
  quota on requests the node will reject anyway.
- **Rate limit ergonomics**: the `interval_secs` cooldown is recorded
  on success only — a 502 from the node doesn't burn the requester's
  quota. (A 429 also doesn't burn it, by definition.)
- **Faucet keypair rotation**: stop the service, generate a new key,
  drain the old address with `seal transfer ... --key old.json`, swap
  in `new.json` via `--key`, restart. No persistent state on the
  faucet side beyond the in-memory cooldown maps, which reset on
  restart by design (a restart shouldn't punish someone who hit the
  cooldown right before).
- **Not in CI**: never wired into `scripts/ci.sh`. A CI loop hitting
  the faucet would burn the testnet drip balance and risk leaking
  the keyfile through workflow logs.

## Cross-chain context

`docs/TESTNET-FAUCETS.md` cross-references the foreign-chain faucets
needed for bridge-e2e (XLM friendbot, Solana airdrop, Circle SPL-USDC
sandbox).
