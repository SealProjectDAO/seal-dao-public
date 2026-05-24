# Testnet Validator Registration

The Seal incentivized testnet uses a self-serve registration portal
so prospective validator operators can advertise their
`{pubkey, vrf_pubkey, name}` to the network without an out-of-band
ask. The portal is the in-tree HTTP service `apps/seal-registration`.

## What the portal is for

- **Inclusion**: gives the testnet operators a single roster to
  pull from when setting `SEAL_BOOTSTRAP_PEERS` and seeding the
  validator-set genesis section. Without it, every new operator
  has to find the bootstrap node admin out-of-band.
- **Public liveness**: the `/registrations` GET surfaces
  `{pubkey_hex, vrf_pubkey_hex, name, accepted_at_unix_secs}` so
  the explorer-web can show "who's onboarding right now" without
  pulling private contact info.
- **Operator coordination**: the on-disk JSONL keeps the full
  payload (including contact info) so the testnet operations team
  can reach individual validators when something breaks. That
  contact info NEVER leaves the host.

It is **not** an admission gate. Anyone can register; presence
on the roster doesn't grant validator slot. Slot allocation is a
separate operations decision.

## Run the portal

```bash
cargo run -p seal-registration -- \
    --port 8547 \
    --bind 0.0.0.0 \
    --store registrations.jsonl \
    --interval-secs 60
```

Flags:

| Flag             | Default                    | Meaning                                        |
| ---------------- | -------------------------- | ---------------------------------------------- |
| `--port`         | 8547                       | HTTP listen port                               |
| `--bind`         | 127.0.0.1                  | bind address (use 0.0.0.0 for public exposure) |
| `--store`        | registrations.jsonl        | append-only JSONL store path                   |
| `--interval-secs`| 60                         | per-IP cooldown                                |

The portal is **not wired into `scripts/ci.sh`** — it's a
long-running HTTP service. Run it under systemd / a process
supervisor on the testnet operations host.

## Wire format

### POST /register

```json
{
  "pubkey_hex":      "<1952-byte ML-DSA-65 verifying key, hex>",
  "vrf_pubkey_hex":  "<32-byte VRF public key, hex>",
  "name":            "validator-display-name",
  "contact":         "ops@example.com or @ops on Telegram",
  "signature_hex":   "<3309-byte ML-DSA-65 signature, hex>"
}
```

`signature_hex` is over the bytes
`SHA3-256(b"register" || pubkey_hex || vrf_pubkey_hex || name ||
contact)`. The portal reproduces the same byte string and
verifies against the supplied `pubkey_hex`. Anyone can submit any
operator's payload, but without the operator's signing key the
signature won't verify.

Soft caps: `name ≤ 200`, `contact ≤ 400`. Empty fields are
rejected at 400.

Re-submitting with the same `pubkey_hex` returns a 200 with
`status: "already-registered"` rather than an error.

### GET /registrations

```json
{
  "registrations": [
    {
      "pubkey_hex": "...",
      "vrf_pubkey_hex": "...",
      "name": "validator-display-name",
      "accepted_at_unix_secs": 1745000000
    },
    ...
  ],
  "count": 17
}
```

Stable order: `accepted_at_unix_secs` ASC, ties broken by
`pubkey_hex`. `contact` is **omitted** — it stays in the
on-host JSONL only.

### GET /health

`200 ok\n` when the service is up.

## Operator one-shot CLI

`seal register-validator` wraps the build-canonical-bytes + sign +
POST flow. Given a wallet keyfile (from `seal keygen --output`) and
a 64-hex VRF public key:

```bash
seal register-validator \
    --portal http://<portal>:8547 \
    --key wallet.json \
    --name "validator-alpha" \
    --contact "alpha@example.com" \
    --vrf-pubkey-hex "$VRF_PUBKEY_HEX"
```

Expected on first submit:
`{"status":"ok","pubkey_hex":"…","name":"validator-alpha"}`.
Subsequent calls with the same `pubkey_hex` return
`{"status":"already-registered",…}` — the portal dedupes idempotently.

The wallet's verifying_key is what advertises your validator;
make sure `wallet.json` matches the keyfile you pass to
`seal-node --validator-key` so the running node signs blocks under
the same identity the portal roster lists.

## Operator hand-build (curl fallback)

For ops shops that can't run the seal-cli binary, the canonical
message is `b"register" || pubkey_hex || vrf_pubkey_hex || name ||
contact`, SHA3-256-hashed, ML-DSA-65-signed. `seal sign-file` writes
that exact bytes layout when fed a temp file:

```bash
PUBKEY=$(jq -r .verifying_key wallet.json)
VRF_PK=<64-hex-chars = 32 bytes>
NAME="validator-alpha"
CONTACT="alpha@example.com"
PORTAL="http://<portal>:8547"

printf 'register%s%s%s%s' "$PUBKEY" "$VRF_PK" "$NAME" "$CONTACT" \
    > /tmp/seal-reg-msg.bin
cargo run --quiet -p seal-cli -- sign-file /tmp/seal-reg-msg.bin \
    --key wallet.json --out /tmp/seal-reg.sig
SIG=$(cat /tmp/seal-reg.sig)

curl -X POST "$PORTAL/register" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc \
        --arg pk "$PUBKEY" --arg vrf "$VRF_PK" \
        --arg n "$NAME"   --arg c "$CONTACT" --arg s "$SIG" \
        '{pubkey_hex:$pk, vrf_pubkey_hex:$vrf, name:$n,
          contact:$c, signature_hex:$s}')"
```

## Persistence + recovery

- The store is append-only JSONL: one record per line, no
  rewrites. A partial append + crash leaves the on-disk store
  parseable up to the last full line.
- On startup the portal calls `load_jsonl()`, which:
  1. Returns an empty map if the file doesn't exist (fresh
     install).
  2. Skips blank lines.
  3. Last-write wins for duplicate `pubkey_hex` entries —
     duplicates would only arrive via direct file edits, but
     tolerating them keeps the service from refusing to start
     after a manual fix-up.
- The in-memory `HashMap<pubkey_hex, RegistrationRecord>` is
  rebuilt from the JSONL at startup; everything after that flows
  through the lock-protected mutator.

## Privacy / threat model

- `contact` is operator-private. It NEVER leaves the host via
  HTTP. If a future explorer view wants per-validator contact
  surfacing, that's a separate decision and should require an
  opt-in flag in the registration record.
- The signing key never touches the portal. The portal only sees
  signatures + public keys.
- The portal does NOT prove the operator controls the underlying
  validator stake or runs a real node. Slot allocation /
  network-set membership are separate decisions made by the
  testnet ops team using the registration roster as input.
