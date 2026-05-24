# Testnet validator-count + bridge-committee sizing

Concrete bring-up recipes for 3-, 5-, and 7-validator Seal
testnets, with bridge-committee size that can be **independent**
of the validator count.

Two knobs are involved:

| Knob | What it controls | Flag(s) |
|------|-------------------|---------|
| **Validator count** (N_v) | How many `seal-node` instances peer up via libp2p and produce blocks. | per-node `--port`, `--bootstrap-peers` |
| **Bridge committee size** (N_b) | How many of those validators participate in the Ringtail aggregate signature for bridge unlock claims. M-of-N_b is the threshold. | `--bridge-ringtail-committee-size N_b` + `--bridge-ringtail-threshold M` + `--bridge-ringtail-party-id i` (0..N_b-1) |

**Important: N_b ≤ N_v.** Only the first N_b validators (by
`--bridge-ringtail-party-id`) participate in the committee. The
remaining N_v − N_b validators run consensus but stay out of the
bridge signing path (no `--bridge-ringtail-*` flags).

---

## 0. Choosing M (threshold) and N_b (committee size)

The on-chain `verify_signature_full` accepts any aggregate that
meets the M-of-N_b threshold encoded in `PublicParams`. Practical
sizing:

| N_b | Recommended M | Tolerated faults | Notes |
|-----|---------------|------------------|-------|
| 1 | 1 | 0 | HMAC-equivalent placeholder (committee-of-1). Useful for testing the wire format. |
| 3 | 2 | 1 | Minimum to actually exercise threshold logic. |
| 4 | 3 | 1 | Even N_b: M = ⌈2N_b/3⌉. |
| 5 | 3 | 2 | Sweet spot for early multi-validator testnet. |
| 7 | 5 | 2 | Recommended pre-mainnet shape (matches mainnet target of 7-of-N supermajority). |

The rule of thumb is `M = ⌈2·N_b/3⌉` (BFT supermajority). If you
go below 2N_b/3 you're vulnerable to forged aggregate signatures
once the count of compromised validators ≥ N_b − M.

---

## 1. 3-validator testnet

The `bridges/docker-compose.testnet.yml` stack already ships 3
validators (`seal-1`, `seal-2`, `seal-3`). This is the **default
configuration** for local-stack runs.

### 1.1 Seal validators

```bash
cd bridges
docker compose -f docker-compose.testnet.yml up -d
```

Ports:
- `seal-1` RPC → `:8545`
- `seal-2` RPC → `:8546`
- `seal-3` RPC → `:8547`

### 1.2 Bridge committee variants

| Variant | N_b | M | What it tests |
|---------|-----|---|---------------|
| **A — Committee-of-1** | 1 | 1 | Wire format only. Use HMAC mode instead in practice. |
| **B — 2-of-3 full** (default) | 3 | 2 | Real threshold logic, all validators sign. |

For **Variant B** every validator runs:

```bash
seal-node ... \
    --bridge-ringtail-keypair-file /var/lib/seal/ringtail-keypair.json \
    --bridge-ringtail-mac-key-hex 2222222222222222222222222222222222222222222222222222222222222222 \
    --bridge-ringtail-party-id <0|1|2> \
    --bridge-ringtail-threshold 2 \
    --bridge-ringtail-committee-size 3 \
    --bridge-poll-interval-secs 10
```

`scripts/bridge-test-ringtail-multi.sh` automates the variant-B
override compose. Run as-is for the default 3/2-of-3 setup.

---

## 2. 5-validator testnet

The main monitoring stack at the repo root (`docker-compose.yml`)
ships 5 validators (`seal-validator-1` … `seal-validator-5`,
service names `node1`…`node5`). Used for consensus-load testing.

### 2.1 Seal validators

```bash
docker compose up -d           # from repo root
docker compose ps              # confirm all 5 Healthy
```

Ports:
- `node1` RPC → `:8545` (only node1 publishes externally by default)
- `node2`…`node5` RPC → reachable container-internal on `:8545`,
  not host-mapped.

For host-side access to the other nodes, edit `docker-compose.yml`
to add port mappings (`"8546:8545"`, `"8547:8545"`, …) or attach
to the `sealnet` network from a sidecar.

### 2.2 Bridge committee variants

| Variant | N_b | M | Validators that sign | What it tests |
|---------|-----|---|-----------------------|---------------|
| **A — Subset 3-of-5** | 3 | 2 | node1..3 | Smaller committee than consensus set — common production shape. |
| **B — Full 3-of-5** | 5 | 3 | node1..5 | All consensus validators also in the bridge committee. |
| **C — Full 4-of-5** | 5 | 4 | node1..5 | Stricter threshold (tolerates 1 fault, not 2). |

**Variant A** (N_b=3 < N_v=5) — only `node1`, `node2`, `node3`
get the `--bridge-ringtail-*` flags. `node4`, `node5` run
consensus but stay out of the bridge signing path.

**Variant B** (N_b=5) — every validator gets the flags, with
`--bridge-ringtail-party-id 0..4`.

### 2.3 Override compose for the 5-validator stack

A ready-to-use override is committed at
[`bridges/docker-compose.ringtail-5.override.yml`](../bridges/docker-compose.ringtail-5.override.yml).
Apply with:

```bash
docker compose -f docker-compose.yml \
               -f bridges/docker-compose.ringtail-5.override.yml \
               up -d
```

The committed file is **Variant B (3-of-5 full)** — all 5
validators in the committee, threshold 3. For Variant A (3-of-5
subset, only node1..3 sign) or Variant C (4-of-5), edit the
override or use the manual flags below.

The full yaml is reproduced here for the operator who wants to
hand-tune it:

```yaml
# 5-validator Ringtail override — Variant B (3-of-5 full committee).
# Apply with:
#   docker compose -f docker-compose.yml \
#                  -f docker-compose.ringtail-5.override.yml up -d
services:
  node1: { volumes: [ "./bridges/ringtail-keys/validator-1.json:/data/ringtail-keypair.json:ro" ],
           command: [ "--slots","0","--port","4001","--rpc-port","8545","--rpc-external","--data-dir","/data",
                      "--bridge-ringtail-keypair-file","/data/ringtail-keypair.json",
                      "--bridge-ringtail-mac-key-hex","2222222222222222222222222222222222222222222222222222222222222222",
                      "--bridge-ringtail-party-id","0",
                      "--bridge-ringtail-threshold","3",
                      "--bridge-ringtail-committee-size","5",
                      "--bridge-poll-interval-secs","10" ] }
  node2: { volumes: [ "./bridges/ringtail-keys/validator-2.json:/data/ringtail-keypair.json:ro" ],
           command: [ "--slots","0","--port","4001","--rpc-port","8545","--rpc-external","--data-dir","/data",
                      "--bootstrap-peers","/dns4/seal-validator-1/tcp/4001",
                      "--bridge-ringtail-keypair-file","/data/ringtail-keypair.json",
                      "--bridge-ringtail-mac-key-hex","2222222222222222222222222222222222222222222222222222222222222222",
                      "--bridge-ringtail-party-id","1",
                      "--bridge-ringtail-threshold","3",
                      "--bridge-ringtail-committee-size","5",
                      "--bridge-poll-interval-secs","10" ] }
  node3: { volumes: [ "./bridges/ringtail-keys/validator-3.json:/data/ringtail-keypair.json:ro" ],
           command: [ "--slots","0","--port","4001","--rpc-port","8545","--rpc-external","--data-dir","/data",
                      "--bootstrap-peers","/dns4/seal-validator-1/tcp/4001",
                      "--bridge-ringtail-keypair-file","/data/ringtail-keypair.json",
                      "--bridge-ringtail-mac-key-hex","2222222222222222222222222222222222222222222222222222222222222222",
                      "--bridge-ringtail-party-id","2",
                      "--bridge-ringtail-threshold","3",
                      "--bridge-ringtail-committee-size","5",
                      "--bridge-poll-interval-secs","10" ] }
  node4: { volumes: [ "./bridges/ringtail-keys/validator-4.json:/data/ringtail-keypair.json:ro" ],
           command: [ "--slots","0","--port","4001","--rpc-port","8545","--rpc-external","--data-dir","/data",
                      "--bootstrap-peers","/dns4/seal-validator-1/tcp/4001",
                      "--bridge-ringtail-keypair-file","/data/ringtail-keypair.json",
                      "--bridge-ringtail-mac-key-hex","2222222222222222222222222222222222222222222222222222222222222222",
                      "--bridge-ringtail-party-id","3",
                      "--bridge-ringtail-threshold","3",
                      "--bridge-ringtail-committee-size","5",
                      "--bridge-poll-interval-secs","10" ] }
  node5: { volumes: [ "./bridges/ringtail-keys/validator-5.json:/data/ringtail-keypair.json:ro" ],
           command: [ "--slots","0","--port","4001","--rpc-port","8545","--rpc-external","--data-dir","/data",
                      "--bootstrap-peers","/dns4/seal-validator-1/tcp/4001",
                      "--bridge-ringtail-keypair-file","/data/ringtail-keypair.json",
                      "--bridge-ringtail-mac-key-hex","2222222222222222222222222222222222222222222222222222222222222222",
                      "--bridge-ringtail-party-id","4",
                      "--bridge-ringtail-threshold","3",
                      "--bridge-ringtail-committee-size","5",
                      "--bridge-poll-interval-secs","10" ] }
```

For **Variant A (subset 3-of-5)**, drop the `--bridge-ringtail-*`
block from `node4` and `node5` and change `--bridge-ringtail-committee-size`
on node1..3 from `5` to `3`.

For **Variant C (4-of-5)**, set `--bridge-ringtail-threshold` to
`4` on all five.

---

## 3. 7-validator testnet

A ready-to-use 7-validator docker stack is committed at
[`bridges/docker-compose.ringtail-7.override.yml`](../bridges/docker-compose.ringtail-7.override.yml).
It extends the 3-validator bridge stack at
`bridges/docker-compose.testnet.yml` with 4 additional validators
(seal-4 … seal-7), all wired with Ringtail flags for
**Variant A (5-of-7 full committee)** — the recommended
pre-mainnet shape, tolerates 2 simultaneous faults.

Apply with:

```bash
cd bridges
docker compose -f docker-compose.testnet.yml \
               -f docker-compose.ringtail-7.override.yml \
               up -d
```

Smoke-test with:

```bash
./scripts/bridge-test-ringtail-7.sh
```

Alternatively, for a non-docker host-process run (no Solana +
Stellar local stack), use `scripts/testnet.sh 7`.

### 3.1 Seal validators — `scripts/testnet.sh` path

```bash
./scripts/testnet.sh 7
```

Spawns 7 host-side `seal-node` processes:
- `node-1` … `node-7` data dirs under `testnet-data/`
- P2P ports `4001..4007`
- RPC ports `8545..8551`
- node-1 is bootstrap; node-2..7 dial it

### 3.2 Bridge committee variants

| Variant | N_b | M | Validators that sign | What it tests |
|---------|-----|---|-----------------------|---------------|
| **A — Subset 5-of-7** | 7 | 5 | all | Pre-mainnet shape. Tolerates 2 simultaneous faults. |
| **B — Subset 4-of-5** | 5 | 4 | node-1..5 | 5-validator committee living inside a 7-validator consensus set. |
| **C — Subset 3-of-3** | 3 | 2 | node-1..3 | Bridge committee MUCH smaller than consensus; cheap to operate, useful for testing the "non-signing validators stay quiet" path. |

### 3.3 Manual 7-validator launch with Ringtail flags

Pick variant A (full 5-of-7) — every validator runs:

```bash
PARTY_ID=$((${NODE_ID} - 1))   # 0..6 from node-1..node-7
./target/release/seal-node --slots 0 \
    --port $((4000 + ${NODE_ID})) \
    --rpc-port $((8544 + ${NODE_ID})) \
    --rpc-external \
    --data-dir testnet-data/node-${NODE_ID} \
    --bootstrap-peers /ip4/127.0.0.1/tcp/4001 \
    --bridge-ringtail-keypair-file bridges/ringtail-keys/validator-${NODE_ID}.json \
    --bridge-ringtail-mac-key-hex 2222222222222222222222222222222222222222222222222222222222222222 \
    --bridge-ringtail-party-id ${PARTY_ID} \
    --bridge-ringtail-threshold 5 \
    --bridge-ringtail-committee-size 7 \
    --bridge-poll-interval-secs 10
```

(Skip `--bootstrap-peers` on node-1.)

For variant B (5-of-5 sub-committee inside a 7-validator
consensus), drop the `--bridge-ringtail-*` block from node-6 and
node-7 entirely and use `--bridge-ringtail-threshold 4
--bridge-ringtail-committee-size 5` on node-1..5.

---

## 4. Validation checklist (any N_v / N_b combo)

After bring-up, run these from any host that can reach all
validators' RPC ports:

```bash
# 1. Every validator's orchestrator is active
for port in 8545 8546 8547 ...; do
    curl -sX POST http://127.0.0.1:$port \
         -H 'content-type: application/json' \
         -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeRingtailStatus"}' \
         | jq -r "\"port=$port  active=\\(.result.orchestrator_active)  feature=\\(.result.feature_compiled_in)\""
done
# Expect: every port active=true feature=true

# 2. All signing validators report the same committee_key_hash
for port in <signing validator ports>; do
    curl -sX POST http://127.0.0.1:$port \
         -H 'content-type: application/json' \
         -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeGetCommitteeKeyStatus"}' \
         | jq -r ".result.committee_key_hash_sha3"
done | sort -u | wc -l
# Expect: 1 (single unique hash)

# 3. Non-signing validators are silent on the orchestrator
#    (orchestrator_active=false on the non-committee tail)

# 4. Trigger a withdrawal; watch session_count blink across
#    signing validators only:
seal-cli bridge-withdraw --recipient <chain-address> --amount 0.01
# poll session_count on each port; ALL signing validators should
# briefly show session_count >= 1, then return to 0. Non-signing
# validators stay at 0 throughout.
```

Tracked smoke scripts (one per validator count):

| Stack | Smoke script | Compose files |
|-------|--------------|---------------|
| 3-validator | `scripts/bridge-test-ringtail-multi.sh` | `bridges/docker-compose.testnet.yml` (auto-generates override inline) |
| 5-validator | `scripts/bridge-test-ringtail-5.sh` | `docker-compose.yml` + `bridges/docker-compose.ringtail-5.override.yml` |
| 7-validator | `scripts/bridge-test-ringtail-7.sh` | `bridges/docker-compose.testnet.yml` + `bridges/docker-compose.ringtail-7.override.yml` |

All three smoke scripts share the same logic: wait for every
node to report `orchestrator_active=true`, then assert
cross-validator convergence of `committee_signature_hex` once a
withdrawal has been driven through the stack.

---

## 5. Cross-VPN multi-machine (real testnet)

Replace `127.0.0.1` with VPN hostnames or VPC private IPs. The
`--bootstrap-peers` multiaddr supports DNS:

```bash
--bootstrap-peers /dns4/seal-validator-1.vpn.internal/tcp/4001
```

See [`docs/GUIDE-OPERATOR.md`](GUIDE-OPERATOR.md#vpn-multi-machine-setup)
for the WireGuard + DNS setup.

For 3-/5-/7-machine layouts that mirror this doc's variants:
- 3 machines: one validator each. Pick committee variant B
  (2-of-3 full).
- 5 machines: one validator each. Pick A (3-of-5 subset) for
  smaller bridge-committee surface area or B (3-of-5 full) for
  full participation.
- 7 machines: one validator each. Pick A (5-of-7 full) — the
  recommended pre-mainnet shape.

---

## See also

- [`docs/RUNBOOK-TESTNET-OPERATOR.md`](RUNBOOK-TESTNET-OPERATOR.md)
  — full end-to-end operator runbook (deploy + flip + fund + smoke).
- [`docs/RINGTAIL-TESTNET.md`](RINGTAIL-TESTNET.md) — Ringtail
  bring-up overview.
- [`scripts/bridge-test-ringtail-multi.sh`](../scripts/bridge-test-ringtail-multi.sh)
  — reference smoke for the 3-validator default. Template for 5/7.
