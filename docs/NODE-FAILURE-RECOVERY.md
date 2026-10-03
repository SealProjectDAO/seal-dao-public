# Node Failure and Consensus Liveness

> **Philosophy:** "Some of you will die, but the Corps will live forever."
> Individual nodes — validator, bridge observer, KMS sidecar — may crash,
> get network-partitioned, or be destroyed at any time. The consensus
> layer **never stops** as long as the failure budget isn't exceeded.
>
> **Date:** 2026-05-31
>
> **Related:** [STATE-SYNC.md](STATE-SYNC.md),
> [RUNBOOK-TESTNET-OPERATOR.md](RUNBOOK-TESTNET-OPERATOR.md),
> [QUICKSTART.md](../QUICKSTART.md)

---

## 1. Consensus fault tolerance guarantees

Seal uses an **Algorand-style BFT consensus** with VRF-based leader
election and committee voting. The protocol guarantees:

| Fault type | Tolerance formula | 3-validator stack | 7-validator stack | 11-validator stack |
|--|--|--|--|--|
| **Crash faults** (node dies, network drops) | $f < n \times (1 - \text{finality\_threshold})$ | $f < 1$ | $f < 2$ | $f < 3$ |
| **Byzantine faults** (misbehavior, equivocation) | $f < n / 3$ | $f < 1$ | $f < 2$ | $f < 3$ |
| **Live & safe** | $f < n \times (1 - 0.67)$ | 2 validators can die | 3 can die | 4 can die |
| **Finality broken** | $f \ge n \times 0.67$ | $\ge 2$ dead → stalls | $\ge 3$ dead → stalls | $\ge 4$ dead → stalls |

**What this means in practice:**

- A single validator crash in a 3-node stack is the worst-case that still
  allows finality — the remaining 2 can reach 2/3 = 67%.
- In a 7-node stack (production target), up to **2 crashes** are invisible
  to liveness. 3 crashes stall consensus but preserve safety (no fork).
- **Byzantine nodes** (double-proposal, double-vote) are slashed and removed
  from the active set at epoch boundary. Up to $f < n/3$ Byzantine nodes
  are tolerated safely.

### 1.1 What happens when a node dies

```
Validator N crashes or gets isolated
    │
    ▼
Other validators continue proposing blocks via VRF election
    │
    ├─ If active_count >= required_for_finality:
    │   → consensus continues normally
    │   → blocks finalize at normal slot cadence
    │
    └─ If active_count drops below threshold:
        → no proposer elected for subsequent slots
        → consensus stalls (liveness lost)
        → safety preserved (no conflicting finality)
```

The **trace module** (`seal-node/src/trace.rs`) detects equivocation,
double-voting, and monotonicity violations. Confirmed offenders are
reported to `SlashingManager` which marks them inactive at the next
epoch boundary.

### 1.2 Network partitions

A network partition splits validators into two or more islands.
Consensus continues in the **majority partition** (the one with
$\ge 2/3$ of active stake). The minority partition's nodes see:

```
[consensus loop] waiting for block proposal at slot 42
[consensus loop] no proposal received, voting for nil
[consensus loop] waiting for block proposal at slot 43
...
```

The partition heals automatically when connectivity returns.
The minority-side nodes re-sync via the standard block-replay path
(if within retention window) or snapshot sync (§4).

---

## 2. Validator node recovery

### 2.1 Identifying the failure

```bash
# Check if your node is still syncing
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBlockHeight","params":{}}'

# Compare with peers
curl -s http://<peer-ip>:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBlockHeight","params":{}}'

# Check if you're still in the validator set
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getValidatorByAddress","params":{"address":"sealt1..."}}'
```

If your block height is lagging by many slots, you've been isolated.
If your validator address returns nothing, you've been slashed.

### 2.2 Restarting a crashed validator

```bash
# 1. Stop cleanly (if container is stuck)
docker compose stop seal-1

# 2. Check logs for crash cause
docker logs seal-1 --tail 100

# 3. Start with data volume intact
docker compose start seal-1

# 4. Verify reconnection
docker logs seal-1 | grep "reconnected to gossip"
```

**State persistence:** The validator's chain data lives in a named
Docker volume (`seal-1-data`). As long as you use `docker compose down`
(not `down -v`), the ledger, state HAMT, and database persist across
restarts. The node re-joins the gossip network and catches up
automatically.

### 2.3 Recovering from a long absence

If a node has been offline for more than the snapshot retention window:

```bash
# Option A: Block replay (fast if lag < 100k blocks)
docker compose restart seal-1
# Node replays blocks from last-persisted height

# Option B: Snapshot sync (if lag > retention window)
docker compose exec seal-1 \
  seal-cli snapshot sync \
  --bootstrap http://peer1:8645,http://peer2:8645 \
  --target-height $(curl -s http://peer1:8645 -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBlockHeight","params":{}}' | jq .result)
```

See [STATE-SYNC.md](STATE-SYNC.md) for the full snapshot protocol.

### 2.4 Replacing a dead validator

If a validator is permanently lost (disk failure, compromised host):

```bash
# 1. Generate a new keypair on the replacement host
seal-keygen validator --output /data/validator-key.json

# 2. On a surviving node, update the validator set
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_addValidator","params":{
    "public_key": "<hex>",
    "vrf_public_key": "<hex>",
    "stake": 1000000
  }}'

# 3. The old validator's stake must be unbonded first
#    (governance proposal or council vote depending on config)

# 4. Start the new node with the new key
docker compose up -d seal-1
```

The old validator's stake is slashed proportionally to the downtime
(duration absent $\times$ total_stake). The new validator must stake
$\ge$ `min_stake` to enter the set.

---

## 3. Bridge observer recovery

Bridge observers are **non-critical** — they don't participate in
consensus. If an observer node dies:

```
Observer crashes
    │
    ├── No impact on consensus (validator nodes continue)
    ├── No impact on deposits (Solana/Stellar chains continue accepting locks)
    │
    └── Impact: pending lock events are not forwarded to Seal until
         another observer picks them up (delay = time until restart
         or another observer's next poll cycle)
```

**Recovery:** Simply restart the observer. On start, it polls the
source chain from its last cursor position and replays any missed
events.

```bash
docker compose restart bridge-observer-1

# Verify it caught up
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}'
```

**Multiple observers** provide redundancy. If at least one observer
is running, lock events reach the Seal chain without delay. Having
3 observers on the same source chain is recommended for production.

---

## 4. KMS sidecar failure

The KMS sidecar is **not required for consensus** or for observing
deposits. It is only needed when:

| Operation | KMS needed? | What happens if down |
|--|--|--|
| Block production | No | Validators continue |
| Bridge deposit observation | No | Observers continue polling |
| **Bridge withdrawal signing** | **Yes** | Withdrawals queue, not processed |
| **New node pairing** | **Yes** | New nodes cannot receive keys |
| Committee key rotation | Yes | Rotation cannot execute |

**Recovery:** Restart the KMS sidecar. It reloads the trust store
from disk and re-maps its Unix socket. All keys are already in
memory (LockedBuffer) or can be re-mlocked on startup.

```bash
# Restart KMS sidecar
systemctl restart seal-kms-sidecar

# Verify it's listening
ss -lx | grep seal-kms

# Check trust store integrity
seal-kms-cli trust list
```

---

## 5. Network partition scenarios

### 5.1 Single node isolated (network partition)

```
[Validator A] ←── partition ──→ [Validator B] [Validator C]
                                  ↑              ↑
                              67% stake       33% stake
                              (majority)      (minority)
```

- **B and C** continue producing blocks and finalizing.
- **A** sees timeout on every slot, sends nil votes.
- When partition heals: A re-syncs from B/C's latest block.

### 5.2 Two partitions each with < 2/3 stake

```
[Validator A] [Validator C]   │   [Validator B]
(30% stake)   (10% stake)     │   (60% stake)
       ↑                      │          ↑
    Neither has 2/3          │    Majority has 2/3
    → nil votes only         │    → produces blocks
```

Only the majority partition produces blocks. The minority partition
stalls. When healed, minority nodes catch up via block replay.

### 5.3 All nodes on same host, host crashes

This is not a network partition — it's a total failure. The chain
continues as long as at least one node survives on a different host.

**Mitigation:** Spread validators across multiple physical machines
or cloud availability zones. A single host failure should not take
down $\ge 1/3$ of the validator set.

---

## 6. Monitoring and alerting

### 6.1 Health checks

```bash
# Per-node health
curl -s http://localhost:8645/health

# Block height drift (should be < 3 slots between peers)
for port in 8645 8646 8647; do
  echo -n "Port $port: "
  curl -s http://localhost:$port \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBlockHeight","params":{}}' \
    | jq -r '.result'
done

# Committee participation (are we voting?)
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getConsensusStatus","params":{}}'
```

### 6.2 Alert thresholds

| Metric | Warning | Critical |
|--|--|--|
| Block height lag | > 10 slots from peers | > 30 slots |
| Committee participation | < 80% of slots | < 50% over 5 min |
| Peer count (gossip) | < N-1 peers | 0 peers |
| Slot missed | 1 slot | > 5 consecutive |
| Database write latency | > 100 ms | > 1 s |

---

## 7. Disaster recovery: total node loss

When a validator host is completely unrecoverable:

### 7.1 Preserve what you can

```bash
# If you still have partial SSH access:
rsync -avz /data/seal-node/ user@new-host:/data/seal-node/
rsync -avz ~/.config/seal/validator-key.json user@new-host:~/.config/seal/
```

### 7.2 Spin up replacement

```bash
# 1. New host: install seal-node + dependencies
# 2. Copy validator key from backup (or generate new + governance rotation)
cp validator-key.json /data/seal-node/validator-key.json

# 3. Configure --boot-nodes to reach the live network
docker compose up -d

# 4. Wait for sync (may take minutes to hours depending on lag)
tail -f /var/log/seal-node.log | grep "caught up to tip"
```

### 7.3 Stake transfer (if old key is unrecoverable)

If the validator key is lost and no backup exists, the stake must be
transferred to a new key via governance:

1. Token House proposes: `stake:transfer <old_addr> <new_addr> <amount>`
2. Technical Council approves (2/3 supermajority)
3. Stake moves to new validator key at next epoch boundary

---

## 8. Appendix: Consensus parameters

| Parameter | Default | Production recommendation |
|--|--|--|
| `slot_duration_ms` | 1000 | 1000-3000 (cloud: 2000-3000) |
| `slots_per_epoch` | 100 | 300-600 (faster epoch = faster slash) |
| `committee_size` | 7 | 7-11 |
| `finality_threshold_percent` | 67 | 67 (do not change) |
| `min_stake` | 100_000 | 1_000_000+ (production) |

### 8.1 Choosing your validator count

| Stack size | Max crashes (liveness) | Max crashes (safety) | Min Byzantine | Cost |
|--|--|--|--|--|
| 3 | 1 | 2 | 0 | Low |
| 5 | 1 | 3 | 1 | Medium |
| 7 | 2 | 4 | 2 | Medium-High |
| 11 | 3 | 7 | 3 | High |
| 21 | 6 | 13 | 6 | Very High |

For testnet: **7 validators** (balances resilience and cost).
For mainnet: **11+ validators** across different clouds/regions.
