# Backup and Restore Procedures

> **Goal:** Preserve Seal DAO state so it can be recovered after
> any failure: single-node crash, host loss, data corruption,
> or full network disaster.
>
> **Date:** 2026-05-31
>
> **Related:** [NODE-FAILURE-RECOVERY.md](NODE-FAILURE-RECOVERY.md),
> [STATE-SYNC.md](STATE-SYNC.md),
> [KEYS-KMS-BRIDGE-OPS.md](KEYS-KMS-BRIDGE-OPS.md),
> [RUNBOOK-TESTNET-OPERATOR.md](RUNBOOK-TESTNET-OPERATOR.md)

---

## 1. What to back up

| Category | What | Why | Frequency |
|--|--|--|--|
| **Chain state** | Ledger + HAMT tables | Rebuild node from scratch | Daily snapshot + continuous WAL |
| **Validator key** | `$DATA_DIR/validator-key.json` | Re-identify on new host | Immediate copy on generation |
| **Bridge keys** | Committee key, Ringtail shares | Sign withdrawals | Encrypted off-host |
| **KMS trust store** | `trust_store.json` | Node pairing authority | Every change |
| **Governance state** | Council members, proposals | Continuity of governance | On every state change |
| **Bridge contract IDs** | `.solana-devnet-program-id`, `.stellar-testnet-contract-id` | Observer wiring | On every deploy |
| **Relayer keys** | Solana/Stellar relayer accounts | Fund bridge withdrawals | Encrypted off-host |
| **Docker volumes** | All named volumes | Full state export | On demand |

---

## 2. Chain state backup

### 2.1 Docker volume backup (simplest)

```bash
# Backup all chain state
docker run --rm \
  -v seal-1-data:/source:ro \
  -v $(pwd)/backups:/dest \
  alpine tar czf /dest/seal-1-$(date +%Y%m%d-%H%M%S).tar.gz -C /source .

# Backup all nodes at once
for vol in seal-1-data seal-2-data seal-3-data solana-ledger stellar-data; do
  docker run --rm \
    -v "${vol}:/source:ro" \
    -v $(pwd)/backups:/dest \
    alpine tar czf "/dest/${vol}-$(date +%Y%m%d-%H%M%S).tar.gz" -C /source .
done
```

### 2.2 In-node snapshot (protocol-level)

Use the state sync snapshot protocol ([STATE-SYNC.md](STATE-SYNC.md)):

```bash
# Take a snapshot at current tip
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_takeSnapshot","params":{}}' \
  | jq -r '.result.manifest_path'

# Download the snapshot
seal-cli snapshot export \
  --node http://localhost:8645 \
  --output ~/backups/snapshot-latest.tar.gz

# Verify integrity before restoring
seal-cli snapshot verify \
  --manifest ~/backups/snapshot-latest/manifest.json \
  --chunk-dir ~/backups/snapshot-latest/chunks
```

### 2.3 Automated backup schedule

```bash
#!/usr/bin/env bash
# scripts/backup-chain-state.sh — daily chain state backup

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/seal-dao}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"

echo "[$TIMESTAMP] Starting chain state backup..."

# Docker volume backup
for vol in seal-1-data seal-2-data seal-3-data; do
  docker run --rm \
    -v "${vol}:/source:ro" \
    -v "${BACKUP_DIR}:/dest" \
    alpine tar czf "/dest/${vol}-${TIMESTAMP}.tar.gz" -C /source .
  echo "  [ok] ${vol}"
done

# In-node snapshot
curl -sf http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_takeSnapshot","params":{}}' \
  > /dev/null 2>&1 && echo "  [ok] snapshot taken" || echo "  [!!] snapshot failed"

# Rotate old backups
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +${RETENTION_DAYS} -delete

echo "[$TIMESTAMP] Backup complete. Files in $BACKUP_DIR:"
ls -lh "$BACKUP_DIR" | tail -20
```

Cron entry:

```cron
# Daily at 03:00
0 3 * * * /home/operator/seal-dao/scripts/backup-chain-state.sh >> /var/log/seal-backup.log 2>&1
```

---

## 3. Key backup

### 3.1 Validator key

The validator key identifies your node in the consensus protocol.
If lost, you cannot produce blocks with your identity.

```bash
# Copy immediately after key generation
cp ~/.config/seal/validator-key.json ~/backups/keys/validator-key.json.enc

# Encrypt with a separate passphrase (never store plaintext off-host)
gpg --symmetric --cipher-algo AES256 \
  --output ~/backups/keys/validator-key.json.gpg \
  ~/backups/keys/validator-key.json
```

**Storage recommendations:**
- **Primary:** Encrypted USB drive, stored in a physically secure location
- **Secondary:** GPG-encrypted copy in an encrypted cloud storage bucket
- **Split:** Shamir-split the GPG passphrase among 3 council members

### 3.2 Bridge committee key

```bash
# The committee key is stored in bridges/.bridge-committee-key.hex
# Encrypt and copy off-host immediately
gpg --symmetric --cipher-algo AES256 \
  --output bridges/.bridge-committee-key.hex.gpg \
  bridges/.bridge-committee-key.hex

# Also backup the Solana program ID and Stellar contract ID
for f in bridges/.solana-devnet-program-id bridges/.stellar-testnet-contract-id; do
  [ -f "$f" ] && gpg --symmetric --cipher-algo AES256 --output "${f}.gpg" "$f"
done
```

### 3.3 Bridge withdrawal keys (relayer)

```bash
# Relayer keys fund the actual unlock transactions
gpg --symmetric --cipher-algo AES256 \
  --output bridges/.relayer-keys.json.gpg \
  bridges/.relayer-keys.json
```

### 3.4 KMS trust store

```bash
# KMS trust store — the authority for node pairing
cp ~/.local/share/seal-kms/trust_store.json ~/backups/keys/trust_store.json
gpg --symmetric --cipher-algo AES256 \
  --output ~/backups/keys/trust_store.json.gpg \
  ~/backups/keys/trust_store.json
```

### 3.5 Key backup checklist

After initial setup, verify:

```bash
# Verify all encrypted keys can be decrypted
for f in ~/backups/keys/*.gpg; do
  gpg --decrypt --dry-run "$f" > /dev/null 2>&1 && \
    echo "[ok] $(basename $f)" || \
    echo "[!!] $(basename $f) — DECRYPTION FAILED"
done
```

---

## 4. Governance state backup

### 4.1 TechnicalCouncil (auto-persisted)

The `TechnicalCouncil` is JSON-persisted to disk. Location:
`$DATA_DIR/governance/technical_council.json`.

```bash
# Backup governance state
cp "$DATA_DIR/governance/technical_council.json" ~/backups/keys/
gpg --symmetric --cipher-algo AES256 \
  --output ~/backups/keys/technical_council.json.gpg \
  ~/backups/keys/technical_council.json

# Also back up ServiceOperatorsCouncil and governance proposals
cp "$DATA_DIR/governance/service_operators.json" ~/backups/keys/
cp "$DATA_DIR/governance/proposals.json" ~/backups/keys/
```

### 4.2 Council member key backup

Each council member holds an ML-DSA keypair. Back up each member's
key individually:

```bash
# Per-council-member backup
mkdir -p ~/backups/keys/council-member-$(id -n)/
seal-keygen export --output ~/backups/keys/council-member-$(id -n)/ml-dsa-key.json
gpg --symmetric --cipher-algo AES256 \
  --output ~/backups/keys/council-member-$(id -n)/ml-dsa-key.json.gpg \
  ~/backups/keys/council-member-$(id -n)/ml-dsa-key.json
```

---

## 5. Restore procedures

### 5.1 Restore a single node from volume backup

```bash
# 1. Stop the node
docker compose stop seal-1

# 2. Remove the current (possibly corrupted) volume
docker volume rm seal-1-data

# 3. Create a fresh volume and restore
docker create -v seal-1-data alpine /tmp
docker run --rm \
  -v seal-1-data:/dest \
  -v $(pwd)/backups:/source \
  alpine sh -c 'mkdir -p /dest && tar xzf /source/seal-1-20260531-030000.tar.gz -C /dest'

# 4. Start the node
docker compose start seal-1

# 5. Verify sync
docker logs seal-1 --tail 20
```

### 5.2 Restore from in-node snapshot

```bash
# 1. Stop the node
docker compose stop seal-1

# 2. Clear data volume
docker volume rm seal-1-data
docker volume create seal-1-data

# 3. Import snapshot
docker run --rm \
  -v seal-1-data:/data \
  -v $(pwd)/backups/snapshot-latest:/snapshot \
  seal-dao/node seal-cli snapshot import \
    --manifest /snapshot/manifest.json \
    --chunk-dir /snapshot/chunks

# 4. Start node
docker compose start seal-1

# 5. Verify state root
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getStateRoot","params":{}}'
```

### 5.3 Restore all nodes from snapshot

```bash
#!/usr/bin/env bash
# scripts/restore-from-snapshot.sh — full cluster restore

set -euo pipefail

SNAPSHOT_DIR="${1:?Usage: $0 <snapshot-directory>}"

echo "Restoring all nodes from snapshot..."

for node in seal-1 seal-2 seal-3; do
  vol="${node/-/ }-data"  # e.g., seal-1-data
  echo "  Restoring $node..."
  docker compose stop "$node"
  docker volume rm "$vol" 2>/dev/null || true
  docker volume create "$vol"
  docker run --rm \
    -v "${vol}:/data" \
    -v "${SNAPSHOT_DIR}:/snapshot" \
    seal-dao/node seal-cli snapshot import \
      --manifest /snapshot/manifest.json \
      --chunk-dir /snapshot/chunks
  docker compose start "$node"
  echo "  [ok] $node restored"
done

echo "All nodes restored. Verify with:"
echo "  curl -s http://localhost:8645/health"
```

### 5.4 Restore keys

```bash
# Decrypt validator key
gpg --decrypt ~/backups/keys/validator-key.json.gpg \
  > ~/.config/seal/validator-key.json
chmod 600 ~/.config/seal/validator-key.json

# Decrypt committee key
gpg --decrypt ~/backups/keys/.bridge-committee-key.hex.gpg \
  > bridges/.bridge-committee-key.hex
chmod 600 bridges/.bridge-committee-key.hex

# Decrypt trust store
gpg --decrypt ~/backups/keys/trust_store.json.gpg \
  > ~/.local/share/seal-kms/trust_store.json

# Verify trust store integrity
seal-kms-cli trust list  # should list all paired nodes
```

---

## 6. Disaster recovery: full network restore

When all nodes are lost (e.g., cloud provider outage):

### 6.1 Prerequisites

| Item | Needed |
|--|--|
| Validator keys (all N validators) | From key backup (§3) |
| Chain state snapshot (most recent) | From snapshot backup (§2) |
| Bridge contract IDs | From contract ID backup |
| Committee key | From bridge key backup |
| Governance state | From governance backup (§4) |
| New infrastructure | N+1 hosts (N = validator count) |

### 6.2 Restore sequence

```
1. Provision new infrastructure (N+1 hosts minimum)
2. Install seal-node + dependencies on all hosts
3. Restore validator keys to each host
4. Restore chain state from latest snapshot
5. Start nodes in order: seal-1 first (initializes gossip)
6. Add remaining nodes via --boot-nodes flag
7. Verify: all N+1 nodes reach same tip height
8. Verify: governance state loaded (council, proposals)
9. Verify: bridge observers connected to source chains
10. Resume normal operations
```

```bash
# Bootstrap the cluster (run on first node)
docker compose up -d seal-1

# Add peers to remaining nodes (add to docker-compose.yml before up)
#   environment:
#     - SEAL_BOOT_NODES=/dns/seal-1/tcp/8000
#
# Run on remaining nodes:
for i in 2 3 4; do
  docker compose up -d seal-$i
done

# Wait for full mesh
sleep 30
for port in 8645 8646 8647 8648; do
  echo -n "Port $port height: "
  curl -sf http://localhost:$port \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBlockHeight","params":{}}' \
    | jq -r '.result // "unreachable"'
done
```

### 6.3 Verifying post-restore integrity

```bash
# 1. All nodes at same height
HEIGHTS=$(for port in 8645 8646 8647; do
  curl -sf http://localhost:$port \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBlockHeight","params":{}}' \
    | jq -r '.result'
done)
UNIQUE=$(echo "$HEIGHTS" | sort -u | wc -l)
echo "Node heights: $HEIGHTS"
echo "Unique heights: $UNIQUE (should be 1)"

# 2. State root matches snapshot
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getStateRoot","params":{}}' \
  | jq -r '.result.state_root_hex'

# 3. Governance state loaded
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_governanceState","params":{}}' \
  | jq '.council_size, .active_proposals'

# 4. Bridge observers active
curl -s http://localhost:8645 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}' \
  | jq '.length'
echo "observers registered (should be > 0)"
```

---

## 7. Backup verification

Backups are worthless if they can't be restored. **Test restores
monthly.**

### 7.1 Automated verification script

```bash
#!/usr/bin/env bash
# scripts/verify-backups.sh — test backup integrity

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/seal-dao}"
FAILED=0

echo "=== Backup Verification ==="
echo ""

# 1. Check backup file integrity
echo "[1/4] File integrity..."
for f in "$BACKUP_DIR"/*.tar.gz; do
  if gzip -t "$f" 2>/dev/null; then
    echo "  [ok] $(basename $f)"
  else
    echo "  [!!] $(basename $f) — CORRUPT"
    FAILED=1
  fi
done

# 2. Check encrypted key decryption
echo "[2/4] Key decryption..."
for f in ~/backups/keys/*.gpg; do
  if [ -f "$f" ]; then
    if gpg --decrypt --dry-run "$f" > /dev/null 2>&1; then
      echo "  [ok] $(basename $f)"
    else
      echo "  [!!] $(basename $f) — CANNOT DECRYPT"
      FAILED=1
    fi
  fi
done

# 3. Spot-check snapshot restore (to temp volume)
echo "[3/4] Snapshot restore test..."
LATEST_SNAPSHOT=$(ls -t "$BACKUP_DIR"/snapshot-*.tar.gz 2>/dev/null | head -1)
if [ -n "$LATEST_SNAPSHOT" ]; then
  TEMP_VOL=$(docker volume create)
  docker run --rm \
    -v "${TEMP_VOL}:/dest" \
    -v "${LATEST_SNAPSHOT%.gz}:/snapshot" \
    alpine tar xzf /snapshot -C /dest 2>/dev/null && \
    echo "  [ok] snapshot extracts correctly" || \
    echo "  [!!] snapshot extraction failed"
  docker volume rm "$TEMP_VOL" 2>/dev/null || true
else
  echo "  [!!] no snapshot backups found"
  FAILED=1
fi

# 4. Check backup freshness
echo "[4/4] Backup freshness..."
OLDEST_BACKUP=$(find "$BACKUP_DIR" -name "*.tar.gz" -printf '%T@\n' | sort -n | head -1)
if [ -n "$OLDEST_BACKUP" ]; then
  AGE_HOURS=$(( ($(date +%s) - $(printf "%.0f" $OLDEST_BACKUP)) / 3600 ))
  if [ "$AGE_HOURS" -lt 48 ]; then
    echo "  [ok] most recent backup is ${AGE_HOURS}h old"
  else
    echo "  [!!] most recent backup is ${AGE_HOURS}h old (should be < 48h)"
    FAILED=1
  fi
fi

echo ""
if [ "$FAILED" -eq 1 ]; then
  echo "VERIFICATION FAILED — check logs"
  exit 1
fi
echo "ALL CHECKS PASSED"
```

### 7.2 Verification schedule

| Check | Frequency | Who |
|--|--|--|
| File integrity (gzip -t) | Daily (automated) | Cron |
| Key decryption test | Daily (automated) | Cron |
| Full restore test | Monthly | Operator |
| Cross-region restore | Quarterly | DR team |
| Key rotation + re-backup | After any key change | Operator |

---

## 8. Backup architecture recommendations

### 8.1 Production setup (multi-region)

```
                    ┌──────────────────────────────────┐
                    │        Region A (primary)         │
                    │                                   │
              ┌─────┼─────┐       ┌────────────────┐   │
              │     │     │       │  Backup server   │   │
         ┌────┴─┐ ┌─┴──┐ ┌─┴──┐   │  (encrypted)    │   │
         │ N1   │ │ N2 │ │ N3 │──>│  rsync + gpg    │   │
         └──────┘ └────┘ └────┘   └────────────────┘   │
                         │                              │
                    ┌────┴──────────────────────────┐   │
                    │   Cross-region replication     ├───┘
                    │   (asynchronous, encrypted)    │
                    └────────────┬───────────────────┘
                                 │
                    ┌────────────┴───────────────────┐
                    │        Region B (dr)            │
                    │                                   │
              ┌─────┼─────┐       ┌────────────────┐   │
              │     │     │       │  Restore here   │   │
         ┌────┴─┐ ┌─┴──┐ ┌─┴──┐   │  on disaster    │   │
         │ N4   │ │ N5 │ │ N6 │   │                  │   │
         └──────┘ └────┘ └────┘   └────────────────┘   │
                    └──────────────────────────────────┘
```

### 8.2 Minimum viable backup (testnet / small teams)

```bash
# Single script: backup everything to an encrypted tarball
#!/usr/bin/env bash
# scripts/backup-all.sh — single-file full backup

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-~/backups/seal-dao}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ENCRYPTED_FILE="${BACKUP_DIR}/seal-dao-full-${TIMESTAMP}.tar.gz.gpg"

mkdir -p "$BACKUP_DIR"

# Create staging directory
STAGING=$(mktemp -d)
trap "rm -rf $STAGING" EXIT

# Gather everything
cp -r "$DATA_DIR" "$STAGING/chain-state"
cp -r bridges "$STAGING/bridges"
cp -r "$HOME/.local/share/seal-kms" "$STAGING/kms"
cp -r "$HOME/.config/seal" "$STAGING/seal-config"

# Create encrypted archive
tar czf - -C "$STAGING" . \
  | gpg --symmetric --cipher-algo AES256 \
        --batch --yes \
        --output "$ENCRYPTED_FILE" \
        --passphrase "$(cat ~/seal-backup-passphrase.txt)"

# Copy to off-site storage (adjust for your provider)
# rsync -avz "$ENCRYPTED_FILE" s3://seal-dao-backups/

echo "Full backup: $ENCRYPTED_FILE"
echo "Size: $(du -h "$ENCRYPTED_FILE" | cut -f1)"
```

---

## 9. Quick reference

### Restore in an emergency

```bash
# 1-minute decision tree:

# Node crashed?                                          → docker compose restart
# Node lagging?                                         → docker compose restart + check peers
# Disk full?                                            → clean old logs, increase disk
# Key lost?                                             → restore from backup (§5.4)
# All nodes lost?                                       → §6 full network restore
# Data corrupted?                                       → §5.1 volume restore
# Snapshot needed?                                      → seal-cli snapshot export
# Backup failed?                                        → scripts/verify-backups.sh
```

### Key file locations

| Key | Default path | Backup priority |
|--|--|--|
| Validator key | `$DATA_DIR/validator-key.json` | **CRITICAL** — restore immediately |
| Committee key | `bridges/.bridge-committee-key.hex` | **CRITICAL** — bridge operations |
| KMS trust store | `~/.local/share/seal-kms/trust_store.json` | **HIGH** — node pairing |
| Relayer keys | `bridges/.relayer-keys.json` | **HIGH** — withdrawal funding |
| Council member key | operator-dependent | **CRITICAL** — governance |
| Bridge contract IDs | `bridges/.solana-devnet-program-id` | MEDIUM — re-queryable |
| Bridge contract IDs | `bridges/.stellar-testnet-contract-id` | MEDIUM — re-queryable |
