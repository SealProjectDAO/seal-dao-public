# Seal DAO Monitoring

Prometheus + Grafana monitoring stack for Seal DAO nodes.

## Quick start

```bash
# 1. Start a seal-node with RPC enabled
cargo run -p seal-node -- --slots 0 --rpc-port 8545

# 2. Start the monitoring stack
cd monitoring
docker-compose -f docker-compose.monitoring.yml up -d

# 3. Open dashboards
open http://localhost:3000  # Grafana (admin/admin)
open http://localhost:9090  # Prometheus
```

## Endpoints on the seal-node

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness probe (height, peers, uptime) |
| `/metrics` | GET | Prometheus exposition format |
| `/status` | GET | Rich JSON status for dashboards |
| `seal_getNodeInfo` | RPC | Node info (version, epoch, validators) |

## Dashboards

### Seal Node Overview (`seal-node.json`)
- Chain height, peers, uptime, active leases
- Block production rate (blocks/min)
- Transaction throughput (submitted, accepted, rejected)
- SQL operations (queries/min, writes/min)
- Fee economics (collected vs burned)
- Bridge row: committee-key set (red when 0), paused chains
  (red when >0), pending deposits, total withdrawals, +
  queue-depth timeseries
- Faucet row: drip rate + rejection breakdown (cooldowns vs
  bad-address) so testnet operators can spot keypair drain and
  scripted abuse in one glance
- Registration row: validator-count stat + accepts/duplicates/
  signature-failures timeseries

## Alert rules (`alert.rules.yml`)

Bridge-state alerts auto-loaded by Prometheus on startup. Each
rule's `description` annotation lists the operator action.

| Alert | Severity | Fires when |
|-------|----------|------------|
| `BridgeCommitteeKeyUnset` | critical | `seal_bridge_committee_key_set == 0` for 5m |
| `BridgeChainPaused` | warning | `seal_bridge_paused_chains > 0` for 2m |
| `BridgeDepositsBacklog` | warning | `seal_bridge_deposits_pending > 20` for 5m |
| `BridgeCommitteeKeyFingerprintDrift` | critical | multiple fingerprint label values for an instance within 1m |
| `BridgeCommitteeKeyRotationNotPersisted` | warning | `seal_bridge_committee_key_set == 1 and seal_bridge_committee_key_persisted == 0` for 2m — restart will revert the rotation |
| `BridgeInvariantViolated` | critical (page) | `seal_bridge_invariant_violated == 1` for 1m — total_minted > total_locked on at least one wrapped token |
| `BridgeTokenSupplyMismatch` | critical | `seal_bridge_total_minted{token} - seal_bridge_total_locked{token} > 0` for 30s — names the broken asset in the alert label |
| `FaucetUpstreamFailures` | warning | `rate(seal_faucet_upstream_failures[5m]) > 0.1` — drained keypair or unhealthy seal-node target |
| `FaucetCooldownRejectionSpike` | warning | `rate(seal_faucet_cooldown_rejections_ip[2m]) > 1` — scripted abuse or stuck client |
| `RegistrationSignatureFailures` | warning | `rate(seal_registration_signature_failures[10m]) > 0.05` — wrong-key paste, canonical-message drift, or fuzzing |
| `RegistrationPersistFailures` | critical | `seal_registration_persist_failures > 0` for 1m — disk full / permission on the JSONL store path |

Inspect / silence in Prometheus → http://localhost:9090/alerts.

## Testnet deployment

For multi-node testnet, update `prometheus.yml` to scrape all nodes:

```yaml
scrape_configs:
  - job_name: 'seal-testnet'
    static_configs:
      - targets:
        - 'node1.testnet.seal-dao.org:8545'
        - 'node2.testnet.seal-dao.org:8545'
        - 'node3.testnet.seal-dao.org:8545'
```
