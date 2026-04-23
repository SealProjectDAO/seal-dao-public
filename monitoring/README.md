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
