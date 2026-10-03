# Seal DAO Bug Bounty Program

**Platform**: Immunefi (https://immunefi.com)
**Program Type**: Boosted Bug Bounty
**Status**: Pre-mainnet (active upon publication)

---

## Program Overview

Seal DAO invites security researchers to find vulnerabilities in the Seal
blockchain protocol. This is a PQC-native L1 with a distributed SQL layer.
All findings should be reported through Immunefi.

---

## Rewards

### Smart Contracts & Blockchain

| Severity | Max Reward | Examples |
|----------|------------|---------|
| Critical | $100,000 | Consensus break, unauthorized token minting, private key extraction |
| High | $50,000 | Double-spend, state corruption, RLS bypass, bridge drain |
| Medium | $10,000 | Validator forced ejection, governance manipulation, fee evasion |
| Low | $2,000 | Information leak, non-critical DoS, logging of secrets |

### Cryptography

| Severity | Max Reward | Examples |
|----------|------------|---------|
| Critical | $100,000 | VRF predictability, threshold sig forgery, ML-DSA misuse enabling forgery |
| High | $75,000 | Nonce reuse, weak Gaussian sampling, NTT correctness failure |
| Medium | $25,000 | Side-channel in non-constant-time code, key material not zeroized |
| Low | $5,000 | Suboptimal parameter choices, missing validation on non-critical paths |

### Websites & Applications

| Severity | Max Reward |
|----------|------------|
| Critical | $10,000 |
| High | $5,000 |
| Medium | $2,000 |
| Low | $500 |

**Payment**: USDC on Ethereum mainnet (or SEAL tokens post-mainnet, at
researcher's choice).

---

## Scope

### In Scope

| Target | Type | Repository |
|--------|------|------------|
| Consensus engine | Blockchain | `crates/seal-consensus/` |
| Cryptographic primitives | Blockchain | `crates/seal-crypto/` |
| VRF constructions | Blockchain | `crates/seal-vrf/` |
| Threshold signatures | Blockchain | `crates/seal-threshold/` |
| Token economics | Blockchain | `crates/seal-token/` |
| SQL engine + RLS | Blockchain | `crates/seal-sql/` |
| Bridge | Blockchain | `crates/seal-bridge/` |
| P2P networking | Blockchain | `crates/seal-p2p/` |
| Merkle state tree | Blockchain | `crates/seal-merkle/` |
| MPC protocols | Blockchain | `crates/seal-mpc/` |
| TEE attestation | Blockchain | `crates/seal-tee/` |
| ZK proof system | Blockchain | `crates/seal-zk/` |
| Node binary | Blockchain | `crates/seal-node/` |
| CLI wallet | Application | `crates/seal-cli/` |

### Out of Scope

- **Vendored dependencies** — report upstream to the dependency maintainer
- **Known limitations** documented in `TODO.md`
- **Test-only code** (`#[cfg(test)]` blocks, `tests/` directories)
- **Documentation errors** (typos, formatting)
- **Stub implementations** marked with `// TODO: Replace with...`
- **Denial of service** via resource exhaustion (unless it affects consensus)
- **Social engineering** attacks
- **Physical attacks** on hardware
- **Issues in `libcrux`** — report to Cryspen (https://cryspen.com)

---

## Severity Classification

We use the [Immunefi Severity Classification System v2.3](https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/).

### Critical

Impacts that would cause direct loss of funds or permanent protocol failure:
- Consensus safety violation (conflicting finalized blocks)
- Unauthorized minting or burning of tokens
- Private key extraction from public data
- Bridge fund drain
- VRF output prediction enabling guaranteed leader election

### High

Impacts that could cause significant damage but require specific conditions:
- Double-spend requiring >1/3 stake collusion
- State root manipulation
- RLS bypass exposing private data
- Governance proposal execution without quorum
- Threshold signature forgery with <threshold participants

### Medium

Impacts that degrade protocol guarantees:
- Temporary consensus stall (<1 epoch)
- Fee mechanism manipulation
- Delegation cap bypass
- Slashing of honest validators via crafted evidence
- Memory leak in long-running nodes

### Low

Minor issues with limited impact:
- Information disclosure (node version, peer list)
- Non-critical assertion failures
- Inefficient resource usage
- Missing input validation on non-security-critical paths

---

## Rules

1. **First come, first served** — duplicates receive no reward
2. **Responsible disclosure** — do not disclose publicly before fix is deployed
3. **No mainnet attacks** — test only on local devnet or testnet
4. **Proof of concept required** — provide a working PoC or detailed reproduction steps
5. **One vulnerability per report** — submit separate reports for separate issues
6. **No automated scanning** — findings from automated scanners without manual validation are ineligible

---

## How to Test

```bash
# Clone the repository
git clone https://github.com/seal-dao/seal-dao.git
cd seal-dao

# Build
cargo build

# Run tests
cargo test

# Launch local devnet (1s slots, single node)
cargo run -p seal-cli -- dev --slots 100

# Launch 5-validator testnet
docker compose up

# Fuzz a target
cargo +nightly fuzz run fuzz_ringtail_verify -- -max_total_time=3600
```

---

## Reporting

Submit all findings through the Immunefi platform:
https://immunefi.com/bounty/sealdao

For urgent critical vulnerabilities, also email: **security@seal-dao.org**

Include in your report:
1. **Description** of the vulnerability
2. **Impact** — what can an attacker achieve?
3. **Reproduction steps** or proof of concept
4. **Affected component** — crate name and file path
5. **Suggested fix** (optional but appreciated)

---

## Response SLA

| Severity | First Response | Triage | Fix |
|----------|---------------|--------|-----|
| Critical | 4 hours | 24 hours | 72 hours |
| High | 24 hours | 3 days | 2 weeks |
| Medium | 3 days | 1 week | 1 month |
| Low | 1 week | 2 weeks | Best effort |

---

## Legal

- Researchers acting in good faith under this program will not face legal action
- Testing must not affect other users, mainnet, or third-party systems
- Do not access, modify, or delete data belonging to other users
- Comply with all applicable laws

This program is governed by the [Immunefi Standard Terms](https://immunefi.com/standard-terms/).
