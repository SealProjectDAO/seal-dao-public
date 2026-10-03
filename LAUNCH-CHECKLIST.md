# Seal DAO Mainnet Launch Checklist

**Target Chain ID**: `seal-mainnet-1`

---

## Pre-Launch (T-8 weeks to T-1 week)

### Security Audits
- [ ] Veridise PQC crypto audit — engaged
- [ ] Veridise PQC crypto audit — completed, findings remediated
- [ ] Protocol & economics audit — engaged
- [ ] Protocol & economics audit — completed, findings remediated
- [ ] All Critical/High findings fixed and verified
- [ ] Audit reports published

### Bug Bounty
- [ ] Immunefi program live (see BUG-BOUNTY.md)
- [ ] 4+ weeks of active bounty before launch
- [ ] All Critical/High bounty submissions resolved

### Formal Verification
- [x] Lean 4: 0 sorries (confirmed 2026-05-08, commit `58102e9fc`)
- [ ] Rocq/Coq: 0 Admitted (confirmed)
- [ ] Kani: all 60 harnesses pass
- [ ] Miri: 3 crates pass (seal-crypto, seal-merkle, seal-storage)
- [ ] Extended fuzz campaign: 24h per target, 0 crashes
- [ ] TLA+ model checked with Apalache (Agreement, Liveness invariants)

### Incentivized Testnet
- [ ] Phase 1 complete: 50+ validators, stable consensus
- [ ] Phase 2 complete: epoch transitions, fork recovery
- [ ] Phase 3 complete: stress test (1000 TPS sustained)
- [ ] Phase 4 complete: 72h chaos stability
- [ ] Community governance vote: "approve mainnet readiness"

### Legal / Regulatory (see docs/LEGAL-REVIEW.md — IANAL, gate with counsel)
- [ ] Per-target-market counsel opinions obtained (EU/FR, KR, JP, TW, US, CA)
- [ ] Perps / margin / prediction-market features behind region/feature flag, OFF by default for all six markets
- [ ] Geo-blocking + VPN detection + "no restricted persons" ToS on any hosted front-end; non-circumvention documented
- [ ] OFAC/SDN address + embargoed-jurisdiction screening wired into any front-end
- [ ] Confirmed: no admin keys move/freeze funds; no fee switch to controllable treasury; sequencer/proposer rotation live
- [ ] SEAL distribution structured to minimize security classification; ≤20% any single holder/voting bloc
- [ ] PII-off-chain invariant enforced in seal-sql (test/lint); erasure-by-key-destruction procedure documented
- [ ] PQC distribution = open-source, published NIST standards (FIPS 203/204/205); embargoed-destination screening
- [ ] Stablecoin handling decision per market (EU EMT / JP EPI / US GENIUS / CA VRCA)

---

## Launch Preparation (T-1 week)

### Genesis Block
- [ ] Final validator set collected (min 30 validators)
- [ ] All validator ML-DSA public keys verified
- [ ] All validator VRF public keys verified
- [ ] Genesis timestamp agreed (block T+0)
- [ ] Token distribution verified: 30/20/15/15/10/10
- [ ] `GenesisConfig::mainnet()` produces correct genesis block hash
- [ ] Genesis block hash published and signed by Technical Council
- [ ] Testnet reward allocations finalized and included

### Software Release
- [ ] Version tagged (e.g., v1.0.0)
- [ ] Release binaries built for Linux x86_64, Linux ARM64, macOS ARM64
- [ ] Docker image published to ghcr.io
- [ ] SHA256 checksums published and signed
- [ ] Release notes written

### Infrastructure
- [ ] 3+ bootstrap nodes deployed (US, EU, APAC)
- [ ] Block explorer operational
- [ ] Grafana monitoring dashboards
- [ ] Status page operational
- [ ] RPC endpoints available

### Documentation
- [ ] Validator setup guide published
- [ ] Node operator runbook published
- [ ] SDK documentation (JS/WASM, Python) published
- [ ] API reference published

---

## Launch Day (T+0)

### Sequence

1. **T-2h**: Final go/no-go call with Technical Council
2. **T-1h**: Genesis config distributed to all validators
3. **T-30m**: Validators start nodes with genesis config (nodes wait for genesis_time)
4. **T+0**: Genesis timestamp reached, consensus begins
5. **T+5m**: First epoch transition confirmed
6. **T+30m**: Block explorer shows consistent chain
7. **T+1h**: RPC endpoints opened to public
8. **T+2h**: Bridge deposits enabled (Solana, Stellar)
9. **T+4h**: SDK documentation goes live
10. **T+24h**: First stability checkpoint

### Go/No-Go Criteria

**GO** requires ALL of:
- [ ] 30+ validators ready with correct genesis config
- [ ] All audit Critical/High findings remediated
- [ ] No open Critical bug bounty submissions
- [ ] Incentivized testnet Phase 4 passed
- [ ] Technical Council unanimous approval
- [ ] Bootstrap nodes healthy in all 3 regions

**NO-GO** if ANY of:
- Open Critical audit finding
- <30 validators ready
- Unresolved consensus bug from testnet
- Technical Council veto

---

## Post-Launch (T+1 day to T+30 days)

### Week 1
- [ ] 24/7 on-call rotation active
- [ ] Daily stability reports
- [ ] Monitor for consensus stalls or forks
- [ ] Bridge operation confirmed end-to-end
- [ ] First governance proposals submitted

### Week 2-4
- [ ] Validator set grows to 50+
- [ ] First epoch with full committee rotation
- [ ] Staking/unstaking cycle completed
- [ ] Fee market stabilized
- [ ] Treasury receives first emission allocation
- [ ] Bug bounty ongoing, no Critical findings

### Month 2-3 (Governance Bootstrap per SPEC.md Section 16.2)
- [ ] Month 2: Service Operators Council formed from top validators
- [ ] Month 3: First Token House election for Technical Council
- [ ] Genesis Technical Council begins transition

---

## Emergency Procedures

### Consensus Halt
1. Coordinate on private validator channel
2. Identify root cause (logs, state dumps)
3. If software bug: patch, tag, distribute binary
4. Validators restart with patched binary
5. Consensus resumes from last finalized block

### Critical Vulnerability
1. Activate Immunefi triage SLA (4h first response)
2. Assess exploitability and active exploitation
3. If actively exploited: coordinate emergency patch via private channel
4. Deploy fix to validators before public disclosure
5. Post-mortem published within 7 days

### Bridge Emergency
1. Bridge pause triggered by Technical Council (2/3 vote)
2. Investigate discrepancy between locked and minted tokens
3. Resolve root cause
4. Technical Council vote to resume bridge operations
