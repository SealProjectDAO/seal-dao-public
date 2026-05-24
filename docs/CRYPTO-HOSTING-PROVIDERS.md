# Hosting providers that accept crypto

Cloud / VPS / bare-metal hosts that accept SOL, XLM, USDC, ETH,
BTC (and friends) as payment, with indicative pricing relative to
AWS / Azure / GCP for an equivalent baseline VM.

The Seal bridge mints wrapped USDC on Solana and Stellar; a
natural follow-on is paying for the infrastructure that runs the
validators (or any downstream service) directly in those same
assets, without round-tripping through fiat.

> **⚠️ Staleness.** Hosting providers change their payment-method
> support and pricing constantly. Verify any specific
> provider + accepted-crypto combination on their pricing page
> before committing budget. Prices below are indicative
> 2026-05-16 baselines for a "2 vCPU / 4 GB RAM / 80 GB SSD"
> reference VM, the same shape AWS sells as `t3.medium` (~$30/mo
> on-demand US-east-1). Conversions to USD at then-current
> spot — your actual cost depends on which crypto you pay in and
> the venue's spot vs. on-platform exchange rate.

---

## 0. Reference baseline

The "2 vCPU / 4 GB RAM / 80 GB SSD" shape costs roughly:

| Hyperscaler | SKU | Monthly (USD) | Notes |
|-------------|-----|----------------|-------|
| **AWS** | `t3.medium` | ~$30 + ~$8 EBS = ~$38 | On-demand US-east-1. Reserved instances drop ~40%. |
| **GCP** | `e2-medium` (2 vCPU shared, 4 GB) | ~$25 + ~$13 PD = ~$38 | Similar shape. |
| **Azure** | `B2s` (2 vCPU, 4 GB) | ~$30 + ~$10 disk = ~$40 | Burstable; non-burst is ~$60. |

Call this **the $38/mo hyperscaler baseline.** Everything below
compares to that.

---

## 1. Crypto-payment hosts (general-purpose VPS / bare-metal)

| Provider | Accepts | Equivalent VM (USD/mo) | vs. AWS | Notes |
|----------|---------|--------------------------|---------|-------|
| **Hetzner Cloud** | BTC (via Coinbase Commerce, business accounts) | CCX13 (2 vCPU AMD, 8 GB, 80 GB) ≈ **€17 (~$18)** | **~50%** | Germany / Finland / US (Ashburn, Hillsboro). Best price/performance baseline in the Western market. ETH/USDC via 3rd-party invoice on request. |
| **OVHcloud** | BTC (Coinbase Commerce) | VPS Essential (2 vCPU, 4 GB, 80 GB) ≈ **$8** | **~20%** | France-based, global DCs. Limited crypto support to BTC. Lower-tier VPSes are aggressively priced. |
| **Vultr** | BTC, USDC (Bitpay) | Cloud Compute (2 vCPU, 4 GB, 80 GB) ≈ **$24** | **~65%** | 25+ regions globally. Bitpay processor handles BTC / USDC / ETH conversion to USD billing. |
| **Linode (Akamai)** | BTC, USDC, ETH (Bitpay) | Linode 4GB (2 vCPU, 4 GB, 80 GB) ≈ **$24** | **~65%** | Bought by Akamai 2022; pricing held. Multiple regions. Same Bitpay flow as Vultr. |
| **DigitalOcean** | BTC (Coinbase) | Basic Droplet (2 vCPU, 4 GB, 80 GB) ≈ **$24** | **~65%** | Crypto payment via account credit top-up, not direct invoice. |
| **Cherry Servers** | BTC, ETH, USDC (multiple processors) | Smart VPS (2 vCPU, 4 GB, 80 GB) ≈ **$15** | **~40%** | Lithuania + Netherlands + Chicago. Strong bare-metal lineup; crypto-native billing. |
| **NodeShift** | BTC, ETH, SOL, USDC, USDT, XMR | Compute (2 vCPU, 4 GB, 80 GB) ≈ **$10-20** | **~30-55%** | Crypto-native cloud; multi-region; supports Solana-native USDC. |
| **Servala** | BTC, ETH, SOL, XLM, USDC, USDT, XMR | VPS (2 vCPU, 4 GB) ≈ **$15-25** | **~40-65%** | Crypto-native; explicitly lists XLM and SOL. Smaller operator; verify the SLA before relying for production. |
| **Privex** | BTC, LTC, EOS, HIVE, STEEM, BCH | VPS (2 vCPU, 4 GB) ≈ **$10-20** | **~30-55%** | Crypto-only billing (no fiat option). Stockholm + Belgium + Las Vegas + Roubaix + others. No USDC/ETH/SOL/XLM at last check; mostly BTC/LTC. |
| **BitLaunch** | BTC, LTC, ETH, BCH, XMR | Custom (built on Vultr/DigitalOcean infra) ≈ **$10-25** | **~30-65%** | Reseller of major clouds with crypto-only billing. Privacy-focused; supports XMR. |
| **1984 Hosting** | BTC | VPS (2 vCPU, 4 GB) ≈ **$25** | **~65%** | Iceland; strong privacy stance. Limited to BTC. |
| **Njalla** | BTC, LTC, ETH, XMR, BCH, DASH, ZEC, USDC (and even cash by mail) | VPS (1 vCPU, 1 GB) ≈ **$15**; (2 vCPU, 4 GB) ≈ **$30** | **~40-80%** | Privacy-first; Sweden / Mullvad-adjacent. Higher per-vCPU price; you pay for privacy. |
| **Coinhost** | BTC, ETH, LTC, USDT, USDC | VPS (2 vCPU, 4 GB) ≈ **$20** | **~55%** | Multi-region; supports USDC on Ethereum + Tron. Check if Solana-USDC is listed at signup. |
| **Crypto.Hosting.ch** | BTC, ETH, USDC, USDT, XMR, LTC, others | VPS (2 vCPU, 4 GB) ≈ **$15-25** | **~40-65%** | Swiss; supports many cryptos. |
| **MonoVM** | BTC, USDT, USDC, ETH, LTC, DOGE | VPS (2 vCPU, 4 GB) ≈ **$15-20** | **~40-55%** | Wider catalog; offshore. |
| **Hostinger** | BTC (via Coingate) | Shared/VPS ≈ **$5-15** | **~15-40%** | Budget tier; shared hosting + small VPSes. |
| **AlwaysData** | BTC | Shared / VPS (small) ≈ **$10** | **~25%** | French; long-running; modest crypto support. |

### Highlights for SOL / XLM / USDC

If the goal is to pay **specifically with Solana-native or
Stellar-native USDC** (i.e. the assets the Seal bridge mints
without an intermediate swap):

| Provider | USDC-SPL (Solana) | USDC-XLM (Stellar) | Native SOL | Native XLM |
|----------|--------------------|--------------------|-------------|-------------|
| **NodeShift** | ✅ | ⚠️ (USDC accepted; network selection at checkout) | ✅ | — |
| **Servala** | ✅ | ✅ (explicitly lists XLM) | ✅ | ✅ |
| **Crypto.Hosting.ch** | ⚠️ (USDC accepted; verify network) | ⚠️ | — | — |
| **Coinhost** | ⚠️ (USDC-Ethereum + USDC-Tron primary) | ❌ | — | — |
| **Cherry Servers** | ⚠️ (USDC accepted; Ethereum-network primary) | ❌ | — | — |
| **Hetzner / OVH / Vultr / Linode / DigitalOcean** | ❌ (BTC-only or fiat-only) | ❌ | ❌ | ❌ |

**Practical takeaway:** for direct SOL or USDC-SPL payment,
**NodeShift** and **Servala** are the leanest paths. **Servala**
is the only provider that explicitly lists **XLM-native** payment.
For most others, USDC means USDC-on-Ethereum or USDC-on-Tron,
which requires a CCTP / bridge round-trip from Solana or Stellar
first (see [`BRIDGE-USDC-VENUES.md`](BRIDGE-USDC-VENUES.md) §3).

---

## 2. Decentralized cloud / DePIN

These don't accept "payment" in the traditional sense — you stake
or pay in their network token, which is itself a crypto. Worth
considering for Seal's burn-and-mint economic alignment.

| Provider | Token | Equivalent VM (USD/mo) | vs. AWS | Notes |
|----------|-------|--------------------------|---------|-------|
| **Akash Network** | AKT (Cosmos); also accepts USDC on Akash | (2 vCPU, 4 GB, 80 GB) ≈ **$5-10** | **~15-25%** | Reverse-auction marketplace of provider nodes. Cheapest viable cloud at small scale; less SLA-guarantee than hyperscalers. |
| **Flux** | FLUX | Tier-1 (2 vCPU, 8 GB) ≈ **$8** | **~20%** | Containerized workloads; replicated across multiple nodes. |
| **Render Network** | RNDR | GPU-only | — | Different shape; GPU rendering / inference, not general compute. |
| **Theta Edge Cloud** | TFUEL | Edge compute / CDN | — | Specialized. |
| **Stackup / Aleph.im / Fluence** | various | Function-style serverless | — | Different shape; not 1:1 with a VM. |

**Akash** is the leading mature option. Workloads deploy via
Stack Definition Language (SDL); the network bids your job out to
provider nodes; you pay in AKT or USDC. **Akash routinely runs
80% cheaper than AWS for the same shape.**

For Seal validator hosting specifically, decentralized providers
have a structural alignment win: your infrastructure dollar
flows into a crypto-native economy rather than to a hyperscaler
that doesn't accept your output token.

---

## 3. Regional notes

| Region | Best crypto-friendly host | Reason |
|--------|----------------------------|--------|
| **US** | Linode (Akamai), Vultr, DigitalOcean | Bitpay processing; strong network; multiple regions; predictable SLA. |
| **EU** | Hetzner (DE/FI), OVH (FR), Servala | Hetzner has the price-performance lead; OVH the lowest absolute price; Servala is the most crypto-native. |
| **Asia (KR/JP/TW)** | Vultr, Linode, Cherry Servers (limited APAC) | Hyperscaler-equivalent latency from Japan/Singapore PoPs of Vultr / Linode. Native APAC crypto hosts are sparser. |
| **Singapore** | Vultr (SG region), Linode (SG region), local resellers via BitLaunch | Vultr and Linode both run SG PoPs; pay in BTC / USDC via Bitpay. |
| **Crypto-native (region-agnostic)** | Akash, NodeShift, Servala | Geographic distribution depends on which provider nodes pick up your job (Akash) or where the host's DCs are (NodeShift / Servala). |

---

## 4. Comparison summary

```
Provider          | Price tier  | SOL | XLM | USDC | ETH | BTC | Notes
------------------|-------------|-----|-----|------|-----|-----|------------------
AWS / GCP / Azure | $$$$ (1.0×) |  -  |  -  |  -   |  -  |  -  | reference baseline
                  |             |     |     |      |     |     |
Hetzner           | $   (0.5×)  |  -  |  -  |  -   |  -  |  ✓  | best price/perf EU
OVH               | $   (0.2×)  |  -  |  -  |  -   |  -  |  ✓  | cheapest mainstream
Vultr / Linode    | $$  (0.65×) |  -  |  -  |  ✓   |  ✓  |  ✓  | via Bitpay
DigitalOcean      | $$  (0.65×) |  -  |  -  |  -   |  -  |  ✓  | account credit only
Cherry Servers    | $   (0.4×)  |  -  |  -  |  ✓   |  ✓  |  ✓  | strong bare-metal
NodeShift         | $   (0.3-0.55×) | ✓ | - | ✓ | ✓ | ✓ | crypto-native; SOL+USDC
Servala           | $   (0.4-0.65×) | ✓ | ✓ | ✓ | ✓ | ✓ | explicit XLM support
Coinhost          | $   (0.55×) |  -  |  -  |  ✓   |  ✓  |  ✓  | USDC-ETH/Tron primary
Cryp.Hosting.ch   | $   (0.4-0.65×) | - | - | ⚠ | ✓ | ✓ | wide crypto catalog
Privex            | $   (0.3-0.55×) | - | - | - | - | ✓ | crypto-only billing
Njalla            | $$  (0.4-0.8×)  | - | - | ✓ | ✓ | ✓ | privacy-first; pricier
                  |             |     |     |      |     |     |
Akash Network     | ¢   (0.15-0.25×)| (AKT/USDC) | DePIN; reverse-auction
Flux              | ¢   (0.2×)  | (FLUX)            | DePIN; replicated
```

**Headline numbers:**
- **Mainstream hosts (Hetzner, OVH, Vultr, Linode, DigitalOcean):**
  2-5× cheaper than AWS/Azure/GCP for equivalent shapes, with
  comparable network + SLA.
- **Crypto-native hosts (NodeShift, Servala, Cherry):** 1.5-3× cheaper
  than AWS, plus direct SOL/XLM/USDC payment with no fiat round-trip.
- **DePIN (Akash, Flux):** 4-7× cheaper than AWS, but SLA is best-effort
  / replicated rather than enterprise-grade.

---

## 5. Practical recommendation for Seal validators

For a Seal validator host running `seal-node` + `seal-relayer`
(2 vCPU, 4-8 GB RAM, 100 GB SSD baseline, plus modest egress):

- **Best price / performance / reliability:** Hetzner Cloud
  (CCX13 in DE/FI or Ashburn/Hillsboro for US users), Vultr or
  Linode in the region nearest your other validators. Pay BTC
  via Bitpay (Vultr/Linode) or via Coinbase Commerce (Hetzner
  business account).
- **Best crypto-native alignment (pay in SOL or USDC-SPL
  directly):** NodeShift or Servala. Verify SLA + region before
  committing — these are smaller operators.
- **Cheapest viable (cost over reliability):** Akash Network.
  Acceptable for a non-critical validator; less so for a
  primary. Pay in AKT or USDC.
- **Avoid for production:** privacy-first hosts (Njalla, 1984)
  for cost reasons; shared-hosting tiers (Hostinger shared); and
  any provider that doesn't publish a clear SLA.

---

## See also

- [`docs/BRIDGE-USDC-VENUES.md`](BRIDGE-USDC-VENUES.md) — getting
  USDC onto the Seal bridge in the first place.
- [`docs/RUNBOOK-TESTNET-OPERATOR.md`](RUNBOOK-TESTNET-OPERATOR.md)
  — operator runbook (validator + relayer bring-up).
- [`docs/GUIDE-OPERATOR.md`](GUIDE-OPERATOR.md) — single-node /
  multi-machine / VPN setup details for `seal-node` itself.
