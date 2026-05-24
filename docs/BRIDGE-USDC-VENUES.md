# USDC liquidity venues — Solana + Stellar

Where the wrapped USDC the Seal bridge produces can be traded,
withdrawn, and on/off-ramped, with regional accessibility for
the markets we care about (US, EU, Korea, Japan, Taiwan, Singapore).

> **⚠️ Staleness.** Crypto venue support changes monthly. Listings
> get added, delisted (regulator pressure, exchange policy
> changes), and access gets gated by region without notice.
> **Confirm any specific venue + region combination before
> relying on it for production flow.** This doc is a starting
> map, not a current-state guarantee. Last verified against
> public sources: **2026-05-16**.

USDC variants relevant to the Seal bridge:

| Variant | Issuer | Wrapped form on Seal |
|---------|--------|----------------------|
| **USDC-SPL** | Circle, native on Solana (SPL token, mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` mainnet / `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` devnet) | `WUSDC` (via `lock_tokens` mint-routing on `LockEvent.mint`) |
| **USDC-XLM** | Circle, native on Stellar (Stellar Asset Contract over `USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` mainnet, `USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5` testnet) | `WUSDC` (via Soroban `lock_usdc` entrypoint) |

> Mainnet USDC issuer addresses are stable Circle-controlled
> accounts. Testnet issuers differ; the demo script defaults to
> the testnet pairs.

---

## 1. CEX support — USDC-SPL (Solana)

USDC on Solana is one of the most widely-listed assets in crypto.
Deposit / withdrawal on the Solana network is what matters for
the bridge — listing alone isn't enough if the venue doesn't let
you withdraw to a Solana address.

| Venue | Solana withdrawals | US | EU | KR | JP | TW | SG |
|-------|--------------------|----|----|----|----|----|----|
| **Coinbase** | ✅ | ✅ | ✅ | ❌ | ❌ | ⚠️ (no local presence) | ✅ (Coinbase SG, limited) |
| **Kraken** | ✅ | ✅ (ex-NY) | ✅ | ❌ | ⚠️ (closed JP 2023) | ✅ (via direct API) | ✅ |
| **Binance** | ✅ | ❌ (Binance.US is separate, limited tokens) | ✅ (Binance EU) | ❌ (closed KR ops) | ❌ (closed JP) | ✅ | ⚠️ (no MAS license; Binance SG paused) |
| **Crypto.com** | ✅ | ✅ | ✅ (limited features) | ✅ (limited) | ❌ | ⚠️ | ✅ |
| **OKX** | ✅ | ❌ | ✅ (Malta-licensed) | ❌ | ❌ | ✅ | ⚠️ |
| **Bybit** | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ (limited) |
| **Bitstamp** | ✅ | ✅ | ✅ | ❌ | ❌ | — | ✅ |
| **Gemini** | ✅ | ✅ | ✅ (Ireland-licensed) | ❌ | — | — | ✅ |
| **KuCoin** | ✅ | ⚠️ (no NY) | ✅ | ❌ | ❌ | ✅ | ✅ (limited) |
| **Upbit (KR)** | ⚠️ (KRW-only pairs dominant; USDC withdrawals to Solana available, KYC-gated) | — | — | ✅ | — | — | — |
| **Bithumb (KR)** | ⚠️ (similar to Upbit) | — | — | ✅ | — | — | — |
| **bitFlyer (JP)** | ❌ (USDC not listed) | — | — | — | ❌ | — | — |
| **SBI VC Trade (JP)** | ❌ (no USDC, mainly XLM/XRP) | — | — | — | ❌ | — | — |
| **BitTrade (JP)** | ⚠️ (USDC added late 2024) | — | — | — | ✅ (limited) | — | — |
| **MaiCoin / MAX (TW)** | ⚠️ (USDC-SPL deposits limited; check current state) | — | — | — | — | ⚠️ | — |
| **Independent Reserve (SG)** | ⚠️ (USDC listed, withdrawal network depends) | — | — | — | — | — | ✅ |
| **Coinhako (SG)** | ✅ | — | — | — | — | — | ✅ |

**Highest-confidence Solana on-ramp + USDC withdrawal**: Coinbase,
Kraken, Bitstamp for US/EU; OKX or KuCoin for non-US; for Korea
Upbit/Bithumb if you're a KR resident with KRW; Japan is the
hardest market (FSA-restricted listings); Taiwan via MaiCoin or
foreign exchanges via wire; Singapore Coinhako and Independent
Reserve are the local-licensed options.

> **Japan-specific note.** FSA listing approval is asset-by-asset
> and venue-by-venue. USDC was approved for licensed venues only
> in early 2024 (SBI VC Trade got USDC late, BitTrade added it).
> Verify the deposit/withdrawal network is "Solana" (not just
> "Ethereum") on the venue's asset page before transferring.

---

## 2. CEX support — USDC-XLM (Stellar)

USDC on Stellar has narrower CEX coverage than USDC-SPL because
fewer venues offer Stellar-network deposits/withdrawals.

| Venue | Stellar withdrawals | US | EU | KR | JP | TW | SG |
|-------|----------------------|----|----|----|----|----|----|
| **Coinbase** | ✅ (Coinbase is a co-issuer of USDC-XLM with Circle) | ✅ | ✅ | ❌ | ❌ | — | ✅ |
| **Kraken** | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **Bitstamp** | ✅ | ✅ | ✅ | ❌ | ❌ | — | ✅ |
| **Binance** | ⚠️ (USDC-XLM listing limited; XLM ↔ USDC swap on-platform but Stellar-network USDC withdrawals not always offered) | ❌ | ✅ | ❌ | ❌ | ✅ | ⚠️ |
| **Crypto.com** | ⚠️ (XLM listed, USDC-XLM less common) | ✅ | ✅ | ✅ | ❌ | — | ✅ |
| **OKX** | ⚠️ (Stellar-network USDC depends on regional gateway) | ❌ | ✅ | ❌ | ❌ | ✅ | ⚠️ |
| **KuCoin** | ⚠️ | ⚠️ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **SBI VC Trade (JP)** | ✅ (XLM is a flagship listing) | — | — | — | ✅ (XLM, not USDC-XLM) | — | — |
| **MaiCoin (TW)** | ⚠️ (XLM listed; USDC-XLM less established) | — | — | — | — | ✅ | — |
| **Coinhako (SG)** | ⚠️ | — | — | — | — | — | ✅ |

**Highest-confidence Stellar on-ramp + USDC withdrawal**: Coinbase
(co-issuer; best Stellar support of any large venue), Kraken,
Bitstamp. For Korea/Japan/Taiwan Stellar-network USDC is sparse —
the typical flow is to off-ramp via XLM and convert separately.

> **Coinbase = USDC-XLM issuer.** Circle co-issues USDC on Stellar
> with Coinbase since 2018. For dollar on/off-ramp into
> Stellar-network USDC specifically, Coinbase is the canonical
> path: deposit USD → buy USDC → withdraw to Stellar network →
> deposit on Seal bridge via `usdc-xlm`.

---

## 3. DEX / on-chain venues

### Solana DEXes (USDC-SPL)

| DEX | Type | Notes |
|-----|------|-------|
| **Jupiter** | Aggregator | Single-call routes across Solana DEXes; the default on/off-ramp for SOL ↔ USDC inside the Solana ecosystem. |
| **Raydium** | AMM (concentrated + standard) | Deep USDC pairs against SOL, mSOL, BONK, JTO, JUP, every other SPL major. |
| **Orca** | AMM (Whirlpools, concentrated) | High-liquidity USDC pools; Whirlpools format. |
| **Meteora** | AMM (DLMM, dynamic) | Newer; competitive USDC pair depth on some pairs. |
| **Phoenix** | CLOB | Order book DEX; better for size on USDC-SOL. |
| **Drift** | Perpetuals + spot | Margin/leverage against USDC. |
| **Kamino** | Lending / liquidity | Earn yield on USDC-SPL. |

All accept USDC-SPL natively — no wrapping required to trade.
The Seal bridge produces USDC-SPL when reverse-claiming on
Solana; that token flows directly into any of the above.

### Stellar DEXes (USDC-XLM)

| DEX | Type | Notes |
|-----|------|-------|
| **SDEX** | Stellar's protocol-native order book | Built into the Stellar core protocol; no external contract; classic limit-order book. |
| **Stellar AMM** | Protocol AMM (Stellar Protocol 18+) | Built-in liquidity pools, post-2021 upgrade. |
| **StellarX** | Front-end on SDEX + AMM | Web UI on top of Stellar's native DEX. |
| **Lobstr** | Wallet with built-in swap | Mobile-first; SDEX swaps from the wallet. |
| **Aquarius (AQUA)** | Reward layer on top of Stellar AMM pools | Distributes AQUA tokens to LPs. |
| **Soroswap** | Soroban-smart-contract AMM | Newer; in the Soroban smart-contract era. The Seal bridge contract lives on Soroban, so this is the same execution layer. |

Stellar liquidity is shallower than Solana for USDC pairs (lower
TVL across the ecosystem), but SDEX has been the canonical USDC
trading venue since Circle/Coinbase issued in 2018.

### Cross-chain bridges that route through USDC

If a counterparty has USDC on a third chain (Ethereum, Arbitrum,
Base, Polygon, Avalanche…) and wants to land it on Solana or
Stellar without an exchange round-trip, these are the bridges
that route USDC natively:

| Bridge | Solana | Stellar | Native USDC | Method |
|--------|--------|---------|--------------|--------|
| **Circle CCTP v2** | ✅ | ✅ (post-2024 expansion) | ✅ | Burn + mint via Circle attestation — no wrapped USDC, you get canonical USDC on the destination. |
| **Wormhole** | ✅ | ✅ | ⚠️ (wraps if no CCTP route) | Wrapped USDC for chain pairs without CCTP. |
| **Allbridge Core** | ✅ | ✅ | ⚠️ (own bridged variant) | AMM-based with intermediate liquidity. |
| **Mayan Finance** | ✅ | — | ⚠️ | Solana-centric. |

For Seal users on-ramping USDC into Solana or Stellar from another
chain, **Circle CCTP is the cleanest path** — produces canonical
(unwrapped) USDC on the destination, which then flows directly
through the Seal bridge.

---

## 4. Recommended on/off-ramp matrix by region

For "user wants to put fiat → wrapped USDC on Seal" via the bridge:

| Region | Best on-ramp | Notes |
|--------|---------------|-------|
| **US** | Coinbase → buy USDC → withdraw to Solana or Stellar → deposit via Seal bridge | Coinbase is the canonical USDC venue in the US; Kraken/Gemini/Bitstamp also viable. |
| **EU** | Coinbase EU, Kraken, Bitstamp; SEPA → EUR → USDC → withdraw | Bitstamp is Luxembourg-licensed; Kraken is Ireland-licensed; Binance EU works for EUR/USDC. |
| **Korea** | Upbit or Bithumb (KYC-gated); KRW → USDT-on-Tron → swap to USDC via Binance, then to Solana/Stellar | Direct USDC withdrawal from KR exchanges is restricted; the realistic flow is via an offshore venue. |
| **Japan** | bitFlyer (XLM, not USDC) + offshore swap, OR SBI VC Trade for XLM; USDC requires using BitTrade or routing via Kraken (closed since 2023 — rely on a foreign account if you have one) | Japan is the hardest market — FSA listings are gated. |
| **Taiwan** | MaiCoin / MAX → USDT → swap on offshore exchange to USDC → withdraw to Solana | Native USDC on TW exchanges is limited. |
| **Singapore** | Coinhako, Independent Reserve, Crypto.com SG → USDC → withdraw | MAS-licensed venues offer the cleanest local on-ramp. |

> **Travel-rule + KYC reminder.** USDC withdrawals from CEXes
> above ~$1k typically trigger travel-rule beneficiary-info
> requirements; for cross-jurisdiction routing this can mean
> double-KYC. Plan for the friction.

---

## 5. Seal bridge → CEX deposit gotchas

If a user reverses (`reverse-usdc-sol` or `reverse-usdc-xlm`) and
sends the unlocked USDC to a CEX deposit address:

- **Memo / destination tag requirements.** Stellar CEX deposits
  almost always require a memo / destination tag (Coinbase,
  Kraken, Binance all do). The Seal bridge unlock tx doesn't
  carry a memo field — the CEX-deposit address either:
  - Has a unique-per-user address (no memo needed: Coinbase
    Stellar deposits work this way), or
  - Has a shared deposit address + memo (Binance, Kraken).
    Sending without the memo = **funds lost**.
  Document this clearly for end users.
- **Network selection.** Many CEXes show both Solana and
  Ethereum (and sometimes Algorand, Tron, Polygon) for USDC.
  Users must pick "Solana" or "Stellar" — sending USDC-SPL to an
  Ethereum-network deposit address = funds lost.
- **Minimum deposits.** Coinbase and Binance set per-asset
  deposit minimums (~$10 USDC). Smaller transfers vanish into
  fees or don't credit.

---

## See also

- [`docs/RUNBOOK-TESTNET-OPERATOR.md`](RUNBOOK-TESTNET-OPERATOR.md) §7
  — the demo commands that produce wrapped USDC.
- [`docs/BRIDGE-TESTNET.md`](BRIDGE-TESTNET.md) §4 — on-chain USDC
  contract entrypoints (`lock_usdc`, `unlock_usdc`, `set_usdc_sac`).
- [`scripts/bridge-faucet.sh`](../scripts/bridge-faucet.sh) — testnet
  USDC faucet helpers (`usdc-sol`, `usdc-xlm`).
- [`docs/CRYPTO-HOSTING-PROVIDERS.md`](CRYPTO-HOSTING-PROVIDERS.md)
  — turning the USDC liquidity into cloud infrastructure: hosts
  that accept SOL/XLM/USDC/ETH/BTC.
