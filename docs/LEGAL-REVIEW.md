# Seal DAO — Legal/Regulatory Landscape Review (Node + On-Chain DEX)

> **⚠️ INFORMATION ONLY — NOT LEGAL ADVICE. IANAL.**
> This is a research synthesis of publicly available regulation as of **June 2026**,
> assembled to inform **mainnet go/no-go** and feature-gating decisions. It is **not**
> a legal opinion and **not** a substitute for qualified local counsel in each
> jurisdiction. Crypto regulation is moving fast — several load-bearing items below
> changed in 2024–2026 and some rest on regulatory *guidance/posture* rather than
> binding rulings. **Engage securities, derivatives, AML/sanctions, gaming,
> export-control, and privacy counsel in each target market before launch.**

**Scope:** legal consequences of (a) running a Seal node/validator and (b) the
on-chain DEX (spot CLOB now; planned perps, portfolio/cross margin, prediction
markets) across **EU/France, South Korea, Japan, Taiwan, United States, Canada**.
Native token: **SEAL**. PQC primitives: **ML-DSA, ML-KEM, SHA3**.

**Status:** Proposal / living document. Gates `LAUNCH-CHECKLIST.md`. Pairs with
`docs/DEX-DESIGN.md`, `docs/DEX-PERPS-MARGIN-PROPOSAL.md`, `docs/DEX-SPEED-PQC-PROPOSAL.md`.

---

## 0. The one structural finding that governs everything

Across **all six** jurisdictions the dividing line is the same: **regulation attaches
to intermediation/control, not to running software.** A **bare, non-custodial
validator** — no custody of client keys/assets, no order matching as a business, no
fee capture, no hosted front-end, no admin keys — is the **lowest-risk** posture
everywhere and is *probably* outside the regulated perimeter in every market. But
**no jurisdiction gives validators an explicit safe harbor** — that conclusion is
*inferred* from activity-based definitions, not black-letter law. Risk appears the
moment an **identifiable operator** custodies assets, matches orders, takes fees,
runs the UI, holds admin keys, or concentrates governance.

**Corollary for mainnet:** the protocol/validator layer can plausibly ship globally;
the **product features** (perps, prediction markets, fiat rails, hosted front-end)
are what carry jurisdictional risk and must be **feature-gated and geo-fenced**.

---

## 1. Global feature-risk ranking (worst → best)

| Feature | Aggregate risk | Why (cross-jurisdiction) |
|---|---|---|
| **Prediction markets** | 🔴 **Criminal everywhere** | Illegal gambling under criminal codes in KR (Art. 247, 5 yr), JP (Penal Code 185–187), TW (Art. 268, 3 yr — *with proven on-chain tracing + prosecutions*), FR (CSI L320-1, 3–7 yr; ANJ banned Polymarket & Kalshi), CA (Criminal Code + binary-options ban; OSC fined Polymarket C$200k), US (CFTC event-contract rules + unsettled 50-state gambling preemption). **No licensing cure in most markets.** |
| **Perps / leverage / cross-margin (retail)** | 🔴 **Effectively prohibited** | KR (crypto not an FSCMA underlying; apps delisted), JP (FIEA Type-I + **2× retail cap** → perps incompatible), TW (FSC Point 12 bans VASP derivatives; Futures Act up to 7 yr), EU (MiFID II + ESMA **2:1** crypto-CFD cap + FR advertising ban), CA (CSA 21-332 **bans margin/leverage to any client**), US (CFTC DCM/SEF + CEA §2(c)(2)(D); Ooki/Deridex/Opyn/0x enforcement). |
| **DAO governance / token-voter liability** | 🔴 **High (US-led)** | *CFTC v. Ooki DAO* default judgment: voting token-holders potentially jointly liable as an unincorporated association. Untested on appeal but signalled. |
| **Spot CLOB with identifiable operator** | 🟠 **High** | VASP/exchange licensing trigger: EU MiCA CASP, FR PSAN/CASP, KR VAUPA+FTRA (real-name bank chokepoint), JP PSA CAESP ("virtually managed by a person"), TW MLCA AML registration (criminal if unregistered), CA CTP/CIRO. A **CLOB is the paradigm "exchange"** — *weaker* decentralization defense than an AMM. |
| **Operator with custody / fee-switch / admin keys** | 🟠 **High** | Custody is the strongest AML + money-transmission hook everywhere; fee-switch + admin keys are exactly what defeats every "sufficiently decentralized" carve-out and the FATF "control or sufficient influence" test. US adds criminal §1960 exposure (*US v. Storm*, 2025 conviction). |
| **Native SEAL token** | 🟡 **Context-dependent** | Likely a "crypto asset/commodity" if a pure gas/governance token, **but** staking-yield / revenue-share / profit-from-others'-efforts framing risks **security** reclassification (Howey/Pacific Coast/CISI/investment-contract) → far heavier regime. A **primary token sale** is the classic trigger. |
| **AML/KYC obligations** | 🟠 **Attaches to operators** | If any part is a VASP: KYC/CDD, **travel rule** (KR ₩1M, very strict; EU no de-minimis; JP/TW/CA thresholds), SAR/STR, sanctions screening. Structurally incompatible with a permissionless KYC-less DEX that has an operator. |
| **On-chain personal data** | 🟠 **Structural conflict** | Immutability vs. erasure/deletion rights: GDPR (EDPB Guidelines 02/2025), KR PIPA (up to 10% revenue), JP APPI, TW PDPA, US CCPA/CPRA, CA PIPEDA. **Keep PII off-chain; only hashes/commitments on-chain — and treat even hashes as still-in-scope.** |
| **Bare non-custodial validator** | 🟢 **Lowest (no safe harbor)** | Outside activity-based VASP/MSB definitions in all six; FINTRAC (CA) **expressly exempts validation rewards**. Inference, not a ruling. |
| **PQC primitives (ML-DSA/ML-KEM/SHA3)** | 🟢 **Low** | Open-source published-standard crypto is decontrolled/exempt under EU Dual-Use Cryptography Note, US EAR §734.7 (2021 relaxation), JP FEFTA Art. 17, plus KR/TW/CA Wassenaar-aligned regimes. SHA3 (pure hash) generally outside info-security controls. Assess only proprietary/compiled-binary distribution. |

---

## 2. Per-jurisdiction summary

### 🇪🇺 EU / 🇫🇷 France
- **Validator:** not on MiCA's closed list of 10 crypto-asset services → likely out of scope; settlement-layer decentralization *requires* open node access. No binding ruling, though.
- **Spot DEX:** MiCA **CASP authorization** (operating a trading platform = enumerated service). The **"fully decentralised" carve-out is Recital 22 only**, read narrowly — EBA/ESMA (Jan 2025): "very few DeFi systems" qualify. France: AMF CASP (with ACPR assent); **PACTE grandfathering ends 1 July 2026** (≈now).
- **Perps:** MiFID II financial instruments; **ESMA guidelines (May 2025) treat perpetual futures as derivatives**; **2:1 retail leverage cap**; binary options banned to retail; **France bans electronic advertising of crypto derivatives** (Sapin 2 + loi influenceurs).
- **Prediction markets:** illegal gambling (CSI L320-1); ANJ classified Polymarket & Kalshi as illegal, both geoblocked France; **3–7 yr / €90k–200k**.
- **SEAL:** likely "crypto-asset other than ART/EMT" (Title II white-paper); exemptions for validation-reward & free distribution. Hybrid-token rule: any financial-instrument feature "takes precedence."
- **AML:** obliged entity = the CASP. TFR travel rule (**no de-minimis**, since Dec 2024); AMLR from 2027 (CDD ≥€1,000; Art. 79 bans privacy coins for CASPs).
- **PQC/data:** open-source NIST PQC ≈ no license (Cryptography Note). Art. 434-15-2 can compel key disclosure on judicial order (untested vs. blockchain keys). EDPB 02/2025 + CNIL: keep PII off-chain.

### 🇰🇷 South Korea — one of the highest-risk markets
- **Validator:** KoFIU manual carve-outs (advice/technology; no key control; "bulletin board" venue) suggest a bare validator is *not* a VASP — but **never addressed for nodes** (gray area).
- **Spot DEX:** **VAUPA** (in force Jul 2024) + FTRA VASP registration — requires **ISMS cert + real-name Korean bank account** (the chokepoint; effectively unobtainable for a permissionless DEX). Unregistered operation: **5 yr / ₩50M**. Extraterritorial via "targeting" (Korean UI/KRW/marketing).
- **Perps:** crypto isn't an FSCMA underlying → **effectively prohibited**; FIU moved against ~17 offshore venues, **Apple/Google delisted apps (2025)**; lending/leverage guidelines (Sep 2025) ban leveraged loans.
- **Prediction markets:** Criminal Act **Art. 247 (operator, 5 yr)** / Art. 246 (users); **live 2026 Polymarket criminal probe** of Korean users.
- **AML:** strict travel rule (**₩1M threshold**), real-name verification.
- **PQC/data:** PQC low-risk (open-source export-exempt; no key-disclosure mandate). **PIPA erasure right (10-day) vs. immutability; fines up to 10% of revenue.**

### 🇯🇵 Japan
- **Validator:** not in PSA Art. 2(7) CAESP triggers; non-custodial wallet expressly unregulated. Decisive DEX test: **"if virtually managed by a person"** → licensed; if no manager → unsettled.
- **Spot DEX:** PSA **CAESP** registration (FSA) + **JVCEA** self-regulation + token whitelist (**Green List**: ≥3 member exchanges, ≥6 months). New token like SEAL faces full screening; ≥95% cold storage.
- **Perps:** **FIEA Type-I FIBO**; **2× retail leverage cap** → perps effectively closed to retail; FSA actively warns offshore venues (Bybit et al.).
- **Prediction markets:** **highest risk** — gambling (Penal Code 185–187), operator **3 mo–5 yr**, *both operators and users* liable; bitbank 2026 account-suspension warning re Polymarket.
- **SEAL:** likely "crypto asset" (PSA Art. 2) unless profit-share → security/ERTR (CISI test). Stablecoins = Electronic Payment Instruments (separate registration). **PSA→FIEA reclassification bill** cleared lower house Jun 2026 (~2027 effect).
- **AML:** APTCP, travel rule (since Jun 2023), FEFTA sanctions screening.
- **PQC/data:** FEFTA export controls; **OSS "publicly known technology" exemption (Art. 17)**; **no backdoor/key-disclosure mandate**. APPI erasure vs. immutability.

### 🇹🇼 Taiwan — framework mid-transition
- **Validator:** not an enumerated VASP activity (FATF-aligned 5 services) → outside perimeter, but no explicit safe harbor; "providing instruments enabling control" (custody) language is broad/untested.
- **Spot DEX:** **MLCA AML registration mandatory since 30 Nov 2024**; unregistered = **criminal (2 yr / NT$5M; entities NT$50M)**. Offshore VASPs must form a **local entity**. **Virtual Asset Service Act** (EY-approved Apr 2026, not yet enacted) moves to full **licensing**.
- **Perps:** **FSC Guidelines Point 12 bans VASP crypto derivatives**; Futures Trading Act exposure **up to 7 yr** (plausible, untested).
- **Prediction markets:** **highest criminal risk with proven enforcement** — Art. 268 (operator, 3 yr); **2023–24 Polymarket prosecutions traced on-chain bets → exchange KYC → identity**, charged bettors (as little as 5 USDC) and promoters; IP-blocking did **not** defeat jurisdiction.
- **SEAL:** virtual commodity vs. **STO security** (SEA Art. 6; NT$30M threshold); staking-yield marketing raises security risk.
- **AML/data:** CDD ≥NT$30k, travel rule, 5-yr records; **PDPA erasure vs. immutability** (new PDPC + higher fines 2026). PQC: domestic use unrestricted; export mirrors EU list.

### 🇺🇸 United States — fast-moving, favorable-but-reversible
- **Validator:** FinCEN 2019 guidance — non-custodial software/network-access = **not** a money transmitter. **But** *US v. Storm* (Aug 2025 §1960 conviction of a non-custodial dev; retrial Oct 2026) shows **"decentralization" is not a safe harbor**; the DOJ "Blanche memo" (Apr 2025) narrows prosecution to *willful* violations but is **revisable policy, not law** (Storm continued after it).
- **Spot DEX:** a **CLOB is the paradigm "exchange"** under Exchange Act Rule 3b-16 → exposure *if the matched instruments are securities*. SEC 2025 posture softened (dropped cases, non-binding staff statements; Uniswap probe closed) but **no statute changed and no court ruled** secondary trading is outside the securities laws.
- **Perps:** **highest risk** — CFTC DCM/SEF + CEA §2(c)(2)(D) leveraged-retail trigger; custody kills the actual-delivery exception; DEX-perp enforcement (Deridex/Opyn/0x); **Ooki** DAO-member liability. 2025–26 "onshoring" legalizes perps **only for registered DCMs**, not unregistered DEXs.
- **Prediction markets:** CFTC event-contract NPRM (2026, proposed) — **elections OK, sports contested, war/terror/assassination barred**; Kalshi elections resolved legal; Polymarket re-entered via a **licensed DCM**. **State gambling preemption unsettled** (split injunctions).
- **SEAL:** Howey — decentralized L1 gas token leans "digital commodity"; a **primary sale** is the trigger. **CLARITY Act** (digital-commodity framework + non-custodial safe harbor) **passed House, stuck in Senate** — indicative, not law. **GENIUS Act** (stablecoins) signed Jul 2025.
- **AML/sanctions:** BSA/FinCEN MSB if custodial; **OFAC** strict-liability (Tornado Cash delisted Mar 2025 after *Van Loon*, but screening still required). State **money-transmitter** patchwork + NY BitLicense.
- **PQC/data:** open-source PQC outside the EAR (§734.7); **no key-escrow mandate**. CCPA/CPRA deletion vs. immutability — keep PII off-chain (the **SQL layer is the highest-risk privacy surface**).

### 🇨🇦 Canada
- **Validator:** no MSB/securities trigger from infrastructure; **FINTRAC expressly exempts validation rewards** (strongest "infra ≠ dealer" anchor of any jurisdiction). No DeFi/DEX-specific framework yet.
- **Spot DEX:** **"crypto contract" doctrine** (CSA 21-327): custodial trading without immediate delivery = security/derivative. CTP investment-dealer registration + CIRO; **pre-registration undertakings** (21-332/333). Enforcement: Bybit settled, **KuCoin banned + C$2M**, Binance exited.
- **Perps:** **CSA 21-332 bans margin/credit/leverage to *any* client** → perps effectively prohibited to retail.
- **Prediction markets:** **MI 91-102 binary-options ban** (<30-day, all provinces except BC) + Criminal Code gambling + provincial monopoly; **OSC fined Polymarket operators C$200k** (Apr 2025). Narrow CIRO path excludes sports/elections.
- **SEAL:** Pacific Coast investment-contract test; utility alone doesn't exempt; custodial trading independently creates a "crypto contract." 
- **AML/data:** FINTRAC MSB/FMSB (foreign biz serving Canadians), travel rule, LVCTR ≥C$10k. **PIPEDA** destroy/erase vs. immutability (anonymization bar: "no serious possibility" of re-identification). PQC: ML-KEM/ML-DSA export-controlled (Cat 5 Pt 2 + CSE); watch **Bill C-22 lawful-access** (2026).

---

## 3. Consolidated feature-limitation / patching plan

What to **disable, gate, or geo-fence** to reduce exposure. Mapped to engineering
controls. (Risk-reduction, not immunity — "targeting"/"facilitation" are functional
tests regulators can pierce; geo-blocking alone has failed where on-chain tracing
reached users, e.g. Taiwan/Korea Polymarket.)

### Tier 1 — gate before any public/mainnet exposure (criminal / prohibition risk)
1. **Prediction markets — do not ship to anything these jurisdictions can reach.** This is the only feature with *criminal* exposure in KR/JP/TW/FR and unsettled gambling law in US/CA. For war/terror/assassination-type contracts: **hard-block globally**. Prefer *not building the feature into reachable builds* over IP-blocking (on-chain tracing has defeated geoblocks).
2. **Perps / leverage / margin / cross-margin — disable for retail in all six markets.** Offer **spot only** by default. If ever offered, restrict to non-retail, via a registered venue, never advertised.
3. **No protocol-operated, region-facing front-end for restricted features.** Publish protocol + reference clients as open source; let third parties host. The hosted UI is what converts "validator" into "exchange/CASP/CAESP."

### Tier 2 — structural decentralization (defeats the "controllable operator" theory)
4. **Strictly non-custodial.** Users hold keys; protocol never takes possession/unilateral control. Strongest argument against MSB/VASP/§1960 everywhere.
5. **No admin keys / upgrade-pause that can move or freeze user funds.**
6. **No fee switch routed to a controllable treasury;** avoid concentrated governance. Fees + admin keys + governance control are exactly what breaks MiCA Recital 22, FATF "control or sufficient influence," and US "control" tests. (Reference models: dYdX v4 fee-to-stakers, no central fee entity.)
7. **Rotate the sequencer/proposer** (already VRF-selected) so no single identifiable operator runs matching — relevant to the Track A continuous-engine design.

### Tier 3 — geo-fencing & no-targeting hygiene
8. **Robust geo-blocking** (IP + VPN/proxy detection) + **"No [jurisdiction] persons" ToS**, with evidence you don't circumvent your own controls (the *BitMEX* lesson: undermined geofencing invites *criminal* liability).
9. **No region-targeted indicia:** no local-language UI, no local-fiat pairs/on-ramps, no region-directed marketing/airdrops/influencers, no local customer support. "Targeting" is the extraterritorial hook in KR/JP/TW.
10. **No fiat on-ramps / no local-currency rails.** Removes the strongest "exchange for funds" + VASP trigger (esp. KR real-name bank chokepoint).
11. **OFAC/sanctions + SDN-address screening** at any front-end you control (strict liability; non-negotiable even in the friendly US climate).

### Tier 4 — token & data hygiene
12. **Distribute SEAL via validation rewards / free distribution, not a primary sale.** Avoid staking-yield/revenue-share/profit-from-team framing that triggers security reclassification (Howey/Pacific Coast/CISI/STO) and the EU hybrid-token rule. Aim for no single party ≥20% of tokens/voting (tracks the US CLARITY maturity test).
13. **Treat any stablecoin specially** (EU EMT, JP EPI, US GENIUS Act, CA VRCA) — likely exclude fiat stablecoins from restricted regions.
14. **Keep ALL personal data off-chain.** On-chain: only hashes/commitments/encrypted references — and treat even those as still-in-scope pseudonymous data. Design key-destruction-based "erasure." **The seal-sql distributed SQL layer is the highest-risk privacy surface — never persist PII to the immutable ledger.** Assign controllership at design stage (EDPB 02/2025 / CNIL / PIPA / APPI / PDPA / CCPA / PIPEDA).

### Tier 5 — PQC / export (low risk, light touch)
15. **Publish ML-DSA/ML-KEM/SHA3 implementations as open-source, based on published NIST standards (FIPS 203/204/205)** to stay within every jurisdiction's public-domain/published-tech decontrol. Assess only proprietary/compiled-binary distribution and screen embargoed destinations. Note France Art. 434-15-2 and Canada Bill C-22 (lawful-access) as watch-items, not blockers.

---

## 4. DEX-as-infrastructure: legal structuring of the protocol/front-end split

Reference venues like **Monaco Protocol** sell an "order-book-as-a-service" model:
the protocol runs matching, books, indexers, and settlement **vaults**, takes a thin
**base fee**, and exposes an SDK so independent **app front-ends** plug in, set their
own taker fee, and "keep 100%." It is tempting because it offloads infrastructure —
but it does **not** reduce legal risk by default. It **relocates and often
concentrates** it. Read against §0–§2, "we run the matching engine, order books, and
vaults" is a description of **operating an exchange with custody** — the *high-risk*
operator column, not the low-risk validator column.

### 4.1 The split shields the protocol ONLY if all four conditions hold

The protocol/front-end separation delivers the neutral-infrastructure posture **only
when the protocol genuinely relinquishes control.** Failing *any one* of these likely
makes the protocol itself the regulated exchange/VASP/CASP/CTP + custodian:

1. **Non-custodial settlement.** No protocol- or admin-controlled key can move, freeze,
   or seize user funds. Either users solely control their vault, or there is no
   protocol-held custody at all. *(Custody is the single biggest AML / money-
   transmission / VASP trigger in all six jurisdictions; "vault isolation" segregates
   risk between apps but does **not** remove the custody characterization.)*
2. **No admin keys / no upgrade or pause authority** over the matching or vault
   programs — immutable, autonomous contracts. *(Upgrade/pause authority = "control"
   under FATF's test, MiCA Recital 22, and US "control" analysis; defeats every
   decentralization carve-out.)*
3. **No protocol fee switch to an identifiable, controllable recipient.** Either no
   protocol fee, or a fee that is **burned** / routed by autonomous on-chain rule with
   no entity able to redirect it. *(A base fee to a controllable treasury makes the
   protocol an identifiable operator earning exchange revenue — an obliged entity /
   CASP candidate, and the thread regulators use to tie protocol + front-end into a
   single enterprise.)*
4. **No protocol-operated, region-facing front-end** and no protocol-run targeting of
   any restricted market (no local-language UI, fiat rails, or marketing). *(The
   hosted front-end is what converts "infrastructure" into "operator"; targeting is
   the extraterritorial hook in KR/JP/TW.)*

Hit all four → app front-ends carry the operator liability; the protocol stays thin,
neutral infrastructure. **Monaco-as-marketed fails 1–3** (hosted custody vaults,
implied admin authority, a 5 bps base fee), so as described the protocol is the
regulated party.

### 4.2 Liability that the model *creates* (not just relocates)

- **Distributed front-end exposure with no compliance.** Each app builder setting its
  own fee and "keeping 100%" is plausibly its own unregistered broker/exchange/money-
  transmitter in its users' jurisdiction — handed to many small builders who almost
  certainly run no KYC/AML/sanctions program.
- **Single-enterprise / facilitation theory.** Because protocol and front-end split
  the fee on the *same trade*, a regulator can treat them as one economic enterprise,
  or hold the protocol liable for **knowingly providing exchange infrastructure + fee
  rails to unlicensed front-ends** (aiding/abetting; cf. *CFTC v. ZeroEx/0x*, where a
  pure-infrastructure provider was charged).
- **Sanctions chokepoint.** If *any* front-end serves a sanctioned user, the shared
  protocol is the common point through which the trade clears — strict-liability OFAC
  exposure concentrates on the protocol.

### 4.3 Decision for Seal — non-custodial settlement vs. protocol fee

This is the fork between the two columns of this review. Seal today routes DEX fees
**50% burn / 50% to block proposer** (`docs/DEX-DESIGN.md`) and matching runs **in-node**
(`DexManager`). Recommended structuring if Seal exposes the DEX as shared infra:

| Dimension | ❌ High-risk (Monaco-as-marketed) | ✅ Protective (recommended for Seal) |
|---|---|---|
| **Custody** | Protocol-controlled settlement vaults | **Non-custodial**: settle directly into user-controlled balances (`BalanceStore`); no protocol-movable vault |
| **Upgrade authority** | Admin/upgrade/pause keys on matching+vaults | **No admin keys**; immutable matching; changes only via on-chain governance, never a unilateral key |
| **Protocol fee** | Base fee to a controllable treasury | **Burn-only or autonomous rule** (extend today's 50% burn → no controllable recipient); avoid a redirectable fee switch |
| **Proposer/sequencer** | Single operator runs matching | **Rotate** via existing VRF proposer selection (ties to `DEX-SPEED-PQC-PROPOSAL.md`) |
| **Front-end** | Protocol runs the region-facing UI | **No protocol front-end**; publish SDK/clients open source; app builders host (and own the operator liability) |
| **App fees** | — | App builders may set/keep their own fee — but that makes **them** the regulated operator in their market; document this in builder ToS |

**Net recommendation:** if Seal adopts the DEX-as-infrastructure model, keep settlement
**non-custodial** and the protocol fee **burn-only/autonomous** — do **not** add
protocol-held vaults or a redirectable base fee for convenience. Those two
"convenience" features are exactly what flips Seal from low-risk protocol to regulated
exchange + custodian. The proposer fee Seal pays today is acceptable **only** if it
remains rule-bound and non-redirectable; a discretionary treasury cut is not.

> ⚠️ The proposer-reward half of today's fee split is a borderline case: a per-block,
> protocol-rule-determined reward to a rotating VRF-selected proposer is closer to a
> validator block reward than to "exchange revenue to an operator." Confirm with
> counsel that it reads as the former, not a fee switch. Burn-only is the cleaner
> posture.

---

## 5. Mainnet go/no-go implications

A **defensible mainnet posture** emerges from the matrix:

- **Ship:** the PQC L1 + bare validator network + **spot CLOB**, non-custodial, no
  admin keys, no fee-switch-to-treasury, open-source clients, PII strictly off-chain.
- **Gate behind region controls / defer:** **perps, margin, prediction markets,
  fiat on-ramps, any hosted region-facing front-end.** These are the features that
  move the project from "infrastructure" to "regulated (or criminal) operator."
- **Decide explicitly, with counsel, before launch:** (a) whether any entity
  operates a front-end and in which markets; (b) SEAL distribution mechanics
  (sale vs. rewards); (c) governance concentration; (d) which markets to geo-block
  vs. pursue registration (the **register-and-conform or exit/geo-block** binary that
  Binance/Bybit/KuCoin faced in CA/KR).

### Suggested `LAUNCH-CHECKLIST.md` gates
- [ ] Per-target-market counsel opinions obtained (EU/FR, KR, JP, TW, US, CA).
- [ ] Perps / margin / prediction-market features behind a region/feature flag, **off by default** for all six markets.
- [ ] Geo-blocking + VPN detection + "no restricted persons" ToS on any hosted front-end; documented non-circumvention.
- [ ] OFAC/SDN screening wired into any front-end.
- [ ] Confirmed: no admin keys move/freeze funds; no fee switch to controllable treasury; sequencer/proposer rotation live.
- [ ] SEAL distribution structured to minimize security classification; ≤20% any single holder/voting bloc.
- [ ] PII-off-chain invariant enforced in seal-sql (test/lint); erasure-by-key-destruction procedure documented.
- [ ] PQC distribution = open-source, published standards; embargoed-destination screening.
- [ ] Stablecoin handling decision per market.

---

## 6. Key uncertainties (re-verify with counsel before relying)
- **No jurisdiction has a binding ruling that a pure validator is outside scope** — all inferred from activity-based definitions.
- **"Sufficiently decentralized" carve-outs are narrow and mostly untested** (MiCA Recital 22; FATF control test; US "control"); EBA/ESMA think almost no real system qualifies.
- **US landscape is discretion-driven and reversible** (dropped cases, non-binding staff statements, unenacted CLARITY Act, revisable DOJ memo; *US v. Storm* mid-litigation).
- **Reform in flight:** EU PACTE grandfathering ends Jul 2026; JP PSA→FIEA (~2027); TW VASP Act (post-Apr 2026); KR Phase-2 framework stalled into 2026; CA PCMLTFA amendments + Bill C-22.
- **Token classification is fact-specific** and turns on SEAL's exact rights bundle.
- **On-chain hash = "anonymized/erased"** is unconfirmed by data-protection regulators in every market.
- Several primary-source pages (EUR-Lex, OSC, FSC) returned fetch errors during research; secondary/practitioner sources reproducing official text were used and noted in the per-jurisdiction working notes.

---

*Per-jurisdiction working notes with full citations and authority URLs were produced
during research (EU/FR, KR, JP, TW, US, CA) and can be expanded into standalone
appendices (`docs/legal/<jurisdiction>.md`) on request.*
