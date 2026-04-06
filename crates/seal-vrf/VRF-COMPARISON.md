# VRF Implementations — Comparison

## Current: PqVrf (ML-DSA + SHA3)

**Status: IMPLEMENTED, PQ-SECURE**

Construction: `output = SHA3(ML-DSA.sign(sk, input))`

| Property | Value |
|----------|-------|
| PQ-secure | ✅ Yes (ML-DSA-65, NIST Level 3) |
| Output size | 32 bytes |
| Proof size | 3,309 bytes (one ML-DSA signature) |
| Eval time | ~14 ms (ML-DSA sign) |
| Verify time | ~6 ms (ML-DSA verify + SHA3) |
| Formally verified | ✅ Via libcrux (hax + F*) |
| Deterministic | ⚠️ Needs deterministic signing randomness |
| Security reduction | To ML-DSA unforgeability + SHA3 PRF |

**Pros:**
- Uses NIST-standard crypto (no custom constructions)
- Formally verified implementation (libcrux)
- Available NOW (no porting needed)
- Simple construction, easy to audit

**Cons:**
- Proof size (3.3 KB) is larger than LB-VRF (5 KB total but different tradeoff)
- No formal security reduction as a VRF specifically (only as signature + hash)
- ML-DSA signing uses random nonce — need to derive from sk+input for determinism

## Future Upgrade: LB-VRF (Esgin et al., FC 2021)

**Status: NOT YET IMPLEMENTED**

- Paper: [ePrint 2020/1222](https://eprint.iacr.org/2020/1222)
- Published: Financial Cryptography 2021
- Code: [github.com/zhenfeizhang/lb-vrf](https://github.com/zhenfeizhang/lb-vrf)

| Property | Value |
|----------|-------|
| PQ-secure | ✅ Yes (Module-LWE + Module-SIS) |
| Output size | 84 bytes |
| Proof size | ~5 KB |
| Eval time | ~3 ms |
| Verify time | ~1 ms |
| Public key size | ~3.32 KB |
| Formally verified | ❌ No |
| Deterministic | ✅ Yes (inherent to construction) |
| Security reduction | To Module-LWE/SIS (same as ML-DSA/ML-KEM) |
| Few-time | ⚠️ Yes (1-5 evaluations per key pair) |

**Pros:**
- Formal security proof as a VRF (not just sig+hash)
- Faster evaluation (~3ms vs ~14ms)
- Faster verification (~1ms vs ~6ms)
- Inherently deterministic (no random nonce issue)
- Same hardness assumptions as ML-DSA (Module-LWE/SIS)

**Cons:**
- **Few-time limitation**: each key can evaluate only 1-5 times
  (mitigated by per-epoch key rotation, which Seal already does)
- Existing Rust code is experimental:
  - ~25 commits, single author
  - No NTT acceleration
  - No memory zeroization
  - Incomplete testing
  - Not production-ready
- No formal verification of the code (only the paper's math)
- Larger output (84 bytes vs 32 bytes)
- Requires cryptographic audit before production use

## Code: zhenfeizhang/lb-vrf

```
Repository: https://github.com/zhenfeizhang/lb-vrf
Language:   Rust (~90%)
License:    Apache 2.0 / MIT
Commits:    ~25
Status:     Experimental research code

Structure:
├── src/
│   ├── lib.rs          # VRF trait + types
│   ├── param.rs        # Module-LWE parameters
│   ├── poly.rs         # Polynomial arithmetic (NTT)
│   ├── keygen.rs       # Key generation
│   ├── eval.rs         # VRF evaluation
│   ├── verify.rs       # Proof verification
│   └── utils.rs        # Serialization, helpers
└── tests/
    └── vrf_test.rs     # Basic tests
```

### To integrate:
1. Fork the repo
2. Add to `crates/seal-vrf/` as `lb_vrf.rs` module
3. Implement the `Vrf` trait (same interface as PqVrf)
4. Add NTT acceleration (SIMD on x86, NEON on ARM)
5. Add zeroize on all secret key material
6. Add Kani harnesses for polynomial arithmetic
7. Add cargo-fuzz targets for malformed proofs
8. Commission cryptographic audit (Veridise or equivalent)

### Estimated effort: 2-4 weeks
- Week 1: Port + compile + basic tests
- Week 2: NTT optimization + benchmarks
- Week 3: Security hardening (zeroize, constant-time, fuzz)
- Week 4: Audit preparation + documentation

## Even Further Future: LaV (CRYPTO 2023)

- Paper: [ePrint 2022/141](https://eprint.iacr.org/2022/141)
- **Many-time VRF** (no key rotation needed)
- Output+proof: ~10.3 KB total
- **No implementation exists** (paper only)
- Same Module-LWE/SIS assumptions

## Recommendation

```
Testnet:   PqVrf (ML-DSA + SHA3)  ← current, works now
Mainnet:   LB-VRF (port + audit)  ← smaller proofs, formal reduction
Long-term: LaV (if implemented)   ← no key rotation needed
```

The `Vrf` trait ensures all three are drop-in replacements.
