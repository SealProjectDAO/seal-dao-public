# ZK Proof Architecture for Seal DAO

## Formal Verification Status of zkVMs

### RISC Zero (Primary)

**Formally verified by Veridise** (2025):
- Used the **Picus** tool for automated formal verification of ZK circuits
- Specifically targets **underconstrained bugs** (97% of ZK circuit vulnerabilities)
- Verifies that the RISC-V circuit constraints correctly enforce the ISA semantics
- Result: no underconstrained bugs found in the core circuit

**What Veridise verified:**
- The STARK arithmetization correctly models RV32IM instruction execution
- Memory consistency (reads return the last written value)
- Program counter transitions follow RISC-V spec
- Arithmetic operations match the ISA (add, mul, div, etc.)

**What is NOT verified:**
- The Groth16 SNARK wrapper (we don't use it — PQ security)
- The recursion layer (STARK-to-STARK composition)
- The host-side proof generation logic
- Guest program correctness (that's OUR responsibility)

**Audit history:**
- Multiple external audits (details on risczero.com/security)
- Bug bounty program active
- Apache 2.0, fully open source

### SP1 (Secondary)

**Formally verified by multiple firms:**
- **Veridise**: RISC-V constraint verification (same Picus tool as RISC Zero)
- **Cantina**: Security audit of the proving system
- **Zellic**: Additional security review
- **Nethermind + Ethereum Foundation**: Formal verification of RISC-V constraints

**SP1-specific verification:**
- RISC-V constraints formally verified (collaboration with Nethermind)
- Hypercube proof system independently reviewed
- Prover Network ($PROVE token) audited separately

**What is NOT verified:**
- Groth16/PLONK wrapper (same caveat — we don't use it)
- GPU acceleration codepath (performance optimization, not correctness)

---

## Composite Proof Architecture

### The Problem

A Seal block proof must verify:
1. All transaction signatures are valid (ML-DSA-65)
2. SQL operations produce correct state diffs
3. The Merkle state root matches

**ML-DSA-65 inside a zkVM is expensive**: ~148K R1CS constraints per signature.
With 100 transactions, that's ~15M constraints just for signatures — dominates
the entire proof.

### The Solution: Composite Assertions

Instead of proving everything inside one monolithic ZK circuit, we split
the proof into **composable assertions** verified at different layers:

```
BLOCK VALIDITY =
    ASSERT signature_valid(tx_i, sender_pubkey_i)   -- Native verification
  ∧ ASSERT zkvm_executed(program_hash, inputs_hash, outputs_hash)  -- ZK proof
  ∧ ASSERT state_root_matches(pre_root, post_root)  -- Merkle verification
```

### Layer 1: Native Signature Verification (NOT in ZK)

```
For each transaction tx_i in block:
  ASSERT ML-DSA-65.verify(
    public_key = tx_i.sender,
    message    = tx_i.payload,
    signature  = tx_i.signature
  ) == true

  -- This runs natively (~8ms per sig, ~800ms for 100 txs)
  -- NOT inside the zkVM (would be 10,000x slower)
  -- Validators verify sigs BEFORE including txs in blocks
  -- The block proposer attests: "I verified all signatures"
```

**Why native**: ML-DSA verification is a public operation. Any validator
can re-verify signatures from the block data. There's no secret involved,
so there's no reason to hide it in ZK. Putting it in ZK would add ~15M
constraints for zero security benefit.

### Layer 2: ZK Proof of State Transition (in zkVM)

```
RISC Zero guest program proves:

  INPUTS (public):
    pre_state_root  : Hash256    -- Merkle root before block
    post_state_root : Hash256    -- Merkle root after block
    tx_payloads_hash: Hash256    -- SHA3 of all transaction payloads
    block_height    : u64

  COMPUTATION (private, proven in ZK):
    For each tx payload:
      Parse SQL statement
      Execute against in-memory state
      Update Merkle tree

    Final Merkle root == post_state_root

  OUTPUT:
    STARK proof (~200 KB) that the above computation is correct
```

**What this proves**: Given the pre-state and the transaction payloads,
the post-state root is the ONLY valid result. No one can claim a
different post-state for the same inputs.

**What this does NOT prove**: That the signatures are valid (Layer 1)
or that the VRF election was correct (Layer 3).

### Layer 3: Consensus Assertions (Native + VRF proof)

```
ASSERT VRF.verify(
  proposer_vrf_public_key,
  epoch_seed || slot_number,
  vrf_output,
  vrf_proof
) == true

ASSERT vrf_output < threshold(proposer_stake)
  -- Proposer was legitimately elected

ASSERT threshold_sig.verify(
  committee_public_keys,
  block_hash,
  threshold_signature
) == true
ASSERT threshold_sig.participant_count >= 2/3 * committee_size
  -- Committee approved the block
```

### Composite Verification

A full node verifies a block by checking ALL three layers:

```rust
fn verify_block(block: &Block) -> Result<(), Error> {
    // Layer 1: Verify all transaction signatures (native, ~800ms)
    for tx in &block.transactions {
        let vk = VerifyingKey::from_bytes(&tx.sender)?;
        let sig = Signature::from_bytes(tx.signature.clone());
        vk.verify(&tx.payload, &sig)?;
    }

    // Layer 2: Verify ZK proof of state transition (~2-100ms)
    zk_verifier.verify(&block.zk_proof)?;
    assert_eq!(block.zk_proof.public_inputs.pre_state_root, expected_pre_root);
    assert_eq!(block.zk_proof.public_inputs.post_state_root, block.header.state_root);

    // Layer 3: Verify consensus (VRF + threshold sig, ~20ms)
    verify_vrf_election(&block)?;
    verify_threshold_signature(&block)?;

    Ok(())
}
```

### Light Client Verification (ZK proof only)

A light client that trusts the validator set can skip Layer 1:

```rust
fn light_verify(block_header: &BlockHeader, zk_proof: &ZkProof) -> Result<(), Error> {
    // Only verify the ZK proof + threshold sig
    // Don't need full transaction data
    zk_verifier.verify(zk_proof)?;
    assert_eq!(zk_proof.public_inputs.post_state_root, block_header.state_root);
    verify_threshold_signature(block_header)?;
    Ok(())
}
```

---

## Security Analysis

| Attack | Layer | Defense |
|--------|-------|---------|
| Forged signature | Layer 1 | ML-DSA verification (PQ-secure) |
| Invalid state transition | Layer 2 | ZK proof (STARK, PQ-secure) |
| Fake block proposer | Layer 3 | VRF proof verification |
| Insufficient committee | Layer 3 | Threshold signature ≥ 2/3 |
| ZK proof forgery | Layer 2 | STARK soundness (computationally bounded) |
| zkVM circuit bug | Layer 2 | Veridise formal verification |
| Replay attack | Layer 1 | Nonce tracking per sender |

**Post-quantum security across all layers:**
- Layer 1: ML-DSA-65 (NIST FIPS 204, lattice-based) ✅
- Layer 2: STARK proofs (hash-based, no elliptic curves) ✅
- Layer 3: VRF (HMAC stub now, LB-VRF later) + Threshold (Ringtail later) ⚠️

---

## Formal Verification of the Composite Proof Protocol

The composite proof architecture itself must be formally verified.
Splitting verification across layers introduces composition risks
that don't exist in a monolithic proof.

### Properties to Prove (TLA+ / Lean 4)

**Soundness of composition:**
```
THEOREM composite_sound:
  ∀ block,
    layer1_valid(block)    -- all sigs valid
  ∧ layer2_valid(block)    -- ZK proof valid
  ∧ layer3_valid(block)    -- consensus valid
  → block_valid(block)     -- the block is valid

  -- AND the converse: if any layer fails, the block is rejected
  ∀ block,
    ¬layer1_valid(block) ∨ ¬layer2_valid(block) ∨ ¬layer3_valid(block)
  → ¬block_valid(block)
```

**No gap between layers:**
```
THEOREM no_verification_gap:
  -- Every aspect of block validity is covered by exactly one layer
  -- Nothing can be valid in the composite but invalid in reality

  ∀ tx ∈ block.transactions:
    sig_verified(tx)                -- covered by Layer 1

  ∀ state_transition:
    zk_proven(pre_root, post_root, txs)  -- covered by Layer 2

  ∀ election:
    vrf_verified(proposer, slot)    -- covered by Layer 3
    committee_attested(block, sigs) -- covered by Layer 3
```

**Non-interaction between layers:**
```
THEOREM layer_independence:
  -- Layers cannot weaken each other
  -- A valid Layer 2 proof cannot compensate for invalid Layer 1 sigs
  -- A valid Layer 1 sig cannot compensate for invalid Layer 2 state

  ∀ block:
    layer2_valid(block) ∧ ¬layer1_valid(block)
    → ¬block_valid(block)   -- ZK proof can't save bad sigs

  ∀ block:
    layer1_valid(block) ∧ ¬layer2_valid(block)
    → ¬block_valid(block)   -- good sigs can't save bad state
```

### Verification Approach

| Property | Tool | Status |
|----------|------|--------|
| Composite soundness | TLA+ (extend SealConsensus.tla) | TODO |
| No verification gap | Lean 4 (enumerate all tx fields) | TODO |
| Layer independence | Rocq (prove each layer's isolation) | TODO |
| ZK circuit ↔ SQL semantics | Lean 4 (circuit matches spec) | TODO |
| STARK soundness | Rely on Veridise's verification | Done (external) |
| ML-DSA correctness | Rely on libcrux hax+F* verification | Done (external) |

### What We Rely On (External Verification)

| Component | Verified by | Method | Trust assumption |
|-----------|------------|--------|------------------|
| RISC Zero circuit | Veridise | Picus (automated) | Veridise is competent |
| SP1 circuit | Veridise + Cantina + Nethermind | Multiple methods | Multiple independent reviewers |
| ML-DSA-65 | Cryspen | hax + F* | Cryspen + F* type system |
| ML-KEM-768 | Cryspen | hax + F* | Same |
| SHA3-256 | RustCrypto community | Audited | Well-studied algorithm |
| STARK soundness | Academic | Published proofs | Collision-resistant hash function |

### What We Must Verify Ourselves

| Component | Tool | Priority |
|-----------|------|----------|
| Composite proof protocol | TLA+ | High |
| SQL engine ↔ ZK guest equivalence | Lean 4 / testing | High |
| State root computation determinism | Kani + proptest | Done |
| Signature verification completeness | Lean 4 | Medium |
| Layer boundary: no information leak | Rocq | Medium |

---

## Implementation Plan

### Phase 1: Stub (current)
```
ZkProver trait → StubProver (SHA3 commitment, 32 bytes)
```

### Phase 2: RISC Zero
```
ZkProver trait → RiscZeroProver
  - Guest program: SQL execution + Merkle state diff
  - Host: generates STARK proof
  - Verifier: native STARK verification (no Groth16)
  - Target: <30s CPU, <10s GPU (RTX 4090)
```

### Phase 3: SP1 Alternative
```
ZkProver trait → Sp1Prover
  - Same guest program (Rust, RISC-V ISA)
  - Better GPU acceleration (Hypercube)
  - Target: <15s CPU, <5s GPU (RTX 5090)
```

### Phase 4: GPU Proving Network
```
Dedicated prover nodes with CUDA GPUs
  - Prove blocks for the network
  - Earn SEAL tokens for proving service
  - Multiple provers compete (fastest valid proof wins)
```
