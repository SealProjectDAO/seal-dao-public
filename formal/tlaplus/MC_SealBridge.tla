---- MODULE MC_SealBridge ----
(*
 * Model checking configuration for SealBridge.tla.
 *
 * Run with Apalache:
 *   apalache-mc check --init=Init --next=Next \
 *     --inv=MintedLeqLocked --inv=NoDoubleMint --inv=NoMintWithoutLock \
 *     --inv=BurnedLeqMinted --inv=ReleasedLeqBurned --inv=ReleasedLeqLocked \
 *     --length=10 MC_SealBridge.tla
 *)

EXTENDS SealBridge

\* Small model for bounded checking
MC_MaxDeposits == 3
MC_RequiredConfirms == 2
MC_NumValidators == 3

====
