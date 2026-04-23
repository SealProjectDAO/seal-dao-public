---- MODULE MC_SealBridge ----
(*
 * Model checking configuration for SealBridge.tla.
 *
 * Run with Apalache (0.55.0+). Note: Apalache accepts ONE --inv flag
 * with a comma-separated list of invariants, not repeated --inv flags
 * (repeating --inv makes the CLI dump its "Usage … Options ???" help).
 *
 *   apalache-mc check --cinit=ConstInit --init=Init --next=Next \
 *     --inv=MintedLeqLocked,NoDoubleMint,NoMintWithoutLock,BurnedLeqMinted,ReleasedLeqBurned,ReleasedLeqLocked \
 *     --length=10 MC_SealBridge.tla
 *
 * Or use the wrapper: `./scripts/verify-tla-bridge.sh`.
 *)

EXTENDS SealBridge

\* Small model for bounded checking
MC_MaxDeposits == 3
MC_RequiredConfirms == 2
MC_NumValidators == 3

====
