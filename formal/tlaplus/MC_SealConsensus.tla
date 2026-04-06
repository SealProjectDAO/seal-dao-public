---- MODULE MC_SealConsensus ----
(*
 * Model checking configuration for SealConsensus.
 * Instantiates constants with concrete values for Apalache.
 *)

EXTENDS SealConsensus

\* @type: Set(Str);
MC_Validators == {"v1", "v2", "v3"}

\* @type: Int;
MC_MaxHeight == 3

\* @type: Int;
MC_Threshold == 2  \* 2 of 3 validators (>2/3)

====
