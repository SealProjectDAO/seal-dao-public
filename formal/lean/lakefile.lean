import Lake
open Lake DSL

package «SealVerify» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «SealVerify» where
  srcDir := "."
