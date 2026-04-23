//! WASM bytecode validation using `wasmparser`.
//!
//! This is the registration-time gate for `LANGUAGE wasm` procedures.
//! It catches malformed modules, invalid types, missing exports, and
//! disallowed feature use *before* the bytecode is committed to chain.
//!
//! # Why not full execution?
//!
//! A full deterministic runtime (wasmtime / wasmi) would let us actually
//! invoke the procedure. Wasmtime is not vendored in this workspace yet,
//! so the executor side stays in `WasmProcEngine` (returns
//! `LanguageNotImplemented`). Validating at registration is still the
//! right move: it means a corrupt or hostile module can't sneak past
//! `CREATE FUNCTION` and ride the chain forever.
//!
//! # What we enforce
//!
//! 1. Module parses cleanly under MVP wasm + bulk-memory only.
//! 2. There is exactly one exported function named `run`.
//! 3. The `run` function takes only i64 parameters and returns one i64.
//! 4. No imports (host calls would defeat determinism).
//! 5. No SIMD, threads, references, GC, or component-model features.

use crate::{Procedure, ProcedureLanguage, ProcError};
use wasmparser::{Payload, Validator, WasmFeatures};

/// Validate a WASM procedure body. The body is treated as a hex string
/// (matches the `WasmtimeProcEngine` wire format planned in ADR-001).
pub fn validate_wasm_proc(proc: &Procedure) -> Result<(), ProcError> {
    if proc.language != ProcedureLanguage::Wasm {
        return Err(ProcError::LanguageMismatch {
            expected: ProcedureLanguage::Wasm,
            actual: proc.language,
        });
    }
    let bytes = hex::decode(proc.body.trim())
        .map_err(|e| ProcError::Execution(format!("body hex: {e}")))?;
    validate_wasm_bytes(&bytes, proc.args.len())
}

/// Lower-level: validate raw wasm bytes. Used by tests that want to skip
/// the hex encoding hop.
pub fn validate_wasm_bytes(bytes: &[u8], expected_arg_count: usize) -> Result<(), ProcError> {
    // WASM1 = MVP + mutable globals; deliberately excludes SIMD,
    // threads, references, GC, exception handling, component model.
    let features = WasmFeatures::WASM1;
    let mut validator = Validator::new_with_features(features);

    // First pass: structural validation via wasmparser's Validator.
    let mut found_run_export = false;
    let mut had_imports = false;
    let mut run_func_index: Option<u32> = None;
    let mut function_types: Vec<u32> = Vec::new(); // function index -> type index
    let mut type_sigs: Vec<(Vec<wasmparser::ValType>, Vec<wasmparser::ValType>)> = Vec::new();
    let mut imported_funcs: u32 = 0;

    let parser = wasmparser::Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| ProcError::Execution(format!("parse: {e}")))?;
        validator
            .payload(&payload)
            .map_err(|e| ProcError::Execution(format!("validate: {e}")))?;
        match payload {
            Payload::TypeSection(reader) => {
                for ty in reader {
                    let rg = ty.map_err(|e| ProcError::Execution(format!("type: {e}")))?;
                    for sub in rg.types() {
                        if let wasmparser::CompositeInnerType::Func(ft) = &sub.composite_type.inner
                        {
                            type_sigs.push((
                                ft.params().to_vec(),
                                ft.results().to_vec(),
                            ));
                        } else {
                            type_sigs.push((Vec::new(), Vec::new()));
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group = group.map_err(|e| ProcError::Execution(format!("import: {e}")))?;
                    had_imports = true;
                    match group {
                        wasmparser::Imports::Single(_, imp) => {
                            if matches!(imp.ty, wasmparser::TypeRef::Func(_)) {
                                imported_funcs += 1;
                            }
                        }
                        wasmparser::Imports::Compact1 { items, .. } => {
                            for item in items {
                                let item = item.map_err(|e| {
                                    ProcError::Execution(format!("import item: {e}"))
                                })?;
                                if matches!(item.ty, wasmparser::TypeRef::Func(_)) {
                                    imported_funcs += 1;
                                }
                            }
                        }
                        wasmparser::Imports::Compact2 { ty, names, .. } => {
                            if matches!(ty, wasmparser::TypeRef::Func(_)) {
                                let count = names.into_iter().count();
                                imported_funcs += count as u32;
                            }
                        }
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty_idx in reader {
                    function_types
                        .push(ty_idx.map_err(|e| ProcError::Execution(format!("func: {e}")))?);
                }
            }
            Payload::ExportSection(reader) => {
                for exp in reader {
                    let exp = exp.map_err(|e| ProcError::Execution(format!("export: {e}")))?;
                    if exp.name == "run" && exp.kind == wasmparser::ExternalKind::Func {
                        found_run_export = true;
                        run_func_index = Some(exp.index);
                    }
                }
            }
            _ => {}
        }
    }

    if had_imports {
        return Err(ProcError::Execution(
            "wasm module imports a host function; deterministic procs must be self-contained"
                .into(),
        ));
    }
    let run_idx = run_func_index
        .ok_or_else(|| ProcError::Execution("no exported function named 'run'".into()))?;
    if !found_run_export {
        return Err(ProcError::Execution("missing 'run' export".into()));
    }

    // Resolve `run`'s signature.
    let local_idx = (run_idx as i64) - (imported_funcs as i64);
    if local_idx < 0 {
        return Err(ProcError::Execution(
            "'run' export resolves to an imported function".into(),
        ));
    }
    let local_idx = local_idx as usize;
    if local_idx >= function_types.len() {
        return Err(ProcError::Execution("'run' index out of range".into()));
    }
    let ty_idx = function_types[local_idx] as usize;
    if ty_idx >= type_sigs.len() {
        return Err(ProcError::Execution("'run' type index out of range".into()));
    }
    let (params, results) = &type_sigs[ty_idx];

    if params.len() != expected_arg_count {
        return Err(ProcError::ArgCount {
            expected: expected_arg_count,
            actual: params.len(),
        });
    }
    if results.len() != 1 {
        return Err(ProcError::Execution(format!(
            "'run' must return exactly one value, got {}",
            results.len()
        )));
    }
    for p in params {
        if !matches!(p, wasmparser::ValType::I64) {
            return Err(ProcError::Execution(
                "'run' parameters must all be i64".into(),
            ));
        }
    }
    if !matches!(results[0], wasmparser::ValType::I64) {
        return Err(ProcError::Execution("'run' must return i64".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Procedure, ProcedureArg, ProcedureLanguage};

    /// Hand-built wasm: `(module (func (export "run") (param i64) (result i64)
    /// local.get 0 i64.const 1 i64.add))`. Returns its argument + 1.
    const ADD_ONE_HEX: &str =
        "0061736d0100000001060160017e017e030201000707010372756e00000a09010700200042017c0b";

    /// Empty module — no exports.
    const EMPTY_HEX: &str = "0061736d01000000";

    fn arg(name: &str, ty: &str) -> ProcedureArg {
        ProcedureArg { name: name.into(), type_keyword: ty.into() }
    }

    #[test]
    fn validates_known_good_module() {
        let p = Procedure::new(
            "add_one".into(),
            vec![arg("x", "BIGINT")],
            Some("BIGINT".into()),
            ProcedureLanguage::Wasm,
            ADD_ONE_HEX.into(),
        );
        validate_wasm_proc(&p).expect("known-good wasm must validate");
    }

    #[test]
    fn rejects_non_wasm_proc() {
        let p = Procedure::new(
            "f".into(), vec![], None, ProcedureLanguage::Sql, "SELECT 1".into(),
        );
        let err = validate_wasm_proc(&p).unwrap_err();
        assert!(matches!(err, ProcError::LanguageMismatch { .. }));
    }

    #[test]
    fn rejects_invalid_hex() {
        let p = Procedure::new(
            "f".into(), vec![], None, ProcedureLanguage::Wasm, "garbage".into(),
        );
        let err = validate_wasm_proc(&p).unwrap_err();
        assert!(matches!(err, ProcError::Execution(_)));
    }

    #[test]
    fn rejects_missing_run_export() {
        let p = Procedure::new(
            "f".into(), vec![], None, ProcedureLanguage::Wasm, EMPTY_HEX.into(),
        );
        let err = validate_wasm_proc(&p).unwrap_err();
        assert!(matches!(err, ProcError::Execution(s) if s.contains("run")));
    }

    #[test]
    fn rejects_arg_count_mismatch() {
        // add_one takes 1 param but we declare zero formal args.
        let p = Procedure::new(
            "add_one".into(),
            vec![],
            Some("BIGINT".into()),
            ProcedureLanguage::Wasm,
            ADD_ONE_HEX.into(),
        );
        let err = validate_wasm_proc(&p).unwrap_err();
        assert!(matches!(err, ProcError::ArgCount { expected: 0, actual: 1 }));
    }
}
