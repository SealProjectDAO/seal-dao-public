//! Stored procedures and functions for Seal DAO (ADR-001).
//!
//! # What this crate is
//!
//! Implements the on-chain *registry* of `CREATE FUNCTION ... LANGUAGE
//! sql | wasm` definitions plus the dispatcher that picks an engine at
//! invocation time. Two engines:
//!
//! 1. [`SqlProcEngine`] — bodies are SQL fragments handed back to the
//!    surrounding SQL engine for execution. Inherits the SQL engine's
//!    determinism guarantees and gas accounting.
//! 2. [`WasmProcEngine`] — placeholder for a deterministic wasmtime /
//!    wasmer host. Wire format for stored bytecode is fixed; the real
//!    interpreter lands in a follow-up.
//!
//! # What this crate is NOT
//!
//! - It does not own a SQL parser. `seal-sql` extracts the proc
//!   definition from `Statement::CreateFunction` and hands a finished
//!   [`Procedure`] to [`ProcedureStore::register`].
//! - It does not own the underlying SQL execution. `SqlProcEngine`
//!   defers to a caller-supplied executor closure for `INVOKE` so the
//!   crate stays free of `seal-sql` cycles.
//!
//! # Wire layout (commit-stable)
//!
//! Bytes that go on-chain (and into the gas accounting) for a given
//! procedure are:
//!
//! ```text
//!   sha3-256( name || arg_sig || language_byte || body_bytes )
//! ```
//!
//! `language_byte` is 0x01 for `sql`, 0x02 for `wasm`. Re-deploy under
//! a different body changes the hash, which is what callers anchor
//! their checks against.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub mod error;
pub mod plpgsql;
#[cfg(feature = "wasm-validate")]
pub mod wasm_validate;

pub use error::ProcError;

/// Language a procedure body is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcedureLanguage {
    /// Plain SQL body. Default. Substitution is positional `$N`.
    Sql,
    /// PL/pgSQL body — `BEGIN ... END;` blocks with declared variables,
    /// `IF`/`LOOP`, `RAISE`, etc. Bodies are stored verbatim and
    /// rendered to plain SQL by [`plpgsql::lower_to_sql`] at invocation.
    /// The lowering subset accepted today is documented there.
    PlPgSql,
    /// WASM bytecode body. Opt-in.
    Wasm,
}

impl ProcedureLanguage {
    /// One-byte tag used in the on-chain hash so SQL→WASM rewrites
    /// register as a code change even when the literal body bytes
    /// happen to coincide.
    pub fn tag(&self) -> u8 {
        match self {
            ProcedureLanguage::Sql => 0x01,
            ProcedureLanguage::Wasm => 0x02,
            ProcedureLanguage::PlPgSql => 0x03,
        }
    }

    /// Parse the `LANGUAGE` keyword as it appears after `CREATE
    /// FUNCTION`. Case-insensitive. `None` if the keyword does not
    /// match an enabled language — caller should treat that as a
    /// `LanguageNotSupported` error rather than silently defaulting.
    pub fn from_keyword(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sql" => Some(ProcedureLanguage::Sql),
            "wasm" => Some(ProcedureLanguage::Wasm),
            "plpgsql" => Some(ProcedureLanguage::PlPgSql),
            _ => None,
        }
    }
}

/// One formal argument: `(name, type-keyword)`. The type-keyword is the
/// raw SQL type spelling (`"INTEGER"`, `"TEXT"`, `"SEAL_ADDRESS"`); this
/// crate doesn't try to canonicalise it because `seal-sql` already has
/// authoritative type mapping and we want the wire bytes to reflect what
/// the user actually wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcedureArg {
    pub name: String,
    pub type_keyword: String,
}

/// A registered procedure. Hash is computed eagerly so the registry
/// can dedupe on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Procedure {
    pub name: String,
    pub args: Vec<ProcedureArg>,
    /// `Option<String>` to mirror `CREATE PROCEDURE` (no return) vs
    /// `CREATE FUNCTION` (return type required by SQL).
    pub return_type: Option<String>,
    pub language: ProcedureLanguage,
    /// Body as the user wrote it. For SQL: PL/pgSQL-ish source. For
    /// WASM: hex- or base64-encoded bytecode at deploy time (the
    /// `WasmProcEngine` will decode at invocation).
    pub body: String,
    /// Hash over `name || arg_sig || language_byte || body_bytes`.
    /// See module docs for the wire layout.
    pub code_hash: [u8; 32],
}

impl Procedure {
    /// Build a procedure record and compute its on-chain hash.
    pub fn new(
        name: String,
        args: Vec<ProcedureArg>,
        return_type: Option<String>,
        language: ProcedureLanguage,
        body: String,
    ) -> Self {
        let code_hash = compute_code_hash(&name, &args, language, &body);
        Procedure {
            name,
            args,
            return_type,
            language,
            body,
            code_hash,
        }
    }
}

/// On-chain procedure hash. Stable wire format.
pub fn compute_code_hash(
    name: &str,
    args: &[ProcedureArg],
    language: ProcedureLanguage,
    body: &str,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(name.as_bytes());
    // Length-prefix args + a zero separator so e.g. `(a INT, b INT)` and
    // `(ab INT, INT)` can't collide.
    for arg in args {
        h.update((arg.name.len() as u32).to_le_bytes());
        h.update(arg.name.as_bytes());
        h.update((arg.type_keyword.len() as u32).to_le_bytes());
        h.update(arg.type_keyword.as_bytes());
    }
    h.update([0u8]);
    h.update([language.tag()]);
    h.update(body.as_bytes());
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// In-memory registry of procedure definitions.
///
/// Real on-chain code lives in the SQL engine's namespace storage;
/// this struct is the index the dispatcher consults during `INVOKE`.
#[derive(Default, Debug, Clone)]
pub struct ProcedureStore {
    by_name: HashMap<String, Procedure>,
}

impl ProcedureStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new procedure. Returns the on-chain hash on success.
    /// Conflicts with an existing name produce `Duplicate` so the
    /// caller can decide between `OR REPLACE` semantics and a hard
    /// reject.
    pub fn register(&mut self, proc: Procedure) -> Result<[u8; 32], ProcError> {
        if self.by_name.contains_key(&proc.name) {
            return Err(ProcError::Duplicate(proc.name));
        }
        let hash = proc.code_hash;
        self.by_name.insert(proc.name.clone(), proc);
        Ok(hash)
    }

    /// Replace an existing procedure (or insert if absent). Mirrors
    /// `CREATE OR REPLACE FUNCTION`. Returns the new hash.
    pub fn upsert(&mut self, proc: Procedure) -> [u8; 32] {
        let hash = proc.code_hash;
        self.by_name.insert(proc.name.clone(), proc);
        hash
    }

    pub fn get(&self, name: &str) -> Option<&Procedure> {
        self.by_name.get(name)
    }

    pub fn drop(&mut self, name: &str) -> Result<(), ProcError> {
        self.by_name
            .remove(name)
            .ok_or_else(|| ProcError::NotFound(name.to_string()))?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(|s| s.as_str())
    }
}

/// Common interface for executing a procedure body. Implemented by
/// each language backend.
pub trait ProcedureEngine {
    /// Invoke a registered procedure with positional arguments. The
    /// return shape is intentionally a `String`-keyed JSON-ish value
    /// (`Vec<u8>`) so this trait stays free of the `seal-sql` row
    /// types.
    fn invoke(&mut self, proc: &Procedure, args: &[String]) -> Result<Vec<u8>, ProcError>;
}

/// SQL backend. Calls a caller-supplied executor closure with the
/// substituted body so this crate doesn't depend on `seal-sql`.
pub struct SqlProcEngine<F>
where
    F: FnMut(&str) -> Result<Vec<u8>, ProcError>,
{
    pub exec: F,
}

impl<F> SqlProcEngine<F>
where
    F: FnMut(&str) -> Result<Vec<u8>, ProcError>,
{
    pub fn new(exec: F) -> Self {
        Self { exec }
    }
}

impl<F> ProcedureEngine for SqlProcEngine<F>
where
    F: FnMut(&str) -> Result<Vec<u8>, ProcError>,
{
    fn invoke(&mut self, proc: &Procedure, args: &[String]) -> Result<Vec<u8>, ProcError> {
        if proc.language != ProcedureLanguage::Sql {
            return Err(ProcError::LanguageMismatch {
                expected: ProcedureLanguage::Sql,
                actual: proc.language,
            });
        }
        if args.len() != proc.args.len() {
            return Err(ProcError::ArgCount {
                expected: proc.args.len(),
                actual: args.len(),
            });
        }
        // Naive `$1`, `$2`, ... substitution. Good enough for the
        // ADR-001 milestone; the real PL/pgSQL parser will handle
        // declared variables, control flow, and quoting properly.
        let mut body = proc.body.clone();
        for (i, value) in args.iter().enumerate() {
            let placeholder = format!("${}", i + 1);
            body = body.replace(&placeholder, value);
        }
        (self.exec)(&body)
    }
}

/// WASM backend stub. Returns `LanguageNotImplemented` until a
/// deterministic wasmtime / wasmer host is wired up. Keeping the
/// dispatcher path live (rather than `unimplemented!()`) lets users
/// `CREATE FUNCTION ... LANGUAGE wasm` and have it stored — the
/// failure surfaces only on `INVOKE`.
#[derive(Default)]
pub struct WasmProcEngine;

impl WasmProcEngine {
    pub fn new() -> Self {
        Self
    }
}

impl ProcedureEngine for WasmProcEngine {
    fn invoke(&mut self, proc: &Procedure, _args: &[String]) -> Result<Vec<u8>, ProcError> {
        if proc.language != ProcedureLanguage::Wasm {
            return Err(ProcError::LanguageMismatch {
                expected: ProcedureLanguage::Wasm,
                actual: proc.language,
            });
        }
        Err(ProcError::LanguageNotImplemented(ProcedureLanguage::Wasm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(name: &str, ty: &str) -> ProcedureArg {
        ProcedureArg {
            name: name.into(),
            type_keyword: ty.into(),
        }
    }

    #[test]
    fn language_keyword_parses_case_insensitive() {
        assert_eq!(
            ProcedureLanguage::from_keyword("sql"),
            Some(ProcedureLanguage::Sql)
        );
        assert_eq!(
            ProcedureLanguage::from_keyword("SQL"),
            Some(ProcedureLanguage::Sql)
        );
        assert_eq!(
            ProcedureLanguage::from_keyword("WASM"),
            Some(ProcedureLanguage::Wasm)
        );
        assert_eq!(
            ProcedureLanguage::from_keyword("plpgsql"),
            Some(ProcedureLanguage::PlPgSql)
        );
        assert_eq!(
            ProcedureLanguage::from_keyword("PLPGSQL"),
            Some(ProcedureLanguage::PlPgSql)
        );
        assert_eq!(ProcedureLanguage::from_keyword("python"), None);
    }

    #[test]
    fn code_hash_is_stable_across_constructions() {
        let p1 = Procedure::new(
            "f".into(),
            vec![arg("x", "INT")],
            Some("INT".into()),
            ProcedureLanguage::Sql,
            "SELECT $1".into(),
        );
        let p2 = Procedure::new(
            "f".into(),
            vec![arg("x", "INT")],
            Some("INT".into()),
            ProcedureLanguage::Sql,
            "SELECT $1".into(),
        );
        assert_eq!(p1.code_hash, p2.code_hash);
    }

    #[test]
    fn code_hash_changes_on_language_swap() {
        let p1 = Procedure::new(
            "f".into(),
            vec![],
            Some("INT".into()),
            ProcedureLanguage::Sql,
            "BODY".into(),
        );
        let p2 = Procedure::new(
            "f".into(),
            vec![],
            Some("INT".into()),
            ProcedureLanguage::Wasm,
            "BODY".into(),
        );
        assert_ne!(p1.code_hash, p2.code_hash);
    }

    #[test]
    fn code_hash_changes_on_arg_rename() {
        let p1 = Procedure::new(
            "f".into(),
            vec![arg("x", "INT")],
            None,
            ProcedureLanguage::Sql,
            "BODY".into(),
        );
        let p2 = Procedure::new(
            "f".into(),
            vec![arg("y", "INT")],
            None,
            ProcedureLanguage::Sql,
            "BODY".into(),
        );
        assert_ne!(p1.code_hash, p2.code_hash);
    }

    #[test]
    fn store_register_then_get() {
        let mut store = ProcedureStore::new();
        let p = Procedure::new(
            "double".into(),
            vec![arg("x", "INT")],
            Some("INT".into()),
            ProcedureLanguage::Sql,
            "SELECT $1 * 2".into(),
        );
        let hash = store.register(p.clone()).unwrap();
        assert_eq!(hash, p.code_hash);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("double").unwrap().body, "SELECT $1 * 2");
    }

    #[test]
    fn store_rejects_duplicate_unless_upsert() {
        let mut store = ProcedureStore::new();
        let p = Procedure::new(
            "f".into(),
            vec![],
            None,
            ProcedureLanguage::Sql,
            "SELECT 1".into(),
        );
        store.register(p.clone()).unwrap();
        let err = store.register(p.clone()).unwrap_err();
        assert!(matches!(err, ProcError::Duplicate(_)));

        // Upsert path always succeeds.
        let p2 = Procedure::new(
            "f".into(),
            vec![],
            None,
            ProcedureLanguage::Sql,
            "SELECT 2".into(),
        );
        let _ = store.upsert(p2.clone());
        assert_eq!(store.get("f").unwrap().body, "SELECT 2");
    }

    #[test]
    fn sql_engine_substitutes_positional_args() {
        let mut engine = SqlProcEngine::new(|sql: &str| Ok(sql.as_bytes().to_vec()));
        let proc = Procedure::new(
            "add".into(),
            vec![arg("a", "INT"), arg("b", "INT")],
            Some("INT".into()),
            ProcedureLanguage::Sql,
            "SELECT $1 + $2".into(),
        );
        let result = engine
            .invoke(&proc, &["10".into(), "32".into()])
            .unwrap();
        assert_eq!(result, b"SELECT 10 + 32");
    }

    #[test]
    fn sql_engine_rejects_arg_count_mismatch() {
        let mut engine = SqlProcEngine::new(|_| Ok(Vec::new()));
        let proc = Procedure::new(
            "one_arg".into(),
            vec![arg("x", "INT")],
            None,
            ProcedureLanguage::Sql,
            "SELECT $1".into(),
        );
        let err = engine.invoke(&proc, &[]).unwrap_err();
        assert!(matches!(err, ProcError::ArgCount { expected: 1, actual: 0 }));
    }

    #[test]
    fn sql_engine_rejects_wasm_proc() {
        let mut engine = SqlProcEngine::new(|_| Ok(Vec::new()));
        let proc = Procedure::new(
            "f".into(),
            vec![],
            None,
            ProcedureLanguage::Wasm,
            "00 00".into(),
        );
        let err = engine.invoke(&proc, &[]).unwrap_err();
        assert!(matches!(err, ProcError::LanguageMismatch { .. }));
    }

    #[test]
    fn wasm_engine_returns_not_implemented() {
        let mut engine = WasmProcEngine::new();
        let proc = Procedure::new(
            "f".into(),
            vec![],
            None,
            ProcedureLanguage::Wasm,
            "deadbeef".into(),
        );
        let err = engine.invoke(&proc, &[]).unwrap_err();
        assert!(matches!(
            err,
            ProcError::LanguageNotImplemented(ProcedureLanguage::Wasm)
        ));
    }
}
