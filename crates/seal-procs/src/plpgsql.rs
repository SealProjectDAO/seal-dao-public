//! PL/pgSQL parser shim.
//!
//! Postgres' PL/pgSQL is a procedural language wrapping SQL with
//! declared variables, `IF`/`LOOP`, exception handling, and `RAISE`. A
//! full implementation is its own multi-month project. This shim
//! accepts the *subset* that `LANGUAGE plpgsql` deployments in our test
//! suite currently use, and is structured so the parser can grow:
//!
//! ```text
//! BEGIN
//!     RETURN <expr>;
//! END;
//! ```
//!
//! and:
//!
//! ```text
//! BEGIN
//!     <SQL statement>;
//!     <SQL statement>;
//!     RETURN <expr>;
//! END;
//! ```
//!
//! Lowering rules:
//!
//! * The trailing `RETURN <expr>;` becomes `SELECT <expr>` and is run
//!   as the final SQL statement.
//! * Any preceding `;`-terminated SQL statements are run in declaration
//!   order through `seal-sql`.
//! * Statements outside a `BEGIN ... END;` block are passed through
//!   unchanged so callers can register a one-liner without the
//!   ceremony.
//!
//! What this DOES NOT yet handle (returns
//! `ProcError::LanguageNotImplemented`):
//!
//! * `DECLARE` blocks with typed local variables
//! * `IF`/`ELSIF`/`ELSE`/`END IF`
//! * `LOOP`/`WHILE`/`FOR ... IN ... LOOP`
//! * `EXCEPTION WHEN ... THEN` blocks
//! * `RAISE NOTICE | EXCEPTION`
//!
//! When the executor crate is ready to lift one of those, it can land
//! here behind the same lowering API.

use crate::error::ProcError;

/// Lower a PL/pgSQL body to a sequence of plain SQL statements ready
/// for `seal-sql::Engine::execute`. The output is a vector so the
/// caller can decide whether to execute statements one at a time
/// (committing intermediate writes) or join them with `;` and submit
/// in one batch.
pub fn lower_to_sql(body: &str) -> Result<Vec<String>, ProcError> {
    let trimmed = body.trim();

    // No-block form: pass straight through. Lets a caller register
    // `LANGUAGE plpgsql AS $$SELECT 1$$;` without forcing them to wrap.
    let upper = trimmed.to_ascii_uppercase();
    if !upper.starts_with("BEGIN") {
        return Ok(vec![rewrite_return_to_select(trimmed)]);
    }

    // BEGIN ... END; or BEGIN ... END
    let inner = trimmed
        .strip_prefix("BEGIN")
        .or_else(|| trimmed.strip_prefix("begin"))
        .ok_or_else(|| ProcError::Execution("expected BEGIN".into()))?
        .trim_start();
    let inner = inner
        .trim_end()
        .trim_end_matches(';')
        .trim_end()
        .strip_suffix("END")
        .or_else(|| {
            inner
                .trim_end()
                .trim_end_matches(';')
                .trim_end()
                .strip_suffix("end")
        })
        .ok_or_else(|| ProcError::Execution("expected END".into()))?;

    // Split inner block on `;` boundaries, preserving order, dropping empties.
    let mut stmts: Vec<String> = inner
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Reject anything that looks like a control-flow construct we
    // haven't lowered yet — silently passing them to seal-sql would
    // produce a confusing parse error downstream.
    for stmt in &stmts {
        let head = stmt
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        match head.as_str() {
            "IF" | "ELSIF" | "ELSE" | "WHILE" | "LOOP" | "FOR" | "DECLARE" | "RAISE"
            | "EXCEPTION" | "PERFORM" => {
                return Err(ProcError::LanguageNotImplemented(
                    crate::ProcedureLanguage::PlPgSql,
                ));
            }
            _ => {}
        }
    }

    // Trailing `RETURN <expr>` becomes `SELECT <expr>` so the final
    // result is queryable.
    if let Some(last) = stmts.last_mut() {
        *last = rewrite_return_to_select(last);
    }

    Ok(stmts)
}

/// Helper: rewrite `RETURN <expr>` (case-insensitive) into `SELECT <expr>`.
/// Anything else is returned untouched.
fn rewrite_return_to_select(stmt: &str) -> String {
    let trimmed = stmt.trim_start();
    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("RETURN ") {
        format!("SELECT {}", &trimmed[7..])
    } else {
        stmt.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_no_block_body() {
        let out = lower_to_sql("SELECT 1").unwrap();
        assert_eq!(out, vec!["SELECT 1".to_string()]);
    }

    #[test]
    fn rewrites_naked_return_to_select() {
        let out = lower_to_sql("RETURN 42").unwrap();
        assert_eq!(out, vec!["SELECT 42".to_string()]);
    }

    #[test]
    fn lowers_begin_end_block_with_return() {
        let body = "BEGIN INSERT INTO t (id) VALUES (1); RETURN 1; END;";
        let out = lower_to_sql(body).unwrap();
        assert_eq!(
            out,
            vec![
                "INSERT INTO t (id) VALUES (1)".to_string(),
                "SELECT 1".to_string(),
            ]
        );
    }

    #[test]
    fn lowers_begin_end_block_without_trailing_semicolon() {
        let body = "BEGIN SELECT 1 END";
        let out = lower_to_sql(body).unwrap();
        assert_eq!(out, vec!["SELECT 1".to_string()]);
    }

    #[test]
    fn rejects_unsupported_control_flow() {
        let body = "BEGIN IF x > 0 THEN RAISE NOTICE 'pos'; END IF; RETURN 1; END;";
        let err = lower_to_sql(body).unwrap_err();
        assert!(matches!(
            err,
            ProcError::LanguageNotImplemented(crate::ProcedureLanguage::PlPgSql)
        ));
    }

    #[test]
    fn rejects_declare_block() {
        let body = "BEGIN DECLARE x INT; RETURN x; END;";
        let err = lower_to_sql(body).unwrap_err();
        assert!(matches!(
            err,
            ProcError::LanguageNotImplemented(crate::ProcedureLanguage::PlPgSql)
        ));
    }
}
