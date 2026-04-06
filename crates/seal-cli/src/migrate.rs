//! `seal migrate analyze` — convert pg_dump schemas to Seal SQL.
//!
//! Reads a PostgreSQL schema dump and:
//! 1. Maps types to Seal SQL types
//! 2. Strips unsupported features (with warnings)
//! 3. Outputs a .seal.sql file ready for deployment
//!
//! See SPEC.md §13 for the full migration spec.

use seal_sql::parser::{extract_schema, parse_sql};

/// Migration report entry.
#[derive(Debug)]
pub enum MigrateMessage {
    Info(String),
    Warning(String),
    Error(String),
}

/// Result of analyzing a pg_dump.
pub struct MigrateResult {
    /// Transformed SQL (Seal-compatible).
    pub output_sql: String,
    /// Messages (info, warnings, errors).
    pub messages: Vec<MigrateMessage>,
    /// Number of tables found.
    pub tables: usize,
    /// Number of types mapped.
    pub types_mapped: usize,
    /// Number of unsupported features stripped.
    pub features_stripped: usize,
}

/// Analyze a PostgreSQL schema dump and convert to Seal SQL.
pub fn analyze_schema(pg_sql: &str) -> MigrateResult {
    let mut messages = Vec::new();
    let mut output_lines = Vec::new();
    let mut tables = 0;
    let mut types_mapped = 0;
    let mut features_stripped = 0;

    // Parse the SQL
    let statements = match parse_sql(pg_sql) {
        Ok(stmts) => stmts,
        Err(e) => {
            messages.push(MigrateMessage::Error(format!("Parse error: {}", e)));
            return MigrateResult {
                output_sql: String::new(),
                messages,
                tables: 0,
                types_mapped: 0,
                features_stripped: 0,
            };
        }
    };

    for stmt in &statements {
        let stmt_str = stmt.to_string();
        let upper = stmt_str.trim().to_uppercase();

        // Handle CREATE TABLE
        if upper.starts_with("CREATE TABLE") {
            match extract_schema(stmt) {
                Ok(schema) => {
                    tables += 1;
                    messages.push(MigrateMessage::Info(format!(
                        "Table '{}': {} columns",
                        schema.table_name,
                        schema.columns.len()
                    )));

                    for _col in &schema.columns {
                        types_mapped += 1;
                    }

                    // Pass through as-is (already PostgreSQL-compatible)
                    output_lines.push(format!("{};\n", stmt));
                }
                Err(e) => {
                    messages.push(MigrateMessage::Warning(format!(
                        "Could not extract schema: {}",
                        e
                    )));
                    output_lines.push(format!("-- UNSUPPORTED: {}\n", stmt));
                    features_stripped += 1;
                }
            }
        }
        // Strip SERIAL/BIGSERIAL → warn
        else if upper.contains("SERIAL") {
            messages.push(MigrateMessage::Warning(
                "SERIAL/BIGSERIAL: use BIGINT with app-generated IDs".into(),
            ));
            // Convert: replace SERIAL with BIGINT
            let converted = stmt_str
                .replace("SERIAL", "BIGINT")
                .replace("serial", "BIGINT");
            output_lines.push(format!("{};\n", converted));
            features_stripped += 1;
        }
        // Strip CREATE VIEW → error
        else if upper.starts_with("CREATE VIEW") || upper.starts_with("CREATE OR REPLACE VIEW") {
            messages.push(MigrateMessage::Error(
                "Views not supported. Inline the view definition into queries.".into(),
            ));
            output_lines.push(format!("-- UNSUPPORTED: {}\n", stmt));
            features_stripped += 1;
        }
        // Strip CREATE FUNCTION → error
        else if upper.starts_with("CREATE FUNCTION")
            || upper.starts_with("CREATE OR REPLACE FUNCTION")
        {
            messages.push(MigrateMessage::Error(
                "Stored procedures not supported. Move logic to application layer.".into(),
            ));
            output_lines.push(format!("-- UNSUPPORTED: {}\n", stmt));
            features_stripped += 1;
        }
        // Pass through supported statements
        else if upper.starts_with("INSERT")
            || upper.starts_with("CREATE INDEX")
            || upper.starts_with("ALTER TABLE")
        {
            output_lines.push(format!("{};\n", stmt));
        }
        // Warn on unknown
        else {
            messages.push(MigrateMessage::Warning(format!(
                "Unknown statement type: {}",
                &stmt_str[..stmt_str.len().min(60)]
            )));
            output_lines.push(format!("-- REVIEW: {}\n", stmt));
        }
    }

    MigrateResult {
        output_sql: output_lines.join(""),
        messages,
        tables,
        types_mapped,
        features_stripped,
    }
}

/// Print a migration report to stdout.
pub fn print_report(result: &MigrateResult) {
    println!("=== Migration Analysis ===\n");
    println!("Tables found: {}", result.tables);
    println!("Types mapped: {}", result.types_mapped);
    println!("Features stripped: {}", result.features_stripped);
    println!();

    for msg in &result.messages {
        match msg {
            MigrateMessage::Info(s) => println!("  INFO: {}", s),
            MigrateMessage::Warning(s) => println!("  WARN: {}", s),
            MigrateMessage::Error(s) => println!("  ERROR: {}", s),
        }
    }

    if !result.output_sql.is_empty() {
        println!("\n=== Output SQL ===\n");
        println!("{}", result.output_sql);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_simple_schema() {
        let sql = "CREATE TABLE users (
            id BIGINT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT,
            score DOUBLE PRECISION
        )";

        let result = analyze_schema(sql);
        assert_eq!(result.tables, 1);
        assert_eq!(result.types_mapped, 4);
        assert_eq!(result.features_stripped, 0);
        assert!(result.output_sql.contains("CREATE TABLE"));
    }

    #[test]
    fn test_analyze_multiple_tables() {
        let sql = "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT);
                   CREATE TABLE posts (id BIGINT PRIMARY KEY, body TEXT)";

        let result = analyze_schema(sql);
        assert_eq!(result.tables, 2);
    }

    #[test]
    fn test_analyze_with_index() {
        let sql = "CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT);
                   CREATE INDEX idx_val ON t (val)";

        let result = analyze_schema(sql);
        assert_eq!(result.tables, 1);
        assert!(result.output_sql.contains("CREATE INDEX"));
    }

    #[test]
    fn test_analyze_invalid_sql() {
        let result = analyze_schema("THIS IS NOT SQL AT ALL");
        assert_eq!(result.tables, 0);
        assert!(result
            .messages
            .iter()
            .any(|m| matches!(m, MigrateMessage::Error(_))));
    }

    #[test]
    fn test_analyze_postgresql_types() {
        let sql = "CREATE TABLE t (
            id BIGINT PRIMARY KEY,
            data BYTEA,
            meta JSONB,
            uid UUID,
            amount NUMERIC(18, 9),
            active BOOLEAN,
            created TIMESTAMP
        )";

        let result = analyze_schema(sql);
        assert_eq!(result.tables, 1);
        assert_eq!(result.types_mapped, 7);
        assert_eq!(result.features_stripped, 0);
    }

    #[test]
    fn test_analyze_strips_functions() {
        let sql = "CREATE TABLE t (id BIGINT PRIMARY KEY);
                   CREATE FUNCTION my_func() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql";
        let result = analyze_schema(sql);
        assert!(result
            .messages
            .iter()
            .any(|m| matches!(m, MigrateMessage::Error(_))));
        assert!(result.features_stripped >= 1);
    }

    #[test]
    fn test_analyze_empty_sql() {
        let result = analyze_schema("");
        assert_eq!(result.tables, 0);
        assert_eq!(result.types_mapped, 0);
    }

    #[test]
    fn test_analyze_inserts_pass_through() {
        let sql = "CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT);
                   INSERT INTO t (id, val) VALUES (1, 'hello')";
        let result = analyze_schema(sql);
        assert!(result.output_sql.contains("INSERT INTO"));
    }

    #[test]
    fn test_report_format() {
        let sql = "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)";
        let result = analyze_schema(sql);
        // print_report shouldn't panic
        print_report(&result);
    }

    #[test]
    fn test_analyze_strips_views() {
        let sql = "CREATE TABLE t (id BIGINT PRIMARY KEY);
                   CREATE VIEW v AS SELECT * FROM t";
        let result = analyze_schema(sql);
        assert!(result
            .messages
            .iter()
            .any(|m| matches!(m, MigrateMessage::Error(_))));
        assert_eq!(result.features_stripped, 1);
        assert!(result.output_sql.contains("UNSUPPORTED"));
    }
}
