//! SQL parser — wraps sqlparser-rs with PostgreSQL dialect.

use sqlparser::ast::{ColumnOption, DataType, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::error::SqlError;
use crate::types::{Column, Schema, SealType};

/// Parse a SQL string into sqlparser AST statements.
pub fn parse_sql(sql: &str) -> Result<Vec<Statement>, SqlError> {
    let dialect = PostgreSqlDialect {};
    Parser::parse_sql(&dialect, sql).map_err(|e| SqlError::Parse(e.to_string()))
}

/// Convert a sqlparser DataType to a SealType.
pub fn map_data_type(dt: &DataType) -> Result<SealType, SqlError> {
    match dt {
        DataType::SmallInt(_) => Ok(SealType::SmallInt),
        DataType::Int(_) | DataType::Integer(_) => Ok(SealType::Integer),
        DataType::BigInt(_) => Ok(SealType::BigInt),
        DataType::Real => Ok(SealType::Real),
        DataType::Float4 => Ok(SealType::Real),
        DataType::DoublePrecision | DataType::Float8 => Ok(SealType::DoublePrecision),
        DataType::Numeric(_) | DataType::Decimal(_) => Ok(SealType::Numeric),
        DataType::Text => Ok(SealType::Text),
        DataType::Varchar(_) | DataType::CharVarying(_) => Ok(SealType::Text),
        DataType::Char(_) | DataType::Character(_) => Ok(SealType::Text),
        DataType::Bytea => Ok(SealType::Bytea),
        DataType::Boolean => Ok(SealType::Boolean),
        DataType::Timestamp(_, _) => Ok(SealType::Timestamp),
        DataType::Uuid => Ok(SealType::Uuid),
        DataType::JSON | DataType::JSONB => Ok(SealType::Jsonb),
        DataType::Custom(name, _) => {
            let name_str = name.to_string().to_uppercase();
            match name_str.as_str() {
                "SEAL_ADDRESS" => Ok(SealType::SealAddress),
                "SEAL_AMOUNT" => Ok(SealType::SealAmount),
                "TIMESTAMPTZ" => Ok(SealType::TimestampTz),
                "INTERVAL" => Ok(SealType::Interval),
                _ => Err(SqlError::Unsupported(format!("type: {}", name_str))),
            }
        }
        DataType::Interval => Ok(SealType::Interval),
        _ => Err(SqlError::Unsupported(format!("type: {}", dt))),
    }
}

/// Extract a Schema from a CREATE TABLE statement.
pub fn extract_schema(stmt: &Statement) -> Result<Schema, SqlError> {
    match stmt {
        Statement::CreateTable(ct) => {
            let table_name = ct.name.to_string();
            let mut columns = Vec::new();

            for col_def in &ct.columns {
                let name = col_def.name.value.clone();
                let data_type = map_data_type(&col_def.data_type)?;
                let mut nullable = true;
                let mut primary_key = false;

                for option in &col_def.options {
                    match &option.option {
                        ColumnOption::NotNull => nullable = false,
                        ColumnOption::Unique { is_primary, .. } => {
                            if *is_primary {
                                primary_key = true;
                                nullable = false;
                            }
                        }
                        _ => {}
                    }
                }

                columns.push(Column {
                    name,
                    data_type,
                    nullable,
                    primary_key,
                });
            }

            Ok(Schema {
                table_name,
                columns,
            })
        }
        _ => Err(SqlError::Parse("expected CREATE TABLE statement".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_create_table() {
        let sql = "CREATE TABLE users (
            id BIGINT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT,
            balance NUMERIC(18, 9),
            active BOOLEAN DEFAULT true
        )";

        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);

        let schema = extract_schema(&stmts[0]).unwrap();
        assert_eq!(schema.table_name, "users");
        assert_eq!(schema.columns.len(), 5);

        assert_eq!(schema.columns[0].name, "id");
        assert_eq!(schema.columns[0].data_type, SealType::BigInt);
        assert!(schema.columns[0].primary_key);
        assert!(!schema.columns[0].nullable);

        assert_eq!(schema.columns[1].name, "name");
        assert_eq!(schema.columns[1].data_type, SealType::Text);
        assert!(!schema.columns[1].nullable);

        assert_eq!(schema.columns[2].name, "email");
        assert_eq!(schema.columns[2].data_type, SealType::Text);
        assert!(schema.columns[2].nullable);

        assert_eq!(schema.columns[3].data_type, SealType::Numeric);
        assert_eq!(schema.columns[4].data_type, SealType::Boolean);
    }

    #[test]
    fn test_parse_insert() {
        let sql = "INSERT INTO users (id, name) VALUES (1, 'alice')";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Statement::Insert(_)));
    }

    #[test]
    fn test_parse_select() {
        let sql = "SELECT id, name FROM users WHERE active = true ORDER BY name LIMIT 10";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Statement::Query(_)));
    }

    #[test]
    fn test_parse_select_with_join() {
        let sql = "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.author_id";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_parse_select_with_group_by() {
        let sql = "SELECT author_id, COUNT(*) FROM posts GROUP BY author_id HAVING COUNT(*) > 5";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_parse_update() {
        let sql = "UPDATE users SET name = 'bob' WHERE id = 1";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Statement::Update { .. }));
    }

    #[test]
    fn test_parse_delete() {
        let sql = "DELETE FROM users WHERE id = 1";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Statement::Delete(_)));
    }

    #[test]
    fn test_parse_create_index() {
        let sql = "CREATE INDEX idx_users_name ON users (name)";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_parse_alter_table() {
        let sql = "ALTER TABLE users ADD COLUMN age INTEGER";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Statement::AlterTable { .. }));
    }

    #[test]
    fn test_parse_multiple_statements() {
        let sql = "CREATE TABLE t1 (id INTEGER PRIMARY KEY); INSERT INTO t1 (id) VALUES (1)";
        let stmts = parse_sql(sql).unwrap();
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn test_parse_invalid_sql() {
        assert!(parse_sql("THIS IS NOT SQL").is_err());
    }

    #[test]
    fn test_type_mapping() {
        assert_eq!(
            map_data_type(&DataType::SmallInt(None)).unwrap(),
            SealType::SmallInt
        );
        assert_eq!(
            map_data_type(&DataType::BigInt(None)).unwrap(),
            SealType::BigInt
        );
        assert_eq!(map_data_type(&DataType::Text).unwrap(), SealType::Text);
        assert_eq!(
            map_data_type(&DataType::Boolean).unwrap(),
            SealType::Boolean
        );
        assert_eq!(map_data_type(&DataType::Bytea).unwrap(), SealType::Bytea);
        assert_eq!(map_data_type(&DataType::Uuid).unwrap(), SealType::Uuid);
        assert_eq!(map_data_type(&DataType::JSONB).unwrap(), SealType::Jsonb);
    }

    #[test]
    fn test_postgresql_types_roundtrip() {
        // This SQL uses PostgreSQL-specific types and should parse correctly
        let sql = "CREATE TABLE test (
            id BIGINT PRIMARY KEY,
            data BYTEA,
            metadata JSONB,
            uid UUID,
            score DOUBLE PRECISION,
            is_active BOOLEAN,
            amount NUMERIC(18, 9)
        )";
        let stmts = parse_sql(sql).unwrap();
        let schema = extract_schema(&stmts[0]).unwrap();
        assert_eq!(schema.columns[1].data_type, SealType::Bytea);
        assert_eq!(schema.columns[2].data_type, SealType::Jsonb);
        assert_eq!(schema.columns[3].data_type, SealType::Uuid);
        assert_eq!(schema.columns[4].data_type, SealType::DoublePrecision);
        assert_eq!(schema.columns[5].data_type, SealType::Boolean);
        assert_eq!(schema.columns[6].data_type, SealType::Numeric);
    }
}
