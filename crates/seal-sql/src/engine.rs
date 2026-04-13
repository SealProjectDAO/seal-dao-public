//! SQL execution engine.
//!
//! Executes parsed SQL statements against an in-memory table store.
//! Tables are stored as collections of rows in a HashMap (for Phase 0).
//! In production, tables will be backed by the Merkle B-tree (seal-merkle).

use sqlparser::ast::{
    self, AssignmentTarget, Expr, FromTable, SelectItem, SetExpr, Statement, Value,
};
use std::collections::HashMap;

use crate::error::SqlError;
use crate::parser::{extract_schema, parse_sql};
use crate::types::{Row, Schema, SealValue};

/// Query result returned by the engine.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Column names in the result set.
    pub columns: Vec<String>,
    /// Rows of data.
    pub rows: Vec<Row>,
    /// Number of rows affected (for INSERT/UPDATE/DELETE).
    pub rows_affected: u64,
}

/// A record of what changed during a write operation.
#[derive(Debug, Clone, Default)]
pub struct WriteLog {
    /// Table that was modified.
    pub table: String,
    /// Row indices that were inserted or updated.
    pub modified_rows: Vec<usize>,
    /// Row indices that were deleted.
    pub deleted_rows: Vec<usize>,
    /// Whether the table structure changed (CREATE/DROP/ALTER).
    pub schema_changed: bool,
}

/// In-memory SQL execution engine.
pub struct Engine {
    schemas: HashMap<String, Schema>,
    /// Index manager for accelerated WHERE lookups.
    pub indexes: crate::index::IndexManager,
    tables: HashMap<String, Vec<Row>>,
    /// Log of the last write operation (for incremental Merkle updates).
    pub last_write_log: Option<WriteLog>,
    /// Block seed for deterministic salt derivation (#STORAGE-FORGET).
    /// When set, row salts are derived from SHA3(seed || table || index)
    /// so all validators processing the same block produce identical state roots.
    /// When None, random salts are used (local/test mode).
    block_seed: Option<Vec<u8>>,
    /// Monotonic counter for salt uniqueness within a block.
    salt_counter: usize,
}

impl Engine {
    pub fn new() -> Self {
        Engine {
            schemas: HashMap::new(),
            tables: HashMap::new(),
            indexes: crate::index::IndexManager::new(),
            last_write_log: None,
            block_seed: None,
            salt_counter: 0,
        }
    }

    /// Set the block seed for deterministic salt derivation.
    /// Call this before executing transactions in a block so all validators
    /// produce identical salts (and thus identical state roots).
    pub fn set_block_seed(&mut self, seed: Vec<u8>) {
        self.block_seed = Some(seed);
        self.salt_counter = 0;
    }

    /// Clear the block seed (reverts to random salts).
    pub fn clear_block_seed(&mut self) {
        self.block_seed = None;
        self.salt_counter = 0;
    }

    /// Get the current block seed (if set).
    pub fn block_seed(&self) -> Option<&Vec<u8>> {
        self.block_seed.as_ref()
    }

    /// Execute a SQL string. Populates `last_write_log` for write operations.
    pub fn execute(&mut self, sql: &str) -> Result<QueryResult, SqlError> {
        self.last_write_log = None;
        let stmts = parse_sql(sql)?;
        let mut last_result = QueryResult {
            columns: vec![],
            rows: vec![],
            rows_affected: 0,
        };

        for stmt in stmts {
            last_result = self.execute_statement(&stmt)?;
        }

        Ok(last_result)
    }

    fn execute_statement(&mut self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        match stmt {
            Statement::CreateTable(_) => self.execute_create_table(stmt),
            Statement::Insert(_) => self.execute_insert(stmt),
            Statement::Query(_) => self.execute_select(stmt),
            Statement::Update { .. } => self.execute_update(stmt),
            Statement::Delete(_) => self.execute_delete(stmt),
            Statement::Drop { .. } => self.execute_drop(stmt),
            Statement::CreateIndex(ci) => {
                let table = ci.table_name.to_string();
                for col in &ci.columns {
                    let col_name = col.expr.to_string();
                    self.indexes.create_index(&table, &col_name);
                }
                Ok(QueryResult {
                    columns: vec![],
                    rows: vec![],
                    rows_affected: 0,
                })
            }
            _ => Err(SqlError::Unsupported(format!("statement: {}", stmt))),
        }
    }

    fn execute_create_table(&mut self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        let schema = extract_schema(stmt)?;
        let name = schema.table_name.clone();

        if self.schemas.contains_key(&name) {
            return Err(SqlError::TableAlreadyExists(name));
        }

        self.schemas.insert(name.clone(), schema);
        self.tables.insert(name.clone(), Vec::new());

        self.last_write_log = Some(WriteLog {
            table: name,
            modified_rows: vec![],
            deleted_rows: vec![],
            schema_changed: true,
        });

        Ok(QueryResult {
            columns: vec![],
            rows: vec![],
            rows_affected: 0,
        })
    }

    fn execute_insert(&mut self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        if let Statement::Insert(insert) = stmt {
            let table_name = insert.table_name.to_string();
            let schema = self
                .schemas
                .get(&table_name)
                .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?
                .clone();

            // Get column names from INSERT or default to schema order
            let col_names: Vec<String> = if insert.columns.is_empty() {
                schema.columns.iter().map(|c| c.name.clone()).collect()
            } else {
                insert.columns.iter().map(|c| c.value.clone()).collect()
            };

            // Extract values from the source
            let source = insert
                .source
                .as_ref()
                .ok_or_else(|| SqlError::Execution("INSERT missing source".into()))?;
            let rows_data = match source.body.as_ref() {
                SetExpr::Values(values) => &values.rows,
                _ => return Err(SqlError::Unsupported("INSERT from subquery".into())),
            };

            let mut count = 0u64;
            for row_exprs in rows_data {
                let mut values = vec![SealValue::Null; schema.columns.len()];

                for (i, expr) in row_exprs.iter().enumerate() {
                    if i >= col_names.len() {
                        break;
                    }
                    let col_idx = schema
                        .find_column(&col_names[i])
                        .ok_or_else(|| SqlError::ColumnNotFound(col_names[i].clone()))?
                        .0;
                    values[col_idx] = eval_expr_to_value(expr)?;
                }

                // Check NOT NULL constraints
                for (i, col) in schema.columns.iter().enumerate() {
                    if !col.nullable && values[i].is_null() {
                        return Err(SqlError::NotNull(col.name.clone()));
                    }
                }

                let rows = self.tables.get_mut(&table_name)
                    .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?;
                let row_idx = rows.len();
                let mut row = Row {
                    values: values.clone(),
                    salt: [0u8; 32],
                };
                if let Some(ref seed) = self.block_seed {
                    row.derive_salt(seed, &table_name, self.salt_counter);
                    self.salt_counter += 1;
                } else {
                    row.generate_salt();
                }
                rows.push(row);
                count += 1;

                // Update indexes with the new row
                for (col_idx, col) in schema.columns.iter().enumerate() {
                    if self.indexes.has_index(&table_name, &col.name) {
                        let val_str = format!("{:?}", values[col_idx]);
                        if let Some(idx) = self.indexes.get_index_mut(&table_name, &col.name) {
                            idx.insert(val_str, row_idx);
                        }
                    }
                }
            }

            self.last_write_log = Some(WriteLog {
                table: table_name,
                modified_rows: (0..count as usize).collect(),
                deleted_rows: vec![],
                schema_changed: false,
            });

            Ok(QueryResult {
                columns: vec![],
                rows: vec![],
                rows_affected: count,
            })
        } else {
            Err(SqlError::Execution("expected INSERT".into()))
        }
    }

    fn execute_select(&self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        if let Statement::Query(query) = stmt {
            match query.body.as_ref() {
                SetExpr::Select(select) => {
                    // Get table name from FROM clause
                    if select.from.is_empty() {
                        return Err(SqlError::Execution("SELECT missing FROM".into()));
                    }
                    let table_name = select.from[0].relation.to_string();
                    let schema = self
                        .schemas
                        .get(&table_name)
                        .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?;
                    let rows = self
                        .tables
                        .get(&table_name)
                        .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?;

                    // Filter by WHERE clause (index-accelerated when possible)
                    let filtered: Vec<&Row> = if let Some(ref expr) = select.selection {
                        // Try to use an index for simple equality: col = value
                        if let Some(indices) =
                            try_index_lookup(expr, &table_name, schema, &self.indexes)
                        {
                            // Index hit: only check the matching rows
                            indices
                                .iter()
                                .filter_map(|&idx| rows.get(idx))
                                .filter(|row| eval_where(expr, row, schema).unwrap_or(false))
                                .collect()
                        } else {
                            // No index: full table scan
                            rows.iter()
                                .filter(|row| eval_where(expr, row, schema).unwrap_or(false))
                                .collect()
                        }
                    } else {
                        rows.iter().collect()
                    };

                    // Project columns
                    let (col_names, col_indices) =
                        resolve_select_items(&select.projection, schema)?;

                    let result_rows: Vec<Row> = filtered
                        .iter()
                        .map(|row| Row {
                            values: col_indices.iter().map(|&i| row.values[i].clone()).collect(),
                            salt: row.salt,
                        })
                        .collect();

                    Ok(QueryResult {
                        columns: col_names,
                        rows: result_rows,
                        rows_affected: 0,
                    })
                }
                _ => Err(SqlError::Unsupported("complex SELECT".into())),
            }
        } else {
            Err(SqlError::Execution("expected SELECT".into()))
        }
    }

    fn execute_update(&mut self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        if let Statement::Update {
            table,
            assignments,
            selection,
            ..
        } = stmt
        {
            let table_name = table.relation.to_string();
            let schema = self
                .schemas
                .get(&table_name)
                .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?
                .clone();
            let rows = self
                .tables
                .get_mut(&table_name)
                .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?;

            let mut count = 0u64;
            let mut modified_rows = Vec::new();
            for (row_idx, row) in rows.iter_mut().enumerate() {
                let matches = match selection {
                    Some(expr) => eval_where(expr, row, &schema).unwrap_or(false),
                    None => true,
                };

                if matches {
                    for assignment in assignments {
                        let col_name = match &assignment.target {
                            AssignmentTarget::ColumnName(name) => name.to_string(),
                            AssignmentTarget::Tuple(_) => {
                                return Err(SqlError::Unsupported("tuple assignment".into()));
                            }
                        };
                        let (col_idx, _) = schema
                            .find_column(&col_name)
                            .ok_or_else(|| SqlError::ColumnNotFound(col_name.clone()))?;
                        row.values[col_idx] = eval_expr_to_value(&assignment.value)?;
                    }
                    // Rotate salt on UPDATE for anti-correlation (#STORAGE-FORGET)
                    if let Some(ref seed) = self.block_seed {
                        row.derive_salt(seed, &table_name, self.salt_counter);
                        self.salt_counter += 1;
                    } else {
                        row.generate_salt();
                    }
                    modified_rows.push(row_idx);
                    count += 1;
                }
            }

            self.last_write_log = Some(WriteLog {
                table: table_name,
                modified_rows,
                deleted_rows: vec![],
                schema_changed: false,
            });

            Ok(QueryResult {
                columns: vec![],
                rows: vec![],
                rows_affected: count,
            })
        } else {
            Err(SqlError::Execution("expected UPDATE".into()))
        }
    }

    fn execute_delete(&mut self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        if let Statement::Delete(delete) = stmt {
            let tables = match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables,
            };
            let table_ref = tables
                .first()
                .ok_or_else(|| SqlError::Execution("DELETE missing FROM".into()))?;
            let table_name = table_ref.relation.to_string();
            let schema = self
                .schemas
                .get(&table_name)
                .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?
                .clone();
            let rows = self
                .tables
                .get_mut(&table_name)
                .ok_or_else(|| SqlError::TableNotFound(table_name.clone()))?;

            // Find which rows will be deleted
            let mut deleted_rows = Vec::new();
            for (idx, row) in rows.iter().enumerate() {
                let should_delete = match &delete.selection {
                    Some(expr) => eval_where(expr, row, &schema).unwrap_or(false),
                    None => true,
                };
                if should_delete {
                    deleted_rows.push(idx);
                }
            }

            let before = rows.len();
            rows.retain(|row| match &delete.selection {
                Some(expr) => !eval_where(expr, row, &schema).unwrap_or(false),
                None => false,
            });

            self.last_write_log = Some(WriteLog {
                table: table_name,
                modified_rows: vec![],
                deleted_rows,
                schema_changed: false,
            });

            Ok(QueryResult {
                columns: vec![],
                rows: vec![],
                rows_affected: (before - rows.len()) as u64,
            })
        } else {
            Err(SqlError::Execution("expected DELETE".into()))
        }
    }

    fn execute_drop(&mut self, stmt: &Statement) -> Result<QueryResult, SqlError> {
        if let Statement::Drop { names, .. } = stmt {
            for name in names {
                let table_name = name.to_string();
                self.schemas.remove(&table_name);
                self.tables.remove(&table_name);
            }
            Ok(QueryResult {
                columns: vec![],
                rows: vec![],
                rows_affected: 0,
            })
        } else {
            Err(SqlError::Execution("expected DROP".into()))
        }
    }

    /// Get a table's schema.
    pub fn get_schema(&self, table_name: &str) -> Option<&Schema> {
        self.schemas.get(table_name)
    }

    /// Get all table names.
    pub fn table_names(&self) -> Vec<&str> {
        self.schemas.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of rows in a table.
    pub fn row_count(&self, table_name: &str) -> Option<usize> {
        self.tables.get(table_name).map(|rows| rows.len())
    }

    /// Estimate the byte size of a table (rows + salts).
    /// Used for storage lease cost computation (#STORAGE-FORGET).
    pub fn table_byte_size(&self, table_name: &str) -> Option<u64> {
        let rows = self.tables.get(table_name)?;
        let mut total: u64 = 0;
        for row in rows {
            // 32 bytes for salt
            total += 32;
            // Estimate value sizes
            for val in &row.values {
                total += match val {
                    SealValue::Null => 1,
                    SealValue::SmallInt(_) => 2,
                    SealValue::Integer(_) => 4,
                    SealValue::BigInt(_) | SealValue::Timestamp(_) | SealValue::SealAmount(_) => 8,
                    SealValue::Real(_) => 4,
                    SealValue::DoublePrecision(_) => 8,
                    SealValue::Boolean(_) => 1,
                    SealValue::Text(s) => 8 + s.len() as u64,
                    SealValue::Numeric(s) | SealValue::Jsonb(s) => 8 + s.len() as u64,
                    SealValue::Bytea(b) | SealValue::SealAddress(b) | SealValue::Uuid(b) => 8 + b.len() as u64,
                };
            }
        }
        Some(total)
    }

    /// Compute a deterministic state root hash over all tables.
    /// Uses SHA3-256 over sorted table names and their serialized rows.
    /// This provides a real Merkle-compatible state commitment.
    pub fn state_root(&self) -> seal_crypto::hash::Hash256 {
        use seal_crypto::hash::Sha3Hasher;

        let mut hasher = Sha3Hasher::new();

        // Sort table names for determinism
        let mut table_names: Vec<&str> = self.schemas.keys().map(|s| s.as_str()).collect();
        table_names.sort();

        for name in &table_names {
            hasher.update(name.as_bytes());

            // Hash schema
            if let Some(schema) = self.schemas.get(*name) {
                for col in &schema.columns {
                    hasher.update(col.name.as_bytes());
                    hasher.update(format!("{:?}", col.data_type).as_bytes());
                }
            }

            // Hash rows (salt included for anti-correlation — #STORAGE-FORGET)
            if let Some(rows) = self.tables.get(*name) {
                let row_count = rows.len() as u64;
                hasher.update(&row_count.to_le_bytes());
                for row in rows {
                    hasher.update(&row.salt);
                    for val in &row.values {
                        let serialized = format!("{:?}", val);
                        hasher.update(serialized.as_bytes());
                    }
                }
            }
        }

        hasher.finalize()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to use an index for a simple WHERE clause (col = value).
/// Returns Some(row_indices) if an index can be used, None otherwise.
fn try_index_lookup(
    expr: &Expr,
    table_name: &str,
    _schema: &Schema,
    indexes: &crate::index::IndexManager,
) -> Option<Vec<usize>> {
    // Only handle simple: column = literal
    if let Expr::BinaryOp { left, op, right } = expr {
        if !matches!(op, ast::BinaryOperator::Eq) {
            return None;
        }

        // Check if left is a column name and right is a literal (or vice versa)
        let (col_name, value) = match (left.as_ref(), right.as_ref()) {
            (Expr::Identifier(ident), Expr::Value(v)) => {
                (ident.value.clone(), format!("{:?}", eval_expr_to_value(&Expr::Value(v.clone())).ok()?))
            }
            (Expr::Value(v), Expr::Identifier(ident)) => {
                (ident.value.clone(), format!("{:?}", eval_expr_to_value(&Expr::Value(v.clone())).ok()?))
            }
            _ => return None,
        };

        // Check if there's an index on this column
        if indexes.has_index(table_name, &col_name) {
            let idx = indexes.get_index(table_name, &col_name)?;
            let rows = idx.lookup_eq(&value);
            if !rows.is_empty() {
                return Some(rows);
            }
        }
    }
    None
}

/// Evaluate a SQL expression to a SealValue (for INSERT values and SET clauses).
fn eval_expr_to_value(expr: &Expr) -> Result<SealValue, SqlError> {
    match expr {
        Expr::Value(v) => match v {
            Value::Number(n, _) => {
                if let Ok(i) = n.parse::<i64>() {
                    Ok(SealValue::BigInt(i))
                } else if let Ok(f) = n.parse::<f64>() {
                    Ok(SealValue::DoublePrecision(f))
                } else {
                    Ok(SealValue::Numeric(n.clone()))
                }
            }
            Value::SingleQuotedString(s) => Ok(SealValue::Text(s.clone())),
            Value::DoubleQuotedString(s) => Ok(SealValue::Text(s.clone())),
            Value::Boolean(b) => Ok(SealValue::Boolean(*b)),
            Value::Null => Ok(SealValue::Null),
            _ => Err(SqlError::Unsupported(format!("value: {:?}", v))),
        },
        Expr::UnaryOp { op, expr } => {
            let val = eval_expr_to_value(expr)?;
            match op {
                ast::UnaryOperator::Minus => match val {
                    SealValue::BigInt(n) => Ok(SealValue::BigInt(-n)),
                    SealValue::DoublePrecision(f) => Ok(SealValue::DoublePrecision(-f)),
                    _ => Err(SqlError::Execution("cannot negate".into())),
                },
                _ => Err(SqlError::Unsupported(format!("unary op: {:?}", op))),
            }
        }
        _ => Err(SqlError::Unsupported(format!("expression: {:?}", expr))),
    }
}

/// Evaluate a WHERE clause predicate against a row.
fn eval_where(expr: &Expr, row: &Row, schema: &Schema) -> Result<bool, SqlError> {
    match expr {
        Expr::BinaryOp { left, op, right } => match op {
            ast::BinaryOperator::Eq => {
                let l = eval_row_expr(left, row, schema)?;
                let r = eval_row_expr(right, row, schema)?;
                Ok(l == r)
            }
            ast::BinaryOperator::NotEq => {
                let l = eval_row_expr(left, row, schema)?;
                let r = eval_row_expr(right, row, schema)?;
                Ok(l != r)
            }
            ast::BinaryOperator::And => {
                Ok(eval_where(left, row, schema)? && eval_where(right, row, schema)?)
            }
            ast::BinaryOperator::Or => {
                Ok(eval_where(left, row, schema)? || eval_where(right, row, schema)?)
            }
            ast::BinaryOperator::Gt => {
                let l = eval_row_expr(left, row, schema)?;
                let r = eval_row_expr(right, row, schema)?;
                Ok(compare_values(&l, &r) == Some(std::cmp::Ordering::Greater))
            }
            ast::BinaryOperator::Lt => {
                let l = eval_row_expr(left, row, schema)?;
                let r = eval_row_expr(right, row, schema)?;
                Ok(compare_values(&l, &r) == Some(std::cmp::Ordering::Less))
            }
            _ => Err(SqlError::Unsupported(format!("operator: {:?}", op))),
        },
        _ => Err(SqlError::Unsupported(format!("where expr: {:?}", expr))),
    }
}

/// Evaluate an expression that references row columns.
fn eval_row_expr(expr: &Expr, row: &Row, schema: &Schema) -> Result<SealValue, SqlError> {
    match expr {
        Expr::Identifier(ident) => {
            let (idx, _) = schema
                .find_column(&ident.value)
                .ok_or_else(|| SqlError::ColumnNotFound(ident.value.clone()))?;
            Ok(row.values[idx].clone())
        }
        Expr::Value(_) | Expr::UnaryOp { .. } => eval_expr_to_value(expr),
        _ => Err(SqlError::Unsupported(format!("row expr: {:?}", expr))),
    }
}

/// Compare two SealValues for ordering.
fn compare_values(a: &SealValue, b: &SealValue) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (SealValue::BigInt(a), SealValue::BigInt(b)) => Some(a.cmp(b)),
        (SealValue::Integer(a), SealValue::Integer(b)) => Some(a.cmp(b)),
        (SealValue::Text(a), SealValue::Text(b)) => Some(a.cmp(b)),
        (SealValue::Boolean(a), SealValue::Boolean(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

/// Resolve SELECT columns to indices.
fn resolve_select_items(
    items: &[SelectItem],
    schema: &Schema,
) -> Result<(Vec<String>, Vec<usize>), SqlError> {
    let mut names = Vec::new();
    let mut indices = Vec::new();

    for item in items {
        match item {
            SelectItem::Wildcard(_) => {
                for (i, col) in schema.columns.iter().enumerate() {
                    names.push(col.name.clone());
                    indices.push(i);
                }
            }
            SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                let (idx, col) = schema
                    .find_column(&ident.value)
                    .ok_or_else(|| SqlError::ColumnNotFound(ident.value.clone()))?;
                names.push(col.name.clone());
                indices.push(idx);
            }
            _ => return Err(SqlError::Unsupported(format!("select item: {:?}", item))),
        }
    }

    Ok((names, indices))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_table() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();
        assert!(engine.get_schema("users").is_some());
    }

    #[test]
    fn test_create_duplicate_table() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .unwrap();
        assert!(engine
            .execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .is_err());
    }

    #[test]
    fn test_insert_and_select() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();

        let r = engine
            .execute("INSERT INTO users (id, name) VALUES (1, 'alice')")
            .unwrap();
        assert_eq!(r.rows_affected, 1);

        let r = engine.execute("SELECT * FROM users").unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.columns, vec!["id", "name"]);
        assert_eq!(r.rows[0].values[0], SealValue::BigInt(1));
        assert_eq!(r.rows[0].values[1], SealValue::Text("alice".into()));
    }

    #[test]
    fn test_select_with_where() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'a')")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (2, 'b')")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (3, 'c')")
            .unwrap();

        let r = engine.execute("SELECT * FROM t WHERE id = 2").unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0].values[1], SealValue::Text("b".into()));
    }

    #[test]
    fn test_select_specific_columns() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, name TEXT, email TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, name, email) VALUES (1, 'alice', 'a@b.c')")
            .unwrap();

        let r = engine.execute("SELECT name FROM t").unwrap();
        assert_eq!(r.columns, vec!["name"]);
        assert_eq!(r.rows[0].values.len(), 1);
        assert_eq!(r.rows[0].values[0], SealValue::Text("alice".into()));
    }

    #[test]
    fn test_update() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'old')")
            .unwrap();

        let r = engine
            .execute("UPDATE t SET val = 'new' WHERE id = 1")
            .unwrap();
        assert_eq!(r.rows_affected, 1);

        let r = engine.execute("SELECT * FROM t WHERE id = 1").unwrap();
        assert_eq!(r.rows[0].values[1], SealValue::Text("new".into()));
    }

    #[test]
    fn test_delete() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'a')")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (2, 'b')")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (3, 'c')")
            .unwrap();

        let r = engine.execute("DELETE FROM t WHERE id = 2").unwrap();
        assert_eq!(r.rows_affected, 1);

        let r = engine.execute("SELECT * FROM t").unwrap();
        assert_eq!(r.rows.len(), 2);
    }

    #[test]
    fn test_drop_table() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .unwrap();
        engine.execute("DROP TABLE t").unwrap();
        assert!(engine.get_schema("t").is_none());
    }

    #[test]
    fn test_not_null_violation() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();
        // Insert without providing name (which is NOT NULL)
        assert!(engine.execute("INSERT INTO t (id) VALUES (1)").is_err());
    }

    #[test]
    fn test_table_not_found() {
        let mut engine = Engine::new();
        assert!(engine.execute("SELECT * FROM nonexistent").is_err());
    }

    #[test]
    fn test_multiple_inserts() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();

        for i in 0..100 {
            engine
                .execute(&format!(
                    "INSERT INTO t (id, val) VALUES ({}, 'item_{}')",
                    i, i
                ))
                .unwrap();
        }

        let r = engine.execute("SELECT * FROM t").unwrap();
        assert_eq!(r.rows.len(), 100);
    }

    #[test]
    fn test_where_greater_than() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, score BIGINT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, score) VALUES (1, 10)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, score) VALUES (2, 50)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, score) VALUES (3, 90)")
            .unwrap();

        let r = engine.execute("SELECT * FROM t WHERE score > 40").unwrap();
        assert_eq!(r.rows.len(), 2);
    }

    #[test]
    fn test_boolean_values() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, active BOOLEAN)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, active) VALUES (1, true)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, active) VALUES (2, false)")
            .unwrap();

        let r = engine
            .execute("SELECT * FROM t WHERE active = true")
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0].values[0], SealValue::BigInt(1));
    }

    #[test]
    fn test_state_root_empty() {
        let engine = Engine::new();
        let root = engine.state_root();
        // Empty engine should have a consistent root
        let root2 = engine.state_root();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_state_root_changes_on_insert() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        let root1 = engine.state_root();

        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'hello')")
            .unwrap();
        let root2 = engine.state_root();
        assert_ne!(root1, root2, "state root should change after insert");

        engine
            .execute("INSERT INTO t (id, val) VALUES (2, 'world')")
            .unwrap();
        let root3 = engine.state_root();
        assert_ne!(root2, root3, "state root should change after second insert");
    }

    #[test]
    fn test_state_root_deterministic() {
        // With random salts, two separate engines produce different roots
        // (by design — #STORAGE-FORGET). Determinism is preserved within
        // a single engine: same state → same root on repeated calls.
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'a')")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (2, 'b')")
            .unwrap();

        let root1 = engine.state_root();
        let root2 = engine.state_root();
        assert_eq!(root1, root2, "same state must produce same root");
    }

    #[test]
    fn test_state_root_changes_on_update() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'old')")
            .unwrap();
        let root_before = engine.state_root();

        engine
            .execute("UPDATE t SET val = 'new' WHERE id = 1")
            .unwrap();
        let root_after = engine.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_state_root_changes_on_delete() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (1, 'a')")
            .unwrap();
        engine
            .execute("INSERT INTO t (id, val) VALUES (2, 'b')")
            .unwrap();
        let root_before = engine.state_root();

        engine.execute("DELETE FROM t WHERE id = 1").unwrap();
        let root_after = engine.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_row_count() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE t (id BIGINT PRIMARY KEY)")
            .unwrap();
        assert_eq!(engine.row_count("t"), Some(0));

        engine.execute("INSERT INTO t (id) VALUES (1)").unwrap();
        assert_eq!(engine.row_count("t"), Some(1));

        engine.execute("INSERT INTO t (id) VALUES (2)").unwrap();
        assert_eq!(engine.row_count("t"), Some(2));

        assert_eq!(engine.row_count("nonexistent"), None);
    }

    #[test]
    fn test_create_index() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)")
            .unwrap();
        engine
            .execute("CREATE INDEX idx_name ON users (name)")
            .unwrap();

        assert!(engine.indexes.has_index("users", "name"));
        assert!(!engine.indexes.has_index("users", "email"));
    }

    #[test]
    fn test_index_populated_on_insert() {
        let mut engine = Engine::new();
        engine
            .execute("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)")
            .unwrap();
        engine
            .execute("CREATE INDEX idx_name ON users (name)")
            .unwrap();
        engine
            .execute("INSERT INTO users (id, name) VALUES (1, 'alice')")
            .unwrap();
        engine
            .execute("INSERT INTO users (id, name) VALUES (2, 'bob')")
            .unwrap();
        engine
            .execute("INSERT INTO users (id, name) VALUES (3, 'alice')")
            .unwrap();

        // Index should have entries
        let idx = engine.indexes.get_index("users", "name").unwrap();
        assert_eq!(idx.distinct_count(), 2); // alice + bob

        // SELECT with WHERE on indexed column works
        let result = engine
            .execute("SELECT * FROM users WHERE name = 'alice'")
            .unwrap();
        assert_eq!(result.rows.len(), 2);
    }
}
