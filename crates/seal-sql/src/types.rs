//! Seal SQL type system — PostgreSQL-compatible subset.

use serde::{Deserialize, Serialize};

/// Supported SQL column types (PostgreSQL names).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealType {
    SmallInt,        // 16-bit signed
    Integer,         // 32-bit signed
    BigInt,          // 64-bit signed
    Real,            // 32-bit float
    DoublePrecision, // 64-bit float
    Numeric,         // Arbitrary precision decimal (stored as string)
    Text,            // Variable-length UTF-8
    Bytea,           // Binary data
    Boolean,         // true/false
    Timestamp,       // Date and time (stored as i64 micros since epoch)
    TimestampTz,     // Timestamp with time zone
    Interval,        // Time duration
    Uuid,            // UUID (stored as 16 bytes)
    Jsonb,           // JSON binary
    SealAddress,     // Native chain address (32 bytes)
    SealAmount,      // Native token amount (u64, 9 decimal places)
}

/// A runtime SQL value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SealValue {
    Null,
    SmallInt(i16),
    Integer(i32),
    BigInt(i64),
    Real(f32),
    DoublePrecision(f64),
    Numeric(String),
    Text(String),
    Bytea(Vec<u8>),
    Boolean(bool),
    Timestamp(i64),       // microseconds since epoch
    Uuid(Vec<u8>),        // 16 bytes
    Jsonb(String),        // JSON string
    SealAddress(Vec<u8>), // 32 bytes
    SealAmount(u64),      // micro-SEAL (9 decimals)
}

impl SealValue {
    pub fn type_name(&self) -> &str {
        match self {
            SealValue::Null => "NULL",
            SealValue::SmallInt(_) => "SMALLINT",
            SealValue::Integer(_) => "INTEGER",
            SealValue::BigInt(_) => "BIGINT",
            SealValue::Real(_) => "REAL",
            SealValue::DoublePrecision(_) => "DOUBLE PRECISION",
            SealValue::Numeric(_) => "NUMERIC",
            SealValue::Text(_) => "TEXT",
            SealValue::Bytea(_) => "BYTEA",
            SealValue::Boolean(_) => "BOOLEAN",
            SealValue::Timestamp(_) => "TIMESTAMP",
            SealValue::Uuid(_) => "UUID",
            SealValue::Jsonb(_) => "JSONB",
            SealValue::SealAddress(_) => "SEAL_ADDRESS",
            SealValue::SealAmount(_) => "SEAL_AMOUNT",
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, SealValue::Null)
    }
}

/// A column definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub data_type: SealType,
    pub nullable: bool,
    pub primary_key: bool,
}

/// A table schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub table_name: String,
    pub columns: Vec<Column>,
}

impl Schema {
    pub fn find_column(&self, name: &str) -> Option<(usize, &Column)> {
        self.columns
            .iter()
            .enumerate()
            .find(|(_, c)| c.name == name)
    }

    pub fn primary_key_column(&self) -> Option<(usize, &Column)> {
        self.columns.iter().enumerate().find(|(_, c)| c.primary_key)
    }
}

/// A row of data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub values: Vec<SealValue>,
}

impl Row {
    pub fn get(&self, idx: usize) -> Option<&SealValue> {
        self.values.get(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_find_column() {
        let schema = Schema {
            table_name: "users".into(),
            columns: vec![
                Column {
                    name: "id".into(),
                    data_type: SealType::BigInt,
                    nullable: false,
                    primary_key: true,
                },
                Column {
                    name: "name".into(),
                    data_type: SealType::Text,
                    nullable: false,
                    primary_key: false,
                },
                Column {
                    name: "email".into(),
                    data_type: SealType::Text,
                    nullable: true,
                    primary_key: false,
                },
            ],
        };

        assert_eq!(schema.find_column("id").unwrap().0, 0);
        assert_eq!(schema.find_column("email").unwrap().0, 2);
        assert!(schema.find_column("missing").is_none());
    }

    #[test]
    fn test_schema_primary_key() {
        let schema = Schema {
            table_name: "test".into(),
            columns: vec![
                Column {
                    name: "id".into(),
                    data_type: SealType::BigInt,
                    nullable: false,
                    primary_key: true,
                },
                Column {
                    name: "val".into(),
                    data_type: SealType::Text,
                    nullable: true,
                    primary_key: false,
                },
            ],
        };
        let (idx, col) = schema.primary_key_column().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(col.name, "id");
    }

    #[test]
    fn test_value_type_name() {
        assert_eq!(SealValue::Integer(42).type_name(), "INTEGER");
        assert_eq!(SealValue::Text("hi".into()).type_name(), "TEXT");
        assert_eq!(SealValue::Null.type_name(), "NULL");
    }
}
