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

/// Per-row random salt for Merkle leaf anti-correlation.
///
/// Each row carries a 32-byte salt mixed into its Merkle leaf hash:
///   `leaf = SHA3("table:pk" || salt || serialized_row)`
///
/// This ensures:
/// - Same row content at different times produces different hashes (salt differs)
/// - Historical Merkle roots cannot reconstruct or correlate data without salts
/// - Salts are stored alongside rows in active state only (never in block headers)
///
/// See QA.md #STORAGE-FORGET for the full design.
pub type RowSalt = [u8; 32];

/// A row of data with anti-correlation salt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub values: Vec<SealValue>,
    /// Random salt for Merkle leaf anti-correlation (right-to-be-forgotten).
    /// Generated on INSERT, rotated on UPDATE.
    #[serde(default = "default_salt")]
    pub salt: RowSalt,
}

fn default_salt() -> RowSalt {
    [0u8; 32]
}

impl Row {
    pub fn get(&self, idx: usize) -> Option<&SealValue> {
        self.values.get(idx)
    }

    /// Generate a fresh random salt for this row (for local/test use).
    pub fn generate_salt(&mut self) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.salt);
    }

    /// Derive a deterministic salt from a block seed + table + row index.
    /// All validators processing the same block derive identical salts,
    /// but different blocks produce different salts (anti-correlation).
    pub fn derive_salt(&mut self, block_seed: &[u8], table: &str, row_index: usize) {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b"row_salt");
        hasher.update(block_seed);
        hasher.update(table.as_bytes());
        hasher.update(&row_index.to_le_bytes());
        let result = hasher.finalize();
        self.salt.copy_from_slice(&result[..32]);
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
