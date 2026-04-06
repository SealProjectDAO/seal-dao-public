//! SQL error types.

#[derive(Debug, thiserror::Error)]
pub enum SqlError {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("table not found: {0}")]
    TableNotFound(String),

    #[error("table already exists: {0}")]
    TableAlreadyExists(String),

    #[error("column not found: {0}")]
    ColumnNotFound(String),

    #[error("type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    #[error("not null violation: column {0}")]
    NotNull(String),

    #[error("unsupported feature: {0}")]
    Unsupported(String),

    #[error("execution error: {0}")]
    Execution(String),
}
