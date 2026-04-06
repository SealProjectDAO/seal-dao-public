//! PostgreSQL-compatible SQL parser and execution engine for Seal DAO.
//!
//! Seal SQL is a **subset of PostgreSQL**. Any valid Seal SQL is valid PostgreSQL.
//! The parser uses [sqlparser-rs](https://github.com/apache/datafusion-sqlparser-rs)
//! with the PostgreSQL dialect.
//!
//! Supported: CREATE TABLE, INSERT, SELECT (with JOIN, GROUP BY, ORDER BY),
//! UPDATE, DELETE, CREATE POLICY, CREATE INDEX, ALTER TABLE.

pub mod engine;
pub mod error;
pub mod index;
pub mod merkle_state;
pub mod namespace;
pub mod parser;
pub mod rbtree;
pub mod rls;
pub mod types;

pub use engine::Engine;
pub use error::SqlError;
pub use merkle_state::MerkleEngine;
pub use namespace::AppNamespace;
pub use parser::parse_sql;
pub use rls::{Policy, PolicyAction, RlsManager};
pub use types::{Column, Row, Schema, SealType, SealValue};
