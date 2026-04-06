//! Developer CLI tools for Seal DAO.
//!
//! Commands:
//! - `seal demo` — run interactive demo
//! - `seal migrate analyze <file>` — convert pg_dump to Seal SQL
//! - `seal app deploy --schema <file> --name <name>` — deploy SQL schema
//! - `seal sql --app <name> "<query>"` — execute SQL
//! - `seal node info` — show node identity and chain status

pub mod migrate;
