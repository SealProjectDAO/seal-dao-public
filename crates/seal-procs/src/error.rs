//! Errors raised by the procedure registry and dispatcher.

use crate::ProcedureLanguage;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcError {
    #[error("procedure '{0}' already exists")]
    Duplicate(String),

    #[error("procedure '{0}' not found")]
    NotFound(String),

    #[error("language not yet implemented: {0:?}")]
    LanguageNotImplemented(ProcedureLanguage),

    #[error("language mismatch: dispatched to {expected:?} but procedure body is {actual:?}")]
    LanguageMismatch {
        expected: ProcedureLanguage,
        actual: ProcedureLanguage,
    },

    #[error("argument count mismatch: expected {expected}, got {actual}")]
    ArgCount { expected: usize, actual: usize },

    #[error("execution error: {0}")]
    Execution(String),
}
