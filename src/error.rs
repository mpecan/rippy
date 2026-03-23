use std::path::PathBuf;

/// All errors that can occur in rippy.
#[derive(Debug, thiserror::Error)]
pub enum RippyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{path}:{line}: {message}")]
    Config {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("parse error: {0}")]
    Parse(String),

    #[error("unknown mode: {0}")]
    UnknownMode(String),

    #[error("missing field: {0}")]
    MissingField(String),
}
