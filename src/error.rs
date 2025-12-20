//! Unified error types for the IAM analyzer.

use thiserror::Error;

/// Main error type for the IAM analyzer.
#[derive(Debug, Error)]
pub enum Error {
    /// Error parsing an ARN.
    #[error("Invalid ARN '{0}': {1}")]
    InvalidArn(String, String),

    /// Error parsing a policy JSON.
    #[error("Invalid policy JSON: {0}")]
    InvalidPolicy(#[from] serde_json::Error),

    /// Error parsing an action pattern.
    #[error("Invalid action pattern '{0}': {1}")]
    InvalidAction(String, String),

    /// Error parsing a condition operator.
    #[error("Unknown condition operator: {0}")]
    UnknownOperator(String),

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid condition value.
    #[error("Invalid condition value for {operator}: {message}")]
    InvalidConditionValue { operator: String, message: String },

    /// Error reading a file.
    #[error("Failed to read file '{path}': {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Error building request context.
    #[error("Invalid request context: {0}")]
    InvalidContext(String),

    /// Unknown AWS action.
    #[error("Unknown action '{action}'{}", suggestion.as_ref().map(|s| format!(" - did you mean '{}'?", s)).unwrap_or_default())]
    UnknownAction {
        action: String,
        suggestion: Option<String>,
    },

    /// Invalid condition key for action.
    #[error("Condition key '{key}' is not valid for action '{action}'")]
    InvalidConditionKey { key: String, action: String },

    /// Unknown AWS service.
    #[error("Unknown AWS service '{0}'")]
    UnknownService(String),

    /// Service validation error (collection of validation issues).
    #[error("Policy validation failed:\n{}", .0.join("\n"))]
    ValidationFailed(Vec<String>),

    /// Generic error.
    #[error("{0}")]
    Other(String),
}

/// Result type alias for IAM analyzer operations.
pub type Result<T> = std::result::Result<T, Error>;
