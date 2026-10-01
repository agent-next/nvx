use std::fmt;

use serde::{Deserialize, Serialize};

/// Result type used throughout this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Boxed error type accepted as the source of an [`Error`].
type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Stable classification of an [`Error`].
///
/// Codes follow the MXC state-aware error model. [`ErrorCode::mxc_code`] returns the MXC wire
/// code for each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request is structurally invalid.
    MalformedRequest,
    /// The sandbox ID is structurally invalid.
    MalformedId,
    /// The sandbox ID is well formed but no longer refers to a provisioned sandbox.
    StaleId,
    /// The operation requires a running sandbox, but the sandbox is only provisioned.
    NotStarted,
    /// The sandbox is already running.
    AlreadyStarted,
    /// The sandbox is already stopped.
    AlreadyStopped,
    /// The request is well formed, but the backend cannot represent or enforce it.
    PolicyValidation,
    /// A runtime dependency of the backend is missing or unusable.
    BackendUnavailable,
    /// The backend does not implement the requested operation.
    Unsupported,
    /// Any other backend failure.
    BackendError,
}

impl ErrorCode {
    /// Returns the snake_case wire spelling of this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::MalformedId => "malformed_id",
            Self::StaleId => "stale_id",
            Self::NotStarted => "not_started",
            Self::AlreadyStarted => "already_started",
            Self::AlreadyStopped => "already_stopped",
            Self::PolicyValidation => "policy_validation",
            Self::BackendUnavailable => "backend_unavailable",
            Self::Unsupported => "unsupported",
            Self::BackendError => "backend_error",
        }
    }

    /// Returns the MXC state-aware error code for this code.
    ///
    /// MXC has no separate "unsupported" code, so [`ErrorCode::Unsupported`] maps to
    /// `backend_error`.
    pub const fn mxc_code(self) -> &'static str {
        match self {
            Self::Unsupported => "backend_error",
            other => other.as_str(),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned by every fallible operation in this crate.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Error {
    code: ErrorCode,
    message: String,
    #[source]
    source: Option<BoxedSource>,
}

impl Error {
    /// Creates an error with the given code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    /// Attaches an underlying cause to this error.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<BoxedSource>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Returns the stable classification of this error.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the human-readable description of this error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the contract's serializable `{ "code", "message" }` error body.
    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code,
            message: self.message.clone(),
        }
    }
}

// Which helpers are used depends on the enabled backends.
#[allow(dead_code)]
impl Error {
    pub(crate) fn malformed_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::MalformedRequest, message)
    }

    pub(crate) fn malformed_id(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::MalformedId, message)
    }

    pub(crate) fn stale_id(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::StaleId, message)
    }

    pub(crate) fn not_started(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotStarted, message)
    }

    pub(crate) fn already_started(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AlreadyStarted, message)
    }

    pub(crate) fn already_stopped(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AlreadyStopped, message)
    }

    pub(crate) fn policy_validation(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PolicyValidation, message)
    }

    pub(crate) fn backend_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BackendUnavailable, message)
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, message)
    }

    pub(crate) fn backend_error(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BackendError, message)
    }
}

/// Serializable error body of the NVX contract: `{ "code": ..., "message": ... }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable error classification.
    pub code: ErrorCode,
    /// Human-readable description.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_use_contract_spelling() {
        let body = Error::new(ErrorCode::PolicyValidation, "nope").body();
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(json, r#"{"code":"policy_validation","message":"nope"}"#);
        assert_eq!(serde_json::from_str::<ErrorBody>(&json).unwrap(), body);
    }

    #[test]
    fn unsupported_maps_to_mxc_backend_error() {
        assert_eq!(ErrorCode::Unsupported.mxc_code(), "backend_error");
        assert_eq!(ErrorCode::StaleId.mxc_code(), "stale_id");
        assert_eq!(
            ErrorCode::BackendUnavailable.mxc_code(),
            "backend_unavailable"
        );
    }

    #[test]
    fn display_includes_code_and_message() {
        let error = Error::stale_id("sandbox nvx:00 was deprovisioned");
        assert_eq!(
            error.to_string(),
            "stale_id: sandbox nvx:00 was deprovisioned"
        );
    }
}
