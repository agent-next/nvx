// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Typed agent failures.
//!
//! A PID 1 that fails by dying takes every diagnostic with it, so each failure carries a
//! stable code the host can map onto a customer-visible sandbox failure reason and a message
//! for a human reading the console.

use ::std::fmt;
use ::std::io;

/// Result alias for agent operations.
pub type Result<T> = ::std::result::Result<T, AgentError>;

/// Stable host-facing error code set for phase-0 PID-1 failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Internal,
    MountFailed,
    ExecFailed,
    BadRequest,
    WorkloadBusy,
    FreezeFailed,
    QuiesceFailed,
    CheckpointTimeout,
}

/// A failure with a stable code.
#[derive(Debug)]
pub enum AgentError {
    /// An operating-system call failed.
    Io {
        /// What the agent was doing.
        context: String,
        /// The underlying error.
        source: io::Error,
    },
    /// The sandbox filesystem could not be assembled.
    Mount(String),
    /// The kernel command line does not describe a usable sandbox.
    Config(String),
    /// A workload could not be started.
    Exec(String),
    /// A host request could not be understood.
    BadRequest(String),
    /// A capture could not be taken because the workload is not in a capturable state.
    WorkloadBusy(String),
    /// The container cgroup could not be frozen or thawed.
    Freeze(String),
    /// The scratch filesystem could not be quiesced or resumed.
    Quiesce(String),
    /// The container cgroup did not reach the requested freeze state in time.
    CheckpointTimeout(String),
    /// The agent itself failed.
    Internal(String),
}

impl AgentError {
    /// Wraps an OS error with what the agent was attempting.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Builds a filesystem-assembly failure.
    pub fn mount(message: impl Into<String>) -> Self {
        Self::Mount(message.into())
    }

    /// Builds a configuration failure.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Builds a workload-start failure.
    pub fn exec(message: impl Into<String>) -> Self {
        Self::Exec(message.into())
    }

    /// Builds a malformed-request failure.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    /// Builds a "the workload cannot be captured right now" failure.
    pub fn workload_busy(message: impl Into<String>) -> Self {
        Self::WorkloadBusy(message.into())
    }

    /// Builds a cgroup freeze/thaw failure.
    pub fn freeze(message: impl Into<String>) -> Self {
        Self::Freeze(message.into())
    }

    /// Builds a filesystem quiesce failure.
    pub fn quiesce(message: impl Into<String>) -> Self {
        Self::Quiesce(message.into())
    }

    /// Builds a freeze-timeout failure.
    pub fn checkpoint_timeout(message: impl Into<String>) -> Self {
        Self::CheckpointTimeout(message.into())
    }

    /// Builds an internal failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// The wire code the host receives for this failure.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Io { .. } | Self::Internal(_) => ErrorCode::Internal,
            Self::Mount(_) => ErrorCode::MountFailed,
            Self::Config(_) => ErrorCode::MountFailed,
            Self::Exec(_) => ErrorCode::ExecFailed,
            Self::BadRequest(_) => ErrorCode::BadRequest,
            Self::WorkloadBusy(_) => ErrorCode::WorkloadBusy,
            Self::Freeze(_) => ErrorCode::FreezeFailed,
            Self::Quiesce(_) => ErrorCode::QuiesceFailed,
            Self::CheckpointTimeout(_) => ErrorCode::CheckpointTimeout,
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::Mount(message)
            | Self::Config(message)
            | Self::Exec(message)
            | Self::BadRequest(message)
            | Self::WorkloadBusy(message)
            | Self::Freeze(message)
            | Self::Quiesce(message)
            | Self::CheckpointTimeout(message)
            | Self::Internal(message) => write!(formatter, "{message}"),
        }
    }
}

impl ::std::error::Error for AgentError {}

impl From<io::Error> for AgentError {
    fn from(source: io::Error) -> Self {
        Self::io("agent operation", source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_failures_to_stable_wire_codes() {
        assert_eq!(AgentError::mount("x").code(), ErrorCode::MountFailed);
        assert_eq!(AgentError::exec("x").code(), ErrorCode::ExecFailed);
        assert_eq!(AgentError::bad_request("x").code(), ErrorCode::BadRequest);
        assert_eq!(AgentError::internal("x").code(), ErrorCode::Internal);
        assert_eq!(
            AgentError::workload_busy("x").code(),
            ErrorCode::WorkloadBusy
        );
        assert_eq!(AgentError::freeze("x").code(), ErrorCode::FreezeFailed);
        assert_eq!(AgentError::quiesce("x").code(), ErrorCode::QuiesceFailed);
        assert_eq!(
            AgentError::checkpoint_timeout("x").code(),
            ErrorCode::CheckpointTimeout
        );
        assert_eq!(
            AgentError::io("reading", io::Error::other("boom")).code(),
            ErrorCode::Internal
        );
    }

    #[test]
    fn includes_context_in_io_failures() {
        let error = AgentError::io("mounting scratch", io::Error::other("boom"));
        assert_eq!(format!("{error}"), "mounting scratch: boom");
    }
}
