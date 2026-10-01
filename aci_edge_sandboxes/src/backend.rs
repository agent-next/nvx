use std::fmt;
use std::io;

use crate::capabilities::Capabilities;
use crate::error::Result;
use crate::exec::ExecOutcome;
use crate::id::SandboxId;
use crate::input::InputSource;
use crate::model::{
    DeprovisionResult, ExecRequest, ProvisionRequest, ProvisionResult, StartResult, StopResult,
};

/// Implementation of the NVX sandbox lifecycle.
///
/// [`AciSandbox`](crate::AciSandbox) checks structure and [`Backend::capabilities`], then calls the
/// backend's validation hook before performing an operation. Backends must be safe
/// to call concurrently and from separate processes that share the same persistent state.
///
/// Implementations must report state-machine violations with the matching
/// [`ErrorCode`](crate::ErrorCode): an unknown or deprovisioned ID is
/// [`StaleId`](crate::ErrorCode::StaleId), `exec` on a stopped sandbox is
/// [`NotStarted`](crate::ErrorCode::NotStarted), `start` on a running sandbox and `deprovision`
/// of a running sandbox are [`AlreadyStarted`](crate::ErrorCode::AlreadyStarted), and `stop` on
/// a stopped sandbox is [`AlreadyStopped`](crate::ErrorCode::AlreadyStopped).
pub trait Backend: Send + Sync + fmt::Debug {
    /// Returns the backend's name.
    fn name(&self) -> &str;

    /// Returns the features this backend honors.
    fn capabilities(&self) -> Capabilities;

    /// Checks that the backend's runtime dependencies are present, returning
    /// [`ErrorCode::BackendUnavailable`](crate::ErrorCode::BackendUnavailable) otherwise.
    fn probe(&self) -> Result<()>;

    /// Checks deterministic provision policies without probing the host or changing state.
    ///
    /// Called after structural and capability validation. Override this when the backend has
    /// additional policy restrictions; operations must apply the same checks. The default
    /// implementation imposes no additional restrictions.
    fn validate_provision(&self, _request: &ProvisionRequest) -> Result<()> {
        Ok(())
    }

    /// Checks deterministic exec policies without probing the host or changing state.
    ///
    /// Called after structural and capability validation. Override this when the backend has
    /// additional policy restrictions; operations must apply the same checks. The default
    /// implementation imposes no additional restrictions.
    fn validate_exec(&self, _request: &ExecRequest) -> Result<()> {
        Ok(())
    }

    /// Allocates a sandbox without starting it.
    fn provision(&self, request: &ProvisionRequest) -> Result<ProvisionResult>;

    /// Moves a provisioned sandbox to the running state.
    fn start(&self, sandbox_id: &SandboxId) -> Result<StartResult>;

    /// Starts a workload in a running sandbox.
    ///
    /// The backend must refuse the request before running anything when it cannot honor it, then
    /// deliver the workload's output through `io` and drop `io` before the returned control
    /// reports the outcome.
    fn exec(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
        io: ExecIo,
    ) -> Result<Box<dyn ExecControl>>;

    /// Moves a running sandbox back to the provisioned state.
    fn stop(&self, sandbox_id: &SandboxId) -> Result<StopResult>;

    /// Releases a provisioned sandbox. The sandbox ID becomes stale.
    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<DeprovisionResult>;
}

/// Receives one output stream of an execution.
pub trait OutputSink: Send {
    /// Delivers the next chunk of output, blocking while the consumer applies backpressure.
    ///
    /// An error means the consumer has gone away. Backends should then discard the rest of the
    /// stream instead of failing the execution.
    fn write(&mut self, chunk: &[u8]) -> io::Result<()>;
}

/// Stream endpoints for one execution, provided to [`Backend::exec`].
pub struct ExecIo {
    /// Receives the workload's standard output.
    pub stdout: Box<dyn OutputSink>,
    /// Receives the workload's standard error.
    pub stderr: Box<dyn OutputSink>,
    /// Supplies the workload's standard input when the request uses
    /// [`StdinMode::Piped`](crate::StdinMode::Piped). End-of-file closes the workload's input.
    /// Use its close handle to interrupt input workers on cancellation or timeout, and finish
    /// those workers before reporting the outcome.
    pub stdin: Option<InputSource>,
}

impl fmt::Debug for ExecIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecIo")
            .field("stdout", &"<sink>")
            .field("stderr", &"<sink>")
            .field("stdin", &self.stdin.as_ref().map(|_| "<source>"))
            .finish()
    }
}

/// Control surface of a live execution.
pub trait ExecControl: Send + Sync {
    /// Blocks until the execution reaches its terminal outcome.
    ///
    /// Callers invoke this at most once. An error means the outcome could not be determined, for
    /// example because the connection to the sandbox was lost.
    fn wait(&self) -> Result<ExecOutcome>;

    /// Requests cancellation. A cancelled execution reports [`ExecOutcome::Cancelled`].
    fn cancel(&self) -> Result<()>;
}
