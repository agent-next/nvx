//! Rust interface to the NVX state-aware microVM sandbox lifecycle.
//!
//! NVX runs untrusted workloads inside hardware-isolated microVMs built on OpenVMM. This crate
//! exposes the five lifecycle operations of the NVX state-aware daemon contract:
//!
//! | Operation | Transition | Result |
//! | --- | --- | --- |
//! | [`AciSandbox::provision`] | (none) → provisioned | opaque [`SandboxId`] and optional metadata |
//! | [`AciSandbox::start`] | provisioned → running | optional metadata |
//! | [`AciSandbox::exec`] | running → running | live output streams and an [`ExecOutcome`] |
//! | [`AciSandbox::stop`] | running → provisioned | optional metadata |
//! | [`AciSandbox::deprovision`] | provisioned → (none) | optional metadata; the ID becomes stale |
//!
//! Every operation is implemented by a pluggable [`Backend`]. The default backend,
//! [`openvmm::OpenVmmBackend`], drives the `openvmm` binary directly. [`AciSandbox`] validates each
//! request in a fixed order before the backend acts on it: structural errors
//! ([`ErrorCode::MalformedRequest`], [`ErrorCode::MalformedId`]) come first, then requests the
//! backend cannot honor ([`ErrorCode::PolicyValidation`]), then backend-specific failures.
//! Rejected requests never run anything.
//!
//! # Example
//!
//! ```no_run
//! use aci_edge_sandboxes::openvmm::OpenVmmConfig;
//! use aci_edge_sandboxes::{ExecRequest, AciSandbox, ProvisionRequest};
//!
//! # fn main() -> aci_edge_sandboxes::Result<()> {
//! // Locates OpenVMM, the guest kernel, and the Alpine initramfs; see `openvmm::Artifacts`.
//! let nvx = AciSandbox::openvmm(OpenVmmConfig::discover()?)?;
//! let sandbox = nvx.provision(&ProvisionRequest::new())?.sandbox_id;
//! nvx.start(&sandbox)?;
//! let output = nvx
//!     .exec(&sandbox, &ExecRequest::command_line("echo hello"))?
//!     .wait_with_output()?;
//! assert_eq!(output.stdout, b"hello\n");
//! nvx.stop(&sandbox)?;
//! nvx.deprovision(&sandbox)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `openvmm` (default): the [`openvmm`] backend.
//! - `bundled`: stages the OpenVMM executable, guest kernel, and control initramfs at build time;
//!   see `openvmm::Artifacts::bundled`.
//! - `async`: Tokio wrappers ([`AsyncAciSandbox`], [`AsyncExecution`]) around the synchronous core.
//! - `testing`: an in-memory [`testing::MockBackend`] for consumers' own tests.

mod backend;
mod capabilities;
mod cidr;
mod client;
mod error;
mod exec;
mod id;
mod input;
mod model;
mod stream;
mod validate;

#[cfg(feature = "async")]
mod async_api;
#[cfg(feature = "openvmm")]
pub mod openvmm;
#[cfg(feature = "testing")]
pub mod testing;

#[cfg(feature = "async")]
pub use async_api::{AsyncAciSandbox, AsyncExecution, InputStream, OutputStream};
pub use backend::{Backend, ExecControl, ExecIo, OutputSink};
pub use capabilities::{
    Capabilities, ExecCapabilities, FilesystemCapabilities, NetworkCapabilities,
};
pub use client::AciSandbox;
pub use error::{Error, ErrorBody, ErrorCode, Result};
pub use exec::{Canceller, ExecFailure, ExecOutcome, ExecOutput, Execution};
pub use id::SandboxId;
pub use input::{InputCloser, InputSource};
pub use model::{
    Access, Command, DeprovisionResult, EgressPolicy, ExecRequest, FilesystemPolicy, IngressPolicy,
    Metadata, MicrovmConfig, MicrovmProvision, NetworkPeer, NetworkPolicy, NetworkPort,
    NetworkRule, ProcessSpec, Protocol, ProvisionRequest, ProvisionResult, StartResult, StdinMode,
    StopResult,
};
