//! Serializable data model of the edge sandbox lifecycle.
//!
//! These are the requests, results, capabilities, and errors of `aci_edge_sandboxes`, without any
//! backend. A backend that runs in a separate component, such as a native host library, uses the
//! same definitions to read and write the JSON that crosses its boundary, so both sides agree on
//! every field. `aci_edge_sandboxes` re-exports the types, so its users need not depend on this
//! crate directly.

pub mod capabilities;
pub mod cidr;
pub mod error;
pub mod id;
pub mod model;
pub mod validate;

pub use capabilities::{
    Capabilities, ExecCapabilities, FilesystemCapabilities, NetworkCapabilities,
};
pub use error::{Error, ErrorBody, ErrorCode, Result};
pub use id::SandboxId;
pub use model::{
    Access, Command, DeprovisionResult, EgressPolicy, ExecRequest, FilesystemPolicy, IngressPolicy,
    Metadata, MicrovmConfig, MicrovmProvision, NetworkPeer, NetworkPolicy, NetworkPort,
    NetworkRule, ProcessSpec, Protocol, ProvisionRequest, ProvisionResult, StartResult, StdinMode,
    StopResult,
};
