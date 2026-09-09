// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Experimental protocol types and deterministic state transitions for the
//! `nvx.mxc.agent.v1` control channel.
//!
//! This crate deliberately does **not** claim compatibility with ACI schemas.
//! It provides an explicit adapter boundary for future integration.

pub mod codec;
pub mod e2e_profile;
pub mod mapping;
pub mod messages;
pub mod mxc_extension;
pub mod state;

pub use crate::codec::{
    EncodedRecordTooLargeError, INNER_RECORD_HEADER_BYTES, INNER_RECORD_MAX_BYTES, InnerRecord,
    InnerRecordDecodeError, InnerRecordEncodeError, InnerRecordKind, MAX_STREAM_CHUNK_BYTES,
    OPENVMM_OUTER_RECORD_MAX_BYTES,
};
pub use crate::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy, MappingError,
    RelativeChildPath, SymlinkContainmentPolicy,
};
pub use crate::messages::{
    AgentControlMessage, BuildStatus, CapabilityProofMaterial, HealthStatus, HostControlMessage,
    IsolationStatus, LaunchIdentity, NetworkMode, NetworkStatus, ProtocolErrorCode,
    ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, StreamName, WORKLOAD_GID_MXC,
    WORKLOAD_GROUP_MXC, WORKLOAD_UID_MXC, WORKLOAD_USER_MXC, WorkloadIdentityStatus,
};
pub use crate::state::{
    ActiveExecEvent, AgentProtocolState, CHANNEL_LOSS_CLEANUP_DEADLINE_SECS, CleanupStatus,
    ExecDisposition, ExecTerminalEvent, FlowControlWindow, LaunchAdmissionError,
    LaunchAdmissionInput, PROTOCOL_VERSION, StateError,
};

/// Adapter boundary reserved for future ACI integration.
///
/// Implementations are intentionally out-of-scope for this experimental protocol.
pub mod adapter {
    use crate::messages::HostControlMessage;

    /// Marker trait for translating between this protocol and a future adapter.
    ///
    /// No compatibility claim is made by this trait itself.
    pub trait FutureAciAdapter {
        /// Adapter-specific error type.
        type Error;

        /// Converts one host message into adapter-owned bytes.
        fn encode_host_message(&self, message: &HostControlMessage)
        -> Result<Vec<u8>, Self::Error>;
    }
}
