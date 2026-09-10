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
pub mod service;
pub mod state;

pub use crate::codec::{
    EncodedRecordTooLargeError, INNER_RECORD_HEADER_BYTES, INNER_RECORD_MAX_BYTES, InnerRecord,
    InnerRecordDecodeError, InnerRecordEncodeError, InnerRecordKind, MAX_STREAM_CHUNK_BYTES,
    OPENVMM_OUTER_RECORD_MAX_BYTES,
};
pub use crate::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy, MappingError,
    RelativeChildPath, SymlinkContainmentPolicy, validate_canonical_root_path,
    validate_mapping_set,
};
pub use crate::messages::{
    AgentControlMessage, BuildStatus, CapabilityProofMaterial, ExecDisposition, FlowCreditRequest,
    HealthStatus, HostControlMessage, IsolationStatus, LaunchIdentity, NetworkMode, NetworkStatus,
    ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, StderrChunkRecord,
    StderrEofRecord, StdinChunkRecord, StdinEofRecord, StdoutChunkRecord, StdoutEofRecord,
    StreamName, WORKLOAD_GID_MXC, WORKLOAD_GROUP_MXC, WORKLOAD_UID_MXC, WORKLOAD_USER_MXC,
    WorkloadIdentityStatus,
};
pub use crate::service::{
    AuthenticateChannelRequest, CancelReason, ChannelReadResult, ConfigureSessionRequest,
    CreateProcessRequest, DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES,
    DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS, DEFAULT_STDIN_QUEUE_LIMIT_BYTES, FilesystemStatus,
    HVC1_DEVICE_PATH, HealthSnapshot, HvcFramedChannel, LaunchBinding,
    MAX_INNER_RECORD_BYTES_FOR_OPENVMM, MAX_LABEL_COUNT, MAX_MAP_ENTRIES, MAX_REQUEST_BODY_BYTES,
    MAX_STRING_BYTES, MxcCapabilities, MxcControlService, OPENVMM_OUTER_FRAME_OVERHEAD_BYTES,
    PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES, ProcessSupervisor, ReadySnapshot, ServiceError,
    ServiceErrorCode, SessionConfiguration, SupervisorEvent, WaitReadyRequest,
};
pub use crate::state::{
    ActiveExecEvent, AgentProtocolState, CHANNEL_LOSS_CLEANUP_DEADLINE_SECS, CleanupStatus,
    ExecTerminalEvent, FlowControlWindow, LaunchAdmissionError, LaunchAdmissionInput,
    PROTOCOL_VERSION, StateError,
};

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

#[derive(Debug)]
pub struct ProtocolError {
    message: String,
}

impl ProtocolError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ProtocolError {}

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
