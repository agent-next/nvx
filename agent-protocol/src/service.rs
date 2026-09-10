// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::codec::{
    INNER_RECORD_MAX_BYTES, InnerRecord, InnerRecordDecodeError, OPENVMM_OUTER_RECORD_MAX_BYTES,
};
use crate::mapping::{
    CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy, validate_mapping_set,
};
use crate::messages::{
    AgentControlMessage, BuildStatus, ExecDisposition, FlowCreditRequest, IsolationStatus,
    LaunchIdentity, NetworkStatus, ReadyStatus, SERVICE_IDENTITY, StderrChunkRecord,
    StderrEofRecord, StdinChunkRecord, StdinEofRecord, StdoutChunkRecord, StdoutEofRecord,
    StreamName, WorkloadIdentityStatus,
};
use crate::state::{
    ActiveExecEvent, AgentProtocolState, CHANNEL_LOSS_CLEANUP_DEADLINE_SECS, LaunchAdmissionInput,
    PROTOCOL_VERSION, StateError,
};

pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;
pub const MAX_LABEL_COUNT: usize = 32;
pub const MAX_MAP_ENTRIES: usize = 32;
pub const MAX_STRING_BYTES: usize = 256;
pub const HVC1_DEVICE_PATH: &str = "/dev/hvc1";
/// Conservative fixed cap for OpenVMM outer framing bytes.
///
/// OpenVMM enforces a 65_536-byte complete record limit including its own framing.
/// Until this crate imports exact OpenVMM framing metadata, we reserve 64 bytes.
pub const OPENVMM_OUTER_FRAME_OVERHEAD_BYTES: usize = 64;
pub const MAX_INNER_RECORD_BYTES_FOR_OPENVMM: usize =
    OPENVMM_OUTER_RECORD_MAX_BYTES - OPENVMM_OUTER_FRAME_OVERHEAD_BYTES;
pub const DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES: usize = 256 * 1024;
pub const DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS: usize = 64;
pub const DEFAULT_STDIN_QUEUE_LIMIT_BYTES: usize = 128 * 1024;

const _: [(); 1] =
    [(); (OPENVMM_OUTER_RECORD_MAX_BYTES > OPENVMM_OUTER_FRAME_OVERHEAD_BYTES) as usize];
const _: [(); 1] = [(); (MAX_INNER_RECORD_BYTES_FOR_OPENVMM <= INNER_RECORD_MAX_BYTES) as usize];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchBinding {
    pub protocol_version: u32,
    pub image_version: String,
    pub launch: LaunchIdentity,
    pub channel_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfiguration {
    pub root: CanonicalHostMappingRoot,
    pub mappings: Vec<ChildMapping>,
    pub containment: MappingContainmentPolicy,
    pub labels: Vec<String>,
    pub attributes: BTreeMap<String, String>,
    pub filesystem: FilesystemStatus,
    pub network: NetworkStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemStatus {
    pub rootfs_ready: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureSessionRequest {
    pub protocol_version: u32,
    pub image_version: String,
    pub launch: LaunchIdentity,
    pub channel_generation: u64,
    pub idempotent_replay: bool,
    pub configuration: SessionConfiguration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitReadyRequest {
    pub protocol_version: u32,
    pub image_version: String,
    pub launch: LaunchIdentity,
    pub channel_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MxcCapabilities {
    pub protocol_version: u32,
    pub image_version: String,
    pub available_operations: Vec<String>,
    pub unavailable_operations: Vec<UnavailableOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnavailableOperation {
    pub operation: String,
    pub capability_flag: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadySnapshot {
    pub protocol_version: u32,
    pub image_version: String,
    pub launch: LaunchIdentity,
    pub channel_generation: u64,
    pub filesystem: FilesystemStatus,
    pub network: NetworkStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub launch_admitted: bool,
    pub configured: bool,
    pub quiesced: bool,
    pub shutting_down: bool,
    pub filesystem: Option<FilesystemStatus>,
    pub network: Option<NetworkStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceErrorCode {
    UnsupportedProtocolVersion,
    ImageVersionMismatch,
    LaunchNonceMismatch,
    LaunchGenerationMismatch,
    ChannelGenerationMismatch,
    RequestTooLarge,
    TooManyEntries,
    StringTooLong,
    InvalidMappings,
    ConfigurationRequired,
    ConfigurationConflict,
    LifecycleError,
    ProtocolFrameError,
    ChannelIo,
    StreamChunkTooLarge,
    InvalidInput,
    Backpressure,
    Supervisor,
    CleanupTimeout,
    UnsupportedOperation,
    AuthenticationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
}

impl ServiceError {
    fn new(code: ServiceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl core::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ServiceError {}

impl From<StateError> for ServiceError {
    fn from(value: StateError) -> Self {
        Self::new(ServiceErrorCode::LifecycleError, value.to_string())
    }
}

pub struct MxcControlService {
    binding: LaunchBinding,
    expected_capability: [u8; 32],
    configured: Option<SessionConfiguration>,
    protocol_state: AgentProtocolState,
    build_status: BuildStatus,
    isolation_status: IsolationStatus,
    workload_identity: WorkloadIdentityStatus,
    authenticated: bool,
    quiesced: bool,
    shutting_down: bool,
    active_exec: Option<ActiveExecution>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveExecution {
    exec_id: u32,
    stdin_next_sequence: u64,
    stdout_next_sequence: u64,
    stderr_next_sequence: u64,
    stdin_queue_bytes: usize,
    stdin_eof_received: bool,
    timed_out: bool,
    cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProcessRequest {
    pub exec_id: u32,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    Cancelled,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticateChannelRequest {
    pub service: String,
    pub protocol_version: u32,
    pub launch: LaunchIdentity,
    pub channel_generation: u64,
    pub capability_proof: [u8; 32],
}

pub trait ProcessSupervisor {
    fn spawn(&mut self, request: &CreateProcessRequest) -> Result<(), ServiceError>;
    fn queue_stdin(&mut self, exec_id: u32, chunk: Vec<u8>) -> Result<(), ServiceError>;
    fn close_stdin(&mut self, exec_id: u32) -> Result<(), ServiceError>;
    fn take_stdin_drain_bytes(&mut self, exec_id: u32) -> Result<usize, ServiceError>;
    fn peek_event(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError>;
    fn ack_event(&mut self, exec_id: u32) -> Result<(), ServiceError>;
    fn terminate(&mut self, exec_id: u32) -> Result<(), ServiceError>;
    fn kill(&mut self, exec_id: u32) -> Result<(), ServiceError>;
    fn poll(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError>;
    fn cleanup_for_disconnect(
        &mut self,
        exec_id: u32,
        deadline: Duration,
    ) -> Result<bool, ServiceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorEvent {
    StdoutChunk(Vec<u8>),
    StdoutEof,
    StderrChunk(Vec<u8>),
    StderrEof,
    DescendantsCleaned,
    Exited(i32),
    Signaled(i32),
}

pub struct HvcFramedChannel<T: Read + Write> {
    io: T,
    max_frame_bytes: usize,
    read_buffer: Vec<u8>,
    write_queue_bytes: usize,
    write_queue_limit_bytes: usize,
    write_queue_limit_records: usize,
    queued_frames: VecDeque<Vec<u8>>,
    current_write_offset: usize,
    write_credits: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelReadResult {
    Record(InnerRecord),
    WouldBlock,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PumpSupervisorResult {
    Drained,
    WouldBlock,
}

impl MxcControlService {
    pub fn new(binding: LaunchBinding) -> Self {
        Self::new_with_status(
            binding,
            BuildStatus {
                agent_version: "unknown".to_string(),
                kernel_release: "unknown".to_string(),
                profile: "mxc-prototype".to_string(),
            },
            NetworkStatus {
                mode: crate::messages::NetworkMode::NoNic,
                detail: None,
            },
            IsolationStatus {
                pid_namespace: true,
                mount_namespace: true,
                uts_namespace: true,
                ipc_namespace: true,
                private_proc: true,
                private_dev: true,
                private_devpts: true,
                private_shm: true,
                read_only_sys: true,
                capabilities_dropped: true,
                no_new_privs: true,
                cgroup_separation: true,
                orphan_reaping: true,
            },
            WorkloadIdentityStatus::mxc_fixed(),
        )
    }

    pub fn new_with_status(
        binding: LaunchBinding,
        build_status: BuildStatus,
        _network: NetworkStatus,
        isolation_status: IsolationStatus,
        workload_identity: WorkloadIdentityStatus,
    ) -> Self {
        Self {
            expected_capability: fallback_expected_capability(binding.launch),
            binding,
            configured: None,
            protocol_state: AgentProtocolState::new(),
            build_status,
            isolation_status,
            workload_identity,
            authenticated: false,
            quiesced: false,
            shutting_down: false,
            active_exec: None,
        }
    }

    pub fn get_capabilities(&self) -> MxcCapabilities {
        MxcCapabilities {
            protocol_version: self.binding.protocol_version,
            image_version: self.binding.image_version.clone(),
            available_operations: vec![
                "GetCapabilities".to_string(),
                "AuthenticateChannel".to_string(),
                "ConfigureSession".to_string(),
                "WaitReady".to_string(),
                "Health".to_string(),
            ],
            unavailable_operations: vec![
                UnavailableOperation {
                    operation: "Exec".to_string(),
                    capability_flag: "exec.phase0".to_string(),
                    reason:
                        "phase-0 control slice exposes readiness only; exec lifecycle is disabled"
                            .to_string(),
                },
                UnavailableOperation {
                    operation: "Streams".to_string(),
                    capability_flag: "streams.phase0".to_string(),
                    reason: "phase-0 control slice does not expose process stream transport"
                        .to_string(),
                },
                UnavailableOperation {
                    operation: "Cancel".to_string(),
                    capability_flag: "cancel.phase0".to_string(),
                    reason: "phase-0 control slice does not allow execution cancellation"
                        .to_string(),
                },
                UnavailableOperation {
                    operation: "Quiesce".to_string(),
                    capability_flag: "quiesce.phase0".to_string(),
                    reason: "phase-0 control slice does not expose quiesce transitions".to_string(),
                },
                UnavailableOperation {
                    operation: "DisconnectCleanup".to_string(),
                    capability_flag: "disconnect_cleanup.phase0".to_string(),
                    reason: "phase-0 control slice does not expose disconnect cleanup control"
                        .to_string(),
                },
                UnavailableOperation {
                    operation: "Resume".to_string(),
                    capability_flag: "resume.phase0".to_string(),
                    reason: "phase-0 control slice does not expose resume transitions".to_string(),
                },
                UnavailableOperation {
                    operation: "Shutdown".to_string(),
                    capability_flag: "shutdown.phase0".to_string(),
                    reason: "phase-0 control slice does not expose in-band shutdown control"
                        .to_string(),
                },
            ],
        }
    }

    pub fn update_runtime_isolation(&mut self, isolation: IsolationStatus) {
        self.isolation_status = isolation;
    }

    pub fn set_expected_capability(&mut self, capability: [u8; 32]) {
        self.expected_capability = capability;
    }

    pub fn ready_status(&self, network: NetworkStatus) -> ReadyStatus {
        ReadyStatus {
            service: SERVICE_IDENTITY.to_string(),
            protocol_version: PROTOCOL_VERSION,
            build: self.build_status.clone(),
            network,
            isolation: self.isolation_status.clone(),
            workload_identity: self.workload_identity.clone(),
        }
    }

    pub fn authenticate_channel(
        &mut self,
        request: AuthenticateChannelRequest,
        now_secs: u64,
        network: NetworkStatus,
    ) -> Result<ReadyStatus, ServiceError> {
        if request.service != SERVICE_IDENTITY {
            return Err(ServiceError::new(
                ServiceErrorCode::UnsupportedOperation,
                format!("unsupported service identity {}", request.service),
            ));
        }
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(ServiceError::new(
                ServiceErrorCode::UnsupportedProtocolVersion,
                format!(
                    "protocol version {} is not supported",
                    request.protocol_version
                ),
            ));
        }
        if !constant_time_eq32(&request.capability_proof, &self.expected_capability) {
            return Err(ServiceError::new(
                ServiceErrorCode::AuthenticationFailed,
                "capability proof did not match trusted launch capability",
            ));
        }
        let ready =
            self.protocol_state.admit_launch(LaunchAdmissionInput {
                now_secs,
                service: request.service,
                version: request.protocol_version,
                launch: request.launch,
                capability_proof: request.capability_proof.to_vec().try_into().map_err(
                    |error| {
                        ServiceError::new(
                            ServiceErrorCode::InvalidInput,
                            format!("invalid capability proof: {error}"),
                        )
                    },
                )?,
                build: self.build_status.clone(),
                network,
                isolation: self.isolation_status.clone(),
                workload_identity: self.workload_identity.clone(),
            })?;
        let AgentControlMessage::Ready { status, .. } = ready else {
            return Err(ServiceError::new(
                ServiceErrorCode::LifecycleError,
                "launch admission did not return Ready",
            ));
        };
        self.binding.launch = request.launch;
        self.binding.channel_generation = request.channel_generation;
        self.authenticated = true;
        Ok(status)
    }

    pub fn configure_session(
        &mut self,
        request: ConfigureSessionRequest,
    ) -> Result<(), ServiceError> {
        if !self.authenticated {
            return Err(ServiceError::new(
                ServiceErrorCode::ConfigurationRequired,
                "authenticated launch binding is required before ConfigureSession",
            ));
        }
        self.validate_binding(
            request.protocol_version,
            &request.image_version,
            request.launch,
            request.channel_generation,
        )?;
        validate_configuration_bounds(&request.configuration)?;
        if let Err(error) = validate_mapping_set(&request.configuration.mappings) {
            return Err(ServiceError::new(
                ServiceErrorCode::InvalidMappings,
                format!("{error}"),
            ));
        }

        match &self.configured {
            None => {
                self.protocol_state.configure(
                    request.launch,
                    request.configuration.root.clone(),
                    request.configuration.mappings.clone(),
                    request.configuration.containment,
                )?;
                self.configured = Some(request.configuration);
                Ok(())
            }
            Some(existing) if request.idempotent_replay && existing == &request.configuration => {
                Ok(())
            }
            Some(_) => Err(ServiceError::new(
                ServiceErrorCode::ConfigurationConflict,
                "session configuration is immutable after first successful apply",
            )),
        }
    }

    pub fn wait_ready(&self, request: WaitReadyRequest) -> Result<ReadySnapshot, ServiceError> {
        if !self.authenticated {
            return Err(ServiceError::new(
                ServiceErrorCode::ConfigurationRequired,
                "authenticated launch binding is required before WaitReady",
            ));
        }
        self.validate_binding(
            request.protocol_version,
            &request.image_version,
            request.launch,
            request.channel_generation,
        )?;
        let configuration = self.configured.as_ref().ok_or_else(|| {
            ServiceError::new(
                ServiceErrorCode::ConfigurationRequired,
                "session must be configured before WaitReady can report ready",
            )
        })?;
        Ok(ReadySnapshot {
            protocol_version: self.binding.protocol_version,
            image_version: self.binding.image_version.clone(),
            launch: self.binding.launch,
            channel_generation: self.binding.channel_generation,
            filesystem: configuration.filesystem.clone(),
            network: configuration.network.clone(),
        })
    }

    pub fn health(&self) -> HealthSnapshot {
        let health = self.protocol_state.health();
        HealthSnapshot {
            launch_admitted: health.launch_admitted,
            configured: self.configured.is_some(),
            quiesced: health.quiesced || self.quiesced,
            shutting_down: self.shutting_down,
            filesystem: self
                .configured
                .as_ref()
                .map(|config| config.filesystem.clone()),
            network: self
                .configured
                .as_ref()
                .map(|config| config.network.clone()),
        }
    }

    pub fn active_exec_id(&self) -> Option<u32> {
        self.active_exec.as_ref().map(|exec| exec.exec_id)
    }

    pub fn launch_admitted(&self) -> bool {
        self.protocol_state.health().launch_admitted
    }

    pub fn unsupported_operation(&self, operation: &str) -> Result<(), ServiceError> {
        Err(ServiceError::new(
            ServiceErrorCode::UnsupportedOperation,
            format!("{operation} is outside the current operational slice"),
        ))
    }

    pub fn create_process(
        &mut self,
        request: CreateProcessRequest,
        supervisor: &mut impl ProcessSupervisor,
    ) -> Result<(), ServiceError> {
        self.require_configured()?;
        validate_create_process_request(&request)?;
        self.protocol_state.create_exec(request.exec_id)?;
        supervisor.spawn(&request)?;
        self.active_exec = Some(ActiveExecution {
            exec_id: request.exec_id,
            stdin_next_sequence: 0,
            stdout_next_sequence: 0,
            stderr_next_sequence: 0,
            stdin_queue_bytes: 0,
            stdin_eof_received: false,
            timed_out: false,
            cancelled: false,
        });
        Ok(())
    }

    pub fn grant_flow_credits(&mut self, request: FlowCreditRequest) -> Result<(), ServiceError> {
        self.protocol_state.apply_exec_event(
            request.exec_id,
            ActiveExecEvent::AddFlowCredits {
                stream: request.stream,
                credits: request.credits,
            },
        )?;
        Ok(())
    }

    pub fn stdin_chunk(
        &mut self,
        record: StdinChunkRecord,
        supervisor: &mut impl ProcessSupervisor,
    ) -> Result<(), ServiceError> {
        let active = self.active_exec.as_mut().ok_or_else(|| {
            ServiceError::new(
                ServiceErrorCode::LifecycleError,
                "no active exec for stdin chunk",
            )
        })?;
        if active.exec_id != record.exec_id {
            return Err(ServiceError::new(
                ServiceErrorCode::LifecycleError,
                format!(
                    "stdin chunk exec id {} does not match active exec {}",
                    record.exec_id, active.exec_id
                ),
            ));
        }
        if record.chunk.len() > max_stream_chunk_cap() {
            return Err(ServiceError::new(
                ServiceErrorCode::StreamChunkTooLarge,
                format!("stdin chunk exceeds max {}", max_stream_chunk_cap()),
            ));
        }
        sync_stdin_accounting(active, supervisor)?;
        let next_bytes = active
            .stdin_queue_bytes
            .checked_add(record.chunk.len())
            .ok_or_else(|| {
                ServiceError::new(ServiceErrorCode::Backpressure, "stdin queue byte overflow")
            })?;
        if next_bytes > DEFAULT_STDIN_QUEUE_LIMIT_BYTES {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "stdin queue is full; apply host-side backpressure",
            ));
        }
        let protocol_snapshot = self.protocol_state.clone();
        let active_snapshot = active.clone();
        self.protocol_state.apply_exec_event(
            record.exec_id,
            ActiveExecEvent::StdinChunk {
                sequence: record.sequence,
            },
        )?;
        active.stdin_next_sequence = active.stdin_next_sequence.saturating_add(1);
        if let Err(error) = supervisor.queue_stdin(record.exec_id, record.chunk) {
            self.protocol_state = protocol_snapshot;
            *active = active_snapshot;
            return Err(error);
        }
        active.stdin_queue_bytes = next_bytes;
        Ok(())
    }

    pub fn stdin_eof(
        &mut self,
        record: StdinEofRecord,
        supervisor: &mut impl ProcessSupervisor,
    ) -> Result<(), ServiceError> {
        let active = self.active_exec.as_mut().ok_or_else(|| {
            ServiceError::new(
                ServiceErrorCode::LifecycleError,
                "no active exec for stdin eof",
            )
        })?;
        if active.exec_id != record.exec_id {
            return Err(ServiceError::new(
                ServiceErrorCode::LifecycleError,
                "stdin eof does not match active execution",
            ));
        }
        sync_stdin_accounting(active, supervisor)?;
        if active.stdin_queue_bytes != 0 {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "stdin queue is not drained; retry stdin eof after consumer drain",
            ));
        }
        let protocol_snapshot = self.protocol_state.clone();
        let active_snapshot = active.clone();
        self.protocol_state.apply_exec_event(
            record.exec_id,
            ActiveExecEvent::StdinEof {
                sequence: record.sequence,
            },
        )?;
        active.stdin_next_sequence = active.stdin_next_sequence.saturating_add(1);
        if let Err(error) = supervisor.close_stdin(record.exec_id) {
            self.protocol_state = protocol_snapshot;
            *active = active_snapshot;
            return Err(error);
        }
        active.stdin_eof_received = true;
        Ok(())
    }

    pub fn cancel_exec(
        &mut self,
        exec_id: u32,
        reason: CancelReason,
        supervisor: &mut impl ProcessSupervisor,
    ) -> Result<(), ServiceError> {
        let active = self.active_exec.as_mut().ok_or_else(|| {
            ServiceError::new(
                ServiceErrorCode::LifecycleError,
                "no active execution to cancel",
            )
        })?;
        if active.exec_id != exec_id {
            return Err(ServiceError::new(
                ServiceErrorCode::LifecycleError,
                "cancel request targets unknown execution",
            ));
        }
        let disposition = match reason {
            CancelReason::Cancelled => {
                active.cancelled = true;
                ExecDisposition::Cancelled
            }
            CancelReason::TimedOut => {
                active.timed_out = true;
                ExecDisposition::TimedOut
            }
        };
        self.protocol_state
            .apply_exec_event(exec_id, ActiveExecEvent::Disposition(disposition))?;
        supervisor.close_stdin(exec_id)?;
        supervisor.terminate(exec_id)?;
        Ok(())
    }

    pub fn quiesce(&mut self) -> Result<AgentControlMessage, ServiceError> {
        let message = self.protocol_state.quiesce()?;
        self.quiesced = true;
        Ok(message)
    }

    pub fn resume(&mut self) -> Result<AgentControlMessage, ServiceError> {
        let message = self.protocol_state.resume()?;
        self.quiesced = false;
        Ok(message)
    }

    pub fn shutdown(&mut self) -> Result<AgentControlMessage, ServiceError> {
        let message = self.protocol_state.graceful_shutdown()?;
        self.shutting_down = true;
        Ok(message)
    }

    pub fn begin_disconnect_cleanup(
        &mut self,
        now_secs: u64,
        supervisor: &mut impl ProcessSupervisor,
    ) -> Result<(), ServiceError> {
        self.protocol_state.begin_channel_loss_cleanup(now_secs)?;
        if let Some(active) = self.active_exec.as_ref() {
            let cleaned = supervisor.cleanup_for_disconnect(
                active.exec_id,
                Duration::from_secs(CHANNEL_LOSS_CLEANUP_DEADLINE_SECS),
            )?;
            if !cleaned {
                return Err(ServiceError::new(
                    ServiceErrorCode::CleanupTimeout,
                    "channel-loss cleanup exceeded bounded deadline; must fail closed",
                ));
            }
            self.active_exec = None;
        }
        self.protocol_state.complete_channel_loss_cleanup();
        self.authenticated = false;
        self.configured = None;
        Ok(())
    }

    pub fn pump_supervisor(
        &mut self,
        supervisor: &mut impl ProcessSupervisor,
    ) -> Result<Vec<AgentControlMessage>, ServiceError> {
        let Some(current) = self.active_exec.as_ref() else {
            return Ok(Vec::new());
        };
        let exec_id = current.exec_id;
        let mut out = Vec::new();
        while let Some(event) = supervisor.peek_event(exec_id)? {
            if self.active_exec.is_none() {
                break;
            }
            apply_supervisor_event(self, exec_id, event, &mut out)?;
            supervisor.ack_event(exec_id)?;
        }
        Ok(out)
    }

    pub fn pump_supervisor_to_channel<T: Read + Write>(
        &mut self,
        supervisor: &mut impl ProcessSupervisor,
        channel: &mut HvcFramedChannel<T>,
    ) -> Result<PumpSupervisorResult, ServiceError> {
        let Some(current) = self.active_exec.as_ref() else {
            return Ok(PumpSupervisorResult::Drained);
        };
        let exec_id = current.exec_id;
        while let Some(event) = supervisor.peek_event(exec_id)? {
            if self.active_exec.is_none() {
                break;
            }
            let protocol_snapshot = self.protocol_state.clone();
            let active_snapshot = self.active_exec.clone();
            let mut messages = Vec::new();
            apply_supervisor_event(self, exec_id, event, &mut messages)?;
            let payloads = match channel.reserve_control_messages(&messages) {
                Ok(payloads) => payloads,
                Err(error) if error.code == ServiceErrorCode::Backpressure => {
                    self.protocol_state = protocol_snapshot;
                    self.active_exec = active_snapshot;
                    return Ok(PumpSupervisorResult::WouldBlock);
                }
                Err(error) => {
                    self.protocol_state = protocol_snapshot;
                    self.active_exec = active_snapshot;
                    return Err(error);
                }
            };
            channel.queue_reserved_control_payloads(payloads)?;
            supervisor.ack_event(exec_id)?;
        }
        Ok(PumpSupervisorResult::Drained)
    }

    fn require_configured(&self) -> Result<(), ServiceError> {
        if !self.authenticated || self.configured.is_none() {
            return Err(ServiceError::new(
                ServiceErrorCode::ConfigurationRequired,
                "configure_session must complete before process execution",
            ));
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        protocol_version: u32,
        image_version: &str,
        launch: LaunchIdentity,
        channel_generation: u64,
    ) -> Result<(), ServiceError> {
        if protocol_version != self.binding.protocol_version || protocol_version != PROTOCOL_VERSION
        {
            return Err(ServiceError::new(
                ServiceErrorCode::UnsupportedProtocolVersion,
                format!(
                    "protocol version {protocol_version} is not supported (expected {})",
                    self.binding.protocol_version
                ),
            ));
        }
        if image_version != self.binding.image_version {
            return Err(ServiceError::new(
                ServiceErrorCode::ImageVersionMismatch,
                "request image version does not match the admitted launch image",
            ));
        }
        if launch.generation != self.binding.launch.generation {
            return Err(ServiceError::new(
                ServiceErrorCode::LaunchGenerationMismatch,
                "request launch generation does not match the admitted generation",
            ));
        }
        if launch.nonce != self.binding.launch.nonce {
            return Err(ServiceError::new(
                ServiceErrorCode::LaunchNonceMismatch,
                "request launch nonce does not match the admitted nonce",
            ));
        }
        if channel_generation != self.binding.channel_generation {
            return Err(ServiceError::new(
                ServiceErrorCode::ChannelGenerationMismatch,
                "request channel generation does not match the authenticated channel",
            ));
        }
        Ok(())
    }
}

fn sync_stdin_accounting(
    active: &mut ActiveExecution,
    supervisor: &mut impl ProcessSupervisor,
) -> Result<(), ServiceError> {
    let drained = supervisor.take_stdin_drain_bytes(active.exec_id)?;
    if drained > active.stdin_queue_bytes {
        active.stdin_queue_bytes = 0;
    } else {
        active.stdin_queue_bytes -= drained;
    }
    Ok(())
}

fn apply_supervisor_event(
    service: &mut MxcControlService,
    exec_id: u32,
    event: SupervisorEvent,
    out: &mut Vec<AgentControlMessage>,
) -> Result<(), ServiceError> {
    match event {
        SupervisorEvent::StdoutChunk(chunk) => {
            if chunk.len() > max_stream_chunk_cap() {
                return Err(ServiceError::new(
                    ServiceErrorCode::StreamChunkTooLarge,
                    format!("stdout chunk exceeds max {}", max_stream_chunk_cap()),
                ));
            }
            let sequence = service
                .active_exec
                .as_ref()
                .map(|exec| exec.stdout_next_sequence)
                .ok_or_else(|| {
                    ServiceError::new(ServiceErrorCode::LifecycleError, "active exec missing")
                })?;
            service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::StdoutChunk { sequence })?;
            if let Some(active_exec) = service.active_exec.as_mut() {
                active_exec.stdout_next_sequence =
                    active_exec.stdout_next_sequence.saturating_add(1);
            }
            out.push(AgentControlMessage::StdoutChunk(StdoutChunkRecord {
                exec_id,
                sequence,
                chunk,
            }));
        }
        SupervisorEvent::StdoutEof => {
            let sequence = service
                .active_exec
                .as_ref()
                .map(|exec| exec.stdout_next_sequence)
                .ok_or_else(|| {
                    ServiceError::new(ServiceErrorCode::LifecycleError, "active exec missing")
                })?;
            service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::StdoutEof { sequence })?;
            if let Some(active_exec) = service.active_exec.as_mut() {
                active_exec.stdout_next_sequence =
                    active_exec.stdout_next_sequence.saturating_add(1);
            }
            out.push(AgentControlMessage::StdoutEof(StdoutEofRecord {
                exec_id,
                sequence,
            }));
            service.protocol_state.apply_exec_event(
                exec_id,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )?;
            out.push(AgentControlMessage::StreamDrained {
                exec_id,
                stream: StreamName::Stdout,
            });
        }
        SupervisorEvent::StderrChunk(chunk) => {
            if chunk.len() > max_stream_chunk_cap() {
                return Err(ServiceError::new(
                    ServiceErrorCode::StreamChunkTooLarge,
                    format!("stderr chunk exceeds max {}", max_stream_chunk_cap()),
                ));
            }
            let sequence = service
                .active_exec
                .as_ref()
                .map(|exec| exec.stderr_next_sequence)
                .ok_or_else(|| {
                    ServiceError::new(ServiceErrorCode::LifecycleError, "active exec missing")
                })?;
            service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::StderrChunk { sequence })?;
            if let Some(active_exec) = service.active_exec.as_mut() {
                active_exec.stderr_next_sequence =
                    active_exec.stderr_next_sequence.saturating_add(1);
            }
            out.push(AgentControlMessage::StderrChunk(StderrChunkRecord {
                exec_id,
                sequence,
                chunk,
            }));
        }
        SupervisorEvent::StderrEof => {
            let sequence = service
                .active_exec
                .as_ref()
                .map(|exec| exec.stderr_next_sequence)
                .ok_or_else(|| {
                    ServiceError::new(ServiceErrorCode::LifecycleError, "active exec missing")
                })?;
            service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::StderrEof { sequence })?;
            if let Some(active_exec) = service.active_exec.as_mut() {
                active_exec.stderr_next_sequence =
                    active_exec.stderr_next_sequence.saturating_add(1);
            }
            out.push(AgentControlMessage::StderrEof(StderrEofRecord {
                exec_id,
                sequence,
            }));
            service.protocol_state.apply_exec_event(
                exec_id,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stderr,
                },
            )?;
            out.push(AgentControlMessage::StreamDrained {
                exec_id,
                stream: StreamName::Stderr,
            });
        }
        SupervisorEvent::DescendantsCleaned => {
            if let Some(terminal) = service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::DescendantsCleaned)?
            {
                out.push(AgentControlMessage::DescendantsCleaned { exec_id });
                out.push(AgentControlMessage::ExecTerminal {
                    exec_id: terminal.exec_id,
                    disposition: terminal.disposition,
                });
                service.active_exec = None;
            } else {
                out.push(AgentControlMessage::DescendantsCleaned { exec_id });
            }
        }
        SupervisorEvent::Exited(exit_code) => {
            let disposition = if service
                .active_exec
                .as_ref()
                .is_some_and(|exec| exec.cancelled)
            {
                ExecDisposition::Cancelled
            } else if service
                .active_exec
                .as_ref()
                .is_some_and(|exec| exec.timed_out)
            {
                ExecDisposition::TimedOut
            } else {
                ExecDisposition::ExitCode(exit_code)
            };
            if let Some(terminal) = service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::Disposition(disposition))?
            {
                out.push(AgentControlMessage::ExecTerminal {
                    exec_id: terminal.exec_id,
                    disposition: terminal.disposition,
                });
                service.active_exec = None;
            }
        }
        SupervisorEvent::Signaled(signal) => {
            let disposition = if service
                .active_exec
                .as_ref()
                .is_some_and(|exec| exec.cancelled)
            {
                ExecDisposition::Cancelled
            } else if service
                .active_exec
                .as_ref()
                .is_some_and(|exec| exec.timed_out)
            {
                ExecDisposition::TimedOut
            } else {
                ExecDisposition::Signaled(signal)
            };
            if let Some(terminal) = service
                .protocol_state
                .apply_exec_event(exec_id, ActiveExecEvent::Disposition(disposition))?
            {
                out.push(AgentControlMessage::ExecTerminal {
                    exec_id: terminal.exec_id,
                    disposition: terminal.disposition,
                });
                service.active_exec = None;
            }
        }
    }
    Ok(())
}

impl<T: Read + Write> HvcFramedChannel<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            max_frame_bytes: OPENVMM_OUTER_RECORD_MAX_BYTES,
            read_buffer: Vec::new(),
            write_queue_bytes: 0,
            write_queue_limit_bytes: DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES,
            write_queue_limit_records: DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS,
            queued_frames: VecDeque::new(),
            current_write_offset: 0,
            write_credits: u32::MAX,
        }
    }

    pub fn grant_write_credits(&mut self, credits: u32) {
        self.write_credits = self.write_credits.saturating_add(credits);
    }

    pub fn is_write_saturated(&self) -> bool {
        self.write_credits == 0
            || self.queued_frames.len() >= self.write_queue_limit_records
            || self.write_queue_bytes >= self.write_queue_limit_bytes
    }

    pub fn has_queued_writes(&self) -> bool {
        !self.queued_frames.is_empty()
    }

    pub fn queue_inner_record(&mut self, record: &InnerRecord) -> Result<(), ServiceError> {
        let encoded = record.encode().map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::ProtocolFrameError,
                format!("failed to encode inner record: {error:?}"),
            )
        })?;
        if encoded.len() > MAX_INNER_RECORD_BYTES_FOR_OPENVMM {
            return Err(ServiceError::new(
                ServiceErrorCode::ProtocolFrameError,
                format!(
                    "inner record {} exceeds conservative OpenVMM cap {}",
                    encoded.len(),
                    MAX_INNER_RECORD_BYTES_FOR_OPENVMM
                ),
            ));
        }
        self.queue_frame_bytes(&encoded)
    }

    pub fn queue_control_message(
        &mut self,
        message: &AgentControlMessage,
    ) -> Result<(), ServiceError> {
        let payload = encode_control_message_payload(message)?;
        self.reserve_frames(&[payload.len()])?;
        self.queue_encoded_payload(payload)
    }

    pub fn queue_frame_bytes(&mut self, payload: &[u8]) -> Result<(), ServiceError> {
        self.reserve_frames(&[payload.len()])?;
        self.queue_encoded_payload(payload.to_vec())
    }

    pub fn reserve_control_messages(
        &self,
        messages: &[AgentControlMessage],
    ) -> Result<Vec<Vec<u8>>, ServiceError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        if self.write_credits < messages.len() as u32 {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "writer queue credit exhausted",
            ));
        }
        if self.queued_frames.len().saturating_add(messages.len()) > self.write_queue_limit_records
        {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "writer queue reached record capacity",
            ));
        }
        let mut payloads = Vec::with_capacity(messages.len());
        for message in messages {
            payloads.push(encode_control_message_payload(message)?);
        }
        self.reserve_frames_for_payloads(&payloads)?;
        Ok(payloads)
    }

    pub fn queue_reserved_control_payloads(
        &mut self,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), ServiceError> {
        for payload in payloads {
            self.queue_encoded_payload(payload)?;
        }
        Ok(())
    }

    fn reserve_frames(&self, payload_lengths: &[usize]) -> Result<(), ServiceError> {
        if payload_lengths.is_empty() {
            return Ok(());
        }
        if self.write_credits < payload_lengths.len() as u32 {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "writer queue credit exhausted",
            ));
        }
        if self
            .queued_frames
            .len()
            .saturating_add(payload_lengths.len())
            > self.write_queue_limit_records
        {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "writer queue reached record capacity",
            ));
        }
        let mut total_outer_bytes = 0usize;
        for payload_len in payload_lengths {
            let outer_len = payload_len.checked_add(4).ok_or_else(|| {
                ServiceError::new(ServiceErrorCode::ProtocolFrameError, "length overflow")
            })?;
            if outer_len > self.max_frame_bytes {
                return Err(ServiceError::new(
                    ServiceErrorCode::ProtocolFrameError,
                    format!("frame length {outer_len} exceeds {}", self.max_frame_bytes),
                ));
            }
            total_outer_bytes = total_outer_bytes.checked_add(outer_len).ok_or_else(|| {
                ServiceError::new(ServiceErrorCode::Backpressure, "writer queue byte overflow")
            })?;
        }
        let next_bytes = self
            .write_queue_bytes
            .checked_add(total_outer_bytes)
            .ok_or_else(|| {
                ServiceError::new(ServiceErrorCode::Backpressure, "writer queue byte overflow")
            })?;
        if next_bytes > self.write_queue_limit_bytes {
            return Err(ServiceError::new(
                ServiceErrorCode::Backpressure,
                "writer queue reached byte capacity",
            ));
        }
        Ok(())
    }

    fn reserve_frames_for_payloads(&self, payloads: &[Vec<u8>]) -> Result<(), ServiceError> {
        let lengths: Vec<usize> = payloads.iter().map(|payload| payload.len()).collect();
        self.reserve_frames(&lengths)
    }

    fn queue_encoded_payload(&mut self, payload: Vec<u8>) -> Result<(), ServiceError> {
        let outer_len = payload.len().checked_add(4).ok_or_else(|| {
            ServiceError::new(ServiceErrorCode::ProtocolFrameError, "length overflow")
        })?;
        self.reserve_frames(&[payload.len()])?;
        self.write_credits -= 1;
        let mut frame = Vec::with_capacity(outer_len);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        self.write_queue_bytes =
            self.write_queue_bytes
                .checked_add(outer_len)
                .ok_or_else(|| {
                    ServiceError::new(ServiceErrorCode::Backpressure, "writer queue byte overflow")
                })?;
        self.queued_frames.push_back(frame);
        Ok(())
    }

    pub fn flush_once(&mut self) -> Result<bool, ServiceError> {
        let Some(front) = self.queued_frames.front() else {
            return Ok(false);
        };
        let bytes = &front[self.current_write_offset..];
        if bytes.is_empty() {
            return Ok(false);
        }
        let written = match self.io.write(bytes) {
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(channel_io_error(error)),
        };
        if written == 0 {
            return Ok(false);
        }
        self.current_write_offset = self.current_write_offset.saturating_add(written);
        if self.current_write_offset == front.len() {
            let popped = self.queued_frames.pop_front().expect("front exists");
            self.write_queue_bytes = self.write_queue_bytes.saturating_sub(popped.len());
            self.current_write_offset = 0;
        }
        Ok(true)
    }

    pub fn read_next_inner_record(&mut self) -> Result<Option<InnerRecord>, ServiceError> {
        match self.try_read_next_inner_record()? {
            ChannelReadResult::Record(record) => Ok(Some(record)),
            ChannelReadResult::WouldBlock | ChannelReadResult::Closed => Ok(None),
        }
    }

    pub fn try_read_next_inner_record(&mut self) -> Result<ChannelReadResult, ServiceError> {
        loop {
            if self.read_buffer.len() >= 4 {
                let payload_len =
                    u32::from_be_bytes(self.read_buffer[0..4].try_into().expect("len")) as usize;
                let frame_len = payload_len.checked_add(4).ok_or_else(|| {
                    ServiceError::new(
                        ServiceErrorCode::ProtocolFrameError,
                        "incoming frame length overflow",
                    )
                })?;
                if frame_len > self.max_frame_bytes {
                    return Err(ServiceError::new(
                        ServiceErrorCode::ProtocolFrameError,
                        format!(
                            "incoming frame {frame_len} exceeds {}",
                            self.max_frame_bytes
                        ),
                    ));
                }
                if payload_len > MAX_INNER_RECORD_BYTES_FOR_OPENVMM {
                    return Err(ServiceError::new(
                        ServiceErrorCode::ProtocolFrameError,
                        format!(
                            "incoming payload {} exceeds conservative cap {}",
                            payload_len, MAX_INNER_RECORD_BYTES_FOR_OPENVMM
                        ),
                    ));
                }
                if self.read_buffer.len() < frame_len {
                    // Need more bytes.
                } else {
                    let payload = self.read_buffer[4..frame_len].to_vec();
                    self.read_buffer.drain(0..frame_len);
                    let record = InnerRecord::decode(&payload).map_err(inner_decode_error)?;
                    return Ok(ChannelReadResult::Record(record));
                }
            }

            let mut scratch = [0_u8; 4096];
            let size = match self.io.read(&mut scratch) {
                Ok(size) => size,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(ChannelReadResult::WouldBlock);
                }
                Err(error) => return Err(channel_io_error(error)),
            };
            if size == 0 {
                return Ok(ChannelReadResult::Closed);
            }
            self.read_buffer.extend_from_slice(&scratch[..size]);
            if self.read_buffer.len() > self.max_frame_bytes {
                return Err(ServiceError::new(
                    ServiceErrorCode::ProtocolFrameError,
                    "decoder buffer exceeded bounded allocation",
                ));
            }
        }
    }
}

fn encode_control_message_payload(message: &AgentControlMessage) -> Result<Vec<u8>, ServiceError> {
    let record = InnerRecord::control(message).map_err(|error| {
        ServiceError::new(
            ServiceErrorCode::ProtocolFrameError,
            format!("failed to build control record: {error:?}"),
        )
    })?;
    let encoded = record.encode().map_err(|error| {
        ServiceError::new(
            ServiceErrorCode::ProtocolFrameError,
            format!("failed to encode inner record: {error:?}"),
        )
    })?;
    if encoded.len() > MAX_INNER_RECORD_BYTES_FOR_OPENVMM {
        return Err(ServiceError::new(
            ServiceErrorCode::ProtocolFrameError,
            format!(
                "inner record {} exceeds conservative OpenVMM cap {}",
                encoded.len(),
                MAX_INNER_RECORD_BYTES_FOR_OPENVMM
            ),
        ));
    }
    Ok(encoded)
}

fn fallback_expected_capability(launch: LaunchIdentity) -> [u8; 32] {
    let mut capability = [0_u8; 32];
    capability[..16].copy_from_slice(&launch.nonce);
    capability[16..].copy_from_slice(&launch.nonce);
    capability
}

fn validate_configuration_bounds(configuration: &SessionConfiguration) -> Result<(), ServiceError> {
    let encoded_len = serde_json::to_vec(configuration)
        .map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::RequestTooLarge,
                format!("failed to serialize request for size checks: {error}"),
            )
        })?
        .len();
    if encoded_len > MAX_REQUEST_BODY_BYTES {
        return Err(ServiceError::new(
            ServiceErrorCode::RequestTooLarge,
            format!(
                "encoded session configuration is {encoded_len} bytes and exceeds {}",
                MAX_REQUEST_BODY_BYTES
            ),
        ));
    }
    if configuration.labels.len() > MAX_LABEL_COUNT {
        return Err(ServiceError::new(
            ServiceErrorCode::TooManyEntries,
            format!("session labels exceed maximum count {}", MAX_LABEL_COUNT),
        ));
    }
    if configuration.attributes.len() > MAX_MAP_ENTRIES {
        return Err(ServiceError::new(
            ServiceErrorCode::TooManyEntries,
            format!(
                "session attribute map exceeds maximum entry count {}",
                MAX_MAP_ENTRIES
            ),
        ));
    }
    for value in &configuration.labels {
        if value.len() > MAX_STRING_BYTES {
            return Err(ServiceError::new(
                ServiceErrorCode::StringTooLong,
                format!("label exceeds maximum length {} bytes", MAX_STRING_BYTES),
            ));
        }
    }
    for (key, value) in &configuration.attributes {
        if key.len() > MAX_STRING_BYTES || value.len() > MAX_STRING_BYTES {
            return Err(ServiceError::new(
                ServiceErrorCode::StringTooLong,
                format!(
                    "attribute key/value exceeds maximum length {} bytes",
                    MAX_STRING_BYTES
                ),
            ));
        }
    }
    if configuration.filesystem.detail.len() > MAX_STRING_BYTES {
        return Err(ServiceError::new(
            ServiceErrorCode::StringTooLong,
            format!(
                "filesystem detail exceeds maximum length {} bytes",
                MAX_STRING_BYTES
            ),
        ));
    }
    Ok(())
}

fn validate_create_process_request(request: &CreateProcessRequest) -> Result<(), ServiceError> {
    if request.argv.is_empty() {
        return Err(ServiceError::new(
            ServiceErrorCode::InvalidInput,
            "argv must include executable path",
        ));
    }
    for arg in &request.argv {
        validate_string(arg, "argv element")?;
    }
    if let Some(cwd) = &request.cwd {
        validate_string(cwd, "cwd")?;
        if !cwd.starts_with('/') {
            return Err(ServiceError::new(
                ServiceErrorCode::InvalidInput,
                format!("cwd must be absolute: {cwd}"),
            ));
        }
    }
    for entry in &request.env {
        validate_string(entry, "env entry")?;
        let Some((key, _value)) = entry.split_once('=') else {
            return Err(ServiceError::new(
                ServiceErrorCode::InvalidInput,
                format!("env entry must be KEY=VALUE: {entry}"),
            ));
        };
        if key.is_empty() {
            return Err(ServiceError::new(
                ServiceErrorCode::InvalidInput,
                "env key must not be empty",
            ));
        }
    }
    Ok(())
}

fn validate_string(value: &str, context: &str) -> Result<(), ServiceError> {
    if value.len() > MAX_STRING_BYTES {
        return Err(ServiceError::new(
            ServiceErrorCode::StringTooLong,
            format!("{context} exceeds max {MAX_STRING_BYTES} bytes"),
        ));
    }
    if value.contains('\0') {
        return Err(ServiceError::new(
            ServiceErrorCode::InvalidInput,
            format!("{context} contains embedded NUL byte"),
        ));
    }
    Ok(())
}

fn constant_time_eq32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for index in 0..32 {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

fn max_stream_chunk_cap() -> usize {
    MAX_INNER_RECORD_BYTES_FOR_OPENVMM.saturating_sub(20)
}

fn channel_io_error(error: io::Error) -> ServiceError {
    ServiceError::new(ServiceErrorCode::ChannelIo, error.to_string())
}

fn inner_decode_error(error: InnerRecordDecodeError) -> ServiceError {
    ServiceError::new(
        ServiceErrorCode::ProtocolFrameError,
        format!("inner frame decode failed: {error:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::InnerRecordKind;
    use crate::mapping::{AccessMode, RelativeChildPath, SymlinkContainmentPolicy};
    use crate::messages::{HealthStatus, HostControlMessage, NetworkMode};
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    fn launch(generation: u64) -> LaunchIdentity {
        LaunchIdentity {
            generation,
            nonce: [generation as u8; 16],
        }
    }

    fn sample_binding() -> LaunchBinding {
        LaunchBinding {
            protocol_version: PROTOCOL_VERSION,
            image_version: "img-v1".to_string(),
            launch: launch(7),
            channel_generation: 17,
        }
    }

    fn sample_configuration() -> SessionConfiguration {
        SessionConfiguration {
            root: CanonicalHostMappingRoot::parse("/sandbox".to_string()).unwrap(),
            mappings: vec![ChildMapping {
                child: RelativeChildPath::parse("runtime".to_string()).unwrap(),
                access: AccessMode::ReadOnly,
            }],
            containment: MappingContainmentPolicy {
                symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            },
            labels: vec!["runtime".to_string()],
            attributes: BTreeMap::from([("profile".to_string(), "mxc-prototype".to_string())]),
            filesystem: FilesystemStatus {
                rootfs_ready: true,
                detail: "sandbox layers mounted".to_string(),
            },
            network: NetworkStatus {
                mode: NetworkMode::PortableNetwork,
                detail: Some("10.0.0.2/24 gateway=10.0.0.1".to_string()),
            },
        }
    }

    fn wait_request() -> WaitReadyRequest {
        WaitReadyRequest {
            protocol_version: PROTOCOL_VERSION,
            image_version: "img-v1".to_string(),
            launch: launch(7),
            channel_generation: 17,
        }
    }

    fn authenticated_unconfigured_service() -> MxcControlService {
        let mut service = MxcControlService::new(sample_binding());
        service
            .authenticate_channel(
                AuthenticateChannelRequest {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch: launch(7),
                    channel_generation: 17,
                    capability_proof: [7; 32],
                },
                1,
                NetworkStatus {
                    mode: NetworkMode::NoNic,
                    detail: None,
                },
            )
            .unwrap();
        service
    }

    #[test]
    fn get_capabilities_reports_only_reachable_phase0_operations() {
        let service = MxcControlService::new(sample_binding());
        let capabilities = service.get_capabilities();
        assert_eq!(
            capabilities.available_operations,
            vec![
                "GetCapabilities".to_string(),
                "AuthenticateChannel".to_string(),
                "ConfigureSession".to_string(),
                "WaitReady".to_string(),
                "Health".to_string(),
            ]
        );
    }

    #[test]
    fn get_capabilities_marks_unimplemented_operations_unavailable_with_reasons() {
        let service = MxcControlService::new(sample_binding());
        let capabilities = service.get_capabilities();

        let unavailable = capabilities
            .unavailable_operations
            .iter()
            .map(|entry| {
                assert!(!entry.capability_flag.is_empty());
                assert!(!entry.reason.is_empty());
                entry.operation.as_str()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            unavailable,
            std::collections::BTreeSet::from([
                "Exec",
                "Streams",
                "Cancel",
                "Quiesce",
                "DisconnectCleanup",
                "Resume",
                "Shutdown",
            ])
        );

        let advertised = capabilities
            .available_operations
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(unavailable.is_disjoint(&advertised));
    }

    #[test]
    fn wait_ready_is_level_triggered_once_configuration_is_applied() {
        let mut service = authenticated_unconfigured_service();
        service
            .configure_session(ConfigureSessionRequest {
                protocol_version: PROTOCOL_VERSION,
                image_version: "img-v1".to_string(),
                launch: launch(7),
                channel_generation: 17,
                idempotent_replay: false,
                configuration: sample_configuration(),
            })
            .unwrap();
        let first = service.wait_ready(wait_request()).unwrap();
        let second = service.wait_ready(wait_request()).unwrap();
        assert_eq!(first, second);
        assert!(first.filesystem.rootfs_ready);
        assert_eq!(first.network.mode, NetworkMode::PortableNetwork);
    }

    #[test]
    fn authentication_rejects_wrong_capability_same_length() {
        let mut service = MxcControlService::new(sample_binding());
        let error = service
            .authenticate_channel(
                AuthenticateChannelRequest {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch: launch(7),
                    channel_generation: 17,
                    capability_proof: [4; 32],
                },
                1,
                NetworkStatus {
                    mode: NetworkMode::NoNic,
                    detail: None,
                },
            )
            .expect_err("must reject wrong capability");
        assert_eq!(error.code, ServiceErrorCode::AuthenticationFailed);
    }

    #[test]
    fn wait_ready_rejects_wrong_nonce_version_and_channel_generation() {
        let mut service = authenticated_unconfigured_service();
        service
            .configure_session(ConfigureSessionRequest {
                protocol_version: PROTOCOL_VERSION,
                image_version: "img-v1".to_string(),
                launch: launch(7),
                channel_generation: 17,
                idempotent_replay: false,
                configuration: sample_configuration(),
            })
            .unwrap();

        let wrong_nonce = WaitReadyRequest {
            launch: LaunchIdentity {
                generation: 7,
                nonce: [0xAA; 16],
            },
            ..wait_request()
        };
        assert_eq!(
            service.wait_ready(wrong_nonce).unwrap_err().code,
            ServiceErrorCode::LaunchNonceMismatch
        );

        let wrong_version = WaitReadyRequest {
            protocol_version: 99,
            ..wait_request()
        };
        assert_eq!(
            service.wait_ready(wrong_version).unwrap_err().code,
            ServiceErrorCode::UnsupportedProtocolVersion
        );

        let wrong_channel_generation = WaitReadyRequest {
            channel_generation: 22,
            ..wait_request()
        };
        assert_eq!(
            service
                .wait_ready(wrong_channel_generation)
                .unwrap_err()
                .code,
            ServiceErrorCode::ChannelGenerationMismatch
        );
    }

    #[test]
    fn configure_session_is_immutable_and_replay_requires_idempotent_bit() {
        let mut service = authenticated_unconfigured_service();
        let initial = sample_configuration();
        service
            .configure_session(ConfigureSessionRequest {
                protocol_version: PROTOCOL_VERSION,
                image_version: "img-v1".to_string(),
                launch: launch(7),
                channel_generation: 17,
                idempotent_replay: false,
                configuration: initial.clone(),
            })
            .unwrap();

        let conflicting = SessionConfiguration {
            filesystem: FilesystemStatus {
                rootfs_ready: true,
                detail: "different".to_string(),
            },
            ..sample_configuration()
        };
        assert_eq!(
            service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: PROTOCOL_VERSION,
                    image_version: "img-v1".to_string(),
                    launch: launch(7),
                    channel_generation: 17,
                    idempotent_replay: true,
                    configuration: conflicting,
                })
                .unwrap_err()
                .code,
            ServiceErrorCode::ConfigurationConflict
        );

        assert_eq!(
            service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: PROTOCOL_VERSION,
                    image_version: "img-v1".to_string(),
                    launch: launch(7),
                    channel_generation: 17,
                    idempotent_replay: false,
                    configuration: initial,
                })
                .unwrap_err()
                .code,
            ServiceErrorCode::ConfigurationConflict
        );

        assert!(
            service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: PROTOCOL_VERSION,
                    image_version: "img-v1".to_string(),
                    launch: launch(7),
                    channel_generation: 17,
                    idempotent_replay: true,
                    configuration: sample_configuration(),
                })
                .is_ok()
        );
    }

    #[test]
    fn health_reports_configuration_and_network_filesystem_state() {
        let mut service = authenticated_unconfigured_service();
        let initial = service.health();
        assert!(initial.launch_admitted);
        assert!(!initial.configured);

        service
            .configure_session(ConfigureSessionRequest {
                protocol_version: PROTOCOL_VERSION,
                image_version: "img-v1".to_string(),
                launch: launch(7),
                channel_generation: 17,
                idempotent_replay: false,
                configuration: sample_configuration(),
            })
            .unwrap();
        let configured = service.health();
        assert!(configured.configured);
        assert!(configured.filesystem.unwrap().rootfs_ready);
        assert_eq!(
            configured.network.unwrap().mode,
            NetworkMode::PortableNetwork
        );
        assert!(!configured.shutting_down);
    }

    #[test]
    fn configuration_bounds_enforce_map_list_string_and_body_limits() {
        let mut service = authenticated_unconfigured_service();
        let mut too_many_labels = sample_configuration();
        too_many_labels.labels = (0..=MAX_LABEL_COUNT)
            .map(|i| format!("label-{i}"))
            .collect();
        assert_eq!(
            service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: PROTOCOL_VERSION,
                    image_version: "img-v1".to_string(),
                    launch: launch(7),
                    channel_generation: 17,
                    idempotent_replay: false,
                    configuration: too_many_labels,
                })
                .unwrap_err()
                .code,
            ServiceErrorCode::TooManyEntries
        );

        let mut too_long = sample_configuration();
        too_long.filesystem.detail = "x".repeat(MAX_STRING_BYTES + 1);
        assert_eq!(
            service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: PROTOCOL_VERSION,
                    image_version: "img-v1".to_string(),
                    launch: launch(7),
                    channel_generation: 17,
                    idempotent_replay: false,
                    configuration: too_long,
                })
                .unwrap_err()
                .code,
            ServiceErrorCode::StringTooLong
        );
    }

    #[test]
    fn constants_prove_conservative_openvmm_record_math() {
        assert_eq!(
            OPENVMM_OUTER_RECORD_MAX_BYTES,
            MAX_INNER_RECORD_BYTES_FOR_OPENVMM + OPENVMM_OUTER_FRAME_OVERHEAD_BYTES
        );
    }

    #[derive(Clone, Default)]
    struct FakeSupervisor {
        events: VecDeque<SupervisorEvent>,
        spawned: Vec<CreateProcessRequest>,
        stdin: Vec<Vec<u8>>,
        fail_next_stdin_backpressure: bool,
        stdin_closed: bool,
        stdin_pending_bytes: usize,
        stdin_drained_bytes: usize,
        terminated: u32,
        killed: u32,
        cleanup_ok: bool,
    }

    impl ProcessSupervisor for FakeSupervisor {
        fn spawn(&mut self, request: &CreateProcessRequest) -> Result<(), ServiceError> {
            self.spawned.push(request.clone());
            Ok(())
        }

        fn queue_stdin(&mut self, _exec_id: u32, chunk: Vec<u8>) -> Result<(), ServiceError> {
            if self.fail_next_stdin_backpressure {
                self.fail_next_stdin_backpressure = false;
                return Err(ServiceError::new(
                    ServiceErrorCode::Backpressure,
                    "stdin queue reached byte limit",
                ));
            }
            self.stdin_pending_bytes = self.stdin_pending_bytes.saturating_add(chunk.len());
            self.stdin.push(chunk);
            Ok(())
        }

        fn close_stdin(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
            if self.stdin_pending_bytes != 0 {
                return Err(ServiceError::new(
                    ServiceErrorCode::Backpressure,
                    "stdin queue is not drained",
                ));
            }
            self.stdin_closed = true;
            Ok(())
        }

        fn take_stdin_drain_bytes(&mut self, _exec_id: u32) -> Result<usize, ServiceError> {
            let drained = self.stdin_drained_bytes;
            self.stdin_drained_bytes = 0;
            Ok(drained)
        }

        fn peek_event(&mut self, _exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
            Ok(self.events.front().cloned())
        }

        fn ack_event(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
            let _ = self.events.pop_front();
            Ok(())
        }

        fn terminate(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
            self.terminated += 1;
            Ok(())
        }

        fn kill(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
            self.killed += 1;
            Ok(())
        }

        fn poll(&mut self, _exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
            let event = self.peek_event(0)?;
            if event.is_some() {
                self.ack_event(0)?;
            }
            Ok(event)
        }

        fn cleanup_for_disconnect(
            &mut self,
            _exec_id: u32,
            _deadline: Duration,
        ) -> Result<bool, ServiceError> {
            Ok(self.cleanup_ok)
        }
    }

    fn authenticated_service() -> MxcControlService {
        let mut service = MxcControlService::new(sample_binding());
        let ready = service
            .authenticate_channel(
                AuthenticateChannelRequest {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch: launch(7),
                    channel_generation: 17,
                    capability_proof: [7; 32],
                },
                1,
                NetworkStatus {
                    mode: NetworkMode::NoNic,
                    detail: None,
                },
            )
            .unwrap();
        assert_eq!(ready.service, SERVICE_IDENTITY);
        service
            .configure_session(ConfigureSessionRequest {
                protocol_version: PROTOCOL_VERSION,
                image_version: "img-v1".to_string(),
                launch: launch(7),
                channel_generation: 17,
                idempotent_replay: false,
                configuration: sample_configuration(),
            })
            .unwrap();
        service
    }

    fn drain_supervisor_messages(
        service: &mut MxcControlService,
        supervisor: &mut FakeSupervisor,
    ) -> Vec<AgentControlMessage> {
        let mut messages = Vec::new();
        for _ in 0..512 {
            let batch = service.pump_supervisor(supervisor).unwrap();
            messages.extend(batch);
            if supervisor.events.is_empty() && service.active_exec_id().is_none() {
                break;
            }
        }
        messages
    }

    fn drain_fake_stdin(supervisor: &mut FakeSupervisor) {
        if let Some(chunk) = supervisor.stdin.first() {
            let len = chunk.len();
            supervisor.stdin.remove(0);
            supervisor.stdin_pending_bytes = supervisor.stdin_pending_bytes.saturating_sub(len);
            supervisor.stdin_drained_bytes = supervisor.stdin_drained_bytes.saturating_add(len);
        }
    }

    #[test]
    fn exec_is_sequential_and_exec_id_not_reused() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 41,
                    argv: vec!["/bin/echo".to_string(), "ok".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec!["A=B".to_string()],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        let second = service.create_process(
            CreateProcessRequest {
                exec_id: 42,
                argv: vec!["/bin/echo".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        );
        assert_eq!(second.unwrap_err().code, ServiceErrorCode::LifecycleError);

        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Exited(0));
        let messages = drain_supervisor_messages(&mut service, &mut supervisor);
        assert!(matches!(
            messages.last(),
            Some(AgentControlMessage::ExecTerminal { exec_id: 41, .. })
        ));
        let reused = service.create_process(
            CreateProcessRequest {
                exec_id: 41,
                argv: vec!["/bin/echo".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        );
        assert_eq!(reused.unwrap_err().code, ServiceErrorCode::LifecycleError);
        assert!(
            service
                .create_process(
                    CreateProcessRequest {
                        exec_id: 43,
                        argv: vec!["/bin/echo".to_string()],
                        cwd: Some("/".to_string()),
                        env: vec![],
                        timeout_ms: None,
                    },
                    &mut supervisor,
                )
                .is_ok()
        );
    }

    #[test]
    fn binary_streaming_preserves_nul_and_terminal_is_last() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 3,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 3,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 3,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .unwrap();

        supervisor
            .events
            .push_back(SupervisorEvent::StdoutChunk(vec![1, 0, 2, 0, 3]));
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Exited(0));
        let messages = drain_supervisor_messages(&mut service, &mut supervisor);
        assert!(matches!(
            &messages[0],
            AgentControlMessage::StdoutChunk(StdoutChunkRecord { chunk, .. }) if chunk == &vec![1, 0, 2, 0, 3]
        ));
        assert!(matches!(
            messages.last(),
            Some(AgentControlMessage::ExecTerminal {
                disposition: ExecDisposition::ExitCode(0),
                ..
            })
        ));
    }

    #[test]
    fn cancellation_closes_stdin_and_emits_single_terminal() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 77,
                    argv: vec!["/bin/sleep".to_string(), "100".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(1_000),
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .cancel_exec(77, CancelReason::Cancelled, &mut supervisor)
            .unwrap();
        assert!(supervisor.stdin_closed);
        assert_eq!(supervisor.terminated, 1);

        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 77,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 77,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .unwrap();
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Signaled(15));
        let messages = drain_supervisor_messages(&mut service, &mut supervisor);
        let terminals: Vec<_> = messages
            .iter()
            .filter(|message| matches!(message, AgentControlMessage::ExecTerminal { .. }))
            .collect();
        assert_eq!(terminals.len(), 1);
        assert!(matches!(
            terminals[0],
            AgentControlMessage::ExecTerminal {
                disposition: ExecDisposition::Cancelled,
                ..
            }
        ));
    }

    #[test]
    fn stdin_eof_closes_stream_and_calls_supervisor() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 51,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .stdin_eof(
                StdinEofRecord {
                    exec_id: 51,
                    sequence: 0,
                },
                &mut supervisor,
            )
            .unwrap();
        assert!(supervisor.stdin_closed, "stdin must be closed at EOF");
    }

    #[test]
    fn timed_out_disposition_wins_over_signal_exit() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 52,
                    argv: vec!["/bin/sleep".to_string(), "10".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(1),
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .cancel_exec(52, CancelReason::TimedOut, &mut supervisor)
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 52,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 52,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .unwrap();
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Signaled(9));
        let messages = drain_supervisor_messages(&mut service, &mut supervisor);
        assert!(matches!(
            messages.last(),
            Some(AgentControlMessage::ExecTerminal {
                disposition: ExecDisposition::TimedOut,
                ..
            })
        ));
    }

    #[test]
    fn stdin_backpressure_is_transactional_and_sequence_retry_succeeds() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 61,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 61,
                stream: StreamName::Stdin,
                credits: 1,
            })
            .unwrap();

        supervisor.fail_next_stdin_backpressure = true;
        let first_attempt = service.stdin_chunk(
            StdinChunkRecord {
                exec_id: 61,
                sequence: 0,
                chunk: b"abc".to_vec(),
            },
            &mut supervisor,
        );
        assert_eq!(
            first_attempt.unwrap_err().code,
            ServiceErrorCode::Backpressure
        );
        assert!(supervisor.stdin.is_empty());

        service
            .stdin_chunk(
                StdinChunkRecord {
                    exec_id: 61,
                    sequence: 0,
                    chunk: b"abc".to_vec(),
                },
                &mut supervisor,
            )
            .unwrap();
        assert_eq!(supervisor.stdin, vec![b"abc".to_vec()]);
    }

    #[test]
    fn stdin_accounting_tracks_drain_and_eof_waits_for_queue_to_empty() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 62,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 62,
                stream: StreamName::Stdin,
                credits: 512,
            })
            .unwrap();

        let chunk = vec![7_u8; 32 * 1024];
        for sequence in 0..5_u64 {
            service
                .stdin_chunk(
                    StdinChunkRecord {
                        exec_id: 62,
                        sequence,
                        chunk: chunk.clone(),
                    },
                    &mut supervisor,
                )
                .unwrap();
            if sequence < 4 {
                drain_fake_stdin(&mut supervisor);
            }
        }
        let eof_pending = service.stdin_eof(
            StdinEofRecord {
                exec_id: 62,
                sequence: 5,
            },
            &mut supervisor,
        );
        assert_eq!(
            eof_pending.unwrap_err().code,
            ServiceErrorCode::Backpressure
        );
        while !supervisor.stdin.is_empty() {
            drain_fake_stdin(&mut supervisor);
        }
        service
            .stdin_eof(
                StdinEofRecord {
                    exec_id: 62,
                    sequence: 5,
                },
                &mut supervisor,
            )
            .unwrap();
        assert!(supervisor.stdin_closed);
    }

    #[test]
    fn instantaneous_stdin_over_bound_rejects_then_retries_same_sequence() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 63,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 63,
                stream: StreamName::Stdin,
                credits: 4,
            })
            .unwrap();
        let max_chunk = vec![1_u8; max_stream_chunk_cap()];
        let full_chunks = DEFAULT_STDIN_QUEUE_LIMIT_BYTES / max_stream_chunk_cap();
        let remainder = DEFAULT_STDIN_QUEUE_LIMIT_BYTES % max_stream_chunk_cap();
        let mut next_sequence = 0_u64;
        for _ in 0..full_chunks {
            service
                .stdin_chunk(
                    StdinChunkRecord {
                        exec_id: 63,
                        sequence: next_sequence,
                        chunk: max_chunk.clone(),
                    },
                    &mut supervisor,
                )
                .unwrap();
            next_sequence = next_sequence.saturating_add(1);
        }
        if remainder != 0 {
            service
                .stdin_chunk(
                    StdinChunkRecord {
                        exec_id: 63,
                        sequence: next_sequence,
                        chunk: vec![1_u8; remainder],
                    },
                    &mut supervisor,
                )
                .unwrap();
            next_sequence = next_sequence.saturating_add(1);
        }
        let second = service.stdin_chunk(
            StdinChunkRecord {
                exec_id: 63,
                sequence: next_sequence,
                chunk: vec![2_u8; 1],
            },
            &mut supervisor,
        );
        assert_eq!(second.unwrap_err().code, ServiceErrorCode::Backpressure);
        drain_fake_stdin(&mut supervisor);
        service
            .stdin_chunk(
                StdinChunkRecord {
                    exec_id: 63,
                    sequence: next_sequence,
                    chunk: vec![2_u8; 1],
                },
                &mut supervisor,
            )
            .unwrap();
    }

    #[test]
    fn terminal_message_is_emitted_after_output_and_eofs() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 53,
                    argv: vec!["/bin/echo".to_string(), "x".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 53,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 53,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .unwrap();

        supervisor
            .events
            .push_back(SupervisorEvent::StdoutChunk(vec![120]));
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor.events.push_back(SupervisorEvent::Exited(0));
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        let messages = drain_supervisor_messages(&mut service, &mut supervisor);
        let terminal_index = messages
            .iter()
            .position(|message| matches!(message, AgentControlMessage::ExecTerminal { .. }))
            .unwrap();
        let stdout_chunk_index = messages
            .iter()
            .position(|message| matches!(message, AgentControlMessage::StdoutChunk(_)))
            .unwrap();
        let stdout_eof_index = messages
            .iter()
            .position(|message| matches!(message, AgentControlMessage::StdoutEof(_)))
            .unwrap();
        let stderr_eof_index = messages
            .iter()
            .position(|message| matches!(message, AgentControlMessage::StderrEof(_)))
            .unwrap();
        assert!(stdout_chunk_index < terminal_index);
        assert!(stdout_eof_index < terminal_index);
        assert!(stderr_eof_index < terminal_index);
    }

    #[test]
    fn disconnect_cleanup_blocks_reconnect_until_done() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor {
            cleanup_ok: false,
            ..FakeSupervisor::default()
        };
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 88,
                    argv: vec!["/bin/sleep".to_string(), "1".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        let cleanup = service.begin_disconnect_cleanup(100, &mut supervisor);
        assert_eq!(cleanup.unwrap_err().code, ServiceErrorCode::CleanupTimeout);
    }

    #[test]
    fn reconnect_requires_strictly_newer_generation() {
        let mut service = MxcControlService::new(sample_binding());
        service
            .authenticate_channel(
                AuthenticateChannelRequest {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch: launch(7),
                    channel_generation: 17,
                    capability_proof: [7; 32],
                },
                1,
                NetworkStatus {
                    mode: NetworkMode::NoNic,
                    detail: None,
                },
            )
            .unwrap();
        let mut supervisor = FakeSupervisor::default();
        service
            .begin_disconnect_cleanup(2, &mut supervisor)
            .unwrap();
        let same = service.authenticate_channel(
            AuthenticateChannelRequest {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: launch(7),
                channel_generation: 17,
                capability_proof: [7; 32],
            },
            40,
            NetworkStatus {
                mode: NetworkMode::NoNic,
                detail: None,
            },
        );
        assert_eq!(same.unwrap_err().code, ServiceErrorCode::LifecycleError);
        let newer = service.authenticate_channel(
            AuthenticateChannelRequest {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: launch(8),
                channel_generation: 17,
                capability_proof: [7; 32],
            },
            40,
            NetworkStatus {
                mode: NetworkMode::NoNic,
                detail: None,
            },
        );
        assert!(newer.is_ok());
    }

    #[test]
    fn framed_channel_writes_and_reads_with_partial_io() {
        #[derive(Clone, Default)]
        struct PartialIo {
            in_bytes: Rc<RefCell<Vec<u8>>>,
            out_bytes: Rc<RefCell<Vec<u8>>>,
            read_cursor: usize,
            max_step: usize,
        }
        impl Read for PartialIo {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let bytes = self.in_bytes.borrow();
                if self.read_cursor >= bytes.len() {
                    return Ok(0);
                }
                let end = (self.read_cursor + self.max_step)
                    .min(bytes.len())
                    .min(self.read_cursor + buf.len());
                let count = end - self.read_cursor;
                buf[..count].copy_from_slice(&bytes[self.read_cursor..end]);
                self.read_cursor = end;
                Ok(count)
            }
        }
        impl Write for PartialIo {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let count = buf.len().min(self.max_step);
                self.out_bytes.borrow_mut().extend_from_slice(&buf[..count]);
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let source_record = InnerRecord {
            exec_id: 0,
            kind: InnerRecordKind::Control,
            end_of_stream: false,
            sequence: 0,
            payload: serde_json::to_vec(&HostControlMessage::Health).unwrap(),
        };
        let encoded = source_record.encode().unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        framed.extend_from_slice(&encoded);
        let io = PartialIo {
            in_bytes: Rc::new(RefCell::new(framed)),
            out_bytes: Rc::new(RefCell::new(Vec::new())),
            read_cursor: 0,
            max_step: 3,
        };
        let mut channel = HvcFramedChannel::new(io.clone());
        let decoded = channel.read_next_inner_record().unwrap().unwrap();
        assert_eq!(decoded.kind, InnerRecordKind::Control);
        channel.queue_inner_record(&source_record).unwrap();
        while channel.flush_once().unwrap() {}
        assert!(!io.out_bytes.borrow().is_empty());
    }

    #[test]
    fn framed_channel_backpressure_is_bounded() {
        let io = Cursor::new(Vec::<u8>::new());
        let mut channel = HvcFramedChannel::new(io);
        channel.write_queue_limit_records = 1;
        let record = InnerRecord::control(&HealthStatus {
            quiesced: false,
            launch_admitted: true,
        })
        .unwrap();
        channel.queue_inner_record(&record).unwrap();
        let second = channel.queue_inner_record(&record);
        assert_eq!(second.unwrap_err().code, ServiceErrorCode::Backpressure);
    }

    #[test]
    fn framed_channel_credit_saturation_recovers_without_data_loss() {
        let io = Cursor::new(Vec::<u8>::new());
        let mut channel = HvcFramedChannel::new(io);
        channel.write_credits = 1;
        let first = InnerRecord::control(&HealthStatus {
            quiesced: false,
            launch_admitted: true,
        })
        .unwrap();
        let second = InnerRecord::control(&HealthStatus {
            quiesced: true,
            launch_admitted: false,
        })
        .unwrap();
        channel.queue_inner_record(&first).unwrap();
        let saturated = channel.queue_inner_record(&second);
        assert_eq!(saturated.unwrap_err().code, ServiceErrorCode::Backpressure);
        channel.grant_write_credits(1);
        channel.queue_inner_record(&second).unwrap();
        while channel.flush_once().unwrap() {}
        let written = channel.io.into_inner();
        let mut readback = HvcFramedChannel::new(Cursor::new(written));
        let first_out = readback.read_next_inner_record().unwrap().unwrap();
        let second_out = readback.read_next_inner_record().unwrap().unwrap();
        assert_eq!(first_out.payload, first.payload);
        assert_eq!(second_out.payload, second.payload);
        assert!(readback.read_next_inner_record().unwrap().is_none());
    }

    #[test]
    fn pump_supervisor_to_channel_backpressure_keeps_front_until_credit_and_capacity() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 64,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 64,
                stream: StreamName::Stdout,
                credits: 2,
            })
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 64,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .unwrap();
        supervisor
            .events
            .push_back(SupervisorEvent::StdoutChunk(vec![1, 0, 2, 0, 3]));
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Exited(0));

        let mut channel = HvcFramedChannel::new(Cursor::new(Vec::<u8>::new()));
        channel.write_credits = 0;
        channel.write_queue_limit_records = 256;
        let blocked = service
            .pump_supervisor_to_channel(&mut supervisor, &mut channel)
            .unwrap();
        assert_eq!(blocked, PumpSupervisorResult::WouldBlock);
        assert!(matches!(
            supervisor.events.front(),
            Some(SupervisorEvent::StdoutChunk(chunk)) if chunk == &vec![1, 0, 2, 0, 3]
        ));

        channel.grant_write_credits(16);
        while service
            .pump_supervisor_to_channel(&mut supervisor, &mut channel)
            .unwrap()
            == PumpSupervisorResult::WouldBlock
        {}
        while channel.flush_once().unwrap() {}
        let written = channel.io.into_inner();
        let mut readback = HvcFramedChannel::new(Cursor::new(written));
        let mut observed = Vec::new();
        while let Some(record) = readback.read_next_inner_record().unwrap() {
            let message = serde_json::from_slice::<AgentControlMessage>(&record.payload).unwrap();
            observed.push(message);
        }
        assert!(matches!(
            observed.first(),
            Some(AgentControlMessage::StdoutChunk(StdoutChunkRecord { chunk, .. }))
                if chunk == &vec![1, 0, 2, 0, 3]
        ));
        let terminal_count = observed
            .iter()
            .filter(|message| matches!(message, AgentControlMessage::ExecTerminal { .. }))
            .count();
        assert_eq!(terminal_count, 1);
    }

    #[test]
    fn pump_supervisor_to_channel_waits_for_256_record_queue_capacity_losslessly() {
        let mut service = authenticated_service();
        let mut supervisor = FakeSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 65,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 65,
                stream: StreamName::Stdout,
                credits: 2,
            })
            .unwrap();

        supervisor
            .events
            .push_back(SupervisorEvent::StdoutChunk(vec![9, 0, 9]));
        supervisor.events.push_back(SupervisorEvent::StdoutEof);

        let mut channel = HvcFramedChannel::new(Cursor::new(Vec::<u8>::new()));
        channel.write_queue_limit_records = 256;
        channel.write_credits = 256;
        let filler = AgentControlMessage::Health(HealthStatus {
            quiesced: false,
            launch_admitted: true,
        });
        for _ in 0..256 {
            channel.queue_control_message(&filler).unwrap();
        }
        let blocked = service
            .pump_supervisor_to_channel(&mut supervisor, &mut channel)
            .unwrap();
        assert_eq!(blocked, PumpSupervisorResult::WouldBlock);
        assert!(matches!(
            supervisor.events.front(),
            Some(SupervisorEvent::StdoutChunk(chunk)) if chunk == &vec![9, 0, 9]
        ));

        while channel.flush_once().unwrap() {}
        channel.grant_write_credits(4);
        assert_eq!(
            service
                .pump_supervisor_to_channel(&mut supervisor, &mut channel)
                .unwrap(),
            PumpSupervisorResult::Drained
        );
        while channel.flush_once().unwrap() {}
        let written = channel.io.into_inner();
        let mut readback = HvcFramedChannel::new(Cursor::new(written));
        let mut observed_control = Vec::new();
        while let Some(record) = readback.read_next_inner_record().unwrap() {
            let message = serde_json::from_slice::<AgentControlMessage>(&record.payload).unwrap();
            observed_control.push(message);
        }
        let last_three = observed_control.split_off(observed_control.len() - 3);
        assert!(matches!(
            &last_three[0],
            AgentControlMessage::StdoutChunk(StdoutChunkRecord { chunk, .. }) if chunk == &vec![9, 0, 9]
        ));
        assert!(matches!(
            &last_three[1],
            AgentControlMessage::StdoutEof(StdoutEofRecord { .. })
        ));
        assert!(matches!(
            &last_three[2],
            AgentControlMessage::StreamDrained {
                stream: StreamName::Stdout,
                ..
            }
        ));
    }
}
