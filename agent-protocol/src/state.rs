// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::mapping::{
    CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy, MappingError,
    validate_mapping_set,
};
use crate::messages::{
    AgentControlMessage, AgentSessionState, BuildStatus, CapabilityProofMaterial, DnsStatus,
    ExecDisposition, HealthStatus, IsolationStatus, LaunchIdentity, NetworkMode, NetworkSetupState,
    NetworkStatus, ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY,
    StreamName, TerminationOutcome, WorkloadIdentityStatus,
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const CHANNEL_LOSS_CLEANUP_DEADLINE_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowControlWindow {
    pub available_credits: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecTerminalEvent {
    pub exec_id: u32,
    pub disposition: ExecDisposition,
    pub termination: Option<TerminationOutcome>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveExecEvent {
    AddFlowCredits { stream: StreamName, credits: u32 },
    StdinChunk { sequence: u64 },
    StdinEof { sequence: u64 },
    StdoutChunk { sequence: u64 },
    StdoutEof { sequence: u64 },
    StderrChunk { sequence: u64 },
    StderrEof { sequence: u64 },
    StreamDrained { stream: StreamName },
    DescendantsCleaned,
    Disposition(ExecDisposition),
    TerminationOutcome(TerminationOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStatus {
    NotRequired,
    InProgress { generation: u64, deadline_secs: u64 },
    Completed { generation: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchAdmissionError {
    CleanupInProgress {
        generation: u64,
        deadline_secs: u64,
        now_secs: u64,
    },
    ActiveLaunchExists {
        generation: u64,
    },
    UnsupportedService(String),
    UnsupportedVersion(u32),
    GenerationNotNewer {
        latest_generation: u64,
        attempted: u64,
    },
    IsolationContractViolation {
        missing: Vec<IsolationContractProperty>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationContractProperty {
    PidNamespace,
    MountNamespace,
    UtsNamespace,
    IpcNamespace,
    PrivateProc,
    PrivateDev,
    PrivateDevpts,
    PrivateShm,
    ReadOnlySys,
    CapabilitiesDropped,
    NoNewPrivs,
    CgroupSeparation,
    OrphanReaping,
    FixedMxcIdentity,
}

#[derive(Debug)]
pub enum StateError {
    LaunchAdmission(LaunchAdmissionError),
    LaunchGenerationConflict {
        expected: LaunchIdentity,
        actual: LaunchIdentity,
    },
    ConfigureAlreadyApplied,
    ConfigureAfterExec,
    ConfigureRequiredForExec,
    InvalidLifecycleTransition {
        operation: &'static str,
    },
    LaunchQuiesced,
    LaunchShuttingDown,
    Mapping(MappingError),
    ActiveExecExists {
        active_exec_id: u32,
    },
    ExecIdReusedInGeneration {
        exec_id: u32,
    },
    UnknownExecId {
        exec_id: u32,
    },
    StreamSequenceMismatch {
        stream: StreamName,
        expected: u64,
        actual: u64,
    },
    StreamSequenceExhausted {
        stream: StreamName,
        last_sequence: u64,
    },
    StreamAlreadyClosed {
        stream: StreamName,
        exec_id: u32,
    },
    FlowControlCreditExhausted {
        stream: StreamName,
        exec_id: u32,
    },
    FlowControlCreditOverflow {
        stream: StreamName,
    },
    InvalidDrainStream {
        stream: StreamName,
        exec_id: u32,
    },
    StreamDrainBeforeEof {
        stream: StreamName,
        exec_id: u32,
    },
    StreamAlreadyDrained {
        stream: StreamName,
        exec_id: u32,
    },
    DescendantsAlreadyCleaned {
        exec_id: u32,
    },
    DispositionAlreadySet {
        exec_id: u32,
        current: ExecDisposition,
        attempted: ExecDisposition,
    },
    MissingTerminalPrerequisites {
        exec_id: u32,
    },
    TerminationOutcomeConflict {
        exec_id: u32,
        current: TerminationOutcome,
        attempted: TerminationOutcome,
    },
    UnexpectedTerminationOutcomeForDisposition {
        exec_id: u32,
        disposition: ExecDisposition,
        termination: TerminationOutcome,
    },
    ChannelAuthenticationRequired,
}

impl StateError {
    pub fn to_protocol_error_detail(&self) -> ProtocolErrorDetail {
        let code = match self {
            Self::LaunchAdmission(LaunchAdmissionError::CleanupInProgress { .. }) => {
                ProtocolErrorCode::CleanupInProgress
            }
            Self::LaunchAdmission(LaunchAdmissionError::ActiveLaunchExists { .. }) => {
                ProtocolErrorCode::ActiveLaunchExists
            }
            Self::LaunchAdmission(LaunchAdmissionError::UnsupportedService(_)) => {
                ProtocolErrorCode::UnsupportedService
            }
            Self::LaunchAdmission(LaunchAdmissionError::UnsupportedVersion(_)) => {
                ProtocolErrorCode::UnsupportedProtocolVersion
            }
            Self::LaunchAdmission(LaunchAdmissionError::GenerationNotNewer { .. }) => {
                ProtocolErrorCode::LaunchGenerationNotNewer
            }
            Self::LaunchAdmission(LaunchAdmissionError::IsolationContractViolation { .. }) => {
                ProtocolErrorCode::IsolationContractViolation
            }
            Self::LaunchGenerationConflict { .. } => ProtocolErrorCode::LaunchGenerationConflict,
            Self::ConfigureAlreadyApplied => ProtocolErrorCode::ConfigureAlreadyApplied,
            Self::ConfigureAfterExec => ProtocolErrorCode::ConfigureAfterExec,
            Self::ConfigureRequiredForExec => ProtocolErrorCode::ConfigureRequiredForExec,
            Self::InvalidLifecycleTransition { .. } => {
                ProtocolErrorCode::InvalidLifecycleTransition
            }
            Self::LaunchQuiesced => ProtocolErrorCode::LaunchQuiesced,
            Self::LaunchShuttingDown => ProtocolErrorCode::LaunchShuttingDown,
            Self::Mapping(MappingError::OverlapConflict { .. }) => {
                ProtocolErrorCode::MappingConflict
            }
            Self::Mapping(_) => ProtocolErrorCode::InvalidMappingPath,
            Self::ActiveExecExists { .. } => ProtocolErrorCode::ActiveExecExists,
            Self::ExecIdReusedInGeneration { .. } => ProtocolErrorCode::ExecIdReusedInGeneration,
            Self::UnknownExecId { .. } => ProtocolErrorCode::UnknownExecId,
            Self::StreamSequenceMismatch { .. } => ProtocolErrorCode::StreamSequenceMismatch,
            Self::StreamSequenceExhausted { .. } => ProtocolErrorCode::StreamSequenceExhausted,
            Self::StreamAlreadyClosed { .. } => ProtocolErrorCode::StreamAlreadyClosed,
            Self::FlowControlCreditExhausted { .. } => {
                ProtocolErrorCode::FlowControlCreditExhausted
            }
            Self::FlowControlCreditOverflow { .. } => ProtocolErrorCode::FlowControlCreditOverflow,
            Self::InvalidDrainStream { .. } => ProtocolErrorCode::InvalidDrainStream,
            Self::StreamDrainBeforeEof { .. } => ProtocolErrorCode::StreamDrainBeforeEof,
            Self::StreamAlreadyDrained { .. } => ProtocolErrorCode::StreamAlreadyDrained,
            Self::DescendantsAlreadyCleaned { .. } => ProtocolErrorCode::DescendantsAlreadyCleaned,
            Self::DispositionAlreadySet { .. } => ProtocolErrorCode::DispositionAlreadySet,
            Self::MissingTerminalPrerequisites { .. } => {
                ProtocolErrorCode::MissingTerminalPrerequisites
            }
            Self::TerminationOutcomeConflict { .. } => {
                ProtocolErrorCode::MissingTerminalPrerequisites
            }
            Self::UnexpectedTerminationOutcomeForDisposition { .. } => {
                ProtocolErrorCode::MissingTerminalPrerequisites
            }
            Self::ChannelAuthenticationRequired => ProtocolErrorCode::ChannelAuthenticationRequired,
        };
        ProtocolErrorDetail {
            code,
            message: self.to_string(),
        }
    }
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureState {
    pub root: CanonicalHostMappingRoot,
    pub mappings: Vec<ChildMapping>,
    pub containment: MappingContainmentPolicy,
}

#[derive(Clone, Debug)]
pub struct AgentProtocolState {
    launch: Option<LaunchState>,
    cleanup_status: CleanupStatus,
    latest_generation: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct LaunchAdmissionInput {
    pub now_secs: u64,
    pub service: String,
    pub version: u32,
    pub launch: LaunchIdentity,
    pub capability_proof: CapabilityProofMaterial,
    pub build: BuildStatus,
    pub network: NetworkStatus,
    pub isolation: IsolationStatus,
    pub workload_identity: WorkloadIdentityStatus,
}

impl AgentProtocolState {
    pub fn new() -> Self {
        Self {
            launch: None,
            cleanup_status: CleanupStatus::NotRequired,
            latest_generation: None,
        }
    }

    pub fn cleanup_status(&self) -> CleanupStatus {
        self.cleanup_status
    }

    pub fn admit_launch(
        &mut self,
        input: LaunchAdmissionInput,
    ) -> Result<AgentControlMessage, StateError> {
        let LaunchAdmissionInput {
            now_secs,
            service,
            version,
            launch,
            capability_proof,
            build,
            network,
            isolation,
            workload_identity,
        } = input;

        if service != SERVICE_IDENTITY {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::UnsupportedService(service),
            ));
        }
        if version != PROTOCOL_VERSION {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::UnsupportedVersion(version),
            ));
        }
        validate_prototype_launch_contract(&isolation, &workload_identity)
            .map_err(StateError::LaunchAdmission)?;

        self.progress_cleanup_if_deadline_elapsed(now_secs);
        if let CleanupStatus::InProgress {
            generation,
            deadline_secs,
        } = self.cleanup_status
        {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::CleanupInProgress {
                    generation,
                    deadline_secs,
                    now_secs,
                },
            ));
        }

        if let Some(active) = self.launch.as_ref() {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::ActiveLaunchExists {
                    generation: active.identity.generation,
                },
            ));
        }

        if let Some(latest) = self.latest_generation
            && launch.generation <= latest
        {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::GenerationNotNewer {
                    latest_generation: latest,
                    attempted: launch.generation,
                },
            ));
        }

        self.latest_generation = Some(launch.generation);
        self.launch = Some(LaunchState::new(launch, capability_proof.to_bytes()));
        self.cleanup_status = CleanupStatus::Completed {
            generation: launch.generation,
        };
        Ok(AgentControlMessage::Ready {
            launch,
            status: ReadyStatus {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                build,
                network,
                isolation,
                workload_identity,
            },
        })
    }

    pub fn configure(
        &mut self,
        launch: LaunchIdentity,
        root: CanonicalHostMappingRoot,
        mappings: Vec<ChildMapping>,
        containment: MappingContainmentPolicy,
    ) -> Result<(), StateError> {
        let launch_state = self.launch_mut()?;
        if launch_state.identity != launch {
            return Err(StateError::LaunchGenerationConflict {
                expected: launch_state.identity,
                actual: launch,
            });
        }
        if launch_state.proof_binding.generation != launch.generation
            || launch_state.proof_binding.nonce != launch.nonce
        {
            return Err(StateError::LaunchGenerationConflict {
                expected: launch_state.identity,
                actual: launch,
            });
        }
        if launch_state.configure.is_some() {
            return Err(StateError::ConfigureAlreadyApplied);
        }
        if !launch_state.used_exec_ids.is_empty() || launch_state.active_exec.is_some() {
            return Err(StateError::ConfigureAfterExec);
        }
        validate_mapping_set(&mappings).map_err(StateError::Mapping)?;
        launch_state.configure = Some(ConfigureState {
            root,
            mappings,
            containment,
        });
        Ok(())
    }

    pub fn create_exec(&mut self, exec_id: u32) -> Result<(), StateError> {
        if let CleanupStatus::InProgress { .. } = self.cleanup_status {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::CleanupInProgress {
                    generation: self.cleanup_generation(),
                    deadline_secs: self.cleanup_deadline(),
                    now_secs: self.cleanup_deadline(),
                },
            ));
        }
        let launch_state = self.launch_mut()?;
        if launch_state.configure.is_none() {
            return Err(StateError::ConfigureRequiredForExec);
        }
        match launch_state.lifecycle {
            LaunchLifecycle::Ready => {}
            LaunchLifecycle::Quiesced => return Err(StateError::LaunchQuiesced),
            LaunchLifecycle::ShuttingDown => return Err(StateError::LaunchShuttingDown),
        }
        if let Some(active) = launch_state.active_exec {
            return Err(StateError::ActiveExecExists {
                active_exec_id: active.exec_id,
            });
        }
        if launch_state.used_exec_ids.contains(&exec_id) {
            return Err(StateError::ExecIdReusedInGeneration { exec_id });
        }
        launch_state.active_exec = Some(ExecState::new(exec_id));
        launch_state.used_exec_ids.insert(exec_id);
        Ok(())
    }

    pub fn health(&self) -> HealthStatus {
        let launch_admitted = self.launch.is_some();
        let quiesced = self
            .launch
            .as_ref()
            .is_some_and(|launch| launch.lifecycle == LaunchLifecycle::Quiesced);
        let shutting_down = self
            .launch
            .as_ref()
            .is_some_and(|launch| launch.lifecycle == LaunchLifecycle::ShuttingDown);
        let agent_state = if shutting_down {
            AgentSessionState::ShuttingDown
        } else if quiesced {
            AgentSessionState::Quiesced
        } else if launch_admitted {
            AgentSessionState::Active
        } else {
            AgentSessionState::Phase0Readiness
        };
        HealthStatus {
            agent_state,
            quiesced,
            launch_admitted,
            shutting_down,
            channel_generation: 0,
            active_exec_id: self
                .launch
                .as_ref()
                .and_then(|launch| launch.active_exec.map(|exec| exec.exec_id)),
            filesystem: None,
            network: Some(NetworkStatus {
                mode: NetworkMode::NoNic,
                setup_state: NetworkSetupState::Ready,
                interface: None,
                default_gateway: None,
                dns: DnsStatus {
                    ready: true,
                    servers: Vec::new(),
                },
                failure: None,
            }),
            last_failure: None,
        }
    }

    pub(crate) fn is_completed_exec_id(&self, exec_id: u32) -> bool {
        self.launch.as_ref().is_some_and(|launch| {
            launch.used_exec_ids.contains(&exec_id)
                && launch
                    .active_exec
                    .is_none_or(|active| active.exec_id != exec_id)
        })
    }

    pub fn quiesce(&mut self) -> Result<AgentControlMessage, StateError> {
        let launch_state = self.launch_mut()?;
        match launch_state.lifecycle {
            LaunchLifecycle::Ready => {
                if launch_state.active_exec.is_some() {
                    return Err(StateError::InvalidLifecycleTransition {
                        operation: "quiesce",
                    });
                }
                launch_state.lifecycle = LaunchLifecycle::Quiesced;
                Ok(AgentControlMessage::Quiesced)
            }
            _ => Err(StateError::InvalidLifecycleTransition {
                operation: "quiesce",
            }),
        }
    }

    pub fn resume(&mut self) -> Result<AgentControlMessage, StateError> {
        let launch_state = self.launch_mut()?;
        match launch_state.lifecycle {
            LaunchLifecycle::Quiesced => {
                launch_state.lifecycle = LaunchLifecycle::Ready;
                Ok(AgentControlMessage::Resumed)
            }
            _ => Err(StateError::InvalidLifecycleTransition {
                operation: "resume",
            }),
        }
    }

    pub fn graceful_shutdown(&mut self) -> Result<AgentControlMessage, StateError> {
        let launch_state = self.launch_mut()?;
        if launch_state.lifecycle == LaunchLifecycle::ShuttingDown {
            return Err(StateError::InvalidLifecycleTransition {
                operation: "shutdown",
            });
        }
        launch_state.lifecycle = LaunchLifecycle::ShuttingDown;
        Ok(AgentControlMessage::ShuttingDown)
    }

    pub fn apply_exec_event(
        &mut self,
        exec_id: u32,
        event: ActiveExecEvent,
    ) -> Result<Option<ExecTerminalEvent>, StateError> {
        let launch_state = self.launch_mut()?;
        let exec = launch_state
            .active_exec
            .as_mut()
            .ok_or(StateError::UnknownExecId { exec_id })?;
        if exec.exec_id != exec_id {
            return Err(StateError::UnknownExecId { exec_id });
        }
        exec.apply(event)?;

        if exec.has_required_terminal_prerequisites() && exec.can_emit_terminal() {
            exec.validate_terminal_termination_outcome()?;
            let terminal = ExecTerminalEvent {
                exec_id,
                disposition: exec
                    .disposition
                    .expect("disposition must exist when terminal is emitted"),
                termination: exec.termination_outcome,
            };
            exec.terminal_emitted = true;
            launch_state.active_exec = None;
            return Ok(Some(terminal));
        }
        Ok(None)
    }

    pub fn begin_channel_loss_cleanup(
        &mut self,
        now_secs: u64,
        cleanup_timeout: Duration,
    ) -> Result<(), StateError> {
        let launch = self
            .launch
            .take()
            .ok_or(StateError::ChannelAuthenticationRequired)?;
        let generation = launch.identity.generation;
        self.latest_generation = Some(self.latest_generation.unwrap_or(generation).max(generation));
        let cleanup_secs = cleanup_timeout
            .as_secs()
            .clamp(1, CHANNEL_LOSS_CLEANUP_DEADLINE_SECS);
        let deadline_secs = now_secs.saturating_add(cleanup_secs);
        self.cleanup_status = CleanupStatus::InProgress {
            generation,
            deadline_secs,
        };
        Ok(())
    }

    pub fn complete_channel_loss_cleanup(&mut self) {
        if let CleanupStatus::InProgress { generation, .. } = self.cleanup_status {
            self.cleanup_status = CleanupStatus::Completed { generation };
        }
    }

    fn cleanup_generation(&self) -> u64 {
        match self.cleanup_status {
            CleanupStatus::InProgress { generation, .. }
            | CleanupStatus::Completed { generation } => generation,
            CleanupStatus::NotRequired => self.latest_generation.unwrap_or(0),
        }
    }

    fn cleanup_deadline(&self) -> u64 {
        match self.cleanup_status {
            CleanupStatus::InProgress { deadline_secs, .. } => deadline_secs,
            _ => 0,
        }
    }

    fn progress_cleanup_if_deadline_elapsed(&mut self, now_secs: u64) {
        if let CleanupStatus::InProgress {
            generation,
            deadline_secs,
        } = self.cleanup_status
            && now_secs >= deadline_secs
        {
            self.cleanup_status = CleanupStatus::Completed { generation };
        }
    }

    fn launch_mut(&mut self) -> Result<&mut LaunchState, StateError> {
        self.launch
            .as_mut()
            .ok_or(StateError::ChannelAuthenticationRequired)
    }
}

fn validate_prototype_launch_contract(
    isolation: &IsolationStatus,
    workload_identity: &WorkloadIdentityStatus,
) -> Result<(), LaunchAdmissionError> {
    let mut missing = Vec::new();
    if !isolation.pid_namespace {
        missing.push(IsolationContractProperty::PidNamespace);
    }
    if !isolation.mount_namespace {
        missing.push(IsolationContractProperty::MountNamespace);
    }
    if !isolation.uts_namespace {
        missing.push(IsolationContractProperty::UtsNamespace);
    }
    if !isolation.ipc_namespace {
        missing.push(IsolationContractProperty::IpcNamespace);
    }
    if !isolation.private_proc {
        missing.push(IsolationContractProperty::PrivateProc);
    }
    if !isolation.private_dev {
        missing.push(IsolationContractProperty::PrivateDev);
    }
    if !isolation.private_devpts {
        missing.push(IsolationContractProperty::PrivateDevpts);
    }
    if !isolation.private_shm {
        missing.push(IsolationContractProperty::PrivateShm);
    }
    if !isolation.read_only_sys {
        missing.push(IsolationContractProperty::ReadOnlySys);
    }
    if !isolation.capabilities_dropped {
        missing.push(IsolationContractProperty::CapabilitiesDropped);
    }
    if !isolation.no_new_privs {
        missing.push(IsolationContractProperty::NoNewPrivs);
    }
    if !isolation.cgroup_separation {
        missing.push(IsolationContractProperty::CgroupSeparation);
    }
    if !isolation.orphan_reaping {
        missing.push(IsolationContractProperty::OrphanReaping);
    }
    if workload_identity != &WorkloadIdentityStatus::mxc_fixed() {
        missing.push(IsolationContractProperty::FixedMxcIdentity);
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LaunchAdmissionError::IsolationContractViolation { missing })
    }
}

impl Default for AgentProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchLifecycle {
    Ready,
    Quiesced,
    ShuttingDown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaunchProofBinding {
    generation: u64,
    nonce: [u8; 16],
    proof: [u8; 32],
}

#[derive(Clone, Debug)]
struct LaunchState {
    identity: LaunchIdentity,
    proof_binding: LaunchProofBinding,
    configure: Option<ConfigureState>,
    used_exec_ids: BTreeSet<u32>,
    active_exec: Option<ExecState>,
    lifecycle: LaunchLifecycle,
}

impl LaunchState {
    fn new(identity: LaunchIdentity, proof: [u8; 32]) -> Self {
        Self {
            identity,
            proof_binding: LaunchProofBinding {
                generation: identity.generation,
                nonce: identity.nonce,
                proof,
            },
            configure: None,
            used_exec_ids: BTreeSet::new(),
            active_exec: None,
            lifecycle: LaunchLifecycle::Ready,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ExecState {
    exec_id: u32,
    stdin_next_seq: u64,
    stdout_next_seq: u64,
    stderr_next_seq: u64,
    stdin_closed: bool,
    stdout_closed: bool,
    stderr_closed: bool,
    stdout_drained: bool,
    stderr_drained: bool,
    descendants_cleaned: bool,
    disposition: Option<ExecDisposition>,
    termination_outcome: Option<TerminationOutcome>,
    terminal_emitted: bool,
    stdin_window: FlowControlWindow,
    stdout_window: FlowControlWindow,
    stderr_window: FlowControlWindow,
}

impl ExecState {
    fn new(exec_id: u32) -> Self {
        Self {
            exec_id,
            stdin_next_seq: 0,
            stdout_next_seq: 0,
            stderr_next_seq: 0,
            stdin_closed: false,
            stdout_closed: false,
            stderr_closed: false,
            stdout_drained: false,
            stderr_drained: false,
            descendants_cleaned: false,
            disposition: None,
            termination_outcome: None,
            terminal_emitted: false,
            stdin_window: FlowControlWindow {
                available_credits: 0,
            },
            stdout_window: FlowControlWindow {
                available_credits: 0,
            },
            stderr_window: FlowControlWindow {
                available_credits: 0,
            },
        }
    }

    fn apply(&mut self, event: ActiveExecEvent) -> Result<(), StateError> {
        match event {
            ActiveExecEvent::AddFlowCredits { stream, credits } => {
                self.add_flow_credits(stream, credits)
            }
            ActiveExecEvent::StdinChunk { sequence } => {
                self.apply_chunk(StreamName::Stdin, sequence)
            }
            ActiveExecEvent::StdinEof { sequence } => self.apply_eof(StreamName::Stdin, sequence),
            ActiveExecEvent::StdoutChunk { sequence } => {
                self.apply_chunk(StreamName::Stdout, sequence)
            }
            ActiveExecEvent::StdoutEof { sequence } => self.apply_eof(StreamName::Stdout, sequence),
            ActiveExecEvent::StderrChunk { sequence } => {
                self.apply_chunk(StreamName::Stderr, sequence)
            }
            ActiveExecEvent::StderrEof { sequence } => self.apply_eof(StreamName::Stderr, sequence),
            ActiveExecEvent::StreamDrained { stream } => self.apply_stream_drained(stream),
            ActiveExecEvent::DescendantsCleaned => self.apply_descendants_cleaned(),
            ActiveExecEvent::Disposition(disposition) => self.apply_disposition(disposition),
            ActiveExecEvent::TerminationOutcome(termination) => {
                self.apply_termination_outcome(termination)
            }
        }
    }

    fn apply_chunk(&mut self, stream: StreamName, sequence: u64) -> Result<(), StateError> {
        self.ensure_open(stream)?;
        let next = checked_next_sequence(stream, self.next_sequence(stream), sequence)?;
        self.consume_credit(stream)?;
        self.set_next_sequence(stream, next);
        Ok(())
    }

    fn apply_eof(&mut self, stream: StreamName, sequence: u64) -> Result<(), StateError> {
        self.ensure_open(stream)?;
        let next = checked_next_sequence(stream, self.next_sequence(stream), sequence)?;
        self.set_next_sequence(stream, next);
        self.set_closed(stream);
        Ok(())
    }

    fn apply_stream_drained(&mut self, stream: StreamName) -> Result<(), StateError> {
        if stream == StreamName::Stdin {
            return Err(StateError::InvalidDrainStream {
                stream,
                exec_id: self.exec_id,
            });
        }
        if !self.is_closed(stream) {
            return Err(StateError::StreamDrainBeforeEof {
                stream,
                exec_id: self.exec_id,
            });
        }
        if self.is_drained(stream) {
            return Err(StateError::StreamAlreadyDrained {
                stream,
                exec_id: self.exec_id,
            });
        }
        self.set_drained(stream);
        Ok(())
    }

    fn apply_descendants_cleaned(&mut self) -> Result<(), StateError> {
        if self.descendants_cleaned {
            return Err(StateError::DescendantsAlreadyCleaned {
                exec_id: self.exec_id,
            });
        }
        self.descendants_cleaned = true;
        Ok(())
    }

    fn apply_disposition(&mut self, disposition: ExecDisposition) -> Result<(), StateError> {
        if let Some(current) = self.disposition {
            return Err(StateError::DispositionAlreadySet {
                exec_id: self.exec_id,
                current,
                attempted: disposition,
            });
        }
        if matches!(
            disposition,
            ExecDisposition::Cancelled | ExecDisposition::TimedOut
        ) {
            self.stdin_closed = true;
        }
        self.disposition = Some(disposition);
        Ok(())
    }

    fn apply_termination_outcome(
        &mut self,
        termination: TerminationOutcome,
    ) -> Result<(), StateError> {
        if matches!(
            self.disposition,
            Some(ExecDisposition::ExitCode(_) | ExecDisposition::Signaled(_))
        ) {
            return Err(StateError::UnexpectedTerminationOutcomeForDisposition {
                exec_id: self.exec_id,
                disposition: self
                    .disposition
                    .expect("checked above to be present for non-termination dispositions"),
                termination,
            });
        }
        if let Some(current) = self.termination_outcome {
            if current == termination {
                return Ok(());
            }
            return Err(StateError::TerminationOutcomeConflict {
                exec_id: self.exec_id,
                current,
                attempted: termination,
            });
        }
        self.termination_outcome = Some(termination);
        Ok(())
    }

    fn add_flow_credits(&mut self, stream: StreamName, credits: u32) -> Result<(), StateError> {
        let window = match stream {
            StreamName::Stdin => &mut self.stdin_window,
            StreamName::Stdout => &mut self.stdout_window,
            StreamName::Stderr => &mut self.stderr_window,
        };
        window.available_credits = window
            .available_credits
            .checked_add(credits)
            .ok_or(StateError::FlowControlCreditOverflow { stream })?;
        Ok(())
    }

    fn ensure_open(&self, stream: StreamName) -> Result<(), StateError> {
        let closed = match stream {
            StreamName::Stdin => self.stdin_closed,
            StreamName::Stdout => self.stdout_closed,
            StreamName::Stderr => self.stderr_closed,
        };
        if closed {
            return Err(StateError::StreamAlreadyClosed {
                stream,
                exec_id: self.exec_id,
            });
        }
        Ok(())
    }

    fn consume_credit(&mut self, stream: StreamName) -> Result<(), StateError> {
        let window = match stream {
            StreamName::Stdin => &mut self.stdin_window,
            StreamName::Stdout => &mut self.stdout_window,
            StreamName::Stderr => &mut self.stderr_window,
        };
        if window.available_credits == 0 {
            return Err(StateError::FlowControlCreditExhausted {
                stream,
                exec_id: self.exec_id,
            });
        }
        window.available_credits -= 1;
        Ok(())
    }

    fn next_sequence(&self, stream: StreamName) -> u64 {
        match stream {
            StreamName::Stdin => self.stdin_next_seq,
            StreamName::Stdout => self.stdout_next_seq,
            StreamName::Stderr => self.stderr_next_seq,
        }
    }

    fn set_next_sequence(&mut self, stream: StreamName, value: u64) {
        match stream {
            StreamName::Stdin => self.stdin_next_seq = value,
            StreamName::Stdout => self.stdout_next_seq = value,
            StreamName::Stderr => self.stderr_next_seq = value,
        }
    }

    fn is_closed(&self, stream: StreamName) -> bool {
        match stream {
            StreamName::Stdin => self.stdin_closed,
            StreamName::Stdout => self.stdout_closed,
            StreamName::Stderr => self.stderr_closed,
        }
    }

    fn set_closed(&mut self, stream: StreamName) {
        match stream {
            StreamName::Stdin => self.stdin_closed = true,
            StreamName::Stdout => self.stdout_closed = true,
            StreamName::Stderr => self.stderr_closed = true,
        }
    }

    fn is_drained(&self, stream: StreamName) -> bool {
        match stream {
            StreamName::Stdin => false,
            StreamName::Stdout => self.stdout_drained,
            StreamName::Stderr => self.stderr_drained,
        }
    }

    fn set_drained(&mut self, stream: StreamName) {
        match stream {
            StreamName::Stdin => {}
            StreamName::Stdout => self.stdout_drained = true,
            StreamName::Stderr => self.stderr_drained = true,
        }
    }

    fn has_required_terminal_prerequisites(&self) -> bool {
        self.stdout_closed
            && self.stderr_closed
            && self.stdout_drained
            && self.stderr_drained
            && self.descendants_cleaned
            && self.disposition.is_some()
    }

    fn can_emit_terminal(&self) -> bool {
        !self.terminal_emitted
            && self.has_required_terminal_prerequisites()
            && matches!(
                self.disposition,
                Some(ExecDisposition::Cancelled | ExecDisposition::TimedOut)
            ) == self.termination_outcome.is_some()
    }

    fn validate_terminal_termination_outcome(&self) -> Result<(), StateError> {
        let disposition = self
            .disposition
            .expect("disposition must exist when validating terminal");
        match (disposition, self.termination_outcome) {
            (ExecDisposition::Cancelled | ExecDisposition::TimedOut, Some(_)) => Ok(()),
            (ExecDisposition::Cancelled | ExecDisposition::TimedOut, None) => Ok(()),
            (ExecDisposition::ExitCode(_) | ExecDisposition::Signaled(_), None) => Ok(()),
            (ExecDisposition::ExitCode(_) | ExecDisposition::Signaled(_), Some(termination)) => {
                Err(StateError::UnexpectedTerminationOutcomeForDisposition {
                    exec_id: self.exec_id,
                    disposition,
                    termination,
                })
            }
        }
    }
}

fn checked_next_sequence(stream: StreamName, next: u64, received: u64) -> Result<u64, StateError> {
    if next != received {
        return Err(StateError::StreamSequenceMismatch {
            stream,
            expected: next,
            actual: received,
        });
    }
    next.checked_add(1)
        .ok_or(StateError::StreamSequenceExhausted {
            stream,
            last_sequence: next,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{AccessMode, RelativeChildPath, SymlinkContainmentPolicy};
    use crate::messages::NetworkMode;

    fn launch_id(generation: u64) -> LaunchIdentity {
        LaunchIdentity {
            generation,
            nonce: [generation as u8; 16],
        }
    }

    fn proof(value: u8) -> CapabilityProofMaterial {
        CapabilityProofMaterial::try_from(vec![value; 32]).expect("proof")
    }

    fn test_isolation() -> IsolationStatus {
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
        }
    }

    fn admission_input(generation: u64, now_secs: u64) -> LaunchAdmissionInput {
        LaunchAdmissionInput {
            now_secs,
            service: SERVICE_IDENTITY.to_string(),
            version: PROTOCOL_VERSION,
            launch: launch_id(generation),
            capability_proof: proof(generation as u8),
            build: BuildStatus {
                agent_version: "test".to_string(),
                kernel_release: "test".to_string(),
                profile: "debug".to_string(),
            },
            network: NetworkStatus {
                mode: NetworkMode::NoNic,
                setup_state: NetworkSetupState::Ready,
                interface: None,
                default_gateway: None,
                dns: DnsStatus {
                    ready: true,
                    servers: Vec::new(),
                },
                failure: None,
            },
            isolation: test_isolation(),
            workload_identity: WorkloadIdentityStatus::mxc_fixed(),
        }
    }

    fn configure_ready(state: &mut AgentProtocolState, generation: u64) {
        state
            .configure(
                launch_id(generation),
                CanonicalHostMappingRoot::parse("/root".to_string()).expect("root"),
                vec![ChildMapping {
                    child: RelativeChildPath::parse("workspace".to_string()).expect("path"),
                    access: AccessMode::ReadWrite,
                }],
                MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            )
            .expect("configure");
    }

    fn ready_state(generation: u64) -> AgentProtocolState {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(generation, 1))
            .expect("admit launch");
        configure_ready(&mut state, generation);
        state
    }

    #[test]
    fn launch_requires_supported_service_and_version() {
        let mut state = AgentProtocolState::new();
        let mut input = admission_input(1, 1);
        input.service = "wrong".to_string();
        assert!(matches!(
            state.admit_launch(input),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::UnsupportedService(_)
            ))
        ));

        let mut input = admission_input(1, 1);
        input.version = 99;
        assert!(matches!(
            state.admit_launch(input),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::UnsupportedVersion(_)
            ))
        ));
    }

    #[test]
    fn launch_enforces_required_isolation_contract_properties() {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(1, 1))
            .expect("fully compliant isolation launch");

        let make_input = |property: IsolationContractProperty| {
            let mut input = admission_input(2, 2);
            match property {
                IsolationContractProperty::PidNamespace => input.isolation.pid_namespace = false,
                IsolationContractProperty::MountNamespace => {
                    input.isolation.mount_namespace = false
                }
                IsolationContractProperty::UtsNamespace => input.isolation.uts_namespace = false,
                IsolationContractProperty::IpcNamespace => input.isolation.ipc_namespace = false,
                IsolationContractProperty::PrivateProc => input.isolation.private_proc = false,
                IsolationContractProperty::PrivateDev => input.isolation.private_dev = false,
                IsolationContractProperty::PrivateDevpts => input.isolation.private_devpts = false,
                IsolationContractProperty::PrivateShm => input.isolation.private_shm = false,
                IsolationContractProperty::ReadOnlySys => input.isolation.read_only_sys = false,
                IsolationContractProperty::CapabilitiesDropped => {
                    input.isolation.capabilities_dropped = false
                }
                IsolationContractProperty::NoNewPrivs => input.isolation.no_new_privs = false,
                IsolationContractProperty::CgroupSeparation => {
                    input.isolation.cgroup_separation = false
                }
                IsolationContractProperty::OrphanReaping => input.isolation.orphan_reaping = false,
                IsolationContractProperty::FixedMxcIdentity => {
                    input.workload_identity = WorkloadIdentityStatus {
                        user: "root".to_string(),
                        group: "root".to_string(),
                        uid: 0,
                        gid: 0,
                    }
                }
            }
            input
        };

        let properties = [
            IsolationContractProperty::PidNamespace,
            IsolationContractProperty::MountNamespace,
            IsolationContractProperty::UtsNamespace,
            IsolationContractProperty::IpcNamespace,
            IsolationContractProperty::PrivateProc,
            IsolationContractProperty::PrivateDev,
            IsolationContractProperty::PrivateDevpts,
            IsolationContractProperty::PrivateShm,
            IsolationContractProperty::ReadOnlySys,
            IsolationContractProperty::CapabilitiesDropped,
            IsolationContractProperty::NoNewPrivs,
            IsolationContractProperty::CgroupSeparation,
            IsolationContractProperty::OrphanReaping,
            IsolationContractProperty::FixedMxcIdentity,
        ];

        for property in properties {
            let mut per_case = AgentProtocolState::new();
            let input = make_input(property);
            let error = per_case.admit_launch(input).expect_err("must reject");
            match error {
                StateError::LaunchAdmission(LaunchAdmissionError::IsolationContractViolation {
                    missing,
                }) => {
                    assert_eq!(missing, vec![property]);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn launch_stores_capability_proof_bound_to_nonce_and_generation() {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(7, 1))
            .expect("launch admission");
        let launch = state.launch.as_ref().expect("active launch");
        assert_eq!(launch.proof_binding.generation, 7);
        assert_eq!(launch.proof_binding.nonce, [7; 16]);
        assert_eq!(launch.proof_binding.proof, [7; 32]);
    }

    #[test]
    fn active_launch_rejects_reconnect_attempts() {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(1, 1))
            .expect("first launch");
        assert!(matches!(
            state.admit_launch(admission_input(2, 2)),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::ActiveLaunchExists { .. }
            ))
        ));
    }

    #[test]
    fn stale_or_same_generation_is_rejected() {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(2, 1))
            .expect("first launch");
        state
            .begin_channel_loss_cleanup(10, Duration::from_secs(30))
            .expect("cleanup start");
        assert!(matches!(
            state.admit_launch(admission_input(2, 45)),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::GenerationNotNewer { .. }
            ))
        ));
        assert!(matches!(
            state.admit_launch(admission_input(1, 45)),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::GenerationNotNewer { .. }
            ))
        ));
    }

    #[test]
    fn cleanup_blocks_launch_until_deadline_and_then_allows_newer_generation() {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(5, 1))
            .expect("first launch");
        state
            .begin_channel_loss_cleanup(100, Duration::from_secs(30))
            .expect("cleanup start");
        assert!(matches!(
            state.admit_launch(admission_input(6, 120)),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::CleanupInProgress { .. }
            ))
        ));

        state
            .admit_launch(admission_input(6, 130))
            .expect("new generation after cleanup");
        assert_eq!(
            state.cleanup_status(),
            CleanupStatus::Completed { generation: 6 }
        );
    }

    #[test]
    fn cleanup_can_be_completed_early_after_disconnect_cleanup_finishes() {
        let mut state = AgentProtocolState::new();
        state.admit_launch(admission_input(9, 1)).expect("launch");
        state
            .begin_channel_loss_cleanup(10, Duration::from_secs(30))
            .expect("cleanup start");
        state.complete_channel_loss_cleanup();
        state
            .admit_launch(admission_input(10, 11))
            .expect("new generation after explicit cleanup completion");
    }

    #[test]
    fn configure_only_once_and_must_match_launch_identity() {
        let mut state = ready_state(1);
        assert!(matches!(
            state.configure(
                launch_id(1),
                CanonicalHostMappingRoot::parse("/root".to_string()).expect("root"),
                vec![],
                MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            ),
            Err(StateError::ConfigureAlreadyApplied)
        ));
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(3, 1))
            .expect("launch admission");
        assert!(matches!(
            state.configure(
                launch_id(4),
                CanonicalHostMappingRoot::parse("/root".to_string()).expect("root"),
                vec![],
                MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            ),
            Err(StateError::LaunchGenerationConflict { .. })
        ));
    }

    #[test]
    fn no_exec_before_configure_and_exec_id_constraints_hold() {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(admission_input(1, 1))
            .expect("launch admission");
        assert!(matches!(
            state.create_exec(1),
            Err(StateError::ConfigureRequiredForExec)
        ));
        configure_ready(&mut state, 1);
        state.create_exec(7).expect("exec create");
        assert!(matches!(
            state.create_exec(8),
            Err(StateError::ActiveExecExists { .. })
        ));
    }

    #[test]
    fn quiesce_resume_and_shutdown_transitions_are_gated() {
        let mut state = ready_state(1);
        state.quiesce().expect("quiesce");
        assert!(matches!(
            state.create_exec(1),
            Err(StateError::LaunchQuiesced)
        ));
        state.resume().expect("resume");
        state.create_exec(1).expect("exec");
        assert!(matches!(
            state.quiesce(),
            Err(StateError::InvalidLifecycleTransition { .. })
        ));
    }

    #[test]
    fn graceful_shutdown_blocks_new_execs() {
        let mut state = ready_state(2);
        state.graceful_shutdown().expect("shutdown");
        assert!(matches!(
            state.create_exec(1),
            Err(StateError::LaunchShuttingDown)
        ));
    }

    #[test]
    fn channel_loss_enters_bounded_cleanup_state() {
        let mut state = ready_state(3);
        state
            .begin_channel_loss_cleanup(10, Duration::from_secs(30))
            .expect("cleanup");
        assert!(matches!(
            state.cleanup_status(),
            CleanupStatus::InProgress {
                generation: 3,
                deadline_secs: 40
            }
        ));
        assert!(matches!(
            state.create_exec(1),
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::CleanupInProgress { .. }
            ))
        ));
    }

    #[test]
    fn flow_credits_are_required_and_distinct_per_stream() {
        let mut state = ready_state(4);
        state.create_exec(20).expect("exec");
        assert!(matches!(
            state.apply_exec_event(20, ActiveExecEvent::StdoutChunk { sequence: 0 }),
            Err(StateError::FlowControlCreditExhausted {
                stream: StreamName::Stdout,
                ..
            })
        ));
        state
            .apply_exec_event(
                20,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: 1,
                },
            )
            .expect("credit");
        state
            .apply_exec_event(20, ActiveExecEvent::StdoutChunk { sequence: 0 })
            .expect("stdout chunk");
        assert!(matches!(
            state.apply_exec_event(20, ActiveExecEvent::StderrChunk { sequence: 0 }),
            Err(StateError::FlowControlCreditExhausted {
                stream: StreamName::Stderr,
                ..
            })
        ));
    }

    #[test]
    fn sequence_mismatch_is_transactional_for_credit_and_sequence_state() {
        let mut state = ready_state(10);
        state.create_exec(26).expect("exec");
        state
            .apply_exec_event(
                26,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: 1,
                },
            )
            .expect("credit");
        assert!(matches!(
            state.apply_exec_event(26, ActiveExecEvent::StdoutChunk { sequence: 1 }),
            Err(StateError::StreamSequenceMismatch {
                stream: StreamName::Stdout,
                expected: 0,
                actual: 1
            })
        ));

        let launch = state.launch.as_ref().expect("launch");
        let exec = launch.active_exec.as_ref().expect("active exec");
        assert_eq!(exec.stdout_window.available_credits, 1);
        assert_eq!(exec.stdout_next_seq, 0);

        state
            .apply_exec_event(26, ActiveExecEvent::StdoutChunk { sequence: 0 })
            .expect("correct chunk after mismatch");
        let launch = state.launch.as_ref().expect("launch");
        let exec = launch.active_exec.as_ref().expect("active exec");
        assert_eq!(exec.stdout_window.available_credits, 0);
        assert_eq!(exec.stdout_next_seq, 1);
    }

    #[test]
    fn invalid_or_duplicate_exec_transitions_are_typed_errors() {
        let mut state = ready_state(11);
        state.create_exec(27).expect("exec");

        assert!(matches!(
            state.apply_exec_event(
                27,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdin
                }
            ),
            Err(StateError::InvalidDrainStream {
                stream: StreamName::Stdin,
                exec_id: 27
            })
        ));

        assert!(matches!(
            state.apply_exec_event(
                27,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout
                }
            ),
            Err(StateError::StreamDrainBeforeEof {
                stream: StreamName::Stdout,
                exec_id: 27
            })
        ));

        state
            .apply_exec_event(27, ActiveExecEvent::StdoutEof { sequence: 0 })
            .expect("stdout eof");
        state
            .apply_exec_event(
                27,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )
            .expect("stdout drained");
        assert!(matches!(
            state.apply_exec_event(
                27,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout
                }
            ),
            Err(StateError::StreamAlreadyDrained {
                stream: StreamName::Stdout,
                exec_id: 27
            })
        ));

        state
            .apply_exec_event(27, ActiveExecEvent::DescendantsCleaned)
            .expect("descendants cleaned");
        assert!(matches!(
            state.apply_exec_event(27, ActiveExecEvent::DescendantsCleaned),
            Err(StateError::DescendantsAlreadyCleaned { exec_id: 27 })
        ));

        state
            .apply_exec_event(
                27,
                ActiveExecEvent::Disposition(ExecDisposition::ExitCode(0)),
            )
            .expect("disposition");
        assert!(matches!(
            state.apply_exec_event(27, ActiveExecEvent::Disposition(ExecDisposition::TimedOut)),
            Err(StateError::DispositionAlreadySet {
                exec_id: 27,
                current: ExecDisposition::ExitCode(0),
                attempted: ExecDisposition::TimedOut
            })
        ));
    }

    #[test]
    fn cancellation_disposition_closes_stdin_before_terminal_prerequisites() {
        let mut state = ready_state(12);
        state.create_exec(28).expect("exec");
        state
            .apply_exec_event(
                28,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdin,
                    credits: 1,
                },
            )
            .expect("stdin credit");
        state
            .apply_exec_event(28, ActiveExecEvent::Disposition(ExecDisposition::Cancelled))
            .expect("cancelled disposition");
        state
            .apply_exec_event(
                28,
                ActiveExecEvent::TerminationOutcome(TerminationOutcome::GracefulTerm),
            )
            .expect("graceful termination outcome");

        assert!(matches!(
            state.apply_exec_event(28, ActiveExecEvent::StdinChunk { sequence: 0 }),
            Err(StateError::StreamAlreadyClosed {
                stream: StreamName::Stdin,
                exec_id: 28
            })
        ));
        let launch = state.launch.as_ref().expect("launch");
        let exec = launch.active_exec.as_ref().expect("active exec");
        assert_eq!(exec.stdin_window.available_credits, 1);

        state
            .apply_exec_event(28, ActiveExecEvent::StdoutEof { sequence: 0 })
            .expect("stdout eof");
        state
            .apply_exec_event(28, ActiveExecEvent::StderrEof { sequence: 0 })
            .expect("stderr eof");
        state
            .apply_exec_event(
                28,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )
            .expect("stdout drained");
        state
            .apply_exec_event(
                28,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stderr,
                },
            )
            .expect("stderr drained");
        let terminal = state
            .apply_exec_event(28, ActiveExecEvent::DescendantsCleaned)
            .expect("descendants cleaned")
            .expect("terminal");
        assert_eq!(terminal.disposition, ExecDisposition::Cancelled);
    }

    #[test]
    fn flow_credit_addition_uses_checked_arithmetic() {
        let mut state = ready_state(5);
        state.create_exec(21).expect("exec");
        state
            .apply_exec_event(
                21,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: u32::MAX,
                },
            )
            .expect("max credit");
        assert!(matches!(
            state.apply_exec_event(
                21,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: 1
                }
            ),
            Err(StateError::FlowControlCreditOverflow {
                stream: StreamName::Stdout
            })
        ));
    }

    #[test]
    fn sequence_gaps_and_repeated_eof_are_rejected() {
        let mut state = ready_state(6);
        state.create_exec(22).expect("exec");
        state
            .apply_exec_event(
                22,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: 2,
                },
            )
            .expect("credit");
        assert!(matches!(
            state.apply_exec_event(22, ActiveExecEvent::StdoutChunk { sequence: 1 }),
            Err(StateError::StreamSequenceMismatch {
                stream: StreamName::Stdout,
                expected: 0,
                actual: 1
            })
        ));
        state
            .apply_exec_event(22, ActiveExecEvent::StdoutChunk { sequence: 0 })
            .expect("chunk");
        state
            .apply_exec_event(22, ActiveExecEvent::StdoutEof { sequence: 1 })
            .expect("eof");
        assert!(matches!(
            state.apply_exec_event(22, ActiveExecEvent::StdoutEof { sequence: 2 }),
            Err(StateError::StreamAlreadyClosed {
                stream: StreamName::Stdout,
                ..
            })
        ));
    }

    #[test]
    fn sequence_increment_exhaustion_returns_typed_error() {
        let mut state = ready_state(7);
        state.create_exec(23).expect("exec");
        let launch = state.launch.as_mut().expect("launch");
        let exec = launch.active_exec.as_mut().expect("active exec");
        exec.stdin_next_seq = u64::MAX;
        state
            .apply_exec_event(
                23,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdin,
                    credits: 1,
                },
            )
            .expect("credit");
        assert!(matches!(
            state.apply_exec_event(23, ActiveExecEvent::StdinChunk { sequence: u64::MAX }),
            Err(StateError::StreamSequenceExhausted {
                stream: StreamName::Stdin,
                ..
            })
        ));
    }

    #[test]
    fn cancellation_and_timeout_dispositions_are_preserved() {
        let mut state = ready_state(8);
        state.create_exec(24).expect("exec");
        state
            .apply_exec_event(
                24,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: 1,
                },
            )
            .expect("credit");
        state
            .apply_exec_event(
                24,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stderr,
                    credits: 1,
                },
            )
            .expect("credit");
        state
            .apply_exec_event(24, ActiveExecEvent::StdoutEof { sequence: 0 })
            .expect("stdout eof");
        state
            .apply_exec_event(24, ActiveExecEvent::StderrEof { sequence: 0 })
            .expect("stderr eof");
        state
            .apply_exec_event(
                24,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )
            .expect("stdout drained");
        state
            .apply_exec_event(
                24,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stderr,
                },
            )
            .expect("stderr drained");
        state
            .apply_exec_event(24, ActiveExecEvent::DescendantsCleaned)
            .expect("cleaned");
        state
            .apply_exec_event(
                24,
                ActiveExecEvent::TerminationOutcome(TerminationOutcome::ForcedKill),
            )
            .expect("forced termination outcome");
        let terminal = state
            .apply_exec_event(24, ActiveExecEvent::Disposition(ExecDisposition::Cancelled))
            .expect("disposition")
            .expect("terminal");
        assert_eq!(
            terminal,
            ExecTerminalEvent {
                exec_id: 24,
                disposition: ExecDisposition::Cancelled,
                termination: Some(TerminationOutcome::ForcedKill),
            }
        );
    }

    #[test]
    fn terminal_event_waits_for_all_prerequisites_and_is_unique() {
        let mut state = ready_state(9);
        state.create_exec(25).expect("exec");
        state
            .apply_exec_event(
                25,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stdout,
                    credits: 1,
                },
            )
            .expect("credit");
        state
            .apply_exec_event(
                25,
                ActiveExecEvent::AddFlowCredits {
                    stream: StreamName::Stderr,
                    credits: 1,
                },
            )
            .expect("credit");
        state
            .apply_exec_event(25, ActiveExecEvent::Disposition(ExecDisposition::TimedOut))
            .expect("disposition");
        state
            .apply_exec_event(
                25,
                ActiveExecEvent::TerminationOutcome(TerminationOutcome::ForcedKill),
            )
            .expect("forced timeout termination outcome");
        assert!(
            state
                .apply_exec_event(25, ActiveExecEvent::StdoutEof { sequence: 0 })
                .expect("stdout eof")
                .is_none()
        );
        assert!(
            state
                .apply_exec_event(25, ActiveExecEvent::StderrEof { sequence: 0 })
                .expect("stderr eof")
                .is_none()
        );
        state
            .apply_exec_event(
                25,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )
            .expect("stdout drained");
        assert!(
            state
                .apply_exec_event(25, ActiveExecEvent::DescendantsCleaned)
                .expect("cleaned")
                .is_none()
        );
        let terminal = state
            .apply_exec_event(
                25,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stderr,
                },
            )
            .expect("stderr drained")
            .expect("terminal");
        assert!(matches!(terminal.disposition, ExecDisposition::TimedOut));
        assert!(matches!(
            state.apply_exec_event(25, ActiveExecEvent::Disposition(ExecDisposition::TimedOut)),
            Err(StateError::UnknownExecId { exec_id: 25 })
        ));
    }

    #[test]
    fn timeout_terminal_waits_until_termination_outcome_arrives() {
        let mut state = ready_state(10);
        state.create_exec(26).expect("exec");
        state
            .apply_exec_event(26, ActiveExecEvent::Disposition(ExecDisposition::TimedOut))
            .expect("disposition");
        state
            .apply_exec_event(26, ActiveExecEvent::StdoutEof { sequence: 0 })
            .expect("stdout eof");
        state
            .apply_exec_event(26, ActiveExecEvent::StderrEof { sequence: 0 })
            .expect("stderr eof");
        state
            .apply_exec_event(
                26,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )
            .expect("stdout drained");
        state
            .apply_exec_event(
                26,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stderr,
                },
            )
            .expect("stderr drained");
        let before_termination = state
            .apply_exec_event(26, ActiveExecEvent::DescendantsCleaned)
            .expect("descendants cleaned");
        assert!(before_termination.is_none());
    }

    #[test]
    fn terminal_waits_for_termination_outcome_and_emits_once() {
        let mut state = ready_state(13);
        state.create_exec(29).expect("exec");
        state
            .apply_exec_event(29, ActiveExecEvent::Disposition(ExecDisposition::TimedOut))
            .expect("disposition");
        state
            .apply_exec_event(29, ActiveExecEvent::StdoutEof { sequence: 0 })
            .expect("stdout eof");
        state
            .apply_exec_event(29, ActiveExecEvent::StderrEof { sequence: 0 })
            .expect("stderr eof");
        state
            .apply_exec_event(
                29,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stdout,
                },
            )
            .expect("stdout drained");
        state
            .apply_exec_event(
                29,
                ActiveExecEvent::StreamDrained {
                    stream: StreamName::Stderr,
                },
            )
            .expect("stderr drained");
        let before_termination = state
            .apply_exec_event(29, ActiveExecEvent::DescendantsCleaned)
            .expect("descendants cleaned");
        assert!(before_termination.is_none());

        let terminal = state
            .apply_exec_event(
                29,
                ActiveExecEvent::TerminationOutcome(TerminationOutcome::ForcedKill),
            )
            .expect("termination outcome")
            .expect("terminal");
        assert_eq!(
            terminal,
            ExecTerminalEvent {
                exec_id: 29,
                disposition: ExecDisposition::TimedOut,
                termination: Some(TerminationOutcome::ForcedKill),
            }
        );
        assert!(matches!(
            state.apply_exec_event(
                29,
                ActiveExecEvent::TerminationOutcome(TerminationOutcome::ForcedKill)
            ),
            Err(StateError::UnknownExecId { exec_id: 29 })
        ));
    }

    #[test]
    fn non_terminated_exit_rejects_termination_outcome_metadata() {
        let mut state = ready_state(11);
        state.create_exec(27).expect("exec");
        state
            .apply_exec_event(
                27,
                ActiveExecEvent::Disposition(ExecDisposition::ExitCode(0)),
            )
            .expect("disposition");
        let error = state
            .apply_exec_event(
                27,
                ActiveExecEvent::TerminationOutcome(TerminationOutcome::ForcedKill),
            )
            .expect_err("normal exit must not carry termination metadata");
        assert!(matches!(
            error,
            StateError::UnexpectedTerminationOutcomeForDisposition {
                exec_id: 27,
                disposition: ExecDisposition::ExitCode(0),
                termination: TerminationOutcome::ForcedKill
            }
        ));
    }

    #[test]
    fn protocol_error_mapping_covers_new_state_errors() {
        let detail = StateError::FlowControlCreditExhausted {
            stream: StreamName::Stdout,
            exec_id: 1,
        }
        .to_protocol_error_detail();
        assert_eq!(detail.code, ProtocolErrorCode::FlowControlCreditExhausted);

        let detail = StateError::ConfigureRequiredForExec.to_protocol_error_detail();
        assert_eq!(detail.code, ProtocolErrorCode::ConfigureRequiredForExec);
    }
}
