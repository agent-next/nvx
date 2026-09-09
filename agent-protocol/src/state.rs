// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::BTreeSet;

use crate::mapping::{
    CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy, MappingError,
    validate_mapping_set,
};
use crate::messages::{
    AgentControlMessage, BuildStatus, HealthStatus, IsolationStatus, LaunchIdentity, NetworkStatus,
    ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, StreamName,
    WorkloadIdentityStatus,
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const CHANNEL_LOSS_CLEANUP_DEADLINE_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowControlWindow {
    pub available_credits: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecDisposition {
    ExitCode(i32),
    Signaled(i32),
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecTerminalEvent {
    pub exec_id: u32,
    pub disposition: ExecDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveExecEvent {
    StdinFrame { sequence: u64 },
    StdinEof { sequence: u64 },
    StdoutFrame { sequence: u64 },
    StdoutEof { sequence: u64 },
    StderrFrame { sequence: u64 },
    StderrEof { sequence: u64 },
    StreamsDrained,
    DescendantsCleaned,
    Disposition(ExecDisposition),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStatus {
    NotRequired,
    InProgress { deadline_secs: u64 },
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchAdmissionError {
    CleanupInProgress { deadline_secs: u64, now_secs: u64 },
    UnsupportedService(String),
    UnsupportedVersion(u32),
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
    StreamAlreadyClosed {
        stream: StreamName,
        exec_id: u32,
    },
    MissingTerminalPrerequisites {
        exec_id: u32,
    },
    ChannelAuthenticationRequired,
}

impl StateError {
    pub fn to_protocol_error_detail(&self) -> ProtocolErrorDetail {
        let code = match self {
            Self::LaunchAdmission(LaunchAdmissionError::CleanupInProgress { .. }) => {
                ProtocolErrorCode::CleanupInProgress
            }
            Self::LaunchAdmission(LaunchAdmissionError::UnsupportedService(_)) => {
                ProtocolErrorCode::UnsupportedService
            }
            Self::LaunchAdmission(LaunchAdmissionError::UnsupportedVersion(_)) => {
                ProtocolErrorCode::UnsupportedProtocolVersion
            }
            Self::LaunchGenerationConflict { .. } => ProtocolErrorCode::LaunchGenerationConflict,
            Self::ConfigureAlreadyApplied => ProtocolErrorCode::ConfigureAlreadyApplied,
            Self::ConfigureAfterExec => ProtocolErrorCode::ConfigureAfterExec,
            Self::Mapping(MappingError::OverlapConflict { .. }) => {
                ProtocolErrorCode::MappingConflict
            }
            Self::Mapping(_) => ProtocolErrorCode::InvalidMappingPath,
            Self::ActiveExecExists { .. } => ProtocolErrorCode::ActiveExecExists,
            Self::ExecIdReusedInGeneration { .. } => ProtocolErrorCode::ExecIdReusedInGeneration,
            Self::UnknownExecId { .. } => ProtocolErrorCode::UnknownExecId,
            Self::StreamSequenceMismatch { .. } => ProtocolErrorCode::StreamSequenceMismatch,
            Self::StreamAlreadyClosed { .. } => ProtocolErrorCode::StreamAlreadyClosed,
            Self::MissingTerminalPrerequisites { .. } => {
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
}

#[derive(Clone, Debug)]
pub struct LaunchAdmissionInput {
    pub now_secs: u64,
    pub service: String,
    pub version: u32,
    pub launch: LaunchIdentity,
    pub build: BuildStatus,
    pub network: NetworkStatus,
    pub isolation: IsolationStatus,
}

impl AgentProtocolState {
    pub fn new() -> Self {
        Self {
            launch: None,
            cleanup_status: CleanupStatus::NotRequired,
        }
    }

    pub fn admit_launch(
        &mut self,
        input: LaunchAdmissionInput,
    ) -> Result<AgentControlMessage, StateError> {
        if input.service != SERVICE_IDENTITY {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::UnsupportedService(input.service),
            ));
        }
        if input.version != PROTOCOL_VERSION {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::UnsupportedVersion(input.version),
            ));
        }
        if let CleanupStatus::InProgress { deadline_secs } = self.cleanup_status
            && input.now_secs <= deadline_secs
        {
            return Err(StateError::LaunchAdmission(
                LaunchAdmissionError::CleanupInProgress {
                    deadline_secs,
                    now_secs: input.now_secs,
                },
            ));
        }

        self.launch = Some(LaunchState::new(input.launch));
        self.cleanup_status = CleanupStatus::Completed;
        Ok(AgentControlMessage::Ready {
            launch: input.launch,
            status: ReadyStatus {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                build: input.build,
                network: input.network,
                isolation: input.isolation,
                workload_identity: WorkloadIdentityStatus::mxc_fixed(),
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
        let launch_state = self.launch_mut()?;
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
        let quiesced = self.launch.as_ref().is_some_and(|launch| launch.quiesced);
        HealthStatus {
            quiesced,
            launch_admitted,
        }
    }

    pub fn quiesce(&mut self) -> Result<AgentControlMessage, StateError> {
        let launch_state = self.launch_mut()?;
        launch_state.quiesced = true;
        Ok(AgentControlMessage::Quiesced)
    }

    pub fn resume(&mut self) -> Result<AgentControlMessage, StateError> {
        let launch_state = self.launch_mut()?;
        launch_state.quiesced = false;
        Ok(AgentControlMessage::Resumed)
    }

    pub fn graceful_shutdown(&mut self) -> Result<AgentControlMessage, StateError> {
        let launch_state = self.launch_mut()?;
        launch_state.shutting_down = true;
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

        if exec.can_emit_terminal() {
            let terminal = ExecTerminalEvent {
                exec_id,
                disposition: exec
                    .disposition
                    .expect("disposition must exist when terminal is emitted"),
            };
            exec.terminal_emitted = true;
            launch_state.active_exec = None;
            return Ok(Some(terminal));
        }
        Ok(None)
    }

    pub fn begin_channel_loss_cleanup(&mut self, now_secs: u64) -> Result<(), StateError> {
        if self.launch.is_none() {
            return Err(StateError::ChannelAuthenticationRequired);
        }
        self.cleanup_status = CleanupStatus::InProgress {
            deadline_secs: now_secs.saturating_add(CHANNEL_LOSS_CLEANUP_DEADLINE_SECS),
        };
        self.launch = None;
        Ok(())
    }

    fn launch_mut(&mut self) -> Result<&mut LaunchState, StateError> {
        self.launch
            .as_mut()
            .ok_or(StateError::ChannelAuthenticationRequired)
    }
}

impl Default for AgentProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
struct LaunchState {
    identity: LaunchIdentity,
    configure: Option<ConfigureState>,
    used_exec_ids: BTreeSet<u32>,
    active_exec: Option<ExecState>,
    quiesced: bool,
    shutting_down: bool,
}

impl LaunchState {
    fn new(identity: LaunchIdentity) -> Self {
        Self {
            identity,
            configure: None,
            used_exec_ids: BTreeSet::new(),
            active_exec: None,
            quiesced: false,
            shutting_down: false,
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
    streams_drained: bool,
    descendants_cleaned: bool,
    disposition: Option<ExecDisposition>,
    terminal_emitted: bool,
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
            streams_drained: false,
            descendants_cleaned: false,
            disposition: None,
            terminal_emitted: false,
        }
    }

    fn apply(&mut self, event: ActiveExecEvent) -> Result<(), StateError> {
        match event {
            ActiveExecEvent::StdinFrame { sequence } => {
                if self.stdin_closed {
                    return Err(StateError::StreamAlreadyClosed {
                        stream: StreamName::Stdin,
                        exec_id: self.exec_id,
                    });
                }
                expect_sequence(StreamName::Stdin, &mut self.stdin_next_seq, sequence)
            }
            ActiveExecEvent::StdinEof { sequence } => {
                if self.stdin_closed {
                    return Err(StateError::StreamAlreadyClosed {
                        stream: StreamName::Stdin,
                        exec_id: self.exec_id,
                    });
                }
                expect_sequence(StreamName::Stdin, &mut self.stdin_next_seq, sequence)?;
                self.stdin_closed = true;
                Ok(())
            }
            ActiveExecEvent::StdoutFrame { sequence } => {
                if self.stdout_closed {
                    return Err(StateError::StreamAlreadyClosed {
                        stream: StreamName::Stdout,
                        exec_id: self.exec_id,
                    });
                }
                expect_sequence(StreamName::Stdout, &mut self.stdout_next_seq, sequence)
            }
            ActiveExecEvent::StdoutEof { sequence } => {
                if self.stdout_closed {
                    return Err(StateError::StreamAlreadyClosed {
                        stream: StreamName::Stdout,
                        exec_id: self.exec_id,
                    });
                }
                expect_sequence(StreamName::Stdout, &mut self.stdout_next_seq, sequence)?;
                self.stdout_closed = true;
                Ok(())
            }
            ActiveExecEvent::StderrFrame { sequence } => {
                if self.stderr_closed {
                    return Err(StateError::StreamAlreadyClosed {
                        stream: StreamName::Stderr,
                        exec_id: self.exec_id,
                    });
                }
                expect_sequence(StreamName::Stderr, &mut self.stderr_next_seq, sequence)
            }
            ActiveExecEvent::StderrEof { sequence } => {
                if self.stderr_closed {
                    return Err(StateError::StreamAlreadyClosed {
                        stream: StreamName::Stderr,
                        exec_id: self.exec_id,
                    });
                }
                expect_sequence(StreamName::Stderr, &mut self.stderr_next_seq, sequence)?;
                self.stderr_closed = true;
                Ok(())
            }
            ActiveExecEvent::StreamsDrained => {
                self.streams_drained = true;
                Ok(())
            }
            ActiveExecEvent::DescendantsCleaned => {
                self.descendants_cleaned = true;
                Ok(())
            }
            ActiveExecEvent::Disposition(disposition) => {
                self.disposition = Some(disposition);
                Ok(())
            }
        }
    }

    fn can_emit_terminal(&self) -> bool {
        !self.terminal_emitted
            && self.stdout_closed
            && self.stderr_closed
            && self.streams_drained
            && self.descendants_cleaned
            && self.disposition.is_some()
    }
}

fn expect_sequence(stream: StreamName, next: &mut u64, received: u64) -> Result<(), StateError> {
    if *next != received {
        return Err(StateError::StreamSequenceMismatch {
            stream,
            expected: *next,
            actual: received,
        });
    }
    *next = next.saturating_add(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{AccessMode, RelativeChildPath, SymlinkContainmentPolicy};
    use crate::messages::NetworkMode;

    fn launch_id() -> LaunchIdentity {
        LaunchIdentity {
            generation: 1,
            nonce: [1; 16],
        }
    }

    fn ready_state() -> AgentProtocolState {
        let mut state = AgentProtocolState::new();
        state
            .admit_launch(LaunchAdmissionInput {
                now_secs: 1,
                service: SERVICE_IDENTITY.to_string(),
                version: PROTOCOL_VERSION,
                launch: launch_id(),
                build: BuildStatus {
                    agent_version: "test".to_string(),
                    kernel_release: "test".to_string(),
                    profile: "debug".to_string(),
                },
                network: NetworkStatus {
                    mode: NetworkMode::NoNic,
                    detail: None,
                },
                isolation: IsolationStatus {
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
            })
            .expect("admit launch");
        state
            .configure(
                launch_id(),
                CanonicalHostMappingRoot("/root".to_string()),
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
        state
    }

    #[test]
    fn configure_only_once() {
        let mut state = ready_state();
        let second = state.configure(
            launch_id(),
            CanonicalHostMappingRoot("/root".to_string()),
            vec![],
            MappingContainmentPolicy {
                symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            },
        );
        assert!(matches!(second, Err(StateError::ConfigureAlreadyApplied)));
    }

    #[test]
    fn one_active_exec_and_terminal_ordering() {
        let mut state = ready_state();
        state.create_exec(7).expect("start");
        assert!(matches!(
            state.create_exec(8),
            Err(StateError::ActiveExecExists { .. })
        ));
        assert!(
            state
                .apply_exec_event(7, ActiveExecEvent::Disposition(ExecDisposition::TimedOut))
                .expect("event")
                .is_none()
        );
        assert!(
            state
                .apply_exec_event(7, ActiveExecEvent::StdoutEof { sequence: 0 })
                .expect("event")
                .is_none()
        );
        assert!(
            state
                .apply_exec_event(7, ActiveExecEvent::StderrEof { sequence: 0 })
                .expect("event")
                .is_none()
        );
        assert!(
            state
                .apply_exec_event(7, ActiveExecEvent::StreamsDrained)
                .expect("event")
                .is_none()
        );
        let terminal = state
            .apply_exec_event(7, ActiveExecEvent::DescendantsCleaned)
            .expect("event")
            .expect("terminal");
        assert_eq!(terminal.exec_id, 7);
        assert!(matches!(terminal.disposition, ExecDisposition::TimedOut));
    }

    #[test]
    fn cleanup_blocks_new_generation_until_deadline() {
        let mut state = ready_state();
        state.begin_channel_loss_cleanup(10).expect("cleanup");
        let blocked = state.admit_launch(LaunchAdmissionInput {
            now_secs: 20,
            service: SERVICE_IDENTITY.to_string(),
            version: PROTOCOL_VERSION,
            launch: launch_id(),
            build: BuildStatus {
                agent_version: "test".to_string(),
                kernel_release: "test".to_string(),
                profile: "debug".to_string(),
            },
            network: NetworkStatus {
                mode: NetworkMode::NoNic,
                detail: None,
            },
            isolation: IsolationStatus {
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
        });
        assert!(matches!(
            blocked,
            Err(StateError::LaunchAdmission(
                LaunchAdmissionError::CleanupInProgress { .. }
            ))
        ));
    }
}
