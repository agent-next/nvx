use ::std::collections::BTreeMap;
use ::std::process::ExitCode;
#[cfg(target_os = "linux")]
use ::std::thread;
#[cfg(target_os = "linux")]
use ::std::time::{Duration, Instant};

use ::agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
#[cfg(target_os = "linux")]
use ::agent_protocol::messages::{AgentControlMessage, ExecDisposition};
#[cfg(target_os = "linux")]
use ::agent_protocol::messages::{FlowCreditRequest, StreamName};
use ::agent_protocol::messages::{LaunchIdentity, NetworkMode, NetworkStatus, SERVICE_IDENTITY};
use ::agent_protocol::mxc_extension::{
    AciAdapterStatus, MODELED_REQUIREMENTS, MxcRequirement, UnsupportedAciAdapter,
};
#[cfg(target_os = "linux")]
use ::agent_protocol::service::ProcessSupervisor;
use ::agent_protocol::service::{
    AuthenticateChannelRequest, ConfigureSessionRequest, FilesystemStatus, LaunchBinding,
    MxcControlService, ServiceErrorCode, SessionConfiguration, WaitReadyRequest,
};
#[cfg(target_os = "linux")]
use ::agent_protocol::service::{
    CancelReason, CreateProcessRequest, ServiceError, SupervisorEvent,
};
use ::agent_protocol::state::PROTOCOL_VERSION;
#[cfg(target_os = "linux")]
use ::nvx_agent::LinuxProcessSupervisor;
use ::serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementStatus {
    Pass,
    Fail,
    Blocked,
    NotImplemented,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequirementResult {
    pub name: String,
    pub requirement: MxcRequirement,
    pub status: RequirementStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceReadiness {
    Ready,
    NotReady,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterState {
    pub kind: String,
    pub status: RequirementStatus,
    pub required_revision: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessReport {
    pub phase: String,
    pub service_readiness: ServiceReadiness,
    pub adapter: AdapterState,
    pub requirements: Vec<RequirementResult>,
}

fn launch_identity() -> LaunchIdentity {
    LaunchIdentity {
        generation: 7,
        nonce: [7; 16],
    }
}

fn launch_binding() -> LaunchBinding {
    LaunchBinding {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
    }
}

fn session_configuration() -> SessionConfiguration {
    SessionConfiguration {
        root: CanonicalHostMappingRoot::parse("/sandbox".to_string()).expect("root"),
        mappings: vec![ChildMapping {
            child: RelativeChildPath::parse("runtime".to_string()).expect("child"),
            access: AccessMode::ReadOnly,
        }],
        containment: MappingContainmentPolicy {
            symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        },
        labels: vec!["runtime".to_string()],
        attributes: BTreeMap::from([("profile".to_string(), "mxc".to_string())]),
        filesystem: FilesystemStatus {
            rootfs_ready: true,
            detail: "sandbox layers mounted".to_string(),
        },
        network: NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some("10.0.0.2/24".to_string()),
        },
    }
}

fn wait_ready_request() -> WaitReadyRequest {
    WaitReadyRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
    }
}

fn configure_request(idempotent_replay: bool) -> ConfigureSessionRequest {
    ConfigureSessionRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
        idempotent_replay,
        configuration: session_configuration(),
    }
}

fn authenticate(service: &mut MxcControlService) {
    service
        .authenticate_channel(
            AuthenticateChannelRequest {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: launch_identity(),
                channel_generation: 44,
                capability_proof: [7; 32],
            },
            1,
            session_configuration().network.clone(),
        )
        .expect("authenticate");
}

fn run_launch_bound_readiness() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    let capabilities = service.get_capabilities();
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");

    let wrong_nonce = WaitReadyRequest {
        launch: LaunchIdentity {
            generation: 7,
            nonce: [1; 16],
        },
        ..wait_ready_request()
    };
    let wrong_nonce_rejected = matches!(
        service.wait_ready(wrong_nonce).map(|_| ()),
        Err(error) if error.code == ServiceErrorCode::LaunchNonceMismatch
    );
    let first = service.wait_ready(wait_ready_request());
    let second = service.wait_ready(wait_ready_request());
    let health = service.health();
    let unavailable_operations = capabilities
        .unavailable_operations
        .iter()
        .map(|entry| entry.operation.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let passed = wrong_nonce_rejected
        && capabilities.protocol_version == PROTOCOL_VERSION
        && capabilities.available_operations
            == vec![
                "GetCapabilities".to_string(),
                "AuthenticateChannel".to_string(),
                "ConfigureSession".to_string(),
                "WaitReady".to_string(),
                "Health".to_string(),
            ]
        && unavailable_operations
            == std::collections::BTreeSet::from([
                "Exec", "Streams", "Cancel", "Quiesce", "Resume", "Shutdown",
            ])
        && capabilities
            .unavailable_operations
            .iter()
            .all(|entry| !entry.capability_flag.is_empty() && !entry.reason.is_empty())
        && first.is_ok()
        && second.is_ok()
        && first == second
        && health.configured
        && health
            .filesystem
            .as_ref()
            .is_some_and(|status| status.rootfs_ready);
    RequirementResult {
        name: MxcRequirement::Ready.name().to_string(),
        requirement: MxcRequirement::Ready,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "WaitReady is launch-bound to nonce/version/channel generation and GetCapabilities truthfully reports the phase-0 operational slice.".to_string()
        } else {
            "WaitReady launch binding, level-trigger behavior, or capability truthfulness failed."
                .to_string()
        },
    }
}

fn run_immutable_configuration() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("first configure");
    let same_without_idempotent = service.configure_session(configure_request(false));
    let same_with_idempotent = service.configure_session(configure_request(true));
    let mut conflicting_request = configure_request(true);
    conflicting_request.configuration.filesystem.detail = "changed".to_string();
    let conflicting = service.configure_session(conflicting_request);
    let passed = matches!(
        same_without_idempotent.map(|_| ()),
        Err(error) if error.code == ServiceErrorCode::ConfigurationConflict
    ) && same_with_idempotent.is_ok()
        && matches!(
            conflicting.map(|_| ()),
            Err(error) if error.code == ServiceErrorCode::ConfigurationConflict
        );
    RequirementResult {
        name: MxcRequirement::Bootstrap.name().to_string(),
        requirement: MxcRequirement::Bootstrap,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "ConfigureSession applies once; non-idempotent replay/conflict is rejected.".to_string()
        } else {
            "Immutable ConfigureSession rules failed.".to_string()
        },
    }
}

fn run_health_probe() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    let before = service.health();
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");
    let after = service.health();
    let passed = !before.launch_admitted
        && !before.configured
        && after.launch_admitted
        && after.configured
        && after.network.is_some()
        && after.filesystem.is_some();
    RequirementResult {
        name: MxcRequirement::Probe.name().to_string(),
        requirement: MxcRequirement::Probe,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Health reports launch admission plus filesystem/network readiness snapshots."
                .to_string()
        } else {
            "Health readiness snapshot behavior failed.".to_string()
        },
    }
}

#[cfg(target_os = "linux")]
fn activated_service() -> MxcControlService {
    let mut service = MxcControlService::new_pid1_runtime(launch_binding(), 4242);
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");
    service.activate_full_lifecycle().expect("activate");
    service
}

#[cfg(target_os = "linux")]
struct ExecObservation {
    messages: Vec<AgentControlMessage>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    terminals: Vec<(usize, ExecDisposition)>,
    stdout_eof: Option<usize>,
    stderr_eof: Option<usize>,
    descendants_cleaned: Option<usize>,
    max_chunk_bytes: usize,
}

#[cfg(not(target_os = "linux"))]
fn blocked_requirement(requirement: MxcRequirement, reason: &str) -> RequirementResult {
    RequirementResult {
        name: requirement.name().to_string(),
        requirement,
        status: RequirementStatus::Blocked,
        reason: reason.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn collect_until_exec_finishes(
    service: &mut MxcControlService,
    supervisor: &mut LinuxProcessSupervisor,
    timeout: Duration,
) -> Result<ExecObservation, String> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "timeout overflow".to_string())?;
    let mut observation = ExecObservation {
        messages: Vec::new(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        terminals: Vec::new(),
        stdout_eof: None,
        stderr_eof: None,
        descendants_cleaned: None,
        max_chunk_bytes: 0,
    };

    while Instant::now() < deadline {
        let batch = service
            .pump_supervisor(supervisor)
            .map_err(|error| format!("pumping supervisor failed: {error}"))?;
        if !batch.is_empty() {
            for message in batch {
                let index = observation.messages.len();
                match &message {
                    AgentControlMessage::StdoutChunk(record) => {
                        observation.max_chunk_bytes =
                            observation.max_chunk_bytes.max(record.chunk.len());
                        observation.stdout.extend_from_slice(&record.chunk);
                    }
                    AgentControlMessage::StderrChunk(record) => {
                        observation.max_chunk_bytes =
                            observation.max_chunk_bytes.max(record.chunk.len());
                        observation.stderr.extend_from_slice(&record.chunk);
                    }
                    AgentControlMessage::StdoutEof(_) => observation.stdout_eof = Some(index),
                    AgentControlMessage::StderrEof(_) => observation.stderr_eof = Some(index),
                    AgentControlMessage::DescendantsCleaned { .. } => {
                        observation.descendants_cleaned = Some(index)
                    }
                    AgentControlMessage::ExecTerminal { disposition, .. } => {
                        observation.terminals.push((index, *disposition))
                    }
                    _ => {}
                }
                observation.messages.push(message);
            }
        }
        if service.active_exec_id().is_none() {
            return Ok(observation);
        }
        thread::sleep(Duration::from_millis(10));
    }

    if let Some(exec_id) = service.active_exec_id() {
        let _ = service.cancel_exec(exec_id, CancelReason::Cancelled, supervisor);
        let _ = supervisor.cleanup_for_disconnect(exec_id, Duration::from_secs(1));
    }
    Err("execution did not reach terminal state before timeout".to_string())
}

#[cfg(target_os = "linux")]
fn spawn_exec(
    service: &mut MxcControlService,
    supervisor: &mut LinuxProcessSupervisor,
    exec_id: u32,
    argv: Vec<String>,
    timeout_ms: Option<u64>,
) -> Result<(), String> {
    service
        .create_process(
            CreateProcessRequest {
                exec_id,
                argv,
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms,
            },
            supervisor,
        )
        .map_err(|error| format!("create_process failed for exec {exec_id}: {error}"))
}

#[cfg(target_os = "linux")]
fn grant_output_credits(
    service: &mut MxcControlService,
    exec_id: u32,
    credits: u32,
) -> Result<(), String> {
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id,
            stream: StreamName::Stdout,
            credits,
        })
        .map_err(|error| format!("stdout credits failed for exec {exec_id}: {error}"))?;
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id,
            stream: StreamName::Stderr,
            credits,
        })
        .map_err(|error| format!("stderr credits failed for exec {exec_id}: {error}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn terminal_after_eof_and_cleanup(observation: &ExecObservation) -> bool {
    if observation.terminals.len() != 1 {
        return false;
    }
    let terminal_index = observation.terminals[0].0;
    observation
        .stdout_eof
        .is_some_and(|index| index < terminal_index)
        && observation
            .stderr_eof
            .is_some_and(|index| index < terminal_index)
        && observation
            .descendants_cleaned
            .is_some_and(|index| index < terminal_index)
}

#[cfg(target_os = "linux")]
fn run_exec_sequencing() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let mut outcomes = Vec::new();
    let mut saw_busy_rejection = false;

    for (exec_id, exit_code) in [(300_u32, 10), (301_u32, 11), (302_u32, 12)] {
        let argv = if exec_id == 300 {
            vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                format!("sleep 0.2; exit {exit_code}"),
            ]
        } else {
            vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                format!("exit {exit_code}"),
            ]
        };
        if let Err(error) = spawn_exec(&mut service, &mut supervisor, exec_id, argv, None) {
            return RequirementResult {
                name: MxcRequirement::ExecuteCommand.name().to_string(),
                requirement: MxcRequirement::ExecuteCommand,
                status: RequirementStatus::Fail,
                reason: error,
            };
        }
        if let Err(error) = grant_output_credits(&mut service, exec_id, 8) {
            return RequirementResult {
                name: MxcRequirement::ExecuteCommand.name().to_string(),
                requirement: MxcRequirement::ExecuteCommand,
                status: RequirementStatus::Fail,
                reason: error,
            };
        }
        if exec_id == 300 {
            let busy = service.create_process(
                CreateProcessRequest {
                    exec_id: 399,
                    argv: vec!["/bin/true".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            );
            saw_busy_rejection = matches!(
                busy,
                Err(ServiceError {
                    code: ServiceErrorCode::WorkloadBusy,
                    ..
                })
            );
        }
        let observation = match collect_until_exec_finishes(
            &mut service,
            &mut supervisor,
            Duration::from_secs(5),
        ) {
            Ok(observation) => observation,
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::ExecuteCommand.name().to_string(),
                    requirement: MxcRequirement::ExecuteCommand,
                    status: RequirementStatus::Fail,
                    reason: error,
                };
            }
        };
        outcomes.push(
            observation
                .terminals
                .first()
                .map(|(_, disposition)| *disposition),
        );
    }

    let passed = saw_busy_rejection
        && outcomes
            == vec![
                Some(ExecDisposition::ExitCode(10)),
                Some(ExecDisposition::ExitCode(11)),
                Some(ExecDisposition::ExitCode(12)),
            ];
    RequirementResult {
        name: MxcRequirement::ExecuteCommand.name().to_string(),
        requirement: MxcRequirement::ExecuteCommand,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Three real subprocesses ran sequentially in one supervisor/session and an overlapping create received typed WorkloadBusy.".to_string()
        } else {
            "Sequential execution outcomes or typed busy rejection did not match contract."
                .to_string()
        },
    }
}

#[cfg(target_os = "linux")]
fn run_binary_stream_separation() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let exec_id = 401_u32;
    if let Err(error) = spawn_exec(
        &mut service,
        &mut supervisor,
        exec_id,
        vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "printf 'A\\000B\\377C'; printf 'X\\000Y\\376Z' 1>&2".to_string(),
        ],
        None,
    ) {
        return RequirementResult {
            name: MxcRequirement::InteractiveShell.name().to_string(),
            requirement: MxcRequirement::InteractiveShell,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = grant_output_credits(&mut service, exec_id, 8) {
        return RequirementResult {
            name: MxcRequirement::InteractiveShell.name().to_string(),
            requirement: MxcRequirement::InteractiveShell,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }

    let observation =
        match collect_until_exec_finishes(&mut service, &mut supervisor, Duration::from_secs(5)) {
            Ok(observation) => observation,
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::InteractiveShell.name().to_string(),
                    requirement: MxcRequirement::InteractiveShell,
                    status: RequirementStatus::Fail,
                    reason: error,
                };
            }
        };
    let expected_stdout = vec![b'A', 0, b'B', 255, b'C'];
    let expected_stderr = vec![b'X', 0, b'Y', 254, b'Z'];
    let passed = observation.stdout == expected_stdout && observation.stderr == expected_stderr;
    RequirementResult {
        name: MxcRequirement::InteractiveShell.name().to_string(),
        requirement: MxcRequirement::InteractiveShell,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Real subprocess output preserved exact stdout/stderr separation including arbitrary bytes and NUL.".to_string()
        } else {
            "Real stdout/stderr bytes diverged from expected binary-safe separation.".to_string()
        },
    }
}

#[cfg(target_os = "linux")]
fn run_backpressure_contract() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let exec_id = 501_u32;
    if let Err(error) = spawn_exec(
        &mut service,
        &mut supervisor,
        exec_id,
        vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "i=0; while [ $i -lt 20000 ]; do printf '0123456789abcdef0123456789abcdef'; i=$((i+1)); done".to_string(),
        ],
        None,
    ) {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = service.grant_flow_credits(FlowCreditRequest {
        exec_id,
        stream: StreamName::Stderr,
        credits: 64,
    }) {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: format!("stderr credits failed for high-output scenario: {error}"),
        };
    }
    let mut max_chunk_bytes = 0usize;
    let pressure_deadline = Instant::now() + Duration::from_secs(3);
    let mut credit_backpressured = false;
    while Instant::now() < pressure_deadline {
        match service.pump_supervisor(&mut supervisor) {
            Ok(messages) => {
                for message in messages {
                    match message {
                        AgentControlMessage::StdoutChunk(record) => {
                            max_chunk_bytes = max_chunk_bytes.max(record.chunk.len());
                        }
                        AgentControlMessage::StderrChunk(record) => {
                            max_chunk_bytes = max_chunk_bytes.max(record.chunk.len());
                        }
                        _ => {}
                    }
                }
            }
            Err(ServiceError {
                code: ServiceErrorCode::LifecycleError,
                message,
            }) if message.contains("FlowControlCreditExhausted") => {
                if let Some(active_exec_id) = service.active_exec_id() {
                    match supervisor.peek_event(active_exec_id) {
                        Ok(Some(SupervisorEvent::StdoutChunk(chunk)))
                        | Ok(Some(SupervisorEvent::StderrChunk(chunk))) => {
                            max_chunk_bytes = max_chunk_bytes.max(chunk.len());
                        }
                        _ => {}
                    }
                }
                credit_backpressured = true;
                break;
            }
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::StreamLogs.name().to_string(),
                    requirement: MxcRequirement::StreamLogs,
                    status: RequirementStatus::Fail,
                    reason: format!("high-output pump failed: {error}"),
                };
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    let health_responsive_during_credit_pressure = service.health().configured;
    if let Some(active_exec_id) = service.active_exec_id() {
        let _ = service.cancel_exec(active_exec_id, CancelReason::Cancelled, &mut supervisor);
        let cleanup_deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < cleanup_deadline {
            match service.pump_supervisor(&mut supervisor) {
                Ok(_) => {
                    if service.active_exec_id().is_none() {
                        break;
                    }
                }
                Err(error) if error.code == ServiceErrorCode::Supervisor => break,
                Err(_) => break,
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let stdin_exec_id = 502_u32;
    if let Err(error) = spawn_exec(
        &mut service,
        &mut supervisor,
        stdin_exec_id,
        vec!["/bin/cat".to_string()],
        None,
    ) {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = grant_output_credits(&mut service, stdin_exec_id, 4_096) {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = service.grant_flow_credits(FlowCreditRequest {
        exec_id: stdin_exec_id,
        stream: StreamName::Stdin,
        credits: 8,
    }) {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: format!("stdin credits failed: {error}"),
        };
    }

    let protocol_safe_cap = agent_protocol::PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES;
    let oversized = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id: stdin_exec_id,
            sequence: 0,
            chunk: vec![1_u8; protocol_safe_cap + 1],
        },
        &mut supervisor,
    );
    let oversized_rejected = matches!(
        oversized,
        Err(ServiceError {
            code: ServiceErrorCode::StreamChunkTooLarge,
            ..
        })
    );
    if let Err(error) = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id: stdin_exec_id,
            sequence: 0,
            chunk: vec![2_u8; protocol_safe_cap],
        },
        &mut supervisor,
    ) {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: format!("max-sized stdin chunk failed: {error}"),
        };
    }
    let saturated = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id: stdin_exec_id,
            sequence: 1,
            chunk: vec![3_u8; 1],
        },
        &mut supervisor,
    );
    let queue_saturated = matches!(
        saturated,
        Err(ServiceError {
            code: ServiceErrorCode::Backpressure,
            ..
        })
    );
    let health_responsive_during_stdin_pressure = service.health().configured;

    let mut second_chunk_accepted = false;
    let second_chunk_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < second_chunk_deadline {
        match service.stdin_chunk(
            agent_protocol::StdinChunkRecord {
                exec_id: stdin_exec_id,
                sequence: 1,
                chunk: vec![3_u8; 1],
            },
            &mut supervisor,
        ) {
            Ok(()) => {
                second_chunk_accepted = true;
                break;
            }
            Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                ..
            }) => {
                let _ = service.pump_supervisor(&mut supervisor);
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::StreamLogs.name().to_string(),
                    requirement: MxcRequirement::StreamLogs,
                    status: RequirementStatus::Fail,
                    reason: format!("stdin retry failed: {error}"),
                };
            }
        }
    }
    if !second_chunk_accepted {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: "stdin queue did not drain before bounded retry deadline".to_string(),
        };
    }

    let mut eof_sent = false;
    for _ in 0..100 {
        match service.stdin_eof(
            agent_protocol::StdinEofRecord {
                exec_id: stdin_exec_id,
                sequence: 2,
            },
            &mut supervisor,
        ) {
            Ok(()) => {
                eof_sent = true;
                break;
            }
            Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                ..
            }) => {
                let _ = service.pump_supervisor(&mut supervisor);
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::StreamLogs.name().to_string(),
                    requirement: MxcRequirement::StreamLogs,
                    status: RequirementStatus::Fail,
                    reason: format!("stdin eof after retry failed: {error}"),
                };
            }
        }
    }
    if !eof_sent {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: "stdin eof remained backpressured past bounded retry window".to_string(),
        };
    }
    if let Err(error) =
        collect_until_exec_finishes(&mut service, &mut supervisor, Duration::from_secs(8))
    {
        return RequirementResult {
            name: MxcRequirement::StreamLogs.name().to_string(),
            requirement: MxcRequirement::StreamLogs,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }

    let passed = credit_backpressured
        && oversized_rejected
        && queue_saturated
        && second_chunk_accepted
        && max_chunk_bytes <= protocol_safe_cap
        && health_responsive_during_credit_pressure
        && health_responsive_during_stdin_pressure;
    RequirementResult {
        name: MxcRequirement::StreamLogs.name().to_string(),
        requirement: MxcRequirement::StreamLogs,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Real high-output execution hit flow-credit backpressure, max stream chunk stayed protocol-safe, max-sized stdin queueing enforced the protocol-safe cap, and Health remained responsive while backpressured.".to_string()
        } else {
            format!(
                "Backpressure contract failed (credit_backpressured={credit_backpressured}, oversized_rejected={oversized_rejected}, queue_saturated={queue_saturated}, second_chunk_accepted={second_chunk_accepted}, max_chunk_bytes={max_chunk_bytes}, protocol_safe_cap={protocol_safe_cap}, health_credit={health_responsive_during_credit_pressure}, health_stdin={health_responsive_during_stdin_pressure})."
            )
        },
    }
}

#[cfg(target_os = "linux")]
fn run_terminal_semantics() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();

    let stdin_exec_id = 601_u32;
    if let Err(error) = spawn_exec(
        &mut service,
        &mut supervisor,
        stdin_exec_id,
        vec!["/bin/cat".to_string()],
        None,
    ) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = grant_output_credits(&mut service, stdin_exec_id, 16) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id: stdin_exec_id,
            stream: StreamName::Stdin,
            credits: 2,
        })
        .expect("stdin credits");
    let stdin_payload = vec![b'i', b'n', 0, b'p', b'u', b't', b'\n'];
    if let Err(error) = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id: stdin_exec_id,
            sequence: 0,
            chunk: stdin_payload.clone(),
        },
        &mut supervisor,
    ) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: format!("stdin chunk failed: {error}"),
        };
    }
    let mut eof_sent = false;
    for _ in 0..100 {
        match service.stdin_eof(
            agent_protocol::StdinEofRecord {
                exec_id: stdin_exec_id,
                sequence: 1,
            },
            &mut supervisor,
        ) {
            Ok(()) => {
                eof_sent = true;
                break;
            }
            Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                ..
            }) => {
                let _ = service.pump_supervisor(&mut supervisor);
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::Signal.name().to_string(),
                    requirement: MxcRequirement::Signal,
                    status: RequirementStatus::Fail,
                    reason: format!("stdin eof failed: {error}"),
                };
            }
        }
    }
    if !eof_sent {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: "stdin eof remained backpressured past bounded retry window".to_string(),
        };
    }
    let normal =
        match collect_until_exec_finishes(&mut service, &mut supervisor, Duration::from_secs(5)) {
            Ok(observation) => observation,
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::Signal.name().to_string(),
                    requirement: MxcRequirement::Signal,
                    status: RequirementStatus::Fail,
                    reason: error,
                };
            }
        };

    let cancel_exec_id = 602_u32;
    if let Err(error) = spawn_exec(
        &mut service,
        &mut supervisor,
        cancel_exec_id,
        vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "trap '' TERM; while :; do sleep 1; done".to_string(),
        ],
        None,
    ) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = grant_output_credits(&mut service, cancel_exec_id, 8) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) =
        service.cancel_exec(cancel_exec_id, CancelReason::Cancelled, &mut supervisor)
    {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: format!("cancel failed: {error}"),
        };
    }
    let cancelled =
        match collect_until_exec_finishes(&mut service, &mut supervisor, Duration::from_secs(8)) {
            Ok(observation) => observation,
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::Signal.name().to_string(),
                    requirement: MxcRequirement::Signal,
                    status: RequirementStatus::Fail,
                    reason: error,
                };
            }
        };

    let timeout_exec_id = 603_u32;
    if let Err(error) = spawn_exec(
        &mut service,
        &mut supervisor,
        timeout_exec_id,
        vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "trap '' TERM; while :; do sleep 1; done".to_string(),
        ],
        Some(150),
    ) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    if let Err(error) = grant_output_credits(&mut service, timeout_exec_id, 8) {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: error,
        };
    }
    thread::sleep(Duration::from_millis(200));
    if let Err(error) =
        service.cancel_exec(timeout_exec_id, CancelReason::TimedOut, &mut supervisor)
    {
        return RequirementResult {
            name: MxcRequirement::Signal.name().to_string(),
            requirement: MxcRequirement::Signal,
            status: RequirementStatus::Fail,
            reason: format!("timeout cancel failed: {error}"),
        };
    }
    let timed_out =
        match collect_until_exec_finishes(&mut service, &mut supervisor, Duration::from_secs(8)) {
            Ok(observation) => observation,
            Err(error) => {
                return RequirementResult {
                    name: MxcRequirement::Signal.name().to_string(),
                    requirement: MxcRequirement::Signal,
                    status: RequirementStatus::Fail,
                    reason: error,
                };
            }
        };

    let normal_ok = normal.stdout == stdin_payload
        && normal
            .terminals
            .first()
            .is_some_and(|(_, disposition)| *disposition == ExecDisposition::ExitCode(0))
        && terminal_after_eof_and_cleanup(&normal);
    let cancelled_ok = cancelled
        .terminals
        .first()
        .is_some_and(|(_, disposition)| *disposition == ExecDisposition::Cancelled)
        && terminal_after_eof_and_cleanup(&cancelled);
    let timeout_ok = timed_out
        .terminals
        .first()
        .is_some_and(|(_, disposition)| *disposition == ExecDisposition::TimedOut)
        && terminal_after_eof_and_cleanup(&timed_out);
    let passed = normal_ok && cancelled_ok && timeout_ok;
    RequirementResult {
        name: MxcRequirement::Signal.name().to_string(),
        requirement: MxcRequirement::Signal,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Real executions proved stdin EOF/normal exit, cancelled and timed-out termination, and exactly one terminal event emitted only after stdout/stderr EOF plus descendant cleanup.".to_string()
        } else {
            "Terminal ordering/disposition invariants were not satisfied for one or more real executions.".to_string()
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn run_exec_sequencing() -> RequirementResult {
    blocked_requirement(
        MxcRequirement::ExecuteCommand,
        "Scenario requires Linux runtime/supervisor process execution path and is blocked on non-Linux hosts.",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_binary_stream_separation() -> RequirementResult {
    blocked_requirement(
        MxcRequirement::InteractiveShell,
        "Scenario requires Linux runtime/supervisor process execution path and is blocked on non-Linux hosts.",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_backpressure_contract() -> RequirementResult {
    blocked_requirement(
        MxcRequirement::StreamLogs,
        "Scenario requires Linux runtime/supervisor process execution path and is blocked on non-Linux hosts.",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_terminal_semantics() -> RequirementResult {
    blocked_requirement(
        MxcRequirement::Signal,
        "Scenario requires Linux runtime/supervisor process execution path and is blocked on non-Linux hosts.",
    )
}

fn run_identity_verification() -> RequirementResult {
    RequirementResult {
        name: MxcRequirement::WaitContainerExited.name().to_string(),
        requirement: MxcRequirement::WaitContainerExited,
        status: RequirementStatus::Blocked,
        reason:
            "Linux helper execution for uid/gid verification requires running the nvx-agent runtime/supervisor Linux path; blocked in this host-only harness binary."
                .to_string(),
    }
}

fn run_isolation_verification() -> RequirementResult {
    RequirementResult {
        name: MxcRequirement::PrepareSnapshot.name().to_string(),
        requirement: MxcRequirement::PrepareSnapshot,
        status: RequirementStatus::Blocked,
        reason:
            "Namespace/capability/no_new_privs/root/orphan-reaping verification requires Linux helper process with namespace privileges; blocked here."
                .to_string(),
    }
}

fn run_mapping_install_verification() -> RequirementResult {
    RequirementResult {
        name: MxcRequirement::PostRestore.name().to_string(),
        requirement: MxcRequirement::PostRestore,
        status: RequirementStatus::Blocked,
        reason:
            "Mount-namespace mapping installation and readonly-hardening checks require Linux virtio-fs/mount privileges; blocked in this harness environment."
                .to_string(),
    }
}

fn unsupported_result(requirement: MxcRequirement) -> RequirementResult {
    RequirementResult {
        name: requirement.name().to_string(),
        requirement,
        status: RequirementStatus::NotImplemented,
        reason: "Operational slice intentionally excludes this runtime requirement.".to_string(),
    }
}

pub fn phase0_report() -> HarnessReport {
    let adapter = match UnsupportedAciAdapter::status() {
        AciAdapterStatus::Unsupported {
            required_revision,
            reason,
        } => AdapterState {
            kind: "aci".to_string(),
            status: RequirementStatus::Blocked,
            required_revision: required_revision.to_string(),
            reason: reason.to_string(),
        },
    };

    let readiness = run_launch_bound_readiness();
    let bootstrap = run_immutable_configuration();
    let probe = run_health_probe();
    let scenario3 = run_exec_sequencing();
    let scenario4 = run_binary_stream_separation();
    let scenario5 = run_backpressure_contract();
    let scenario6 = run_terminal_semantics();
    let scenario7 = run_identity_verification();
    let scenario8 = run_isolation_verification();
    let scenario9 = run_mapping_install_verification();

    let mut requirements = Vec::with_capacity(MODELED_REQUIREMENTS.len());
    for requirement in MODELED_REQUIREMENTS {
        if requirement == MxcRequirement::Ready {
            requirements.push(readiness.clone());
        } else if requirement == MxcRequirement::Bootstrap {
            requirements.push(bootstrap.clone());
        } else if requirement == MxcRequirement::ExecuteCommand {
            requirements.push(scenario3.clone());
        } else if requirement == MxcRequirement::InteractiveShell {
            requirements.push(scenario4.clone());
        } else if requirement == MxcRequirement::StreamLogs {
            requirements.push(scenario5.clone());
        } else if requirement == MxcRequirement::Signal {
            requirements.push(scenario6.clone());
        } else if requirement == MxcRequirement::WaitContainerExited {
            requirements.push(scenario7.clone());
        } else if requirement == MxcRequirement::Probe {
            requirements.push(probe.clone());
        } else if requirement == MxcRequirement::PrepareSnapshot {
            requirements.push(scenario8.clone());
        } else if requirement == MxcRequirement::PostRestore {
            requirements.push(scenario9.clone());
        } else {
            requirements.push(unsupported_result(requirement));
        }
    }

    let service_readiness = if requirements
        .iter()
        .any(|result| result.status != RequirementStatus::Pass)
    {
        ServiceReadiness::NotReady
    } else {
        ServiceReadiness::Ready
    };

    HarnessReport {
        phase: "phase0-operational-slice".to_string(),
        service_readiness,
        adapter,
        requirements,
    }
}

pub fn is_passing_report(report: &HarnessReport) -> bool {
    if report.service_readiness != ServiceReadiness::Ready {
        return false;
    }
    if report.requirements.len() != MODELED_REQUIREMENTS.len() {
        return false;
    }
    report
        .requirements
        .iter()
        .all(|result| result.status == RequirementStatus::Pass)
}

pub fn report_exit_code(report: &HarnessReport) -> ExitCode {
    if is_passing_report(report) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::std::collections::BTreeSet;

    #[test]
    fn phase0_report_has_exactly_twelve_named_results() {
        let report = phase0_report();
        assert_eq!(report.requirements.len(), 12);
        let names: BTreeSet<_> = report
            .requirements
            .iter()
            .map(|result| result.name.as_str())
            .collect();
        let expected_names: BTreeSet<_> = MODELED_REQUIREMENTS
            .iter()
            .map(|requirement| requirement.name())
            .collect();
        assert_eq!(names, expected_names);
    }

    #[test]
    fn phase0_report_remains_nonzero_until_all_requirements_pass() {
        let report = phase0_report();
        assert_eq!(report.service_readiness, ServiceReadiness::NotReady);
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn harness_executes_real_launch_configure_and_probe_scenarios() {
        let report = phase0_report();
        let readiness = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Ready)
            .unwrap();
        assert_eq!(readiness.status, RequirementStatus::Pass);

        let bootstrap = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Bootstrap)
            .unwrap();
        assert_eq!(bootstrap.status, RequirementStatus::Pass);

        let probe = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Probe)
            .unwrap();
        assert_eq!(probe.status, RequirementStatus::Pass);

        let exec = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::ExecuteCommand)
            .unwrap();
        if cfg!(target_os = "linux") {
            assert_eq!(exec.status, RequirementStatus::Pass, "{}", exec.reason);
        } else {
            assert_eq!(exec.status, RequirementStatus::Blocked);
        }

        let streams = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::InteractiveShell)
            .unwrap();
        if cfg!(target_os = "linux") {
            assert_eq!(
                streams.status,
                RequirementStatus::Pass,
                "{}",
                streams.reason
            );
        } else {
            assert_eq!(streams.status, RequirementStatus::Blocked);
        }

        let backpressure = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::StreamLogs)
            .unwrap();
        if cfg!(target_os = "linux") {
            assert_eq!(
                backpressure.status,
                RequirementStatus::Pass,
                "{}",
                backpressure.reason
            );
        } else {
            assert_eq!(backpressure.status, RequirementStatus::Blocked);
        }

        let terminal = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Signal)
            .unwrap();
        if cfg!(target_os = "linux") {
            assert_eq!(
                terminal.status,
                RequirementStatus::Pass,
                "{}",
                terminal.reason
            );
        } else {
            assert_eq!(terminal.status, RequirementStatus::Blocked);
        }

        let uid_gid = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::WaitContainerExited)
            .unwrap();
        assert_eq!(uid_gid.status, RequirementStatus::Blocked);

        let isolation = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::PrepareSnapshot)
            .unwrap();
        assert_eq!(isolation.status, RequirementStatus::Blocked);

        let mappings = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::PostRestore)
            .unwrap();
        assert_eq!(mappings.status, RequirementStatus::Blocked);
    }
}
