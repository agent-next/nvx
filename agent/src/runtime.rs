// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_protocol::{
    AccessMode, AgentControlMessage, AuthenticateChannelRequest, BuildStatus, CancelReason,
    ChannelReadResult, ConfigureSessionRequest, CreateProcessRequest, DnsStatus,
    GuestControlSession, GuestEvent, HostControlMessage, LaunchBinding, LaunchIdentity,
    MAX_SHUTDOWN_GRACE_TIMEOUT_MS, MappingContainmentPolicy, MxcControlService, NetworkFailureCode,
    NetworkFailureStatus, NetworkInterfaceStatus, NetworkLinkState, NetworkMode, NetworkSetupState,
    NetworkStatus, OPENVMM_OUTER_FRAME_OVERHEAD_BYTES, PROTOCOL_VERSION, ProcessSupervisor,
    ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, ServiceError,
    ServiceErrorCode, SessionConfiguration, WaitReadyRequest, WorkloadIdentityStatus,
};

use crate::config::{GuestMountRoot, SessionConfiguration as AgentSessionConfiguration};
use crate::error::{AgentError, Result};
use crate::isolation::{self, apply_and_verify_workload_isolation, default_isolation_plan};
use crate::mappings::{
    MappingResolver, ResolvedMapping, install_resolved_mappings_in_holder_mount_namespace,
};
use crate::supervisor::LinuxProcessSupervisor;

const LOOP_SLEEP: Duration = Duration::from_millis(10);
const CONTROL_SESSION_ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_GUEST_MAPPING_ROOT: &str = "/mnt/virtiofs";
const DEFAULT_WORKLOAD_CGROUP_PATH: &str = "/sys/fs/cgroup/nvx.workload";
const BOOT_DIAGNOSTIC_TTY: &str = "hvc1";
const PROC_MOUNT_TARGET: &str = "/proc";
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";
const OUTBOUND_PENDING_LIMIT: usize = 256;
const FREEZE_WAIT_TIMEOUT: Duration = Duration::from_secs(2);
const NETWORK_READY_TIMEOUT: Duration = Duration::from_secs(2);
const NETWORK_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_NETWORK_METADATA_ITEMS: usize = 8;
const MAX_NETWORK_METADATA_STRING_BYTES: usize = 128;
const MAX_PROC_TEXT_BYTES: usize = 64 * 1024;
/// Best-effort fatal-session delivery window before fail-closed stop proceeds regardless
/// of channel backpressure or host read behavior.
const FATAL_SESSION_DELIVERY_DEADLINE: Duration = Duration::from_millis(250);

static SIGCHLD_PENDING: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static SYNC_HELPER_BLOCK_MS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static SYNC_HELPER_UNREAPABLE_AFTER_KILL: AtomicBool = AtomicBool::new(false);

pub fn run_runtime() -> Result<()> {
    assert_conservative_openvmm_overhead()?;
    install_sigchld_wakeup_handler()?;
    let launch_config = read_launch_binding()?;
    let binding = launch_config.binding;
    let build = detect_build_status();
    let network = detect_network_status();
    let isolation_result = apply_and_verify_workload_isolation(&default_isolation_plan())?;
    let isolation_holder_pid = isolation_result.holder_pid;
    let mut service = MxcControlService::new_pid1_runtime_with_status(
        binding.clone(),
        build,
        network.clone(),
        isolation_result.status,
        WorkloadIdentityStatus::mxc_fixed(),
        isolation_holder_pid,
    );
    let mut supervisor = LinuxProcessSupervisor::new_with_holder(isolation_result.holder_pid)
        .map_err(|error| AgentError::internal(error.to_string()))?;
    let mut pending_hello: Option<AuthenticateChannelRequest> = None;
    let mut active_timeout: Option<(u32, Instant)> = None;
    let mut pending_outbound = VecDeque::new();
    let mut graceful_shutdown: Option<GracefulShutdownState> = None;
    let mut fatal_shutdown: Option<FatalSessionShutdown> = None;
    let mut writable_mapping_paths: Vec<String> = Vec::new();

    loop {
        let file = open_control_tty_raw_nonblocking(&launch_config.control_tty_device_path)?;
        let control_transport =
            GuestControlTransport::connect(file, CONTROL_SESSION_ATTACH_TIMEOUT)?;
        let mut channel = agent_protocol::HvcFramedChannel::new(control_transport);

        loop {
            enforce_active_timeout(
                &mut service,
                &mut supervisor,
                &mut active_timeout,
                &mut pending_outbound,
                &mut fatal_shutdown,
            )?;

            drain_outbound_to_channel(&mut channel, &mut pending_outbound)?;
            pump_supervisor_to_channel_lossless(&mut service, &mut supervisor, &mut channel)?;
            if service.active_exec_id().is_none() {
                active_timeout = None;
            }
            while channel
                .flush_once()
                .map_err(|error| AgentError::internal(error.to_string()))?
            {}

            if let Some(state) = fatal_shutdown.as_ref()
                && should_stop_after_fatal_delivery(
                    state,
                    pending_outbound.is_empty(),
                    channel.has_queued_writes(),
                    Instant::now(),
                )
            {
                if let Some(graceful) = graceful_shutdown.as_ref() {
                    log_unreaped_sync_helpers_fatal_context(
                        &graceful.pending_sync_helper_pids,
                        "fatal-session-stop",
                    );
                }
                return Ok(());
            }

            if let Some(state) = graceful_shutdown.as_mut()
                && !state.cleanup_started
            {
                service
                    .begin_disconnect_cleanup_with_deadline(
                        now_secs(),
                        &mut supervisor,
                        state.absolute_deadline,
                    )
                    .map_err(|error| AgentError::fail_closed(error.to_string()))?;
                state.cleanup_started = true;
            }

            if let Some(state) = graceful_shutdown.as_mut()
                && state.cleanup_started
                && !state.sync_done
            {
                reap_pending_sync_helpers_nonblocking(&mut state.pending_sync_helper_pids);
                if Instant::now() >= state.absolute_deadline {
                    log_unreaped_sync_helpers_fatal_context(
                        &state.pending_sync_helper_pids,
                        "graceful-deadline-reached-before-sync",
                    );
                    return Ok(());
                }
                if let Err(error) = bounded_sync_writable_mappings_until_deadline(
                    state.absolute_deadline,
                    &state.writable_mapping_paths,
                    &mut state.pending_sync_helper_pids,
                ) {
                    eprintln!("NVX-AGENT-FAIL-CLOSED-SYNC: {error}");
                }
                reap_pending_sync_helpers_nonblocking(&mut state.pending_sync_helper_pids);
                state.sync_done = true;
            }

            if let Some(state) = graceful_shutdown.as_mut() {
                reap_pending_sync_helpers_nonblocking(&mut state.pending_sync_helper_pids);
            }

            if should_complete_shutdown(
                graceful_shutdown.as_ref(),
                service.active_exec_id(),
                pending_outbound.is_empty(),
                channel.has_queued_writes(),
                Instant::now(),
            ) {
                if let Some(graceful) = graceful_shutdown.as_ref() {
                    log_unreaped_sync_helpers_fatal_context(
                        &graceful.pending_sync_helper_pids,
                        "graceful-stop",
                    );
                }
                return Ok(());
            }

            if service.active_exec_id().is_none() {
                isolation::reap_all_children();
            }

            if fatal_shutdown.is_some() {
                thread::sleep(LOOP_SLEEP);
                continue;
            }

            match channel
                .try_read_next_inner_record()
                .map_err(|error| AgentError::internal(error.to_string()))?
            {
                ChannelReadResult::WouldBlock => {
                    if !SIGCHLD_PENDING.swap(false, Ordering::SeqCst) {
                        thread::sleep(LOOP_SLEEP);
                    }
                    continue;
                }
                ChannelReadResult::Closed => {
                    if service.launch_admitted() {
                        service
                            .begin_disconnect_cleanup(now_secs(), &mut supervisor)
                            .map_err(|error| AgentError::internal(error.to_string()))?;
                    }
                    isolation::reap_all_children();
                    pending_hello = None;
                    pending_outbound.clear();
                    active_timeout = None;
                    graceful_shutdown = None;
                    writable_mapping_paths.clear();
                    break;
                }
                ChannelReadResult::Record(record) => {
                    let receipt_instant = Instant::now();
                    let mut dispatch = HostDispatchContext {
                        service: &mut service,
                        supervisor: &mut supervisor,
                        pending_hello: &mut pending_hello,
                        active_timeout: &mut active_timeout,
                        writable_mapping_paths: &mut writable_mapping_paths,
                        isolation_holder_pid,
                        received_at: receipt_instant,
                    };
                    let outbound = handle_host_record(&binding, &mut dispatch, record);
                    let outbound = match outbound {
                        Ok(messages) => messages,
                        Err(error) if error.requires_fail_closed_action() => {
                            fail_closed_cleanup_and_stop(&mut service, &mut supervisor, &error);
                            if let Some(graceful) = graceful_shutdown.as_ref() {
                                log_unreaped_sync_helpers_fatal_context(
                                    &graceful.pending_sync_helper_pids,
                                    "fail-closed-cleanup-stop",
                                );
                            }
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    };
                    if outbound.fatal_session && fatal_shutdown.is_none() {
                        let reason = outbound.messages.iter().find_map(|message| match message {
                            AgentControlMessage::Error(detail)
                                if detail.code == ProtocolErrorCode::FatalSession =>
                            {
                                Some(detail.message.clone())
                            }
                            _ => None,
                        });
                        if let Some(reason) = reason {
                            start_fatal_shutdown(
                                &mut service,
                                &mut supervisor,
                                &mut fatal_shutdown,
                                reason,
                                Instant::now(),
                            );
                        }
                    }
                    if let Some(deadline) = outbound.shutdown_deadline {
                        graceful_shutdown = Some(GracefulShutdownState {
                            absolute_deadline: deadline,
                            cleanup_started: false,
                            sync_done: false,
                            writable_mapping_paths: writable_mapping_paths
                                .iter()
                                .cloned()
                                .map(std::path::PathBuf::from)
                                .collect(),
                            pending_sync_helper_pids: Vec::new(),
                        });
                    }
                    for message in outbound.messages {
                        enqueue_outbound(&mut pending_outbound, message)?;
                    }
                }
            }
        }
    }
}

fn handle_host_record<S: ProcessSupervisor>(
    binding: &LaunchBinding,
    dispatch: &mut HostDispatchContext<'_, S>,
    record: agent_protocol::InnerRecord,
) -> Result<HostRecordOutcome> {
    if record.kind != agent_protocol::InnerRecordKind::Control {
        return Ok(HostRecordOutcome {
            messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                code: ProtocolErrorCode::InvalidLifecycleTransition,
                message: "non-control record on control channel".to_string(),
            })],
            fatal_session: false,
            shutdown_deadline: None,
        });
    }
    let host_message: HostControlMessage = match serde_json::from_slice(&record.payload) {
        Ok(message) => message,
        Err(error) => {
            return Ok(HostRecordOutcome {
                messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                    code: ProtocolErrorCode::InvalidLifecycleTransition,
                    message: format!("invalid host control payload: {error}"),
                })],
                fatal_session: false,
                shutdown_deadline: None,
            });
        }
    };
    match handle_host_message(binding, dispatch, host_message) {
        Ok(outcome) => Ok(HostRecordOutcome {
            messages: outcome.messages,
            fatal_session: false,
            shutdown_deadline: outcome.shutdown_deadline,
        }),
        Err(HostDispatchError::Service(error)) => {
            let detail = protocol_error_from_service(error);
            let fatal_session = detail.code == ProtocolErrorCode::FatalSession;
            Ok(HostRecordOutcome {
                messages: vec![AgentControlMessage::Error(detail)],
                fatal_session,
                shutdown_deadline: None,
            })
        }
        Err(HostDispatchError::Agent(error)) => {
            if error.requires_fail_closed_action() {
                return Err(error);
            }
            Ok(HostRecordOutcome {
                messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                    code: ProtocolErrorCode::InvalidLifecycleTransition,
                    message: error.to_string(),
                })],
                fatal_session: false,
                shutdown_deadline: None,
            })
        }
    }
}

fn fail_closed_cleanup_and_stop<S: ProcessSupervisor>(
    service: &mut MxcControlService,
    supervisor: &mut S,
    reason: &AgentError,
) {
    eprintln!("NVX-AGENT-FAIL-CLOSED: {reason}");
    if let Err(error) = service.begin_disconnect_cleanup(now_secs(), supervisor) {
        eprintln!("NVX-AGENT-FAIL-CLOSED-CLEANUP: {error}");
    }
}

enum HostDispatchError {
    Service(ServiceError),
    Agent(AgentError),
}

struct HostDispatchOutcome {
    messages: Vec<AgentControlMessage>,
    shutdown_deadline: Option<Instant>,
}

struct HostDispatchContext<'a, S: ProcessSupervisor> {
    service: &'a mut MxcControlService,
    supervisor: &'a mut S,
    pending_hello: &'a mut Option<AuthenticateChannelRequest>,
    active_timeout: &'a mut Option<(u32, Instant)>,
    writable_mapping_paths: &'a mut Vec<String>,
    isolation_holder_pid: libc::pid_t,
    received_at: Instant,
}

impl From<ServiceError> for HostDispatchError {
    fn from(value: ServiceError) -> Self {
        Self::Service(value)
    }
}

impl From<AgentError> for HostDispatchError {
    fn from(value: AgentError) -> Self {
        Self::Agent(value)
    }
}

fn protocol_error_from_service(error: ServiceError) -> ProtocolErrorDetail {
    let code = match error.code {
        ServiceErrorCode::UnsupportedProtocolVersion => {
            ProtocolErrorCode::UnsupportedProtocolVersion
        }
        ServiceErrorCode::UnsupportedOperation => ProtocolErrorCode::UnsupportedOperation,
        ServiceErrorCode::WorkloadBusy => ProtocolErrorCode::ActiveExecExists,
        ServiceErrorCode::FatalSession => ProtocolErrorCode::FatalSession,
        _ => ProtocolErrorCode::InvalidLifecycleTransition,
    };
    ProtocolErrorDetail {
        code,
        message: error.to_string(),
    }
}

fn handle_host_message<S: ProcessSupervisor>(
    binding: &LaunchBinding,
    dispatch: &mut HostDispatchContext<'_, S>,
    message: HostControlMessage,
) -> std::result::Result<HostDispatchOutcome, HostDispatchError> {
    match message {
        HostControlMessage::HostHello {
            service: remote_service,
            protocol_version,
            launch,
            capability_proof,
        } => {
            if remote_service != SERVICE_IDENTITY {
                return Ok(HostDispatchOutcome {
                    messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                        code: ProtocolErrorCode::UnsupportedService,
                        message: format!("unsupported service identity {remote_service}"),
                    })],
                    shutdown_deadline: None,
                });
            }
            if protocol_version != PROTOCOL_VERSION {
                return Ok(HostDispatchOutcome {
                    messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                        code: ProtocolErrorCode::UnsupportedProtocolVersion,
                        message: format!("unsupported protocol version {protocol_version}"),
                    })],
                    shutdown_deadline: None,
                });
            }
            *dispatch.pending_hello = Some(AuthenticateChannelRequest {
                service: remote_service,
                protocol_version,
                launch,
                channel_generation: binding.channel_generation,
                capability_proof: capability_proof.to_bytes(),
            });
            Ok(HostDispatchOutcome {
                messages: Vec::new(),
                shutdown_deadline: None,
            })
        }
        HostControlMessage::Configure {
            launch,
            root,
            mappings,
            containment,
        } => {
            let Some(authentication) = dispatch.pending_hello.clone() else {
                return Ok(HostDispatchOutcome {
                    messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                        code: ProtocolErrorCode::ChannelAuthenticationRequired,
                        message: "host hello is required before configure".to_string(),
                    })],
                    shutdown_deadline: None,
                });
            };
            let network = detect_network_status();
            let guest_mount_root = GuestMountRoot::parse(DEFAULT_GUEST_MAPPING_ROOT.to_string())?;
            let _ = dispatch.service.authenticate_channel(
                authentication,
                now_secs(),
                network.clone(),
            )?;
            let resolved_mappings = resolve_declared_mappings(&guest_mount_root, &mappings)?;
            let configuration = session_configuration_from_host(
                launch,
                root,
                mappings,
                containment,
                network.clone(),
            )?;
            dispatch
                .service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: binding.protocol_version,
                    image_version: binding.image_version.clone(),
                    launch,
                    channel_generation: binding.channel_generation,
                    idempotent_replay: false,
                    configuration,
                })?;
            install_resolved_mappings_in_holder_mount_namespace(
                dispatch.isolation_holder_pid,
                guest_mount_root.as_str(),
                &resolved_mappings,
            )
            .map_err(|error| {
                AgentError::fail_closed(format!(
                    "mapping installation failed after configuration commit: {error}"
                ))
            })?;
            dispatch.service.activate_full_lifecycle()?;
            *dispatch.writable_mapping_paths = resolved_mappings
                .iter()
                .filter(|mapping| mapping.access == AccessMode::ReadWrite)
                .map(|mapping| mapping.guest_path.display().to_string())
                .collect();
            let _ = dispatch.service.wait_ready(WaitReadyRequest {
                protocol_version: binding.protocol_version,
                image_version: binding.image_version.clone(),
                launch,
                channel_generation: binding.channel_generation,
            });
            Ok(HostDispatchOutcome {
                messages: vec![AgentControlMessage::Ready {
                    launch,
                    status: ready_status(dispatch.service, network),
                }],
                shutdown_deadline: None,
            })
        }
        HostControlMessage::CreateProcess {
            exec_id,
            argv,
            cwd,
            env,
            timeout_ms,
        } => {
            let timeout_deadline = timeout_ms
                .map(|timeout| {
                    Instant::now()
                        .checked_add(Duration::from_millis(timeout))
                        .ok_or_else(|| ServiceError {
                            code: ServiceErrorCode::InvalidInput,
                            message: format!(
                                "timeout_ms cannot be represented as a runtime deadline ({timeout})"
                            ),
                        })
                })
                .transpose()?;
            dispatch.service.create_process(
                CreateProcessRequest {
                    exec_id,
                    argv,
                    cwd,
                    env,
                    timeout_ms,
                },
                dispatch.supervisor,
            )?;
            if let Some(deadline) = timeout_deadline {
                *dispatch.active_timeout = Some((exec_id, deadline));
            }
            Ok(HostDispatchOutcome {
                messages: Vec::new(),
                shutdown_deadline: None,
            })
        }
        HostControlMessage::CancelExecution { exec_id } => {
            dispatch
                .service
                .cancel_exec(exec_id, CancelReason::Cancelled, dispatch.supervisor)?;
            Ok(HostDispatchOutcome {
                messages: Vec::new(),
                shutdown_deadline: None,
            })
        }
        HostControlMessage::FlowCredits(request) => {
            dispatch.service.grant_flow_credits(request)?;
            Ok(HostDispatchOutcome {
                messages: Vec::new(),
                shutdown_deadline: None,
            })
        }
        HostControlMessage::StdinChunk(record) => {
            dispatch.service.stdin_chunk(record, dispatch.supervisor)?;
            Ok(HostDispatchOutcome {
                messages: Vec::new(),
                shutdown_deadline: None,
            })
        }
        HostControlMessage::StdinEof(record) => {
            dispatch.service.stdin_eof(record, dispatch.supervisor)?;
            Ok(HostDispatchOutcome {
                messages: Vec::new(),
                shutdown_deadline: None,
            })
        }
        HostControlMessage::Health => {
            let snapshot = dispatch.service.health();
            Ok(HostDispatchOutcome {
                messages: vec![AgentControlMessage::Health(agent_protocol::HealthStatus {
                    agent_state: snapshot.agent_state,
                    quiesced: snapshot.quiesced,
                    launch_admitted: snapshot.launch_admitted,
                    shutting_down: snapshot.shutting_down,
                    channel_generation: snapshot.channel_generation,
                    active_exec_id: snapshot.active_exec_id,
                    filesystem: snapshot.filesystem.map(|fs| {
                        agent_protocol::FilesystemHealthStatus {
                            rootfs_ready: fs.rootfs_ready,
                            detail: fs.detail,
                        }
                    }),
                    network: snapshot.network,
                    last_failure: snapshot.last_failure,
                })],
                shutdown_deadline: None,
            })
        }
        HostControlMessage::Quiesce => {
            dispatch.service.ensure_supported_operation("Quiesce")?;
            Ok(HostDispatchOutcome {
                messages: vec![quiesce_transactional(dispatch.service, |freeze| {
                    set_workload_frozen(
                        Path::new(DEFAULT_WORKLOAD_CGROUP_PATH),
                        freeze,
                        FREEZE_WAIT_TIMEOUT,
                    )
                })?],
                shutdown_deadline: None,
            })
        }
        HostControlMessage::Resume => {
            dispatch.service.ensure_supported_operation("Resume")?;
            Ok(HostDispatchOutcome {
                messages: vec![resume_transactional(dispatch.service, |freeze| {
                    set_workload_frozen(
                        Path::new(DEFAULT_WORKLOAD_CGROUP_PATH),
                        freeze,
                        FREEZE_WAIT_TIMEOUT,
                    )
                })?],
                shutdown_deadline: None,
            })
        }
        HostControlMessage::Shutdown { grace_timeout_ms } => {
            if grace_timeout_ms == 0 {
                return Err(ServiceError {
                    code: ServiceErrorCode::InvalidInput,
                    message: "grace_timeout_ms must be greater than zero".to_string(),
                }
                .into());
            }
            if grace_timeout_ms > MAX_SHUTDOWN_GRACE_TIMEOUT_MS {
                return Err(ServiceError {
                    code: ServiceErrorCode::InvalidInput,
                    message: format!(
                        "grace_timeout_ms exceeds maximum supported value {MAX_SHUTDOWN_GRACE_TIMEOUT_MS}"
                    ),
                }
                .into());
            }
            let deadline = dispatch
                .received_at
                .checked_add(Duration::from_millis(grace_timeout_ms))
                .ok_or_else(|| ServiceError {
                    code: ServiceErrorCode::InvalidInput,
                    message: format!(
                        "grace_timeout_ms cannot be represented as a runtime deadline ({grace_timeout_ms})"
                    ),
                })?;
            Ok(HostDispatchOutcome {
                messages: vec![
                    dispatch
                        .service
                        .shutdown_with_grace_timeout(grace_timeout_ms)?,
                ],
                shutdown_deadline: Some(deadline),
            })
        }
    }
}

fn session_configuration_from_host(
    launch: LaunchIdentity,
    root: agent_protocol::CanonicalHostMappingRoot,
    mappings: Vec<agent_protocol::ChildMapping>,
    containment: MappingContainmentPolicy,
    network: NetworkStatus,
) -> Result<SessionConfiguration> {
    let filesystem_detail = format!(
        "verified {} mapping entries under {}",
        mappings.len(),
        root.as_str()
    );
    let _ = AgentSessionConfiguration::new(
        launch,
        root.clone(),
        GuestMountRoot::parse(DEFAULT_GUEST_MAPPING_ROOT.to_string())?,
        mappings.clone(),
        network.mode,
        WorkloadIdentityStatus::mxc_fixed(),
    )?;
    Ok(SessionConfiguration {
        root,
        mappings,
        containment,
        labels: vec!["mxc".to_string()],
        attributes: BTreeMap::new(),
        filesystem: agent_protocol::FilesystemStatus {
            rootfs_ready: true,
            detail: filesystem_detail,
        },
        network,
    })
}

fn ready_status(service: &MxcControlService, network: NetworkStatus) -> ReadyStatus {
    service.ready_status(network)
}

fn resolve_declared_mappings(
    guest_mount_root: &GuestMountRoot,
    mappings: &[agent_protocol::ChildMapping],
) -> Result<Vec<ResolvedMapping>> {
    let resolver = MappingResolver::new(guest_mount_root.as_str(), mappings.to_vec())?;
    let mut resolved = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        resolved.push(resolver.resolve_declared(&mapping.child)?);
    }
    Ok(resolved)
}

fn detect_network_status() -> NetworkStatus {
    match list_non_loopback_interfaces() {
        Ok(adapters) if adapters.is_empty() => no_nic_network_status(),
        Ok(_) => detect_portable_network_status(NETWORK_READY_TIMEOUT),
        Err(failure) => failed_portable_network_status(failure),
    }
}

#[cfg(feature = "harness-supervisor")]
#[allow(dead_code)]
pub fn harness_detect_network_status_with_probe(
    interfaces_present: bool,
    timeout: Duration,
    probe: impl FnMut() -> std::result::Result<NetworkStatus, NetworkFailureStatus>,
    sleep: impl FnMut(Duration),
) -> NetworkStatus {
    if !interfaces_present {
        return no_nic_network_status();
    }
    detect_portable_network_status_with_probe(timeout, probe, sleep)
}

fn no_nic_network_status() -> NetworkStatus {
    NetworkStatus {
        mode: NetworkMode::NoNic,
        setup_state: NetworkSetupState::Ready,
        interface: None,
        default_gateway: None,
        dns: DnsStatus {
            ready: true,
            servers: Vec::new(),
        },
        failure: None,
    }
}

fn detect_portable_network_status(timeout: Duration) -> NetworkStatus {
    detect_portable_network_status_with_probe(timeout, collect_portable_network_status, |delay| {
        thread::sleep(delay);
    })
}

fn detect_portable_network_status_with_probe(
    timeout: Duration,
    mut probe: impl FnMut() -> std::result::Result<NetworkStatus, NetworkFailureStatus>,
    mut sleep: impl FnMut(Duration),
) -> NetworkStatus {
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    loop {
        let failure = match probe() {
            Ok(status) => return status,
            Err(failure) => failure,
        };
        if Instant::now() >= deadline {
            return failed_portable_network_status(failure);
        }
        sleep(NETWORK_POLL_INTERVAL);
    }
}

fn collect_portable_network_status() -> std::result::Result<NetworkStatus, NetworkFailureStatus> {
    let interfaces = list_non_loopback_interfaces()?;
    let primary = interfaces.first().ok_or(NetworkFailureStatus {
        code: NetworkFailureCode::InterfaceMissing,
        detail: "portable-network mode requires one non-loopback interface".to_string(),
    })?;
    let interface = collect_interface_status(primary)?;
    collect_portable_network_status_with_sources(
        interface,
        || parse_default_route_gateway_ipv4(primary),
        parse_dns_status,
    )
}

fn collect_portable_network_status_with_sources(
    interface: NetworkInterfaceStatus,
    mut route_probe: impl FnMut() -> std::result::Result<Option<Ipv4Addr>, NetworkFailureStatus>,
    mut dns_probe: impl FnMut() -> std::result::Result<DnsStatus, NetworkFailureStatus>,
) -> std::result::Result<NetworkStatus, NetworkFailureStatus> {
    if !matches!(interface.link_state, NetworkLinkState::Up) {
        return Err(NetworkFailureStatus {
            code: NetworkFailureCode::InterfaceMissing,
            detail: format!("interface {} is not link-up", interface.name),
        });
    }
    if interface.addresses.is_empty() {
        return Err(NetworkFailureStatus {
            code: NetworkFailureCode::AddressMissing,
            detail: format!("interface {} has no assigned addresses", interface.name),
        });
    }
    let gateway = route_probe()?.ok_or(NetworkFailureStatus {
        code: NetworkFailureCode::RouteMissing,
        detail: format!("interface {} has no IPv4 default route", interface.name),
    })?;
    let dns = dns_probe()?;
    if !dns.ready {
        return Err(NetworkFailureStatus {
            code: NetworkFailureCode::DnsMissing,
            detail: "portable-network mode requires at least one DNS server".to_string(),
        });
    }
    Ok(NetworkStatus {
        mode: NetworkMode::PortableNetwork,
        setup_state: NetworkSetupState::Ready,
        interface: Some(NetworkInterfaceStatus {
            default_route: Some(gateway.to_string()),
            ..interface
        }),
        default_gateway: Some(gateway.to_string()),
        dns,
        failure: None,
    })
}

#[cfg(feature = "harness-supervisor")]
#[allow(dead_code)]
pub fn harness_collect_portable_network_status(
    interface: NetworkInterfaceStatus,
    route_table_text: &str,
    resolv_conf_text: &str,
) -> std::result::Result<NetworkStatus, NetworkFailureStatus> {
    let name = interface.name.clone();
    collect_portable_network_status_with_sources(
        interface,
        || parse_default_route_gateway_ipv4_from_text(&name, route_table_text),
        || parse_dns_status_from_text(resolv_conf_text),
    )
}

fn failed_portable_network_status(failure: NetworkFailureStatus) -> NetworkStatus {
    NetworkStatus {
        mode: NetworkMode::PortableNetwork,
        setup_state: NetworkSetupState::Failed,
        interface: None,
        default_gateway: None,
        dns: DnsStatus {
            ready: false,
            servers: Vec::new(),
        },
        failure: Some(NetworkFailureStatus {
            code: failure.code,
            detail: bounded_network_text(&failure.detail),
        }),
    }
}

fn list_non_loopback_interfaces() -> std::result::Result<Vec<String>, NetworkFailureStatus> {
    let entries = std::fs::read_dir("/sys/class/net").map_err(|error| NetworkFailureStatus {
        code: NetworkFailureCode::Io,
        detail: bounded_network_text(&format!("reading /sys/class/net failed: {error}")),
    })?;
    let mut adapters = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| NetworkFailureStatus {
            code: NetworkFailureCode::Io,
            detail: bounded_network_text(&format!("reading interface entry failed: {error}")),
        })?;
        let name = bounded_network_text(&entry.file_name().to_string_lossy());
        if name.is_empty() || name == "lo" {
            continue;
        }
        if adapters.len() < MAX_NETWORK_METADATA_ITEMS {
            adapters.push(name);
        }
    }
    adapters.sort();
    Ok(adapters)
}

fn collect_interface_status(
    interface_name: &str,
) -> std::result::Result<NetworkInterfaceStatus, NetworkFailureStatus> {
    let ifindex_text = read_limited_text(
        Path::new(&format!("/sys/class/net/{interface_name}/ifindex")),
        128,
    )?;
    let index = ifindex_text
        .trim()
        .parse::<u32>()
        .map_err(|error| NetworkFailureStatus {
            code: NetworkFailureCode::InterfaceMalformed,
            detail: bounded_network_text(&format!("invalid ifindex for {interface_name}: {error}")),
        })?;
    let operstate_text = read_limited_text(
        Path::new(&format!("/sys/class/net/{interface_name}/operstate")),
        64,
    )?;
    let link_state = match operstate_text.trim() {
        "up" => NetworkLinkState::Up,
        "down" => NetworkLinkState::Down,
        _ => NetworkLinkState::Unknown,
    };
    let addresses = collect_interface_addresses(interface_name)?;
    Ok(NetworkInterfaceStatus {
        name: bounded_network_text(interface_name),
        index,
        link_state,
        addresses,
        default_route: None,
    })
}

fn collect_interface_addresses(
    interface_name: &str,
) -> std::result::Result<Vec<String>, NetworkFailureStatus> {
    let mut addrs = Vec::new();
    let mut ptr: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a linked list pointer to ptr on success.
    let rc = unsafe { libc::getifaddrs(&mut ptr as *mut *mut libc::ifaddrs) };
    if rc != 0 {
        return Err(NetworkFailureStatus {
            code: NetworkFailureCode::Io,
            detail: bounded_network_text(&format!(
                "getifaddrs failed: {}",
                io::Error::last_os_error()
            )),
        });
    }
    // SAFETY: ptr is initialized by successful getifaddrs and must be released with freeifaddrs.
    let mut current = ptr;
    while !current.is_null() && addrs.len() < MAX_NETWORK_METADATA_ITEMS {
        // SAFETY: current points to a valid ifaddrs node while traversing the list.
        let item = unsafe { &*current };
        if !item.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string.
            let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) };
            if name.to_string_lossy() == interface_name
                && let Some(value) = sockaddr_to_ip(item.ifa_addr)
            {
                addrs.push(bounded_network_text(&value.to_string()));
            }
        }
        current = item.ifa_next;
    }
    // SAFETY: ptr is the original list pointer from getifaddrs.
    unsafe { libc::freeifaddrs(ptr) };
    if addrs.is_empty() {
        return Err(NetworkFailureStatus {
            code: NetworkFailureCode::AddressMissing,
            detail: format!("interface {interface_name} has no IP addresses"),
        });
    }
    Ok(addrs)
}

fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees addr points to a valid socket address for family dispatch.
    let family = unsafe { (*addr).sa_family as i32 };
    match family {
        libc::AF_INET => {
            // SAFETY: AF_INET implies sockaddr_in layout.
            let sin = unsafe { &*(addr as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: AF_INET6 implies sockaddr_in6 layout.
            let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn parse_default_route_gateway_ipv4(
    interface_name: &str,
) -> std::result::Result<Option<Ipv4Addr>, NetworkFailureStatus> {
    let route = read_limited_text(Path::new("/proc/net/route"), MAX_PROC_TEXT_BYTES)?;
    parse_default_route_gateway_ipv4_from_text(interface_name, &route)
}

fn parse_default_route_gateway_ipv4_from_text(
    interface_name: &str,
    route_text: &str,
) -> std::result::Result<Option<Ipv4Addr>, NetworkFailureStatus> {
    for line in route_text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        if fields[0] != interface_name || fields[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(fields[3], 16).map_err(|error| NetworkFailureStatus {
            code: NetworkFailureCode::RouteMalformed,
            detail: bounded_network_text(&format!(
                "invalid route flags for {interface_name}: {error}"
            )),
        })?;
        if (flags & 0x1) == 0 {
            continue;
        }
        let gateway = u32::from_str_radix(fields[2], 16).map_err(|error| NetworkFailureStatus {
            code: NetworkFailureCode::RouteMalformed,
            detail: bounded_network_text(&format!("invalid gateway for {interface_name}: {error}")),
        })?;
        return Ok(Some(Ipv4Addr::from(gateway.to_le_bytes())));
    }
    Ok(None)
}

fn parse_dns_status() -> std::result::Result<DnsStatus, NetworkFailureStatus> {
    let resolv = read_limited_text(Path::new("/etc/resolv.conf"), MAX_PROC_TEXT_BYTES)?;
    parse_dns_status_from_text(&resolv)
}

fn parse_dns_status_from_text(
    resolv_conf: &str,
) -> std::result::Result<DnsStatus, NetworkFailureStatus> {
    let mut servers = Vec::new();
    for line in resolv_conf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        if key != "nameserver" {
            continue;
        }
        let value = fields.next().ok_or(NetworkFailureStatus {
            code: NetworkFailureCode::DnsMalformed,
            detail: "resolv.conf nameserver entry missing address".to_string(),
        })?;
        let parsed = value
            .parse::<IpAddr>()
            .map_err(|error| NetworkFailureStatus {
                code: NetworkFailureCode::DnsMalformed,
                detail: bounded_network_text(&format!(
                    "invalid nameserver address {value}: {error}"
                )),
            })?;
        if servers.len() < MAX_NETWORK_METADATA_ITEMS {
            servers.push(bounded_network_text(&parsed.to_string()));
        }
    }
    Ok(DnsStatus {
        ready: !servers.is_empty(),
        servers,
    })
}

fn read_limited_text(
    path: &Path,
    max_bytes: usize,
) -> std::result::Result<String, NetworkFailureStatus> {
    let file = File::open(path).map_err(|error| NetworkFailureStatus {
        code: NetworkFailureCode::Io,
        detail: bounded_network_text(&format!("opening {} failed: {error}", path.display())),
    })?;
    let mut limited = file.take(max_bytes.saturating_add(1) as u64);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| NetworkFailureStatus {
            code: NetworkFailureCode::Io,
            detail: bounded_network_text(&format!("reading {} failed: {error}", path.display())),
        })?;
    if bytes.len() > max_bytes {
        return Err(NetworkFailureStatus {
            code: NetworkFailureCode::Parse,
            detail: bounded_network_text(&format!(
                "{} exceeded bounded metadata size {max_bytes}",
                path.display()
            )),
        });
    }
    String::from_utf8(bytes).map_err(|error| NetworkFailureStatus {
        code: NetworkFailureCode::Parse,
        detail: bounded_network_text(&format!("{} is not valid UTF-8: {error}", path.display())),
    })
}

fn bounded_network_text(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_control() && ch != ' ' {
            continue;
        }
        if out.len() >= MAX_NETWORK_METADATA_STRING_BYTES {
            break;
        }
        out.push(ch);
    }
    out
}

fn detect_build_status() -> BuildStatus {
    BuildStatus {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        kernel_release: detect_kernel_release().unwrap_or_else(|| "unknown".to_string()),
        profile: "mxc-prototype".to_string(),
    }
}

fn detect_kernel_release() -> Option<String> {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uts points to writable memory for uname output.
    let rc = unsafe { libc::uname(uts.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: uname succeeded and initialized uts.
    let uts = unsafe { uts.assume_init() };
    let ptr = uts.release.as_ptr();
    // SAFETY: uname returns a NUL-terminated C string in release.
    let text = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .to_string();
    Some(text)
}

fn assert_conservative_openvmm_overhead() -> Result<()> {
    let max_inner = agent_protocol::OPENVMM_OUTER_RECORD_MAX_BYTES
        .checked_sub(OPENVMM_OUTER_FRAME_OVERHEAD_BYTES)
        .ok_or_else(|| AgentError::internal("OpenVMM framing bound underflow"))?;
    if max_inner < agent_protocol::INNER_RECORD_HEADER_BYTES {
        return Err(AgentError::internal(
            "OpenVMM framing reserve leaves no room for inner record header",
        ));
    }
    Ok(())
}

struct LaunchRuntimeConfig {
    binding: LaunchBinding,
    control_tty_device_path: String,
}

struct HostRecordOutcome {
    messages: Vec<AgentControlMessage>,
    fatal_session: bool,
    shutdown_deadline: Option<Instant>,
}

struct FatalSessionShutdown {
    delivery_deadline: Instant,
}

struct GracefulShutdownState {
    absolute_deadline: Instant,
    cleanup_started: bool,
    sync_done: bool,
    writable_mapping_paths: Vec<PathBuf>,
    pending_sync_helper_pids: Vec<libc::pid_t>,
}

fn bounded_sync_writable_mappings_until_deadline(
    absolute_deadline: Instant,
    writable_mapping_paths: &[PathBuf],
    pending_sync_helper_pids: &mut Vec<libc::pid_t>,
) -> Result<()> {
    if writable_mapping_paths.is_empty() {
        return Ok(());
    }
    if Instant::now() >= absolute_deadline {
        return Err(AgentError::fail_closed(
            "mapping sync skipped because shutdown deadline is already elapsed".to_string(),
        ));
    }
    // SAFETY: fork is used to isolate potentially blocking sync syscalls from PID1.
    let helper_pid = unsafe { libc::fork() };
    if helper_pid < 0 {
        return Err(AgentError::io(
            "forking mapping sync helper",
            io::Error::last_os_error(),
        ));
    }
    if helper_pid == 0 {
        let code = run_mapping_sync_helper(writable_mapping_paths);
        // SAFETY: child exits immediately without unwinding parent state.
        unsafe { libc::_exit(code) };
    }
    if process_is_in_workload_cgroup(helper_pid)? {
        let _ = unsafe { libc::kill(helper_pid, libc::SIGKILL) };
        let _ = try_reap_child_nonblocking(helper_pid);
        return Err(AgentError::fail_closed(format!(
            "mapping sync helper pid={helper_pid} resolved to workload cgroup; refusing helper/workload identity ambiguity"
        )));
    }
    loop {
        if let Some(status) = try_reap_child_nonblocking(helper_pid)? {
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                return Ok(());
            }
            return Err(AgentError::fail_closed(format!(
                "mapping sync helper failed (status={status}, pid={helper_pid})"
            )));
        }
        if Instant::now() >= absolute_deadline {
            // SAFETY: helper_pid refers to the bounded sync helper child.
            let _ = unsafe { libc::kill(helper_pid, libc::SIGKILL) };
            if sync_helper_unreapable_after_kill_failpoint() {
                pending_sync_helper_pids.push(helper_pid);
                return Err(AgentError::fail_closed(format!(
                    "mapping sync helper exceeded shutdown deadline; SIGKILL sent; simulated unreaped helper pid={helper_pid} tracked for later nonblocking reap"
                )));
            }
            if try_reap_child_nonblocking(helper_pid)?.is_none() {
                pending_sync_helper_pids.push(helper_pid);
                return Err(AgentError::fail_closed(format!(
                    "mapping sync helper exceeded shutdown deadline; SIGKILL sent; helper pid={helper_pid} still unreaped and tracked for later nonblocking reap"
                )));
            }
            return Err(AgentError::fail_closed(format!(
                "mapping sync helper exceeded shutdown deadline and was killed (pid={helper_pid})"
            )));
        }
        let now = Instant::now();
        if now >= absolute_deadline {
            continue;
        }
        thread::sleep((absolute_deadline - now).min(LOOP_SLEEP));
    }
}

fn run_mapping_sync_helper(writable_mapping_paths: &[PathBuf]) -> i32 {
    #[cfg(test)]
    {
        let block_ms = SYNC_HELPER_BLOCK_MS.load(Ordering::SeqCst);
        if block_ms > 0 {
            thread::sleep(Duration::from_millis(block_ms));
        }
    }
    if !configure_sync_helper_child_safety() {
        return 2;
    }
    let mut synced_devices = HashSet::new();
    for path in writable_mapping_paths {
        let bytes = path.as_os_str().as_bytes();
        let c_path = match std::ffi::CString::new(bytes) {
            Ok(value) => value,
            Err(_) => return 1,
        };
        // SAFETY: c_path is NUL-terminated and flags are constant.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return 1;
        }
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is valid and stat points to initialized storage for fstat.
        let stat_rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if stat_rc != 0 {
            // SAFETY: best-effort close for owned descriptor.
            let _ = unsafe { libc::close(fd) };
            return 1;
        }
        // SAFETY: fstat succeeded and initialized stat.
        let stat = unsafe { stat.assume_init() };
        if synced_devices.insert(stat.st_dev) {
            // SAFETY: fd is valid and owned by this helper process.
            let sync_rc = unsafe { libc::syncfs(fd) };
            if sync_rc != 0 {
                // SAFETY: fallback to per-inode fsync when syncfs is unavailable/fails.
                let fsync_rc = unsafe { libc::fsync(fd) };
                if fsync_rc != 0 {
                    // SAFETY: best-effort close for owned descriptor.
                    let _ = unsafe { libc::close(fd) };
                    return 1;
                }
            }
        }
        // SAFETY: best-effort close for owned descriptor.
        let _ = unsafe { libc::close(fd) };
    }
    0
}

fn configure_sync_helper_child_safety() -> bool {
    let parent_pid = unsafe { libc::getppid() };
    // SAFETY: PR_SET_PDEATHSIG is called with a fixed integer signal argument.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return false;
    }
    // SAFETY: best-effort parent liveness race check after PR_SET_PDEATHSIG.
    if unsafe { libc::getppid() } != parent_pid {
        return false;
    }
    process_is_in_workload_cgroup_for_self()
        .map(|is_workload| !is_workload)
        .unwrap_or(false)
}

fn process_is_in_workload_cgroup_for_self() -> io::Result<bool> {
    process_is_in_workload_cgroup_by_path(Path::new("/proc/self/cgroup"))
}

fn process_is_in_workload_cgroup(pid: libc::pid_t) -> Result<bool> {
    let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    process_is_in_workload_cgroup_by_path(path.as_path())
        .map_err(|error| AgentError::io(format!("reading helper cgroup for pid {pid}"), error))
}

fn process_is_in_workload_cgroup_by_path(path: &Path) -> io::Result<bool> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .any(|cgroup_path| cgroup_path.contains("/nvx.workload")))
}

fn try_reap_child_nonblocking(pid: libc::pid_t) -> io::Result<Option<i32>> {
    let mut status = 0_i32;
    // SAFETY: waitpid is called with WNOHANG and a writable status pointer.
    let wait_rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if wait_rc == pid {
        return Ok(Some(status));
    }
    if wait_rc == 0 {
        return Ok(None);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        return Ok(Some(0));
    }
    Err(error)
}

fn reap_pending_sync_helpers_nonblocking(pending_sync_helper_pids: &mut Vec<libc::pid_t>) {
    let mut retained = Vec::with_capacity(pending_sync_helper_pids.len());
    for pid in pending_sync_helper_pids.drain(..) {
        match try_reap_child_nonblocking(pid) {
            Ok(Some(_)) => {}
            Ok(None) => retained.push(pid),
            Err(error) => {
                eprintln!(
                    "NVX-AGENT-FAIL-CLOSED-SYNC: nonblocking reap of mapping sync helper pid={pid} failed: {error}"
                );
                retained.push(pid);
            }
        }
    }
    *pending_sync_helper_pids = retained;
}

fn log_unreaped_sync_helpers_fatal_context(pending_sync_helper_pids: &[libc::pid_t], reason: &str) {
    if pending_sync_helper_pids.is_empty() {
        return;
    }
    eprintln!(
        "NVX-AGENT-FAIL-CLOSED-SYNC: shutdown context={reason} has unreaped mapping sync helper pid(s) {:?}; fail-closed stop proceeds without blocking waitpid",
        pending_sync_helper_pids
    );
}

#[cfg(test)]
fn sync_helper_unreapable_after_kill_failpoint() -> bool {
    SYNC_HELPER_UNREAPABLE_AFTER_KILL.load(Ordering::SeqCst)
}

#[cfg(not(test))]
fn sync_helper_unreapable_after_kill_failpoint() -> bool {
    false
}

fn start_fatal_shutdown<S: ProcessSupervisor>(
    service: &mut MxcControlService,
    supervisor: &mut S,
    shutdown: &mut Option<FatalSessionShutdown>,
    reason: String,
    now: Instant,
) {
    if shutdown.is_some() {
        return;
    }
    let fail_closed = AgentError::fail_closed(format!(
        "fatal session protocol error requires runtime stop: {reason}"
    ));
    fail_closed_cleanup_and_stop(service, supervisor, &fail_closed);
    let delivery_deadline = now
        .checked_add(FATAL_SESSION_DELIVERY_DEADLINE)
        .unwrap_or(now);
    *shutdown = Some(FatalSessionShutdown { delivery_deadline });
}

fn should_stop_after_fatal_delivery(
    shutdown: &FatalSessionShutdown,
    pending_outbound_empty: bool,
    has_queued_writes: bool,
    now: Instant,
) -> bool {
    (pending_outbound_empty && !has_queued_writes) || now >= shutdown.delivery_deadline
}

fn should_complete_shutdown(
    shutdown: Option<&GracefulShutdownState>,
    active_exec_id: Option<u32>,
    pending_outbound_empty: bool,
    has_queued_writes: bool,
    now: Instant,
) -> bool {
    let Some(shutdown) = shutdown else {
        return false;
    };
    if active_exec_id.is_none() && pending_outbound_empty && !has_queued_writes {
        return true;
    }
    shutdown.cleanup_started && now >= shutdown.absolute_deadline
}

#[allow(dead_code)]
pub fn harness_should_complete_shutdown_when_writer_blocked(
    active_exec_id: Option<u32>,
    grace_timeout_ms: u64,
    elapsed_ms: u64,
) -> bool {
    let start = Instant::now();
    let deadline = start
        .checked_add(Duration::from_millis(grace_timeout_ms))
        .unwrap_or(start);
    let now = start
        .checked_add(Duration::from_millis(elapsed_ms))
        .unwrap_or(deadline);
    let shutdown = GracefulShutdownState {
        absolute_deadline: deadline,
        cleanup_started: true,
        sync_done: true,
        writable_mapping_paths: Vec::new(),
        pending_sync_helper_pids: Vec::new(),
    };
    should_complete_shutdown(Some(&shutdown), active_exec_id, false, true, now)
}

fn enforce_active_timeout<S: ProcessSupervisor>(
    service: &mut MxcControlService,
    supervisor: &mut S,
    active_timeout: &mut Option<(u32, Instant)>,
    pending_outbound: &mut VecDeque<AgentControlMessage>,
    fatal_shutdown: &mut Option<FatalSessionShutdown>,
) -> Result<()> {
    let Some((exec_id, deadline)) = *active_timeout else {
        return Ok(());
    };
    if Instant::now() < deadline {
        return Ok(());
    }
    match service.cancel_exec(exec_id, CancelReason::TimedOut, supervisor) {
        Ok(()) => {
            *active_timeout = None;
            Ok(())
        }
        Err(error) if error.code == ServiceErrorCode::FatalSession => {
            let detail = protocol_error_from_service(error);
            let reason = detail.message.clone();
            start_fatal_shutdown(service, supervisor, fatal_shutdown, reason, Instant::now());
            if let Err(delivery_error) =
                enqueue_outbound(pending_outbound, AgentControlMessage::Error(detail))
            {
                eprintln!(
                    "NVX-AGENT-FATAL-DELIVERY-BEST-EFFORT: failed to queue fatal-session protocol error: {delivery_error}"
                );
            }
            Ok(())
        }
        Err(error) => {
            eprintln!("NVX-AGENT-TIMEOUT-RETRY: {error}");
            Ok(())
        }
    }
}

fn read_launch_binding() -> Result<LaunchRuntimeConfig> {
    ensure_procfs_for_pid1_startup()?;
    let cmdline = std::fs::read_to_string(PROC_CMDLINE_PATH)
        .map_err(|error| AgentError::io("reading /proc/cmdline", error))?;
    let channel_generation = parse_required_u64_arg(
        &cmdline,
        &["nvx.channel_generation", "nvx_channel_generation"],
    )?;
    let control_tty_device_path = parse_required_control_tty_arg(&cmdline)?;
    Ok(LaunchRuntimeConfig {
        binding: LaunchBinding {
            protocol_version: PROTOCOL_VERSION,
            image_version: env!("CARGO_PKG_VERSION").to_string(),
            launch: LaunchIdentity {
                generation: 0,
                nonce: [0_u8; 16],
            },
            channel_generation,
        },
        control_tty_device_path,
    })
}

fn ensure_procfs_for_pid1_startup() -> Result<()> {
    ensure_procfs_for_pid1_startup_with_ops(
        || Path::new(PROC_CMDLINE_PATH).exists(),
        || {
            std::fs::create_dir_all(PROC_MOUNT_TARGET)
                .map_err(|error| AgentError::io("creating /proc mountpoint", error))
        },
        mount_procfs_on_proc,
    )
}

fn ensure_procfs_for_pid1_startup_with_ops(
    cmdline_exists: impl FnMut() -> bool,
    ensure_proc_mountpoint: impl FnMut() -> Result<()>,
    mount_procfs: impl FnMut() -> Result<()>,
) -> Result<()> {
    ensure_procfs_mounted_with_ops(cmdline_exists, ensure_proc_mountpoint, mount_procfs).map_err(
        |error| {
            if error.requires_fail_closed_action() {
                error
            } else {
                AgentError::fail_closed(format!(
                    "PID 1 startup requires mounted procfs before reading /proc/cmdline: {error}",
                ))
            }
        },
    )
}

fn ensure_procfs_mounted_with_ops(
    mut cmdline_exists: impl FnMut() -> bool,
    mut ensure_proc_mountpoint: impl FnMut() -> Result<()>,
    mut mount_procfs: impl FnMut() -> Result<()>,
) -> Result<()> {
    if cmdline_exists() {
        return Ok(());
    }
    ensure_proc_mountpoint()?;
    mount_procfs()?;
    if cmdline_exists() {
        return Ok(());
    }
    Err(AgentError::fail_closed(
        "procfs mount completed but /proc/cmdline is still unavailable",
    ))
}

fn mount_procfs_on_proc() -> Result<()> {
    let source = std::ffi::CString::new("proc")
        .map_err(|_| AgentError::mount("proc source contains NUL"))?;
    let target = std::ffi::CString::new(PROC_MOUNT_TARGET)
        .map_err(|_| AgentError::mount("proc target contains NUL"))?;
    let fstype = std::ffi::CString::new("proc")
        .map_err(|_| AgentError::mount("proc fstype contains NUL"))?;
    // SAFETY: mount is called with constant C strings and null data.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBUSY) {
        return Ok(());
    }
    Err(AgentError::io("mounting procfs on /proc", error))
}

fn parse_required_u64_arg(cmdline: &str, keys: &[&str]) -> Result<u64> {
    let (key, value) = extract_unique_cmdline_value(cmdline, keys)?;
    value
        .parse::<u64>()
        .map_err(|error| AgentError::config(format!("invalid {key} value: {error}")))
}

fn parse_required_control_tty_arg(cmdline: &str) -> Result<String> {
    let (_, tty_name) = extract_unique_cmdline_value(cmdline, &["nvx_control_tty"])?;
    if tty_name == BOOT_DIAGNOSTIC_TTY {
        return Err(AgentError::config(
            "nvx_control_tty must differ from boot diagnostics tty hvc1",
        ));
    }
    if !tty_name.starts_with("hvc")
        || tty_name.len() <= 3
        || !tty_name[3..].chars().all(|ch| ch.is_ascii_digit())
    {
        return Err(AgentError::config(format!(
            "nvx_control_tty must use hvcN form, got {tty_name}"
        )));
    }
    Ok(format!("/dev/{tty_name}"))
}

fn extract_unique_cmdline_value(cmdline: &str, keys: &[&str]) -> Result<(String, String)> {
    let mut found: Option<(String, String)> = None;
    for token in cmdline.split_whitespace() {
        for key in keys {
            if token == *key {
                return Err(AgentError::config(format!(
                    "kernel argument {key} must use key=value form",
                )));
            }
            let prefix = format!("{key}=");
            if let Some(value) = token.strip_prefix(&prefix) {
                if value.is_empty() {
                    return Err(AgentError::config(format!(
                        "kernel argument {key} must not be empty",
                    )));
                }
                if found.is_some() {
                    return Err(AgentError::config(format!(
                        "duplicate kernel argument for {}",
                        keys.join(", ")
                    )));
                }
                found = Some(((*key).to_string(), value.to_string()));
            }
        }
    }
    found.ok_or_else(|| {
        AgentError::config(format!(
            "missing required kernel argument; expected one of: {}",
            keys.join(", ")
        ))
    })
}

#[cfg(test)]
fn parse_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(AgentError::config(
            "capability must be exactly 64 hex characters",
        ));
    }
    let mut capability = [0_u8; 32];
    for (index, slot) in capability.iter_mut().enumerate() {
        let start = index * 2;
        let end = start + 2;
        let byte = u8::from_str_radix(&value[start..end], 16)
            .map_err(|error| AgentError::config(format!("invalid capability hex: {error}")))?;
        *slot = byte;
    }
    Ok(capability)
}

fn now_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

fn enqueue_outbound(
    queue: &mut VecDeque<AgentControlMessage>,
    message: AgentControlMessage,
) -> Result<()> {
    if queue.len() >= OUTBOUND_PENDING_LIMIT {
        return Err(AgentError::internal(
            "outbound pending queue exceeded bounded capacity",
        ));
    }
    queue.push_back(message);
    Ok(())
}

fn drain_outbound_to_channel<T: io::Read + io::Write>(
    channel: &mut agent_protocol::HvcFramedChannel<T>,
    queue: &mut VecDeque<AgentControlMessage>,
) -> Result<()> {
    while let Some(front) = queue.front() {
        match channel.queue_control_message(front) {
            Ok(()) => {
                queue.pop_front();
            }
            Err(error) if error.code == ServiceErrorCode::Backpressure => return Ok(()),
            Err(error) => return Err(AgentError::internal(error.to_string())),
        }
    }
    Ok(())
}

fn pump_supervisor_to_channel_lossless<T: io::Read + io::Write>(
    service: &mut MxcControlService,
    supervisor: &mut impl ProcessSupervisor,
    channel: &mut agent_protocol::HvcFramedChannel<T>,
) -> Result<()> {
    match service
        .pump_supervisor_to_channel(supervisor, channel)
        .map_err(|error| AgentError::internal(error.to_string()))?
    {
        agent_protocol::service::PumpSupervisorResult::Drained
        | agent_protocol::service::PumpSupervisorResult::WouldBlock => Ok(()),
    }
}

fn quiesce_transactional(
    service: &mut MxcControlService,
    mut set_frozen: impl FnMut(bool) -> Result<()>,
) -> Result<AgentControlMessage> {
    service
        .ensure_supported_operation("Quiesce")
        .map_err(|error| AgentError::bad_request(error.to_string()))?;
    let initial = service.health();
    if initial.quiesced {
        return Err(AgentError::bad_request(
            "invalid lifecycle transition: quiesce",
        ));
    }

    if initial.active_exec_id.is_some() {
        return Err(AgentError::bad_request(
            "quiesce rejected while an execution is active; retry after workload completion",
        ));
    }
    set_frozen(true)?;
    match service.quiesce() {
        Ok(message) => Ok(message),
        Err(error) => {
            if let Err(rollback_error) = set_frozen(false) {
                if rollback_error.requires_fail_closed_action() {
                    return Err(rollback_error);
                }
                return Err(AgentError::quiesce(format!(
                    "quiesce lifecycle commit failed after freezing ({error}); rollback thaw failed: {rollback_error}"
                )));
            }
            Err(AgentError::bad_request(error.to_string()))
        }
    }
}

fn resume_transactional(
    service: &mut MxcControlService,
    mut set_frozen: impl FnMut(bool) -> Result<()>,
) -> Result<AgentControlMessage> {
    service
        .ensure_supported_operation("Resume")
        .map_err(|error| AgentError::bad_request(error.to_string()))?;
    let initial = service.health();
    if !initial.quiesced {
        return Err(AgentError::bad_request(
            "invalid lifecycle transition: resume",
        ));
    }

    set_frozen(false)?;
    match service.resume() {
        Ok(message) => Ok(message),
        Err(error) => {
            if let Err(rollback_error) = set_frozen(true) {
                if rollback_error.requires_fail_closed_action() {
                    return Err(rollback_error);
                }
                return Err(AgentError::quiesce(format!(
                    "resume lifecycle commit failed after thawing ({error}); rollback freeze failed: {rollback_error}"
                )));
            }
            Err(AgentError::bad_request(error.to_string()))
        }
    }
}

#[cfg(feature = "harness-supervisor")]
#[allow(dead_code)]
pub fn harness_quiesce_transactional(
    service: &mut MxcControlService,
    cgroup_dir: &Path,
) -> std::result::Result<(), String> {
    quiesce_transactional(service, |freeze| {
        set_workload_frozen(cgroup_dir, freeze, FREEZE_WAIT_TIMEOUT)?;
        Ok(())
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[cfg(feature = "harness-supervisor")]
#[allow(dead_code)]
pub fn harness_resume_transactional(
    service: &mut MxcControlService,
    cgroup_dir: &Path,
) -> std::result::Result<(), String> {
    resume_transactional(service, |freeze| {
        set_workload_frozen(cgroup_dir, freeze, FREEZE_WAIT_TIMEOUT)
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn set_workload_frozen(cgroup_dir: &Path, freeze: bool, timeout: Duration) -> Result<()> {
    let freeze_path = cgroup_dir.join("cgroup.freeze");
    let events_path = cgroup_dir.join("cgroup.events");
    if !freeze_path.exists() || !events_path.exists() {
        return Err(AgentError::freeze(format!(
            "cgroup freezer interface unavailable at {}",
            cgroup_dir.display()
        )));
    }
    let original = read_cgroup_freeze_value(&freeze_path)?;
    let context = cgroup_dir.display().to_string();
    let mut read_current = || read_cgroup_freeze_value(&freeze_path);
    let mut write_current = |value: bool| {
        std::fs::write(&freeze_path, if value { "1\n" } else { "0\n" })
            .map_err(|error| AgentError::io(format!("writing {}", freeze_path.display()), error))
    };
    let mut read_events = || {
        std::fs::read_to_string(&events_path)
            .map_err(|error| AgentError::io(format!("reading {}", events_path.display()), error))
    };
    let mut sleep = |duration: Duration| thread::sleep(duration);
    let mut ops = FreezerOps {
        context: &context,
        read_current: &mut read_current,
        write_current: &mut write_current,
        read_events: &mut read_events,
        sleep: &mut sleep,
    };
    set_workload_frozen_with_ops(freeze, original, timeout, &mut ops)
}

struct FreezerOps<'a> {
    context: &'a str,
    read_current: &'a mut dyn FnMut() -> Result<bool>,
    write_current: &'a mut dyn FnMut(bool) -> Result<()>,
    read_events: &'a mut dyn FnMut() -> Result<String>,
    sleep: &'a mut dyn FnMut(Duration),
}

fn set_workload_frozen_with_ops(
    freeze: bool,
    original: bool,
    timeout: Duration,
    ops: &mut FreezerOps<'_>,
) -> Result<()> {
    (ops.write_current)(freeze)?;
    match wait_for_frozen_state(freeze, timeout, ops) {
        Ok(()) => Ok(()),
        Err(verify_error) => {
            rollback_cgroup_freeze(original, timeout, ops).map_err(|rollback_error| {
                AgentError::fail_closed(format!(
                    "post-write freezer state uncertainty in {}: verification error ({verify_error}); rollback failed: {rollback_error}",
                    ops.context
                ))
            })?;
            Err(verify_error)
        }
    }
}

fn rollback_cgroup_freeze(
    original: bool,
    timeout: Duration,
    ops: &mut FreezerOps<'_>,
) -> Result<()> {
    (ops.write_current)(original)?;
    wait_for_frozen_state(original, timeout, ops)?;
    let observed = (ops.read_current)()?;
    if observed != original {
        return Err(AgentError::freeze(format!(
            "rollback verification mismatch in {}: expected cgroup.freeze={} observed={}",
            ops.context,
            if original { 1 } else { 0 },
            if observed { 1 } else { 0 }
        )));
    }
    Ok(())
}

fn wait_for_frozen_state(
    expected: bool,
    timeout: Duration,
    ops: &mut FreezerOps<'_>,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| AgentError::freeze("freeze deadline overflow"))?;
    loop {
        let events = (ops.read_events)()?;
        if parse_cgroup_frozen_flag(&events)? == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AgentError::checkpoint_timeout(format!(
                "timed out waiting for cgroup.freeze={} in {}",
                if expected { 1 } else { 0 },
                ops.context
            )));
        }
        (ops.sleep)(Duration::from_millis(10));
    }
}

fn read_cgroup_freeze_value(path: &Path) -> Result<bool> {
    let value = std::fs::read_to_string(path)
        .map_err(|error| AgentError::io(format!("reading {}", path.display()), error))?;
    parse_cgroup_freeze_value(&value)
}

fn parse_cgroup_freeze_value(value: &str) -> Result<bool> {
    match value.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(AgentError::freeze("cgroup.freeze value must be 0 or 1")),
    }
}

fn parse_cgroup_frozen_flag(events: &str) -> Result<bool> {
    for line in events.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        if key != "frozen" {
            continue;
        }
        let Some(value) = fields.next() else {
            return Err(AgentError::freeze(
                "cgroup.events frozen entry missing value",
            ));
        };
        return match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(AgentError::freeze(
                "cgroup.events frozen value must be 0 or 1",
            )),
        };
    }
    Err(AgentError::freeze(
        "cgroup.events missing required frozen entry",
    ))
}

fn install_sigchld_wakeup_handler() -> Result<()> {
    unsafe extern "C" fn sigchld_handler(_signal: i32) {
        SIGCHLD_PENDING.store(true, Ordering::SeqCst);
    }
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_flags = libc::SA_RESTART;
    action.sa_sigaction = sigchld_handler as *const () as usize;
    // SAFETY: action.sa_mask points to valid mutable memory.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(AgentError::io(
            "sigemptyset(SIGCHLD handler)",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: sigaction is called with initialized pointers and SIGCHLD.
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
        return Err(AgentError::io(
            "sigaction(SIGCHLD)",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

struct GuestControlTransport {
    session: GuestControlSession<File>,
    read_buffer: VecDeque<u8>,
    eof_after_reset: bool,
}

impl GuestControlTransport {
    fn connect(file: File, attach_timeout: Duration) -> Result<Self> {
        let mut session = GuestControlSession::new(file);
        let deadline = Instant::now()
            .checked_add(attach_timeout)
            .ok_or_else(|| AgentError::internal("control-session attach deadline overflow"))?;
        session.attach_with_deadline(deadline).map_err(|error| {
            AgentError::internal(format!("control-session attach failed: {error}"))
        })?;
        Ok(Self {
            session,
            read_buffer: VecDeque::new(),
            eof_after_reset: false,
        })
    }

    fn fill_read_buffer(&mut self) -> io::Result<()> {
        if self.eof_after_reset {
            return Ok(());
        }
        match self.session.try_recv_event() {
            Ok(Some(GuestEvent::Data(payload))) => {
                self.read_buffer.extend(payload);
                Ok(())
            }
            Ok(Some(GuestEvent::Reset { .. })) => {
                self.eof_after_reset = true;
                Ok(())
            }
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "control-session idle",
            )),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                error.to_string(),
            )),
        }
    }
}

impl Read for GuestControlTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof_after_reset {
            return Ok(0);
        }
        if self.read_buffer.is_empty() {
            self.fill_read_buffer()?;
            if self.eof_after_reset {
                return Ok(0);
            }
        }
        let mut read = 0usize;
        while read < buf.len() {
            let Some(byte) = self.read_buffer.pop_front() else {
                break;
            };
            buf[read] = byte;
            read += 1;
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "control-session idle",
            ));
        }
        Ok(read)
    }
}

impl Write for GuestControlTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.session
            .send_data(buf.to_vec())
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn open_control_tty_raw_nonblocking(path: &str) -> Result<File> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| AgentError::config("hvc path contains interior NUL"))?;
    // SAFETY: open called with a valid NUL-terminated path and constant flags.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return Err(AgentError::io(
            format!("opening {path}"),
            io::Error::last_os_error(),
        ));
    }
    configure_fd_raw_nonblocking(fd)?;
    // SAFETY: fd is newly opened and transferred to File ownership.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn configure_fd_raw_nonblocking(fd: i32) -> Result<()> {
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: termios points to writable memory.
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(AgentError::io(
            "tcgetattr on control tty",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: tcgetattr succeeded and initialized termios.
    let mut termios = unsafe { termios.assume_init() };
    // SAFETY: cfmakeraw mutates a valid termios struct in place.
    unsafe { libc::cfmakeraw(&mut termios as *mut libc::termios) };
    // SAFETY: tcsetattr writes the configured termios to the same fd.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios as *const libc::termios) } != 0 {
        return Err(AgentError::io(
            "tcsetattr raw mode on control tty",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_GETFL reads descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(AgentError::io(
            "fcntl(F_GETFL) on control tty",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_SETFL writes descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(AgentError::io(
            "fcntl(F_SETFL O_NONBLOCK) on control tty",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::{
        AccessMode, AuthenticateChannelRequest, CanonicalHostMappingRoot, ConfigureSessionRequest,
        CreateProcessRequest, DnsStatus, FlowCreditRequest, HealthStatus, HostControlMessage,
        InnerRecord, LaunchBinding, LaunchIdentity, MappingContainmentPolicy, NetworkMode,
        NetworkSetupState, NetworkStatus, ProcessSupervisor, ProtocolErrorCode, SERVICE_IDENTITY,
        ServiceError, ServiceErrorCode, SessionConfiguration, StreamName, SupervisorEvent,
        SymlinkContainmentPolicy,
    };
    use std::cell::RefCell;
    use std::io::{self, Cursor, Read, Write};
    use std::rc::Rc;

    #[test]
    fn capability_parser_accepts_exact_64_hex_characters() {
        let capability =
            parse_hex_32("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap();
        assert_eq!(capability[0], 0x00);
        assert_eq!(capability[31], 0xff);
    }

    #[test]
    fn capability_parser_rejects_invalid_length_and_digits() {
        assert!(parse_hex_32("0011").is_err());
        assert!(
            parse_hex_32("gg112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .is_err()
        );
    }

    #[test]
    fn cmdline_unique_extraction_rejects_duplicates() {
        let cmdline = "quiet nvx.channel_generation=7 nvx_channel_generation=8";
        let duplicate = extract_unique_cmdline_value(
            cmdline,
            &["nvx.channel_generation", "nvx_channel_generation"],
        );
        assert!(duplicate.is_err());
    }

    #[test]
    fn procfs_startup_guard_is_idempotent_when_cmdline_already_present() {
        let mut mkdir_calls = 0_u32;
        let mut mount_calls = 0_u32;
        ensure_procfs_mounted_with_ops(
            || true,
            || {
                mkdir_calls = mkdir_calls.saturating_add(1);
                Ok(())
            },
            || {
                mount_calls = mount_calls.saturating_add(1);
                Ok(())
            },
        )
        .expect("existing procfs should not trigger setup");
        assert_eq!(mkdir_calls, 0);
        assert_eq!(mount_calls, 0);
    }

    #[test]
    fn procfs_startup_guard_mounts_once_when_cmdline_initially_missing() {
        let mut mount_calls = 0_u32;
        let mut exists_checks = 0_u32;
        ensure_procfs_mounted_with_ops(
            || {
                exists_checks = exists_checks.saturating_add(1);
                exists_checks > 1
            },
            || Ok(()),
            || {
                mount_calls = mount_calls.saturating_add(1);
                Ok(())
            },
        )
        .expect("guard should mount procfs and proceed");
        assert_eq!(mount_calls, 1);
        assert_eq!(exists_checks, 2);
    }

    #[test]
    fn procfs_startup_guard_fails_closed_when_cmdline_stays_missing() {
        let error = ensure_procfs_mounted_with_ops(|| false, || Ok(()), || Ok(()))
            .expect_err("missing cmdline after mount must fail closed");
        assert_eq!(error.code(), crate::error::ErrorCode::FailClosed);
        assert!(
            error
                .to_string()
                .contains("/proc/cmdline is still unavailable"),
            "expected explicit procfs fail-closed reason"
        );
    }

    #[test]
    fn procfs_startup_guard_propagates_mount_failure() {
        let error = ensure_procfs_mounted_with_ops(
            || false,
            || Ok(()),
            || {
                Err(AgentError::io(
                    "mounting procfs on /proc",
                    io::Error::from_raw_os_error(libc::EPERM),
                ))
            },
        )
        .expect_err("mount failure must be surfaced");
        assert_eq!(error.code(), crate::error::ErrorCode::Internal);
    }

    #[test]
    fn procfs_startup_guard_wraps_non_fail_closed_errors_for_pid1_path() {
        let error = ensure_procfs_for_pid1_startup_with_ops(
            || false,
            || {
                Err(AgentError::io(
                    "creating /proc mountpoint",
                    io::Error::from_raw_os_error(libc::EROFS),
                ))
            },
            || Ok(()),
        )
        .expect_err("pid1 guard must fail closed on procfs setup failure");
        assert_eq!(error.code(), crate::error::ErrorCode::FailClosed);
        assert!(error.to_string().contains("requires mounted procfs"));
    }

    #[test]
    fn control_tty_parser_accepts_reserved_hvc_device_and_rejects_boot_console() {
        let control = parse_required_control_tty_arg("quiet nvx_control_tty=hvc2")
            .expect("expected hvc2 to be accepted");
        assert_eq!(control, "/dev/hvc2");
        assert!(parse_required_control_tty_arg("quiet nvx_control_tty=hvc1").is_err());
        assert!(parse_required_control_tty_arg("quiet nvx_control_tty=ttyS0").is_err());
    }

    #[test]
    fn cgroup_frozen_parser_accepts_and_rejects_expected_shapes() {
        assert!(parse_cgroup_frozen_flag("populated 1\nfrozen 1\n").unwrap());
        assert!(!parse_cgroup_frozen_flag("frozen 0\n").unwrap());
        assert!(parse_cgroup_frozen_flag("frozen maybe\n").is_err());
        assert!(parse_cgroup_frozen_flag("populated 1\n").is_err());
    }

    #[test]
    fn openvmm_overhead_constant_remains_conservative() {
        assert!(assert_conservative_openvmm_overhead().is_ok());
        assert_eq!(OPENVMM_OUTER_FRAME_OVERHEAD_BYTES, 44);
    }

    #[test]
    fn no_nic_network_status_is_ready_without_interface_fields() {
        let status = no_nic_network_status();
        assert_eq!(status.mode, NetworkMode::NoNic);
        assert_eq!(status.setup_state, NetworkSetupState::Ready);
        assert!(status.interface.is_none());
        assert!(status.default_gateway.is_none());
        assert!(status.dns.ready);
        assert!(status.failure.is_none());
    }

    #[test]
    fn parses_portable_default_route_and_dns_with_typed_bounds() {
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let gateway = parse_default_route_gateway_ipv4_from_text("eth0", route)
            .expect("parse route")
            .expect("default route");
        assert_eq!(gateway.to_string(), "10.0.0.1");

        let dns = parse_dns_status_from_text(
            "# comment\nnameserver 10.0.0.53\nnameserver 2001:4860:4860::8888\n",
        )
        .expect("parse resolv");
        assert!(dns.ready);
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.servers[0], "10.0.0.53");
    }

    #[test]
    fn portable_status_probe_timeout_returns_typed_failure() {
        let mut probes = 0_u32;
        let status = detect_portable_network_status_with_probe(
            Duration::from_millis(1),
            || {
                probes = probes.saturating_add(1);
                Err(NetworkFailureStatus {
                    code: NetworkFailureCode::RouteMissing,
                    detail: "missing default route".to_string(),
                })
            },
            |_sleep| {},
        );
        assert!(probes >= 1);
        assert_eq!(status.mode, NetworkMode::PortableNetwork);
        assert_eq!(status.setup_state, NetworkSetupState::Failed);
        assert!(matches!(
            status.failure,
            Some(NetworkFailureStatus {
                code: NetworkFailureCode::RouteMissing,
                ..
            })
        ));
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct RuntimeTestSupervisor {
        exec_id: Option<u32>,
        events: VecDeque<SupervisorEvent>,
        acked_events: usize,
        spawn_calls: usize,
        queue_stdin_calls: usize,
        close_stdin_calls: usize,
        terminate_calls: usize,
        kill_calls: usize,
        cleanup_for_disconnect_calls: usize,
        fail_next_spawn: Option<ServiceError>,
        fail_next_close_stdin: Option<ServiceError>,
        fail_next_terminate: Option<ServiceError>,
    }

    impl ProcessSupervisor for RuntimeTestSupervisor {
        fn spawn(
            &mut self,
            request: &CreateProcessRequest,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            if let Some(error) = self.fail_next_spawn.take() {
                return Err(error);
            }
            self.exec_id = Some(request.exec_id);
            self.spawn_calls = self.spawn_calls.saturating_add(1);
            Ok(())
        }

        fn queue_stdin(
            &mut self,
            _exec_id: u32,
            _chunk: Vec<u8>,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            self.queue_stdin_calls = self.queue_stdin_calls.saturating_add(1);
            Ok(())
        }

        fn close_stdin(
            &mut self,
            _exec_id: u32,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            if let Some(error) = self.fail_next_close_stdin.take() {
                return Err(error);
            }
            self.close_stdin_calls = self.close_stdin_calls.saturating_add(1);
            Ok(())
        }

        fn take_stdin_drain_bytes(
            &mut self,
            _exec_id: u32,
        ) -> std::result::Result<usize, agent_protocol::ServiceError> {
            Ok(0)
        }

        fn peek_event(
            &mut self,
            exec_id: u32,
        ) -> std::result::Result<Option<SupervisorEvent>, agent_protocol::ServiceError> {
            if self.exec_id != Some(exec_id) {
                return Ok(None);
            }
            Ok(self.events.front().cloned())
        }

        fn ack_event(
            &mut self,
            _exec_id: u32,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            self.events.pop_front();
            self.acked_events = self.acked_events.saturating_add(1);
            Ok(())
        }

        fn terminate(
            &mut self,
            _exec_id: u32,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            if let Some(error) = self.fail_next_terminate.take() {
                return Err(error);
            }
            self.terminate_calls = self.terminate_calls.saturating_add(1);
            Ok(())
        }

        fn kill(&mut self, _exec_id: u32) -> std::result::Result<(), agent_protocol::ServiceError> {
            self.kill_calls = self.kill_calls.saturating_add(1);
            Ok(())
        }

        fn poll(
            &mut self,
            exec_id: u32,
        ) -> std::result::Result<Option<SupervisorEvent>, agent_protocol::ServiceError> {
            let event = self.peek_event(exec_id)?;
            if event.is_some() {
                self.ack_event(exec_id)?;
            }
            Ok(event)
        }

        fn cleanup_for_disconnect(
            &mut self,
            _exec_id: u32,
            _absolute_deadline: Instant,
        ) -> std::result::Result<bool, agent_protocol::ServiceError> {
            self.cleanup_for_disconnect_calls = self.cleanup_for_disconnect_calls.saturating_add(1);
            Ok(true)
        }
    }

    #[derive(Clone)]
    struct RuntimeTestIo {
        read_cursor: Cursor<Vec<u8>>,
        writes: Rc<RefCell<Vec<u8>>>,
    }

    impl RuntimeTestIo {
        fn new(writes: Rc<RefCell<Vec<u8>>>) -> Self {
            Self {
                read_cursor: Cursor::new(Vec::new()),
                writes,
            }
        }
    }

    impl Read for RuntimeTestIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_cursor.read(buf)
        }
    }

    impl Write for RuntimeTestIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn runtime_test_service() -> MxcControlService {
        let launch = LaunchIdentity {
            generation: 7,
            nonce: [7; 16],
        };
        let binding = LaunchBinding {
            protocol_version: PROTOCOL_VERSION,
            image_version: "img-v1".to_string(),
            launch,
            channel_generation: 17,
        };
        let mut service = MxcControlService::new_pid1_runtime(binding, 4242);
        service
            .authenticate_channel(
                AuthenticateChannelRequest {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch,
                    channel_generation: 17,
                    capability_proof: [7; 32],
                },
                1,
                no_nic_network_status(),
            )
            .unwrap();
        service
            .configure_session(ConfigureSessionRequest {
                protocol_version: PROTOCOL_VERSION,
                image_version: "img-v1".to_string(),
                launch,
                channel_generation: 17,
                idempotent_replay: false,
                configuration: SessionConfiguration {
                    root: CanonicalHostMappingRoot::parse("/sandbox".to_string()).unwrap(),
                    mappings: vec![agent_protocol::ChildMapping {
                        child: agent_protocol::RelativeChildPath::parse("runtime".to_string())
                            .unwrap(),
                        access: AccessMode::ReadOnly,
                    }],
                    containment: MappingContainmentPolicy {
                        symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                        reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    },
                    labels: vec!["runtime".to_string()],
                    attributes: BTreeMap::new(),
                    filesystem: agent_protocol::FilesystemStatus {
                        rootfs_ready: true,
                        detail: "ready".to_string(),
                    },
                    network: portable_network_status(),
                },
            })
            .unwrap();
        service
    }

    fn no_nic_network_status() -> NetworkStatus {
        NetworkStatus {
            mode: NetworkMode::NoNic,
            setup_state: NetworkSetupState::Ready,
            interface: None,
            default_gateway: None,
            dns: DnsStatus {
                ready: true,
                servers: Vec::new(),
            },
            failure: None,
        }
    }

    fn portable_network_status() -> NetworkStatus {
        NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            setup_state: NetworkSetupState::Ready,
            interface: None,
            default_gateway: Some("10.0.0.1".to_string()),
            dns: DnsStatus {
                ready: true,
                servers: vec!["10.0.0.53".to_string()],
            },
            failure: None,
        }
    }

    #[test]
    fn runtime_supervisor_pump_waits_for_full_record_limit_and_replays_once_losslessly() {
        let mut service = runtime_test_service();
        let mut supervisor = RuntimeTestSupervisor::default();
        service.activate_full_lifecycle().unwrap();
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

        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut channel = agent_protocol::HvcFramedChannel::new(RuntimeTestIo::new(writes.clone()));
        let filler = AgentControlMessage::Health(HealthStatus {
            agent_state: agent_protocol::AgentSessionState::Active,
            quiesced: false,
            launch_admitted: true,
            shutting_down: false,
            channel_generation: 17,
            active_exec_id: None,
            filesystem: None,
            network: Some(no_nic_network_status()),
            last_failure: None,
        });
        for _ in 0..agent_protocol::DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS {
            channel.queue_control_message(&filler).unwrap();
        }
        assert_eq!(
            channel.queue_control_message(&filler).unwrap_err().code,
            ServiceErrorCode::Backpressure
        );

        pump_supervisor_to_channel_lossless(&mut service, &mut supervisor, &mut channel).unwrap();
        assert!(matches!(
            supervisor.events.front(),
            Some(SupervisorEvent::StdoutChunk(chunk)) if chunk == &vec![9, 0, 9]
        ));
        assert_eq!(supervisor.acked_events, 0);

        while channel.flush_once().unwrap() {}
        pump_supervisor_to_channel_lossless(&mut service, &mut supervisor, &mut channel).unwrap();
        while channel.flush_once().unwrap() {}

        let mut readback =
            agent_protocol::HvcFramedChannel::new(Cursor::new(writes.borrow().clone()));
        let mut observed = Vec::new();
        while let Some(record) = readback.read_next_inner_record().unwrap() {
            observed.push(serde_json::from_slice::<AgentControlMessage>(&record.payload).unwrap());
        }
        let last_three = observed.split_off(observed.len() - 3);
        assert!(matches!(
            &last_three[0],
            AgentControlMessage::StdoutChunk(agent_protocol::StdoutChunkRecord { chunk, .. })
                if chunk == &vec![9, 0, 9]
        ));
        assert!(matches!(
            &last_three[1],
            AgentControlMessage::StdoutEof(agent_protocol::StdoutEofRecord { .. })
        ));
        assert!(matches!(
            &last_three[2],
            AgentControlMessage::StreamDrained {
                stream: StreamName::Stdout,
                ..
            }
        ));
        assert_eq!(supervisor.acked_events, 2);
    }

    #[test]
    fn runtime_supervisor_pump_waits_for_delayed_flow_credits_without_failing_pid1() {
        let mut service = runtime_test_service();
        let mut supervisor = RuntimeTestSupervisor::default();
        service.activate_full_lifecycle().unwrap();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 66,
                    argv: vec!["/bin/cat".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        supervisor
            .events
            .push_back(SupervisorEvent::StdoutChunk(vec![1, 0, 2, 0, 3]));
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Exited {
            exit_code: 0,
            termination: None,
        });

        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut channel = agent_protocol::HvcFramedChannel::new(RuntimeTestIo::new(writes.clone()));

        pump_supervisor_to_channel_lossless(&mut service, &mut supervisor, &mut channel).unwrap();
        assert!(matches!(
            supervisor.events.front(),
            Some(SupervisorEvent::StdoutChunk(chunk)) if chunk == &vec![1, 0, 2, 0, 3]
        ));
        assert_eq!(
            supervisor.acked_events, 0,
            "front event must not be consumed"
        );
        assert_eq!(
            service.active_exec_id(),
            Some(66),
            "runtime service must stay alive"
        );

        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id: 66,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .unwrap();
        while matches!(
            service
                .pump_supervisor_to_channel(&mut supervisor, &mut channel)
                .unwrap(),
            agent_protocol::service::PumpSupervisorResult::WouldBlock
        ) {}
        while channel.flush_once().unwrap() {}

        let mut readback =
            agent_protocol::HvcFramedChannel::new(Cursor::new(writes.borrow().clone()));
        let mut observed = Vec::new();
        while let Some(record) = readback.read_next_inner_record().unwrap() {
            observed.push(serde_json::from_slice::<AgentControlMessage>(&record.payload).unwrap());
        }
        assert!(matches!(
            observed.first(),
            Some(AgentControlMessage::StdoutChunk(agent_protocol::StdoutChunkRecord {
                chunk,
                ..
            })) if chunk == &vec![1, 0, 2, 0, 3]
        ));
        assert!(observed.iter().any(|message| {
            matches!(
                message,
                AgentControlMessage::ExecTerminal {
                    disposition: agent_protocol::ExecDisposition::ExitCode(0),
                    ..
                }
            )
        }));
        assert_eq!(service.active_exec_id(), None);
    }

    #[test]
    fn quiesce_freezes_and_marks_service_quiesced_after_runtime_activation() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();

        let mut touched_freezer = false;
        let message = quiesce_transactional(&mut service, |_freeze| {
            touched_freezer = true;
            Ok(())
        })
        .unwrap();
        assert!(touched_freezer);
        assert!(matches!(message, AgentControlMessage::Quiesced));
        assert!(service.health().quiesced);
    }

    #[test]
    fn resume_requires_quiesced_state_after_runtime_activation() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();

        let mut touched_freezer = false;
        let error = resume_transactional(&mut service, |_freeze| {
            touched_freezer = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!touched_freezer);
        assert_eq!(error.code(), crate::error::ErrorCode::BadRequest);
        assert!(error.to_string().contains("invalid lifecycle transition"));
        assert!(!service.health().quiesced);
    }

    #[test]
    fn quiesce_rejects_active_execution_without_freezing() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        let mut supervisor = RuntimeTestSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 9,
                    argv: vec!["/bin/sleep".to_string(), "1".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        assert_eq!(service.active_exec_id(), Some(9));

        let mut touched_freezer = false;
        let error = quiesce_transactional(&mut service, |_freeze| {
            touched_freezer = true;
            Ok(())
        })
        .unwrap_err();

        assert!(!touched_freezer);
        assert_eq!(error.code(), crate::error::ErrorCode::BadRequest);
        assert!(
            error
                .to_string()
                .contains("quiesce rejected while an execution is active")
        );
        assert!(!service.health().quiesced);
        assert_eq!(service.active_exec_id(), Some(9));
    }

    #[derive(Default)]
    struct FakeFreezer {
        freeze_value: bool,
        writes: Vec<bool>,
        event_reads: VecDeque<Result<String>>,
    }

    impl FakeFreezer {
        fn with_original(original: bool) -> Self {
            Self {
                freeze_value: original,
                writes: Vec::new(),
                event_reads: VecDeque::new(),
            }
        }
    }

    fn run_fake_set_workload_frozen(
        freezer: Rc<RefCell<FakeFreezer>>,
        requested: bool,
        timeout: Duration,
    ) -> Result<()> {
        let original = freezer.borrow().freeze_value;
        let mut read_current = {
            let freezer = Rc::clone(&freezer);
            move || Ok(freezer.borrow().freeze_value)
        };
        let mut write_current = {
            let freezer = Rc::clone(&freezer);
            move |value: bool| {
                let mut freezer = freezer.borrow_mut();
                freezer.freeze_value = value;
                freezer.writes.push(value);
                Ok(())
            }
        };
        let mut read_events = {
            let freezer = Rc::clone(&freezer);
            move || {
                let mut freezer = freezer.borrow_mut();
                if let Some(next) = freezer.event_reads.pop_front() {
                    return next;
                }
                Ok(format!(
                    "frozen {}\n",
                    if freezer.freeze_value { 1 } else { 0 }
                ))
            }
        };
        let mut sleep = |_duration: Duration| {};
        let mut ops = FreezerOps {
            context: "fake-freezer",
            read_current: &mut read_current,
            write_current: &mut write_current,
            read_events: &mut read_events,
            sleep: &mut sleep,
        };
        set_workload_frozen_with_ops(requested, original, timeout, &mut ops)
    }

    #[test]
    fn fake_freezer_timeout_after_write_rolls_back_and_retry_succeeds() {
        let freezer = Rc::new(RefCell::new(FakeFreezer::with_original(false)));
        freezer
            .borrow_mut()
            .event_reads
            .push_back(Ok("frozen 0\n".to_string()));
        let error =
            run_fake_set_workload_frozen(freezer.clone(), true, Duration::ZERO).unwrap_err();
        assert_eq!(error.code(), crate::error::ErrorCode::CheckpointTimeout);
        assert!(!error.requires_fail_closed_action());
        assert!(!freezer.borrow().freeze_value);
        assert_eq!(freezer.borrow().writes, vec![true, false]);

        run_fake_set_workload_frozen(freezer.clone(), true, Duration::from_millis(20)).unwrap();
        assert!(freezer.borrow().freeze_value);
    }

    #[test]
    fn fake_freezer_read_error_after_write_rolls_back_and_retry_succeeds() {
        let freezer = Rc::new(RefCell::new(FakeFreezer::with_original(false)));
        freezer
            .borrow_mut()
            .event_reads
            .push_back(Err(AgentError::io(
                "reading fake cgroup.events",
                io::Error::other("injected read failure"),
            )));
        let error = run_fake_set_workload_frozen(freezer.clone(), true, Duration::from_millis(20))
            .unwrap_err();
        assert_eq!(error.code(), crate::error::ErrorCode::Internal);
        assert!(!error.requires_fail_closed_action());
        assert!(!freezer.borrow().freeze_value);
        assert_eq!(freezer.borrow().writes, vec![true, false]);

        run_fake_set_workload_frozen(freezer.clone(), true, Duration::from_millis(20)).unwrap();
        assert!(freezer.borrow().freeze_value);
    }

    #[test]
    fn fake_freezer_parse_error_after_write_rolls_back_and_retry_succeeds() {
        let freezer = Rc::new(RefCell::new(FakeFreezer::with_original(false)));
        freezer
            .borrow_mut()
            .event_reads
            .push_back(Ok("frozen maybe\n".to_string()));
        let error = run_fake_set_workload_frozen(freezer.clone(), true, Duration::from_millis(20))
            .unwrap_err();
        assert_eq!(error.code(), crate::error::ErrorCode::FreezeFailed);
        assert!(!error.requires_fail_closed_action());
        assert!(!freezer.borrow().freeze_value);
        assert_eq!(freezer.borrow().writes, vec![true, false]);

        run_fake_set_workload_frozen(freezer.clone(), true, Duration::from_millis(20)).unwrap();
        assert!(freezer.borrow().freeze_value);
    }

    #[test]
    fn fake_freezer_rollback_verification_failure_returns_fail_closed_error() {
        let freezer = Rc::new(RefCell::new(FakeFreezer::with_original(false)));
        freezer
            .borrow_mut()
            .event_reads
            .push_back(Err(AgentError::io(
                "reading fake cgroup.events",
                io::Error::other("injected read failure"),
            )));
        freezer
            .borrow_mut()
            .event_reads
            .push_back(Err(AgentError::io(
                "reading fake cgroup.events",
                io::Error::other("injected rollback verification failure"),
            )));
        let error = run_fake_set_workload_frozen(freezer.clone(), true, Duration::from_millis(20))
            .unwrap_err();
        assert!(error.requires_fail_closed_action());
        assert_eq!(error.code(), crate::error::ErrorCode::FailClosed);
        assert!(!freezer.borrow().freeze_value);
        assert_eq!(freezer.borrow().writes, vec![true, false]);
    }

    fn runtime_test_binding() -> LaunchBinding {
        LaunchBinding {
            protocol_version: PROTOCOL_VERSION,
            image_version: "img-v1".to_string(),
            launch: LaunchIdentity {
                generation: 7,
                nonce: [7; 16],
            },
            channel_generation: 17,
        }
    }

    fn control_record(message: &HostControlMessage) -> agent_protocol::InnerRecord {
        InnerRecord::control(message).expect("control record")
    }

    #[test]
    fn phase0_handle_host_record_rejects_unavailable_operations_without_side_effects() {
        let binding = runtime_test_binding();
        let mut service = runtime_test_service();
        let mut supervisor = RuntimeTestSupervisor::default();
        let mut pending_hello = None;
        let mut active_timeout = None;
        let mut writable_mapping_paths = Vec::new();

        let baseline_health = service.health();
        let baseline_active_exec = service.active_exec_id();
        let baseline_supervisor = supervisor.clone();

        let operations = [
            HostControlMessage::CreateProcess {
                exec_id: 41,
                argv: vec!["/bin/echo".to_string(), "ok".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            HostControlMessage::FlowCredits(FlowCreditRequest {
                exec_id: 41,
                stream: StreamName::Stdout,
                credits: 1,
            }),
            HostControlMessage::StdinChunk(agent_protocol::StdinChunkRecord {
                exec_id: 41,
                sequence: 0,
                chunk: b"input".to_vec(),
            }),
            HostControlMessage::StdinEof(agent_protocol::StdinEofRecord {
                exec_id: 41,
                sequence: 1,
            }),
            HostControlMessage::CancelExecution { exec_id: 41 },
            HostControlMessage::Quiesce,
            HostControlMessage::Resume,
            HostControlMessage::Shutdown {
                grace_timeout_ms: 100,
            },
        ];

        for operation in operations {
            let mut dispatch = HostDispatchContext {
                service: &mut service,
                supervisor: &mut supervisor,
                pending_hello: &mut pending_hello,
                active_timeout: &mut active_timeout,
                writable_mapping_paths: &mut writable_mapping_paths,
                isolation_holder_pid: 4242,
                received_at: Instant::now(),
            };
            let outbound = handle_host_record(&binding, &mut dispatch, control_record(&operation))
                .expect("dispatch");
            assert!(!outbound.fatal_session);
            assert_eq!(outbound.messages.len(), 1);
            assert!(matches!(
                &outbound.messages[0],
                AgentControlMessage::Error(ProtocolErrorDetail {
                    code: ProtocolErrorCode::UnsupportedOperation,
                    ..
                })
            ));
            assert_eq!(service.health(), baseline_health);
            assert_eq!(service.active_exec_id(), baseline_active_exec);
            assert!(pending_hello.is_none());
            assert!(active_timeout.is_none());
            assert_eq!(supervisor, baseline_supervisor);
        }
    }

    #[test]
    fn create_process_fatal_session_error_maps_to_typed_protocol_error_and_stop_signal() {
        let binding = runtime_test_binding();
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        let mut supervisor = RuntimeTestSupervisor {
            fail_next_spawn: Some(ServiceError {
                code: ServiceErrorCode::FatalSession,
                message: "Supervisor: spawning process: post-spawn rollback cleanup uncertainty: rollback cleanup actions failed: waiting for spawned child rollback: injected".to_string(),
            }),
            ..RuntimeTestSupervisor::default()
        };
        let mut pending_hello = None;
        let mut active_timeout = None;
        let mut writable_mapping_paths = Vec::new();
        let mut dispatch = HostDispatchContext {
            service: &mut service,
            supervisor: &mut supervisor,
            pending_hello: &mut pending_hello,
            active_timeout: &mut active_timeout,
            writable_mapping_paths: &mut writable_mapping_paths,
            isolation_holder_pid: 4242,
            received_at: Instant::now(),
        };

        let outbound = handle_host_record(
            &binding,
            &mut dispatch,
            control_record(&HostControlMessage::CreateProcess {
                exec_id: 89,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 1".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            }),
        )
        .expect("dispatch");

        assert!(outbound.fatal_session);
        assert!(matches!(
            outbound.messages.as_slice(),
            [AgentControlMessage::Error(ProtocolErrorDetail {
                code: ProtocolErrorCode::FatalSession,
                ..
            })]
        ));
        let blocked = service
            .create_process(
                CreateProcessRequest {
                    exec_id: 90,
                    argv: vec!["/bin/echo".to_string(), "blocked".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .expect_err("fatal service state must block further executions");
        assert_eq!(blocked.code, ServiceErrorCode::FatalSession);
    }

    #[test]
    fn timeout_enforcement_retries_without_clearing_active_deadline_on_recoverable_failure() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        let mut supervisor = RuntimeTestSupervisor {
            fail_next_close_stdin: Some(ServiceError {
                code: ServiceErrorCode::Backpressure,
                message: "injected close-stdin backpressure".to_string(),
            }),
            ..RuntimeTestSupervisor::default()
        };
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 204,
                    argv: vec!["/bin/sleep".to_string(), "10".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(1),
                },
                &mut supervisor,
            )
            .unwrap();
        let mut active_timeout = Some((204, Instant::now() - Duration::from_millis(1)));
        let mut pending_outbound = VecDeque::new();
        let mut fatal_shutdown = None;

        enforce_active_timeout(
            &mut service,
            &mut supervisor,
            &mut active_timeout,
            &mut pending_outbound,
            &mut fatal_shutdown,
        )
        .unwrap();

        assert_eq!(active_timeout.map(|(exec_id, _)| exec_id), Some(204));
        assert!(fatal_shutdown.is_none());
        assert!(pending_outbound.is_empty());
        assert_eq!(service.active_exec_id(), Some(204));
    }

    #[test]
    fn timeout_enforcement_fatal_failure_enters_bounded_fatal_shutdown_and_enqueues_error() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        let mut supervisor = RuntimeTestSupervisor {
            fail_next_terminate: Some(ServiceError {
                code: ServiceErrorCode::FatalSession,
                message: "injected terminate uncertainty".to_string(),
            }),
            ..RuntimeTestSupervisor::default()
        };
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 205,
                    argv: vec!["/bin/sleep".to_string(), "10".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(1),
                },
                &mut supervisor,
            )
            .unwrap();
        let mut active_timeout = Some((205, Instant::now() - Duration::from_millis(1)));
        let mut pending_outbound = VecDeque::new();
        let mut fatal_shutdown = None;

        enforce_active_timeout(
            &mut service,
            &mut supervisor,
            &mut active_timeout,
            &mut pending_outbound,
            &mut fatal_shutdown,
        )
        .unwrap();

        assert_eq!(supervisor.cleanup_for_disconnect_calls, 1);
        assert_eq!(service.active_exec_id(), None);
        assert!(fatal_shutdown.is_some());
        assert!(matches!(
            pending_outbound.front(),
            Some(AgentControlMessage::Error(ProtocolErrorDetail {
                code: ProtocolErrorCode::FatalSession,
                ..
            }))
        ));
    }

    #[test]
    fn timeout_enforcement_fatal_failure_with_full_pending_queue_still_starts_cleanup_and_deadline_stop()
     {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        let mut supervisor = RuntimeTestSupervisor {
            fail_next_terminate: Some(ServiceError {
                code: ServiceErrorCode::FatalSession,
                message: "injected terminate uncertainty".to_string(),
            }),
            ..RuntimeTestSupervisor::default()
        };
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 207,
                    argv: vec!["/bin/sleep".to_string(), "10".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(1),
                },
                &mut supervisor,
            )
            .unwrap();
        let mut active_timeout = Some((207, Instant::now() - Duration::from_millis(1)));
        let mut pending_outbound = VecDeque::new();
        for _ in 0..OUTBOUND_PENDING_LIMIT {
            pending_outbound.push_back(AgentControlMessage::Error(ProtocolErrorDetail {
                code: ProtocolErrorCode::InvalidLifecycleTransition,
                message: "prefill".to_string(),
            }));
        }
        let mut fatal_shutdown = None;

        enforce_active_timeout(
            &mut service,
            &mut supervisor,
            &mut active_timeout,
            &mut pending_outbound,
            &mut fatal_shutdown,
        )
        .unwrap();

        assert_eq!(supervisor.cleanup_for_disconnect_calls, 1);
        assert_eq!(service.active_exec_id(), None);
        assert_eq!(
            pending_outbound.len(),
            OUTBOUND_PENDING_LIMIT,
            "fatal delivery must remain best-effort under pending queue saturation"
        );
        let state = fatal_shutdown.as_ref().expect("fatal shutdown state");
        assert!(should_stop_after_fatal_delivery(
            state,
            false,
            true,
            state.delivery_deadline + Duration::from_millis(1),
        ));
    }

    #[test]
    fn fatal_shutdown_starts_cleanup_immediately_and_stops_by_delivery_deadline_when_writer_blocked()
     {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        let mut supervisor = RuntimeTestSupervisor::default();
        service
            .create_process(
                CreateProcessRequest {
                    exec_id: 206,
                    argv: vec!["/bin/sleep".to_string(), "10".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .unwrap();
        let mut fatal_shutdown = None;
        let start = Instant::now();
        start_fatal_shutdown(
            &mut service,
            &mut supervisor,
            &mut fatal_shutdown,
            "injected fatal protocol failure".to_string(),
            start,
        );
        assert_eq!(
            supervisor.cleanup_for_disconnect_calls, 1,
            "fatal-session cleanup must begin immediately even if outbound delivery is blocked"
        );
        assert_eq!(service.active_exec_id(), None);
        let state = fatal_shutdown.as_ref().expect("fatal shutdown state");

        let pending_outbound_empty = false;
        let has_queued_writes = true;
        assert!(!should_stop_after_fatal_delivery(
            state,
            pending_outbound_empty,
            has_queued_writes,
            start,
        ));
        assert!(should_stop_after_fatal_delivery(
            state,
            pending_outbound_empty,
            has_queued_writes,
            start + FATAL_SESSION_DELIVERY_DEADLINE + Duration::from_millis(1),
        ));
    }

    #[test]
    fn shutdown_blocked_writer_honors_requested_deadline_without_extension() {
        assert!(!harness_should_complete_shutdown_when_writer_blocked(
            None, 10, 9
        ));
        assert!(harness_should_complete_shutdown_when_writer_blocked(
            None, 10, 10
        ));
        assert!(harness_should_complete_shutdown_when_writer_blocked(
            None, 10, 11
        ));
    }

    #[test]
    fn mapping_sync_helper_deadline_timeout_is_bounded_and_fail_closed() {
        let root = std::env::temp_dir().join("nvx-agent-runtime-sync-timeout");
        let _ = std::fs::create_dir_all(&root);
        SYNC_HELPER_BLOCK_MS.store(300, Ordering::SeqCst);
        SYNC_HELPER_UNREAPABLE_AFTER_KILL.store(false, Ordering::SeqCst);
        let mut pending_sync_helper_pids = Vec::new();
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(50))
            .unwrap_or(started);
        let result = bounded_sync_writable_mappings_until_deadline(
            deadline,
            &[root],
            &mut pending_sync_helper_pids,
        );
        SYNC_HELPER_BLOCK_MS.store(0, Ordering::SeqCst);
        reap_pending_sync_helpers_nonblocking(&mut pending_sync_helper_pids);
        assert!(
            result.is_err(),
            "blocked helper must fail closed at deadline"
        );
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "pid1 wait must remain bounded by caller deadline",
        );
    }

    #[test]
    fn mapping_sync_helper_honors_very_short_valid_deadline() {
        let root = std::env::temp_dir().join("nvx-agent-runtime-sync-short");
        let _ = std::fs::create_dir_all(&root);
        SYNC_HELPER_BLOCK_MS.store(200, Ordering::SeqCst);
        SYNC_HELPER_UNREAPABLE_AFTER_KILL.store(false, Ordering::SeqCst);
        let mut pending_sync_helper_pids = Vec::new();
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(1))
            .unwrap_or(started);
        let result = bounded_sync_writable_mappings_until_deadline(
            deadline,
            &[root],
            &mut pending_sync_helper_pids,
        );
        SYNC_HELPER_BLOCK_MS.store(0, Ordering::SeqCst);
        reap_pending_sync_helpers_nonblocking(&mut pending_sync_helper_pids);
        assert!(
            result.is_err(),
            "very short deadline must fail closed quickly"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "sync helper wait exceeded very short caller deadline bound",
        );
    }

    #[test]
    fn mapping_sync_helper_timeout_tracks_unreaped_helper_without_blocking_pid1() {
        let root = std::env::temp_dir().join("nvx-agent-runtime-sync-unreapable");
        let _ = std::fs::create_dir_all(&root);
        SYNC_HELPER_BLOCK_MS.store(300, Ordering::SeqCst);
        SYNC_HELPER_UNREAPABLE_AFTER_KILL.store(true, Ordering::SeqCst);
        let mut pending_sync_helper_pids = Vec::new();
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(20))
            .unwrap_or(started);
        let result = bounded_sync_writable_mappings_until_deadline(
            deadline,
            &[root],
            &mut pending_sync_helper_pids,
        );
        SYNC_HELPER_UNREAPABLE_AFTER_KILL.store(false, Ordering::SeqCst);
        SYNC_HELPER_BLOCK_MS.store(0, Ordering::SeqCst);
        assert!(result.is_err(), "timeout must fail closed");
        let message = format!(
            "{}",
            result.expect_err("sync helper timeout must return error")
        );
        assert!(
            message.contains("tracked"),
            "must report tracked unreaped helper"
        );
        assert!(
            !pending_sync_helper_pids.is_empty(),
            "must retain unreaped helper pid for deferred reap"
        );
        assert!(
            started.elapsed() <= Duration::from_millis(400),
            "deadline path must not block on waitpid after timeout"
        );
        reap_pending_sync_helpers_nonblocking(&mut pending_sync_helper_pids);
    }
}
