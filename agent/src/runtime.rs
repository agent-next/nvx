// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_protocol::{
    AgentControlMessage, AuthenticateChannelRequest, BuildStatus, CancelReason, ChannelReadResult,
    ConfigureSessionRequest, CreateProcessRequest, HVC1_DEVICE_PATH, HostControlMessage,
    LaunchBinding, LaunchIdentity, MappingContainmentPolicy, MxcControlService, NetworkMode,
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
const DEFAULT_GUEST_MAPPING_ROOT: &str = "/mnt/virtiofs";
const DEFAULT_WORKLOAD_CGROUP_PATH: &str = "/sys/fs/cgroup/nvx.workload";
const OUTBOUND_PENDING_LIMIT: usize = 256;
const FREEZE_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

static SIGCHLD_PENDING: AtomicBool = AtomicBool::new(false);

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
    service.set_expected_capability(launch_config.expected_capability);
    let mut supervisor = LinuxProcessSupervisor::new_with_holder(isolation_result.holder_pid)
        .map_err(|error| AgentError::internal(error.to_string()))?;
    let mut pending_hello: Option<AuthenticateChannelRequest> = None;
    let mut active_timeout: Option<(u32, Instant)> = None;
    let mut pending_outbound = VecDeque::new();
    let mut shutdown_requested = false;
    let mut shutdown_cleanup_started = false;
    let mut fatal_session_reason: Option<String> = None;

    loop {
        let file = open_hvc1_raw_nonblocking(HVC1_DEVICE_PATH)?;
        let mut channel = agent_protocol::HvcFramedChannel::new(file);

        loop {
            if let Some((exec_id, deadline)) = active_timeout
                && Instant::now() >= deadline
            {
                let _ = service.cancel_exec(exec_id, CancelReason::TimedOut, &mut supervisor);
                active_timeout = None;
            }

            drain_outbound_to_channel(&mut channel, &mut pending_outbound)?;
            pump_supervisor_to_channel_lossless(&mut service, &mut supervisor, &mut channel)?;
            if service.active_exec_id().is_none() {
                active_timeout = None;
            }
            while channel
                .flush_once()
                .map_err(|error| AgentError::internal(error.to_string()))?
            {}

            if let Some(reason) = fatal_session_reason.as_deref()
                && pending_outbound.is_empty()
                && !channel.has_queued_writes()
            {
                let reason = AgentError::fail_closed(format!(
                    "fatal session protocol error requires runtime stop: {reason}"
                ));
                fail_closed_cleanup_and_stop(&mut service, &mut supervisor, &reason);
                return Ok(());
            }

            if shutdown_requested && !shutdown_cleanup_started {
                if let Some(exec_id) = service.active_exec_id() {
                    supervisor
                        .close_stdin(exec_id)
                        .map_err(|error| AgentError::internal(error.to_string()))?;
                    supervisor
                        .terminate(exec_id)
                        .map_err(|error| AgentError::internal(error.to_string()))?;
                }
                shutdown_cleanup_started = true;
            }

            if shutdown_requested
                && service.active_exec_id().is_none()
                && pending_outbound.is_empty()
                && !channel.has_queued_writes()
            {
                return Ok(());
            }

            if service.active_exec_id().is_none() {
                isolation::reap_all_children();
            }

            if fatal_session_reason.is_some() {
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
                    shutdown_requested = false;
                    shutdown_cleanup_started = false;
                    break;
                }
                ChannelReadResult::Record(record) => {
                    let outbound = handle_host_record(
                        &binding,
                        &mut service,
                        &mut supervisor,
                        &mut pending_hello,
                        &mut active_timeout,
                        isolation_holder_pid,
                        record,
                    );
                    let outbound = match outbound {
                        Ok(messages) => messages,
                        Err(error) if error.requires_fail_closed_action() => {
                            fail_closed_cleanup_and_stop(&mut service, &mut supervisor, &error);
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    };
                    if outbound.fatal_session && fatal_session_reason.is_none() {
                        fatal_session_reason =
                            outbound.messages.iter().find_map(|message| match message {
                                AgentControlMessage::Error(detail)
                                    if detail.code == ProtocolErrorCode::FatalSession =>
                                {
                                    Some(detail.message.clone())
                                }
                                _ => None,
                            });
                    }
                    for message in outbound.messages {
                        if matches!(message, AgentControlMessage::ShuttingDown) {
                            shutdown_requested = true;
                        }
                        enqueue_outbound(&mut pending_outbound, message)?;
                    }
                }
            }
        }
    }
}

fn handle_host_record<S: ProcessSupervisor>(
    binding: &LaunchBinding,
    service: &mut MxcControlService,
    supervisor: &mut S,
    pending_hello: &mut Option<AuthenticateChannelRequest>,
    active_timeout: &mut Option<(u32, Instant)>,
    isolation_holder_pid: libc::pid_t,
    record: agent_protocol::InnerRecord,
) -> Result<HostRecordOutcome> {
    if record.kind != agent_protocol::InnerRecordKind::Control {
        return Ok(HostRecordOutcome {
            messages: vec![AgentControlMessage::Error(ProtocolErrorDetail {
                code: ProtocolErrorCode::InvalidLifecycleTransition,
                message: "non-control record on control channel".to_string(),
            })],
            fatal_session: false,
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
            });
        }
    };
    match handle_host_message(
        binding,
        service,
        supervisor,
        pending_hello,
        active_timeout,
        isolation_holder_pid,
        host_message,
    ) {
        Ok(messages) => Ok(HostRecordOutcome {
            messages,
            fatal_session: false,
        }),
        Err(HostDispatchError::Service(error)) => {
            let detail = protocol_error_from_service(error);
            let fatal_session = detail.code == ProtocolErrorCode::FatalSession;
            Ok(HostRecordOutcome {
                messages: vec![AgentControlMessage::Error(detail)],
                fatal_session,
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
    service: &mut MxcControlService,
    supervisor: &mut S,
    pending_hello: &mut Option<AuthenticateChannelRequest>,
    active_timeout: &mut Option<(u32, Instant)>,
    isolation_holder_pid: libc::pid_t,
    message: HostControlMessage,
) -> std::result::Result<Vec<AgentControlMessage>, HostDispatchError> {
    match message {
        HostControlMessage::HostHello {
            service: remote_service,
            protocol_version,
            launch,
            capability_proof,
        } => {
            if remote_service != SERVICE_IDENTITY {
                return Ok(vec![AgentControlMessage::Error(ProtocolErrorDetail {
                    code: ProtocolErrorCode::UnsupportedService,
                    message: format!("unsupported service identity {remote_service}"),
                })]);
            }
            if protocol_version != PROTOCOL_VERSION {
                return Ok(vec![AgentControlMessage::Error(ProtocolErrorDetail {
                    code: ProtocolErrorCode::UnsupportedProtocolVersion,
                    message: format!("unsupported protocol version {protocol_version}"),
                })]);
            }
            *pending_hello = Some(AuthenticateChannelRequest {
                service: remote_service,
                protocol_version,
                launch,
                channel_generation: binding.channel_generation,
                capability_proof: capability_proof.to_bytes(),
            });
            Ok(Vec::new())
        }
        HostControlMessage::Configure {
            launch,
            root,
            mappings,
            containment,
        } => {
            let Some(authentication) = pending_hello.clone() else {
                return Ok(vec![AgentControlMessage::Error(ProtocolErrorDetail {
                    code: ProtocolErrorCode::ChannelAuthenticationRequired,
                    message: "host hello is required before configure".to_string(),
                })]);
            };
            let network = detect_network_status();
            let guest_mount_root = GuestMountRoot::parse(DEFAULT_GUEST_MAPPING_ROOT.to_string())?;
            let _ = service.authenticate_channel(authentication, now_secs(), network.clone())?;
            let resolved_mappings = resolve_declared_mappings(&guest_mount_root, &mappings)?;
            let configuration = session_configuration_from_host(
                launch,
                root,
                mappings,
                containment,
                network.clone(),
            )?;
            service.configure_session(ConfigureSessionRequest {
                protocol_version: binding.protocol_version,
                image_version: binding.image_version.clone(),
                launch,
                channel_generation: binding.channel_generation,
                idempotent_replay: false,
                configuration,
            })?;
            install_resolved_mappings_in_holder_mount_namespace(
                isolation_holder_pid,
                guest_mount_root.as_str(),
                &resolved_mappings,
            )
            .map_err(|error| {
                AgentError::fail_closed(format!(
                    "mapping installation failed after configuration commit: {error}"
                ))
            })?;
            service.activate_full_lifecycle()?;
            let _ = service.wait_ready(WaitReadyRequest {
                protocol_version: binding.protocol_version,
                image_version: binding.image_version.clone(),
                launch,
                channel_generation: binding.channel_generation,
            });
            Ok(vec![AgentControlMessage::Ready {
                launch,
                status: ready_status(service, network),
            }])
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
            service.create_process(
                CreateProcessRequest {
                    exec_id,
                    argv,
                    cwd,
                    env,
                    timeout_ms,
                },
                supervisor,
            )?;
            if let Some(deadline) = timeout_deadline {
                *active_timeout = Some((exec_id, deadline));
            }
            Ok(Vec::new())
        }
        HostControlMessage::CancelExecution { exec_id } => {
            service.cancel_exec(exec_id, CancelReason::Cancelled, supervisor)?;
            Ok(Vec::new())
        }
        HostControlMessage::FlowCredits(request) => {
            service.grant_flow_credits(request)?;
            Ok(Vec::new())
        }
        HostControlMessage::StdinChunk(record) => {
            service.stdin_chunk(record, supervisor)?;
            Ok(Vec::new())
        }
        HostControlMessage::StdinEof(record) => {
            service.stdin_eof(record, supervisor)?;
            Ok(Vec::new())
        }
        HostControlMessage::Health => {
            let snapshot = service.health();
            Ok(vec![AgentControlMessage::Health(
                agent_protocol::HealthStatus {
                    quiesced: snapshot.quiesced,
                    launch_admitted: snapshot.launch_admitted,
                },
            )])
        }
        HostControlMessage::Quiesce => {
            service.ensure_supported_operation("Quiesce")?;
            Ok(vec![quiesce_transactional(service, |freeze| {
                // SAFETY: sync has no memory-safety preconditions.
                unsafe { libc::sync() };
                set_workload_frozen(
                    Path::new(DEFAULT_WORKLOAD_CGROUP_PATH),
                    freeze,
                    FREEZE_WAIT_TIMEOUT,
                )?;
                // SAFETY: sync has no memory-safety preconditions.
                unsafe { libc::sync() };
                Ok(())
            })?])
        }
        HostControlMessage::Resume => {
            service.ensure_supported_operation("Resume")?;
            Ok(vec![resume_transactional(service, |freeze| {
                set_workload_frozen(
                    Path::new(DEFAULT_WORKLOAD_CGROUP_PATH),
                    freeze,
                    FREEZE_WAIT_TIMEOUT,
                )
            })?])
        }
        HostControlMessage::Shutdown { .. } => Ok(vec![service.shutdown()?]),
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
    let mut adapters = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" {
                adapters.push(name);
            }
        }
    }
    if adapters.is_empty() {
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        }
    } else {
        adapters.sort();
        NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some(format!("interfaces={}", adapters.join(","))),
        }
    }
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
    expected_capability: [u8; 32],
}

struct HostRecordOutcome {
    messages: Vec<AgentControlMessage>,
    fatal_session: bool,
}

fn read_launch_binding() -> Result<LaunchRuntimeConfig> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|error| AgentError::io("reading /proc/cmdline", error))?;
    let channel_generation = parse_required_u64_arg(
        &cmdline,
        &["nvx.channel_generation", "nvx_channel_generation"],
    )?;
    let expected_capability = parse_required_hex_32_arg(
        &cmdline,
        &["nvx.launch_capability", "nvx_launch_capability"],
    )?;
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
        expected_capability,
    })
}

fn parse_required_u64_arg(cmdline: &str, keys: &[&str]) -> Result<u64> {
    let (key, value) = extract_unique_cmdline_value(cmdline, keys)?;
    value
        .parse::<u64>()
        .map_err(|error| AgentError::config(format!("invalid {key} value: {error}")))
}

fn parse_required_hex_32_arg(cmdline: &str, keys: &[&str]) -> Result<[u8; 32]> {
    let (key, value) = extract_unique_cmdline_value(cmdline, keys)?;
    parse_hex_32(&value)
        .map_err(|error| AgentError::config(format!("invalid {key} value: {error}")))
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

fn open_hvc1_raw_nonblocking(path: &str) -> Result<File> {
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
            "tcgetattr on /dev/hvc1",
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
            "tcsetattr raw mode on /dev/hvc1",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_GETFL reads descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(AgentError::io(
            "fcntl(F_GETFL) on /dev/hvc1",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_SETFL writes descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(AgentError::io(
            "fcntl(F_SETFL O_NONBLOCK) on /dev/hvc1",
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
        CreateProcessRequest, FlowCreditRequest, HealthStatus, HostControlMessage, InnerRecord,
        LaunchBinding, LaunchIdentity, MappingContainmentPolicy, NetworkMode, NetworkStatus,
        ProcessSupervisor, ProtocolErrorCode, SERVICE_IDENTITY, ServiceError, ServiceErrorCode,
        SessionConfiguration, StreamName, SupervisorEvent, SymlinkContainmentPolicy,
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
        let cmdline = "quiet nvx.channel_generation=7 nvx_channel_generation=8 nvx.launch_capability=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let duplicate = extract_unique_cmdline_value(
            cmdline,
            &["nvx.channel_generation", "nvx_channel_generation"],
        );
        assert!(duplicate.is_err());
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
        assert_eq!(OPENVMM_OUTER_FRAME_OVERHEAD_BYTES, 64);
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
            _deadline: Duration,
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
                NetworkStatus {
                    mode: NetworkMode::NoNic,
                    detail: None,
                },
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
                    network: NetworkStatus {
                        mode: NetworkMode::PortableNetwork,
                        detail: Some("test".to_string()),
                    },
                },
            })
            .unwrap();
        service
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
            quiesced: false,
            launch_admitted: true,
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
        supervisor.events.push_back(SupervisorEvent::Exited(0));

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
    fn quiesce_remains_unavailable_after_runtime_activation() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();

        let mut touched_freezer = false;
        let error = quiesce_transactional(&mut service, |_freeze| {
            touched_freezer = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!touched_freezer);
        assert_eq!(error.code(), crate::error::ErrorCode::BadRequest);
        assert!(error.to_string().contains("UnsupportedOperation"));
        assert!(!service.health().quiesced);
    }

    #[test]
    fn resume_remains_unavailable_after_runtime_activation() {
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
        assert!(error.to_string().contains("UnsupportedOperation"));
        assert!(!service.health().quiesced);
    }

    #[test]
    fn quiesce_unavailable_preserves_active_execution() {
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
        assert!(error.to_string().contains("UnsupportedOperation"));
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
            let outbound = handle_host_record(
                &binding,
                &mut service,
                &mut supervisor,
                &mut pending_hello,
                &mut active_timeout,
                4242,
                control_record(&operation),
            )
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

        let outbound = handle_host_record(
            &binding,
            &mut service,
            &mut supervisor,
            &mut pending_hello,
            &mut active_timeout,
            4242,
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
}
