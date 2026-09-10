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
    ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, ServiceErrorCode,
    SessionConfiguration, WaitReadyRequest, WorkloadIdentityStatus,
};

use crate::config::{GuestMountRoot, SessionConfiguration as AgentSessionConfiguration};
use crate::error::{AgentError, Result};
use crate::isolation::{self, apply_and_verify_workload_isolation, default_isolation_plan};
use crate::mappings::MappingResolver;
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
    let mut service = MxcControlService::new_pid1_runtime_with_status(
        binding.clone(),
        build,
        network.clone(),
        isolation_result.status,
        WorkloadIdentityStatus::mxc_fixed(),
        isolation_result.holder_pid,
    );
    service.set_expected_capability(launch_config.expected_capability);
    let mut supervisor = LinuxProcessSupervisor::new_with_holder(isolation_result.holder_pid)
        .map_err(|error| AgentError::internal(error.to_string()))?;
    let mut pending_hello: Option<AuthenticateChannelRequest> = None;
    let mut active_timeout: Option<(u32, Instant)> = None;
    let mut pending_outbound = VecDeque::new();
    let mut shutdown_requested = false;
    let mut shutdown_cleanup_started = false;

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
                        record,
                    )?;
                    for message in outbound {
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

fn handle_host_record(
    binding: &LaunchBinding,
    service: &mut MxcControlService,
    supervisor: &mut LinuxProcessSupervisor,
    pending_hello: &mut Option<AuthenticateChannelRequest>,
    active_timeout: &mut Option<(u32, Instant)>,
    record: agent_protocol::InnerRecord,
) -> Result<Vec<AgentControlMessage>> {
    if record.kind != agent_protocol::InnerRecordKind::Control {
        return Ok(vec![AgentControlMessage::Error(ProtocolErrorDetail {
            code: ProtocolErrorCode::InvalidLifecycleTransition,
            message: "non-control record on control channel".to_string(),
        })]);
    }
    let host_message: HostControlMessage = match serde_json::from_slice(&record.payload) {
        Ok(message) => message,
        Err(error) => {
            return Ok(vec![AgentControlMessage::Error(ProtocolErrorDetail {
                code: ProtocolErrorCode::InvalidLifecycleTransition,
                message: format!("invalid host control payload: {error}"),
            })]);
        }
    };
    match handle_host_message(
        binding,
        service,
        supervisor,
        pending_hello,
        active_timeout,
        host_message,
    ) {
        Ok(messages) => Ok(messages),
        Err(error) => Ok(vec![AgentControlMessage::Error(ProtocolErrorDetail {
            code: ProtocolErrorCode::InvalidLifecycleTransition,
            message: error.to_string(),
        })]),
    }
}

fn handle_host_message(
    binding: &LaunchBinding,
    service: &mut MxcControlService,
    supervisor: &mut LinuxProcessSupervisor,
    pending_hello: &mut Option<AuthenticateChannelRequest>,
    active_timeout: &mut Option<(u32, Instant)>,
    message: HostControlMessage,
) -> Result<Vec<AgentControlMessage>> {
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
            let _ = service
                .authenticate_channel(authentication, now_secs(), network.clone())
                .map_err(|error| AgentError::bad_request(error.to_string()))?;
            verify_declared_mappings(&guest_mount_root, &mappings)?;
            let configuration = session_configuration_from_host(
                launch,
                root,
                mappings,
                containment,
                network.clone(),
            )?;
            service
                .configure_session(ConfigureSessionRequest {
                    protocol_version: binding.protocol_version,
                    image_version: binding.image_version.clone(),
                    launch,
                    channel_generation: binding.channel_generation,
                    idempotent_replay: false,
                    configuration,
                })
                .map_err(|error| AgentError::bad_request(error.to_string()))?;
            service
                .activate_full_lifecycle()
                .map_err(|error| AgentError::bad_request(error.to_string()))?;
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
            service
                .create_process(
                    CreateProcessRequest {
                        exec_id,
                        argv,
                        cwd,
                        env,
                        timeout_ms,
                    },
                    supervisor,
                )
                .map_err(|error| AgentError::exec(error.to_string()))?;
            if let Some(timeout) = timeout_ms
                && let Some(deadline) = Instant::now().checked_add(Duration::from_millis(timeout))
            {
                *active_timeout = Some((exec_id, deadline));
            }
            Ok(Vec::new())
        }
        HostControlMessage::CancelExecution { exec_id } => {
            service
                .cancel_exec(exec_id, CancelReason::Cancelled, supervisor)
                .map_err(|error| AgentError::exec(error.to_string()))?;
            Ok(Vec::new())
        }
        HostControlMessage::FlowCredits(request) => {
            service
                .grant_flow_credits(request)
                .map_err(|error| AgentError::bad_request(error.to_string()))?;
            Ok(Vec::new())
        }
        HostControlMessage::StdinChunk(record) => {
            service
                .stdin_chunk(record, supervisor)
                .map_err(|error| AgentError::exec(error.to_string()))?;
            Ok(Vec::new())
        }
        HostControlMessage::StdinEof(record) => {
            service
                .stdin_eof(record, supervisor)
                .map_err(|error| AgentError::exec(error.to_string()))?;
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
        HostControlMessage::Quiesce => Ok(vec![quiesce_transactional(service, |freeze| {
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
        })?]),
        HostControlMessage::Resume => Ok(vec![resume_transactional(service, |freeze| {
            set_workload_frozen(
                Path::new(DEFAULT_WORKLOAD_CGROUP_PATH),
                freeze,
                FREEZE_WAIT_TIMEOUT,
            )
        })?]),
        HostControlMessage::Shutdown { .. } => {
            Ok(vec![service.shutdown().map_err(|error| {
                AgentError::bad_request(error.to_string())
            })?])
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

fn verify_declared_mappings(
    guest_mount_root: &GuestMountRoot,
    mappings: &[agent_protocol::ChildMapping],
) -> Result<()> {
    let resolver = MappingResolver::new(guest_mount_root.as_str(), mappings.to_vec())?;
    for mapping in mappings {
        let _ = resolver.resolve_declared(&mapping.child)?;
    }
    Ok(())
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
    std::fs::write(&freeze_path, if freeze { "1\n" } else { "0\n" })
        .map_err(|error| AgentError::io(format!("writing {}", freeze_path.display()), error))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| AgentError::freeze("freeze deadline overflow"))?;
    loop {
        let events = std::fs::read_to_string(&events_path)
            .map_err(|error| AgentError::io(format!("reading {}", events_path.display()), error))?;
        if parse_cgroup_frozen_flag(&events)? == freeze {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AgentError::checkpoint_timeout(format!(
                "timed out waiting for cgroup.freeze={} in {}",
                if freeze { 1 } else { 0 },
                cgroup_dir.display()
            )));
        }
        thread::sleep(Duration::from_millis(10));
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
        CreateProcessRequest, FlowCreditRequest, HealthStatus, LaunchBinding, LaunchIdentity,
        MappingContainmentPolicy, NetworkMode, NetworkStatus, ProcessSupervisor, SERVICE_IDENTITY,
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

    #[derive(Default)]
    struct RuntimeTestSupervisor {
        exec_id: Option<u32>,
        events: VecDeque<SupervisorEvent>,
        acked_events: usize,
    }

    impl ProcessSupervisor for RuntimeTestSupervisor {
        fn spawn(
            &mut self,
            request: &CreateProcessRequest,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            self.exec_id = Some(request.exec_id);
            Ok(())
        }

        fn queue_stdin(
            &mut self,
            _exec_id: u32,
            _chunk: Vec<u8>,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
            Ok(())
        }

        fn close_stdin(
            &mut self,
            _exec_id: u32,
        ) -> std::result::Result<(), agent_protocol::ServiceError> {
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
            Ok(())
        }

        fn kill(&mut self, _exec_id: u32) -> std::result::Result<(), agent_protocol::ServiceError> {
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
    fn runtime_supervisor_pump_waits_for_full_256_queue_and_replays_once_losslessly() {
        let mut service = runtime_test_service();
        let mut supervisor = RuntimeTestSupervisor::default();
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
        service.activate_full_lifecycle().unwrap();
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
        for _ in 0..256 {
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
    fn quiesce_freeze_failure_leaves_running_and_retry_succeeds() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();

        let mut attempts = 0_u32;
        let error = quiesce_transactional(&mut service, |freeze| {
            assert!(freeze);
            attempts += 1;
            if attempts == 1 {
                return Err(AgentError::freeze("injected freeze failure"));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.code(), crate::error::ErrorCode::FreezeFailed);
        assert!(!service.health().quiesced);

        let message = quiesce_transactional(&mut service, |freeze| {
            assert!(freeze);
            Ok(())
        })
        .unwrap();
        assert!(matches!(message, AgentControlMessage::Quiesced));
        assert!(service.health().quiesced);
    }

    #[test]
    fn resume_thaw_failure_leaves_quiesced_and_retry_succeeds() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();
        quiesce_transactional(&mut service, |_| Ok(())).unwrap();
        assert!(service.health().quiesced);

        let mut attempts = 0_u32;
        let error = resume_transactional(&mut service, |freeze| {
            assert!(!freeze);
            attempts += 1;
            if attempts == 1 {
                return Err(AgentError::freeze("injected thaw failure"));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.code(), crate::error::ErrorCode::FreezeFailed);
        assert!(service.health().quiesced);

        let message = resume_transactional(&mut service, |freeze| {
            assert!(!freeze);
            Ok(())
        })
        .unwrap();
        assert!(matches!(message, AgentControlMessage::Resumed));
        assert!(!service.health().quiesced);
    }

    #[test]
    fn timeout_paths_preserve_state_and_allow_retry() {
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().unwrap();

        let error = quiesce_transactional(&mut service, |_| {
            Err(AgentError::checkpoint_timeout("injected freeze timeout"))
        })
        .unwrap_err();
        assert_eq!(error.code(), crate::error::ErrorCode::CheckpointTimeout);
        assert!(!service.health().quiesced);
        quiesce_transactional(&mut service, |_| Ok(())).unwrap();
        assert!(service.health().quiesced);

        let error = resume_transactional(&mut service, |_| {
            Err(AgentError::checkpoint_timeout("injected thaw timeout"))
        })
        .unwrap_err();
        assert_eq!(error.code(), crate::error::ErrorCode::CheckpointTimeout);
        assert!(service.health().quiesced);
        resume_transactional(&mut service, |_| Ok(())).unwrap();
        assert!(!service.health().quiesced);
    }
}
