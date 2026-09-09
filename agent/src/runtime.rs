// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_protocol::{
    AgentControlMessage, AuthenticateChannelRequest, BuildStatus, CancelReason, ChannelReadResult,
    ConfigureSessionRequest, CreateProcessRequest, HVC1_DEVICE_PATH, HostControlMessage,
    IsolationStatus, LaunchBinding, LaunchIdentity, MappingContainmentPolicy, MxcControlService,
    NetworkMode, NetworkStatus, OPENVMM_OUTER_FRAME_OVERHEAD_BYTES, PROTOCOL_VERSION,
    ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, SessionConfiguration,
    WaitReadyRequest, WorkloadIdentityStatus,
};

use crate::config::{GuestMountRoot, SessionConfiguration as AgentSessionConfiguration};
use crate::error::{AgentError, Result};
use crate::isolation::{apply_and_verify_workload_isolation, default_isolation_plan};
use crate::mappings::MappingResolver;
use crate::supervisor::LinuxProcessSupervisor;

const LOOP_SLEEP: Duration = Duration::from_millis(10);
const DEFAULT_GUEST_MAPPING_ROOT: &str = "/mnt/virtiofs";

pub fn run_runtime() -> Result<()> {
    assert_conservative_openvmm_overhead()?;
    let binding = read_launch_binding()?;
    let build = detect_build_status();
    let network = detect_network_status();
    let isolation = optimistic_isolation_status();
    let mut service = MxcControlService::new_with_status(
        binding.clone(),
        build,
        network.clone(),
        isolation,
        WorkloadIdentityStatus::mxc_fixed(),
    );
    let file = open_hvc1_raw_nonblocking(HVC1_DEVICE_PATH)?;
    let mut channel = agent_protocol::HvcFramedChannel::new(file);
    let mut supervisor = LinuxProcessSupervisor::new();
    let mut pending_hello: Option<AuthenticateChannelRequest> = None;
    let mut active_timeout: Option<(u32, Instant)> = None;

    loop {
        if let Some((exec_id, deadline)) = active_timeout
            && Instant::now() >= deadline
        {
            let _ = service.cancel_exec(exec_id, CancelReason::TimedOut, &mut supervisor);
            active_timeout = None;
        }

        for message in service
            .pump_supervisor(&mut supervisor)
            .map_err(|error| AgentError::internal(error.to_string()))?
        {
            if matches!(message, AgentControlMessage::ExecTerminal { .. }) {
                active_timeout = None;
            }
            queue_agent_message(&mut channel, &message)?;
        }
        while channel
            .flush_once()
            .map_err(|error| AgentError::internal(error.to_string()))?
        {}

        match channel
            .try_read_next_inner_record()
            .map_err(|error| AgentError::internal(error.to_string()))?
        {
            ChannelReadResult::WouldBlock => {
                thread::sleep(LOOP_SLEEP);
                continue;
            }
            ChannelReadResult::Closed => {
                let cleanup = service.begin_disconnect_cleanup(now_secs(), &mut supervisor);
                if let Err(error) = cleanup {
                    return Err(AgentError::internal(format!(
                        "channel-loss cleanup failed closed: {error}"
                    )));
                }
                return Ok(());
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
                    let shutting_down = matches!(message, AgentControlMessage::ShuttingDown);
                    queue_agent_message(&mut channel, &message)?;
                    while channel
                        .flush_once()
                        .map_err(|error| AgentError::internal(error.to_string()))?
                    {
                    }
                    if shutting_down {
                        return Ok(());
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
            let isolation_result = apply_and_verify_workload_isolation(&default_isolation_plan())?;
            let _ = isolation_result.holder_pid;
            service.update_runtime_isolation(isolation_result.status.clone());
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
            let _ = service.wait_ready(WaitReadyRequest {
                protocol_version: binding.protocol_version,
                image_version: binding.image_version.clone(),
                launch,
                channel_generation: binding.channel_generation,
            });
            let ready = AgentControlMessage::Ready {
                launch,
                status: ready_status(service, network),
            };
            Ok(vec![ready])
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
        HostControlMessage::Quiesce => {
            Ok(vec![service.quiesce().map_err(|error| {
                AgentError::bad_request(error.to_string())
            })?])
        }
        HostControlMessage::Resume => {
            Ok(vec![service.resume().map_err(|error| {
                AgentError::bad_request(error.to_string())
            })?])
        }
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

fn queue_agent_message<T: io::Read + io::Write>(
    channel: &mut agent_protocol::HvcFramedChannel<T>,
    message: &AgentControlMessage,
) -> Result<()> {
    channel
        .queue_control_message(message)
        .map_err(|error| AgentError::internal(error.to_string()))
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

fn read_launch_binding() -> Result<LaunchBinding> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|error| AgentError::io("reading /proc/cmdline", error))?;
    let generation = parse_u64_arg(
        &cmdline,
        &["nvx.launch_generation", "nvx_launch_generation"],
    )?;
    let channel_generation = parse_u64_arg(
        &cmdline,
        &["nvx.channel_generation", "nvx_channel_generation"],
    )?;
    let nonce = parse_nonce_arg(&cmdline, &["nvx.launch_nonce", "nvx_launch_nonce"])?;
    Ok(LaunchBinding {
        protocol_version: PROTOCOL_VERSION,
        image_version: env!("CARGO_PKG_VERSION").to_string(),
        launch: LaunchIdentity { generation, nonce },
        channel_generation,
    })
}

fn parse_u64_arg(cmdline: &str, keys: &[&str]) -> Result<u64> {
    for key in keys {
        if let Some(value) = extract_cmdline_value(cmdline, key) {
            return value.parse::<u64>().map_err(|error| {
                AgentError::config(format!("invalid {key} value {value:?}: {error}"))
            });
        }
    }
    Err(AgentError::config(format!(
        "missing required kernel argument; expected one of: {}",
        keys.join(", ")
    )))
}

fn parse_nonce_arg(cmdline: &str, keys: &[&str]) -> Result<[u8; 16]> {
    for key in keys {
        if let Some(value) = extract_cmdline_value(cmdline, key) {
            return parse_nonce_hex(&value).map_err(|error| {
                AgentError::config(format!("invalid {key} value {value:?}: {error}"))
            });
        }
    }
    Err(AgentError::config(format!(
        "missing required kernel nonce argument; expected one of: {}",
        keys.join(", ")
    )))
}

fn extract_cmdline_value(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
    }
    None
}

fn parse_nonce_hex(value: &str) -> Result<[u8; 16]> {
    if value.len() != 32 {
        return Err(AgentError::config(
            "nonce must be exactly 32 hex characters",
        ));
    }
    let mut nonce = [0_u8; 16];
    for (index, slot) in nonce.iter_mut().enumerate() {
        let start = index * 2;
        let end = start + 2;
        let byte = u8::from_str_radix(&value[start..end], 16)
            .map_err(|error| AgentError::config(format!("invalid nonce hex: {error}")))?;
        *slot = byte;
    }
    Ok(nonce)
}

fn now_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

fn optimistic_isolation_status() -> IsolationStatus {
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

    #[test]
    fn nonce_parser_accepts_exact_32_hex_characters() {
        let nonce = parse_nonce_hex("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(nonce[0], 0x00);
        assert_eq!(nonce[15], 0xff);
    }

    #[test]
    fn nonce_parser_rejects_invalid_length_and_digits() {
        assert!(parse_nonce_hex("0011").is_err());
        assert!(parse_nonce_hex("gg112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn cmdline_value_extraction_reads_kernel_tokens() {
        let cmdline =
            "quiet nvx.launch_generation=7 nvx_launch_nonce=00112233445566778899aabbccddeeff";
        assert_eq!(
            extract_cmdline_value(cmdline, "nvx.launch_generation").as_deref(),
            Some("7")
        );
        assert_eq!(
            extract_cmdline_value(cmdline, "nvx_launch_nonce").as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
    }

    #[test]
    fn openvmm_overhead_constant_remains_conservative() {
        assert!(assert_conservative_openvmm_overhead().is_ok());
        assert_eq!(OPENVMM_OUTER_FRAME_OVERHEAD_BYTES, 64);
    }
}
