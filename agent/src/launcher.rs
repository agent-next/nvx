// Copyright(c) The microvm authors.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::ffi::CString;
use std::fs;
use std::io;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use serde_json::{Map, Value};

use agent_protocol::{WORKLOAD_GID_MXC, WORKLOAD_UID_MXC};

const INTERNAL_LAUNCHER_FLAG: &str = "--nvx-internal-launcher";
const INTERNAL_LAUNCHER_CONFIG_FD_FLAG: &str = "--nvx-launcher-config-fd";
const INTERNAL_LAUNCHER_STATUS_FD_FLAG: &str = "--nvx-launcher-status-fd";
const LAUNCHER_CONFIG_VERSION: u32 = 1;
const LAUNCHER_CONFIG_MAX_BYTES: usize = 64 * 1024;
const LAUNCHER_MAX_ARGV: usize = 256;
const LAUNCHER_MAX_ENV: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct LauncherConfig {
    pub(crate) version: u32,
    pub(crate) argv: Vec<String>,
    pub(crate) env: Vec<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) mount_ns_fd: i32,
    pub(crate) uts_ns_fd: i32,
    pub(crate) ipc_ns_fd: i32,
    pub(crate) pid_ns_fd: i32,
    pub(crate) cgroup_procs_fd: i32,
}

#[derive(Clone, Copy)]
struct ChildCredentialPlan {
    last_capability_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

pub(crate) enum LauncherMode {
    Run(LauncherInvocation),
    NotLauncher,
    Invalid(String),
}

pub(crate) struct LauncherInvocation {
    pub(crate) config_fd: RawFd,
    pub(crate) status_fd: RawFd,
}

pub(crate) fn parse_launcher_invocation(args: &[String]) -> LauncherMode {
    if args.len() <= 1 || args[1] != INTERNAL_LAUNCHER_FLAG {
        return LauncherMode::NotLauncher;
    }
    if args.len() != 6 {
        return LauncherMode::Invalid("internal launcher argument count mismatch".to_string());
    }
    if args[2] != INTERNAL_LAUNCHER_CONFIG_FD_FLAG {
        return LauncherMode::Invalid("missing internal launcher config fd flag".to_string());
    }
    if args[4] != INTERNAL_LAUNCHER_STATUS_FD_FLAG {
        return LauncherMode::Invalid("missing internal launcher status fd flag".to_string());
    }
    let config_fd = match args[3].parse::<i32>() {
        Ok(value) if value >= 3 => value,
        _ => return LauncherMode::Invalid("invalid internal launcher config fd".to_string()),
    };
    let status_fd = match args[5].parse::<i32>() {
        Ok(value) if value >= 3 => value,
        _ => return LauncherMode::Invalid("invalid internal launcher status fd".to_string()),
    };
    LauncherMode::Run(LauncherInvocation {
        config_fd,
        status_fd,
    })
}

pub(crate) fn build_launcher_command_args(config_fd: RawFd, status_fd: RawFd) -> Vec<String> {
    vec![
        INTERNAL_LAUNCHER_FLAG.to_string(),
        INTERNAL_LAUNCHER_CONFIG_FD_FLAG.to_string(),
        config_fd.to_string(),
        INTERNAL_LAUNCHER_STATUS_FD_FLAG.to_string(),
        status_fd.to_string(),
    ]
}

pub(crate) fn write_launcher_config(fd: RawFd, config: &LauncherConfig) -> io::Result<()> {
    let mut object = Map::new();
    object.insert("version".to_string(), Value::from(config.version));
    object.insert(
        "argv".to_string(),
        Value::Array(
            config
                .argv
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect(),
        ),
    );
    object.insert(
        "env".to_string(),
        Value::Array(
            config
                .env
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect(),
        ),
    );
    object.insert(
        "cwd".to_string(),
        config
            .cwd
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );
    object.insert("mount_ns_fd".to_string(), Value::from(config.mount_ns_fd));
    object.insert("uts_ns_fd".to_string(), Value::from(config.uts_ns_fd));
    object.insert("ipc_ns_fd".to_string(), Value::from(config.ipc_ns_fd));
    object.insert("pid_ns_fd".to_string(), Value::from(config.pid_ns_fd));
    object.insert(
        "cgroup_procs_fd".to_string(),
        Value::from(config.cgroup_procs_fd),
    );
    let payload = serde_json::to_vec(&Value::Object(object)).map_err(io::Error::other)?;
    if payload.len() > LAUNCHER_CONFIG_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher config exceeds maximum size",
        ));
    }
    write_all_fd(fd, &payload)
}

pub(crate) fn run_launcher_mode(invocation: LauncherInvocation) -> io::Result<()> {
    // SAFETY: from_raw_fd takes ownership of inherited descriptors.
    let mut config_file = unsafe { fs::File::from_raw_fd(invocation.config_fd) };
    // SAFETY: from_raw_fd takes ownership of inherited descriptors.
    let status_file = unsafe { fs::File::from_raw_fd(invocation.status_fd) };
    let status_fd = status_file.as_raw_fd();

    // Refuse privileged mode unless currently root. Workload user (mxc) cannot escalate.
    // SAFETY: geteuid reads process credentials and has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        let _ = write_all_fd(status_fd, &1_i32.to_ne_bytes());
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "internal launcher requires root euid",
        ));
    }

    let mut payload = Vec::with_capacity(1024);
    let max = LAUNCHER_CONFIG_MAX_BYTES as u64;
    config_file.by_ref().take(max).read_to_end(&mut payload)?;
    if payload.len() >= LAUNCHER_CONFIG_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher config payload exceeds limit",
        ));
    }
    let value: Value = serde_json::from_slice(&payload).map_err(io::Error::other)?;
    let config = parse_launcher_config_value(value)?;
    validate_launcher_config(&config)?;
    run_launcher(config, status_fd)
}

fn parse_launcher_config_value(value: Value) -> io::Result<LauncherConfig> {
    let object = value.as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher config must be a JSON object",
        )
    })?;
    let version = read_required_u32(object, "version")?;
    let argv = read_required_string_vec(object, "argv")?;
    let env = read_required_string_vec(object, "env")?;
    let cwd = read_optional_string(object, "cwd")?;
    let mount_ns_fd = read_required_i32(object, "mount_ns_fd")?;
    let uts_ns_fd = read_required_i32(object, "uts_ns_fd")?;
    let ipc_ns_fd = read_required_i32(object, "ipc_ns_fd")?;
    let pid_ns_fd = read_required_i32(object, "pid_ns_fd")?;
    let cgroup_procs_fd = read_required_i32(object, "cgroup_procs_fd")?;
    Ok(LauncherConfig {
        version,
        argv,
        env,
        cwd,
        mount_ns_fd,
        uts_ns_fd,
        ipc_ns_fd,
        pid_ns_fd,
        cgroup_procs_fd,
    })
}

fn read_required_u32(object: &Map<String, Value>, key: &str) -> io::Result<u32> {
    let value = object.get(key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config missing '{key}'"),
        )
    })?;
    let number = value.as_u64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config '{key}' must be u32"),
        )
    })?;
    u32::try_from(number).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config '{key}' must be within u32 range"),
        )
    })
}

fn read_required_i32(object: &Map<String, Value>, key: &str) -> io::Result<i32> {
    let value = object.get(key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config missing '{key}'"),
        )
    })?;
    let number = value.as_i64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config '{key}' must be i32"),
        )
    })?;
    i32::try_from(number).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config '{key}' must be within i32 range"),
        )
    })
}

fn read_required_string_vec(object: &Map<String, Value>, key: &str) -> io::Result<Vec<String>> {
    let value = object.get(key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config missing '{key}'"),
        )
    })?;
    let array = value.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config '{key}' must be an array"),
        )
    })?;
    let mut entries = Vec::with_capacity(array.len());
    for item in array {
        let text = item.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("launcher config '{key}' must contain only strings"),
            )
        })?;
        entries.push(text.to_string());
    }
    Ok(entries)
}

fn read_optional_string(object: &Map<String, Value>, key: &str) -> io::Result<Option<String>> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher config '{key}' must be a string or null"),
        )
    })?;
    Ok(Some(text.to_string()))
}

fn validate_launcher_config(config: &LauncherConfig) -> io::Result<()> {
    if config.version != LAUNCHER_CONFIG_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher config version mismatch",
        ));
    }
    if config.argv.is_empty() || config.argv.len() > LAUNCHER_MAX_ARGV {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher argv must contain 1..=256 entries",
        ));
    }
    if config.env.len() > LAUNCHER_MAX_ENV {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher env exceeds entry limit",
        ));
    }
    for entry in &config.env {
        let Some((key, _)) = entry.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher env entry must use KEY=VALUE format",
            ));
        };
        if key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher env key cannot be empty",
            ));
        }
    }
    for fd in [
        config.mount_ns_fd,
        config.uts_ns_fd,
        config.ipc_ns_fd,
        config.pid_ns_fd,
        config.cgroup_procs_fd,
    ] {
        if fd < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher requires inherited non-stdio descriptors",
            ));
        }
    }
    Ok(())
}

fn run_launcher(config: LauncherConfig, status_fd: RawFd) -> io::Result<()> {
    let credential_plan = prepare_child_credential_plan()?;
    let cwd_cstring = match config.cwd.as_ref() {
        Some(path) => Some(CString::new(path.as_str()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher cwd contains interior NUL byte",
            )
        })?),
        None => None,
    };
    let argv_cstrings = config
        .argv
        .iter()
        .map(|arg| {
            CString::new(arg.as_str()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "launcher argv contains interior NUL byte",
                )
            })
        })
        .collect::<io::Result<Vec<CString>>>()?;
    let env_cstrings = config
        .env
        .iter()
        .map(|entry| {
            CString::new(entry.as_str()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "launcher env contains interior NUL byte",
                )
            })
        })
        .collect::<io::Result<Vec<CString>>>()?;
    let mut argv_ptrs = argv_cstrings
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<*const libc::c_char>>();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs = env_cstrings
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<*const libc::c_char>>();
    env_ptrs.push(std::ptr::null());

    setns_checked(config.mount_ns_fd, libc::CLONE_NEWNS)?;
    setns_checked(config.uts_ns_fd, libc::CLONE_NEWUTS)?;
    setns_checked(config.ipc_ns_fd, libc::CLONE_NEWIPC)?;
    setns_checked(config.pid_ns_fd, libc::CLONE_NEWPID)?;
    move_self_to_cgroup_fd(config.cgroup_procs_fd)?;

    // SAFETY: fork returns twice and is handled in branch-specific code below.
    let workload_pid = unsafe { libc::fork() };
    if workload_pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if workload_pid > 0 {
        let wait_status = wait_for_pid(workload_pid)?;
        write_all_fd(status_fd, &wait_status.to_ne_bytes())?;
        // SAFETY: exiting launcher parent without running Rust destructors avoids post-fork locks.
        unsafe {
            if libc::WIFEXITED(wait_status) {
                libc::_exit(libc::WEXITSTATUS(wait_status));
            }
            if libc::WIFSIGNALED(wait_status) {
                libc::_exit(128 + libc::WTERMSIG(wait_status));
            }
            libc::_exit(1);
        }
    }

    // Child path: avoid allocations/locks; perform only direct syscalls and fixed-memory work.
    let child_result: io::Result<()> = (|| {
        apply_workload_exec_credentials(Some(credential_plan))?;
        if let Some(cwd) = cwd_cstring.as_ref() {
            // SAFETY: cwd is a valid NUL-terminated string.
            if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        close_non_stdio_fds();
        // SAFETY: pointers reference NUL-terminated argv/env arrays ending with NULL.
        unsafe {
            libc::execve(
                argv_cstrings[0].as_ptr(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            );
        }
        Err(io::Error::last_os_error())
    })();
    let code = child_result
        .err()
        .and_then(|error| error.raw_os_error())
        .unwrap_or(1);
    // SAFETY: _exit terminates process immediately without unwinding in post-fork child.
    unsafe { libc::_exit(code.clamp(1, 255)) };
}

fn wait_for_pid(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0_i32;
    loop {
        // SAFETY: waitpid writes status for the requested direct child.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc >= 0 {
            return Ok(status);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(error);
    }
}

fn setns_checked(fd: i32, nstype: i32) -> io::Result<()> {
    // SAFETY: fd references a namespace descriptor inherited from trusted parent.
    let rc = unsafe { libc::setns(fd, nstype) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn move_self_to_cgroup_fd(cgroup_procs_fd: i32) -> io::Result<()> {
    let mut payload = [0_u8; 32];
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let encoded = encode_pid_line(pid, &mut payload)?;
    write_all_fd(cgroup_procs_fd, encoded)
}

fn encode_pid_line(pid: i32, scratch: &mut [u8; 32]) -> io::Result<&[u8]> {
    if pid < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pid must be non-negative",
        ));
    }
    let mut value = pid as u32;
    let mut cursor = scratch.len();
    cursor -= 1;
    scratch[cursor] = b'\n';
    if value == 0 {
        cursor -= 1;
        scratch[cursor] = b'0';
        return Ok(&scratch[cursor..]);
    }
    while value > 0 {
        if cursor == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pid line buffer overflow",
            ));
        }
        cursor -= 1;
        scratch[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    Ok(&scratch[cursor..])
}

fn write_all_fd(fd: i32, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        // SAFETY: bytes points to a valid memory range for current slice.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "launcher status/config write returned zero",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn prepare_child_credential_plan() -> io::Result<ChildCredentialPlan> {
    let raw = fs::read_to_string("/proc/sys/kernel/cap_last_cap")?;
    let last_capability_index = raw
        .trim()
        .parse::<i32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cap_last_cap"))?;
    Ok(ChildCredentialPlan {
        last_capability_index,
    })
}

fn apply_workload_exec_credentials(plan: Option<ChildCredentialPlan>) -> io::Result<()> {
    let Some(plan) = plan else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "child credential plan is missing",
        ));
    };
    // SAFETY: setgroups called with zero groups and null pointer.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: prctl ambient clear has no pointer arguments.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut capability = 0_i32;
    while capability <= plan.last_capability_index {
        // SAFETY: prctl validates capability indexes.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM) {
                return Err(error);
            }
            break;
        }
        capability += 1;
    }
    // SAFETY: setgid/setuid use fixed workload identity constants.
    if unsafe { libc::setgid(WORKLOAD_GID_MXC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: setuid uses fixed workload identity constants.
    if unsafe { libc::setuid(WORKLOAD_UID_MXC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let header = LinuxCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [LinuxCapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: syscall receives valid pointers to initialized capability header/data.
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: prctl no_new_privs has no pointer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn close_non_stdio_fds() {
    #[cfg(any(target_env = "gnu", target_env = "musl"))]
    {
        // SAFETY: syscall arguments are plain integers; ENOSYS is handled by fallback.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
        if rc == 0 {
            return;
        }
    }
    // SAFETY: sysconf returns open-file limit or -1; fallback cap keeps loop bounded.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let upper = if max < 0 { 4096 } else { max as i32 };
    let mut fd = 3_i32;
    while fd < upper {
        // SAFETY: best-effort close for all non-stdio descriptors.
        let _ = unsafe { libc::close(fd) };
        fd += 1;
    }
}
