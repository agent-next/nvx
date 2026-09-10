// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use agent_protocol::{
    CreateProcessRequest, DEFAULT_STDIN_QUEUE_LIMIT_BYTES, ProcessSupervisor, ServiceError,
    ServiceErrorCode, SupervisorEvent, WORKLOAD_GID_MXC, WORKLOAD_UID_MXC,
};

const STDIO_CHUNK_BYTES: usize = 4096;
const TERM_GRACE: Duration = Duration::from_millis(250);
const POLL_SLEEP: Duration = Duration::from_millis(10);

pub struct LinuxProcessSupervisor {
    active: Option<ActiveProcess>,
    holder: Option<NamespaceHolder>,
}

struct NamespaceHolder {
    cgroup_dir: PathBuf,
    cgroup_procs_path: CString,
    mount_ns_fd: i32,
    uts_ns_fd: i32,
    ipc_ns_fd: i32,
    pid_ns_fd: i32,
}

struct ActiveProcess {
    exec_id: u32,
    child: Child,
    process_group_id: i32,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdout_eof: bool,
    stderr_eof: bool,
    stdin_queue: VecDeque<Vec<u8>>,
    stdin_queue_bytes: usize,
    stdin_offset: usize,
    terminate_sent_at: Option<Instant>,
    kill_sent: bool,
    exit_status_reported: bool,
    descendants_cleaned_reported: bool,
    cgroup_dir: Option<PathBuf>,
    event_queue: VecDeque<SupervisorEvent>,
}

impl LinuxProcessSupervisor {
    pub fn new() -> Self {
        Self {
            active: None,
            holder: None,
        }
    }

    pub fn new_with_holder(holder_pid: libc::pid_t) -> Result<Self, ServiceError> {
        Ok(Self {
            active: None,
            holder: Some(NamespaceHolder::from_pid(holder_pid)?),
        })
    }
}

impl Default for LinuxProcessSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessSupervisor for LinuxProcessSupervisor {
    fn spawn(&mut self, request: &CreateProcessRequest) -> Result<(), ServiceError> {
        if self.active.is_some() {
            return Err(supervisor_error(
                "spawn rejected because an execution is already active",
            ));
        }

        let mut command = Command::new(&request.argv[0]);
        command.args(request.argv.iter().skip(1));
        if let Some(cwd) = &request.cwd {
            command.current_dir(cwd);
        }
        for entry in &request.env {
            let (key, value) = entry
                .split_once('=')
                .ok_or_else(|| supervisor_error("env entry must be KEY=VALUE"))?;
            command.env(key, value);
        }
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.process_group(0);
        if let Some(holder) = self.holder.as_ref() {
            let mount_ns_fd = holder.mount_ns_fd;
            let uts_ns_fd = holder.uts_ns_fd;
            let ipc_ns_fd = holder.ipc_ns_fd;
            let pid_ns_fd = holder.pid_ns_fd;
            let cgroup_procs_path = holder.cgroup_procs_path.clone();
            // SAFETY: closure performs direct namespace and identity syscalls before exec.
            unsafe {
                command.pre_exec(move || {
                    setns_checked(mount_ns_fd, libc::CLONE_NEWNS)?;
                    setns_checked(uts_ns_fd, libc::CLONE_NEWUTS)?;
                    setns_checked(ipc_ns_fd, libc::CLONE_NEWIPC)?;
                    setns_checked(pid_ns_fd, libc::CLONE_NEWPID)?;
                    move_self_to_cgroup(&cgroup_procs_path)?;
                    let workload_pid = libc::fork();
                    if workload_pid < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if workload_pid > 0 {
                        let mut status = 0_i32;
                        loop {
                            let rc = libc::waitpid(workload_pid, &mut status, 0);
                            if rc < 0 {
                                let error = io::Error::last_os_error();
                                if error.raw_os_error() == Some(libc::EINTR) {
                                    continue;
                                }
                                libc::_exit(1);
                            }
                            break;
                        }
                        if (status & 0x7f) == 0 {
                            libc::_exit((status >> 8) & 0xff);
                        }
                        libc::_exit(1);
                    }
                    if libc::setgid(WORKLOAD_GID_MXC) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::setuid(WORKLOAD_UID_MXC) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let mut child = command
            .spawn()
            .map_err(|error| supervisor_io("spawning process", error))?;
        let pid = child.id() as i32;
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        if let Some(stdin_ref) = stdin.as_mut() {
            set_nonblocking(stdin_ref.as_raw_fd())?;
        }
        if let Some(stdout_ref) = stdout.as_mut() {
            set_nonblocking(stdout_ref.as_raw_fd())?;
        }
        if let Some(stderr_ref) = stderr.as_mut() {
            set_nonblocking(stderr_ref.as_raw_fd())?;
        }

        let cgroup_dir = self
            .holder
            .as_ref()
            .map(|holder| holder.cgroup_dir.clone())
            .or_else(|| try_prepare_workload_cgroup(request.exec_id, pid));
        self.active = Some(ActiveProcess {
            exec_id: request.exec_id,
            child,
            process_group_id: pid,
            stdin,
            stdout,
            stderr,
            stdout_eof: false,
            stderr_eof: false,
            stdin_queue: VecDeque::new(),
            stdin_queue_bytes: 0,
            stdin_offset: 0,
            terminate_sent_at: None,
            kill_sent: false,
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            cgroup_dir,
            event_queue: VecDeque::new(),
        });
        Ok(())
    }

    fn queue_stdin(&mut self, exec_id: u32, chunk: Vec<u8>) -> Result<(), ServiceError> {
        let active = self.require_active(exec_id)?;
        let next_bytes = active
            .stdin_queue_bytes
            .checked_add(chunk.len())
            .ok_or_else(|| supervisor_error("stdin queue byte overflow"))?;
        if next_bytes > DEFAULT_STDIN_QUEUE_LIMIT_BYTES {
            return Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                message: "stdin queue reached byte limit".to_string(),
            });
        }
        active.stdin_queue_bytes = next_bytes;
        active.stdin_queue.push_back(chunk);
        Ok(())
    }

    fn close_stdin(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        let active = self.require_active(exec_id)?;
        active.stdin_queue.clear();
        active.stdin_queue_bytes = 0;
        active.stdin_offset = 0;
        active.stdin = None;
        Ok(())
    }

    fn terminate(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        let active = self.require_active(exec_id)?;
        active.stdin = None;
        send_terminate(active)?;
        Ok(())
    }

    fn kill(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        let active = self.require_active(exec_id)?;
        active.stdin = None;
        send_kill(active)?;
        Ok(())
    }

    fn poll(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
        let active = self.require_active(exec_id)?;
        refresh_active_state(active)?;
        Ok(active.event_queue.pop_front())
    }

    fn cleanup_for_disconnect(
        &mut self,
        exec_id: u32,
        deadline: Duration,
    ) -> Result<bool, ServiceError> {
        let active = self.require_active(exec_id)?;
        active.stdin = None;
        send_terminate(active)?;
        let deadline_at = Instant::now()
            .checked_add(deadline)
            .ok_or_else(|| supervisor_error("disconnect deadline overflow"))?;

        while Instant::now() < deadline_at {
            refresh_active_state(active)?;
            if active.exit_status_reported
                && active.descendants_cleaned_reported
                && active.stdout_eof
                && active.stderr_eof
            {
                self.active = None;
                return Ok(true);
            }
            std::thread::sleep(POLL_SLEEP);
        }
        send_kill(active)?;
        while Instant::now() < deadline_at {
            refresh_active_state(active)?;
            if active.exit_status_reported
                && active.descendants_cleaned_reported
                && active.stdout_eof
                && active.stderr_eof
            {
                self.active = None;
                return Ok(true);
            }
            std::thread::sleep(POLL_SLEEP);
        }
        Ok(false)
    }
}

impl LinuxProcessSupervisor {
    fn require_active(&mut self, exec_id: u32) -> Result<&mut ActiveProcess, ServiceError> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| supervisor_error("no active process"))?;
        if active.exec_id != exec_id {
            return Err(supervisor_error("exec id does not match active process"));
        }
        Ok(active)
    }
}

impl NamespaceHolder {
    fn from_pid(holder_pid: libc::pid_t) -> Result<Self, ServiceError> {
        let cgroup_dir = PathBuf::from("/sys/fs/cgroup/nvx.workload");
        let cgroup_procs_path = CString::new(format!("{}/cgroup.procs", cgroup_dir.display()))
            .map_err(|_| supervisor_error("holder cgroup path contains interior NUL"))?;
        Ok(Self {
            cgroup_dir,
            cgroup_procs_path,
            mount_ns_fd: open_namespace_fd(holder_pid, "mnt")?,
            uts_ns_fd: open_namespace_fd(holder_pid, "uts")?,
            ipc_ns_fd: open_namespace_fd(holder_pid, "ipc")?,
            pid_ns_fd: open_namespace_fd(holder_pid, "pid")?,
        })
    }
}

impl Drop for NamespaceHolder {
    fn drop(&mut self) {
        // SAFETY: best-effort close for process-owned descriptors.
        let _ = unsafe { libc::close(self.mount_ns_fd) };
        // SAFETY: best-effort close for process-owned descriptors.
        let _ = unsafe { libc::close(self.uts_ns_fd) };
        // SAFETY: best-effort close for process-owned descriptors.
        let _ = unsafe { libc::close(self.ipc_ns_fd) };
        // SAFETY: best-effort close for process-owned descriptors.
        let _ = unsafe { libc::close(self.pid_ns_fd) };
    }
}

fn open_namespace_fd(pid: libc::pid_t, ns_name: &str) -> Result<i32, ServiceError> {
    let path = CString::new(format!("/proc/{pid}/ns/{ns_name}"))
        .map_err(|_| supervisor_error("namespace path contains interior NUL"))?;
    // SAFETY: path is NUL-terminated and flags are constants.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(supervisor_io(
            format!("opening holder namespace /proc/{pid}/ns/{ns_name}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

fn setns_checked(fd: i32, nstype: i32) -> io::Result<()> {
    // SAFETY: fd references a namespace descriptor opened by open_namespace_fd.
    let rc = unsafe { libc::setns(fd, nstype) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn move_self_to_cgroup(cgroup_procs_path: &CString) -> io::Result<()> {
    // SAFETY: path pointer is NUL-terminated and flags are constants.
    let fd = unsafe { libc::open(cgroup_procs_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid_digits = [0_u8; 21];
    let mut len = 0usize;
    let mut value = unsafe { libc::getpid() } as u32;
    loop {
        pid_digits[len] = b'0' + (value % 10) as u8;
        len += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut payload = [0_u8; 22];
    for index in 0..len {
        payload[index] = pid_digits[len - index - 1];
    }
    payload[len] = b'\n';
    // SAFETY: payload pointer valid for len+1 bytes.
    let rc = unsafe { libc::write(fd, payload.as_ptr().cast(), len + 1) };
    // SAFETY: best-effort close for opened descriptor.
    let _ = unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn refresh_active_state(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    pump_stdout(active)?;
    pump_stderr(active)?;
    pump_stdin(active)?;
    maybe_escalate_kill(active)?;
    maybe_report_exit(active)?;
    maybe_report_descendants_cleaned(active)?;
    Ok(())
}

fn maybe_report_exit(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.exit_status_reported {
        return Ok(());
    }
    let Some(status) = active
        .child
        .try_wait()
        .map_err(|error| supervisor_io("polling child status", error))?
    else {
        return Ok(());
    };
    if let Some(code) = status.code() {
        active.event_queue.push_back(SupervisorEvent::Exited(code));
    } else if let Some(signal) = status.signal() {
        active
            .event_queue
            .push_back(SupervisorEvent::Signaled(signal));
    } else {
        active.event_queue.push_back(SupervisorEvent::Exited(1));
    }
    active.exit_status_reported = true;
    Ok(())
}

fn maybe_report_descendants_cleaned(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.descendants_cleaned_reported || !active.exit_status_reported {
        return Ok(());
    }
    kill_exec_descendants(active, libc::SIGKILL)?;
    active
        .event_queue
        .push_back(SupervisorEvent::DescendantsCleaned);
    active.descendants_cleaned_reported = true;
    Ok(())
}

fn maybe_escalate_kill(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.kill_sent {
        return Ok(());
    }
    let Some(term_sent_at) = active.terminate_sent_at else {
        return Ok(());
    };
    if term_sent_at.elapsed() >= TERM_GRACE {
        send_kill(active)?;
    }
    Ok(())
}

fn send_terminate(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.terminate_sent_at.is_none() {
        kill_exec_descendants(active, libc::SIGTERM)?;
        active.terminate_sent_at = Some(Instant::now());
    }
    Ok(())
}

fn send_kill(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if !active.kill_sent {
        kill_exec_descendants(active, libc::SIGKILL)?;
        active.kill_sent = true;
    }
    Ok(())
}

fn kill_exec_descendants(active: &ActiveProcess, signal: i32) -> Result<(), ServiceError> {
    if let Some(cgroup_dir) = &active.cgroup_dir {
        let path = cgroup_dir.join("cgroup.kill");
        if path.exists() {
            fs::write(&path, "1\n").map_err(|error| {
                supervisor_io(format!("writing cgroup.kill at {}", path.display()), error)
            })?;
        }
    }
    // SAFETY: kill is called with a negative process group id to signal the process group.
    let rc = unsafe { libc::kill(-active.process_group_id, signal) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(supervisor_io("signaling process group", error));
        }
    }
    Ok(())
}

fn pump_stdout(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.stdout_eof {
        return Ok(());
    }
    let Some(stdout) = active.stdout.as_mut() else {
        active.stdout_eof = true;
        return Ok(());
    };
    loop {
        let mut chunk = vec![0_u8; STDIO_CHUNK_BYTES];
        match io::Read::read(stdout, &mut chunk) {
            Ok(0) => {
                active.stdout = None;
                active.stdout_eof = true;
                active.event_queue.push_back(SupervisorEvent::StdoutEof);
                return Ok(());
            }
            Ok(size) => {
                chunk.truncate(size);
                active
                    .event_queue
                    .push_back(SupervisorEvent::StdoutChunk(chunk));
                if size < STDIO_CHUNK_BYTES {
                    return Ok(());
                }
            }
            Err(error) if would_block(&error) => return Ok(()),
            Err(error) => return Err(supervisor_io("reading child stdout", error)),
        }
    }
}

fn pump_stderr(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.stderr_eof {
        return Ok(());
    }
    let Some(stderr) = active.stderr.as_mut() else {
        active.stderr_eof = true;
        return Ok(());
    };
    loop {
        let mut chunk = vec![0_u8; STDIO_CHUNK_BYTES];
        match io::Read::read(stderr, &mut chunk) {
            Ok(0) => {
                active.stderr = None;
                active.stderr_eof = true;
                active.event_queue.push_back(SupervisorEvent::StderrEof);
                return Ok(());
            }
            Ok(size) => {
                chunk.truncate(size);
                active
                    .event_queue
                    .push_back(SupervisorEvent::StderrChunk(chunk));
                if size < STDIO_CHUNK_BYTES {
                    return Ok(());
                }
            }
            Err(error) if would_block(&error) => return Ok(()),
            Err(error) => return Err(supervisor_io("reading child stderr", error)),
        }
    }
}

fn pump_stdin(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    let Some(stdin) = active.stdin.as_mut() else {
        return Ok(());
    };
    while let Some(front) = active.stdin_queue.front() {
        let bytes = &front[active.stdin_offset..];
        if bytes.is_empty() {
            active.stdin_offset = 0;
            active.stdin_queue.pop_front();
            continue;
        }
        match io::Write::write(stdin, bytes) {
            Ok(0) => return Ok(()),
            Ok(size) => {
                active.stdin_offset = active.stdin_offset.saturating_add(size);
                active.stdin_queue_bytes = active.stdin_queue_bytes.saturating_sub(size);
                if active.stdin_offset >= front.len() {
                    active.stdin_offset = 0;
                    active.stdin_queue.pop_front();
                }
            }
            Err(error) if would_block(&error) => return Ok(()),
            Err(error) => return Err(supervisor_io("writing child stdin", error)),
        }
    }
    Ok(())
}

fn set_nonblocking(fd: i32) -> Result<(), ServiceError> {
    // SAFETY: fcntl with F_GETFL reads flags for a valid descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(supervisor_io(
            "reading descriptor flags",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl with F_SETFL writes modified descriptor flags.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(supervisor_io(
            "setting descriptor nonblocking mode",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn try_prepare_workload_cgroup(exec_id: u32, pid: i32) -> Option<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup/nvx.workload");
    let dir = root.join(format!("exec-{exec_id}-{pid}"));
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let procs = dir.join("cgroup.procs");
    if fs::write(&procs, format!("{pid}\n")).is_err() {
        return None;
    }
    Some(dir)
}

fn would_block(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock)
}

fn supervisor_error(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::Supervisor,
        message: message.into(),
    }
}

fn supervisor_io(context: impl Into<String>, error: io::Error) -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::Supervisor,
        message: format!("{}: {}", context.into(), error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::CreateProcessRequest;

    fn wait_for_event(
        supervisor: &mut LinuxProcessSupervisor,
        exec_id: u32,
        timeout: Duration,
        predicate: impl Fn(&SupervisorEvent) -> bool,
    ) -> Option<SupervisorEvent> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(event)) = supervisor.poll(exec_id)
                && predicate(&event)
            {
                return Some(event);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }

    #[test]
    fn subprocess_stdout_nul_bytes_are_preserved() {
        let mut supervisor = LinuxProcessSupervisor::new();
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id: 1,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf '\\001\\000\\002\\000\\003'".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .unwrap();
        let output = wait_for_event(&mut supervisor, 1, Duration::from_secs(2), |event| {
            matches!(event, SupervisorEvent::StdoutChunk(_))
        });
        match output {
            Some(SupervisorEvent::StdoutChunk(chunk)) => assert_eq!(chunk, vec![1, 0, 2, 0, 3]),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn terminate_escalates_and_emits_terminal_events() {
        let mut supervisor = LinuxProcessSupervisor::new();
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id: 2,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "trap '' TERM; sleep 5".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .unwrap();
        supervisor.terminate(2).unwrap();
        let signaled = wait_for_event(&mut supervisor, 2, Duration::from_secs(3), |event| {
            matches!(event, SupervisorEvent::Signaled(_))
        });
        assert!(signaled.is_some(), "expected signaled event");
        let cleaned = wait_for_event(&mut supervisor, 2, Duration::from_secs(1), |event| {
            matches!(event, SupervisorEvent::DescendantsCleaned)
        });
        assert!(cleaned.is_some(), "expected descendant cleanup event");
    }

    #[test]
    fn holder_spawn_abstraction_rejects_invalid_holder_pid() {
        let result = LinuxProcessSupervisor::new_with_holder(-1);
        assert!(result.is_err(), "invalid holder pid must fail closed");
    }

    #[test]
    #[ignore = "requires Linux root privileges and namespace/cgroup write access"]
    fn holder_namespace_execution_matches_holder_namespace_ids() {
        let mut supervisor = LinuxProcessSupervisor::new_with_holder(1).expect("holder");
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id: 9,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "readlink /proc/self/ns/mnt; readlink /proc/self/ns/pid; readlink /proc/self/ns/uts; readlink /proc/self/ns/ipc".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
    }
}
