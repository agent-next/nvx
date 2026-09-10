// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs;
use std::io;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use agent_protocol::{
    CreateProcessRequest, DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES,
    DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS, DEFAULT_STDIN_QUEUE_LIMIT_BYTES, ProcessSupervisor,
    ServiceError, ServiceErrorCode, SupervisorEvent, WORKLOAD_GID_MXC, WORKLOAD_UID_MXC,
};

const STDIO_CHUNK_BYTES: usize = 4096;
const TERM_GRACE: Duration = Duration::from_millis(250);
const POLL_SLEEP: Duration = Duration::from_millis(10);
const MAX_STDIO_CHUNKS_PER_REFRESH: usize = 4;
const DESCENDANTS_CLEANUP_DEADLINE: Duration = Duration::from_secs(5);

#[cfg(test)]
static PREPARE_CGROUP_FAILPOINT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub struct LinuxProcessSupervisor {
    active: Option<ActiveProcess>,
    holder: Option<NamespaceHolder>,
}

struct NamespaceHolder {
    cgroup_dir: PathBuf,
    mount_ns_fd: i32,
    uts_ns_fd: i32,
    ipc_ns_fd: i32,
    pid_ns_fd: i32,
}

struct PreparedExecCgroup {
    cgroup_dir: PathBuf,
    cgroup_procs_path: CString,
    cgroup_procs_fd: i32,
    cleanup_armed: bool,
}

impl PreparedExecCgroup {
    fn disarm_cleanup(&mut self) {
        self.cleanup_armed = false;
    }

    fn rollback_empty_cgroup(&mut self) -> io::Result<()> {
        let close_error = self.close_fd();
        let remove_error = fs::remove_dir(&self.cgroup_dir);
        match (close_error, remove_error) {
            (Ok(()), Ok(())) => {
                self.cleanup_armed = false;
                Ok(())
            }
            (Err(close), Ok(())) => Err(close),
            (Ok(()), Err(remove)) => Err(remove),
            (Err(close), Err(remove)) => Err(io::Error::other(format!(
                "closing prepared cgroup descriptor failed: {close}; removing empty prepared cgroup {} failed: {remove}",
                self.cgroup_dir.display()
            ))),
        }
    }

    fn close_fd(&mut self) -> io::Result<()> {
        if self.cgroup_procs_fd < 0 {
            return Ok(());
        }
        // SAFETY: best-effort close for process-owned descriptor.
        let rc = unsafe { libc::close(self.cgroup_procs_fd) };
        self.cgroup_procs_fd = -1;
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for PreparedExecCgroup {
    fn drop(&mut self) {
        if let Err(error) = self.close_fd() {
            eprintln!(
                "nvx-agent supervisor cleanup failure action=close-prepared-exec-cgroup-fd path={} error={}",
                self.cgroup_dir.display(),
                error
            );
        }
        if self.cleanup_armed
            && let Err(error) = fs::remove_dir(&self.cgroup_dir)
        {
            eprintln!(
                "nvx-agent supervisor cleanup failure action=remove-prepared-exec-cgroup path={} error={}",
                self.cgroup_dir.display(),
                error
            );
        }
    }
}

#[derive(Clone, Copy)]
struct ChildCredentialPlan {
    last_capability_index: i32,
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
    stdin_queue_bytes_atomic: Arc<AtomicUsize>,
    stdin_drained_bytes_atomic: Arc<AtomicUsize>,
    stdin_offset: usize,
    stdin_close_requested: bool,
    terminate_sent_at: Option<Instant>,
    kill_sent: bool,
    exit_status_reported: bool,
    descendants_cleaned_reported: bool,
    descendants_cleanup_started_at: Option<Instant>,
    cgroup_dir: Option<PathBuf>,
    event_queue: VecDeque<SupervisorEvent>,
    event_queue_bytes: usize,
    prefer_stdout_next: bool,
    holder_wait_status: Option<fs::File>,
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
        let cgroup_root = self
            .holder
            .as_ref()
            .map(|holder| holder.cgroup_dir.as_path())
            .unwrap_or_else(|| Path::new("/sys/fs/cgroup/nvx.workload"));
        let strict_cgroup = self.holder.is_some();
        let prepared_cgroup = if strict_cgroup {
            Some(prepare_exec_cgroup(cgroup_root, request.exec_id)?)
        } else {
            prepare_exec_cgroup(cgroup_root, request.exec_id).ok()
        };
        let credential_plan = prepare_child_credential_plan().ok();
        let mut holder_wait_status = None;
        let mut holder_wait_status_write_fd = None;
        if let Some(holder) = self.holder.as_ref() {
            let mount_ns_fd = holder.mount_ns_fd;
            let uts_ns_fd = holder.uts_ns_fd;
            let ipc_ns_fd = holder.ipc_ns_fd;
            let pid_ns_fd = holder.pid_ns_fd;
            let exec_cgroup_fd = prepared_cgroup
                .as_ref()
                .map(|prepared| prepared.cgroup_procs_fd)
                .ok_or_else(|| {
                    supervisor_error("holder-backed execution requires prepared cgroup")
                })?;
            let (status_read_fd, status_write_fd) = create_cloexec_pipe()
                .map_err(|error| supervisor_io("creating status pipe", error))?;
            // SAFETY: status_read_fd is newly created and uniquely owned here.
            let status_reader = unsafe { fs::File::from_raw_fd(status_read_fd) };
            set_nonblocking(status_reader.as_raw_fd())?;
            holder_wait_status = Some(status_reader);
            holder_wait_status_write_fd = Some(status_write_fd);
            // SAFETY: closure performs direct namespace and identity syscalls before exec.
            unsafe {
                command.pre_exec(move || {
                    // SAFETY: best-effort close in child pre-exec context.
                    let _ = libc::close(status_read_fd);
                    setns_checked(mount_ns_fd, libc::CLONE_NEWNS)?;
                    setns_checked(uts_ns_fd, libc::CLONE_NEWUTS)?;
                    setns_checked(ipc_ns_fd, libc::CLONE_NEWIPC)?;
                    setns_checked(pid_ns_fd, libc::CLONE_NEWPID)?;
                    move_self_to_cgroup_fd(exec_cgroup_fd)?;
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
                        let encoded = status.to_ne_bytes();
                        let _ = write_all_fd(status_write_fd, &encoded);
                        // SAFETY: best-effort close in child pre-exec context.
                        let _ = libc::close(status_write_fd);
                        if libc::WIFEXITED(status) {
                            libc::_exit(libc::WEXITSTATUS(status));
                        }
                        if libc::WIFSIGNALED(status) {
                            libc::_exit(128 + libc::WTERMSIG(status));
                        }
                        libc::_exit(1);
                    }
                    // SAFETY: best-effort close in child pre-exec context.
                    let _ = libc::close(status_write_fd);
                    apply_workload_exec_credentials(credential_plan)?;
                    Ok(())
                });
            }
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(spawn_error) => {
                if let Some(fd) = holder_wait_status_write_fd.take() {
                    // SAFETY: best-effort close for locally created descriptor.
                    let _ = unsafe { libc::close(fd) };
                }
                return Err(report_spawn_failure_with_cgroup_cleanup(
                    prepared_cgroup,
                    spawn_error,
                ));
            }
        };
        if let Some(fd) = holder_wait_status_write_fd.take() {
            // SAFETY: best-effort close for locally created descriptor.
            let _ = unsafe { libc::close(fd) };
        }
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

        let stdin_queue_bytes_atomic = Arc::new(AtomicUsize::new(0));
        let stdin_drained_bytes_atomic = Arc::new(AtomicUsize::new(0));
        let cgroup_dir = if let Some(mut prepared) = prepared_cgroup {
            prepared.disarm_cleanup();
            if self.holder.is_none() {
                let _ = move_pid_to_exec_cgroup(&prepared.cgroup_procs_path, pid);
            }
            Some(prepared.cgroup_dir.clone())
        } else {
            try_prepare_workload_cgroup(request.exec_id, pid)
        };
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
            stdin_queue_bytes_atomic,
            stdin_drained_bytes_atomic,
            stdin_offset: 0,
            stdin_close_requested: false,
            terminate_sent_at: None,
            kill_sent: false,
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: None,
            cgroup_dir,
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status,
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
        active
            .stdin_queue_bytes_atomic
            .store(next_bytes, Ordering::Release);
        active.stdin_queue.push_back(chunk);
        Ok(())
    }

    fn close_stdin(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        let active = self.require_active(exec_id)?;
        active.stdin_close_requested = true;
        if active.stdin_queue_bytes == 0
            && active.stdin_queue.is_empty()
            && active.stdin_offset == 0
        {
            active.stdin = None;
        }
        Ok(())
    }

    fn take_stdin_drain_bytes(&mut self, exec_id: u32) -> Result<usize, ServiceError> {
        let active = self.require_active(exec_id)?;
        Ok(active.stdin_drained_bytes_atomic.swap(0, Ordering::AcqRel))
    }

    fn peek_event(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
        let active = self.require_active(exec_id)?;
        refresh_active_state(active)?;
        Ok(active.event_queue.front().cloned())
    }

    fn ack_event(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        let mut release_cgroup = None;
        {
            let active = self.require_active(exec_id)?;
            if let Some(event) = active.event_queue.pop_front() {
                active.event_queue_bytes = active
                    .event_queue_bytes
                    .saturating_sub(event_payload_bytes(&event));
            }
            if active.exit_status_reported
                && active.descendants_cleaned_reported
                && active.stdout_eof
                && active.stderr_eof
                && active.event_queue.is_empty()
            {
                release_cgroup = active.cgroup_dir.clone();
            }
        }
        if release_cgroup.is_some() {
            self.active = None;
            remove_exec_cgroup(release_cgroup.as_deref(), self.holder.as_ref())?;
        }
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
        let event = self.peek_event(exec_id)?;
        if event.is_some() {
            self.ack_event(exec_id)?;
        }
        Ok(event)
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
                let release_cgroup = active.cgroup_dir.clone();
                self.active = None;
                remove_exec_cgroup(release_cgroup.as_deref(), self.holder.as_ref())?;
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
                let release_cgroup = active.cgroup_dir.clone();
                self.active = None;
                remove_exec_cgroup(release_cgroup.as_deref(), self.holder.as_ref())?;
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
        Ok(Self {
            cgroup_dir,
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

fn refresh_active_state(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if can_refresh_streams(active) {
        pump_stdio_round_robin(active)?;
    }
    pump_stdin(active)?;
    maybe_escalate_kill(active)?;
    if can_enqueue_event(active, 0) {
        maybe_report_exit(active)?;
    }
    if can_enqueue_event(active, 0) {
        maybe_report_descendants_cleaned(active)?;
    }
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
    if let Some(wait_status) = read_holder_wait_status(active)? {
        if libc::WIFEXITED(wait_status) {
            push_event(
                active,
                SupervisorEvent::Exited(libc::WEXITSTATUS(wait_status)),
            )?;
        } else if libc::WIFSIGNALED(wait_status) {
            push_event(
                active,
                SupervisorEvent::Signaled(libc::WTERMSIG(wait_status)),
            )?;
        } else {
            push_event(active, SupervisorEvent::Exited(1))?;
        }
    } else if let Some(code) = status.code() {
        push_event(active, SupervisorEvent::Exited(code))?;
    } else if let Some(signal) = status.signal() {
        push_event(active, SupervisorEvent::Signaled(signal))?;
    } else {
        push_event(active, SupervisorEvent::Exited(1))?;
    }
    active.exit_status_reported = true;
    Ok(())
}

fn maybe_report_descendants_cleaned(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    if active.descendants_cleaned_reported || !active.exit_status_reported {
        return Ok(());
    }
    if active.descendants_cleanup_started_at.is_none() {
        active.descendants_cleanup_started_at = Some(Instant::now());
    }
    kill_exec_descendants(active, libc::SIGKILL)?;
    if descendants_populated_zero(active)? {
        push_event(active, SupervisorEvent::DescendantsCleaned)?;
        active.descendants_cleaned_reported = true;
        return Ok(());
    }
    let started = active
        .descendants_cleanup_started_at
        .unwrap_or_else(Instant::now);
    if started.elapsed() >= DESCENDANTS_CLEANUP_DEADLINE {
        return Err(ServiceError {
            code: ServiceErrorCode::CleanupTimeout,
            message: "descendant cleanup deadline exceeded before populated=0".to_string(),
        });
    }
    Ok(())
}

fn descendants_populated_zero(active: &ActiveProcess) -> Result<bool, ServiceError> {
    let Some(cgroup_dir) = active.cgroup_dir.as_ref() else {
        return Ok(true);
    };
    let events_path = cgroup_dir.join("cgroup.events");
    let text = fs::read_to_string(&events_path).map_err(|error| {
        supervisor_io(
            format!("reading cgroup.events at {}", events_path.display()),
            error,
        )
    })?;
    let populated = parse_populated_from_cgroup_events(&text).ok_or_else(|| ServiceError {
        code: ServiceErrorCode::Supervisor,
        message: format!(
            "cgroup.events missing populated field at {}",
            events_path.display()
        ),
    })?;
    Ok(!populated)
}

fn parse_populated_from_cgroup_events(text: &str) -> Option<bool> {
    for line in text.lines() {
        let (key, value) = line.split_once(' ')?;
        if key == "populated" {
            return match value.trim() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
        }
    }
    None
}

fn read_holder_wait_status(active: &mut ActiveProcess) -> Result<Option<i32>, ServiceError> {
    let Some(mut pipe) = active.holder_wait_status.take() else {
        return Ok(None);
    };
    let mut bytes = [0_u8; std::mem::size_of::<i32>()];
    let result = match pipe.read(&mut bytes) {
        Ok(size) if size == bytes.len() => Ok(Some(i32::from_ne_bytes(bytes))),
        Ok(0) => Err(supervisor_error(
            "holder wait status unavailable (pipe closed before status write)",
        )),
        Ok(_) => Err(supervisor_error("holder wait status short read")),
        Err(error) if would_block(&error) => {
            Err(supervisor_error("holder wait status not yet readable"))
        }
        Err(error) => Err(supervisor_io("reading holder wait status", error)),
    };
    if result.is_err() {
        active.holder_wait_status = Some(pipe);
    }
    result
}

fn can_refresh_streams(active: &ActiveProcess) -> bool {
    if !active.event_queue.is_empty() {
        return false;
    }
    !event_queue_limits_reached(active)
}

fn can_enqueue_event(active: &ActiveProcess, payload_bytes: usize) -> bool {
    active.event_queue.len().saturating_add(1) <= DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS
        && active.event_queue_bytes.saturating_add(payload_bytes)
            <= DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES
}

fn event_queue_limits_reached(active: &ActiveProcess) -> bool {
    active.event_queue.len() >= DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_RECORDS
        || active.event_queue_bytes >= DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES
}

fn event_payload_bytes(event: &SupervisorEvent) -> usize {
    match event {
        SupervisorEvent::StdoutChunk(chunk) | SupervisorEvent::StderrChunk(chunk) => chunk.len(),
        _ => 0,
    }
}

fn push_event(active: &mut ActiveProcess, event: SupervisorEvent) -> Result<(), ServiceError> {
    let payload = event_payload_bytes(&event);
    if !can_enqueue_event(active, payload) {
        return Err(ServiceError {
            code: ServiceErrorCode::Backpressure,
            message: "supervisor event queue capacity exceeded".to_string(),
        });
    }
    let next_bytes = active
        .event_queue_bytes
        .checked_add(payload)
        .ok_or_else(|| supervisor_error("supervisor event queue byte overflow"))?;
    if next_bytes > DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES {
        return Err(ServiceError {
            code: ServiceErrorCode::Backpressure,
            message: "supervisor event queue reached byte capacity".to_string(),
        });
    }
    active.event_queue.push_back(event);
    active.event_queue_bytes = next_bytes;
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
        maybe_write_cgroup_kill(cgroup_dir, signal)?;
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

fn maybe_write_cgroup_kill(cgroup_dir: &Path, signal: i32) -> Result<(), ServiceError> {
    if signal != libc::SIGKILL {
        return Ok(());
    }
    let path = cgroup_dir.join("cgroup.kill");
    if path.exists() {
        fs::write(&path, "1\n").map_err(|error| {
            supervisor_io(format!("writing cgroup.kill at {}", path.display()), error)
        })?;
    }
    Ok(())
}

fn pump_stdio_round_robin(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    let mut budget = MAX_STDIO_CHUNKS_PER_REFRESH;
    while budget > 0 && !event_queue_limits_reached(active) {
        let mut produced = false;
        if active.prefer_stdout_next {
            produced |= pump_stdout_chunk(active)?;
            if budget > 0 && !event_queue_limits_reached(active) {
                produced |= pump_stderr_chunk(active)?;
            }
        } else {
            produced |= pump_stderr_chunk(active)?;
            if budget > 0 && !event_queue_limits_reached(active) {
                produced |= pump_stdout_chunk(active)?;
            }
        }
        active.prefer_stdout_next = !active.prefer_stdout_next;
        if !produced {
            break;
        }
        budget = budget.saturating_sub(1);
    }
    Ok(())
}

fn pump_stdout_chunk(active: &mut ActiveProcess) -> Result<bool, ServiceError> {
    if active.stdout_eof {
        return Ok(false);
    }
    let Some(stdout) = active.stdout.as_mut() else {
        active.stdout_eof = true;
        return Ok(false);
    };
    let mut chunk = vec![0_u8; STDIO_CHUNK_BYTES];
    match io::Read::read(stdout, &mut chunk) {
        Ok(0) => {
            active.stdout = None;
            active.stdout_eof = true;
            push_event(active, SupervisorEvent::StdoutEof)?;
            Ok(true)
        }
        Ok(size) => {
            chunk.truncate(size);
            push_event(active, SupervisorEvent::StdoutChunk(chunk))?;
            Ok(true)
        }
        Err(error) if would_block(&error) => Ok(false),
        Err(error) => Err(supervisor_io("reading child stdout", error)),
    }
}

fn pump_stderr_chunk(active: &mut ActiveProcess) -> Result<bool, ServiceError> {
    if active.stderr_eof {
        return Ok(false);
    }
    let Some(stderr) = active.stderr.as_mut() else {
        active.stderr_eof = true;
        return Ok(false);
    };
    let mut chunk = vec![0_u8; STDIO_CHUNK_BYTES];
    match io::Read::read(stderr, &mut chunk) {
        Ok(0) => {
            active.stderr = None;
            active.stderr_eof = true;
            push_event(active, SupervisorEvent::StderrEof)?;
            Ok(true)
        }
        Ok(size) => {
            chunk.truncate(size);
            push_event(active, SupervisorEvent::StderrChunk(chunk))?;
            Ok(true)
        }
        Err(error) if would_block(&error) => Ok(false),
        Err(error) => Err(supervisor_io("reading child stderr", error)),
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
                active
                    .stdin_queue_bytes_atomic
                    .store(active.stdin_queue_bytes, Ordering::Release);
                active
                    .stdin_drained_bytes_atomic
                    .fetch_add(size, Ordering::AcqRel);
                if active.stdin_offset >= front.len() {
                    active.stdin_offset = 0;
                    active.stdin_queue.pop_front();
                }
            }
            Err(error) if would_block(&error) => return Ok(()),
            Err(error) => return Err(supervisor_io("writing child stdin", error)),
        }
    }
    if active.stdin_close_requested && active.stdin_queue_bytes == 0 {
        active.stdin = None;
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

fn create_cloexec_pipe() -> io::Result<(i32, i32)> {
    let mut fds = [0_i32; 2];
    // SAFETY: pipe2 writes two descriptors into `fds` on success.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn try_prepare_workload_cgroup(exec_id: u32, pid: i32) -> Option<PathBuf> {
    let root = Path::new("/sys/fs/cgroup/nvx.workload");
    let mut prepared = prepare_exec_cgroup(root, exec_id).ok()?;
    if move_pid_to_exec_cgroup(&prepared.cgroup_procs_path, pid).is_err() {
        let _ = prepared.rollback_empty_cgroup();
        return None;
    }
    prepared.disarm_cleanup();
    Some(prepared.cgroup_dir.clone())
}

fn prepare_exec_cgroup(root: &Path, exec_id: u32) -> Result<PreparedExecCgroup, ServiceError> {
    #[cfg(test)]
    if PREPARE_CGROUP_FAILPOINT.load(Ordering::SeqCst) {
        return Err(supervisor_error(
            "injected failure preparing per-exec cgroup",
        ));
    }
    let mut attempt = 0_u64;
    loop {
        let dir = root.join(format!("exec-{exec_id}-{}-{attempt}", std::process::id()));
        match fs::create_dir(&dir) {
            Ok(()) => {
                let cgroup_procs_path = CString::new(format!("{}/cgroup.procs", dir.display()))
                    .map_err(|_| supervisor_error("invalid cgroup path encoding"))?;
                // SAFETY: cgroup.procs_path is a valid NUL-terminated path.
                let fd = unsafe {
                    libc::open(cgroup_procs_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC)
                };
                if fd < 0 {
                    let error = io::Error::last_os_error();
                    let _ = remove_exec_cgroup(Some(dir.as_path()), None);
                    return Err(supervisor_io("opening cgroup.procs", error));
                }
                return Ok(PreparedExecCgroup {
                    cgroup_dir: dir,
                    cgroup_procs_path,
                    cgroup_procs_fd: fd,
                    cleanup_armed: true,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                attempt = attempt.wrapping_add(1);
                continue;
            }
            Err(error) => return Err(supervisor_io("creating per-exec cgroup directory", error)),
        }
    }
}

fn report_spawn_failure_with_cgroup_cleanup(
    mut prepared: Option<PreparedExecCgroup>,
    spawn_error: io::Error,
) -> ServiceError {
    let primary = supervisor_io("spawning process", spawn_error);
    let Some(prepared) = prepared.as_mut() else {
        return primary;
    };
    let cleanup_path = prepared.cgroup_dir.clone();
    match prepared.rollback_empty_cgroup() {
        Ok(()) => primary,
        Err(cleanup_error) => ServiceError {
            code: primary.code,
            message: format!(
                "spawn rollback failed (primary=\"{}\", cleanup_action=\"remove_empty_prepared_exec_cgroup\", cleanup_path=\"{}\", cleanup_error=\"{}\")",
                primary.message,
                cleanup_path.display(),
                cleanup_error
            ),
        },
    }
}

fn move_self_to_cgroup_fd(cgroup_procs_fd: i32) -> io::Result<()> {
    let mut payload = [0_u8; 32];
    let pid = unsafe { libc::getpid() };
    let encoded = encode_pid_line(pid, &mut payload)?;
    write_all_fd(cgroup_procs_fd, encoded)
}

fn move_pid_to_exec_cgroup(cgroup_procs_path: &CString, pid: i32) -> io::Result<()> {
    // SAFETY: path pointer is NUL-terminated and flags are constants.
    let fd = unsafe { libc::open(cgroup_procs_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut payload = [0_u8; 32];
    let encoded = encode_pid_line(pid, &mut payload)?;
    let write_result = write_all_fd(fd, encoded);
    // SAFETY: best-effort close for opened descriptor.
    let _ = unsafe { libc::close(fd) };
    write_result
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
        // SAFETY: bytes points to a valid memory range for the current slice.
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
                "short write while updating cgroup.procs",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn remove_exec_cgroup(
    path: Option<&Path>,
    holder: Option<&NamespaceHolder>,
) -> Result<(), ServiceError> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(holder) = holder
        && path == holder.cgroup_dir.as_path()
    {
        return Ok(());
    }
    if let Some(root) = holder.as_ref().map(|value| value.cgroup_dir.as_path())
        && !path.starts_with(root)
    {
        return Ok(());
    }
    let mut attempts = 0_u32;
    loop {
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(error) if attempts < 10 && is_retryable_remove_error(&error) => {
                attempts = attempts.saturating_add(1);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(supervisor_io(
                    format!("removing per-exec cgroup directory {}", path.display()),
                    error,
                ));
            }
        }
    }
}

fn is_retryable_remove_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EBUSY) | Some(libc::ENOTEMPTY) | Some(libc::EINTR)
    )
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
    verify_no_capability_regain(plan)
}

fn verify_no_capability_regain(plan: ChildCredentialPlan) -> io::Result<()> {
    let mut header = LinuxCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [LinuxCapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: syscall receives valid pointers to writable header/data structures.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for entry in data {
        if entry.effective != 0 || entry.permitted != 0 || entry.inheritable != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capability set must be empty",
            ));
        }
    }
    let mut capability = 0_i32;
    while capability <= plan.last_capability_index {
        // SAFETY: prctl validates capability indexes and returns 0/1.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        if present > 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bounding capability set must be empty",
            ));
        }
        capability += 1;
    }
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PR_SET_NO_NEW_PRIVS is not locked",
        ));
    }
    Ok(())
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
    use std::fs;
    use std::io::Read;
    use tempfile::tempdir;

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

    fn count_exec_cgroup_dirs(root: &Path, prefix: &str) -> usize {
        let Ok(entries) = fs::read_dir(root) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .and_then(|kind| kind.is_dir().then_some(entry))
            })
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .count()
    }

    fn simulate_spawn_failure_with_prepared_cgroup(
        root: &Path,
        exec_id: u32,
    ) -> Result<(), ServiceError> {
        let prepared = prepare_exec_cgroup(root, exec_id)?;
        let spawn_error = io::Error::other("simulated command.spawn failure");
        Err(report_spawn_failure_with_cgroup_cleanup(
            Some(prepared),
            spawn_error,
        ))
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
    fn exec_cgroup_cleanup_skips_holder_and_removes_only_exec_children() {
        let tmp = tempdir().expect("tempdir");
        let holder_root = tmp.path().join("nvx.workload");
        fs::create_dir_all(&holder_root).expect("holder root");
        let exec_dir = holder_root.join("exec-44");
        fs::create_dir_all(&exec_dir).expect("exec dir");
        let holder = NamespaceHolder {
            cgroup_dir: holder_root.clone(),
            mount_ns_fd: -1,
            uts_ns_fd: -1,
            ipc_ns_fd: -1,
            pid_ns_fd: -1,
        };

        remove_exec_cgroup(Some(holder_root.as_path()), Some(&holder)).expect("remove holder root");
        assert!(
            holder_root.exists(),
            "holder membership cgroup must never be deleted by exec cleanup"
        );

        remove_exec_cgroup(Some(exec_dir.as_path()), Some(&holder)).expect("remove exec dir");
        assert!(
            !exec_dir.exists(),
            "exec cleanup must target only per-exec child cgroups"
        );
    }

    #[test]
    fn holder_spawn_fails_closed_when_exec_cgroup_prepare_fails() {
        PREPARE_CGROUP_FAILPOINT.store(true, Ordering::SeqCst);
        let holder_root = tempdir().expect("tempdir");
        let mut supervisor = LinuxProcessSupervisor {
            active: None,
            holder: Some(NamespaceHolder {
                cgroup_dir: holder_root.path().to_path_buf(),
                mount_ns_fd: -1,
                uts_ns_fd: -1,
                ipc_ns_fd: -1,
                pid_ns_fd: -1,
            }),
        };
        let spawn_result = supervisor.spawn(&CreateProcessRequest {
            exec_id: 99,
            argv: vec!["/bin/echo".to_string(), "x".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        });
        PREPARE_CGROUP_FAILPOINT.store(false, Ordering::SeqCst);
        assert!(spawn_result.is_err(), "spawn must fail closed");
        assert!(
            supervisor.active.is_none(),
            "failed cgroup setup must not leave an active child"
        );
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
        let active = supervisor.active.as_ref().expect("active child");
        let cgroup_dir = active.cgroup_dir.as_ref().expect("exec cgroup");
        let cgroup_text =
            fs::read_to_string(format!("/proc/{}/cgroup", active.child.id())).expect("cgroup");
        let exec_leaf = cgroup_dir
            .file_name()
            .expect("exec leaf")
            .to_string_lossy()
            .to_string();
        assert!(
            cgroup_text.contains(&exec_leaf),
            "child must be moved into per-exec cgroup"
        );
    }

    #[test]
    #[ignore = "requires Linux root privileges and namespace/cgroup write access"]
    fn holder_is_reused_across_two_sequential_execs() {
        fn run_and_wait(supervisor: &mut LinuxProcessSupervisor, exec_id: u32) {
            supervisor
                .spawn(&CreateProcessRequest {
                    exec_id,
                    argv: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "exit 0".to_string(),
                    ],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                })
                .expect("spawn");
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                let _ = supervisor.poll(exec_id);
                if supervisor.active.is_none() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("execution did not fully clean up before deadline");
        }

        let mut supervisor = LinuxProcessSupervisor::new_with_holder(1).expect("holder");
        let holder_cgroup = supervisor
            .holder
            .as_ref()
            .expect("holder present")
            .cgroup_dir
            .clone();
        run_and_wait(&mut supervisor, 70);
        assert!(
            supervisor.holder.is_some(),
            "holder must remain alive after first exec"
        );
        run_and_wait(&mut supervisor, 71);
        assert!(
            supervisor.holder.is_some(),
            "holder must remain alive after second exec"
        );
        assert_eq!(
            supervisor
                .holder
                .as_ref()
                .expect("holder present")
                .cgroup_dir,
            holder_cgroup
        );
    }

    #[test]
    fn cgroup_pid_line_encoder_returns_single_pid_newline_buffer() {
        let mut scratch = [0_u8; 32];
        let encoded = encode_pid_line(4242, &mut scratch).expect("encode pid");
        assert_eq!(encoded, b"4242\n");
    }

    #[test]
    fn move_pid_to_exec_cgroup_writes_atomic_pid_line() {
        let temp = tempdir().expect("tempdir");
        let cgroup_procs = temp.path().join("cgroup.procs");
        fs::File::create(&cgroup_procs).expect("create cgroup.procs");
        let c_path = CString::new(cgroup_procs.to_string_lossy().as_bytes().to_vec()).unwrap();

        move_pid_to_exec_cgroup(&c_path, 31337).expect("write cgroup.procs");

        let mut content = Vec::new();
        fs::File::open(&cgroup_procs)
            .expect("open cgroup.procs")
            .read_to_end(&mut content)
            .expect("read content");
        assert_eq!(content, b"31337\n");
    }

    #[test]
    fn sustained_stdout_with_unacked_front_stays_bounded_and_recovers_exactly() {
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 404_u32;
        let expected_bytes = 200 * 4096;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "dd if=/dev/zero bs=4096 count=200 2>/dev/null".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");

        let first = wait_for_event(&mut supervisor, exec_id, Duration::from_secs(2), |event| {
            matches!(event, SupervisorEvent::StdoutChunk(_))
        })
        .expect("first chunk");
        assert!(matches!(first, SupervisorEvent::StdoutChunk(_)));

        std::thread::sleep(Duration::from_millis(200));
        let active = supervisor.active.as_ref().expect("active process");
        assert_eq!(
            active.event_queue.len(),
            1,
            "front-unacked output must stop additional draining"
        );
        assert!(
            active.event_queue_bytes <= DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES,
            "event queue bytes must stay bounded"
        );

        let mut stdout_total = 0usize;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let Some(event) = supervisor.poll(exec_id).expect("poll") else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            if let SupervisorEvent::StdoutChunk(chunk) = event {
                stdout_total = stdout_total.saturating_add(chunk.len());
            }
            if supervisor.active.is_none() {
                break;
            }
        }
        assert_eq!(
            stdout_total, expected_bytes,
            "all producer bytes must recover losslessly after backpressure clears"
        );
        assert!(supervisor.active.is_none(), "process must fully clean up");
    }

    #[test]
    fn cgroup_kill_is_reserved_for_sigkill_escalation() {
        let temp = tempdir().expect("tempdir");
        let cgroup_kill = temp.path().join("cgroup.kill");
        fs::write(&cgroup_kill, b"initial").expect("seed cgroup.kill");

        maybe_write_cgroup_kill(temp.path(), libc::SIGTERM).expect("sigterm write check");
        let after_term = fs::read_to_string(&cgroup_kill).expect("read after term");
        assert_eq!(after_term, "initial", "SIGTERM must not write cgroup.kill");

        maybe_write_cgroup_kill(temp.path(), libc::SIGKILL).expect("sigkill write check");
        let after_kill = fs::read_to_string(&cgroup_kill).expect("read after kill");
        assert_eq!(
            after_kill, "1\n",
            "SIGKILL escalation must write cgroup.kill"
        );
    }

    #[test]
    fn descendants_cleaned_waits_for_populated_zero() {
        let temp = tempdir().expect("tempdir");
        let events_path = temp.path().join("cgroup.events");
        fs::write(&events_path, "populated 1\n").expect("seed populated=1");
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn child");
        let mut active = ActiveProcess {
            exec_id: 1,
            child,
            process_group_id: i32::MAX,
            stdin: None,
            stdout: None,
            stderr: None,
            stdout_eof: true,
            stderr_eof: true,
            stdin_queue: VecDeque::new(),
            stdin_queue_bytes: 0,
            stdin_queue_bytes_atomic: Arc::new(AtomicUsize::new(0)),
            stdin_drained_bytes_atomic: Arc::new(AtomicUsize::new(0)),
            stdin_offset: 0,
            stdin_close_requested: false,
            terminate_sent_at: None,
            kill_sent: true,
            exit_status_reported: true,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: None,
            cgroup_dir: Some(temp.path().to_path_buf()),
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: None,
        };

        maybe_report_descendants_cleaned(&mut active).expect("poll cleanup pending");
        assert!(
            !active.descendants_cleaned_reported,
            "cleanup cannot complete while populated=1"
        );
        assert!(active.event_queue.is_empty(), "no cleanup event yet");

        fs::write(&events_path, "populated 0\n").expect("flip populated=0");
        maybe_report_descendants_cleaned(&mut active).expect("poll cleanup complete");
        assert!(
            active.descendants_cleaned_reported,
            "cleanup should complete"
        );
        assert!(matches!(
            active.event_queue.front(),
            Some(SupervisorEvent::DescendantsCleaned)
        ));
    }

    #[test]
    fn descendants_cleanup_timeout_fails_closed() {
        let temp = tempdir().expect("tempdir");
        let events_path = temp.path().join("cgroup.events");
        fs::write(&events_path, "populated 1\n").expect("seed populated=1");
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 1")
            .spawn()
            .expect("spawn child");
        let mut active = ActiveProcess {
            exec_id: 2,
            child,
            process_group_id: i32::MAX,
            stdin: None,
            stdout: None,
            stderr: None,
            stdout_eof: true,
            stderr_eof: true,
            stdin_queue: VecDeque::new(),
            stdin_queue_bytes: 0,
            stdin_queue_bytes_atomic: Arc::new(AtomicUsize::new(0)),
            stdin_drained_bytes_atomic: Arc::new(AtomicUsize::new(0)),
            stdin_offset: 0,
            stdin_close_requested: false,
            terminate_sent_at: None,
            kill_sent: true,
            exit_status_reported: true,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: Some(
                Instant::now() - DESCENDANTS_CLEANUP_DEADLINE - Duration::from_millis(1),
            ),
            cgroup_dir: Some(temp.path().to_path_buf()),
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: None,
        };
        let error = maybe_report_descendants_cleaned(&mut active).expect_err("timeout expected");
        assert_eq!(error.code, ServiceErrorCode::CleanupTimeout);
    }

    #[test]
    fn remove_exec_cgroup_surfaces_non_empty_directory_error() {
        let temp = tempdir().expect("tempdir");
        let exec_dir = temp.path().join("exec-1");
        fs::create_dir_all(&exec_dir).expect("exec dir");
        fs::write(exec_dir.join("leftover"), b"x").expect("seed non-empty");
        let error = remove_exec_cgroup(Some(exec_dir.as_path()), None).expect_err("must fail");
        assert!(
            error.message.contains("removing per-exec cgroup directory"),
            "cleanup error context must be surfaced"
        );
    }

    #[test]
    #[ignore = "requires writable cgroupfs cgroup.procs semantics"]
    fn spawn_failure_rollback_retries_past_64_without_leaking_exec_dirs() {
        let root = tempdir().expect("tempdir");
        let exec_id = 31337_u32;
        let prefix = format!("exec-{exec_id}-{}-", std::process::id());
        for _ in 0..96 {
            let error = simulate_spawn_failure_with_prepared_cgroup(root.path(), exec_id)
                .expect_err("simulated spawn failure must return error");
            assert!(
                error
                    .message
                    .contains("spawning process: simulated command.spawn failure"),
                "primary spawn context missing: {}",
                error.message
            );
            assert_eq!(
                count_exec_cgroup_dirs(root.path(), &prefix),
                0,
                "failed spawn rollback must remove temporary exec cgroup"
            );
        }
        let mut prepared =
            prepare_exec_cgroup(root.path(), exec_id).expect("prepare after retries");
        let created_dir = prepared.cgroup_dir.clone();
        prepared.disarm_cleanup();
        drop(prepared);
        assert!(
            created_dir.exists(),
            "successful retry must keep prepared cgroup when cleanup is disarmed"
        );
        remove_exec_cgroup(Some(created_dir.as_path()), None).expect("remove created dir");
        assert_eq!(
            count_exec_cgroup_dirs(root.path(), &prefix),
            0,
            "final cleanup should leave no temporary exec cgroup directory"
        );
    }

    #[test]
    #[ignore = "requires writable cgroupfs cgroup.procs semantics"]
    fn spawn_failure_reports_cleanup_error_without_masking_primary() {
        let root = tempdir().expect("tempdir");
        let exec_id = 5150_u32;
        let prepared = prepare_exec_cgroup(root.path(), exec_id).expect("prepare");
        fs::write(prepared.cgroup_dir.join("busy"), b"x").expect("seed non-empty cgroup");
        let error = report_spawn_failure_with_cgroup_cleanup(
            Some(prepared),
            io::Error::other("simulated command.spawn failure"),
        );
        assert!(
            error
                .message
                .contains("primary=\"spawning process: simulated command.spawn failure\""),
            "primary spawn error context must be preserved: {}",
            error.message
        );
        assert!(
            error
                .message
                .contains("cleanup_action=\"remove_empty_prepared_exec_cgroup\""),
            "cleanup action context missing: {}",
            error.message
        );
    }

    #[test]
    #[ignore = "requires Linux root privileges and namespace/cgroup write access"]
    fn holder_failed_spawn_does_not_leak_exec_cgroup_directory() {
        let mut supervisor = LinuxProcessSupervisor::new_with_holder(1).expect("holder");
        let holder_root = supervisor
            .holder
            .as_ref()
            .expect("holder present")
            .cgroup_dir
            .clone();
        let exec_id = 9001_u32;
        let prefix = format!("exec-{exec_id}-{}-", std::process::id());
        let baseline = count_exec_cgroup_dirs(&holder_root, &prefix);
        let spawn_error = supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec!["/definitely/missing/binary".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect_err("missing binary spawn must fail");
        assert!(
            spawn_error.message.contains("spawning process"),
            "spawn failure context missing: {}",
            spawn_error.message
        );
        assert_eq!(
            count_exec_cgroup_dirs(&holder_root, &prefix),
            baseline,
            "failed holder-backed spawn must not leak per-exec cgroup directories"
        );
    }

    #[test]
    #[ignore = "requires Linux root privileges and holder namespaces/cgroups"]
    fn holder_backed_signaled_workload_reports_signaled_disposition() {
        let mut supervisor = LinuxProcessSupervisor::new_with_holder(1).expect("holder");
        let exec_id = 505_u32;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "kill -TERM $$".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        let signal = wait_for_event(&mut supervisor, exec_id, Duration::from_secs(3), |event| {
            matches!(event, SupervisorEvent::Signaled(_))
        });
        assert!(
            matches!(signal, Some(SupervisorEvent::Signaled(libc::SIGTERM))),
            "holder wrapper must preserve inner signal status"
        );
    }
}
