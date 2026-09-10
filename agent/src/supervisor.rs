// Copyright(c) The microvm authors.
// Licensed under the MIT License.

#[cfg(test)]
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fs;
use std::io;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
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
    ServiceError, ServiceErrorCode, SupervisorEvent, TerminationOutcome,
};

use crate::launcher::{self, LauncherConfig};

const STDIO_CHUNK_BYTES: usize = 4096;
const TERM_GRACE: Duration = Duration::from_millis(250);
const POLL_SLEEP: Duration = Duration::from_millis(10);
const MAX_STDIO_CHUNKS_PER_REFRESH: usize = 4;
const DESCENDANTS_CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
const DISCONNECT_TERM_BUDGET_PERCENT: u32 = 60;
const DISCONNECT_POST_KILL_BUDGET_PERCENT: u32 = 20;
const DISCONNECT_DISCARD_MAX_BYTES: usize = 2 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static PREPARE_CGROUP_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}
#[cfg(test)]
thread_local! {
    static REMOVE_CGROUP_FAIL_COUNTDOWN: Cell<u32> = const { Cell::new(0) };
}
#[cfg(test)]
thread_local! {
    static SET_NONBLOCKING_FAIL_CALL: Cell<u32> = const { Cell::new(0) };
}
#[cfg(test)]
thread_local! {
    static LAST_SPAWNED_PID: Cell<i32> = const { Cell::new(0) };
}
#[cfg(test)]
thread_local! {
    static ROLLBACK_CHILD_KILL_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}
#[cfg(test)]
thread_local! {
    static ROLLBACK_CHILD_WAIT_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}
#[cfg(test)]
thread_local! {
    static CGROUP_KILL_WRITE_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}
#[cfg(test)]
thread_local! {
    static CGROUP_KILL_EXISTS_PROBE_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}
#[cfg(test)]
thread_local! {
    static PROCESS_GROUP_SIGNAL_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}

pub struct LinuxProcessSupervisor {
    active: Option<ActiveProcess>,
    holder: Option<NamespaceHolder>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub struct SupervisorQueueUsage {
    pub stdin_queue_bytes: usize,
    pub event_queue_bytes: usize,
    pub event_queue_records: usize,
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

struct SpawnRollbackGuard {
    child: Option<Child>,
    process_group_id: i32,
    cgroup_dir: Option<PathBuf>,
    holder_root: Option<PathBuf>,
    cleanup_armed: bool,
}

impl SpawnRollbackGuard {
    fn new(
        child: Child,
        cgroup_dir: Option<PathBuf>,
        holder_root: Option<PathBuf>,
    ) -> SpawnRollbackGuard {
        let process_group_id = child.id() as i32;
        SpawnRollbackGuard {
            child: Some(child),
            process_group_id,
            cgroup_dir,
            holder_root,
            cleanup_armed: true,
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, ServiceError> {
        self.child
            .as_mut()
            .ok_or_else(|| supervisor_error("spawn rollback guard child is missing"))
    }

    fn into_child(mut self) -> Result<Child, ServiceError> {
        self.cleanup_armed = false;
        self.child
            .take()
            .ok_or_else(|| supervisor_error("spawn rollback guard child is missing"))
    }

    fn rollback_error(&mut self, primary: ServiceError) -> ServiceError {
        match self.cleanup_now() {
            Ok(()) => primary,
            Err(cleanup_error) => ServiceError {
                code: ServiceErrorCode::FatalSession,
                message: format!(
                    "{primary}; post-spawn rollback cleanup uncertainty: {}",
                    cleanup_error.message
                ),
            },
        }
    }

    fn cleanup_now(&mut self) -> Result<(), ServiceError> {
        if !self.cleanup_armed {
            return Ok(());
        }
        self.cleanup_armed = false;
        let mut failures = Vec::new();
        if let Some(cgroup_dir) = self.cgroup_dir.as_deref() {
            let path = cgroup_dir.join("cgroup.kill");
            if let Err(error) = maybe_write_cgroup_kill(cgroup_dir, libc::SIGKILL) {
                failures.push(
                    supervisor_io(format!("writing cgroup.kill at {}", path.display()), error)
                        .message,
                );
            }
        }
        // SAFETY: kill is called with a negative process group id to signal the process group.
        let kill_rc = unsafe { libc::kill(-self.process_group_id, libc::SIGKILL) };
        if kill_rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                failures.push(supervisor_io("signaling spawned process group", error).message);
            }
        }
        if let Some(child) = self.child.as_mut() {
            let kill_injected = rollback_child_kill_failpoint_now();
            if kill_injected {
                failures
                    .push("signaling spawned child rollback: injected kill failure".to_string());
            } else if let Err(error) = child.kill() {
                failures.push(supervisor_io("signaling spawned child rollback", error).message);
            }
            let wait_injected = rollback_child_wait_failpoint_now();
            if wait_injected {
                failures
                    .push("waiting for spawned child rollback: injected wait failure".to_string());
            } else if let Err(error) = child.wait() {
                failures.push(supervisor_io("waiting for spawned child rollback", error).message);
            }
        }
        self.child = None;
        if let Err(error) =
            remove_exec_cgroup(self.cgroup_dir.as_deref(), self.holder_root.as_deref())
        {
            failures.push(error.message);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(supervisor_error(format!(
                "rollback cleanup actions failed: {}",
                failures.join("; ")
            )))
        }
    }
}

#[cfg(test)]
fn rollback_child_kill_failpoint_now() -> bool {
    ROLLBACK_CHILD_KILL_FAILPOINT.with(|flag| {
        let current = flag.get();
        if current {
            flag.set(false);
        }
        current
    })
}

#[cfg(not(test))]
fn rollback_child_kill_failpoint_now() -> bool {
    false
}

#[cfg(test)]
fn rollback_child_wait_failpoint_now() -> bool {
    ROLLBACK_CHILD_WAIT_FAILPOINT.with(|flag| {
        let current = flag.get();
        if current {
            flag.set(false);
        }
        current
    })
}

#[cfg(not(test))]
fn rollback_child_wait_failpoint_now() -> bool {
    false
}

#[cfg(test)]
fn cgroup_kill_write_failpoint_now() -> bool {
    CGROUP_KILL_WRITE_FAILPOINT.with(|flag| {
        let current = flag.get();
        if current {
            flag.set(false);
        }
        current
    })
}

#[cfg(not(test))]
fn cgroup_kill_write_failpoint_now() -> bool {
    false
}

#[cfg(test)]
fn cgroup_kill_exists_probe_failpoint_now() -> bool {
    CGROUP_KILL_EXISTS_PROBE_FAILPOINT.with(|flag| {
        let current = flag.get();
        if current {
            flag.set(false);
        }
        current
    })
}

#[cfg(not(test))]
fn cgroup_kill_exists_probe_failpoint_now() -> bool {
    false
}

#[cfg(test)]
fn process_group_signal_failpoint_now() -> bool {
    PROCESS_GROUP_SIGNAL_FAILPOINT.with(|flag| {
        let current = flag.get();
        if current {
            flag.set(false);
        }
        current
    })
}

#[cfg(not(test))]
fn process_group_signal_failpoint_now() -> bool {
    false
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
    holder_wait_status_buffer: Vec<u8>,
    pending_terminal_event: Option<SupervisorEvent>,
    disconnect_discard_output: bool,
    discarded_output_bytes: usize,
    discard_byte_budget_exhausted: bool,
}

enum HolderWaitStatusRead {
    Ready(i32),
    Pending,
    EofBeforePayload,
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

    #[allow(dead_code)]
    pub fn queue_usage(&self) -> SupervisorQueueUsage {
        self.active
            .as_ref()
            .map(|active| SupervisorQueueUsage {
                stdin_queue_bytes: active.stdin_queue_bytes,
                event_queue_bytes: active.event_queue_bytes,
                event_queue_records: active.event_queue.len(),
            })
            .unwrap_or_default()
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

        let mut command;
        let cgroup_root = self
            .holder
            .as_ref()
            .map(|holder| holder.cgroup_dir.as_path())
            .unwrap_or_else(|| Path::new("/sys/fs/cgroup/nvx.workload"));
        let strict_cgroup = self.holder.is_some();
        let mut prepared_cgroup = if strict_cgroup {
            Some(prepare_exec_cgroup(cgroup_root, request.exec_id)?)
        } else {
            prepare_exec_cgroup(cgroup_root, request.exec_id).ok()
        };
        let mut holder_wait_status = None;
        let mut holder_launch_fds: Vec<RawFd> = Vec::new();
        let mut holder_config_write_fd = None;
        let mut holder_launcher_config: Option<LauncherConfig> = None;
        let mut holder_wait_status_write_fd = None;
        if let Some(holder) = self.holder.as_ref() {
            let exec_cgroup_fd = prepared_cgroup
                .as_ref()
                .map(|prepared| prepared.cgroup_procs_fd)
                .ok_or_else(|| {
                    supervisor_error("holder-backed execution requires prepared cgroup")
                })?;
            let mount_ns_fd = dup_inheritable_fd(holder.mount_ns_fd)?;
            let uts_ns_fd = dup_inheritable_fd(holder.uts_ns_fd)?;
            let ipc_ns_fd = dup_inheritable_fd(holder.ipc_ns_fd)?;
            let pid_ns_fd = dup_inheritable_fd(holder.pid_ns_fd)?;
            let cgroup_procs_fd = dup_inheritable_fd(exec_cgroup_fd)?;
            let (status_read_fd, status_write_fd) = create_cloexec_pipe()
                .map_err(|error| supervisor_io("creating status pipe", error))?;
            let status_write_fd = clear_cloexec(status_write_fd)?;
            let (config_read_fd, config_write_fd) = create_cloexec_pipe()
                .map_err(|error| supervisor_io("creating launcher config pipe", error))?;
            let config_read_fd = clear_cloexec(config_read_fd)?;
            // SAFETY: status_read_fd is newly created and uniquely owned here.
            let status_reader = unsafe { fs::File::from_raw_fd(status_read_fd) };
            set_nonblocking(status_reader.as_raw_fd())?;
            holder_wait_status = Some(status_reader);
            holder_wait_status_write_fd = Some(status_write_fd);
            command =
                Command::new(std::env::current_exe().map_err(|error| {
                    supervisor_io("resolving current nvx-agent executable", error)
                })?);
            command.args(launcher::build_launcher_command_args(
                config_read_fd,
                status_write_fd,
            ));
            command.stdin(Stdio::piped());
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
            command.process_group(0);

            holder_launch_fds.extend([
                mount_ns_fd,
                uts_ns_fd,
                ipc_ns_fd,
                pid_ns_fd,
                cgroup_procs_fd,
                config_read_fd,
            ]);
            holder_config_write_fd = Some(config_write_fd);
            holder_launcher_config = Some(LauncherConfig {
                version: 1,
                argv: request.argv.clone(),
                env: request.env.clone(),
                cwd: request.cwd.clone(),
                mount_ns_fd,
                uts_ns_fd,
                ipc_ns_fd,
                pid_ns_fd,
                cgroup_procs_fd,
            });
        } else {
            command = Command::new(&request.argv[0]);
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
        }

        let child = match command.spawn() {
            Ok(child) => child,
            Err(spawn_error) => {
                if let Some(fd) = holder_config_write_fd.take() {
                    // SAFETY: best-effort close for locally created descriptor.
                    let _ = unsafe { libc::close(fd) };
                }
                if let Some(fd) = holder_wait_status_write_fd.take() {
                    // SAFETY: best-effort close for locally created descriptor.
                    let _ = unsafe { libc::close(fd) };
                }
                close_fds_best_effort(&holder_launch_fds);
                return Err(report_spawn_failure_with_cgroup_cleanup(
                    prepared_cgroup,
                    spawn_error,
                ));
            }
        };
        #[cfg(test)]
        LAST_SPAWNED_PID.with(|pid| pid.set(child.id() as i32));
        let rollback_cgroup_dir = prepared_cgroup
            .as_ref()
            .map(|prepared| prepared.cgroup_dir.clone());
        let holder_root_for_rollback = self.holder.as_ref().map(|holder| holder.cgroup_dir.clone());
        let mut spawn_guard =
            SpawnRollbackGuard::new(child, rollback_cgroup_dir, holder_root_for_rollback);
        if let (Some(config), Some(fd)) = (
            holder_launcher_config.as_ref(),
            holder_config_write_fd.take(),
        ) {
            if let Err(error) = launcher::write_launcher_config(fd, config) {
                // SAFETY: best-effort close for locally created descriptor.
                let _ = unsafe { libc::close(fd) };
                close_fds_best_effort(&holder_launch_fds);
                if let Some(wait_fd) = holder_wait_status_write_fd.take() {
                    // SAFETY: best-effort close for locally created descriptor.
                    let _ = unsafe { libc::close(wait_fd) };
                }
                return Err(
                    spawn_guard.rollback_error(report_spawn_failure_with_cgroup_cleanup(
                        prepared_cgroup.take(),
                        io::Error::other(format!(
                            "writing launcher config to inherited pipe failed: {error}"
                        )),
                    )),
                );
            }
            // SAFETY: best-effort close for locally created descriptor.
            let _ = unsafe { libc::close(fd) };
        }
        if let Some(fd) = holder_wait_status_write_fd.take() {
            // SAFETY: best-effort close for locally created descriptor.
            let _ = unsafe { libc::close(fd) };
        }
        close_fds_best_effort(&holder_launch_fds);
        let pid = spawn_guard.child_mut()?.id() as i32;
        let mut stdin = spawn_guard.child_mut()?.stdin.take();
        let mut stdout = spawn_guard.child_mut()?.stdout.take();
        let mut stderr = spawn_guard.child_mut()?.stderr.take();
        if let Some(stdin_ref) = stdin.as_mut()
            && let Err(error) = set_nonblocking(stdin_ref.as_raw_fd())
        {
            return Err(spawn_guard.rollback_error(error));
        }
        if let Some(stdout_ref) = stdout.as_mut()
            && let Err(error) = set_nonblocking(stdout_ref.as_raw_fd())
        {
            return Err(spawn_guard.rollback_error(error));
        }
        if let Some(stderr_ref) = stderr.as_mut()
            && let Err(error) = set_nonblocking(stderr_ref.as_raw_fd())
        {
            return Err(spawn_guard.rollback_error(error));
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
        let child = spawn_guard.into_child()?;
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
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
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
        let holder_root = self.holder.as_ref().map(|holder| holder.cgroup_dir.clone());
        let active = self.require_active(exec_id)?;
        refresh_active_state(active, holder_root.as_deref())?;
        Ok(active.event_queue.front().cloned())
    }

    fn ack_event(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        let mut should_clear_active = false;
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
                should_clear_active = true;
            }
        }
        if should_clear_active {
            self.active = None;
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
        absolute_deadline: Instant,
    ) -> Result<bool, ServiceError> {
        let holder_root = self.holder.as_ref().map(|holder| holder.cgroup_dir.clone());
        let active = self.require_active(exec_id)?;
        active.disconnect_discard_output = true;
        active.event_queue.clear();
        active.event_queue_bytes = 0;
        active.stdin = None;
        let start = Instant::now();
        if start >= absolute_deadline {
            return Err(ServiceError {
                code: ServiceErrorCode::CleanupTimeout,
                message: format!(
                    "disconnect cleanup deadline already expired before SIGTERM (exec_id={exec_id})"
                ),
            });
        }
        let disconnect_budget = absolute_deadline.saturating_duration_since(start);
        let (term_grace_budget, post_kill_budget) = partition_disconnect_budget(disconnect_budget);
        let deadline_at = absolute_deadline;
        let kill_phase_deadline = deadline_at.checked_sub(post_kill_budget).unwrap_or(start);
        let term_phase_deadline = start
            .checked_add(term_grace_budget)
            .unwrap_or(deadline_at)
            .min(kill_phase_deadline);
        if Instant::now() >= absolute_deadline {
            return Err(ServiceError {
                code: ServiceErrorCode::CleanupTimeout,
                message: format!(
                    "disconnect cleanup deadline expired before SIGTERM dispatch (exec_id={exec_id})"
                ),
            });
        }
        send_terminate(active)?;

        while Instant::now() < term_phase_deadline {
            if Instant::now() >= absolute_deadline {
                return Err(ServiceError {
                    code: ServiceErrorCode::CleanupTimeout,
                    message: format!(
                        "disconnect cleanup deadline expired before SIGKILL phase (exec_id={exec_id})"
                    ),
                });
            }
            refresh_active_state_for_disconnect(active, holder_root.as_deref())?;
            if active.exit_status_reported
                && active.descendants_cleaned_reported
                && active.stdout_eof
                && active.stderr_eof
            {
                self.active = None;
                return Ok(true);
            }
            let now = Instant::now();
            let next_deadline = term_phase_deadline.min(absolute_deadline);
            if now >= next_deadline {
                break;
            }
            std::thread::sleep((next_deadline - now).min(POLL_SLEEP));
        }
        let now = Instant::now();
        if now >= absolute_deadline {
            return Err(ServiceError {
                code: ServiceErrorCode::CleanupTimeout,
                message: format!(
                    "disconnect cleanup deadline expired before SIGKILL dispatch (exec_id={exec_id})"
                ),
            });
        }
        let remaining_after_term = absolute_deadline.saturating_duration_since(now);
        if remaining_after_term < post_kill_budget {
            return Err(ServiceError {
                code: ServiceErrorCode::CleanupTimeout,
                message: format!(
                    "disconnect cleanup cannot reserve post-SIGKILL verification budget (exec_id={exec_id}, remaining={remaining_after_term:?}, required={post_kill_budget:?})"
                ),
            });
        }
        send_kill(active)?;
        while Instant::now() < deadline_at {
            if Instant::now() >= absolute_deadline {
                return Err(ServiceError {
                    code: ServiceErrorCode::CleanupTimeout,
                    message: format!(
                        "disconnect cleanup deadline expired during post-SIGKILL verification (exec_id={exec_id})"
                    ),
                });
            }
            refresh_active_state_for_disconnect(active, holder_root.as_deref())?;
            if active.exit_status_reported
                && active.descendants_cleaned_reported
                && active.stdout_eof
                && active.stderr_eof
            {
                self.active = None;
                return Ok(true);
            }
            let now = Instant::now();
            if now >= deadline_at {
                break;
            }
            std::thread::sleep((deadline_at - now).min(POLL_SLEEP));
        }
        Err(ServiceError {
            code: ServiceErrorCode::CleanupTimeout,
            message: format!(
                "disconnect cleanup exceeded absolute deadline after SIGKILL verification (exec_id={exec_id})"
            ),
        })
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

fn refresh_active_state(
    active: &mut ActiveProcess,
    holder_root: Option<&Path>,
) -> Result<(), ServiceError> {
    if can_refresh_streams(active) {
        pump_stdio_round_robin(active)?;
    }
    pump_stdin(active)?;
    maybe_escalate_kill(active)?;
    if can_enqueue_event(active, 0) {
        maybe_report_exit(active)?;
    }
    if can_enqueue_event(active, 0) {
        maybe_report_descendants_cleaned(active, holder_root)?;
    }
    Ok(())
}

fn refresh_active_state_for_disconnect(
    active: &mut ActiveProcess,
    holder_root: Option<&Path>,
) -> Result<(), ServiceError> {
    drain_stdio_for_disconnect(active)?;
    pump_stdin(active)?;
    if active.discard_byte_budget_exhausted && !active.kill_sent {
        send_kill(active)?;
    }
    maybe_escalate_kill(active)?;
    maybe_report_exit(active)?;
    maybe_report_descendants_cleaned(active, holder_root)?;
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
    let terminal = match read_holder_wait_status(active)? {
        HolderWaitStatusRead::Ready(wait_status) => {
            terminal_event_from_wait_status(wait_status, terminal_termination_outcome(active))
        }
        HolderWaitStatusRead::Pending => return Ok(()),
        HolderWaitStatusRead::EofBeforePayload => {
            terminal_event_from_exit_status(status, terminal_termination_outcome(active))
        }
    };
    active.pending_terminal_event = Some(terminal);
    active.exit_status_reported = true;
    Ok(())
}

fn maybe_report_descendants_cleaned(
    active: &mut ActiveProcess,
    holder_root: Option<&Path>,
) -> Result<(), ServiceError> {
    if active.descendants_cleaned_reported || !active.exit_status_reported {
        return Ok(());
    }
    if active.descendants_cleanup_started_at.is_none() {
        active.descendants_cleanup_started_at = Some(Instant::now());
    }
    kill_exec_descendants(active, libc::SIGKILL)?;
    if descendants_populated_zero(active)? {
        if let Err(error) = remove_exec_cgroup(active.cgroup_dir.as_deref(), holder_root) {
            let started = active
                .descendants_cleanup_started_at
                .unwrap_or_else(Instant::now);
            if started.elapsed() >= DESCENDANTS_CLEANUP_DEADLINE {
                return Err(ServiceError {
                    code: ServiceErrorCode::CleanupTimeout,
                    message: format!(
                        "descendant cleanup deadline exceeded before cgroup removal: {}",
                        error.message
                    ),
                });
            }
            return Ok(());
        }
        active.cgroup_dir = None;
        if let Some(terminal) = active.pending_terminal_event.take() {
            push_event(active, terminal)?;
        }
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

fn read_holder_wait_status(
    active: &mut ActiveProcess,
) -> Result<HolderWaitStatusRead, ServiceError> {
    let Some(mut pipe) = active.holder_wait_status.take() else {
        return Ok(HolderWaitStatusRead::EofBeforePayload);
    };
    let expected = std::mem::size_of::<i32>();
    while active.holder_wait_status_buffer.len() < expected {
        let mut scratch = [0_u8; std::mem::size_of::<i32>()];
        let start = active.holder_wait_status_buffer.len();
        let remaining = expected.saturating_sub(start);
        let read_result = pipe.read(&mut scratch[..remaining]);
        match read_result {
            Ok(0) => {
                if active.holder_wait_status_buffer.is_empty() {
                    return Ok(HolderWaitStatusRead::EofBeforePayload);
                }
                return Err(supervisor_error(
                    "holder wait status malformed (truncated payload)",
                ));
            }
            Ok(size) => {
                active
                    .holder_wait_status_buffer
                    .extend_from_slice(&scratch[..size]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if would_block(&error) => {
                active.holder_wait_status = Some(pipe);
                return Ok(HolderWaitStatusRead::Pending);
            }
            Err(error) => return Err(supervisor_io("reading holder wait status", error)),
        }
    }
    let mut bytes = [0_u8; std::mem::size_of::<i32>()];
    bytes.copy_from_slice(&active.holder_wait_status_buffer[..expected]);
    active.holder_wait_status_buffer.clear();
    Ok(HolderWaitStatusRead::Ready(i32::from_ne_bytes(bytes)))
}

fn terminal_termination_outcome(active: &ActiveProcess) -> Option<TerminationOutcome> {
    if active.kill_sent {
        return Some(TerminationOutcome::ForcedKill);
    }
    if active.terminate_sent_at.is_some() {
        return Some(TerminationOutcome::GracefulTerm);
    }
    None
}

fn terminal_event_from_wait_status(
    wait_status: i32,
    termination: Option<TerminationOutcome>,
) -> SupervisorEvent {
    if libc::WIFEXITED(wait_status) {
        return SupervisorEvent::Exited {
            exit_code: libc::WEXITSTATUS(wait_status),
            termination,
        };
    }
    if libc::WIFSIGNALED(wait_status) {
        return SupervisorEvent::Signaled {
            signal: libc::WTERMSIG(wait_status),
            termination,
        };
    }
    SupervisorEvent::Exited {
        exit_code: 1,
        termination,
    }
}

fn terminal_event_from_exit_status(
    status: std::process::ExitStatus,
    termination: Option<TerminationOutcome>,
) -> SupervisorEvent {
    if let Some(code) = status.code() {
        return SupervisorEvent::Exited {
            exit_code: code,
            termination,
        };
    }
    if let Some(signal) = status.signal() {
        return SupervisorEvent::Signaled {
            signal,
            termination,
        };
    }
    SupervisorEvent::Exited {
        exit_code: 1,
        termination,
    }
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
    if active.disconnect_discard_output {
        return Ok(());
    }
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

fn partition_disconnect_budget(total: Duration) -> (Duration, Duration) {
    if total.is_zero() {
        return (Duration::ZERO, Duration::ZERO);
    }
    let total_millis = total.as_millis().min(u128::from(u64::MAX)) as u64;
    let post_kill_millis =
        total_millis.saturating_mul(u64::from(DISCONNECT_POST_KILL_BUDGET_PERCENT)) / 100;
    let mut post_kill = Duration::from_millis(post_kill_millis.max(1));
    if post_kill > total {
        post_kill = total;
    }
    let term_millis = total_millis.saturating_mul(u64::from(DISCONNECT_TERM_BUDGET_PERCENT)) / 100;
    let mut term = Duration::from_millis(term_millis).min(TERM_GRACE);
    if term + post_kill > total {
        term = total.saturating_sub(post_kill);
    }
    (term, post_kill)
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
        let cgroup_kill_path = cgroup_dir.join("cgroup.kill");
        if let Err(error) = maybe_write_cgroup_kill(cgroup_dir, signal) {
            return Err(fatal_termination_uncertainty(format!(
                "initiating termination via cgroup.kill at {} for exec {} (signal={}, pgid={}) failed: {}",
                cgroup_kill_path.display(),
                active.exec_id,
                signal,
                active.process_group_id,
                error
            )));
        }
    }
    if process_group_signal_failpoint_now() {
        return Err(fatal_termination_uncertainty(format!(
            "signaling process group for exec {} (signal={}, pgid={}) failed: injected signal failure",
            active.exec_id, signal, active.process_group_id
        )));
    }
    // SAFETY: kill is called with a negative process group id to signal the process group.
    let rc = unsafe { libc::kill(-active.process_group_id, signal) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(fatal_termination_uncertainty(format!(
                "signaling process group for exec {} (signal={}, pgid={}) failed: {}",
                active.exec_id, signal, active.process_group_id, error
            )));
        }
    }
    Ok(())
}

fn maybe_write_cgroup_kill(cgroup_dir: &Path, signal: i32) -> io::Result<()> {
    let path = cgroup_dir.join("cgroup.kill");
    if cgroup_kill_exists_probe_failpoint_now() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected cgroup.kill existence probe failure",
        ));
    }
    if !path.try_exists()? {
        return Ok(());
    }
    if signal != libc::SIGKILL {
        return Ok(());
    }
    if cgroup_kill_write_failpoint_now() {
        return Err(io::Error::other("injected cgroup.kill write failure"));
    }
    if let Err(error) = fs::write(&path, "1\n") {
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOENT) | Some(libc::ENOTDIR)
        ) || error.kind() == io::ErrorKind::NotFound
        {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn pump_stdio_round_robin(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    let mut budget = MAX_STDIO_CHUNKS_PER_REFRESH;
    while budget > 0 && !event_queue_limits_reached(active) {
        let mut produced = 0_usize;
        if active.prefer_stdout_next {
            if pump_stdout_chunk(active)? {
                produced = produced.saturating_add(1);
            }
            if budget > produced
                && !event_queue_limits_reached(active)
                && pump_stderr_chunk(active)?
            {
                produced = produced.saturating_add(1);
            }
        } else {
            if pump_stderr_chunk(active)? {
                produced = produced.saturating_add(1);
            }
            if budget > produced
                && !event_queue_limits_reached(active)
                && pump_stdout_chunk(active)?
            {
                produced = produced.saturating_add(1);
            }
        }
        active.prefer_stdout_next = !active.prefer_stdout_next;
        if produced == 0 {
            break;
        }
        budget = budget.saturating_sub(produced);
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

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

fn discard_stdio_chunk(
    active: &mut ActiveProcess,
    stream: StreamKind,
) -> Result<bool, ServiceError> {
    if active.discard_byte_budget_exhausted {
        return Ok(false);
    }
    let size = match stream {
        StreamKind::Stdout => {
            read_discard_chunk(&mut active.stdout, &mut active.stdout_eof, "stdout")?
        }
        StreamKind::Stderr => {
            read_discard_chunk(&mut active.stderr, &mut active.stderr_eof, "stderr")?
        }
    };
    if let Some(size) = size {
        let next = active.discarded_output_bytes.saturating_add(size);
        active.discarded_output_bytes = next;
        if next >= DISCONNECT_DISCARD_MAX_BYTES {
            active.discard_byte_budget_exhausted = true;
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

fn read_discard_chunk<R: Read>(
    reader_opt: &mut Option<R>,
    eof_flag: &mut bool,
    label: &str,
) -> Result<Option<usize>, ServiceError> {
    if *eof_flag {
        return Ok(None);
    }
    let Some(reader) = reader_opt.as_mut() else {
        *eof_flag = true;
        return Ok(None);
    };
    let mut chunk = vec![0_u8; STDIO_CHUNK_BYTES];
    match io::Read::read(reader, &mut chunk) {
        Ok(0) => {
            *reader_opt = None;
            *eof_flag = true;
            Ok(Some(0))
        }
        Ok(size) => Ok(Some(size)),
        Err(error) if would_block(&error) => Ok(None),
        Err(error) => Err(supervisor_io(format!("reading child {label}"), error)),
    }
}

fn drain_stdio_for_disconnect(active: &mut ActiveProcess) -> Result<(), ServiceError> {
    let mut budget = MAX_STDIO_CHUNKS_PER_REFRESH;
    while budget > 0 {
        let mut produced = 0_usize;
        if active.prefer_stdout_next {
            if discard_stdio_chunk(active, StreamKind::Stdout)? {
                produced = produced.saturating_add(1);
            }
            if budget > produced && discard_stdio_chunk(active, StreamKind::Stderr)? {
                produced = produced.saturating_add(1);
            }
        } else {
            if discard_stdio_chunk(active, StreamKind::Stderr)? {
                produced = produced.saturating_add(1);
            }
            if budget > produced && discard_stdio_chunk(active, StreamKind::Stdout)? {
                produced = produced.saturating_add(1);
            }
        }
        active.prefer_stdout_next = !active.prefer_stdout_next;
        if produced == 0 {
            break;
        }
        budget = budget.saturating_sub(produced);
    }
    Ok(())
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
    #[cfg(test)]
    {
        let fail_now = SET_NONBLOCKING_FAIL_CALL.with(|fail_call| {
            let current = fail_call.get();
            if current == 0 {
                return false;
            }
            fail_call.set(current - 1);
            current == 1
        });
        if fail_now {
            return Err(supervisor_error(
                "injected failure setting descriptor nonblocking mode",
            ));
        }
    }
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

fn dup_inheritable_fd(fd: RawFd) -> Result<RawFd, ServiceError> {
    // SAFETY: dup duplicates an open descriptor owned by this process.
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(supervisor_io(
            format!("duplicating inherited descriptor {fd}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(duplicated)
}

fn clear_cloexec(fd: RawFd) -> Result<RawFd, ServiceError> {
    // SAFETY: fcntl(F_GETFD) reads descriptor flags for an open descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(supervisor_io(
            format!("reading descriptor flags for fd {fd}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl(F_SETFD) updates descriptor flags for an open descriptor.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(supervisor_io(
            format!("clearing close-on-exec for fd {fd}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

fn close_fds_best_effort(fds: &[RawFd]) {
    for fd in fds {
        // SAFETY: best-effort close for process-owned descriptor duplicates.
        let _ = unsafe { libc::close(*fd) };
    }
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
    if PREPARE_CGROUP_FAILPOINT.with(Cell::get) {
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

fn remove_exec_cgroup(path: Option<&Path>, holder_root: Option<&Path>) -> Result<(), ServiceError> {
    let Some(path) = path else {
        return Ok(());
    };
    if holder_root.is_some_and(|root| path == root) {
        return Ok(());
    }
    if let Some(root) = holder_root
        && !path.starts_with(root)
    {
        return Ok(());
    }
    #[cfg(test)]
    {
        if REMOVE_CGROUP_FAIL_COUNTDOWN.with(|countdown| {
            let remaining = countdown.get();
            if remaining == 0 {
                return false;
            }
            countdown.set(remaining - 1);
            true
        }) {
            return Err(supervisor_io(
                format!("removing per-exec cgroup directory {}", path.display()),
                io::Error::from_raw_os_error(libc::EBUSY),
            ));
        }
    }
    let mut attempts = 0_u32;
    loop {
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(error) if attempts < 10 && is_retryable_remove_error(&error) => {
                remove_emulated_cgroup_control_files(path);
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

fn remove_emulated_cgroup_control_files(path: &Path) {
    for filename in ["cgroup.events", "cgroup.kill", "cgroup.procs"] {
        let file_path = path.join(filename);
        match fs::remove_file(&file_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
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

fn fatal_termination_uncertainty(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::FatalSession,
        message: format!("termination state uncertain: {}", message.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::{
        AccessMode, AuthenticateChannelRequest, CancelReason, CanonicalHostMappingRoot,
        ConfigureSessionRequest, DnsStatus, LaunchBinding, LaunchIdentity,
        MappingContainmentPolicy, MxcControlService, NetworkMode, NetworkSetupState, NetworkStatus,
        PROTOCOL_VERSION, SERVICE_IDENTITY, SessionConfiguration, SymlinkContainmentPolicy,
    };
    use std::fs;
    use std::io::Read;
    use tempfile::tempdir;

    struct TestFailpointScope;

    impl TestFailpointScope {
        fn new() -> Self {
            PREPARE_CGROUP_FAILPOINT.with(|failpoint| failpoint.set(false));
            REMOVE_CGROUP_FAIL_COUNTDOWN.with(|countdown| countdown.set(0));
            SET_NONBLOCKING_FAIL_CALL.with(|fail_call| fail_call.set(0));
            LAST_SPAWNED_PID.with(|pid| pid.set(0));
            ROLLBACK_CHILD_KILL_FAILPOINT.with(|flag| flag.set(false));
            ROLLBACK_CHILD_WAIT_FAILPOINT.with(|flag| flag.set(false));
            CGROUP_KILL_WRITE_FAILPOINT.with(|flag| flag.set(false));
            CGROUP_KILL_EXISTS_PROBE_FAILPOINT.with(|flag| flag.set(false));
            PROCESS_GROUP_SIGNAL_FAILPOINT.with(|flag| flag.set(false));
            Self
        }
    }

    impl Drop for TestFailpointScope {
        fn drop(&mut self) {
            PREPARE_CGROUP_FAILPOINT.with(|failpoint| failpoint.set(false));
            REMOVE_CGROUP_FAIL_COUNTDOWN.with(|countdown| countdown.set(0));
            SET_NONBLOCKING_FAIL_CALL.with(|fail_call| fail_call.set(0));
            LAST_SPAWNED_PID.with(|pid| pid.set(0));
            ROLLBACK_CHILD_KILL_FAILPOINT.with(|flag| flag.set(false));
            ROLLBACK_CHILD_WAIT_FAILPOINT.with(|flag| flag.set(false));
            CGROUP_KILL_WRITE_FAILPOINT.with(|flag| flag.set(false));
            CGROUP_KILL_EXISTS_PROBE_FAILPOINT.with(|flag| flag.set(false));
            PROCESS_GROUP_SIGNAL_FAILPOINT.with(|flag| flag.set(false));
        }
    }

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

    fn wait_for_exit_capture(active: &mut ActiveProcess, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            maybe_report_exit(active).expect("capture terminal disposition");
            if active.exit_status_reported {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for child exit capture");
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

    fn spawn_signaled_child(signal: i32) -> Child {
        let script = format!("kill -{signal} $$");
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .spawn()
            .expect("spawn signaled child")
    }

    fn runtime_test_service() -> MxcControlService {
        let launch = LaunchIdentity {
            generation: 11,
            nonce: [11; 16],
        };
        let binding = LaunchBinding {
            protocol_version: PROTOCOL_VERSION,
            image_version: "img-v1".to_string(),
            launch,
            channel_generation: 19,
        };
        let mut service = MxcControlService::new_pid1_runtime(binding, 4242);
        service
            .authenticate_channel(
                AuthenticateChannelRequest {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch,
                    channel_generation: 19,
                    capability_proof: [11; 32],
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
                channel_generation: 19,
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
                    attributes: std::collections::BTreeMap::new(),
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

    fn cleanup_active_exec(supervisor: &mut LinuxProcessSupervisor, exec_id: u32) {
        if supervisor.active.is_none() {
            return;
        }
        let _ = supervisor.kill(exec_id);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if supervisor.active.is_none() {
                return;
            }
            let _ = supervisor.poll(exec_id);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_pid_eventually_absent(pid: i32, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            // SAFETY: kill with signal 0 probes whether pid exists and is accessible.
            let rc = unsafe { libc::kill(pid, 0) };
            if rc != 0 {
                let os_error = io::Error::last_os_error();
                if os_error.raw_os_error() == Some(libc::ESRCH) {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("rolled-back spawned child pid {pid} still appears alive");
    }

    fn eof_holder_status_pipe() -> fs::File {
        let (read_fd, write_fd) = create_cloexec_pipe().expect("create holder status pipe");
        // SAFETY: write_fd is owned by this test helper and closed exactly once.
        unsafe { libc::close(write_fd) };
        // SAFETY: read fd is uniquely owned and converted into File.
        let reader = unsafe { fs::File::from_raw_fd(read_fd) };
        set_nonblocking(reader.as_raw_fd()).expect("set nonblocking holder status pipe");
        reader
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
            matches!(event, SupervisorEvent::Signaled { .. })
        });
        assert!(signaled.is_some(), "expected signaled event");
        let cleaned = wait_for_event(&mut supervisor, 2, Duration::from_secs(1), |event| {
            matches!(event, SupervisorEvent::DescendantsCleaned)
        });
        assert!(cleaned.is_some(), "expected descendant cleanup event");
    }

    #[test]
    fn disconnect_cleanup_escalates_to_sigkill_within_total_budget() {
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 90_u32;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "trap '' TERM; sleep 30".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        let budget = Duration::from_millis(700);
        let started = Instant::now();
        let deadline = started.checked_add(budget).unwrap_or(started);
        let cleaned = supervisor
            .cleanup_for_disconnect(exec_id, deadline)
            .expect("disconnect cleanup");
        let elapsed = started.elapsed();
        assert!(cleaned, "cleanup should succeed via SIGKILL escalation");
        assert!(
            elapsed <= budget + Duration::from_millis(300),
            "cleanup must stay within bounded total budget (elapsed={elapsed:?}, budget={budget:?})"
        );
        assert!(supervisor.active.is_none());
    }

    #[test]
    fn disconnect_cleanup_drains_output_even_when_queue_is_nonempty() {
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 91_u32;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "trap '' TERM; dd if=/dev/zero bs=1024 count=128 2>/dev/null; (dd if=/dev/zero bs=1024 count=128 2>/dev/null; sleep 30) & cat >/dev/null".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        let peek_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < peek_deadline {
            if let Some(SupervisorEvent::StdoutChunk(_)) =
                supervisor.peek_event(exec_id).expect("peek")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            supervisor
                .active
                .as_ref()
                .is_some_and(|active| !active.event_queue.is_empty()),
            "expected non-empty queue before disconnect cleanup"
        );
        let now = Instant::now();
        let deadline = now.checked_add(Duration::from_secs(2)).unwrap_or(now);
        let cleaned = supervisor
            .cleanup_for_disconnect(exec_id, deadline)
            .expect("disconnect cleanup");
        assert!(cleaned, "cleanup must finish with queued output present");
        assert_eq!(supervisor.queue_usage().event_queue_records, 0);
        assert_eq!(supervisor.queue_usage().event_queue_bytes, 0);
        assert!(supervisor.active.is_none());
    }

    #[test]
    fn disconnect_cleanup_deadline_already_expired_fails_before_signals() {
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 92_u32;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 30".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap_or_else(Instant::now);
        let error = supervisor
            .cleanup_for_disconnect(exec_id, deadline)
            .expect_err("expired deadline must fail immediately");
        assert_eq!(error.code, ServiceErrorCode::CleanupTimeout);
        let active = supervisor.active.as_ref().expect("active process retained");
        assert!(active.terminate_sent_at.is_none(), "must not send SIGTERM");
        assert!(!active.kill_sent, "must not send SIGKILL");
        cleanup_active_exec(&mut supervisor, exec_id);
    }

    #[test]
    fn disconnect_cleanup_very_short_deadline_stays_within_budget_tolerance() {
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 93_u32;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "trap '' TERM; sleep 30".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(1))
            .unwrap_or(started);
        let error = supervisor
            .cleanup_for_disconnect(exec_id, deadline)
            .expect_err("very short deadline must fail closed");
        let elapsed = started.elapsed();
        assert_eq!(error.code, ServiceErrorCode::CleanupTimeout);
        assert!(
            elapsed <= Duration::from_millis(250),
            "disconnect cleanup must not sleep past a very short deadline (elapsed={elapsed:?})"
        );
        cleanup_active_exec(&mut supervisor, exec_id);
    }

    #[test]
    fn terminate_with_empty_holder_status_pipe_uses_launcher_signal_once() {
        let exec_id = 73_u32;
        let temp = tempdir().expect("tempdir");
        let exec_dir = temp.path().join("exec-terminate");
        fs::create_dir_all(&exec_dir).expect("create exec cgroup dir");
        fs::write(exec_dir.join("cgroup.events"), "populated 0\n").expect("seed populated=0");

        let child = spawn_signaled_child(libc::SIGTERM);
        let mut supervisor = LinuxProcessSupervisor::new();
        supervisor.active = Some(ActiveProcess {
            exec_id,
            process_group_id: child.id() as i32,
            child,
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
            kill_sent: false,
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: None,
            cgroup_dir: Some(exec_dir),
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: Some(eof_holder_status_pipe()),
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        });

        supervisor.terminate(exec_id).expect("terminate");
        let mut terminal_count = 0usize;
        let mut cleaned_count = 0usize;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if supervisor.active.is_none() {
                break;
            }
            let Some(event) = supervisor.poll(exec_id).expect("poll") else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            match event {
                SupervisorEvent::Signaled {
                    signal,
                    termination,
                } => {
                    terminal_count = terminal_count.saturating_add(1);
                    assert_eq!(signal, libc::SIGTERM);
                    assert_eq!(termination, Some(TerminationOutcome::GracefulTerm));
                }
                SupervisorEvent::Exited { termination, .. } => {
                    terminal_count = terminal_count.saturating_add(1);
                    assert_eq!(termination, Some(TerminationOutcome::GracefulTerm));
                }
                SupervisorEvent::DescendantsCleaned => {
                    cleaned_count = cleaned_count.saturating_add(1);
                }
                _ => {}
            }
        }
        assert!(
            supervisor.active.is_none(),
            "active process must fully clean up"
        );
        assert_eq!(terminal_count, 1, "must publish exactly one terminal event");
        assert_eq!(cleaned_count, 1, "must publish descendants-cleaned once");
    }

    #[test]
    fn kill_with_empty_holder_status_pipe_uses_launcher_signal_once() {
        let exec_id = 74_u32;
        let temp = tempdir().expect("tempdir");
        let exec_dir = temp.path().join("exec-kill");
        fs::create_dir_all(&exec_dir).expect("create exec cgroup dir");
        fs::write(exec_dir.join("cgroup.events"), "populated 0\n").expect("seed populated=0");
        fs::write(exec_dir.join("cgroup.kill"), "initial").expect("seed cgroup.kill");

        let child = spawn_signaled_child(libc::SIGKILL);
        let mut supervisor = LinuxProcessSupervisor::new();
        supervisor.active = Some(ActiveProcess {
            exec_id,
            process_group_id: child.id() as i32,
            child,
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
            kill_sent: false,
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: None,
            cgroup_dir: Some(exec_dir.clone()),
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: Some(eof_holder_status_pipe()),
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        });

        supervisor.kill(exec_id).expect("kill");
        let mut terminal_count = 0usize;
        let mut cleaned_count = 0usize;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if supervisor.active.is_none() {
                break;
            }
            let Some(event) = supervisor.poll(exec_id).expect("poll") else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            match event {
                SupervisorEvent::Signaled {
                    signal,
                    termination,
                } => {
                    terminal_count = terminal_count.saturating_add(1);
                    assert_eq!(signal, libc::SIGKILL);
                    assert_eq!(termination, Some(TerminationOutcome::ForcedKill));
                }
                SupervisorEvent::Exited { termination, .. } => {
                    terminal_count = terminal_count.saturating_add(1);
                    assert_eq!(termination, Some(TerminationOutcome::ForcedKill));
                }
                SupervisorEvent::DescendantsCleaned => {
                    cleaned_count = cleaned_count.saturating_add(1);
                }
                _ => {}
            }
        }
        assert!(
            supervisor.active.is_none(),
            "active process must fully clean up"
        );
        assert_eq!(terminal_count, 1, "must publish exactly one terminal event");
        assert_eq!(cleaned_count, 1, "must publish descendants-cleaned once");
    }

    #[test]
    fn malformed_nonempty_holder_status_payload_fails_closed() {
        let child = spawn_signaled_child(libc::SIGTERM);
        let (read_fd, write_fd) = create_cloexec_pipe().expect("create holder status pipe");
        // SAFETY: write fd is owned in this scope for test setup.
        let mut writer = unsafe { fs::File::from_raw_fd(write_fd) };
        std::io::Write::write_all(&mut writer, &[0x7f]).expect("write partial payload");
        drop(writer);
        // SAFETY: read fd is uniquely owned and converted into File.
        let reader = unsafe { fs::File::from_raw_fd(read_fd) };
        set_nonblocking(reader.as_raw_fd()).expect("set nonblocking");

        let mut active = ActiveProcess {
            exec_id: 88,
            process_group_id: child.id() as i32,
            child,
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
            kill_sent: false,
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: None,
            cgroup_dir: None,
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: Some(reader),
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match maybe_report_exit(&mut active) {
                Ok(()) if !active.exit_status_reported => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(()) => panic!("malformed payload must fail closed"),
                Err(error) => {
                    assert!(
                        error.message.contains("malformed"),
                        "must reject nonempty truncated payload: {}",
                        error.message
                    );
                    return;
                }
            }
        }
        panic!("timed out waiting for malformed payload error");
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

        remove_exec_cgroup(
            Some(holder_root.as_path()),
            Some(holder.cgroup_dir.as_path()),
        )
        .expect("remove holder root");
        assert!(
            holder_root.exists(),
            "holder membership cgroup must never be deleted by exec cleanup"
        );

        remove_exec_cgroup(Some(exec_dir.as_path()), Some(holder.cgroup_dir.as_path()))
            .expect("remove exec dir");
        assert!(
            !exec_dir.exists(),
            "exec cleanup must target only per-exec child cgroups"
        );
    }

    #[test]
    fn holder_spawn_fails_closed_when_exec_cgroup_prepare_fails() {
        let _scope = TestFailpointScope::new();
        PREPARE_CGROUP_FAILPOINT.with(|failpoint| failpoint.set(true));
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
        assert!(spawn_result.is_err(), "spawn must fail closed");
        assert!(
            supervisor.active.is_none(),
            "failed cgroup setup must not leave an active child"
        );
    }

    #[test]
    fn post_spawn_nonblocking_failure_rolls_back_child_and_clears_active_state() {
        let _scope = TestFailpointScope::new();
        SET_NONBLOCKING_FAIL_CALL.with(|fail_call| fail_call.set(1));
        let mut supervisor = LinuxProcessSupervisor::new();
        let spawn_result = supervisor.spawn(&CreateProcessRequest {
            exec_id: 707,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 5".to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        });
        let error = spawn_result.expect_err("nonblocking setup failure must rollback");
        assert_eq!(
            error.code,
            ServiceErrorCode::Supervisor,
            "successful rollback must remain a retryable supervisor spawn error"
        );
        assert!(
            error
                .message
                .contains("injected failure setting descriptor nonblocking mode"),
            "expected injected failure to surface: {}",
            error.message
        );
        assert!(
            supervisor.active.is_none(),
            "failed post-spawn setup must not leave active process state"
        );
        let spawned_pid = LAST_SPAWNED_PID.with(|pid| pid.get());
        assert!(spawned_pid > 0, "spawned pid must be captured");
        assert_pid_eventually_absent(spawned_pid, Duration::from_secs(2));
    }

    #[test]
    fn rollback_wait_failure_is_fatal_and_preserves_cleanup_context() {
        let _scope = TestFailpointScope::new();
        SET_NONBLOCKING_FAIL_CALL.with(|fail_call| fail_call.set(1));
        ROLLBACK_CHILD_WAIT_FAILPOINT.with(|flag| flag.set(true));
        let mut supervisor = LinuxProcessSupervisor::new();
        let spawn_result = supervisor.spawn(&CreateProcessRequest {
            exec_id: 708,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 5".to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        });
        let error = spawn_result.expect_err("rollback wait failure must fail closed");
        assert_eq!(error.code, ServiceErrorCode::FatalSession);
        assert!(
            error
                .message
                .contains("injected failure setting descriptor nonblocking mode"),
            "primary setup failure context must be preserved: {}",
            error.message
        );
        assert!(
            error
                .message
                .contains("post-spawn rollback cleanup uncertainty"),
            "cleanup uncertainty marker must be present: {}",
            error.message
        );
        assert!(
            error.message.contains("injected wait failure"),
            "cleanup failure context must include wait failure: {}",
            error.message
        );
        assert!(
            supervisor.active.is_none(),
            "active process state must be cleared"
        );
    }

    #[test]
    fn rollback_kill_failure_is_fatal_and_preserves_cleanup_context() {
        let _scope = TestFailpointScope::new();
        SET_NONBLOCKING_FAIL_CALL.with(|fail_call| fail_call.set(1));
        ROLLBACK_CHILD_KILL_FAILPOINT.with(|flag| flag.set(true));
        let mut supervisor = LinuxProcessSupervisor::new();
        let spawn_result = supervisor.spawn(&CreateProcessRequest {
            exec_id: 709,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 5".to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        });
        let error = spawn_result.expect_err("rollback kill failure must fail closed");
        assert_eq!(error.code, ServiceErrorCode::FatalSession);
        assert!(
            error
                .message
                .contains("injected failure setting descriptor nonblocking mode"),
            "primary setup failure context must be preserved: {}",
            error.message
        );
        assert!(
            error
                .message
                .contains("post-spawn rollback cleanup uncertainty"),
            "cleanup uncertainty marker must be present: {}",
            error.message
        );
        assert!(
            error.message.contains("injected kill failure"),
            "cleanup failure context must include kill failure: {}",
            error.message
        );
        assert!(
            supervisor.active.is_none(),
            "active process state must be cleared"
        );
    }

    #[test]
    fn rollback_cgroup_removal_failure_is_fatal_and_preserves_cleanup_context() {
        let _scope = TestFailpointScope::new();
        let temp = tempdir().expect("tempdir");
        let holder_root = temp.path().join("nvx.workload");
        let exec_dir = holder_root.join("exec-709");
        fs::create_dir_all(&exec_dir).expect("exec cgroup dir");
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 5")
            .spawn()
            .expect("spawn child");
        let spawned_pid = child.id() as i32;
        let mut guard =
            SpawnRollbackGuard::new(child, Some(exec_dir.clone()), Some(holder_root.clone()));
        REMOVE_CGROUP_FAIL_COUNTDOWN.with(|countdown| countdown.set(1));
        let error = guard.rollback_error(supervisor_error(
            "injected post-spawn setup failure requiring rollback",
        ));
        assert_eq!(error.code, ServiceErrorCode::FatalSession);
        assert!(
            error
                .message
                .contains("injected post-spawn setup failure requiring rollback")
        );
        assert!(
            error.message.contains("removing per-exec cgroup directory"),
            "cleanup failure context must include cgroup removal: {}",
            error.message
        );
        assert_pid_eventually_absent(spawned_pid, Duration::from_secs(2));
        assert!(
            exec_dir.exists(),
            "failed rollback must leave per-exec cgroup for diagnostics"
        );
    }

    #[test]
    fn holder_backed_post_spawn_rollback_kills_child_and_removes_exec_cgroup() {
        let _scope = TestFailpointScope::new();
        let temp = tempdir().expect("tempdir");
        let holder_root = temp.path().join("nvx.workload");
        let exec_dir = holder_root.join("exec-990");
        fs::create_dir_all(&exec_dir).expect("exec cgroup dir");
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 5")
            .spawn()
            .expect("spawn child");
        let spawned_pid = child.id() as i32;
        let mut guard =
            SpawnRollbackGuard::new(child, Some(exec_dir.clone()), Some(holder_root.clone()));
        let error = guard.rollback_error(supervisor_error(
            "injected post-spawn setup failure requiring rollback",
        ));
        assert_eq!(
            error.code,
            ServiceErrorCode::Supervisor,
            "successful holder rollback must remain retryable"
        );
        assert_pid_eventually_absent(spawned_pid, Duration::from_secs(2));
        assert!(
            !exec_dir.exists(),
            "holder rollback must remove the per-exec cgroup directory"
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
    fn holder_launcher_spawn_returns_before_stdin_and_preserves_signal_behavior() {
        let mut supervisor = LinuxProcessSupervisor::new_with_holder(1).expect("holder");
        let exec_id = 77_u32;
        let started = Instant::now();
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "read line; printf 'READY:%s\\n' \"$line\"; while :; do sleep 1; done"
                        .to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "holder spawn must return promptly without waiting on stdin"
        );

        supervisor
            .queue_stdin(exec_id, b"hello\n".to_vec())
            .expect("queue stdin");
        supervisor.close_stdin(exec_id).expect("close stdin");

        let stdout_ready = wait_for_event(
            &mut supervisor,
            exec_id,
            Duration::from_secs(2),
            |event| matches!(event, SupervisorEvent::StdoutChunk(chunk) if String::from_utf8_lossy(chunk).contains("READY:hello")),
        );
        assert!(
            stdout_ready.is_some(),
            "stdin must reach workload and produce output"
        );

        supervisor.terminate(exec_id).expect("terminate");
        let signaled = wait_for_event(&mut supervisor, exec_id, Duration::from_secs(2), |event| {
            matches!(event, SupervisorEvent::Signaled { .. })
        });
        assert!(
            signaled.is_some(),
            "signal disposition must be preserved through holder launcher"
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

        let peek_deadline = Instant::now() + Duration::from_secs(2);
        let first = loop {
            assert!(
                Instant::now() < peek_deadline,
                "timed out waiting for first stdout chunk"
            );
            let Some(event) = supervisor.peek_event(exec_id).expect("peek event") else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            if matches!(event, SupervisorEvent::StdoutChunk(_)) {
                break event;
            }
            supervisor.ack_event(exec_id).expect("ack non-stdout event");
        };
        assert!(matches!(first, SupervisorEvent::StdoutChunk(_)));

        std::thread::sleep(Duration::from_millis(200));
        let active = supervisor.active.as_ref().expect("active process");
        let queued_before = active.event_queue.len();
        assert!(
            queued_before > 0,
            "expected at least one queued event after first unacked chunk"
        );
        let bytes_before = active.event_queue_bytes;
        std::thread::sleep(Duration::from_millis(100));
        let active = supervisor.active.as_ref().expect("active process");
        assert_eq!(
            active.event_queue.len(),
            queued_before,
            "front-unacked output must stop additional draining once queue is non-empty"
        );
        assert!(
            active.event_queue_bytes == bytes_before
                && active.event_queue_bytes <= DEFAULT_CHANNEL_WRITE_QUEUE_LIMIT_BYTES,
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
    fn kill_reports_fatal_session_when_cgroup_kill_initiation_is_uncertain() {
        let _scope = TestFailpointScope::new();
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 810;
        supervisor
            .spawn(&CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 10".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .expect("spawn");
        let temp = tempdir().expect("tempdir");
        let cgroup_kill = temp.path().join("cgroup.kill");
        fs::write(&cgroup_kill, "initial").expect("seed cgroup.kill");
        supervisor.active.as_mut().expect("active").cgroup_dir = Some(temp.path().to_path_buf());

        CGROUP_KILL_WRITE_FAILPOINT.with(|flag| flag.set(true));
        let failed = supervisor.kill(exec_id).expect_err("kill must fail closed");
        assert_eq!(failed.code, ServiceErrorCode::FatalSession);
        assert!(failed.message.contains("termination state uncertain"));
        assert!(failed.message.contains("cgroup.kill"));
        assert!(
            failed
                .message
                .contains("injected cgroup.kill write failure")
        );

        cleanup_active_exec(&mut supervisor, exec_id);
    }

    #[test]
    fn cancel_exec_signal_initiation_uncertainty_sets_fatal_session_and_blocks_new_exec() {
        let _scope = TestFailpointScope::new();
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().expect("activate");
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 811;
        service
            .create_process(
                CreateProcessRequest {
                    exec_id,
                    argv: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "sleep 10".to_string(),
                    ],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(5_000),
                },
                &mut supervisor,
            )
            .expect("create");

        PROCESS_GROUP_SIGNAL_FAILPOINT.with(|flag| flag.set(true));
        let failed = service
            .cancel_exec(exec_id, CancelReason::Cancelled, &mut supervisor)
            .expect_err("cancel must fail closed");
        assert_eq!(failed.code, ServiceErrorCode::FatalSession);
        assert!(failed.message.contains("termination state uncertain"));
        assert!(failed.message.contains("injected signal failure"));
        assert!(service.health().shutting_down);

        let retry = service.create_process(
            CreateProcessRequest {
                exec_id: exec_id + 1,
                argv: vec!["/bin/echo".to_string(), "blocked".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        );
        assert_eq!(
            retry.expect_err("fatal session must reject new exec").code,
            ServiceErrorCode::FatalSession
        );

        cleanup_active_exec(&mut supervisor, exec_id);
    }

    #[test]
    fn timeout_cancel_signal_initiation_uncertainty_sets_fatal_session_and_blocks_new_exec() {
        let _scope = TestFailpointScope::new();
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().expect("activate");
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 812;
        service
            .create_process(
                CreateProcessRequest {
                    exec_id,
                    argv: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "sleep 10".to_string(),
                    ],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(5),
                },
                &mut supervisor,
            )
            .expect("create");

        PROCESS_GROUP_SIGNAL_FAILPOINT.with(|flag| flag.set(true));
        let failed = service
            .cancel_exec(exec_id, CancelReason::TimedOut, &mut supervisor)
            .expect_err("timeout cancel must fail closed");
        assert_eq!(failed.code, ServiceErrorCode::FatalSession);
        assert!(failed.message.contains("termination state uncertain"));
        assert!(failed.message.contains("injected signal failure"));
        assert!(service.health().shutting_down);

        let retry = service.create_process(
            CreateProcessRequest {
                exec_id: exec_id + 1,
                argv: vec!["/bin/echo".to_string(), "blocked".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        );
        assert_eq!(
            retry.expect_err("fatal session must reject new exec").code,
            ServiceErrorCode::FatalSession
        );

        cleanup_active_exec(&mut supervisor, exec_id);
    }

    #[test]
    fn cancel_exec_cgroup_existence_probe_uncertainty_sets_fatal_session_and_blocks_new_exec() {
        let _scope = TestFailpointScope::new();
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().expect("activate");
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 813;
        service
            .create_process(
                CreateProcessRequest {
                    exec_id,
                    argv: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "sleep 10".to_string(),
                    ],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(5_000),
                },
                &mut supervisor,
            )
            .expect("create");

        let temp = tempdir().expect("tempdir");
        supervisor.active.as_mut().expect("active").cgroup_dir = Some(temp.path().to_path_buf());
        CGROUP_KILL_EXISTS_PROBE_FAILPOINT.with(|flag| flag.set(true));

        let failed = service
            .cancel_exec(exec_id, CancelReason::Cancelled, &mut supervisor)
            .expect_err("cancel must fail closed");
        assert_eq!(failed.code, ServiceErrorCode::FatalSession);
        assert!(failed.message.contains("termination state uncertain"));
        assert!(failed.message.contains("cgroup.kill"));
        assert!(
            failed
                .message
                .contains("injected cgroup.kill existence probe failure")
        );
        assert!(service.health().shutting_down);

        let retry = service.create_process(
            CreateProcessRequest {
                exec_id: exec_id + 1,
                argv: vec!["/bin/echo".to_string(), "blocked".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        );
        assert_eq!(
            retry.expect_err("fatal session must reject new exec").code,
            ServiceErrorCode::FatalSession
        );

        cleanup_active_exec(&mut supervisor, exec_id);
    }

    #[test]
    fn timeout_cancel_cgroup_existence_probe_uncertainty_sets_fatal_session_and_blocks_new_exec() {
        let _scope = TestFailpointScope::new();
        let mut service = runtime_test_service();
        service.activate_full_lifecycle().expect("activate");
        let mut supervisor = LinuxProcessSupervisor::new();
        let exec_id = 814;
        service
            .create_process(
                CreateProcessRequest {
                    exec_id,
                    argv: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "sleep 10".to_string(),
                    ],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: Some(5),
                },
                &mut supervisor,
            )
            .expect("create");

        let temp = tempdir().expect("tempdir");
        supervisor.active.as_mut().expect("active").cgroup_dir = Some(temp.path().to_path_buf());
        CGROUP_KILL_EXISTS_PROBE_FAILPOINT.with(|flag| flag.set(true));

        let failed = service
            .cancel_exec(exec_id, CancelReason::TimedOut, &mut supervisor)
            .expect_err("timeout cancel must fail closed");
        assert_eq!(failed.code, ServiceErrorCode::FatalSession);
        assert!(failed.message.contains("termination state uncertain"));
        assert!(failed.message.contains("cgroup.kill"));
        assert!(
            failed
                .message
                .contains("injected cgroup.kill existence probe failure")
        );
        assert!(service.health().shutting_down);

        let retry = service.create_process(
            CreateProcessRequest {
                exec_id: exec_id + 1,
                argv: vec!["/bin/echo".to_string(), "blocked".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        );
        assert_eq!(
            retry.expect_err("fatal session must reject new exec").code,
            ServiceErrorCode::FatalSession
        );

        cleanup_active_exec(&mut supervisor, exec_id);
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
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        };

        maybe_report_descendants_cleaned(&mut active, None).expect("poll cleanup pending");
        assert!(
            !active.descendants_cleaned_reported,
            "cleanup cannot complete while populated=1"
        );
        assert!(active.event_queue.is_empty(), "no cleanup event yet");

        fs::write(&events_path, "populated 0\n").expect("flip populated=0");
        maybe_report_descendants_cleaned(&mut active, None).expect("poll cleanup complete");
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
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        };
        let error =
            maybe_report_descendants_cleaned(&mut active, None).expect_err("timeout expected");
        assert_eq!(error.code, ServiceErrorCode::CleanupTimeout);
    }

    #[test]
    fn descendants_cleanup_retries_cgroup_removal_then_publishes_terminal_and_cleanup() {
        let _scope = TestFailpointScope::new();
        let temp = tempdir().expect("tempdir");
        let events_path = temp.path().join("cgroup.events");
        fs::write(&events_path, "populated 0\n").expect("seed populated=0");
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn child");
        let mut active = ActiveProcess {
            exec_id: 3,
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
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: None,
            cgroup_dir: Some(temp.path().to_path_buf()),
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: None,
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        };
        wait_for_exit_capture(&mut active, Duration::from_secs(2));
        REMOVE_CGROUP_FAIL_COUNTDOWN.with(|countdown| countdown.set(1));
        maybe_report_descendants_cleaned(&mut active, None).expect("first removal attempt");
        assert!(
            active.event_queue.is_empty(),
            "events must wait for cgroup removal"
        );
        maybe_report_descendants_cleaned(&mut active, None).expect("second removal attempt");
        assert!(matches!(
            active.event_queue.pop_front(),
            Some(SupervisorEvent::Exited {
                exit_code: 0,
                termination: Some(TerminationOutcome::ForcedKill)
            })
        ));
        assert!(matches!(
            active.event_queue.pop_front(),
            Some(SupervisorEvent::DescendantsCleaned)
        ));
        assert!(active.descendants_cleaned_reported);
    }

    #[test]
    fn descendants_cleanup_timeout_on_persistent_removal_failure_publishes_nothing() {
        let _scope = TestFailpointScope::new();
        let temp = tempdir().expect("tempdir");
        let events_path = temp.path().join("cgroup.events");
        fs::write(&events_path, "populated 0\n").expect("seed populated=0");
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn child");
        let mut active = ActiveProcess {
            exec_id: 4,
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
            exit_status_reported: false,
            descendants_cleaned_reported: false,
            descendants_cleanup_started_at: Some(
                Instant::now() - DESCENDANTS_CLEANUP_DEADLINE - Duration::from_millis(1),
            ),
            cgroup_dir: Some(temp.path().to_path_buf()),
            event_queue: VecDeque::new(),
            event_queue_bytes: 0,
            prefer_stdout_next: true,
            holder_wait_status: None,
            holder_wait_status_buffer: Vec::new(),
            pending_terminal_event: None,
            disconnect_discard_output: false,
            discarded_output_bytes: 0,
            discard_byte_budget_exhausted: false,
        };
        wait_for_exit_capture(&mut active, Duration::from_secs(2));
        REMOVE_CGROUP_FAIL_COUNTDOWN.with(|countdown| countdown.set(128));
        let error = maybe_report_descendants_cleaned(&mut active, None)
            .expect_err("persistent removal failure must time out");
        assert_eq!(error.code, ServiceErrorCode::CleanupTimeout);
        assert!(
            active.event_queue.is_empty(),
            "cleanup timeout must publish neither terminal nor descendants-cleaned"
        );
        assert!(
            active.pending_terminal_event.is_some(),
            "terminal must remain pending while cgroup removal fails"
        );
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
            matches!(event, SupervisorEvent::Signaled { .. })
        });
        assert!(
            matches!(
                signal,
                Some(SupervisorEvent::Signaled {
                    signal: libc::SIGTERM,
                    termination: None
                })
            ),
            "holder wrapper must preserve inner signal status"
        );
    }
}
