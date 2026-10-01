//! Launch and supervision of OpenVMM processes.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::config::OpenVmmConfig;
use super::platform;
use super::protocol::CAPABILITY_LEN;

const KILL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// An OpenVMM process this caller launched and has not released yet.
pub(crate) struct Launched {
    #[cfg(not(windows))]
    child: Child,
    #[cfg(windows)]
    process: platform::LaunchedProcess,
}

impl Launched {
    pub(crate) fn id(&self) -> u32 {
        #[cfg(not(windows))]
        return self.child.id();
        #[cfg(windows)]
        return self.process.id();
    }
}

/// Starts OpenVMM detached from the caller.
///
/// OpenVMM reads its capability from standard input as soon as it starts, so the capability is
/// written into a pipe whose write end is closed before the spawn. The capability never appears
/// in arguments, the environment, or the log. OpenVMM output goes to `log`, and OpenVMM inherits
/// no other handle of the caller, so a caller whose own output is a pipe sees end-of-file when it
/// exits rather than when the VM does.
pub(crate) fn spawn(
    config: &OpenVmmConfig,
    arguments: &[OsString],
    capability: &[u8; CAPABILITY_LEN],
    log: File,
    working_dir: &Path,
) -> io::Result<Launched> {
    let (stdin, mut writer) = io::pipe()?;
    writer.write_all(capability)?;
    drop(writer);
    let stderr = log.try_clone()?;
    #[cfg(windows)]
    {
        platform::spawn_detached(
            &config.openvmm,
            arguments,
            working_dir,
            [stdin.into(), log.into(), stderr.into()],
            config.breakaway_from_job,
        )
        .map(|process| Launched { process })
    }
    #[cfg(not(windows))]
    {
        // Rust marks every descriptor it opens close-on-exec, so OpenVMM receives only these.
        let mut command = Command::new(&config.openvmm);
        command
            .args(arguments)
            .current_dir(working_dir)
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr));
        platform::detach(&mut command, config.breakaway_from_job);
        command.spawn().map(|child| Launched { child })
    }
}

/// Releases a launched process without waiting for it.
///
/// On Unix a background thread reaps the child once it exits so it does not linger as a zombie
/// while this process lives. If that thread cannot start, the child becomes a zombie after it
/// exits; liveness checks treat zombies as exited, so only the process table entry leaks. The
/// OpenVMM process keeps running either way.
pub(crate) fn detach_child(launched: Launched) {
    #[cfg(not(windows))]
    {
        let mut child = launched.child;
        let _ = thread::Builder::new()
            .name("nvx-openvmm-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
    #[cfg(windows)]
    drop(launched);
}

/// Kills a launched process that was never recorded, through its handle, which cannot race with
/// process ID reuse. Returns whether it exited within ten seconds.
pub(crate) fn kill_child(launched: Launched) -> bool {
    #[cfg(windows)]
    return launched.process.terminate(KILL_TIMEOUT);
    #[cfg(not(windows))]
    {
        let mut child = launched.child;
        if child.kill().is_ok() {
            let deadline = Instant::now() + KILL_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return true,
                    Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                    _ => break,
                }
            }
        }
        detach_child(Launched { child });
        false
    }
}

/// Waits until the process with the given identity is gone, returning whether it exited before
/// `deadline`. Inconclusive checks count as still running.
pub(crate) fn wait_for_exit(pid: u32, start_time: u64, deadline: Instant) -> bool {
    loop {
        match platform::process_start_time(pid) {
            Ok(Some(current)) if current == start_time => {}
            Ok(_) => return true,
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Kills the process and waits up to ten seconds for it to disappear.
pub(crate) fn kill(pid: u32, start_time: u64) -> io::Result<bool> {
    platform::kill_process(pid, start_time)?;
    Ok(wait_for_exit(
        pid,
        start_time,
        Instant::now() + KILL_TIMEOUT,
    ))
}
