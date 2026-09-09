// Copyright(c) The microvm authors.
// Licensed under the MIT License.

mod cgroup;
mod config;
mod error;
mod isolation;
mod mappings;
mod mounts;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod supervisor;

use std::process::ExitCode;

use crate::error::{AgentError, Result};

fn run() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !isolation::query_subreaper()? {
            // SAFETY: prctl is called with fixed integer arguments.
            let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
            if rc != 0 {
                return Err(AgentError::io(
                    "setting PR_SET_CHILD_SUBREAPER",
                    std::io::Error::last_os_error(),
                ));
            }
        }
        runtime::run_runtime()?;
        deliberate_poweroff()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(AgentError::internal("runtime is only supported on Linux"))
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn deliberate_poweroff() -> Result<()> {
    // SAFETY: sync has no memory-safety preconditions.
    unsafe { libc::sync() };
    // SAFETY: reboot syscall is invoked with a constant Linux power-off command.
    let rc = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    if rc != 0 {
        return Err(AgentError::internal(format!(
            "reboot(LINUX_REBOOT_CMD_POWER_OFF) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NVX-AGENT-ERROR: [{:?}] {}", error.code(), error);
            ExitCode::FAILURE
        }
    }
}
