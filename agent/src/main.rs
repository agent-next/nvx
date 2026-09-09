// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Phase-0 NVX PID-1 agent prototype.

mod cgroup;
mod config;
mod error;
mod isolation;
mod mappings;
mod mounts;

#[cfg(unix)]
use ::std::mem::MaybeUninit;
use ::std::process::ExitCode;

use ::agent_protocol::mxc_extension::{AciAdapterStatus, UnsupportedAciAdapter};
use ::serde_json::json;

use crate::error::{AgentError, Result};

#[cfg(unix)]
const SHUTDOWN_SIGNALS: [i32; 2] = [libc::SIGINT, libc::SIGTERM];
#[cfg(unix)]
const WAIT_LOOP_SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGCHLD];

#[cfg(unix)]
struct ShutdownSignalBlock {
    blocked_set: libc::sigset_t,
    previous_mask: libc::sigset_t,
}

fn phase0_scaffold_state_json(status: AciAdapterStatus) -> Result<String> {
    match status {
        AciAdapterStatus::Unsupported {
            required_revision,
            reason,
        } => serde_json::to_string(&json!({
            "component": "nvx-agent",
            "phase": "phase0",
            "serviceReadiness": "not-ready",
            "profile": "mxc-prototype",
            "pid1Mode": "boot-diagnostics-wait",
            "runtimeOperations": "not-implemented",
            "adapter": {
                "kind": "aci",
                "status": "blocked",
                "requiredRevision": required_revision,
                "reason": reason,
            },
            "message": "Phase-0 image is protocol/build scaffolding only; runtime MXC operations are unavailable."
        }))
        .map_err(|error| AgentError::internal(format!("failed to encode phase-0 state JSON: {error}"))),
    }
}

fn emit_phase0_scaffold_state(status: AciAdapterStatus) -> Result<()> {
    let payload = phase0_scaffold_state_json(status)?;
    eprintln!("NVX-AGENT-STATE: {payload}");
    Ok(())
}

#[cfg(unix)]
fn wait_for_shutdown_signal(shutdown_mask: &libc::sigset_t) -> Result<()> {
    eprintln!("NVX-AGENT: waiting for host control integration or termination signal");
    loop {
        let signal = wait_for_blocked_shutdown_signal(shutdown_mask, |set, signal| unsafe {
            libc::sigwait(set, signal)
        })?;
        if signal == libc::SIGCHLD {
            #[cfg(target_os = "linux")]
            isolation::reap_all_children();
            continue;
        }
        ensure_shutdown_signal(signal)?;
        eprintln!("NVX-AGENT: received termination signal");
        return Ok(());
    }
}

#[cfg(not(unix))]
fn wait_for_shutdown_signal() -> Result<()> {
    Err(AgentError::internal(
        "phase-0 PID-1 wait loop is supported on Unix targets only",
    ))
}

#[cfg(unix)]
fn blocked_shutdown_signal_mask() -> Result<libc::sigset_t> {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    if unsafe { libc::sigemptyset(set.as_mut_ptr()) } != 0 {
        return Err(AgentError::internal(format!(
            "sigemptyset failed: {}",
            ::std::io::Error::last_os_error()
        )));
    }
    let mut set = unsafe { set.assume_init() };
    for signal in WAIT_LOOP_SIGNALS {
        if unsafe { libc::sigaddset(&mut set, signal) } != 0 {
            return Err(AgentError::internal(format!(
                "sigaddset failed for signal {signal}: {}",
                ::std::io::Error::last_os_error()
            )));
        }
    }
    Ok(set)
}

#[cfg(unix)]
fn block_signals(blocked_set: &libc::sigset_t) -> Result<libc::sigset_t> {
    let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, blocked_set, previous.as_mut_ptr()) };
    if mask_result != 0 {
        return Err(AgentError::internal(format!(
            "pthread_sigmask(SIG_BLOCK) failed: {}",
            ::std::io::Error::from_raw_os_error(mask_result)
        )));
    }
    Ok(unsafe { previous.assume_init() })
}

#[cfg(unix)]
fn install_shutdown_signal_block() -> Result<ShutdownSignalBlock> {
    let blocked_set = blocked_shutdown_signal_mask()?;
    let previous_mask = block_signals(&blocked_set)?;
    Ok(ShutdownSignalBlock {
        blocked_set,
        previous_mask,
    })
}

#[cfg(unix)]
fn restore_signal_mask(previous_mask: &libc::sigset_t) -> Result<()> {
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, previous_mask, ::std::ptr::null_mut()) };
    if mask_result != 0 {
        return Err(AgentError::internal(format!(
            "pthread_sigmask(SIG_SETMASK) failed: {}",
            ::std::io::Error::from_raw_os_error(mask_result)
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_blocked_shutdown_signal(
    blocked_set: &libc::sigset_t,
    wait: impl FnOnce(*const libc::sigset_t, *mut libc::c_int) -> libc::c_int,
) -> Result<i32> {
    let mut signal = 0;
    let wait_result = wait(blocked_set, &mut signal);
    if wait_result != 0 {
        return Err(AgentError::internal(format!(
            "sigwait failed: {}",
            ::std::io::Error::from_raw_os_error(wait_result)
        )));
    }
    Ok(signal)
}

#[cfg(unix)]
fn ensure_shutdown_signal(signal: i32) -> Result<()> {
    if SHUTDOWN_SIGNALS.contains(&signal) {
        return Ok(());
    }
    Err(AgentError::internal(format!(
        "sigwait returned unexpected signal {signal}"
    )))
}

fn run_phase0_scaffold(wait: impl FnOnce() -> Result<()>) -> Result<()> {
    emit_phase0_scaffold_state(UnsupportedAciAdapter::status())?;
    wait()
}

#[cfg(unix)]
fn run() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let is_subreaper = isolation::query_subreaper()?;
        if !is_subreaper {
            let set_result = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
            if set_result != 0 {
                return Err(AgentError::io(
                    "setting PR_SET_CHILD_SUBREAPER in PID1",
                    ::std::io::Error::last_os_error(),
                ));
            }
        }
    }
    let shutdown_signals = install_shutdown_signal_block()?;
    let run_result =
        run_phase0_scaffold(|| wait_for_shutdown_signal(&shutdown_signals.blocked_set));
    let restore_result = restore_signal_mask(&shutdown_signals.previous_mask);
    if let Err(error) = run_result {
        restore_result?;
        return Err(error);
    }
    restore_result?;
    deliberate_poweroff()
}

#[cfg(not(unix))]
fn run() -> Result<()> {
    run_phase0_scaffold(wait_for_shutdown_signal)?;
    deliberate_poweroff()
}

#[cfg(unix)]
fn deliberate_poweroff() -> Result<()> {
    eprintln!("NVX-AGENT: initiating deliberate poweroff");
    unsafe {
        libc::sync();
    }
    let reboot_result = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    if reboot_result != 0 {
        return Err(AgentError::internal(format!(
            "reboot(LINUX_REBOOT_CMD_POWER_OFF) failed: {}",
            ::std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn deliberate_poweroff() -> Result<()> {
    Err(AgentError::internal(
        "deliberate poweroff path is supported on Unix targets only",
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NVX-AGENT-ERROR: [{:?}] {error}", error.code());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::serde_json::Value;
    #[cfg(unix)]
    use ::std::process::Command;
    #[cfg(unix)]
    use ::std::time::{Duration, Instant};

    #[cfg(unix)]
    const BLOCKED_SIGNAL_HELPER_ENV: &str = "NVX_AGENT_BLOCKED_SIGNAL_HELPER";
    #[cfg(unix)]
    const BLOCKED_SIGNAL_HELPER_TEST: &str =
        "tests::blocked_signal_during_initialization_helper_entrypoint";

    #[test]
    fn run_phase0_scaffold_waits_for_shutdown_path() {
        let mut waited = false;
        run_phase0_scaffold(|| {
            waited = true;
            Ok(())
        })
        .unwrap();
        assert!(waited);
    }

    #[test]
    fn run_phase0_scaffold_propagates_wait_failures() {
        let error =
            run_phase0_scaffold(|| Err(AgentError::internal("shutdown wait failed"))).unwrap_err();
        assert!(format!("{error}").contains("shutdown wait failed"));
    }

    #[test]
    fn phase0_state_is_machine_readable_and_not_ready() {
        let payload = phase0_scaffold_state_json(UnsupportedAciAdapter::status()).unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["phase"], "phase0");
        assert_eq!(value["serviceReadiness"], "not-ready");
        assert_eq!(value["runtimeOperations"], "not-implemented");
        assert_eq!(value["adapter"]["status"], "blocked");
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_blocked_shutdown_signal_returns_received_signal() {
        let set = blocked_shutdown_signal_mask().unwrap();
        let signal = wait_for_blocked_shutdown_signal(&set, |_, output| {
            unsafe { *output = libc::SIGTERM };
            0
        })
        .unwrap();
        assert_eq!(signal, libc::SIGTERM);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_blocked_shutdown_signal_reports_wait_error() {
        let set = blocked_shutdown_signal_mask().unwrap();
        let error = wait_for_blocked_shutdown_signal(&set, |_, _| libc::EINVAL).unwrap_err();
        assert!(format!("{error}").contains("sigwait failed"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_shutdown_signal_rejects_unexpected_signal() {
        let error = ensure_shutdown_signal(libc::SIGUSR1).unwrap_err();
        assert!(format!("{error}").contains("unexpected signal"));
    }

    #[cfg(unix)]
    #[test]
    fn blocked_signal_during_initialization_is_consumed_by_wait() {
        let current_exe = ::std::env::current_exe().unwrap();
        let mut child = Command::new(current_exe)
            .arg("--nocapture")
            .arg("--exact")
            .arg("--ignored")
            .arg(BLOCKED_SIGNAL_HELPER_TEST)
            .env(BLOCKED_SIGNAL_HELPER_ENV, "1")
            .spawn()
            .unwrap();

        let timeout = Duration::from_secs(5);
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "helper subprocess failed with status: {status}"
                );
                break;
            }

            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                panic!("timed out waiting for helper subprocess");
            }

            ::std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "helper subprocess entrypoint for blocked signal integration test"]
    fn blocked_signal_during_initialization_helper_entrypoint() {
        if ::std::env::var_os(BLOCKED_SIGNAL_HELPER_ENV).is_none() {
            return;
        }

        let shutdown_signals = install_shutdown_signal_block().unwrap();
        let thread = unsafe { libc::pthread_self() };
        let kill_result = unsafe { libc::pthread_kill(thread, libc::SIGTERM) };
        assert_eq!(
            kill_result,
            0,
            "failed to send blocked thread signal: {}",
            ::std::io::Error::from_raw_os_error(kill_result)
        );
        emit_phase0_scaffold_state(UnsupportedAciAdapter::status()).unwrap();
        wait_for_shutdown_signal(&shutdown_signals.blocked_set).unwrap();
        restore_signal_mask(&shutdown_signals.previous_mask).unwrap();
    }
}
