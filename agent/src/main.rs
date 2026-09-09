// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Phase-0 NVX PID-1 agent prototype.

mod config;
mod error;

#[cfg(unix)]
use ::std::mem::MaybeUninit;
use ::std::process::ExitCode;

use ::agent_protocol::mxc_extension::{
    MODELED_REQUIREMENTS, MXC_EXTENSION_VERSION, MxcExtensionService, MxcRequest,
    UnsupportedAciAdapter,
};

use crate::error::{AgentError, Result};

#[cfg(unix)]
const SHUTDOWN_SIGNALS: [i32; 2] = [libc::SIGINT, libc::SIGTERM];

#[cfg(unix)]
struct ShutdownSignalBlock {
    blocked_set: libc::sigset_t,
    previous_mask: libc::sigset_t,
}

fn probe_mxc_requirements(service: &impl MxcExtensionService) -> usize {
    let mut failures = 0;
    for requirement in MODELED_REQUIREMENTS {
        let response = service.call(MxcRequest {
            version: MXC_EXTENSION_VERSION,
            requirement,
        });
        if let Err(error) = response {
            failures += 1;
            eprintln!("NVX-AGENT: {:?}: {}", error.code, error.message);
        }
    }
    failures
}

#[cfg(unix)]
fn wait_for_shutdown_signal(shutdown_mask: &libc::sigset_t) -> Result<()> {
    eprintln!("NVX-AGENT: waiting for host control integration or termination signal");
    let wait_result = wait_for_blocked_shutdown_signal(shutdown_mask, |set, signal| unsafe {
        libc::sigwait(set, signal)
    });
    let signal = wait_result?;
    ensure_shutdown_signal(signal)?;
    eprintln!("NVX-AGENT: received termination signal");
    Ok(())
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
    for signal in SHUTDOWN_SIGNALS {
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

fn run_service(
    service: &impl MxcExtensionService,
    wait: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let failures = probe_mxc_requirements(service);
    if failures == 0 {
        return Err(AgentError::internal(
            "phase-0 service unexpectedly accepted all modeled operations",
        ));
    }
    wait()
}

#[cfg(unix)]
fn run() -> Result<()> {
    let shutdown_signals = install_shutdown_signal_block()?;
    let adapter = UnsupportedAciAdapter;
    let run_result = run_service(&adapter, || {
        wait_for_shutdown_signal(&shutdown_signals.blocked_set)
    });
    let restore_result = restore_signal_mask(&shutdown_signals.previous_mask);
    if let Err(error) = run_result {
        restore_result?;
        return Err(error);
    }
    restore_result?;
    Ok(())
}

#[cfg(not(unix))]
fn run() -> Result<()> {
    let adapter = UnsupportedAciAdapter;
    run_service(&adapter, wait_for_shutdown_signal)
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
    #[cfg(unix)]
    use ::std::process::Command;
    #[cfg(unix)]
    use ::std::time::{Duration, Instant};

    #[cfg(unix)]
    const BLOCKED_SIGNAL_HELPER_ENV: &str = "NVX_AGENT_BLOCKED_SIGNAL_HELPER";
    #[cfg(unix)]
    const BLOCKED_SIGNAL_HELPER_TEST: &str =
        "tests::blocked_signal_during_initialization_helper_entrypoint";

    struct AcceptingService;

    impl MxcExtensionService for AcceptingService {
        fn call(
            &self,
            request: MxcRequest,
        ) -> ::std::result::Result<
            ::agent_protocol::mxc_extension::MxcResponse,
            ::agent_protocol::mxc_extension::MxcServiceError,
        > {
            Ok(::agent_protocol::mxc_extension::MxcResponse {
                version: request.version,
                requirement: request.requirement,
                state: ::agent_protocol::mxc_extension::MxcRequirementState::Modeled,
            })
        }
    }

    #[test]
    fn run_service_waits_when_requirements_are_unavailable() {
        let mut waited = false;
        run_service(&UnsupportedAciAdapter, || {
            waited = true;
            Ok(())
        })
        .unwrap();
        assert!(waited);
    }

    #[test]
    fn run_service_propagates_wait_failures() {
        let error = run_service(&UnsupportedAciAdapter, || {
            Err(AgentError::internal("shutdown wait failed"))
        })
        .unwrap_err();
        assert!(format!("{error}").contains("shutdown wait failed"));
    }

    #[test]
    fn run_service_rejects_successful_phase_zero_adapter() {
        let error = run_service(&AcceptingService, || Ok(())).unwrap_err();
        assert!(format!("{error}").contains("unexpectedly accepted"));
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
        let _ = probe_mxc_requirements(&UnsupportedAciAdapter);
        wait_for_shutdown_signal(&shutdown_signals.blocked_set).unwrap();
        restore_signal_mask(&shutdown_signals.previous_mask).unwrap();
    }
}
