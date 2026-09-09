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
    let wait_result = wait_for_blocked_shutdown_signal(&shutdown_mask, |set, signal| unsafe {
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

fn run() -> Result<()> {
    #[cfg(unix)]
    {
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
        return Ok(());
    }

    #[cfg(not(unix))]
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
        let mut pipefds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipefds.as_mut_ptr()) }, 0);
        let child_pid = unsafe { libc::fork() };
        assert!(
            child_pid >= 0,
            "fork failed: {}",
            ::std::io::Error::last_os_error()
        );
        if child_pid == 0 {
            unsafe {
                libc::close(pipefds[0]);
            }
            let child_exit = match install_shutdown_signal_block() {
                Ok(shutdown_signals) => {
                    let ready: [u8; 1] = [1];
                    let wrote =
                        unsafe { libc::write(pipefds[1], ready.as_ptr().cast(), ready.len()) };
                    if wrote != 1 {
                        2
                    } else {
                        ::std::thread::sleep(::std::time::Duration::from_millis(100));
                        match wait_for_shutdown_signal(&shutdown_signals.blocked_set) {
                            Ok(()) => 0,
                            Err(_) => 3,
                        }
                    }
                }
                Err(_) => 4,
            };
            unsafe {
                libc::close(pipefds[1]);
                libc::_exit(child_exit);
            }
        }
        unsafe {
            libc::close(pipefds[1]);
        }

        let mut ready = [0_u8; 1];
        let read_result = unsafe { libc::read(pipefds[0], ready.as_mut_ptr().cast(), ready.len()) };
        assert_eq!(read_result, 1);
        assert_eq!(ready[0], 1);
        assert_eq!(unsafe { libc::kill(child_pid, libc::SIGTERM) }, 0);

        let mut status = 0;
        let mut child_exited = false;
        for _ in 0..100 {
            let waited = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
            assert_ne!(
                waited,
                -1,
                "waitpid failed: {}",
                ::std::io::Error::last_os_error()
            );
            if waited == child_pid {
                child_exited = true;
                break;
            }
            ::std::thread::sleep(::std::time::Duration::from_millis(20));
        }
        if !child_exited {
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                libc::waitpid(child_pid, &mut status, 0);
            }
            panic!("timed out waiting for child to consume pending signal");
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        unsafe {
            libc::close(pipefds[0]);
        }
    }
}
