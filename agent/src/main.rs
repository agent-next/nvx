// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Phase-0 NVX PID-1 agent prototype.

mod config;
mod error;

use ::std::process::ExitCode;
#[cfg(unix)]
use ::std::sync::atomic::{AtomicBool, Ordering};

use ::agent_protocol::mxc_extension::{
    MODELED_REQUIREMENTS, MXC_EXTENSION_VERSION, MxcExtensionService, MxcRequest,
    UnsupportedAciAdapter,
};

use crate::error::{AgentError, Result};

#[cfg(unix)]
static TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_shutdown_signal(_: i32) {
    TERMINATION_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_shutdown_handlers() -> Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let handler = handle_shutdown_signal as *const () as libc::sighandler_t;
        let previous = unsafe { libc::signal(signal, handler) };
        if previous == libc::SIG_ERR {
            return Err(AgentError::internal(format!(
                "failed to install handler for signal {signal}"
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_shutdown_handlers() -> Result<()> {
    Err(AgentError::internal(
        "phase-0 PID-1 wait loop is supported on Unix targets only",
    ))
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
fn wait_for_shutdown_signal() -> Result<()> {
    TERMINATION_REQUESTED.store(false, Ordering::SeqCst);
    install_shutdown_handlers()?;
    eprintln!("NVX-AGENT: waiting for host control integration or termination signal");
    while !TERMINATION_REQUESTED.load(Ordering::SeqCst) {
        let pause_result = unsafe { libc::pause() };
        if pause_result == -1 && !TERMINATION_REQUESTED.load(Ordering::SeqCst) {
            let os_error = ::std::io::Error::last_os_error();
            if os_error.raw_os_error() != Some(libc::EINTR) {
                return Err(AgentError::internal(format!(
                    "pause failed while waiting for termination: {os_error}"
                )));
            }
        }
    }
    eprintln!("NVX-AGENT: received termination signal");
    Ok(())
}

#[cfg(not(unix))]
fn wait_for_shutdown_signal() -> Result<()> {
    install_shutdown_handlers()
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
}
