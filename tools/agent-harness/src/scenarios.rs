use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::launch::{LaunchedVm, build_launch_plan, discover_artifacts, launch_whp_vm};
use crate::{
    CheckOutcome, EvidenceCheckStatus, EvidenceSource, HarnessOptions, ScenarioDefinition,
};
#[cfg(windows)]
use crate::{
    control_session::{HostAttachStatus, HostControlSession},
    named_pipe::NamedPipeClient,
};

struct LiveHarnessState {
    vm: Option<LaunchedVm>,
    init_error: Option<String>,
}

static LIVE_STATE: OnceLock<Mutex<LiveHarnessState>> = OnceLock::new();

fn state() -> &'static Mutex<LiveHarnessState> {
    LIVE_STATE.get_or_init(|| {
        Mutex::new(LiveHarnessState {
            vm: None,
            init_error: None,
        })
    })
}

pub(crate) fn run_live_requirement(
    options: &HarnessOptions,
    definition: ScenarioDefinition,
) -> CheckOutcome {
    let mut guard = state().lock().expect("live harness state lock");
    if guard.vm.is_none() && guard.init_error.is_none() {
        let overrides = options.launch_overrides.clone().unwrap_or_default();
        let artifacts = match discover_artifacts(&options.output_dir, &overrides) {
            Ok(artifacts) => artifacts,
            Err(error) => {
                guard.init_error = Some(format!(
                    "{{\"kind\":\"missing-prerequisite\",\"field\":\"{}\",\"path\":\"{}\",\"reason\":\"{}\"}}",
                    error.field,
                    error.path.display(),
                    error.reason.replace('\"', "'")
                ));
                return fail_check(
                    guard
                        .init_error
                        .clone()
                        .unwrap_or_else(|| "missing prerequisite".to_string()),
                );
            }
        };
        let plan = build_launch_plan(&options.output_dir, artifacts);
        match launch_whp_vm(plan) {
            Ok(vm) => {
                guard.vm = Some(vm);
            }
            Err(error) => {
                guard.init_error = Some(error.clone());
                return fail_check(error);
            }
        }
    }

    if let Some(error) = guard.init_error.clone() {
        return fail_check(error);
    }

    let Some(vm) = guard.vm.as_mut() else {
        return fail_check("live vm state unavailable".to_string());
    };
    let check = run_single_requirement(vm, definition);
    if check.check_status != EvidenceCheckStatus::Pass {
        vm.kill();
    }
    check
}

fn run_single_requirement(vm: &mut LaunchedVm, definition: ScenarioDefinition) -> CheckOutcome {
    #[cfg(not(windows))]
    {
        let _ = vm;
        return fail_check(
            "live WHP scenarios require Windows host support and WHP artifacts".to_string(),
        );
    }
    #[cfg(windows)]
    {
        let _pid = vm.process_id();
        let expected_image = vm.plan.artifacts.openvmm_exe.to_string_lossy().into_owned();
        let control = NamedPipeClient::connect(
            &vm.plan.control_pipe_name,
            Duration::from_secs(5),
            Some(expected_image.as_str()),
        );
        let control = match control {
            Ok(client) => client,
            Err(error) => return fail_check(format!("failed to connect control pipe: {error}")),
        };
        let mut session = HostControlSession::new(control);
        if let Err(error) = session.send_host_attach(vm.plan.launch_capability) {
            return fail_check(format!("failed sending HostAttach: {error}"));
        }
        let attach = match session.recv_attach_status() {
            Ok(status) => status,
            Err(error) => {
                return fail_check(format!("failed waiting for broker attach status: {error}"));
            }
        };
        match definition.requirement_number {
            1 => {
                let mut evidence = vec![format!(
                    "connected to OpenVMM control pipe {}",
                    vm.plan.control_pipe_name
                )];
                evidence.push(format!("broker attach response: {attach:?}"));
                if attach == HostAttachStatus::Wait {
                    CheckOutcome {
                        check_status: EvidenceCheckStatus::Pass,
                        evidence_source: EvidenceSource::LiveWhp,
                        error: None,
                        evidence,
                    }
                } else {
                    fail_check("expected Wait before guest Ack during host attach".to_string())
                }
            }
            2..=12 => fail_check(format!(
                "req{:02} failed: live scenario invariant check did not pass",
                definition.requirement_number
            )),
            _ => fail_check("unknown requirement number".to_string()),
        }
    }
}

fn fail_check(error: String) -> CheckOutcome {
    CheckOutcome {
        check_status: EvidenceCheckStatus::Fail,
        evidence_source: EvidenceSource::None,
        error: Some(error),
        evidence: vec![],
    }
}
