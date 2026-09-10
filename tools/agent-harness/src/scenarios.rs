use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::client::MxcAgentClient;
use crate::launch::{LaunchedVm, build_launch_plan, discover_artifacts, launch_whp_vm};
use crate::{
    CheckOutcome, EvidenceCheckStatus, EvidenceSource, HarnessOptions, ScenarioDefinition,
};
#[cfg(windows)]
use crate::{control_session::HostControlSession, named_pipe::NamedPipeClient};
#[cfg(windows)]
use agent_protocol::mapping::{
    CanonicalHostMappingRoot, MappingContainmentPolicy, SymlinkContainmentPolicy,
};
#[cfg(windows)]
use agent_protocol::messages::{
    CapabilityProofMaterial, HostControlMessage, LaunchIdentity, NetworkSetupState,
    SERVICE_IDENTITY,
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
        let pid = vm.process_id();
        let expected_image = vm.plan.artifacts.openvmm_exe.to_string_lossy().into_owned();
        let control = NamedPipeClient::connect(
            &vm.plan.control_pipe_name,
            Duration::from_secs(5),
            Some(pid),
            Some(expected_image.as_str()),
        );
        let control = match control {
            Ok(client) => client,
            Err(error) => return fail_check(format!("failed to connect control pipe: {error}")),
        };
        let session = HostControlSession::new(control);
        let mut client = MxcAgentClient::new(session);
        match definition.requirement_number {
            1 => {
                let launch = LaunchIdentity {
                    generation: vm.plan.channel_generation.saturating_add(1),
                    nonce: vm.plan.launch_nonce,
                };
                let mut capability_proof = [0_u8; 32];
                capability_proof[..16].copy_from_slice(&vm.plan.launch_nonce);
                capability_proof[16..].copy_from_slice(&vm.plan.launch_nonce);
                if let Err(error) = client.authenticate_launch(
                    vm.plan.launch_capability,
                    HostControlMessage::HostHello {
                        service: SERVICE_IDENTITY.to_string(),
                        protocol_version: 1,
                        launch,
                        capability_proof: match CapabilityProofMaterial::try_from(
                            capability_proof.to_vec(),
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                return fail_check(format!(
                                    "failed building capability proof for req1: {error}"
                                ));
                            }
                        },
                    },
                    Duration::from_secs(5),
                ) {
                    return fail_check(format!("launch authentication failed: {error}"));
                }
                let root = match CanonicalHostMappingRoot::parse("/sandbox-root".to_string()) {
                    Ok(root) => root,
                    Err(error) => {
                        return fail_check(format!(
                            "invalid canonical root for req1 probe: {error}"
                        ));
                    }
                };
                if let Err(error) = client.send_configure(HostControlMessage::Configure {
                    launch,
                    root,
                    mappings: vec![],
                    containment: MappingContainmentPolicy {
                        symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                        reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    },
                }) {
                    return fail_check(format!("configure session failed: {error}"));
                }
                let ready = match client.wait_ready(Duration::from_secs(5)) {
                    Ok(message) => message,
                    Err(error) => return fail_check(format!("wait_ready failed: {error}")),
                };
                let health = match client.request_health(Duration::from_secs(5)) {
                    Ok(message) => message,
                    Err(error) => return fail_check(format!("health request failed: {error}")),
                };
                let mut evidence = vec![format!(
                    "connected to OpenVMM control pipe {}",
                    vm.plan.control_pipe_name
                )];
                match ready {
                    agent_protocol::messages::AgentControlMessage::Ready {
                        launch: ready_launch,
                        status,
                    } => {
                        if ready_launch != launch {
                            return fail_check(format!(
                                "ready launch identity mismatch: expected={launch:?} actual={ready_launch:?}"
                            ));
                        }
                        if status.service != SERVICE_IDENTITY || status.protocol_version != 1 {
                            return fail_check(format!(
                                "ready status identity mismatch: service={} protocol_version={}",
                                status.service, status.protocol_version
                            ));
                        }
                        if status.network.setup_state != NetworkSetupState::Ready {
                            return fail_check(format!(
                                "ready network setup_state was {:?}, expected Ready",
                                status.network.setup_state
                            ));
                        }
                        evidence.push(format!(
                            "ready verified launch nonce/generation plus service={} protocol={} network={:?}",
                            status.service, status.protocol_version, status.network.setup_state
                        ));
                    }
                    other => {
                        return fail_check(format!(
                            "wait_ready returned unexpected message: {other:?}"
                        ));
                    }
                }
                match health {
                    agent_protocol::messages::AgentControlMessage::Health(status) => {
                        let Some(filesystem) = status.filesystem else {
                            return fail_check(
                                "health response omitted filesystem status".to_string(),
                            );
                        };
                        let Some(network) = status.network else {
                            return fail_check(
                                "health response omitted network status".to_string(),
                            );
                        };
                        if !filesystem.rootfs_ready {
                            return fail_check("health filesystem rootfs_ready=false".to_string());
                        }
                        if network.setup_state != NetworkSetupState::Ready {
                            return fail_check(format!(
                                "health network setup_state was {:?}, expected Ready",
                                network.setup_state
                            ));
                        }
                        evidence.push(format!(
                            "health verified filesystem rootfs_ready={} and network setup_state={:?}",
                            filesystem.rootfs_ready, network.setup_state
                        ));
                    }
                    other => {
                        return fail_check(format!(
                            "health returned unexpected message: {other:?}"
                        ));
                    }
                }
                CheckOutcome {
                    check_status: EvidenceCheckStatus::Pass,
                    evidence_source: EvidenceSource::LiveWhp,
                    error: None,
                    evidence,
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
