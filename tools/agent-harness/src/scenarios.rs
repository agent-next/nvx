#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::client::{ClientError, MxcAgentClient};
use crate::launch::{LaunchedVm, build_launch_plan, discover_artifacts, launch_whp_vm};
use crate::{
    CheckOutcome, EvidenceCheckStatus, EvidenceSource, HarnessOptions, ScenarioDefinition,
};
#[cfg(windows)]
use crate::{control_session::HostControlSession, named_pipe::NamedPipeClient};
#[cfg(windows)]
use agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
#[cfg(windows)]
use agent_protocol::messages::{
    AgentControlMessage, CapabilityProofMaterial, ExecDisposition, FlowCreditRequest,
    HostControlMessage, LaunchIdentity, NetworkSetupState, ProtocolErrorCode, ProtocolErrorDetail,
    ReadyStatus, SERVICE_IDENTITY, StdinChunkRecord, StdinEofRecord, StreamName,
    TerminationOutcome, WORKLOAD_GID_MXC, WORKLOAD_GROUP_MXC, WORKLOAD_UID_MXC, WORKLOAD_USER_MXC,
};
#[cfg(windows)]
use agent_protocol::{PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES, PROTOCOL_VERSION};
#[cfg(windows)]
use serde::Deserialize;

const LIVE_TIMEOUT: Duration = Duration::from_secs(8);
#[cfg(windows)]
const PROBE_PATH: &str = "/sbin/nvx-agent-probe";
#[cfg(windows)]
const LIVE_RUN_DIR: &str = "live-whp-run";
#[cfg(windows)]
const RAW_ROOT_GUEST_PATH: &str = "/mnt/virtiofs";
#[cfg(windows)]
const ROOT_CANONICAL_HOST: &str = "/sandbox-root";
#[cfg(windows)]
const RW_CHILD: &str = "rw";
#[cfg(windows)]
const RO_CHILD: &str = "ro";
#[cfg(windows)]
const RO_SEED_FILE: &str = "known.bin";
#[cfg(windows)]
const UNDECLARED_CHILD: &str = "undeclared-sibling";
#[cfg(windows)]
const REPARSE_ESCAPE_LINK: &str = "escape-link";

struct LiveHarnessState {
    run_key: Option<String>,
    init_error: Option<String>,
    first_failure: Option<(u8, String)>,
    req1_evidence: Vec<String>,
    #[cfg(windows)]
    session: Option<LiveWhpSession>,
    #[cfg(not(windows))]
    vm: Option<LaunchedVm>,
}

#[cfg(windows)]
struct LiveWhpSession {
    vm: LaunchedVm,
    client: MxcAgentClient<NamedPipeClient>,
    launch: LaunchIdentity,
    root: CanonicalHostMappingRoot,
    containment: MappingContainmentPolicy,
    req9_mappings: Vec<ChildMapping>,
    req9_fixtures: Req9Fixtures,
    baseline_ready: ReadyStatus,
    baseline_health: agent_protocol::messages::HealthStatus,
}

#[cfg(windows)]
#[derive(Clone)]
struct Req9Fixtures {
    run_dir: PathBuf,
    common_root: PathBuf,
    rw_host_dir: PathBuf,
    ro_host_dir: PathBuf,
    ro_seed_host_file: PathBuf,
    ro_seed_bytes: Vec<u8>,
    undeclared_host_path: PathBuf,
    outside_escape_target: PathBuf,
    reparse_link_path: PathBuf,
}

#[cfg(windows)]
#[derive(Deserialize)]
struct ProbeIdentityReport {
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    supplementary_gids: Vec<u32>,
    username: Option<String>,
    groupname: Option<String>,
}

#[cfg(windows)]
#[derive(Deserialize)]
struct ProbeIsolationReport {
    host_pid_visible: bool,
    pid_namespace_matches_proc1: bool,
    private_proc: bool,
    private_dev: bool,
    private_devpts: bool,
    private_shm: bool,
    read_only_sys: bool,
    no_new_privs: bool,
    raw_export_root_visible: bool,
    agent_initramfs_visible: bool,
    mountinfo_has_raw_virtiofs_root: bool,
    capabilities: ProbeCapabilities,
    proc1: ProbeProcIdentity,
}

#[cfg(windows)]
#[derive(Deserialize)]
struct ProbeProcIdentity {
    uid: Option<u32>,
    gid: Option<u32>,
}

#[cfg(windows)]
#[derive(Deserialize)]
struct ProbeCapabilities {
    all_zero: bool,
}

#[cfg(windows)]
#[derive(Deserialize)]
struct ProbeMappingReport {
    rw_output_path: String,
    rw_bytes_hex: String,
    ro_seed_hex: String,
    ro_write_blocked: bool,
    ro_metadata_mutation_blocked: bool,
    undeclared_hidden: bool,
    raw_root_has_only_declared_destinations: bool,
    guest_destinations_exact: bool,
    ro_recursive_mount_read_only: bool,
}

#[cfg(windows)]
struct ExecObservation {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    messages: Vec<AgentControlMessage>,
    disposition: Option<ExecDisposition>,
    termination: Option<TerminationOutcome>,
    stdout_chunk_max: usize,
    stderr_chunk_max: usize,
}

static LIVE_STATE: OnceLock<Mutex<LiveHarnessState>> = OnceLock::new();

fn state() -> &'static Mutex<LiveHarnessState> {
    LIVE_STATE.get_or_init(|| {
        Mutex::new(LiveHarnessState {
            run_key: None,
            init_error: None,
            first_failure: None,
            req1_evidence: vec![],
            #[cfg(windows)]
            session: None,
            #[cfg(not(windows))]
            vm: None,
        })
    })
}

pub(crate) fn run_live_requirement(
    options: &HarnessOptions,
    definition: ScenarioDefinition,
) -> CheckOutcome {
    let mut guard = state().lock().expect("live harness state lock");
    let current_run_key = format!(
        "{}|{}|{}",
        options.output_dir.display(),
        options.backend.as_str(),
        options.mode as u8
    );
    if guard.run_key.as_deref() != Some(current_run_key.as_str()) {
        reset_state(&mut guard);
        guard.run_key = Some(current_run_key);
    }
    if let Err(error) = ensure_live_initialized(&mut guard, options) {
        guard.init_error = Some(error.clone());
        if definition.requirement_number > 1 {
            return blocked_check(format!("blocked after launch/bootstrap failure: {error}"));
        }
        return fail_check(error);
    }

    if let Some((failed_req, reason)) = guard.first_failure.clone()
        && definition.requirement_number > failed_req
    {
        return blocked_check(format!(
            "blocked: skipped after req{:02} failed in same live session ({reason})",
            failed_req
        ));
    }

    let outcome = match definition.requirement_number {
        1 => pass_check(guard.req1_evidence.clone()),
        2 => run_req2_immutable_config(&mut guard),
        3 => run_req3_repeated_exec(&mut guard),
        4 => run_req4_streams(&mut guard),
        5 => run_req5_backpressure(&mut guard),
        6 => run_req6_terminal_semantics(&mut guard),
        7 => run_req7_fixed_mxc_identity(&mut guard),
        8 => run_req8_full_isolation_verification(&mut guard),
        9 => run_req9_mapping_containment(&mut guard),
        10..=12 => fail_check(format!(
            "req{:02} failed: live scenario invariant check did not pass",
            definition.requirement_number
        )),
        _ => fail_check("unknown requirement number".to_string()),
    };

    if outcome.check_status != EvidenceCheckStatus::Pass && guard.first_failure.is_none() {
        let reason = outcome
            .error
            .clone()
            .unwrap_or_else(|| "scenario check did not pass".to_string());
        guard.first_failure = Some((definition.requirement_number, reason));
        teardown_live_session(&mut guard);
    }
    outcome
}

fn reset_state(state: &mut LiveHarnessState) {
    state.init_error = None;
    state.first_failure = None;
    state.req1_evidence.clear();
    teardown_live_session(state);
}

fn teardown_live_session(state: &mut LiveHarnessState) {
    #[cfg(windows)]
    if let Some(mut session) = state.session.take() {
        session.vm.kill();
    }
    #[cfg(not(windows))]
    if let Some(mut vm) = state.vm.take() {
        vm.kill();
    }
}

fn ensure_live_initialized(
    state: &mut LiveHarnessState,
    options: &HarnessOptions,
) -> Result<(), String> {
    if state.init_error.is_some() {
        return Err(state
            .init_error
            .clone()
            .unwrap_or_else(|| "live init failed".to_string()));
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        return Err(
            "live WHP scenarios require Windows host support and WHP artifacts".to_string(),
        );
    }
    #[cfg(windows)]
    {
        if state.session.is_some() {
            return Ok(());
        }
        let mut overrides = options.launch_overrides.clone().unwrap_or_default();
        if overrides.common_root.is_none() {
            overrides.common_root = Some(options.output_dir.join(LIVE_RUN_DIR).join("common-root"));
        }
        let common_root = overrides
            .common_root
            .clone()
            .ok_or_else(|| "common_root override unexpectedly missing".to_string())?;
        let req9_fixtures = prepare_req9_fixtures(&options.output_dir, &common_root)?;
        let artifacts = discover_artifacts(&options.output_dir, &overrides).map_err(|error| {
            format!(
                "{{\"kind\":\"missing-prerequisite\",\"field\":\"{}\",\"path\":\"{}\",\"reason\":\"{}\"}}",
                error.field,
                error.path.display(),
                error.reason.replace('\"', "'")
            )
        })?;
        let plan = build_launch_plan(&options.output_dir, artifacts);
        let launch = LaunchIdentity {
            generation: plan.channel_generation.saturating_add(1),
            nonce: plan.launch_nonce,
        };
        let root = CanonicalHostMappingRoot::parse(ROOT_CANONICAL_HOST.to_string())
            .map_err(|error| format!("invalid canonical root for req1 probe: {error}"))?;
        let containment = MappingContainmentPolicy {
            symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        };
        let req9_mappings = req9_legitimate_mappings()?;
        let vm = launch_whp_vm(plan)?;
        let pid = vm.process_id();
        let expected_image = vm.plan.artifacts.openvmm_exe.to_string_lossy().into_owned();
        let control = NamedPipeClient::connect(
            &vm.plan.control_pipe_name,
            Duration::from_secs(5),
            Some(pid),
            Some(expected_image.as_str()),
        )
        .map_err(|error| format!("failed to connect control pipe: {error}"))?;
        let session = HostControlSession::new(control);
        let mut client = MxcAgentClient::new(session);
        let mut capability_proof = [0_u8; 32];
        capability_proof[..16].copy_from_slice(&vm.plan.launch_nonce);
        capability_proof[16..].copy_from_slice(&vm.plan.launch_nonce);
        client
            .authenticate_launch(
                vm.plan.launch_capability,
                HostControlMessage::HostHello {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch,
                    capability_proof: CapabilityProofMaterial::try_from(capability_proof.to_vec())
                        .map_err(|error| {
                            format!("failed building capability proof for req1: {error}")
                        })?,
                },
                LIVE_TIMEOUT,
            )
            .map_err(|error| format!("launch authentication failed: {error}"))?;
        client
            .send_configure(HostControlMessage::Configure {
                launch,
                root: root.clone(),
                mappings: req9_mappings.clone(),
                containment,
            })
            .map_err(|error| format!("configure session failed: {error}"))?;
        let ready = client
            .wait_ready(LIVE_TIMEOUT)
            .map_err(|error| format!("wait_ready failed: {error}"))?;
        let health = client
            .request_health(LIVE_TIMEOUT)
            .map_err(|error| format!("health request failed: {error}"))?;
        let mut evidence = vec![format!(
            "single live session on control pipe {} completed req1 host-attach/configure/ready/health",
            vm.plan.control_pipe_name
        )];
        evidence.push(format!(
            "req9 mappings were configured immutably at launch: {}(rw), {}(ro) from host root {}",
            RW_CHILD,
            RO_CHILD,
            req9_fixtures.common_root.display()
        ));
        let ready_status = match ready {
            AgentControlMessage::Ready {
                launch: ready_launch,
                status,
            } => {
                if ready_launch != launch {
                    return Err(format!(
                        "ready launch identity mismatch: expected={launch:?} actual={ready_launch:?}"
                    ));
                }
                if status.service != SERVICE_IDENTITY || status.protocol_version != PROTOCOL_VERSION
                {
                    return Err(format!(
                        "ready identity mismatch: service={} protocol={}",
                        status.service, status.protocol_version
                    ));
                }
                if status.network.setup_state != NetworkSetupState::Ready {
                    return Err(format!(
                        "ready network setup_state was {:?}, expected Ready",
                        status.network.setup_state
                    ));
                }
                evidence.push(format!(
                    "ready verified launch nonce/generation plus service={} protocol={} network={:?}",
                    status.service, status.protocol_version, status.network.setup_state
                ));
                status
            }
            other => return Err(format!("wait_ready returned unexpected message: {other:?}")),
        };
        let health_status = match health {
            AgentControlMessage::Health(status) => {
                let Some(filesystem) = status.filesystem.clone() else {
                    return Err("health response omitted filesystem status".to_string());
                };
                let Some(network) = status.network.clone() else {
                    return Err("health response omitted network status".to_string());
                };
                if !filesystem.rootfs_ready {
                    return Err("health filesystem rootfs_ready=false".to_string());
                }
                if network.setup_state != NetworkSetupState::Ready {
                    return Err(format!(
                        "health network setup_state was {:?}, expected Ready",
                        network.setup_state
                    ));
                }
                evidence.push(format!(
                    "health verified filesystem rootfs_ready={} and network setup_state={:?}",
                    filesystem.rootfs_ready, network.setup_state
                ));
                status
            }
            other => return Err(format!("health returned unexpected message: {other:?}")),
        };

        state.req1_evidence = evidence;
        state.session = Some(LiveWhpSession {
            vm,
            client,
            launch,
            root,
            containment,
            req9_mappings,
            req9_fixtures,
            baseline_ready: ready_status,
            baseline_health: health_status,
        });
        Ok(())
    }
}

#[cfg(windows)]
fn req9_legitimate_mappings() -> Result<Vec<ChildMapping>, String> {
    Ok(vec![
        ChildMapping {
            child: RelativeChildPath::parse(RW_CHILD.to_string())
                .map_err(|error| format!("invalid rw mapping child path: {error}"))?,
            access: AccessMode::ReadWrite,
        },
        ChildMapping {
            child: RelativeChildPath::parse(RO_CHILD.to_string())
                .map_err(|error| format!("invalid ro mapping child path: {error}"))?,
            access: AccessMode::ReadOnly,
        },
    ])
}

#[cfg(windows)]
fn prepare_req9_fixtures(output_dir: &Path, common_root: &Path) -> Result<Req9Fixtures, String> {
    let run_dir = output_dir.join(LIVE_RUN_DIR);
    safe_remove_dir(&run_dir, output_dir)?;
    fs::create_dir_all(common_root).map_err(|error| {
        format!(
            "failed to create req9 common-root fixture {}: {error}",
            common_root.display()
        )
    })?;
    let rw_host_dir = common_root.join(RW_CHILD);
    let ro_host_dir = common_root.join(RO_CHILD);
    let undeclared_host_path = common_root.join(UNDECLARED_CHILD);
    let outside_escape_target = run_dir.join("outside-root-escape");
    fs::create_dir_all(&rw_host_dir)
        .map_err(|error| format!("failed to create rw fixture directory: {error}"))?;
    fs::create_dir_all(&ro_host_dir)
        .map_err(|error| format!("failed to create ro fixture directory: {error}"))?;
    fs::create_dir_all(&undeclared_host_path)
        .map_err(|error| format!("failed to create undeclared fixture directory: {error}"))?;
    fs::create_dir_all(&outside_escape_target)
        .map_err(|error| format!("failed to create outside-root fixture directory: {error}"))?;
    let ro_seed_host_file = ro_host_dir.join(RO_SEED_FILE);
    let ro_seed_bytes = vec![0x4e, 0x56, 0x58, 0x00, 0x52, 0x4f, 0xff, 0x7f, 0x10];
    fs::write(&ro_seed_host_file, &ro_seed_bytes)
        .map_err(|error| format!("failed to seed ro fixture file: {error}"))?;
    fs::write(
        outside_escape_target.join("escape-only.txt"),
        b"outside-common-root",
    )
    .map_err(|error| format!("failed to seed outside-root escape fixture: {error}"))?;
    let reparse_link_path = rw_host_dir.join(REPARSE_ESCAPE_LINK);
    create_reparse_link(&outside_escape_target, &reparse_link_path)?;
    Ok(Req9Fixtures {
        run_dir,
        common_root: common_root.to_path_buf(),
        rw_host_dir,
        ro_host_dir,
        ro_seed_host_file,
        ro_seed_bytes,
        undeclared_host_path,
        outside_escape_target,
        reparse_link_path,
    })
}

#[cfg(windows)]
fn safe_remove_dir(path: &Path, output_dir: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    if !path.starts_with(output_dir) {
        return Err(format!(
            "refusing to remove fixture path outside harness output directory: {}",
            path.display()
        ));
    }
    fs::remove_dir_all(path).map_err(|error| {
        format!(
            "failed to remove existing fixture path {}: {error}",
            path.display()
        )
    })
}

#[cfg(windows)]
fn create_reparse_link(target: &Path, link: &Path) -> Result<(), String> {
    if link.exists() {
        fs::remove_file(link).map_err(|error| {
            format!(
                "failed to remove existing reparse fixture link {}: {error}",
                link.display()
            )
        })?;
    }
    std::os::windows::fs::symlink_dir(target, link).map_err(|error| {
        format!(
            "failed to create required reparse/symlink escape fixture {} -> {}: {error}",
            link.display(),
            target.display()
        )
    })
}

#[cfg(windows)]
fn run_req2_immutable_config(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };

    let replay = expect_error_after_send(
        session,
        HostControlMessage::Configure {
            launch: session.launch,
            root: session.root.clone(),
            mappings: session.req9_mappings.clone(),
            containment: session.containment,
        },
        LIVE_TIMEOUT,
    );
    let replay_error = match replay {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let replay_typed = replay_error.code == ProtocolErrorCode::ConfigureAlreadyApplied
        || replay_error.code == ProtocolErrorCode::InvalidLifecycleTransition
        || replay_error.message.contains("ConfigurationConflict")
        || replay_error.message.contains("ConfigureAlreadyApplied");

    let conflicting_mapping_error = expect_error_after_send(
        session,
        HostControlMessage::Configure {
            launch: session.launch,
            root: session.root.clone(),
            mappings: vec![ChildMapping {
                child: match RelativeChildPath::parse("runtime".to_string()) {
                    Ok(value) => value,
                    Err(error) => {
                        return fail_check(format!(
                            "invalid relative mapping path for req2: {error}"
                        ));
                    }
                },
                access: AccessMode::ReadOnly,
            }],
            containment: session.containment,
        },
        LIVE_TIMEOUT,
    );
    let conflicting_mapping_error = match conflicting_mapping_error {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let conflicting_mapping_typed = conflicting_mapping_error.code
        == ProtocolErrorCode::ConfigureAlreadyApplied
        || conflicting_mapping_error.code == ProtocolErrorCode::InvalidLifecycleTransition
        || conflicting_mapping_error.code == ProtocolErrorCode::MappingConflict;

    let mut nonce = session.launch.nonce;
    nonce[0] ^= 0x5A;
    let conflicting_nonce_error = expect_error_after_send(
        session,
        HostControlMessage::Configure {
            launch: LaunchIdentity {
                generation: session.launch.generation,
                nonce,
            },
            root: session.root.clone(),
            mappings: session.req9_mappings.clone(),
            containment: session.containment,
        },
        LIVE_TIMEOUT,
    );
    let conflicting_nonce_error = match conflicting_nonce_error {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let conflicting_nonce_typed = conflicting_nonce_error.code
        == ProtocolErrorCode::LaunchGenerationConflict
        || conflicting_nonce_error.code == ProtocolErrorCode::LaunchGenerationNotNewer
        || conflicting_nonce_error.code == ProtocolErrorCode::InvalidLifecycleTransition
        || conflicting_nonce_error
            .message
            .contains("LaunchNonceMismatch");

    let conflicting_generation_error = expect_error_after_send(
        session,
        HostControlMessage::Configure {
            launch: LaunchIdentity {
                generation: session.launch.generation.saturating_add(1),
                nonce: session.launch.nonce,
            },
            root: session.root.clone(),
            mappings: session.req9_mappings.clone(),
            containment: session.containment,
        },
        LIVE_TIMEOUT,
    );
    let conflicting_generation_error = match conflicting_generation_error {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let conflicting_generation_typed = conflicting_generation_error.code
        == ProtocolErrorCode::LaunchGenerationConflict
        || conflicting_generation_error.code == ProtocolErrorCode::LaunchGenerationNotNewer
        || conflicting_generation_error.code == ProtocolErrorCode::InvalidLifecycleTransition
        || conflicting_generation_error
            .message
            .contains("LaunchGenerationMismatch");

    let ready_after = match session.client.wait_ready(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Ready { launch, status }) => {
            if launch != session.launch {
                return fail_check(format!(
                    "ready changed launch identity after configure replay errors: {launch:?}"
                ));
            }
            status
        }
        Ok(other) => {
            return fail_check(format!("wait_ready returned unexpected message: {other:?}"));
        }
        Err(error) => return fail_check(format!("wait_ready after req2 checks failed: {error}")),
    };
    let health_after = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => status,
        Ok(other) => return fail_check(format!("health returned unexpected message: {other:?}")),
        Err(error) => return fail_check(format!("health after req2 checks failed: {error}")),
    };
    let unchanged =
        ready_after == session.baseline_ready && health_after == session.baseline_health;
    if replay_typed
        && conflicting_mapping_typed
        && conflicting_nonce_typed
        && conflicting_generation_typed
        && unchanged
    {
        pass_check(vec![
            format!(
                "identical configure replay rejected with typed error {:?}",
                replay_error.code
            ),
            format!(
                "conflicting mapping replay rejected with typed error {:?}",
                conflicting_mapping_error.code
            ),
            format!(
                "conflicting launch nonce/generation rejected with typed errors {:?}/{:?}",
                conflicting_nonce_error.code, conflicting_generation_error.code
            ),
            "ready and health snapshots remained unchanged after all rejected req2 mutations (including network and fixed identity fields)".to_string(),
        ])
    } else {
        fail_check("immutable configure-session replay checks failed".to_string())
    }
}

#[cfg(windows)]
fn run_req3_repeated_exec(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let exec1 = 301_u32;
    if let Err(error) = start_probe_exec(
        session,
        exec1,
        &["seq", "--token", "one", "--sleep-ms", "400", "--exit", "10"],
        None,
    ) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec1, StreamName::Stdout, 1) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec1, StreamName::Stderr, 1) {
        return fail_check(error);
    }
    let busy_exec_id = 302_u32;
    if let Err(error) = start_probe_exec(session, busy_exec_id, &["seq", "--token", "busy"], None) {
        return fail_check(error);
    }
    let busy_error = match expect_protocol_error(session, LIVE_TIMEOUT) {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let busy_typed = busy_error.code == ProtocolErrorCode::ActiveExecExists
        || busy_error.message.contains("WorkloadBusy")
        || busy_error.message.contains("ActiveExecExists");
    let busy_side_effect_free = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => status.active_exec_id == Some(exec1),
        _ => false,
    };
    let first = match collect_exec_until_terminal(session, exec1, Duration::from_secs(10), true) {
        Ok(obs) => obs,
        Err(error) => return fail_check(error),
    };
    let run_two = run_simple_probe_exec(session, 303, &["seq", "--token", "two", "--exit", "11"]);
    let run_three =
        run_simple_probe_exec(session, 304, &["seq", "--token", "three", "--exit", "12"]);
    let reused_exec_attempt = start_probe_exec(session, 303, &["seq", "--token", "reuse"], None)
        .and_then(|_| {
            expect_protocol_error(session, LIVE_TIMEOUT).map_err(|error| error.to_string())
        });
    let reuse_detail = match reused_exec_attempt {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let reuse_typed = reuse_detail.code == ProtocolErrorCode::ExecIdReusedInGeneration
        || reuse_detail.code == ProtocolErrorCode::InvalidLifecycleTransition
        || reuse_detail.message.contains("ExecIdReusedInGeneration");
    let expected = matches!(first.disposition, Some(ExecDisposition::ExitCode(10)))
        && first.stdout == b"seq:one\n"
        && first.stderr == b"seq-err:one\n"
        && matches!(run_two, Ok((ExecDisposition::ExitCode(11), ref out, ref err)) if out == b"seq:two\n" && err == b"seq-err:two\n")
        && matches!(run_three, Ok((ExecDisposition::ExitCode(12), ref out, ref err)) if out == b"seq:three\n" && err == b"seq-err:three\n");
    if busy_typed && busy_side_effect_free && reuse_typed && expected {
        pass_check(vec![
            "three sequential commands executed in one warm VM with unique exec IDs and exact stdout/stderr + exit codes".to_string(),
            format!(
                "second create while exec {} active returned typed busy error {:?} and left active_exec_id unchanged",
                exec1, busy_error.code
            ),
            format!(
                "exec ID reuse rejected with typed error {:?}",
                reuse_detail.code
            ),
        ])
    } else {
        fail_check("repeated exec invariants failed".to_string())
    }
}

#[cfg(windows)]
fn run_req4_streams(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let binary = match run_simple_probe_exec(session, 401, &["stream-split"]) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let stdout_expected = vec![b'A', 0, b'B', 0xFF, b'C'];
    let stderr_expected = vec![b'X', 0, b'Y', 0xFE, b'Z'];
    if binary.0 != ExecDisposition::ExitCode(0)
        || binary.1 != stdout_expected
        || binary.2 != stderr_expected
    {
        return fail_check("binary stream split mismatch".to_string());
    }

    let exec_id = 402_u32;
    if let Err(error) = start_probe_exec(session, exec_id, &["stdin-roundtrip"], None) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stdout, 1) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stderr, 1) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stdin, 1) {
        return fail_check(error);
    }
    let payload = vec![0x00, 0x11, 0x22, 0x33, 0xFF, 0x00, 0xAA, 0xFE, 0x7F];
    if let Err(error) = session.client.send_stdin_chunk(StdinChunkRecord {
        exec_id,
        sequence: 0,
        chunk: payload.clone(),
    }) {
        return fail_check(format!("sending stdin chunk failed: {error}"));
    }
    if let Err(error) = session.client.send_stdin_eof(StdinEofRecord {
        exec_id,
        sequence: 1,
    }) {
        return fail_check(format!("sending stdin EOF failed: {error}"));
    }
    let observed = match collect_exec_until_terminal(session, exec_id, LIVE_TIMEOUT, true) {
        Ok(obs) => obs,
        Err(error) => return fail_check(error),
    };
    if observed.disposition != Some(ExecDisposition::ExitCode(0)) || observed.stdout != payload {
        return fail_check("stdin binary roundtrip did not match expected bytes".to_string());
    }
    pass_check(vec![
        "binary stream workload emitted exact independent stdout/stderr byte sequences (including NUL and non-UTF8 bytes)".to_string(),
        "stdin binary roundtrip preserved exact bytes when returned through stdout".to_string(),
    ])
}

#[cfg(windows)]
fn run_req5_backpressure(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let exec_id = 501_u32;
    let target_bytes = 210_000_usize;
    if let Err(error) = start_probe_exec(
        session,
        exec_id,
        &[
            "flood",
            "--stream",
            "stdout",
            "--bytes",
            &target_bytes.to_string(),
            "--chunk",
            "4096",
        ],
        None,
    ) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stderr, 1) {
        return fail_check(error);
    }
    let health_ok = match session
        .client
        .request_health_observing_inbound(LIVE_TIMEOUT, |message| match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                Err(ClientError::Protocol(format!(
                    "req05 pre-credit violation: observed stdout chunk for exec {exec_id} before any stdout credits"
                )))
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                Err(ClientError::Protocol(format!(
                    "req05 pre-credit violation: observed stderr chunk for exec {exec_id} before any stdout credits"
                )))
            }
            _ => Ok(()),
        }) {
        Ok(AgentControlMessage::Health(status)) => status.active_exec_id == Some(exec_id),
        Ok(AgentControlMessage::Error(detail)) => {
            return fail_check(format!(
                "health request failed during req05 zero-credit gate: {:?}: {}",
                detail.code, detail.message
            ));
        }
        Ok(other) => {
            return fail_check(format!(
                "unexpected response while waiting for req05 health gate: {other:?}"
            ));
        }
        Err(error) => {
            return fail_check(format!(
                "health gate failed while verifying req05 zero-credit behavior: {error}"
            ));
        }
    };
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stdout, 1) {
        return fail_check(error);
    }
    let observed =
        match collect_exec_until_terminal(session, exec_id, Duration::from_secs(20), true) {
            Ok(obs) => obs,
            Err(error) => return fail_check(error),
        };
    let mut expected = Vec::with_capacity(target_bytes);
    for i in 0..target_bytes {
        expected.push((i % 256) as u8);
    }
    let chunk_bound_ok = observed.stdout_chunk_max > 0
        && observed.stdout_chunk_max <= PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES
        && observed.stderr_chunk_max <= PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES;
    if health_ok
        && chunk_bound_ok
        && observed.stdout == expected
        && observed.disposition == Some(ExecDisposition::ExitCode(0))
    {
        pass_check(vec![
            "delayed stdout credits held output until recovery; full flooded payload arrived losslessly after credit recovery".to_string(),
            format!(
                "observed stdout/stderr chunk bounds stayed <= {} bytes (no oversized outer data framing)",
                PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES
            ),
            "health request succeeded while output flow was intentionally backpressured".to_string(),
        ])
    } else {
        fail_check("bounded backpressure invariants failed".to_string())
    }
}

#[cfg(windows)]
fn run_req6_terminal_semantics(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let stdin_exec = 601_u32;
    if let Err(error) = start_probe_exec(session, stdin_exec, &["wait-stdin-eof"], None) {
        return fail_check(error);
    }
    for stream in [StreamName::Stdout, StreamName::Stderr, StreamName::Stdin] {
        if let Err(error) = grant_stream(session, stdin_exec, stream, 1) {
            return fail_check(error);
        }
    }
    if let Err(error) = session.client.send_stdin_eof(StdinEofRecord {
        exec_id: stdin_exec,
        sequence: 0,
    }) {
        return fail_check(format!("stdin EOF request failed: {error}"));
    }
    let stdin_observed =
        match collect_exec_until_terminal(session, stdin_exec, Duration::from_secs(10), true) {
            Ok(value) => value,
            Err(error) => return fail_check(error),
        };
    let stdin_eof_ok = stdin_observed.stdout == b"stdin-eof-observed\n"
        && stdin_observed.disposition == Some(ExecDisposition::ExitCode(0))
        && stdin_observed.termination.is_none()
        && terminal_order_ok(
            &stdin_observed.messages,
            stdin_exec,
            ExecDisposition::ExitCode(0),
            None,
        );

    let normal_ok = match run_exec_terminal_check(
        session,
        602,
        &["seq", "--token", "normal", "--exit", "0"],
        None,
        ExecDisposition::ExitCode(0),
    ) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let signal_ok = match run_exec_terminal_check(
        session,
        603,
        &["signal-self", "--signal", "15"],
        None,
        ExecDisposition::Signaled(15),
    ) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let graceful_cancel = match run_cancelled_tree_exec(session, 604, false, None) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let forced_cancel = match run_cancelled_tree_exec(session, 605, true, None) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let timeout_tree = match run_timeout_tree_exec(session, 606, true, 100) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };

    if stdin_eof_ok && normal_ok && signal_ok && graceful_cancel && forced_cancel && timeout_tree {
        pass_check(vec![
            "stdin EOF reached live workload, which acknowledged EOF before clean terminal completion".to_string(),
            "normal/signal terminals carried no forced metadata; cancel reported Graceful when TERM completed, Forced when SIGKILL escalation was initiated, and timeout+SIGTERM-ignore reported forced timeout escalation".to_string(),
            "each terminal arrived exactly once and only after stdout/stderr EOF plus descendants-cleaned; child+grandchild PIDs were gone before cancel/timeout completion".to_string(),
        ])
    } else {
        fail_check("terminal semantics invariants failed".to_string())
    }
}

#[cfg(windows)]
fn run_req7_fixed_mxc_identity(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let (disposition, stdout, stderr) =
        match run_simple_probe_exec(session, 701, &["identity-json"]) {
            Ok(value) => value,
            Err(error) => return fail_check(error),
        };
    if disposition != ExecDisposition::ExitCode(0) || !stderr.is_empty() {
        return fail_check("identity probe execution failed".to_string());
    }
    let identity: ProbeIdentityReport = match serde_json::from_slice(&stdout) {
        Ok(value) => value,
        Err(error) => return fail_check(format!("identity probe json decode failed: {error}")),
    };
    let expected_uid = session.baseline_ready.workload_identity.uid;
    let expected_gid = session.baseline_ready.workload_identity.gid;
    let configured_ok = identity.real_uid == WORKLOAD_UID_MXC
        && identity.effective_uid == WORKLOAD_UID_MXC
        && identity.saved_uid == WORKLOAD_UID_MXC
        && identity.real_gid == WORKLOAD_GID_MXC
        && identity.effective_gid == WORKLOAD_GID_MXC
        && identity.saved_gid == WORKLOAD_GID_MXC;
    let ready_consistent = identity.real_uid == expected_uid
        && identity.effective_uid == expected_uid
        && identity.saved_uid == expected_uid
        && identity.real_gid == expected_gid
        && identity.effective_gid == expected_gid
        && identity.saved_gid == expected_gid;
    let non_root = expected_uid != 0
        && expected_gid != 0
        && identity.supplementary_gids.iter().all(|gid| *gid != 0);
    let identity_names_ok = identity
        .username
        .as_ref()
        .is_none_or(|value| value == WORKLOAD_USER_MXC)
        && identity
            .groupname
            .as_ref()
            .is_none_or(|value| value == WORKLOAD_GROUP_MXC);
    let health_consistent = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => {
            status.launch_admitted
                && status.active_exec_id.is_none()
                && status
                    .filesystem
                    .as_ref()
                    .is_some_and(|filesystem| filesystem.rootfs_ready)
                && status
                    .network
                    .as_ref()
                    .is_some_and(|network| network.setup_state == NetworkSetupState::Ready)
        }
        _ => false,
    };
    if configured_ok && ready_consistent && non_root && identity_names_ok && health_consistent {
        pass_check(vec![
            format!(
                "probe verified fixed identity uid/gid {}/{} for real/effective/saved IDs",
                expected_uid, expected_gid
            ),
            "identity remained non-root and supplementary groups excluded gid 0".to_string(),
            "ready/health snapshots remained consistent with fixed mxc identity configuration"
                .to_string(),
        ])
    } else {
        fail_check("fixed mxc identity live verification failed".to_string())
    }
}

#[cfg(windows)]
fn run_req8_full_isolation_verification(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let isolation_args = [
        "isolation-json",
        "--host-pid",
        &session.vm.process_id().to_string(),
        "--raw-root",
        RAW_ROOT_GUEST_PATH,
        "--expected-rw",
        RW_CHILD,
        "--expected-ro",
        RO_CHILD,
    ];
    let (disposition, stdout, stderr) = match run_simple_probe_exec(session, 801, &isolation_args) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    if disposition != ExecDisposition::ExitCode(0) || !stderr.is_empty() {
        return fail_check("isolation probe execution failed".to_string());
    }
    let report: ProbeIsolationReport = match serde_json::from_slice(&stdout) {
        Ok(value) => value,
        Err(error) => return fail_check(format!("isolation probe json decode failed: {error}")),
    };
    let baseline_ready = &session.baseline_ready;
    let core_isolation_ok = baseline_ready.isolation.pid_namespace
        && baseline_ready.isolation.mount_namespace
        && baseline_ready.isolation.uts_namespace
        && baseline_ready.isolation.ipc_namespace
        && baseline_ready.isolation.private_proc
        && baseline_ready.isolation.private_dev
        && baseline_ready.isolation.private_devpts
        && baseline_ready.isolation.private_shm
        && baseline_ready.isolation.read_only_sys
        && baseline_ready.isolation.capabilities_dropped
        && baseline_ready.isolation.no_new_privs
        && baseline_ready.isolation.orphan_reaping;
    let probe_isolation_ok = !report.host_pid_visible
        && report.pid_namespace_matches_proc1
        && report.private_proc
        && report.private_dev
        && report.private_devpts
        && report.private_shm
        && report.read_only_sys
        && report.no_new_privs
        && report.capabilities.all_zero
        && !report.raw_export_root_visible
        && !report.agent_initramfs_visible
        && !report.mountinfo_has_raw_virtiofs_root
        && report.proc1.uid == Some(WORKLOAD_UID_MXC)
        && report.proc1.gid == Some(WORKLOAD_GID_MXC);
    let normal_cleanup_ok = match run_normal_tree_exec_cleanup(session, 802, 500) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let cancel_cleanup_ok = match run_cancelled_tree_exec(session, 803, false, None) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let timeout_cleanup_ok = match run_timeout_tree_exec(session, 804, true, 100) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    if core_isolation_ok
        && probe_isolation_ok
        && normal_cleanup_ok
        && cancel_cleanup_ok
        && timeout_cleanup_ok
    {
        pass_check(vec![
            "live probe confirmed private pid/mount/uts/ipc namespaces, private proc/dev/devpts/shm, read-only /sys, no_new_privs, and zero capability sets".to_string(),
            "host OpenVMM pid was not visible in guest /proc and raw virtio-fs export remained hidden behind declared mappings".to_string(),
            "child+grandchild workload trees were cleaned after normal exit, cancellation, and timeout paths".to_string(),
        ])
    } else {
        fail_check("full isolation live verification failed".to_string())
    }
}

#[cfg(windows)]
fn run_req9_mapping_containment(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let rw_guest_dir = format!("{RAW_ROOT_GUEST_PATH}/{RW_CHILD}");
    let ro_guest_file = format!("{RAW_ROOT_GUEST_PATH}/{RO_CHILD}/{RO_SEED_FILE}");
    let undeclared_guest_path = format!("{RAW_ROOT_GUEST_PATH}/{UNDECLARED_CHILD}");
    let mapping_args = [
        "mapping-check",
        "--rw-dir",
        rw_guest_dir.as_str(),
        "--ro-file",
        ro_guest_file.as_str(),
        "--undeclared-path",
        undeclared_guest_path.as_str(),
        "--raw-root",
        RAW_ROOT_GUEST_PATH,
        "--expected-rw",
        RW_CHILD,
        "--expected-ro",
        RO_CHILD,
        "--output-name",
        "guest-rw.bin",
    ];
    let (disposition, stdout, stderr) = match run_simple_probe_exec(session, 901, &mapping_args) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    if disposition != ExecDisposition::ExitCode(0) || !stderr.is_empty() {
        return fail_check("mapping probe execution failed".to_string());
    }
    let report: ProbeMappingReport = match serde_json::from_slice(&stdout) {
        Ok(value) => value,
        Err(error) => return fail_check(format!("mapping probe json decode failed: {error}")),
    };
    let host_rw_bytes = match fs::read(session.req9_fixtures.rw_host_dir.join("guest-rw.bin")) {
        Ok(value) => value,
        Err(error) => {
            return fail_check(format!(
                "reading host rw verification artifact failed: {error}"
            ));
        }
    };
    let host_rw_hex = bytes_to_hex(&host_rw_bytes);
    let host_ro_seed_bytes = match fs::read(&session.req9_fixtures.ro_seed_host_file) {
        Ok(value) => value,
        Err(error) => {
            return fail_check(format!(
                "reading host ro seed verification file failed: {error}"
            ));
        }
    };
    let host_ro_seed_hex = bytes_to_hex(&host_ro_seed_bytes);
    let fixture_consistent = host_ro_seed_bytes == session.req9_fixtures.ro_seed_bytes
        && session.req9_fixtures.common_root.exists()
        && session.req9_fixtures.ro_host_dir.exists()
        && session.req9_fixtures.undeclared_host_path.exists()
        && session.req9_fixtures.outside_escape_target.exists()
        && session.req9_fixtures.reparse_link_path.exists();
    let shared_mutation_rejected = expect_error_after_send(
        session,
        HostControlMessage::Configure {
            launch: session.launch,
            root: session.root.clone(),
            mappings: vec![ChildMapping {
                child: match RelativeChildPath::parse("rw/sub".to_string()) {
                    Ok(value) => value,
                    Err(error) => {
                        return fail_check(format!(
                            "invalid req9 post-config mutation child path: {error}"
                        ));
                    }
                },
                access: AccessMode::ReadOnly,
            }],
            containment: session.containment,
        },
        LIVE_TIMEOUT,
    )
    .map(|detail| {
        detail.code == ProtocolErrorCode::ConfigureAlreadyApplied
            || detail.code == ProtocolErrorCode::InvalidLifecycleTransition
            || detail.code == ProtocolErrorCode::MappingConflict
    })
    .unwrap_or(false);
    let validation_checks = match run_req9_validation_session(session) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };

    if report.rw_bytes_hex == host_rw_hex
        && report.ro_seed_hex == host_ro_seed_hex
        && report.ro_write_blocked
        && report.ro_metadata_mutation_blocked
        && report.undeclared_hidden
        && report.raw_root_has_only_declared_destinations
        && report.guest_destinations_exact
        && report.ro_recursive_mount_read_only
        && shared_mutation_rejected
        && fixture_consistent
        && validation_checks
    {
        pass_check(vec![
            format!(
                "rw mapping round-tripped exact workload bytes to host file {}",
                session.req9_fixtures.rw_host_dir.join("guest-rw.bin").display()
            ),
            "ro mapping preserved seed bytes and rejected write plus metadata mutation attempts"
                .to_string(),
            "undeclared sibling/raw export remained hidden; traversal/symlink-over-escape/overlap and post-config mutation checks were rejected".to_string(),
        ])
    } else {
        fail_check(format!(
            "mapping containment checks failed (rw_output_path={})",
            report.rw_output_path
        ))
    }
}

#[cfg(windows)]
fn run_normal_tree_exec_cleanup(
    session: &mut LiveWhpSession,
    exec_id: u32,
    hold_ms: u64,
) -> Result<bool, String> {
    start_probe_exec(
        session,
        exec_id,
        &["spawn-tree", "--hold-ms", &hold_ms.to_string()],
        None,
    )?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    let tree_pids = loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for normal tree pid line for exec {exec_id}"
            ));
        }
        let message = session
            .client
            .recv_agent_control(Duration::from_millis(250))
            .map_err(|error| format!("waiting for normal tree line failed: {error}"))?;
        match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                output.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stdout, 1)?;
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                grant_stream(session, exec_id, StreamName::Stderr, 1)?;
            }
            _ => {}
        }
    };
    let observed = collect_exec_until_terminal(session, exec_id, Duration::from_secs(10), true)?;
    if observed.disposition != Some(ExecDisposition::ExitCode(0)) {
        return Ok(false);
    }
    run_pid_check(
        session,
        890 + exec_id,
        tree_pids.child,
        tree_pids.grandchild,
    )
}

#[cfg(windows)]
fn run_req9_validation_session(shared: &LiveWhpSession) -> Result<bool, String> {
    let mut vm = launch_whp_vm(build_launch_plan(
        &shared.req9_fixtures.run_dir,
        shared.vm.plan.artifacts.clone(),
    ))?;
    let pid = vm.process_id();
    let expected_image = vm.plan.artifacts.openvmm_exe.to_string_lossy().into_owned();
    let control = NamedPipeClient::connect(
        &vm.plan.control_pipe_name,
        Duration::from_secs(5),
        Some(pid),
        Some(expected_image.as_str()),
    )
    .map_err(|error| format!("req9 validation control-pipe connect failed: {error}"))?;
    let session = HostControlSession::new(control);
    let mut client = MxcAgentClient::new(session);
    let launch = LaunchIdentity {
        generation: vm.plan.channel_generation.saturating_add(1),
        nonce: vm.plan.launch_nonce,
    };
    let mut capability_proof = [0_u8; 32];
    capability_proof[..16].copy_from_slice(&vm.plan.launch_nonce);
    capability_proof[16..].copy_from_slice(&vm.plan.launch_nonce);
    client
        .authenticate_launch(
            vm.plan.launch_capability,
            HostControlMessage::HostHello {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch,
                capability_proof: CapabilityProofMaterial::try_from(capability_proof.to_vec())
                    .map_err(|error| format!("req9 validation proof build failed: {error}"))?,
            },
            LIVE_TIMEOUT,
        )
        .map_err(|error| format!("req9 validation launch authentication failed: {error}"))?;
    let root = CanonicalHostMappingRoot::parse(ROOT_CANONICAL_HOST.to_string())
        .map_err(|error| format!("req9 validation root parse failed: {error}"))?;
    let containment = MappingContainmentPolicy {
        symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
    };
    let traversal_detail = send_req9_traversal_probe(&mut client, launch, containment, &root)?;
    let traversal_rejected = traversal_detail.code == ProtocolErrorCode::InvalidLifecycleTransition
        && traversal_detail
            .message
            .contains("invalid host control payload");

    let overlap_error = expect_error_after_send_in(
        &mut client,
        HostControlMessage::Configure {
            launch,
            root: root.clone(),
            mappings: vec![
                ChildMapping {
                    child: RelativeChildPath::parse(RW_CHILD.to_string())
                        .map_err(|error| format!("req9 overlap parse failed: {error}"))?,
                    access: AccessMode::ReadWrite,
                },
                ChildMapping {
                    child: RelativeChildPath::parse(format!("{RW_CHILD}/nested"))
                        .map_err(|error| format!("req9 overlap child parse failed: {error}"))?,
                    access: AccessMode::ReadOnly,
                },
            ],
            containment,
        },
        LIVE_TIMEOUT,
    )?;
    let overlap_rejected = overlap_error.code == ProtocolErrorCode::MappingConflict
        || overlap_error.code == ProtocolErrorCode::InvalidLifecycleTransition;

    let symlink_error = expect_error_after_send_in(
        &mut client,
        HostControlMessage::Configure {
            launch,
            root,
            mappings: vec![ChildMapping {
                child: RelativeChildPath::parse(format!("{RW_CHILD}/{REPARSE_ESCAPE_LINK}"))
                    .map_err(|error| format!("req9 symlink parse failed: {error}"))?,
                access: AccessMode::ReadOnly,
            }],
            containment,
        },
        LIVE_TIMEOUT,
    )?;
    let symlink_rejected = symlink_error.code == ProtocolErrorCode::InvalidLifecycleTransition
        && (symlink_error.message.contains("symlink")
            || symlink_error.message.contains("escaped mapping root"));
    vm.kill();
    Ok(traversal_rejected && overlap_rejected && symlink_rejected)
}

#[cfg(windows)]
fn send_req9_traversal_probe(
    client: &mut MxcAgentClient<NamedPipeClient>,
    launch: LaunchIdentity,
    containment: MappingContainmentPolicy,
    root: &CanonicalHostMappingRoot,
) -> Result<ProtocolErrorDetail, String> {
    let payload = serde_json::json!({
        "type": "configure",
        "launch": launch,
        "root": root,
        "mappings": [
            {
                "child": "../escape",
                "access": "readOnly"
            }
        ],
        "containment": containment
    });
    let encoded = serde_json::to_vec(&payload)
        .map_err(|error| format!("encoding req9 traversal payload failed: {error}"))?;
    client
        .send_raw_control_payload(&encoded)
        .map_err(|error| format!("sending req9 traversal payload failed: {error}"))?;
    expect_protocol_error_in(client, LIVE_TIMEOUT)
}

#[cfg(windows)]
fn expect_error_after_send_in(
    session: &mut MxcAgentClient<NamedPipeClient>,
    message: HostControlMessage,
    timeout: Duration,
) -> Result<ProtocolErrorDetail, String> {
    session
        .send_host_control(message)
        .map_err(|error| format!("sending host control message failed: {error}"))?;
    expect_protocol_error_in(session, timeout)
}

#[cfg(windows)]
fn expect_protocol_error_in(
    session: &mut MxcAgentClient<NamedPipeClient>,
    timeout: Duration,
) -> Result<ProtocolErrorDetail, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll = remaining.min(Duration::from_millis(250));
        match session.recv_agent_control(poll) {
            Ok(AgentControlMessage::Error(detail)) => return Ok(detail),
            Ok(AgentControlMessage::StdoutChunk(record)) => {
                let _ = session.send_flow_credits(FlowCreditRequest {
                    exec_id: record.exec_id,
                    stream: StreamName::Stdout,
                    credits: 1,
                });
            }
            Ok(AgentControlMessage::StderrChunk(record)) => {
                let _ = session.send_flow_credits(FlowCreditRequest {
                    exec_id: record.exec_id,
                    stream: StreamName::Stderr,
                    credits: 1,
                });
            }
            Ok(_) => {}
            Err(ClientError::Timeout(_)) => {}
            Err(error) => return Err(format!("waiting for protocol error failed: {error}")),
        }
    }
    Err("timed out waiting for protocol error response".to_string())
}

#[cfg(windows)]
fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(windows)]
fn run_exec_terminal_check(
    session: &mut LiveWhpSession,
    exec_id: u32,
    args: &[&str],
    timeout_ms: Option<u64>,
    expected: ExecDisposition,
) -> Result<bool, String> {
    start_probe_exec(session, exec_id, args, timeout_ms)?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    let observed = collect_exec_until_terminal(session, exec_id, Duration::from_secs(10), true)?;
    Ok(observed.disposition == Some(expected)
        && observed.termination.is_none()
        && terminal_order_ok(&observed.messages, exec_id, expected, None))
}

#[cfg(windows)]
fn run_cancelled_tree_exec(
    session: &mut LiveWhpSession,
    exec_id: u32,
    ignore_term: bool,
    timeout_ms: Option<u64>,
) -> Result<bool, String> {
    let mut args = vec!["spawn-tree", "--hold-ms", "30000"];
    if ignore_term {
        args.push("--ignore-term");
    }
    start_probe_exec(session, exec_id, &args, timeout_ms)?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    let tree_pids = loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for tree pid line for exec {exec_id}"
            ));
        }
        let message = session
            .client
            .recv_agent_control(Duration::from_millis(250))
            .map_err(|error| format!("waiting for tree line failed: {error}"))?;
        match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                output.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stdout, 1)?;
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                grant_stream(session, exec_id, StreamName::Stderr, 1)?;
            }
            AgentControlMessage::Error(detail) => {
                return Err(format!(
                    "unexpected protocol error before cancel: {:?}",
                    detail.code
                ));
            }
            _ => {}
        }
    };
    session
        .client
        .send_cancel_execution(exec_id)
        .map_err(|error| format!("cancel execution failed: {error}"))?;
    let observed = collect_exec_until_terminal(session, exec_id, Duration::from_secs(12), true)?;
    if observed.disposition != Some(ExecDisposition::Cancelled)
        || observed.termination
            != Some(if ignore_term {
                TerminationOutcome::ForcedKill
            } else {
                TerminationOutcome::GracefulTerm
            })
        || !terminal_order_ok(
            &observed.messages,
            exec_id,
            ExecDisposition::Cancelled,
            Some(if ignore_term {
                TerminationOutcome::ForcedKill
            } else {
                TerminationOutcome::GracefulTerm
            }),
        )
    {
        return Ok(false);
    }
    run_pid_check(
        session,
        690 + exec_id,
        tree_pids.child,
        tree_pids.grandchild,
    )
}

#[cfg(windows)]
fn run_timeout_tree_exec(
    session: &mut LiveWhpSession,
    exec_id: u32,
    ignore_term: bool,
    timeout_ms: u64,
) -> Result<bool, String> {
    let mut args = vec!["spawn-tree", "--hold-ms", "30000"];
    if ignore_term {
        args.push("--ignore-term");
    }
    start_probe_exec(session, exec_id, &args, Some(timeout_ms))?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    let mut output = Vec::new();
    let pid_deadline = Instant::now() + Duration::from_secs(8);
    let tree_pids = loop {
        if Instant::now() >= pid_deadline {
            return Err(format!(
                "timed out waiting for tree pid line for exec {exec_id}"
            ));
        }
        let message = session
            .client
            .recv_agent_control(Duration::from_millis(250))
            .map_err(|error| format!("waiting for timeout tree line failed: {error}"))?;
        match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                output.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stdout, 1)?;
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                grant_stream(session, exec_id, StreamName::Stderr, 1)?;
            }
            AgentControlMessage::Error(detail) => {
                return Err(format!(
                    "unexpected protocol error during timeout setup: {:?}",
                    detail.code
                ));
            }
            _ => {}
        }
    };
    let observed = collect_exec_until_terminal(session, exec_id, Duration::from_secs(12), true)?;
    if observed.disposition != Some(ExecDisposition::TimedOut)
        || observed.termination != Some(TerminationOutcome::ForcedKill)
        || !terminal_order_ok(
            &observed.messages,
            exec_id,
            ExecDisposition::TimedOut,
            Some(TerminationOutcome::ForcedKill),
        )
    {
        return Ok(false);
    }
    run_pid_check(
        session,
        790 + exec_id,
        tree_pids.child,
        tree_pids.grandchild,
    )
}

#[cfg(windows)]
fn run_pid_check(
    session: &mut LiveWhpSession,
    exec_id: u32,
    child: u32,
    grandchild: u32,
) -> Result<bool, String> {
    start_probe_exec(
        session,
        exec_id,
        &[
            "check-pids-gone",
            &child.to_string(),
            &grandchild.to_string(),
        ],
        None,
    )?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    let observed = collect_exec_until_terminal(session, exec_id, Duration::from_secs(8), true)?;
    Ok(observed.disposition == Some(ExecDisposition::ExitCode(0))
        && observed.stdout == b"pids-gone\n")
}

#[cfg(windows)]
fn parse_tree_pids(buffer: &[u8]) -> Option<TreePids> {
    let text = std::str::from_utf8(buffer).ok()?;
    let line = text.lines().find(|line| line.starts_with("tree "))?;
    let mut child = None;
    let mut grandchild = None;
    for token in line.split_whitespace() {
        if let Some(value) = token.strip_prefix("child=") {
            child = value.parse::<u32>().ok();
        } else if let Some(value) = token.strip_prefix("grandchild=") {
            grandchild = value.parse::<u32>().ok();
        }
    }
    Some(TreePids {
        child: child?,
        grandchild: grandchild?,
    })
}

#[cfg(windows)]
struct TreePids {
    child: u32,
    grandchild: u32,
}

#[cfg(windows)]
fn run_simple_probe_exec(
    session: &mut LiveWhpSession,
    exec_id: u32,
    args: &[&str],
) -> Result<(ExecDisposition, Vec<u8>, Vec<u8>), String> {
    start_probe_exec(session, exec_id, args, None)?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    let observed = collect_exec_until_terminal(session, exec_id, LIVE_TIMEOUT, true)?;
    let disposition = observed
        .disposition
        .ok_or_else(|| format!("exec {exec_id} did not produce a terminal disposition"))?;
    Ok((disposition, observed.stdout, observed.stderr))
}

#[cfg(windows)]
fn start_probe_exec(
    session: &mut LiveWhpSession,
    exec_id: u32,
    args: &[&str],
    timeout_ms: Option<u64>,
) -> Result<(), String> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(PROBE_PATH.to_string());
    argv.extend(args.iter().map(|item| (*item).to_string()));
    session
        .client
        .send_create_process(HostControlMessage::CreateProcess {
            exec_id,
            argv,
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms,
        })
        .map_err(|error| format!("create process for exec {exec_id} failed: {error}"))?;
    Ok(())
}

#[cfg(windows)]
fn grant_stream(
    session: &mut LiveWhpSession,
    exec_id: u32,
    stream: StreamName,
    credits: u32,
) -> Result<(), String> {
    session
        .client
        .send_flow_credits(FlowCreditRequest {
            exec_id,
            stream,
            credits,
        })
        .map(|_| ())
        .map_err(|error| format!("granting {stream:?} credits for exec {exec_id} failed: {error}"))
}

#[cfg(windows)]
fn expect_error_after_send(
    session: &mut LiveWhpSession,
    message: HostControlMessage,
    timeout: Duration,
) -> Result<ProtocolErrorDetail, String> {
    session
        .client
        .send_host_control(message)
        .map_err(|error| format!("sending host control message failed: {error}"))?;
    expect_protocol_error(session, timeout)
}

#[cfg(windows)]
fn expect_protocol_error(
    session: &mut LiveWhpSession,
    timeout: Duration,
) -> Result<ProtocolErrorDetail, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll = remaining.min(Duration::from_millis(250));
        match session.client.recv_agent_control(poll) {
            Ok(AgentControlMessage::Error(detail)) => return Ok(detail),
            Ok(AgentControlMessage::StdoutChunk(record)) => {
                let _ = grant_stream(session, record.exec_id, StreamName::Stdout, 1);
            }
            Ok(AgentControlMessage::StderrChunk(record)) => {
                let _ = grant_stream(session, record.exec_id, StreamName::Stderr, 1);
            }
            Ok(_) => {}
            Err(ClientError::Timeout(_)) => {}
            Err(error) => return Err(format!("waiting for protocol error failed: {error}")),
        }
    }
    Err("timed out waiting for protocol error response".to_string())
}

#[cfg(windows)]
fn collect_exec_until_terminal(
    session: &mut LiveWhpSession,
    exec_id: u32,
    timeout: Duration,
    auto_credit: bool,
) -> Result<ExecObservation, String> {
    let deadline = Instant::now() + timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut messages = Vec::new();
    let mut disposition = None;
    let mut termination = None;
    let mut stdout_chunk_max = 0_usize;
    let mut stderr_chunk_max = 0_usize;
    while Instant::now() < deadline {
        let poll = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        let message = match session.client.recv_agent_control(poll) {
            Ok(value) => value,
            Err(ClientError::Timeout(_)) => continue,
            Err(error) => return Err(format!("receiving exec {exec_id} output failed: {error}")),
        };
        match message {
            AgentControlMessage::StdoutChunk(record) => {
                if record.exec_id == exec_id {
                    stdout_chunk_max = stdout_chunk_max.max(record.chunk.len());
                    stdout.extend_from_slice(&record.chunk);
                }
                if auto_credit {
                    let _ = grant_stream(session, record.exec_id, StreamName::Stdout, 1);
                }
                messages.push(AgentControlMessage::StdoutChunk(record));
            }
            AgentControlMessage::StderrChunk(record) => {
                if record.exec_id == exec_id {
                    stderr_chunk_max = stderr_chunk_max.max(record.chunk.len());
                    stderr.extend_from_slice(&record.chunk);
                }
                if auto_credit {
                    let _ = grant_stream(session, record.exec_id, StreamName::Stderr, 1);
                }
                messages.push(AgentControlMessage::StderrChunk(record));
            }
            AgentControlMessage::StdoutEof(record) => {
                messages.push(AgentControlMessage::StdoutEof(record));
            }
            AgentControlMessage::StderrEof(record) => {
                messages.push(AgentControlMessage::StderrEof(record));
            }
            AgentControlMessage::DescendantsCleaned { exec_id: cleaned } => {
                messages.push(AgentControlMessage::DescendantsCleaned { exec_id: cleaned });
            }
            AgentControlMessage::ExecTerminal {
                exec_id: terminal_exec_id,
                disposition: terminal_disposition,
                termination: terminal_termination,
            } => {
                messages.push(AgentControlMessage::ExecTerminal {
                    exec_id: terminal_exec_id,
                    disposition: terminal_disposition,
                    termination: terminal_termination,
                });
                if terminal_exec_id == exec_id {
                    disposition = Some(terminal_disposition);
                    termination = terminal_termination;
                    break;
                }
            }
            AgentControlMessage::Error(detail) => {
                return Err(format!(
                    "exec {exec_id} observed protocol error {:?}: {}",
                    detail.code, detail.message
                ));
            }
            other => {
                messages.push(other);
            }
        }
    }
    if disposition.is_none() {
        return Err(format!(
            "timed out waiting for terminal disposition for exec {exec_id}"
        ));
    }
    Ok(ExecObservation {
        stdout,
        stderr,
        messages,
        disposition,
        termination,
        stdout_chunk_max,
        stderr_chunk_max,
    })
}

#[cfg(windows)]
fn terminal_order_ok(
    messages: &[AgentControlMessage],
    exec_id: u32,
    expected: ExecDisposition,
    expected_termination: Option<TerminationOutcome>,
) -> bool {
    let terminal_positions: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter_map(|(index, message)| match message {
            AgentControlMessage::ExecTerminal {
                exec_id: id,
                disposition,
                termination,
            } if *id == exec_id
                && *disposition == expected
                && *termination == expected_termination =>
            {
                Some(index)
            }
            _ => None,
        })
        .collect();
    if terminal_positions.len() != 1 {
        return false;
    }
    let terminal = terminal_positions[0];
    let stdout_eof = messages
        .iter()
        .position(|message| matches!(message, AgentControlMessage::StdoutEof(record) if record.exec_id == exec_id));
    let stderr_eof = messages
        .iter()
        .position(|message| matches!(message, AgentControlMessage::StderrEof(record) if record.exec_id == exec_id));
    let cleaned = messages
        .iter()
        .position(|message| matches!(message, AgentControlMessage::DescendantsCleaned { exec_id: id } if *id == exec_id));
    stdout_eof.is_some_and(|index| index < terminal)
        && stderr_eof.is_some_and(|index| index < terminal)
        && cleaned.is_some_and(|index| index < terminal)
}

fn pass_check(evidence: Vec<String>) -> CheckOutcome {
    CheckOutcome {
        check_status: EvidenceCheckStatus::Pass,
        evidence_source: EvidenceSource::LiveWhp,
        error: None,
        evidence,
    }
}

fn blocked_check(error: String) -> CheckOutcome {
    CheckOutcome {
        check_status: EvidenceCheckStatus::NotRun,
        evidence_source: EvidenceSource::None,
        error: Some(error),
        evidence: vec![],
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn safe_remove_dir_refuses_paths_outside_output_root() {
        let output = std::env::temp_dir().join("agent-harness-safe-remove-root");
        let outside = std::env::temp_dir().join("agent-harness-safe-remove-outside");
        let _ = fs::create_dir_all(&output);
        let _ = fs::create_dir_all(&outside);
        let result = safe_remove_dir(&outside, &output);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("outside removal must fail")
                .contains("outside harness output directory")
        );
        let _ = fs::remove_dir_all(&output);
        let _ = fs::remove_dir_all(&outside);
    }
}
