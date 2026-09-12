use std::collections::BTreeMap;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::net::{IpAddr, TcpListener};
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::client::{ClientError, MxcAgentClient};
use crate::launch::{LaunchedVm, build_launch_plan, discover_artifacts, launch_whp_vm};
#[cfg(windows)]
use crate::mxc_policy::{NvxProvisionPolicy, adapt_policy};
use crate::{
    CANONICAL_SCENARIOS, CheckOutcome, EvidenceCheckStatus, EvidenceSource, HarnessOptions,
    ScenarioDefinition,
};
#[cfg(windows)]
use crate::{
    control_session::{HostAttachStatus, HostControlSession, HostEvent, SessionError},
    named_pipe::NamedPipeClient,
};
#[cfg(windows)]
use agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
#[cfg(windows)]
use agent_protocol::messages::{
    AgentControlMessage, CapabilityProofMaterial, ExecDisposition, FlowCreditRequest,
    HostControlMessage, LaunchIdentity, NetworkMode, NetworkSetupState, NetworkStatus,
    ProtocolErrorCode, ProtocolErrorDetail, ReadyStatus, SERVICE_IDENTITY, StdinChunkRecord,
    StdinEofRecord, StreamName, TerminationOutcome, WORKLOAD_GID_MXC, WORKLOAD_GROUP_MXC,
    WORKLOAD_UID_MXC, WORKLOAD_USER_MXC,
};
#[cfg(windows)]
use agent_protocol::{
    MAX_SHUTDOWN_GRACE_TIMEOUT_MS, PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES, PROTOCOL_VERSION,
};
#[cfg(windows)]
use serde::Deserialize;

const LIVE_TIMEOUT: Duration = Duration::from_secs(8);
#[cfg(windows)]
const PROBE_PATH: &str = "/sbin/nvx-agent-probe";
#[cfg(windows)]
const TREE_PID_CAPTURE_MAX_BYTES: usize = 8 * 1024;
#[cfg(windows)]
const TREE_PID_CAPTURE_MAX_MESSAGES: usize = 256;
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
#[cfg(windows)]
const SHUTDOWN_VALIDATION_GRACE_MS: u64 = 1200;
#[cfg(windows)]
const SHUTDOWN_VALIDATION_GRACE_TOLERANCE_MS: u64 = 500;

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
    auxiliary_launches_started: u32,
    auxiliary_launches_torn_down: u32,
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
#[derive(Debug, Deserialize)]
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
    open_fds: Vec<ProbeFdEntry>,
}

#[cfg(windows)]
#[derive(Clone, Debug, Deserialize)]
struct ProbeFdEntry {
    fd: i32,
    target: String,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct ProbeProcIdentity {
    uid: Option<u32>,
    gid: Option<u32>,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct ProbeCapabilities {
    all_zero: bool,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
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
#[derive(Debug)]
struct ExecObservation {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    messages: Vec<AgentControlMessage>,
    disposition: Option<ExecDisposition>,
    termination: Option<TerminationOutcome>,
    stdout_chunk_max: usize,
    stderr_chunk_max: usize,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct ExecCollectionLimits {
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    max_total_bytes: usize,
    max_messages: usize,
    max_duration: Duration,
}

#[cfg(windows)]
impl ExecCollectionLimits {
    fn small_probe(timeout: Duration) -> Self {
        Self {
            max_stdout_bytes: 128 * 1024,
            max_stderr_bytes: 64 * 1024,
            max_total_bytes: 160 * 1024,
            max_messages: 256,
            max_duration: timeout,
        }
    }

    fn tree_probe(timeout: Duration) -> Self {
        Self {
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
            max_total_bytes: 96 * 1024,
            max_messages: 384,
            max_duration: timeout,
        }
    }

    fn flood_probe(timeout: Duration, expected_stdout_bytes: usize) -> Self {
        Self {
            max_stdout_bytes: expected_stdout_bytes.saturating_add(4096),
            max_stderr_bytes: 64 * 1024,
            max_total_bytes: expected_stdout_bytes.saturating_add(96 * 1024),
            max_messages: 2048,
            max_duration: timeout,
        }
    }
}

static LIVE_STATE: OnceLock<Mutex<LiveHarnessState>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct PolicyLiveEvidence {
    pub positive_passed: bool,
    pub negative_passed: bool,
    pub blocked: bool,
    pub evidence: Vec<String>,
    pub error: Option<String>,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct PolicyNetworkReport {
    non_loopback_interfaces: Vec<String>,
    has_default_route: bool,
    dns_servers: Vec<String>,
    outbound_connect_succeeded: Option<bool>,
}

#[cfg(windows)]
pub(crate) fn run_live_policy_process_profiles(
    options: &HarnessOptions,
) -> BTreeMap<String, PolicyLiveEvidence> {
    let mut results = BTreeMap::new();
    results.insert(
        "filesystem-rw-ro".to_string(),
        run_policy_profile_with_session(options, run_policy_filesystem_contract),
    );
    results.insert(
        "process-shell".to_string(),
        run_policy_profile_with_session(options, run_policy_shell_contract),
    );
    results.insert(
        "proxy-environment".to_string(),
        run_policy_profile_with_session(options, run_policy_proxy_contract),
    );
    results.insert(
        "control-lifecycle".to_string(),
        run_policy_profile_with_session(options, run_policy_control_lifecycle_contract),
    );
    results
}

#[cfg(windows)]
fn run_policy_profile_with_session(
    options: &HarnessOptions,
    check: fn(&mut LiveHarnessState) -> PolicyLiveEvidence,
) -> PolicyLiveEvidence {
    let mut state = fresh_policy_live_state();
    let init = (|| -> Result<(), String> {
        ensure_live_initialized(&mut state, options)
            .map_err(|error| format!("live WHP bootstrap failed: {error}"))?;
        ensure_policy_probe_capabilities(&mut state)
    })();
    let mut result = match init {
        Ok(()) => check(&mut state),
        Err(error) => policy_live_result_from_error(error),
    };
    if let Err(teardown_error) = teardown_live_session(&mut state) {
        append_policy_teardown_failure(&mut result, teardown_error);
    }
    result
}

#[cfg(windows)]
fn run_with_policy_live_session<T>(
    options: &HarnessOptions,
    check: impl FnOnce(&mut LiveHarnessState) -> Result<T, String>,
) -> Result<T, String> {
    let mut state = fresh_policy_live_state();
    let run = (|| -> Result<T, String> {
        ensure_live_initialized(&mut state, options)
            .map_err(|error| format!("live WHP bootstrap failed: {error}"))?;
        ensure_policy_probe_capabilities(&mut state)?;
        check(&mut state)
    })();
    let teardown = teardown_live_session(&mut state);
    merge_with_teardown(run, teardown)
}

#[cfg(windows)]
fn merge_with_teardown<T>(
    run: Result<T, String>,
    teardown: Result<(), String>,
) -> Result<T, String> {
    match (run, teardown) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(teardown_error)) => Err(format!("teardown failed: {teardown_error}")),
        (Err(error), Err(teardown_error)) => {
            Err(format!("{error}; teardown failed: {teardown_error}"))
        }
    }
}

#[cfg(windows)]
fn append_policy_teardown_failure(result: &mut PolicyLiveEvidence, teardown_error: String) {
    let prefix = result
        .error
        .clone()
        .unwrap_or_else(|| "profile assertions completed".to_string());
    let teardown_text = format!("teardown failed: {teardown_error}");
    result.positive_passed = false;
    result.negative_passed = false;
    result.blocked = false;
    result.error = Some(format!("{prefix}; {teardown_text}"));
}

#[cfg(windows)]
pub(crate) fn run_live_policy_network_profile(options: &HarnessOptions) -> PolicyLiveEvidence {
    let mut positive_evidence = Vec::new();
    let positive = (|| {
        let listener = TcpListener::bind("0.0.0.0:0")
            .map_err(|error| format!("controlled outbound listener bind failed: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("controlled listener nonblocking failed: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("controlled listener address failed: {error}"))?
            .port();
        let acceptor = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => return true,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return false,
                }
            }
            false
        });
        let mut allow_options = options.clone();
        allow_options.output_dir = options.output_dir.join("network-allow-profile");
        let mut allow_overrides = allow_options.launch_overrides.clone().unwrap_or_default();
        let allow_root = allow_options.output_dir.join("common-root");
        allow_overrides.common_root = Some(allow_root.clone());
        let allow_provision = adapt_live_provision_policy(
            "policy-live-network-allow",
            &allow_root,
            serde_json::json!({
                "allowedHosts": ["10.0.0.1"],
                "defaultPolicy": "allow"
            }),
        )?;
        allow_overrides.portable_network =
            portable_network_override_from_provision(&allow_provision)?;
        allow_options.launch_overrides = Some(allow_overrides);
        let endpoint = format!("10.0.0.1:{port}");
        let allow_report = run_with_policy_live_session(&allow_options, |state| {
            run_network_probe(state, 1_322, Some(&endpoint))
        })?;
        let accepted = acceptor
            .join()
            .map_err(|_| "controlled outbound listener thread panicked".to_string())?;
        if allow_report.non_loopback_interfaces.is_empty()
            || !allow_report.has_default_route
            || allow_report.dns_servers.is_empty()
            || allow_report.outbound_connect_succeeded != Some(true)
            || !accepted
        {
            return Err(format!(
                "allow/default-allow network probe failed: report={allow_report:?} hostAccepted={accepted}"
            ));
        }
        positive_evidence.push(format!(
            "defaultPolicy=allow (allowedHosts set) produced portable network and reached controlled host endpoint {endpoint}"
        ));
        Ok(())
    })();

    let mut negative_evidence = Vec::new();
    let negative = (|| {
        let mut block_options = options.clone();
        block_options.output_dir = options.output_dir.join("network-block-profile");
        let mut block_overrides = block_options.launch_overrides.clone().unwrap_or_default();
        let block_root = block_options.output_dir.join("common-root");
        block_overrides.common_root = Some(block_root.clone());
        let block_provision = adapt_live_provision_policy(
            "policy-live-network-block",
            &block_root,
            serde_json::json!({
                "blockedHosts": ["10.0.0.1"],
                "defaultPolicy": "block"
            }),
        )?;
        block_overrides.portable_network =
            portable_network_override_from_provision(&block_provision)?;
        block_options.launch_overrides = Some(block_overrides);
        let block_report = run_with_policy_live_session(&block_options, |state| {
            run_network_probe(state, 1_321, Some("192.0.2.1:9"))
        })?;
        if !block_report.non_loopback_interfaces.is_empty()
            || block_report.has_default_route
            || !block_report.dns_servers.is_empty()
            || block_report.outbound_connect_succeeded != Some(false)
        {
            return Err(format!(
                "defaultPolicy=block negative probe failed: {block_report:?}"
            ));
        }
        negative_evidence.push(
            "defaultPolicy=block (blockedHosts set) produced no-NIC posture and rejected outbound connect"
                .to_string(),
        );

        let mut absent_options = options.clone();
        absent_options.output_dir = options.output_dir.join("network-default-absent-profile");
        let mut absent_overrides = absent_options.launch_overrides.clone().unwrap_or_default();
        let absent_root = absent_options.output_dir.join("common-root");
        absent_overrides.common_root = Some(absent_root.clone());
        let absent_provision = adapt_live_provision_policy(
            "policy-live-network-default-absent",
            &absent_root,
            serde_json::json!({
                "allowedHosts": ["10.0.0.1"]
            }),
        )?;
        absent_overrides.portable_network =
            portable_network_override_from_provision(&absent_provision)?;
        absent_options.launch_overrides = Some(absent_overrides);
        let absent_report = run_with_policy_live_session(&absent_options, |state| {
            run_network_probe(state, 1_323, Some("192.0.2.1:9"))
        })?;
        if !absent_report.non_loopback_interfaces.is_empty()
            || absent_report.has_default_route
            || !absent_report.dns_servers.is_empty()
            || absent_report.outbound_connect_succeeded != Some(false)
        {
            return Err(format!(
                "defaultPolicy absent negative probe failed: {absent_report:?}"
            ));
        }
        negative_evidence.push(
            "defaultPolicy absent remained non-portable (no-NIC) and rejected outbound connect"
                .to_string(),
        );
        Ok(())
    })();

    policy_live_assertions(
        positive,
        negative,
        [positive_evidence, negative_evidence].concat(),
    )
}

#[cfg(not(windows))]
pub(crate) fn run_live_policy_network_profile(_options: &HarnessOptions) -> PolicyLiveEvidence {
    PolicyLiveEvidence {
        positive_passed: false,
        negative_passed: false,
        blocked: true,
        evidence: Vec::new(),
        error: Some("live WHP policy profiles require Windows".to_string()),
    }
}

#[cfg(not(windows))]
pub(crate) fn run_live_policy_process_profiles(
    _options: &HarnessOptions,
) -> BTreeMap<String, PolicyLiveEvidence> {
    [
        "filesystem-rw-ro",
        "process-shell",
        "proxy-environment",
        "control-lifecycle",
    ]
    .into_iter()
    .map(|id| {
        (
            id.to_string(),
            PolicyLiveEvidence {
                positive_passed: false,
                negative_passed: false,
                blocked: true,
                evidence: Vec::new(),
                error: Some("live WHP policy profiles require Windows".to_string()),
            },
        )
    })
    .collect()
}

#[cfg(windows)]
fn fresh_policy_live_state() -> LiveHarnessState {
    LiveHarnessState {
        run_key: None,
        init_error: None,
        first_failure: None,
        req1_evidence: Vec::new(),
        session: None,
    }
}

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
    run_live_requirement_in_state(
        &mut guard,
        options,
        definition,
        &mut ensure_live_initialized,
        &mut run_requirement_check,
        &mut teardown_live_session,
    )
}

fn run_live_requirement_in_state<FInit, FRun, FTeardown>(
    guard: &mut LiveHarnessState,
    options: &HarnessOptions,
    definition: ScenarioDefinition,
    ensure_initialized: &mut FInit,
    run_requirement: &mut FRun,
    teardown: &mut FTeardown,
) -> CheckOutcome
where
    FInit: FnMut(&mut LiveHarnessState, &HarnessOptions) -> Result<(), String>,
    FRun: FnMut(&mut LiveHarnessState, ScenarioDefinition) -> CheckOutcome,
    FTeardown: FnMut(&mut LiveHarnessState) -> Result<(), String>,
{
    if let Some((failed_req, reason)) = guard.first_failure.clone()
        && definition.requirement_number > failed_req
    {
        return blocked_check(format!(
            "blocked: skipped after req{:02} failed in same live session ({reason})",
            failed_req
        ));
    }

    if let Err(error) = ensure_initialized(guard, options) {
        guard.init_error = Some(error.clone());
        let combined = record_first_failure_and_teardown(
            guard,
            definition.requirement_number,
            format!("launch/bootstrap failed: {error}"),
            teardown,
        );
        if definition.requirement_number > 1 {
            return blocked_check(format!(
                "blocked after launch/bootstrap failure: {combined}"
            ));
        }
        return fail_check(combined);
    }

    let outcome = run_requirement(guard, definition);

    if outcome.check_status != EvidenceCheckStatus::Pass && guard.first_failure.is_none() {
        let reason = outcome
            .error
            .clone()
            .unwrap_or_else(|| "scenario check did not pass".to_string());
        let combined = record_first_failure_and_teardown(
            guard,
            definition.requirement_number,
            reason,
            teardown,
        );
        return fail_check(combined);
    }

    if outcome.check_status == EvidenceCheckStatus::Pass
        && is_last_canonical_scenario(definition)
        && let Err(error) = teardown(guard)
    {
        let combined = format!(
            "req{:02} pass evidence collected but final teardown failed: {error}",
            definition.requirement_number
        );
        guard.first_failure = Some((definition.requirement_number, combined.clone()));
        return fail_check(combined);
    }

    outcome
}

fn run_requirement_check(
    guard: &mut LiveHarnessState,
    definition: ScenarioDefinition,
) -> CheckOutcome {
    match definition.requirement_number {
        1 => pass_check(guard.req1_evidence.clone()),
        2 => run_req2_immutable_config(guard),
        3 => run_req3_repeated_exec(guard),
        4 => run_req4_streams(guard),
        5 => run_req5_backpressure(guard),
        6 => run_req6_terminal_semantics(guard),
        7 => run_req7_fixed_mxc_identity(guard),
        8 => run_req8_full_isolation_verification(guard),
        9 => run_req9_mapping_containment(guard),
        10 => run_req10_network_status(guard),
        11 => run_req11_health_quiesce_resume_shutdown(guard),
        12 => run_req12_channel_loss_generation(guard),
        _ => fail_check("unknown requirement number".to_string()),
    }
}

fn is_last_canonical_scenario(definition: ScenarioDefinition) -> bool {
    CANONICAL_SCENARIOS
        .last()
        .is_some_and(|scenario| scenario.requirement_number == definition.requirement_number)
}

fn record_first_failure_and_teardown(
    guard: &mut LiveHarnessState,
    requirement_number: u8,
    reason: String,
    teardown: &mut impl FnMut(&mut LiveHarnessState) -> Result<(), String>,
) -> String {
    let teardown_failure = teardown(guard)
        .err()
        .map(|error| format!("; teardown failed: {error}"))
        .unwrap_or_default();
    let combined = format!("{reason}{teardown_failure}");
    if guard.first_failure.is_none() {
        guard.first_failure = Some((requirement_number, combined.clone()));
    }
    combined
}

fn reset_state(state: &mut LiveHarnessState) {
    state.init_error = None;
    state.first_failure = None;
    state.req1_evidence.clear();
    if let Err(error) = teardown_live_session(state) {
        state.init_error = Some(format!("live session teardown failed: {error}"));
    }
}

fn teardown_live_session(state: &mut LiveHarnessState) -> Result<(), String> {
    let mut failures = Vec::new();
    #[cfg(windows)]
    if let Some(mut session) = state.session.take()
        && let Err(error) = session.vm.kill()
    {
        failures.push(format!("live session VM teardown failed: {error}"));
    }
    #[cfg(not(windows))]
    if let Some(mut vm) = state.vm.take()
        && let Err(error) = vm.kill()
    {
        failures.push(format!("live session VM teardown failed: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
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
        let req9_mappings = req9_legitimate_mappings(&common_root)?;
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
            auxiliary_launches_started: 0,
            auxiliary_launches_torn_down: 0,
            baseline_ready: ready_status,
            baseline_health: health_status,
        });
        Ok(())
    }
}

#[cfg(windows)]
fn req9_legitimate_mappings(common_root: &Path) -> Result<Vec<ChildMapping>, String> {
    let provision = adapt_live_provision_policy(
        "policy-live-provision-mappings",
        common_root,
        serde_json::Value::Null,
    )?;
    Ok(provision.mappings)
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
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        use std::os::windows::fs::MetadataExt;

        let metadata = fs::symlink_metadata(link).map_err(|error| {
            format!(
                "failed to inspect existing reparse fixture link {}: {error}",
                link.display()
            )
        })?;
        let remove_result = if metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
            fs::remove_dir(link)
        } else {
            fs::remove_file(link)
        };
        remove_result.map_err(|error| {
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

    let health_after = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => status,
        Ok(other) => return fail_check(format!("health returned unexpected message: {other:?}")),
        Err(error) => return fail_check(format!("health after req2 checks failed: {error}")),
    };
    let unchanged = health_after == session.baseline_health;
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
            "initial Ready attestation and fresh health snapshot remained unchanged after all rejected req2 mutations (including network and fixed identity fields)".to_string(),
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
    let first = match collect_exec_until_terminal(
        session,
        exec1,
        Duration::from_secs(10),
        true,
        ExecCollectionLimits::small_probe(Duration::from_secs(10)),
    ) {
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
        fail_check(format!(
            "repeated exec invariants failed: busy_typed={busy_typed} busy_side_effect_free={busy_side_effect_free} reuse_typed={reuse_typed} first={first:?} run_two={run_two:?} run_three={run_three:?} reuse_detail={reuse_detail:?}"
        ))
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
    let observed = match collect_exec_until_terminal(
        session,
        exec_id,
        LIVE_TIMEOUT,
        true,
        ExecCollectionLimits::small_probe(LIVE_TIMEOUT),
    ) {
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
    let observed = match collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(20),
        true,
        ExecCollectionLimits::flood_probe(Duration::from_secs(20), target_bytes),
    ) {
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
    let stdin_observed = match collect_exec_until_terminal(
        session,
        stdin_exec,
        Duration::from_secs(10),
        true,
        ExecCollectionLimits::small_probe(Duration::from_secs(10)),
    ) {
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
        && supplementary_groups_are_empty(&identity.supplementary_gids);
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
            "identity remained non-root and supplementary groups were empty".to_string(),
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
        return fail_check(format!(
            "isolation probe execution failed: disposition={disposition:?} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ));
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
    let fd_allowlist_ok = workload_fd_allowlist_ok(&report.open_fds);
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
        && fd_allowlist_ok
        && normal_cleanup_ok
        && cancel_cleanup_ok
        && timeout_cleanup_ok
    {
        pass_check(vec![
            "live probe confirmed private pid/mount/uts/ipc namespaces, private proc/dev/devpts/shm, read-only /sys, no_new_privs, and zero capability sets".to_string(),
            "workload fd table was exact-safe allowlist (only fds 0/1/2 with expected stdio targets)".to_string(),
            "host OpenVMM pid was not visible in guest /proc and raw virtio-fs export remained hidden behind declared mappings".to_string(),
            "child+grandchild workload trees were cleaned after normal exit, cancellation, and timeout paths".to_string(),
        ])
    } else {
        fail_check(format!(
            "full isolation live verification failed: core={core_isolation_ok} probe={probe_isolation_ok} fd_allowlist={fd_allowlist_ok} normal_cleanup={normal_cleanup_ok} cancel_cleanup={cancel_cleanup_ok} timeout_cleanup={timeout_cleanup_ok} report={report:?}"
        ))
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
    session.auxiliary_launches_started = session.auxiliary_launches_started.saturating_add(1);
    let validation_result = run_req9_validation_session(session);
    session.auxiliary_launches_torn_down = session.auxiliary_launches_torn_down.saturating_add(1);
    let validation_checks = match validation_result {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let expected_rw_output_path = format!("{rw_guest_dir}/guest-rw.bin");

    if report.rw_output_path == expected_rw_output_path
        && report.rw_bytes_hex == host_rw_hex
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
            format!(
                "auxiliary validation launches tracked: started={}, torn_down={}",
                session.auxiliary_launches_started, session.auxiliary_launches_torn_down
            ),
        ])
    } else {
        fail_check(format!(
            "mapping containment checks failed: report={report:?} host_rw_match={} host_ro_match={} shared_mutation_rejected={shared_mutation_rejected} fixture_consistent={fixture_consistent} validation_checks={validation_checks}",
            report.rw_bytes_hex == host_rw_hex,
            report.ro_seed_hex == host_ro_seed_hex,
        ))
    }
}

#[cfg(windows)]
fn run_req10_network_status(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let ready = session.baseline_ready.clone();
    let health = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => status,
        Ok(other) => {
            return fail_check(format!(
                "req10 health returned unexpected message: {other:?}"
            ));
        }
        Err(error) => return fail_check(format!("req10 health request failed: {error}")),
    };
    let Some(health_network) = health.network.clone() else {
        return fail_check("req10 health omitted network status".to_string());
    };
    if ready.network != health_network {
        return fail_check(format!(
            "req10 network mismatch between wait_ready and health (ready={:?}, health={:?})",
            ready.network, health_network
        ));
    }
    let mode_evidence = match validate_live_network_status(&ready.network) {
        Ok(line) => line,
        Err(error) => return fail_check(format!("req10 network validation failed: {error}")),
    };
    pass_check(vec![
        "validated req10 using runtime-emitted WaitReady/Health NetworkStatus (no host-constructed status)".to_string(),
        mode_evidence,
        "live req10 attestation reflects only the observed launch mode; malformed/missing portable-network fixtures are not attested unless directly observed in live launch".to_string(),
    ])
}

#[cfg(windows)]
fn run_req11_health_quiesce_resume_shutdown(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let exec_id = 1_101_u32;
    if let Err(error) = start_probe_exec(
        session,
        exec_id,
        &[
            "flood", "--stream", "stdout", "--bytes", "131072", "--chunk", "4096",
        ],
        None,
    ) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stderr, 1) {
        return fail_check(error);
    }
    let health_started = Instant::now();
    let health = match session
        .client
        .request_health_observing_inbound(LIVE_TIMEOUT, |message| match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                Err(ClientError::Protocol(format!(
                    "req11 observed stdout for exec {exec_id} before credits were granted"
                )))
            }
            _ => Ok(()),
        }) {
        Ok(AgentControlMessage::Health(status)) => status,
        Ok(AgentControlMessage::Error(detail)) => {
            return fail_check(format!(
                "req11 health request returned protocol error {:?}: {}",
                detail.code, detail.message
            ));
        }
        Ok(other) => {
            return fail_check(format!(
                "req11 health returned unexpected message: {other:?}"
            ));
        }
        Err(error) => return fail_check(format!("req11 health request failed: {error}")),
    };
    let health_elapsed = health_started.elapsed();
    let health_ok = health.launch_admitted
        && health.filesystem.is_some()
        && health.network.is_some()
        && health.active_exec_id == Some(exec_id)
        && health.channel_generation == session.vm.plan.channel_generation;
    let active_quiesce_rejected = match session.client.request_quiesce(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Error(detail)) => {
            detail.code == ProtocolErrorCode::InvalidLifecycleTransition
                || detail.code == ProtocolErrorCode::ActiveExecExists
                || detail.message.contains("active")
        }
        Ok(_) => false,
        Err(_) => false,
    };
    if let Err(error) = session.client.send_cancel_execution(exec_id) {
        return fail_check(format!("req11 cancel active exec failed: {error}"));
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stdout, 1) {
        return fail_check(format!(
            "req11 stdout credit recovery after cancellation failed: {error}"
        ));
    }
    let cancelled = match collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(12),
        true,
        ExecCollectionLimits::flood_probe(Duration::from_secs(12), 131_072),
    ) {
        Ok(obs) => {
            obs.disposition == Some(ExecDisposition::Cancelled)
                || obs.disposition == Some(ExecDisposition::ExitCode(0))
        }
        Err(error) => return fail_check(error),
    };
    let idle_quiesce_ok = matches!(
        session.client.request_quiesce(LIVE_TIMEOUT),
        Ok(AgentControlMessage::Quiesced)
    );
    if !idle_quiesce_ok {
        return fail_check("req11 idle quiesce did not succeed".to_string());
    }
    let quiesced_exec_attempt =
        start_probe_exec(session, 1_102, &["seq", "--token", "blocked"], None)
            .and_then(|_| expect_protocol_error(session, LIVE_TIMEOUT));
    let quiesced_exec_rejected = matches!(
        quiesced_exec_attempt,
        Ok(ProtocolErrorDetail {
            code: ProtocolErrorCode::LaunchQuiesced | ProtocolErrorCode::InvalidLifecycleTransition,
            ..
        })
    );
    let resumed = matches!(
        session.client.request_resume(LIVE_TIMEOUT),
        Ok(AgentControlMessage::Resumed)
    );
    if !resumed {
        return fail_check("req11 resume did not succeed".to_string());
    }
    let post_resume_exec_ok = matches!(run_simple_probe_exec(session, 1_103, &["seq", "--token", "resume-ok", "--exit", "0"]), Ok((ExecDisposition::ExitCode(0), ref out, _)) if out == b"seq:resume-ok\n");

    let shutdown_validation = match run_req11_shutdown_validation_session(session) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    if health_ok
        && health_elapsed <= LIVE_TIMEOUT
        && active_quiesce_rejected
        && cancelled
        && quiesced_exec_rejected
        && post_resume_exec_ok
        && shutdown_validation
    {
        pass_check(vec![
            format!(
                "health remained responsive under output/backpressure activity (elapsed {:?}) and reported active exec {} with channel_generation={}",
                health_elapsed, exec_id, session.vm.plan.channel_generation
            ),
            "active quiesce was rejected; once idle, quiesce succeeded, blocked new exec admission, then resume restored execution".to_string(),
            format!(
                "dedicated shutdown-validation VM rejected grace=0 and grace>{} with exact validation errors, then acknowledged shutdown and closed the guest control channel within one absolute {}±{}ms cleanup budget",
                MAX_SHUTDOWN_GRACE_TIMEOUT_MS,
                SHUTDOWN_VALIDATION_GRACE_MS,
                SHUTDOWN_VALIDATION_GRACE_TOLERANCE_MS
            ),
            format!(
                "auxiliary validation launches tracked: started={}, torn_down={}",
                session.auxiliary_launches_started, session.auxiliary_launches_torn_down
            ),
        ])
    } else {
        fail_check(format!(
            "req11 invariants failed: health_ok={health_ok} health_elapsed={health_elapsed:?} active_quiesce_rejected={active_quiesce_rejected} cancelled={cancelled} quiesced_exec_rejected={quiesced_exec_rejected} post_resume_exec_ok={post_resume_exec_ok} shutdown_validation={shutdown_validation}"
        ))
    }
}

#[cfg(windows)]
fn run_req12_channel_loss_generation(state: &mut LiveHarnessState) -> CheckOutcome {
    let Some(session) = state.session.as_mut() else {
        return fail_check("live session unavailable".to_string());
    };
    let old_launch = session.launch;
    let exec_id = 1_201_u32;
    let stale_flow_exec_id = 1_298_u32;
    let stale_stdin_exec_id = 1_299_u32;
    let queued_output_bytes = 131_072_u64;
    if let Err(error) = start_probe_exec(
        session,
        exec_id,
        &[
            "spawn-tree",
            "--hold-ms",
            "30000",
            "--stdout-bytes",
            &queued_output_bytes.to_string(),
            "--stdout-chunk",
            "4096",
        ],
        None,
    ) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stdout, 1) {
        return fail_check(error);
    }
    if let Err(error) = grant_stream(session, exec_id, StreamName::Stderr, 1) {
        return fail_check(error);
    }
    let mut output = Vec::new();
    let mut observed_messages = 0_usize;
    let pid_deadline = Instant::now() + Duration::from_secs(8);
    let tree_pids = loop {
        if Instant::now() >= pid_deadline {
            return fail_check("req12 timed out waiting for child+grandchild PID line".to_string());
        }
        let message = match session
            .client
            .recv_agent_control(Duration::from_millis(250))
        {
            Ok(value) => value,
            Err(ClientError::Timeout(_)) => continue,
            Err(error) => {
                return fail_check(format!("req12 waiting for tree line failed: {error}"));
            }
        };
        match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                if let Err(error) = enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    record.chunk.len(),
                ) {
                    return fail_check(error);
                }
                output.extend_from_slice(&record.chunk);
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
                let _ = grant_stream(session, exec_id, StreamName::Stdout, 1);
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                if let Err(error) = enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    0,
                ) {
                    return fail_check(error);
                }
                let _ = grant_stream(session, exec_id, StreamName::Stderr, 1);
            }
            _ => {}
        }
    };
    std::thread::sleep(Duration::from_millis(200));
    let queue_established = match session
        .client
        .request_health_observing_inbound(LIVE_TIMEOUT, |message| {
            if matches!(message, AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id)
            {
                return Err(ClientError::Protocol(format!(
                    "req12 observed stdout for exec {exec_id} while credits were withheld to establish queue/backpressure"
                )));
            }
            Ok(())
        }) {
        Ok(AgentControlMessage::Health(status)) => {
            status.active_exec_id == Some(exec_id)
                && status.channel_generation == session.vm.plan.channel_generation
        }
        Ok(other) => {
            return fail_check(format!(
                "req12 queue-establishment health returned unexpected message: {other:?}"
            ));
        }
        Err(error) => return fail_check(format!("req12 queue-establishment health failed: {error}")),
    };
    let reconnect_launch = LaunchIdentity {
        generation: old_launch.generation.saturating_add(1),
        nonce: next_launch_nonce(old_launch.nonce),
    };
    let reconnect = match reconnect_after_control_drop(session, old_launch, reconnect_launch) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let stale_launch_detail = match expect_error_after_send(
        session,
        HostControlMessage::Configure {
            launch: old_launch,
            root: session.root.clone(),
            mappings: session.req9_mappings.clone(),
            containment: session.containment,
        },
        LIVE_TIMEOUT,
    ) {
        Ok(detail) => detail,
        Err(error) => return fail_check(error),
    };
    let stale_launch_rejected = stale_launch_detail.code
        == ProtocolErrorCode::InvalidLifecycleTransition
        && stale_launch_detail.message.contains("ActiveLaunchExists")
        && stale_launch_detail
            .message
            .contains(&reconnect.new_launch.generation.to_string());
    let stale_flow_detail = match session.client.send_flow_credits(FlowCreditRequest {
        exec_id: stale_flow_exec_id,
        stream: StreamName::Stdout,
        credits: 1,
    }) {
        Ok(_) => match expect_protocol_error(session, LIVE_TIMEOUT) {
            Ok(detail) => detail,
            Err(error) => return fail_check(error),
        },
        Err(error) => return fail_check(format!("req12 stale flow send failed: {error}")),
    };
    let stale_flow_rejected = stale_flow_detail.code
        == ProtocolErrorCode::InvalidLifecycleTransition
        && stale_flow_detail.message.contains("UnknownExecId")
        && stale_flow_detail
            .message
            .contains(&stale_flow_exec_id.to_string());
    let stale_stdin_detail = match session.client.send_stdin_chunk(StdinChunkRecord {
        exec_id: stale_stdin_exec_id,
        sequence: 0,
        chunk: vec![1, 2, 3],
    }) {
        Ok(_) => match expect_protocol_error(session, LIVE_TIMEOUT) {
            Ok(detail) => detail,
            Err(error) => return fail_check(error),
        },
        Err(error) => return fail_check(format!("req12 stale stdin send failed: {error}")),
    };
    let stale_stdin_rejected = stale_stdin_detail.code
        == ProtocolErrorCode::InvalidLifecycleTransition
        && stale_stdin_detail.message.contains("no active exec")
        && stale_stdin_detail
            .message
            .contains(&stale_stdin_exec_id.to_string());
    let cleanup_health_ok = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => {
            status.launch_admitted
                && status.agent_state == agent_protocol::messages::AgentSessionState::Active
                && status.active_exec_id.is_none()
                && status.channel_generation == session.vm.plan.channel_generation
        }
        Ok(other) => {
            return fail_check(format!(
                "req12 post-reconnect cleanup health returned unexpected message: {other:?}"
            ));
        }
        Err(error) => {
            return fail_check(format!(
                "req12 post-reconnect cleanup health failed: {error}"
            ));
        }
    };
    let tree_gone = match run_pid_check(session, 1_202, tree_pids.child, tree_pids.grandchild) {
        Ok(value) => value,
        Err(error) => return fail_check(error),
    };
    let old_exec_reused_once = matches!(
        run_simple_probe_exec(session, exec_id, &["seq", "--token", "reuse-once", "--exit", "0"]),
        Ok((ExecDisposition::ExitCode(0), ref out, _)) if out == b"seq:reuse-once\n"
    );
    let same_generation_second_reuse_detail =
        match start_probe_exec(session, exec_id, &["seq", "--token", "reuse-twice"], None) {
            Ok(()) => match expect_protocol_error(session, LIVE_TIMEOUT) {
                Ok(detail) => detail,
                Err(error) => return fail_check(error),
            },
            Err(error) => return fail_check(error),
        };
    let same_generation_second_reuse_rejected = same_generation_second_reuse_detail.code
        == ProtocolErrorCode::InvalidLifecycleTransition
        && same_generation_second_reuse_detail
            .message
            .contains("ExecIdReusedInGeneration")
        && same_generation_second_reuse_detail
            .message
            .contains(&exec_id.to_string());
    let new_exec_ok = matches!(
        run_simple_probe_exec(session, 1_203, &["seq", "--token", "fresh", "--exit", "0"]),
        Ok((ExecDisposition::ExitCode(0), ref out, _)) if out == b"seq:fresh\n"
    );
    let generation_advanced = reconnect.new_launch.generation > old_launch.generation;
    if generation_advanced
        && queue_established
        && reconnect.replacement_connect_after_close
        && reconnect.ready_observed
        && reconnect.stale_generation_rejected
        && reconnect.same_previous_generation_rejected
        && reconnect.stale_capability_rejected
        && stale_launch_rejected
        && stale_flow_rejected
        && stale_stdin_rejected
        && cleanup_health_ok
        && tree_gone
        && old_exec_reused_once
        && same_generation_second_reuse_rejected
        && new_exec_ok
    {
        pass_check(vec![
            format!(
                "dropped authenticated control pipe during active output-producing child+grandchild exec (child={}, grandchild={}); queue/backpressure was established by withholding stdout credits while the workload emitted {} bytes",
                tree_pids.child, tree_pids.grandchild, queued_output_bytes
            ),
            format!(
                "reconnect closed prior control handle before replacement connect (ordered_close_connect={}); broker attach flow wait_seen={}, reset_seen={}, and admitted strictly newer launch generation {}",
                reconnect.replacement_connect_after_close,
                reconnect.wait_observed, reconnect.reset_observed, reconnect.new_launch.generation
            ),
            "before any new post-reconnect execution, stale HostHello/auth probes, stale configure, stale flow-credits/stdin records, and cleanup health(no active exec) checks each returned the exact correlated typed errors".to_string(),
            "after cleanup completion checks, pid-gone probe verified prior child/grandchild termination; then old exec id succeeded exactly once in the new generation, same-generation second reuse was rejected, and a new unique exec succeeded".to_string(),
        ])
    } else {
        fail_check(format!(
            "req12 channel-loss/reconnect generation invariants failed: generation_advanced={generation_advanced}, queue_established={queue_established}, ordered_reconnect={}, ready_observed={}, stale_generation_rejected={}, same_previous_generation_rejected={}, stale_capability_rejected={}, stale_launch_rejected={stale_launch_rejected}({:?}, {:?}), stale_flow_rejected={stale_flow_rejected}, stale_stdin_rejected={stale_stdin_rejected}({:?}, {:?}), cleanup_health_ok={cleanup_health_ok}, tree_gone={tree_gone}, old_exec_reused_once={old_exec_reused_once}, same_generation_second_reuse_rejected={same_generation_second_reuse_rejected}, new_exec_ok={new_exec_ok}",
            reconnect.replacement_connect_after_close,
            reconnect.ready_observed,
            reconnect.stale_generation_rejected,
            reconnect.same_previous_generation_rejected,
            reconnect.stale_capability_rejected,
            stale_launch_detail.code,
            stale_launch_detail.message,
            stale_stdin_detail.code,
            stale_stdin_detail.message,
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
    let mut stderr = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut observed_messages = 0_usize;
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
                observed_messages = observed_messages.saturating_add(1);
                enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    record.chunk.len(),
                )?;
                output.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stdout, 1)?;
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    0,
                )?;
                stderr.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stderr, 1)?;
            }
            AgentControlMessage::ExecTerminal {
                exec_id: terminal_exec_id,
                disposition,
                termination,
            } if terminal_exec_id == exec_id => {
                return Err(format!(
                    "exec {exec_id} terminated before tree pid line: disposition={disposition:?} termination={termination:?} stderr={}",
                    String::from_utf8_lossy(&stderr)
                ));
            }
            _ => {}
        }
    };
    let observed = collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(10),
        true,
        ExecCollectionLimits::tree_probe(Duration::from_secs(10)),
    )?;
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
    let checks = (|| -> Result<bool, String> {
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
        let traversal_rejected = traversal_detail.code
            == ProtocolErrorCode::InvalidLifecycleTransition
            && traversal_detail
                .message
                .contains("invalid host control payload");

        let symlink_error = expect_error_after_send_in(
            &mut client,
            HostControlMessage::Configure {
                launch,
                root: root.clone(),
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

        let overlap_error = expect_error_after_send_in(
            &mut client,
            HostControlMessage::Configure {
                launch,
                root,
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
        if traversal_rejected && overlap_rejected && symlink_rejected {
            Ok(true)
        } else {
            Err(format!(
                "req9 validation rejection mismatch: traversal={traversal_rejected} code={:?} message={:?}; overlap={overlap_rejected} code={:?}; symlink={symlink_rejected} code={:?} message={:?}",
                traversal_detail.code,
                traversal_detail.message,
                overlap_error.code,
                symlink_error.code,
                symlink_error.message,
            ))
        }
    })();
    let teardown = vm
        .kill()
        .map_err(|error| format!("req9 validation teardown failed: {error}"));
    match (checks, teardown) {
        (Ok(true), Ok(())) => Ok(true),
        (Ok(false), Ok(())) => Ok(false),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(teardown_error)) => Err(teardown_error),
        (Err(check_error), Err(teardown_error)) => Err(format!("{check_error}; {teardown_error}")),
    }
}

#[cfg(windows)]
struct ReconnectObservation {
    new_launch: LaunchIdentity,
    wait_observed: bool,
    ready_observed: bool,
    reset_observed: bool,
    stale_generation_rejected: bool,
    same_previous_generation_rejected: bool,
    stale_capability_rejected: bool,
    replacement_connect_after_close: bool,
}

#[cfg(windows)]
#[derive(Clone)]
struct ReconnectConnectMetadata {
    pipe_path: String,
    expected_image: String,
    process_id: u32,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplaceOrderingObservation {
    old_handle_closed_before_connect: bool,
}

#[cfg(windows)]
fn replace_slot_after_drop<T, F>(
    slot: &mut T,
    placeholder: T,
    connect: F,
) -> Result<ReplaceOrderingObservation, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let old = std::mem::replace(slot, placeholder);
    drop(old);
    let replacement = connect()?;
    let stale_placeholder = std::mem::replace(slot, replacement);
    drop(stale_placeholder);
    Ok(ReplaceOrderingObservation {
        old_handle_closed_before_connect: true,
    })
}

#[cfg(windows)]
fn replace_client_with_reconnect_connect<F>(
    session: &mut LiveWhpSession,
    metadata: &ReconnectConnectMetadata,
    connect: F,
) -> Result<ReplaceOrderingObservation, String>
where
    F: FnOnce(&ReconnectConnectMetadata) -> Result<MxcAgentClient<NamedPipeClient>, String>,
{
    let placeholder_client = MxcAgentClient::new(HostControlSession::new(
        NamedPipeClient::disconnected_placeholder()
            .map_err(|error| format!("req12 reconnect placeholder setup failed: {error}"))?,
    ));
    replace_slot_after_drop(&mut session.client, placeholder_client, || {
        connect(metadata)
    })
}

#[cfg(windows)]
fn reconnect_connect_with_named_pipe(
    metadata: &ReconnectConnectMetadata,
) -> Result<MxcAgentClient<NamedPipeClient>, String> {
    let reconnect_pipe = NamedPipeClient::connect(
        &metadata.pipe_path,
        Duration::from_secs(5),
        Some(metadata.process_id),
        Some(metadata.expected_image.as_str()),
    )
    .map_err(|error| format!("req12 reconnect control-pipe connect failed: {error}"))?;
    Ok(MxcAgentClient::new(HostControlSession::new(reconnect_pipe)))
}

#[cfg(windows)]
fn reconnect_after_control_drop(
    session: &mut LiveWhpSession,
    old_launch: LaunchIdentity,
    new_launch: LaunchIdentity,
) -> Result<ReconnectObservation, String> {
    let metadata = ReconnectConnectMetadata {
        pipe_path: session.vm.plan.control_pipe_name.clone(),
        expected_image: session
            .vm
            .plan
            .artifacts
            .openvmm_exe
            .to_string_lossy()
            .into_owned(),
        process_id: session.vm.process_id(),
    };
    let replace_ordering = replace_client_with_reconnect_connect(
        session,
        &metadata,
        reconnect_connect_with_named_pipe,
    )?;

    let attach_deadline = Instant::now() + Duration::from_secs(5);
    let mut wait_observed = false;
    let mut reset_observed = false;
    {
        loop {
            match session
                .client
                .control_session_mut()
                .send_host_attach(session.vm.plan.launch_capability)
            {
                Ok(()) => break,
                Err(SessionError::Io(error))
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < attach_deadline =>
                {
                    replace_client_with_reconnect_connect(
                        session,
                        &metadata,
                        reconnect_connect_with_named_pipe,
                    )?;
                }
                Err(error) => {
                    return Err(format!("req12 reconnect host-attach send failed: {error}"));
                }
            }
        }
        let raw = session.client.control_session_mut();
        match raw
            .recv_attach_status_until(attach_deadline)
            .map_err(|error| format!("req12 reconnect attach status failed: {error}"))?
        {
            HostAttachStatus::Ready => {}
            HostAttachStatus::Wait => {
                wait_observed = true;
                loop {
                    match raw
                        .recv_event_until(attach_deadline)
                        .map_err(|error| format!("req12 reconnect attach event failed: {error}"))?
                    {
                        HostEvent::Ready => break,
                        HostEvent::Wait => {
                            wait_observed = true;
                        }
                        HostEvent::Reset { .. } => {
                            reset_observed = true;
                        }
                        HostEvent::Error(code) => {
                            return Err(format!(
                                "req12 reconnect attach failed with broker error code {code}"
                            ));
                        }
                        HostEvent::Data(_) => {
                            return Err(
                                "req12 reconnect received data before broker Ready during attach"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            HostAttachStatus::Error(code) => {
                return Err(format!(
                    "req12 reconnect broker rejected host attach with code {code}"
                ));
            }
        }
    }
    let stale_generation_rejected = {
        session
            .client
            .send_host_hello(HostControlMessage::HostHello {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: old_launch,
                capability_proof: launch_capability_proof(old_launch.nonce)?,
            })
            .map_err(|error| format!("req12 reconnect stale HostHello send failed: {error}"))?;
        let detail = expect_error_after_send(
            session,
            HostControlMessage::Configure {
                launch: old_launch,
                root: session.root.clone(),
                mappings: session.req9_mappings.clone(),
                containment: session.containment,
            },
            LIVE_TIMEOUT,
        )?;
        detail.code == ProtocolErrorCode::InvalidLifecycleTransition
            && detail.message.contains("GenerationNotNewer")
    };
    let same_previous_generation = LaunchIdentity {
        generation: old_launch.generation,
        nonce: next_launch_nonce(old_launch.nonce),
    };
    let same_previous_generation_rejected = {
        session
            .client
            .send_host_hello(HostControlMessage::HostHello {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: same_previous_generation,
                capability_proof: launch_capability_proof(same_previous_generation.nonce)?,
            })
            .map_err(|error| {
                format!("req12 reconnect same-generation HostHello send failed: {error}")
            })?;
        let detail = expect_error_after_send(
            session,
            HostControlMessage::Configure {
                launch: same_previous_generation,
                root: session.root.clone(),
                mappings: session.req9_mappings.clone(),
                containment: session.containment,
            },
            LIVE_TIMEOUT,
        )?;
        detail.code == ProtocolErrorCode::InvalidLifecycleTransition
            && detail.message.contains("GenerationNotNewer")
    };
    let stale_capability_rejected = {
        session
            .client
            .send_host_hello(HostControlMessage::HostHello {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: new_launch,
                capability_proof: launch_capability_proof(old_launch.nonce)?,
            })
            .map_err(|error| {
                format!("req12 reconnect stale capability HostHello send failed: {error}")
            })?;
        let detail = expect_error_after_send(
            session,
            HostControlMessage::Configure {
                launch: new_launch,
                root: session.root.clone(),
                mappings: session.req9_mappings.clone(),
                containment: session.containment,
            },
            LIVE_TIMEOUT,
        )?;
        detail.code == ProtocolErrorCode::InvalidLifecycleTransition
            && detail
                .message
                .contains("capability proof did not match trusted launch capability")
    };
    session
        .client
        .send_host_hello(HostControlMessage::HostHello {
            service: SERVICE_IDENTITY.to_string(),
            protocol_version: PROTOCOL_VERSION,
            launch: new_launch,
            capability_proof: launch_capability_proof(new_launch.nonce)?,
        })
        .map_err(|error| format!("req12 reconnect HostHello send failed: {error}"))?;
    if let Some(message) = session
        .client
        .poll_agent_control(Duration::from_millis(10))
        .map_err(|error| format!("req12 reconnect HostHello poll failed: {error}"))?
        && matches!(message, AgentControlMessage::Error(_))
    {
        return Err(format!(
            "req12 reconnect HostHello unexpectedly failed: {message:?}"
        ));
    }
    session
        .client
        .send_configure(HostControlMessage::Configure {
            launch: new_launch,
            root: session.root.clone(),
            mappings: session.req9_mappings.clone(),
            containment: session.containment,
        })
        .map_err(|error| format!("req12 reconnect configure send failed: {error}"))?;
    let ready_observed = matches!(
        session
            .client
            .wait_ready(LIVE_TIMEOUT)
            .map_err(|error| format!("req12 reconnect wait_ready failed: {error}"))?,
        AgentControlMessage::Ready { launch, .. } if launch == new_launch
    );
    session.launch = new_launch;
    Ok(ReconnectObservation {
        new_launch,
        wait_observed,
        ready_observed,
        reset_observed,
        stale_generation_rejected,
        same_previous_generation_rejected,
        stale_capability_rejected,
        replacement_connect_after_close: replace_ordering.old_handle_closed_before_connect,
    })
}

#[cfg(windows)]
fn run_req11_shutdown_validation_session(session: &mut LiveWhpSession) -> Result<bool, String> {
    session.auxiliary_launches_started = session.auxiliary_launches_started.saturating_add(1);
    let validation_dir = session
        .req9_fixtures
        .run_dir
        .join("req11-shutdown-validation");
    fs::create_dir_all(&validation_dir).map_err(|error| {
        format!(
            "creating req11 shutdown validation directory {} failed: {error}",
            validation_dir.display()
        )
    })?;
    let mut vm = launch_whp_vm(build_launch_plan(
        &validation_dir,
        session.vm.plan.artifacts.clone(),
    ))?;
    let checks = (|| -> Result<bool, String> {
        let pid = vm.process_id();
        let expected_image = vm.plan.artifacts.openvmm_exe.to_string_lossy().into_owned();
        let control = NamedPipeClient::connect(
            &vm.plan.control_pipe_name,
            Duration::from_secs(5),
            Some(pid),
            Some(expected_image.as_str()),
        )
        .map_err(|error| format!("req11 shutdown validation pipe connect failed: {error}"))?;
        let mut client = MxcAgentClient::new(HostControlSession::new(control));
        client
            .authenticate_launch(
                vm.plan.launch_capability,
                HostControlMessage::HostHello {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch: LaunchIdentity {
                        generation: vm.plan.channel_generation.saturating_add(1),
                        nonce: vm.plan.launch_nonce,
                    },
                    capability_proof: launch_capability_proof(vm.plan.launch_nonce)?,
                },
                LIVE_TIMEOUT,
            )
            .map_err(|error| format!("req11 shutdown validation launch auth failed: {error}"))?;
        let root = CanonicalHostMappingRoot::parse(ROOT_CANONICAL_HOST.to_string())
            .map_err(|error| format!("req11 shutdown validation root parse failed: {error}"))?;
        client
            .send_configure(HostControlMessage::Configure {
                launch: LaunchIdentity {
                    generation: vm.plan.channel_generation.saturating_add(1),
                    nonce: vm.plan.launch_nonce,
                },
                root,
                mappings: req9_legitimate_mappings(&vm.plan.artifacts.common_root)?,
                containment: MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            })
            .map_err(|error| format!("req11 shutdown validation configure failed: {error}"))?;
        match client
            .wait_ready(LIVE_TIMEOUT)
            .map_err(|error| format!("req11 shutdown validation wait_ready failed: {error}"))?
        {
            AgentControlMessage::Ready { .. } => {}
            other => {
                return Err(format!(
                    "req11 shutdown validation expected Ready, got {other:?}"
                ));
            }
        }
        client
            .send_create_process(HostControlMessage::CreateProcess {
                exec_id: 11_901,
                argv: vec![
                    PROBE_PATH.to_string(),
                    "flood".to_string(),
                    "--stream".to_string(),
                    "stdout".to_string(),
                    "--bytes".to_string(),
                    "524288".to_string(),
                    "--chunk".to_string(),
                    "4096".to_string(),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            })
            .map_err(|error| format!("req11 shutdown validation create failed: {error}"))?;
        client
            .send_flow_credits(FlowCreditRequest {
                exec_id: 11_901,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .map_err(|error| format!("req11 shutdown validation stdout credit failed: {error}"))?;
        client
            .send_flow_credits(FlowCreditRequest {
                exec_id: 11_901,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .map_err(|error| format!("req11 shutdown validation stderr credit failed: {error}"))?;
        let active = matches!(
            client
                .request_health(LIVE_TIMEOUT)
                .map_err(|error| format!("req11 shutdown validation health failed: {error}"))?,
            AgentControlMessage::Health(status) if status.active_exec_id == Some(11_901)
        );
        let invalid_zero_detail = client.request_shutdown(0, LIVE_TIMEOUT).map_err(|error| {
            format!("req11 shutdown validation zero-grace request failed: {error}")
        })?;
        let invalid_zero_rejected = matches!(
            invalid_zero_detail,
            AgentControlMessage::Error(ProtocolErrorDetail { code: ProtocolErrorCode::InvalidLifecycleTransition, ref message })
            if message == "InvalidInput: grace_timeout_ms must be greater than zero"
        );
        let invalid_above_max_detail = client
            .request_shutdown(
                MAX_SHUTDOWN_GRACE_TIMEOUT_MS.saturating_add(1),
                LIVE_TIMEOUT,
            )
            .map_err(|error| {
                format!("req11 shutdown validation over-max request failed: {error}")
            })?;
        let invalid_above_max_rejected = matches!(
            invalid_above_max_detail,
            AgentControlMessage::Error(ProtocolErrorDetail { code: ProtocolErrorCode::InvalidLifecycleTransition, ref message })
            if *message == format!(
                "InvalidInput: grace_timeout_ms exceeds maximum supported value {MAX_SHUTDOWN_GRACE_TIMEOUT_MS}"
            )
        );
        let shutdown_start = Instant::now();
        let shutdown_deadline = shutdown_start
            .checked_add(Duration::from_millis(
                SHUTDOWN_VALIDATION_GRACE_MS + SHUTDOWN_VALIDATION_GRACE_TOLERANCE_MS,
            ))
            .ok_or_else(|| "req11 shutdown validation deadline overflowed".to_string())?;
        let shutdown_ack = matches!(
            client
                .request_shutdown(
                    SHUTDOWN_VALIDATION_GRACE_MS,
                    remaining_until(shutdown_deadline, "req11 shutdown ack")?
                )
                .map_err(|error| format!(
                    "req11 shutdown validation shutdown request failed: {error}"
                ))?,
            AgentControlMessage::ShuttingDown
        );
        let channel_closed = loop {
            let remaining =
                remaining_until(shutdown_deadline, "req11 guest shutdown channel close")?;
            match client.poll_agent_control(remaining) {
                Err(error) if is_expected_channel_close_error(&error) => break true,
                Err(error) => {
                    return Err(format!(
                        "req11 shutdown channel observation failed: {error}"
                    ));
                }
                Ok(Some(_)) => {}
                Ok(None) => break false,
            }
        };
        let elapsed = shutdown_start.elapsed();
        let passed = active
            && invalid_zero_rejected
            && invalid_above_max_rejected
            && shutdown_ack
            && channel_closed
            && elapsed
                <= Duration::from_millis(
                    SHUTDOWN_VALIDATION_GRACE_MS + SHUTDOWN_VALIDATION_GRACE_TOLERANCE_MS,
                );
        if passed {
            Ok(true)
        } else {
            Err(format!(
                "req11 shutdown validation mismatch: active={active} zero_rejected={invalid_zero_rejected} above_max_rejected={invalid_above_max_rejected} ack={shutdown_ack} channel_closed={channel_closed} elapsed={elapsed:?}"
            ))
        }
    })();
    let teardown = vm
        .kill()
        .map_err(|error| format!("req11 shutdown validation teardown failed: {error}"));
    session.auxiliary_launches_torn_down = session.auxiliary_launches_torn_down.saturating_add(1);
    match (checks, teardown) {
        (Ok(true), Ok(())) => Ok(true),
        (Ok(false), Ok(())) => Ok(false),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(teardown_error)) => Err(teardown_error),
        (Err(check_error), Err(teardown_error)) => Err(format!("{check_error}; {teardown_error}")),
    }
}

#[cfg(windows)]
fn validate_live_network_status(status: &NetworkStatus) -> Result<String, String> {
    match status.mode {
        NetworkMode::NoNic => {
            if status.setup_state != NetworkSetupState::Ready {
                return Err(format!(
                    "NoNic setup_state must be Ready, got {:?}",
                    status.setup_state
                ));
            }
            if status.interface.is_some() {
                return Err("NoNic must not report interface details".to_string());
            }
            if status.default_gateway.is_some() {
                return Err("NoNic must not report default gateway".to_string());
            }
            if !status.dns.ready || !status.dns.servers.is_empty() {
                return Err("NoNic must report DNS ready=true with no DNS servers".to_string());
            }
            if status.failure.is_some() {
                return Err("NoNic must not report network failure".to_string());
            }
            Ok("launch mode NoNic: isolated-ready status with no interface/gateway/DNS-server/failure fields".to_string())
        }
        NetworkMode::PortableNetwork => {
            if status.setup_state != NetworkSetupState::Ready {
                return Err(format!(
                    "PortableNetwork setup_state must be Ready, got {:?}",
                    status.setup_state
                ));
            }
            if status.failure.is_some() {
                return Err("PortableNetwork must not report network failure".to_string());
            }
            let interface = status
                .interface
                .as_ref()
                .ok_or_else(|| "PortableNetwork must report interface".to_string())?;
            if interface.link_state != agent_protocol::NetworkLinkState::Up {
                return Err(format!(
                    "PortableNetwork interface link_state must be Up, got {:?}",
                    interface.link_state
                ));
            }
            if interface.addresses.is_empty() || interface.addresses.len() > 8 {
                return Err(format!(
                    "PortableNetwork addresses count must be 1..=8, got {}",
                    interface.addresses.len()
                ));
            }
            for address in &interface.addresses {
                address.parse::<IpAddr>().map_err(|error| {
                    format!("PortableNetwork address {address:?} is invalid: {error}")
                })?;
            }
            let gateway = status
                .default_gateway
                .as_ref()
                .ok_or_else(|| "PortableNetwork must report default gateway".to_string())?;
            gateway
                .parse::<IpAddr>()
                .map_err(|error| format!("PortableNetwork default gateway is invalid: {error}"))?;
            if interface.default_route.as_ref() != Some(gateway) {
                return Err(format!(
                    "PortableNetwork interface.default_route {:?} must match default_gateway {:?}",
                    interface.default_route, gateway
                ));
            }
            if !status.dns.ready {
                return Err("PortableNetwork must report DNS ready=true".to_string());
            }
            if status.dns.servers.is_empty() || status.dns.servers.len() > 8 {
                return Err(format!(
                    "PortableNetwork DNS server count must be 1..=8, got {}",
                    status.dns.servers.len()
                ));
            }
            for server in &status.dns.servers {
                server.parse::<IpAddr>().map_err(|error| {
                    format!("PortableNetwork DNS server {server:?} is invalid: {error}")
                })?;
            }
            Ok(format!(
                "launch mode PortableNetwork: interface={} link-up addresses={} gateway={} dns_servers={}",
                interface.name,
                interface.addresses.len(),
                gateway,
                status.dns.servers.len()
            ))
        }
    }
}

#[cfg(windows)]
fn launch_capability_proof(nonce: [u8; 16]) -> Result<CapabilityProofMaterial, String> {
    let mut capability_proof = [0_u8; 32];
    capability_proof[..16].copy_from_slice(&nonce);
    capability_proof[16..].copy_from_slice(&nonce);
    CapabilityProofMaterial::try_from(capability_proof.to_vec())
        .map_err(|error| format!("building launch capability proof failed: {error}"))
}

#[cfg(windows)]
fn next_launch_nonce(current: [u8; 16]) -> [u8; 16] {
    let mut next = current;
    next[0] ^= 0xA5;
    next[15] ^= 0x5A;
    next
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
fn remaining_until(deadline: Instant, context: &str) -> Result<Duration, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err(format!("deadline exhausted while waiting for {context}"));
    }
    Ok(deadline.saturating_duration_since(now))
}

#[cfg(windows)]
fn is_expected_channel_close_error(error: &ClientError) -> bool {
    match error {
        ClientError::Control(source) | ClientError::ControlOperation { source, .. } => {
            is_expected_channel_close_session_error(source)
        }
        _ => false,
    }
}

#[cfg(windows)]
fn is_expected_channel_close_session_error(source: &SessionError) -> bool {
    match source {
        SessionError::Closed => true,
        SessionError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
        ),
        SessionError::Protocol(_)
        | SessionError::DeadlineExceeded(_)
        | SessionError::SequenceMismatch { .. }
        | SessionError::SessionIdentityMismatch
        | SessionError::UnexpectedRecordType(_) => false,
    }
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
    let observed = collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(10),
        true,
        ExecCollectionLimits::small_probe(Duration::from_secs(10)),
    )?;
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
    let mut stderr = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut observed_messages = 0_usize;
    let tree_pids = loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for tree pid line for exec {exec_id}"
            ));
        }
        let message = match session
            .client
            .recv_agent_control(Duration::from_millis(250))
        {
            Ok(message) => message,
            Err(ClientError::Timeout(_)) => continue,
            Err(error) => return Err(format!("waiting for tree line failed: {error}")),
        };
        match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    record.chunk.len(),
                )?;
                output.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stdout, 1)?;
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    0,
                )?;
                stderr.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stderr, 1)?;
            }
            AgentControlMessage::ExecTerminal {
                exec_id: terminal_exec_id,
                disposition,
                termination,
            } if terminal_exec_id == exec_id => {
                return Err(format!(
                    "exec {exec_id} terminated before timeout-tree pid line: disposition={disposition:?} termination={termination:?} stderr={}",
                    String::from_utf8_lossy(&stderr)
                ));
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
    let observed = collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(12),
        true,
        ExecCollectionLimits::tree_probe(Duration::from_secs(12)),
    )?;
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
    let mut observed_messages = 0_usize;
    let tree_pids = loop {
        if Instant::now() >= pid_deadline {
            return Err(format!(
                "timed out waiting for tree pid line for exec {exec_id}"
            ));
        }
        let message = match session
            .client
            .recv_agent_control(Duration::from_millis(250))
        {
            Ok(message) => message,
            Err(ClientError::Timeout(_)) => continue,
            Err(error) => return Err(format!("waiting for timeout tree line failed: {error}")),
        };
        match message {
            AgentControlMessage::StdoutChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    record.chunk.len(),
                )?;
                output.extend_from_slice(&record.chunk);
                grant_stream(session, exec_id, StreamName::Stdout, 1)?;
                if let Some(pids) = parse_tree_pids(&output) {
                    break pids;
                }
            }
            AgentControlMessage::StderrChunk(record) if record.exec_id == exec_id => {
                observed_messages = observed_messages.saturating_add(1);
                enforce_tree_pid_capture_limit(
                    session,
                    exec_id,
                    observed_messages,
                    output.len(),
                    0,
                )?;
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
    let observed = collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(12),
        true,
        ExecCollectionLimits::tree_probe(Duration::from_secs(12)),
    )?;
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
    let observed = collect_exec_until_terminal(
        session,
        exec_id,
        Duration::from_secs(8),
        true,
        ExecCollectionLimits::small_probe(Duration::from_secs(8)),
    )?;
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
    let observed = collect_exec_until_terminal(
        session,
        exec_id,
        LIVE_TIMEOUT,
        true,
        ExecCollectionLimits::small_probe(LIVE_TIMEOUT),
    )?;
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
const POLICY_SCHEMA_VERSION: &str = "0.9.0-dev";
#[cfg(windows)]
const POLICY_PROBE_CAPABILITY_VERSION: &str = "policy-suite-capabilities-v1";
#[cfg(windows)]
const POLICY_REQUIRED_PROBE_COMMANDS: &[&str] = &[
    "capabilities-json",
    "mapping-check",
    "network-policy-json",
    "spawn-tree",
    "check-pids-gone",
];

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct PolicyProbeCapabilitiesReport {
    version: String,
    supported_commands: Vec<String>,
}

#[cfg(windows)]
fn run_policy_filesystem_contract(state: &mut LiveHarnessState) -> PolicyLiveEvidence {
    let outcome = run_req9_mapping_containment(state);
    match outcome.check_status {
        EvidenceCheckStatus::Pass => PolicyLiveEvidence {
            positive_passed: true,
            negative_passed: true,
            blocked: false,
            evidence: outcome.evidence,
            error: None,
        },
        EvidenceCheckStatus::NotRun => PolicyLiveEvidence {
            positive_passed: false,
            negative_passed: false,
            blocked: true,
            evidence: Vec::new(),
            error: Some(outcome.error.unwrap_or_else(|| {
                "filesystem-rw-ro profile was not run and returned no detail".to_string()
            })),
        },
        EvidenceCheckStatus::Fail => PolicyLiveEvidence {
            positive_passed: false,
            negative_passed: false,
            blocked: false,
            evidence: Vec::new(),
            error: Some(outcome.error.unwrap_or_else(|| {
                "filesystem-rw-ro profile failed without error detail".to_string()
            })),
        },
    }
}

#[cfg(windows)]
fn run_policy_shell_contract(state: &mut LiveHarnessState) -> PolicyLiveEvidence {
    if state.session.is_none() {
        return policy_live_blocked("live session unavailable".to_string());
    }
    let mut evidence = Vec::new();
    let positive = (|| {
        let session = state
            .session
            .as_mut()
            .ok_or_else(|| "live session unavailable".to_string())?;
        let observed = run_policy_command(
            session,
            1_301,
            "printf '%s|%s' \"quoted:$NVX_VALUE\" \"$PWD\"",
            Some("/".to_string()),
            vec!["NVX_VALUE=expanded".to_string()],
            None,
            Duration::from_secs(10),
        )?;
        if observed.stdout != b"quoted:expanded|/"
            || observed.disposition != Some(ExecDisposition::ExitCode(0))
        {
            return Err(format!(
                "shell quoting/expansion/cwd mismatch: disposition={:?} stdout={:?}",
                observed.disposition,
                String::from_utf8_lossy(&observed.stdout)
            ));
        }
        evidence.push(
            "live /bin/sh -c preserved quoting, expansion, explicit cwd, and environment"
                .to_string(),
        );
        let nonzero = run_policy_command(
            session,
            1_302,
            "exit 23",
            None,
            Vec::new(),
            None,
            Duration::from_secs(10),
        )?;
        if nonzero.disposition != Some(ExecDisposition::ExitCode(23)) {
            return Err(format!(
                "nonzero shell exit was not preserved: {:?}",
                nonzero.disposition
            ));
        }
        evidence.push("live shell preserved nonzero exit code 23".to_string());
        if !run_timeout_tree_exec(session, 1_303, true, 250)? {
            return Err(
                "timeout workload did not prove child+grandchild cleanup and terminal ordering"
                    .to_string(),
            );
        }
        evidence.push(
            "timeout command used child+grandchild probe and confirmed descendants-cleaned before terminal plus post-terminal pid-gone verification".to_string(),
        );
        Ok(())
    })();
    let negative = (|| {
        let session = state
            .session
            .as_ref()
            .ok_or_else(|| "live session unavailable".to_string())?;
        let empty = adapt_policy(
            "policy-live-empty-command",
            &policy_exec_config("", None, Vec::new(), None, None),
            &session.vm.plan.artifacts.common_root,
        );
        let empty = match empty {
            Ok(_) => {
                return Err(
                    "empty command was accepted, expected adapter rejection at /process/commandLine"
                        .to_string(),
                );
            }
            Err(errors) => errors,
        };
        let command_line_rejected = empty.iter().any(|error| {
            error.instance_path == "/process/commandLine"
                && (error.code == "invalid_value" || error.code == "schema_validation")
        });
        if !command_line_rejected {
            return Err(format!(
                "empty command rejection did not point to /process/commandLine: {empty:?}"
            ));
        }
        evidence.push(
            "empty command was rejected by adapter at /process/commandLine as required".to_string(),
        );
        Ok(())
    })();
    policy_live_assertions(positive, negative, evidence)
}

#[cfg(windows)]
fn run_policy_proxy_contract(state: &mut LiveHarnessState) -> PolicyLiveEvidence {
    let mut evidence = Vec::new();
    let positive = (|| {
        let session = state
            .session
            .as_mut()
            .ok_or_else(|| "live session unavailable".to_string())?;
        let command = "printf '%s|%s|%s|%s|%s' \"${HTTP_PROXY-unset}\" \"${HTTPS_PROXY-unset}\" \"${http_proxy-unset}\" \"${https_proxy-unset}\" \"${NO_PROXY-unset}\"";
        let proxy = "http://127.0.0.1:18080";
        let config = policy_exec_config(command, None, Vec::new(), None, Some(proxy));
        let adapted = adapt_policy(
            "policy-live-proxy-env",
            &config,
            &session.vm.plan.artifacts.common_root,
        )
        .map_err(|errors| format!("policy adapter rejected proxy config: {errors:?}"))?;
        let exec = adapted.exec.ok_or_else(|| {
            "policy adapter did not emit exec policy for proxy profile".to_string()
        })?;
        let expected_http = exec
            .env
            .iter()
            .find_map(|entry| entry.strip_prefix("HTTP_PROXY="))
            .ok_or_else(|| "adapted exec env omitted HTTP_PROXY".to_string())?;
        let expected_https = exec
            .env
            .iter()
            .find_map(|entry| entry.strip_prefix("HTTPS_PROXY="))
            .ok_or_else(|| "adapted exec env omitted HTTPS_PROXY".to_string())?;
        let injected =
            run_policy_exec_from_adapter(session, 1_312, config, Duration::from_secs(10))?;
        let expected = format!("{expected_http}|{expected_https}|unset|unset|unset");
        if injected.stdout != expected.as_bytes()
            || injected.disposition != Some(ExecDisposition::ExitCode(0))
        {
            return Err(format!(
                "proxy variables were not injected exactly from runtimeConfig.networkProxy: {:?}",
                String::from_utf8_lossy(&injected.stdout)
            ));
        }
        evidence.push(
            "runtimeConfig.networkProxy explicit-port loopback URL projected exactly into HTTP_PROXY/HTTPS_PROXY for live exec environment".to_string(),
        );
        Ok(())
    })();
    let negative = (|| {
        let session = state
            .session
            .as_mut()
            .ok_or_else(|| "live session unavailable".to_string())?;
        let command = "printf '%s|%s|%s|%s|%s' \"${HTTP_PROXY-unset}\" \"${HTTPS_PROXY-unset}\" \"${http_proxy-unset}\" \"${https_proxy-unset}\" \"${NO_PROXY-unset}\"";
        let absent = run_policy_exec_from_adapter(
            session,
            1_311,
            policy_exec_config(command, None, Vec::new(), None, None),
            Duration::from_secs(10),
        )?;
        if absent.stdout != b"unset|unset|unset|unset|unset"
            || absent.disposition != Some(ExecDisposition::ExitCode(0))
        {
            return Err(format!(
                "absent proxy variables were not scrubbed: {:?}",
                String::from_utf8_lossy(&absent.stdout)
            ));
        }
        evidence.push(
            "when runtimeConfig.networkProxy was absent, proxy variables remained fully scrubbed (HTTP/HTTPS lowercase/uppercase and NO_PROXY unset)".to_string(),
        );
        Ok(())
    })();
    policy_live_assertions(positive, negative, evidence)
}

#[cfg(windows)]
fn run_control_lifecycle_dedicated_session(
    state: &mut LiveHarnessState,
) -> Result<Vec<String>, String> {
    let session = state
        .session
        .as_mut()
        .ok_or_else(|| "live session unavailable".to_string())?;
    session.auxiliary_launches_started = session.auxiliary_launches_started.saturating_add(1);
    let validation_dir = session
        .req9_fixtures
        .run_dir
        .join("policy-control-lifecycle-dedicated");
    fs::create_dir_all(&validation_dir).map_err(|error| {
        format!(
            "creating control lifecycle validation directory {} failed: {error}",
            validation_dir.display()
        )
    })?;
    let mut vm = launch_whp_vm(build_launch_plan(
        &validation_dir,
        session.vm.plan.artifacts.clone(),
    ))?;
    let checks = (|| -> Result<Vec<String>, String> {
        let rw = vm.plan.artifacts.common_root.join(RW_CHILD);
        let ro = vm.plan.artifacts.common_root.join(RO_CHILD);
        fs::create_dir_all(&rw)
            .map_err(|error| format!("creating lifecycle rw fixture failed: {error}"))?;
        fs::create_dir_all(&ro)
            .map_err(|error| format!("creating lifecycle ro fixture failed: {error}"))?;

        let pid = vm.process_id();
        let expected_image = vm.plan.artifacts.openvmm_exe.to_string_lossy().into_owned();
        let control = NamedPipeClient::connect(
            &vm.plan.control_pipe_name,
            Duration::from_secs(5),
            Some(pid),
            Some(expected_image.as_str()),
        )
        .map_err(|error| format!("control lifecycle dedicated pipe connect failed: {error}"))?;
        let mut client = MxcAgentClient::new(HostControlSession::new(control));
        let launch = LaunchIdentity {
            generation: vm.plan.channel_generation.saturating_add(1),
            nonce: vm.plan.launch_nonce,
        };
        client
            .authenticate_launch(
                vm.plan.launch_capability,
                HostControlMessage::HostHello {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    launch,
                    capability_proof: launch_capability_proof(vm.plan.launch_nonce)?,
                },
                LIVE_TIMEOUT,
            )
            .map_err(|error| format!("control lifecycle dedicated launch auth failed: {error}"))?;

        let provision = adapt_live_provision_policy(
            "policy-live-control-lifecycle-provision",
            &vm.plan.artifacts.common_root,
            serde_json::Value::Null,
        )?;
        client
            .send_configure(HostControlMessage::Configure {
                launch,
                root: CanonicalHostMappingRoot::parse(ROOT_CANONICAL_HOST.to_string())
                    .map_err(|error| format!("control lifecycle root parse failed: {error}"))?,
                mappings: provision.mappings,
                containment: MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            })
            .map_err(|error| format!("control lifecycle provision/configure failed: {error}"))?;
        adapt_policy(
            "policy-live-control-lifecycle-start",
            &serde_json::json!({
                "version": POLICY_SCHEMA_VERSION,
                "containment": "vm",
                "phase": "start",
                "sandboxId": "policy-live-lifecycle-sandbox",
            }),
            &vm.plan.artifacts.common_root,
        )
        .map_err(|errors| format!("control lifecycle start adaptation failed: {errors:?}"))?;
        match client
            .wait_ready(LIVE_TIMEOUT)
            .map_err(|error| format!("control lifecycle start/wait_ready failed: {error}"))?
        {
            AgentControlMessage::Ready {
                launch: ready_launch,
                ..
            } if ready_launch == launch => {}
            other => {
                return Err(format!(
                    "control lifecycle start expected Ready, got {other:?}"
                ));
            }
        }
        match client
            .request_health(LIVE_TIMEOUT)
            .map_err(|error| format!("control lifecycle ready health failed: {error}"))?
        {
            AgentControlMessage::Health(status) if status.launch_admitted => {}
            other => {
                return Err(format!(
                    "control lifecycle start health unexpected: {other:?}"
                ));
            }
        }

        let exec = adapt_policy(
            "policy-live-control-lifecycle-exec",
            &serde_json::json!({
                "version": POLICY_SCHEMA_VERSION,
                "containment": "vm",
                "phase": "exec",
                "sandboxId": "policy-live-lifecycle-sandbox",
                "containerId": "policy-live-lifecycle-container",
                "process": { "commandLine": "echo lifecycle", "cwd": "/", "env": [], "timeout": 1000 }
            }),
            &vm.plan.artifacts.common_root,
        )
        .map_err(|errors| format!("control lifecycle exec adaptation failed: {errors:?}"))?
        .exec
        .ok_or_else(|| "control lifecycle exec adaptation omitted exec policy".to_string())?;
        client
            .send_create_process(HostControlMessage::CreateProcess {
                exec_id: 1_313,
                argv: exec.argv,
                cwd: exec.cwd,
                env: exec.env,
                timeout_ms: exec.timeout_ms,
            })
            .map_err(|error| format!("control lifecycle exec create failed: {error}"))?;
        client
            .send_flow_credits(FlowCreditRequest {
                exec_id: 1_313,
                stream: StreamName::Stdout,
                credits: 1,
            })
            .map_err(|error| format!("control lifecycle exec stdout credit failed: {error}"))?;
        client
            .send_flow_credits(FlowCreditRequest {
                exec_id: 1_313,
                stream: StreamName::Stderr,
                credits: 1,
            })
            .map_err(|error| format!("control lifecycle exec stderr credit failed: {error}"))?;
        match client
            .wait_exec_terminal(1_313, Duration::from_secs(10))
            .map_err(|error| format!("control lifecycle exec terminal wait failed: {error}"))?
        {
            AgentControlMessage::ExecTerminal {
                exec_id: 1_313,
                disposition: ExecDisposition::ExitCode(0),
                ..
            } => {}
            other => {
                return Err(format!(
                    "control lifecycle exec expected exit code 0 terminal, got {other:?}"
                ));
            }
        }

        adapt_policy(
            "policy-live-control-lifecycle-stop",
            &serde_json::json!({
                "version": POLICY_SCHEMA_VERSION,
                "containment": "vm",
                "phase": "stop",
                "sandboxId": "policy-live-lifecycle-sandbox",
            }),
            &vm.plan.artifacts.common_root,
        )
        .map_err(|errors| format!("control lifecycle stop adaptation failed: {errors:?}"))?;
        let shutdown = client
            .request_shutdown(SHUTDOWN_VALIDATION_GRACE_MS, Duration::from_secs(3))
            .map_err(|error| format!("control lifecycle stop request failed: {error}"))?;
        if !matches!(shutdown, AgentControlMessage::ShuttingDown) {
            return Err(format!(
                "control lifecycle stop expected ShuttingDown ack, got {shutdown:?}"
            ));
        }
        let close_deadline = Instant::now() + Duration::from_secs(3);
        let channel_closed = loop {
            let remaining = close_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break false;
            }
            match client.poll_agent_control(remaining.min(Duration::from_millis(250))) {
                Err(error) if is_expected_channel_close_error(&error) => break true,
                Err(error) => {
                    return Err(format!(
                        "control lifecycle stop channel-close observation failed: {error}"
                    ));
                }
                Ok(Some(_)) => {}
                Ok(None) => break false,
            }
        };
        if !channel_closed {
            return Err(
                "control lifecycle stop did not close guest control channel after shutdown ack"
                    .to_string(),
            );
        }
        adapt_policy(
            "policy-live-control-lifecycle-deprovision",
            &serde_json::json!({
                "version": POLICY_SCHEMA_VERSION,
                "containment": "vm",
                "phase": "deprovision",
                "sandboxId": "policy-live-lifecycle-sandbox",
            }),
            &vm.plan.artifacts.common_root,
        )
        .map_err(|errors| format!("control lifecycle deprovision adaptation failed: {errors:?}"))?;
        Ok(vec![
            "phase=provision mapped to authenticated Configure on dedicated lifecycle session".to_string(),
            "phase=start mapped to Ready + Health on dedicated lifecycle session".to_string(),
            "phase=exec mapped to authenticated CreateProcess/ExecTerminal on dedicated lifecycle session".to_string(),
            "phase=stop mapped to graceful Shutdown ack plus channel close on dedicated lifecycle session".to_string(),
            "phase=deprovision mapped to explicit harness teardown after stop (no Drop-only cleanup)".to_string(),
        ])
    })();
    let teardown = vm
        .kill()
        .map_err(|error| format!("control lifecycle dedicated teardown failed: {error}"));
    session.auxiliary_launches_torn_down = session.auxiliary_launches_torn_down.saturating_add(1);
    match (checks, teardown) {
        (Ok(evidence), Ok(())) => Ok(evidence),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(teardown_error)) => Err(teardown_error),
        (Err(error), Err(teardown_error)) => Err(format!("{error}; {teardown_error}")),
    }
}

#[cfg(windows)]
fn run_policy_control_lifecycle_contract(state: &mut LiveHarnessState) -> PolicyLiveEvidence {
    let mut evidence = Vec::new();
    let positive = (|| {
        let phase_evidence = run_control_lifecycle_dedicated_session(state)?;
        evidence.extend(phase_evidence);
        Ok(())
    })();

    let negative = (|| {
        let session = state
            .session
            .as_ref()
            .ok_or_else(|| "live session unavailable".to_string())?;
        let all_rejected = [
            (
                "control-lifecycle-sandbox-missing",
                serde_json::json!({
                    "version": POLICY_SCHEMA_VERSION,
                    "containment": "vm",
                    "phase": "exec",
                    "process": { "commandLine": "echo missing-sandbox" }
                }),
            ),
            (
                "control-lifecycle-sandbox-present-provision",
                serde_json::json!({
                    "version": POLICY_SCHEMA_VERSION,
                    "containment": "vm",
                    "phase": "provision",
                    "sandboxId": "must-be-absent",
                }),
            ),
            (
                "control-lifecycle-containment-override",
                serde_json::json!({
                    "version": POLICY_SCHEMA_VERSION,
                    "containment": "process",
                    "phase": "provision",
                }),
            ),
            (
                "control-lifecycle-version-override",
                serde_json::json!({
                    "version": "0.9.0",
                    "containment": "vm",
                    "phase": "provision",
                }),
            ),
            (
                "control-lifecycle-phase-missing",
                serde_json::json!({
                    "version": POLICY_SCHEMA_VERSION,
                    "containment": "vm",
                }),
            ),
        ]
        .iter()
        .all(|(case_id, config)| {
            adapt_policy(*case_id, config, &session.vm.plan.artifacts.common_root).is_err()
        });
        let container_id_variants_ok = adapt_policy(
            "control-lifecycle-containerid-null",
            &serde_json::json!({
                "version": POLICY_SCHEMA_VERSION,
                "containment": "vm",
                "phase": "start",
                "sandboxId": "sandbox-null-container",
                "containerId": serde_json::Value::Null,
            }),
            &session.vm.plan.artifacts.common_root,
        )
        .is_ok()
            && adapt_policy(
                "control-lifecycle-containerid-absent",
                &serde_json::json!({
                    "version": POLICY_SCHEMA_VERSION,
                    "containment": "vm",
                    "phase": "start",
                    "sandboxId": "sandbox-absent-container",
                }),
                &session.vm.plan.artifacts.common_root,
            )
            .is_ok();
        if !all_rejected || !container_id_variants_ok {
            return Err(format!(
                "negative lifecycle invariants failed: all_rejected={all_rejected} container_id_variants_ok={container_id_variants_ok}"
            ));
        }
        evidence.push(
            "negative prelaunch adapter checks rejected invalid sandbox/version/containment/phase combinations while allowing containerId null/absent variants".to_string(),
        );
        Ok(())
    })();
    policy_live_assertions(positive, negative, evidence)
}

#[cfg(windows)]
fn adapt_live_provision_policy(
    case_id: &str,
    common_root: &Path,
    network: serde_json::Value,
) -> Result<NvxProvisionPolicy, String> {
    let mut config = serde_json::json!({
        "version": POLICY_SCHEMA_VERSION,
        "containment": "vm",
        "phase": "provision",
        "filesystem": {
            "readonlyPaths": [common_root.join(RO_CHILD).to_string_lossy().into_owned()],
            "readwritePaths": [common_root.join(RW_CHILD).to_string_lossy().into_owned()]
        }
    });
    if !network.is_null() {
        config["network"] = network;
    }
    let adapted = adapt_policy(case_id, &config, common_root)
        .map_err(|errors| format!("policy adapter rejected provision config: {errors:?}"))?;
    adapted
        .provision
        .ok_or_else(|| "policy adapter omitted provision plan for phase=provision".to_string())
}

#[cfg(windows)]
fn portable_network_override_from_provision(
    provision: &NvxProvisionPolicy,
) -> Result<Option<String>, String> {
    match provision.default_network_policy.as_deref() {
        Some("allow") => Ok(Some("10.0.0.2/24".to_string())),
        Some("block") | None => Ok(None),
        Some(other) => Err(format!(
            "runtime gap: unsupported provision defaultPolicy `{other}` (expected allow/block/null)"
        )),
    }
}

#[cfg(windows)]
fn policy_exec_config(
    command_line: &str,
    cwd: Option<&str>,
    env: Vec<String>,
    timeout_ms: Option<u64>,
    runtime_proxy: Option<&str>,
) -> serde_json::Value {
    let mut config = serde_json::json!({
        "version": POLICY_SCHEMA_VERSION,
        "containment": "vm",
        "phase": "exec",
        "sandboxId": "policy-live-sandbox",
        "process": {
            "commandLine": command_line,
            "env": env,
        }
    });
    if let Some(cwd) = cwd {
        config["process"]["cwd"] = serde_json::Value::String(cwd.to_string());
    }
    if let Some(timeout_ms) = timeout_ms {
        config["process"]["timeout"] = serde_json::Value::from(timeout_ms);
    }
    if let Some(proxy) = runtime_proxy {
        config["runtimeConfig"] = serde_json::json!({ "networkProxy": proxy });
    }
    config
}

#[cfg(windows)]
fn run_policy_exec_from_adapter(
    session: &mut LiveWhpSession,
    exec_id: u32,
    config: serde_json::Value,
    timeout: Duration,
) -> Result<ExecObservation, String> {
    let adapted = adapt_policy(
        "policy-live-profile",
        &config,
        &session.vm.plan.artifacts.common_root,
    )
    .map_err(|errors| format!("policy adapter rejected profile config: {errors:?}"))?;
    let exec = adapted
        .exec
        .ok_or_else(|| "policy adapter did not emit exec policy for phase=exec".to_string())?;
    session
        .client
        .send_create_process(HostControlMessage::CreateProcess {
            exec_id,
            argv: exec.argv,
            cwd: exec.cwd,
            env: exec.env,
            timeout_ms: exec.timeout_ms,
        })
        .map_err(|error| format!("policy create process {exec_id} failed: {error}"))?;
    grant_stream(session, exec_id, StreamName::Stdout, 1)?;
    grant_stream(session, exec_id, StreamName::Stderr, 1)?;
    collect_exec_until_terminal(
        session,
        exec_id,
        timeout,
        true,
        ExecCollectionLimits::small_probe(timeout),
    )
}

#[cfg(windows)]
fn run_policy_command(
    session: &mut LiveWhpSession,
    exec_id: u32,
    command_line: &str,
    cwd: Option<String>,
    env: Vec<String>,
    timeout_ms: Option<u64>,
    timeout: Duration,
) -> Result<ExecObservation, String> {
    run_policy_exec_from_adapter(
        session,
        exec_id,
        policy_exec_config(command_line, cwd.as_deref(), env, timeout_ms, None),
        timeout,
    )
}

#[cfg(windows)]
fn run_network_probe(
    state: &mut LiveHarnessState,
    exec_id: u32,
    endpoint: Option<&str>,
) -> Result<PolicyNetworkReport, String> {
    let session = state
        .session
        .as_mut()
        .ok_or_else(|| "live session unavailable".to_string())?;
    let mut args = vec!["network-policy-json"];
    if let Some(endpoint) = endpoint {
        args.push(endpoint);
    }
    let (disposition, stdout, stderr) = run_simple_probe_exec(session, exec_id, &args)?;
    if disposition != ExecDisposition::ExitCode(0) {
        return Err(format!(
            "network policy probe failed: disposition={disposition:?} stderr={:?}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    serde_json::from_slice(&stdout)
        .map_err(|error| format!("network policy probe returned invalid JSON: {error}"))
}

#[cfg(windows)]
fn ensure_policy_probe_capabilities(state: &mut LiveHarnessState) -> Result<(), String> {
    let session = state
        .session
        .as_mut()
        .ok_or_else(|| "live session unavailable".to_string())?;
    let (disposition, stdout, stderr) =
        run_simple_probe_exec(session, 1_390, &["capabilities-json"])?;
    if disposition != ExecDisposition::ExitCode(0) {
        let stderr_text = String::from_utf8_lossy(&stderr);
        if stderr_text.contains("unknown subcommand") {
            return Err(format!(
                "blocked stale-artifact diagnostic: nvx-agent-probe does not support `capabilities-json`; update staged probe artifact at {PROBE_PATH}"
            ));
        }
        return Err(format!(
            "policy probe capability check failed: disposition={disposition:?} stderr={stderr_text}"
        ));
    }
    let report: PolicyProbeCapabilitiesReport = serde_json::from_slice(&stdout).map_err(|error| {
        format!("policy probe capability check failed: capabilities payload is invalid JSON ({error})")
    })?;
    if report.version != POLICY_PROBE_CAPABILITY_VERSION {
        return Err(format!(
            "blocked stale-artifact diagnostic: nvx-agent-probe capability version mismatch (expected={}, actual={})",
            POLICY_PROBE_CAPABILITY_VERSION, report.version
        ));
    }
    let missing_commands = POLICY_REQUIRED_PROBE_COMMANDS
        .iter()
        .copied()
        .filter(|required| {
            !report
                .supported_commands
                .iter()
                .any(|seen| seen == required)
        })
        .collect::<Vec<_>>();
    if !missing_commands.is_empty() {
        return Err(format!(
            "blocked stale-artifact diagnostic: nvx-agent-probe lacks required policy subcommands [{}]",
            missing_commands.join(", ")
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn policy_live_result_from_error(error: String) -> PolicyLiveEvidence {
    if policy_error_is_infrastructure_blocker(&error) {
        policy_live_blocked(error)
    } else {
        PolicyLiveEvidence {
            positive_passed: false,
            negative_passed: false,
            blocked: false,
            evidence: Vec::new(),
            error: Some(error),
        }
    }
}

#[cfg(windows)]
fn policy_live_assertions(
    positive: Result<(), String>,
    negative: Result<(), String>,
    evidence: Vec<String>,
) -> PolicyLiveEvidence {
    let positive_failed_with_blocker = positive
        .as_ref()
        .err()
        .is_some_and(|error| policy_error_is_infrastructure_blocker(error));
    let negative_failed_with_blocker = negative
        .as_ref()
        .err()
        .is_some_and(|error| policy_error_is_infrastructure_blocker(error));
    let any_failed = positive.is_err() || negative.is_err();
    let all_failed_are_blockers = (positive.is_ok() || positive_failed_with_blocker)
        && (negative.is_ok() || negative_failed_with_blocker);

    let mut errors = Vec::new();
    if let Err(error) = &positive {
        errors.push(format!("positive assertion failed: {error}"));
    }
    if let Err(error) = &negative {
        errors.push(format!("negative assertion failed: {error}"));
    }
    let combined_error = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };
    let blocked = any_failed && all_failed_are_blockers;
    PolicyLiveEvidence {
        positive_passed: positive.is_ok(),
        negative_passed: negative.is_ok(),
        blocked,
        evidence,
        error: combined_error,
    }
}

#[cfg(windows)]
fn policy_live_blocked(error: String) -> PolicyLiveEvidence {
    PolicyLiveEvidence {
        positive_passed: false,
        negative_passed: false,
        blocked: true,
        evidence: Vec::new(),
        error: Some(error),
    }
}

#[cfg(windows)]
fn policy_error_is_infrastructure_blocker(error: &str) -> bool {
    if error.contains("teardown failed:") {
        return false;
    }
    error.contains("\"kind\":\"missing-prerequisite\"")
        || error.contains("blocked stale-artifact diagnostic")
        || error.contains("live WHP policy profiles require Windows")
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
    limits: ExecCollectionLimits,
) -> Result<ExecObservation, String> {
    let deadline = Instant::now() + timeout;
    let hard_deadline = Instant::now() + limits.max_duration;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut messages = Vec::new();
    let mut disposition = None;
    let mut termination = None;
    let mut stdout_chunk_max = 0_usize;
    let mut stderr_chunk_max = 0_usize;
    while Instant::now() < deadline {
        if Instant::now() >= hard_deadline {
            let _ = session.client.send_cancel_execution(exec_id);
            return Err(format!(
                "collection duration bound exceeded for exec {exec_id} after {:?}",
                limits.max_duration
            ));
        }
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
                    if collection_chunk_exceeds_bounds(
                        limits,
                        stdout.len(),
                        stderr.len(),
                        record.chunk.len(),
                        true,
                        messages.len().saturating_add(1),
                    ) {
                        let new_stdout = stdout.len().saturating_add(record.chunk.len());
                        let _ = session.client.send_cancel_execution(exec_id);
                        return Err(format!(
                            "collection bounds exceeded for exec {exec_id} (stdout={new_stdout}, stderr={}, messages={})",
                            stderr.len(),
                            messages.len().saturating_add(1)
                        ));
                    }
                    stdout_chunk_max = stdout_chunk_max.max(record.chunk.len());
                    stdout.extend_from_slice(&record.chunk);
                    messages.push(AgentControlMessage::StdoutChunk(record.clone()));
                }
                if auto_credit {
                    let _ = grant_stream(session, record.exec_id, StreamName::Stdout, 1);
                }
            }
            AgentControlMessage::StderrChunk(record) => {
                if record.exec_id == exec_id {
                    if collection_chunk_exceeds_bounds(
                        limits,
                        stdout.len(),
                        stderr.len(),
                        record.chunk.len(),
                        false,
                        messages.len().saturating_add(1),
                    ) {
                        let new_stderr = stderr.len().saturating_add(record.chunk.len());
                        let _ = session.client.send_cancel_execution(exec_id);
                        return Err(format!(
                            "collection bounds exceeded for exec {exec_id} (stdout={}, stderr={new_stderr}, messages={})",
                            stdout.len(),
                            messages.len().saturating_add(1)
                        ));
                    }
                    stderr_chunk_max = stderr_chunk_max.max(record.chunk.len());
                    stderr.extend_from_slice(&record.chunk);
                    messages.push(AgentControlMessage::StderrChunk(record.clone()));
                }
                if auto_credit {
                    let _ = grant_stream(session, record.exec_id, StreamName::Stderr, 1);
                }
            }
            AgentControlMessage::StdoutEof(record) => {
                if record.exec_id == exec_id {
                    if messages.len().saturating_add(1) > limits.max_messages {
                        let _ = session.client.send_cancel_execution(exec_id);
                        return Err(format!(
                            "collection message bound exceeded for exec {exec_id}"
                        ));
                    }
                    messages.push(AgentControlMessage::StdoutEof(record));
                }
            }
            AgentControlMessage::StderrEof(record) => {
                if record.exec_id == exec_id {
                    if messages.len().saturating_add(1) > limits.max_messages {
                        let _ = session.client.send_cancel_execution(exec_id);
                        return Err(format!(
                            "collection message bound exceeded for exec {exec_id}"
                        ));
                    }
                    messages.push(AgentControlMessage::StderrEof(record));
                }
            }
            AgentControlMessage::DescendantsCleaned { exec_id: cleaned } => {
                if cleaned == exec_id {
                    if messages.len().saturating_add(1) > limits.max_messages {
                        let _ = session.client.send_cancel_execution(exec_id);
                        return Err(format!(
                            "collection message bound exceeded for exec {exec_id}"
                        ));
                    }
                    messages.push(AgentControlMessage::DescendantsCleaned { exec_id: cleaned });
                }
            }
            AgentControlMessage::ExecTerminal {
                exec_id: terminal_exec_id,
                disposition: terminal_disposition,
                termination: terminal_termination,
            } => {
                if terminal_exec_id == exec_id {
                    if messages.len().saturating_add(1) > limits.max_messages {
                        let _ = session.client.send_cancel_execution(exec_id);
                        return Err(format!(
                            "collection message bound exceeded for exec {exec_id}"
                        ));
                    }
                    messages.push(AgentControlMessage::ExecTerminal {
                        exec_id: terminal_exec_id,
                        disposition: terminal_disposition,
                        termination: terminal_termination,
                    });
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
            _ => {}
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
fn enforce_tree_pid_capture_limit(
    session: &mut LiveWhpSession,
    exec_id: u32,
    observed_messages: usize,
    current_output_len: usize,
    incoming_stdout_chunk_len: usize,
) -> Result<(), String> {
    let next_size = current_output_len.saturating_add(incoming_stdout_chunk_len);
    if observed_messages > TREE_PID_CAPTURE_MAX_MESSAGES || next_size > TREE_PID_CAPTURE_MAX_BYTES {
        let _ = session.client.send_cancel_execution(exec_id);
        return Err(format!(
            "tree pid capture bounds exceeded for exec {exec_id} (bytes={next_size}, messages={observed_messages})"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn workload_fd_allowlist_ok(entries: &[ProbeFdEntry]) -> bool {
    if entries.len() != 3 {
        return false;
    }
    let mut seen = [false; 3];
    for entry in entries {
        let slot = match entry.fd {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => return false,
        };
        if seen[slot] {
            return false;
        }
        seen[slot] = true;
        if !stdio_target_allowlisted(&entry.target) {
            return false;
        }
    }
    seen.into_iter().all(|value| value)
}

#[cfg(windows)]
fn stdio_target_allowlisted(target: &str) -> bool {
    if target.contains("/proc/") || target.contains("/mnt/") || target.contains("ns:") {
        return false;
    }
    target.starts_with("pipe:[")
        || target.starts_with("/dev/null")
        || target.starts_with("/dev/pts/")
        || target == "/dev/console"
}

#[cfg(windows)]
fn supplementary_groups_are_empty(groups: &[u32]) -> bool {
    groups.is_empty()
}

#[cfg(windows)]
fn collection_chunk_exceeds_bounds(
    limits: ExecCollectionLimits,
    current_stdout_bytes: usize,
    current_stderr_bytes: usize,
    incoming_chunk_bytes: usize,
    is_stdout_chunk: bool,
    next_message_count: usize,
) -> bool {
    let next_stdout = if is_stdout_chunk {
        current_stdout_bytes.saturating_add(incoming_chunk_bytes)
    } else {
        current_stdout_bytes
    };
    let next_stderr = if is_stdout_chunk {
        current_stderr_bytes
    } else {
        current_stderr_bytes.saturating_add(incoming_chunk_bytes)
    };
    let next_total = next_stdout.saturating_add(next_stderr);
    next_stdout > limits.max_stdout_bytes
        || next_stderr > limits.max_stderr_bytes
        || next_total > limits.max_total_bytes
        || next_message_count > limits.max_messages
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
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::{HarnessBackend, HarnessMode};

    fn test_options(tag: &str) -> HarnessOptions {
        HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::LiveWhp,
            output_dir: std::env::temp_dir().join(format!(
                "agent-harness-live-lifecycle-{tag}-{}",
                std::process::id()
            )),
            launch_overrides: None,
        }
    }

    fn empty_state() -> LiveHarnessState {
        LiveHarnessState {
            run_key: None,
            init_error: None,
            first_failure: None,
            req1_evidence: vec!["req1 evidence".to_string()],
            session: None,
        }
    }

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

    #[test]
    fn req7_supplementary_groups_must_be_empty() {
        assert!(supplementary_groups_are_empty(&[]));
        assert!(!supplementary_groups_are_empty(&[123]));
        assert!(!supplementary_groups_are_empty(&[0]));
    }

    #[test]
    fn req8_fd_allowlist_rejects_unexpected_fd_and_host_paths() {
        let allowed = vec![
            ProbeFdEntry {
                fd: 0,
                target: "/dev/null".to_string(),
            },
            ProbeFdEntry {
                fd: 1,
                target: "pipe:[12345]".to_string(),
            },
            ProbeFdEntry {
                fd: 2,
                target: "/dev/pts/0".to_string(),
            },
        ];
        let extra_fd = vec![
            ProbeFdEntry {
                fd: 0,
                target: "/dev/null".to_string(),
            },
            ProbeFdEntry {
                fd: 1,
                target: "pipe:[12345]".to_string(),
            },
            ProbeFdEntry {
                fd: 5,
                target: "pipe:[99999]".to_string(),
            },
        ];
        let host_fd = vec![
            ProbeFdEntry {
                fd: 0,
                target: "/proc/1/ns/mnt".to_string(),
            },
            ProbeFdEntry {
                fd: 1,
                target: "pipe:[12345]".to_string(),
            },
            ProbeFdEntry {
                fd: 2,
                target: "/dev/pts/0".to_string(),
            },
        ];
        assert!(workload_fd_allowlist_ok(&allowed));
        assert!(!workload_fd_allowlist_ok(&extra_fd));
        assert!(!workload_fd_allowlist_ok(&host_fd));
    }

    #[test]
    fn collection_limits_fail_closed_on_flood_overflow() {
        let limits = ExecCollectionLimits::flood_probe(Duration::from_secs(10), 1024);
        assert!(!collection_chunk_exceeds_bounds(limits, 0, 0, 512, true, 1));
        assert!(collection_chunk_exceeds_bounds(
            limits,
            limits.max_stdout_bytes,
            0,
            1,
            true,
            1
        ));
        assert!(collection_chunk_exceeds_bounds(
            limits,
            0,
            0,
            1,
            true,
            limits.max_messages + 1
        ));
    }

    #[test]
    fn first_failure_blocks_later_scenarios_without_relaunch_and_tears_down_once() {
        let options = test_options("no-relaunch-after-failure");
        let mut state = empty_state();
        let launch_count = Cell::new(0_u32);
        let teardown_count = Cell::new(0_u32);
        let launched = Cell::new(false);

        let req1 = CANONICAL_SCENARIOS[0];
        let req2 = CANONICAL_SCENARIOS[1];
        let req3 = CANONICAL_SCENARIOS[2];

        let first = run_live_requirement_in_state(
            &mut state,
            &options,
            req1,
            &mut |_, _| {
                if !launched.get() {
                    launched.set(true);
                    launch_count.set(launch_count.get() + 1);
                }
                Ok(())
            },
            &mut |_, definition| {
                if definition.requirement_number == 1 {
                    pass_check(vec!["req1".to_string()])
                } else if definition.requirement_number == 2 {
                    fail_check("req02 failed".to_string())
                } else {
                    fail_check("unexpected scenario".to_string())
                }
            },
            &mut |_| {
                teardown_count.set(teardown_count.get() + 1);
                launched.set(false);
                Ok(())
            },
        );
        assert_eq!(first.check_status, EvidenceCheckStatus::Pass);

        let second = run_live_requirement_in_state(
            &mut state,
            &options,
            req2,
            &mut |_, _| {
                if !launched.get() {
                    launched.set(true);
                    launch_count.set(launch_count.get() + 1);
                }
                Ok(())
            },
            &mut |_, definition| {
                if definition.requirement_number == 2 {
                    fail_check("req02 failed".to_string())
                } else {
                    fail_check("unexpected scenario".to_string())
                }
            },
            &mut |_| {
                teardown_count.set(teardown_count.get() + 1);
                launched.set(false);
                Ok(())
            },
        );
        assert_eq!(second.check_status, EvidenceCheckStatus::Fail);

        let third = run_live_requirement_in_state(
            &mut state,
            &options,
            req3,
            &mut |_, _| {
                if !launched.get() {
                    launched.set(true);
                    launch_count.set(launch_count.get() + 1);
                }
                Ok(())
            },
            &mut |_, _| pass_check(vec!["unexpected".to_string()]),
            &mut |_| {
                teardown_count.set(teardown_count.get() + 1);
                launched.set(false);
                Ok(())
            },
        );
        assert_eq!(third.check_status, EvidenceCheckStatus::NotRun);
        assert!(
            third
                .error
                .as_deref()
                .is_some_and(|error| error.contains("skipped after req02 failed"))
        );
        assert_eq!(launch_count.get(), 1);
        assert_eq!(teardown_count.get(), 1);
    }

    #[test]
    fn successful_last_scenario_tears_down_exactly_once() {
        let options = test_options("success-final-teardown");
        let mut state = empty_state();
        let launch_count = Cell::new(0_u32);
        let teardown_count = Cell::new(0_u32);
        let launched = Cell::new(false);

        for definition in CANONICAL_SCENARIOS {
            let outcome = run_live_requirement_in_state(
                &mut state,
                &options,
                definition,
                &mut |_, _| {
                    if !launched.get() {
                        launched.set(true);
                        launch_count.set(launch_count.get() + 1);
                    }
                    Ok(())
                },
                &mut |_, _| pass_check(vec!["ok".to_string()]),
                &mut |_| {
                    teardown_count.set(teardown_count.get() + 1);
                    launched.set(false);
                    Ok(())
                },
            );
            assert_eq!(
                outcome.check_status,
                EvidenceCheckStatus::Pass,
                "expected pass for req{:02}",
                definition.requirement_number
            );
        }

        assert_eq!(launch_count.get(), 1);
        assert_eq!(teardown_count.get(), 1);
    }

    #[test]
    fn req10_network_validation_enforces_mode_specific_invariants() {
        let no_nic = NetworkStatus {
            mode: NetworkMode::NoNic,
            setup_state: NetworkSetupState::Ready,
            interface: None,
            default_gateway: None,
            dns: agent_protocol::DnsStatus {
                ready: true,
                servers: vec![],
            },
            failure: None,
        };
        let portable = NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            setup_state: NetworkSetupState::Ready,
            interface: Some(agent_protocol::NetworkInterfaceStatus {
                name: "eth0".to_string(),
                index: 3,
                link_state: agent_protocol::NetworkLinkState::Up,
                addresses: vec!["10.0.0.2".to_string(), "2001:db8::2".to_string()],
                default_route: Some("10.0.0.1".to_string()),
            }),
            default_gateway: Some("10.0.0.1".to_string()),
            dns: agent_protocol::DnsStatus {
                ready: true,
                servers: vec!["10.0.0.53".to_string()],
            },
            failure: None,
        };
        let malformed_portable = NetworkStatus {
            dns: agent_protocol::DnsStatus {
                ready: true,
                servers: vec!["not-an-ip".to_string()],
            },
            ..portable.clone()
        };
        assert!(validate_live_network_status(&no_nic).is_ok());
        assert!(validate_live_network_status(&portable).is_ok());
        assert!(validate_live_network_status(&malformed_portable).is_err());
    }

    #[test]
    fn req12_reconnect_replacement_connect_runs_after_old_drop() {
        #[derive(Clone)]
        struct DropTracked {
            dropped: Arc<AtomicBool>,
            label: &'static str,
        }

        impl Drop for DropTracked {
            fn drop(&mut self) {
                if self.label == "old" {
                    self.dropped.store(true, Ordering::SeqCst);
                }
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let mut slot = DropTracked {
            dropped: Arc::clone(&dropped),
            label: "old",
        };
        let placeholder = DropTracked {
            dropped: Arc::clone(&dropped),
            label: "placeholder",
        };
        let observation = replace_slot_after_drop(&mut slot, placeholder, || {
            if !dropped.load(Ordering::SeqCst) {
                return Err(
                    "old client handle was not dropped before reconnect connect".to_string()
                );
            }
            Ok(DropTracked {
                dropped: Arc::clone(&dropped),
                label: "replacement",
            })
        })
        .expect("replace should succeed");
        assert!(observation.old_handle_closed_before_connect);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn req12_next_launch_nonce_changes_deterministically() {
        let nonce = [7_u8; 16];
        let next = next_launch_nonce(nonce);
        assert_ne!(next, nonce);
        assert_eq!(next[0], nonce[0] ^ 0xA5);
        assert_eq!(next[15], nonce[15] ^ 0x5A);
        assert_eq!(next[1..15], nonce[1..15]);
    }

    #[test]
    fn source_no_longer_contains_hardcoded_req10_to_req12_failure_arm() {
        let source = include_str!("scenarios.rs");
        let banned = ["live scenario invariant", " check did not pass"].concat();
        assert!(
            !source.contains(&banned),
            "req10-req12 hardcoded live failure message must be removed"
        );
        assert!(source.contains("10 => run_req10_network_status"));
        assert!(source.contains("11 => run_req11_health_quiesce_resume_shutdown"));
        assert!(source.contains("12 => run_req12_channel_loss_generation"));
    }

    #[test]
    #[cfg(windows)]
    fn channel_close_classifier_accepts_only_closed_or_explicit_io_kinds() {
        let accepted = [
            ClientError::Control(SessionError::Closed),
            ClientError::Control(SessionError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            ))),
            ClientError::ControlOperation {
                operation: "poll",
                source: SessionError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            },
            ClientError::ControlOperation {
                operation: "poll",
                source: SessionError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            },
        ];
        for error in accepted {
            assert!(
                is_expected_channel_close_error(&error),
                "expected accepted closure error: {error:?}"
            );
        }

        let rejected = [
            ClientError::Control(SessionError::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
            ClientError::Control(SessionError::Protocol(
                agent_protocol::control_session::ProtocolError::InvalidMagic,
            )),
            ClientError::Control(SessionError::SequenceMismatch {
                expected: 5,
                actual: 9,
            }),
            ClientError::Control(SessionError::SessionIdentityMismatch),
            ClientError::Control(SessionError::UnexpectedRecordType(
                agent_protocol::control_session::RecordType::Data,
            )),
            ClientError::Control(SessionError::DeadlineExceeded("control channel close")),
            ClientError::Protocol("unexpected parse path".to_string()),
            ClientError::Timeout("poll"),
        ];
        for error in rejected {
            assert!(
                !is_expected_channel_close_error(&error),
                "expected non-closure error rejection: {error:?}"
            );
        }
    }

    #[test]
    fn policy_profile_infrastructure_blockers_map_to_blocked_status() {
        assert!(policy_error_is_infrastructure_blocker(
            "{\"kind\":\"missing-prerequisite\",\"field\":\"openvmm_exe\"}"
        ));
        assert!(policy_error_is_infrastructure_blocker(
            "blocked stale-artifact diagnostic: nvx-agent-probe does not support capabilities-json"
        ));
        assert!(policy_error_is_infrastructure_blocker(
            "blocked stale-artifact diagnostic: nvx-agent-probe lacks required policy subcommands [policy-network]"
        ));
        assert!(policy_error_is_infrastructure_blocker(
            "live WHP policy profiles require Windows"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "teardown failed: live session VM teardown failed: exit timeout"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "blocked stale-artifact diagnostic: nvx-agent-probe capability version mismatch; teardown failed: live session VM teardown failed: exit timeout"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "live WHP bootstrap failed: failed to connect control pipe: access denied"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "launch authentication failed: protocol mismatch"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "configure session failed: InvalidLifecycleTransition"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "wait_ready failed: timed out waiting for ready"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "health request failed: stale session identity"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "portable-network positive probe failed: report mismatch"
        ));
        assert!(!policy_error_is_infrastructure_blocker(
            "policy probe capability check failed: capabilities payload is invalid JSON (expected value at line 1 column 1)"
        ));
    }

    #[test]
    fn policy_live_assertions_status_combination_only_blocks_for_all_blocker_failures() {
        let semantic_fail =
            Err("portable-network positive probe failed: report mismatch".to_string());
        let blocker_fail = Err(
            "blocked stale-artifact diagnostic: nvx-agent-probe capability version mismatch"
                .to_string(),
        );

        let mixed = policy_live_assertions(
            semantic_fail.clone(),
            blocker_fail.clone(),
            vec!["mixed".to_string()],
        );
        assert!(!mixed.blocked);
        assert!(!mixed.positive_passed);
        assert!(!mixed.negative_passed);

        let single_blocker = policy_live_assertions(Ok(()), blocker_fail.clone(), vec![]);
        assert!(single_blocker.blocked);
        assert!(single_blocker.positive_passed);
        assert!(!single_blocker.negative_passed);

        let both_blocker = policy_live_assertions(blocker_fail.clone(), blocker_fail, vec![]);
        assert!(both_blocker.blocked);
        assert!(!both_blocker.positive_passed);
        assert!(!both_blocker.negative_passed);

        let single_semantic = policy_live_assertions(semantic_fail, Ok(()), vec![]);
        assert!(!single_semantic.blocked);
        assert!(!single_semantic.positive_passed);
        assert!(single_semantic.negative_passed);
    }

    #[test]
    fn policy_live_result_from_invalid_capabilities_json_is_non_blocking_failure() {
        let result = policy_live_result_from_error(
            "policy probe capability check failed: capabilities payload is invalid JSON (expected value at line 1 column 1)"
                .to_string(),
        );
        assert!(!result.blocked);
        assert!(!result.positive_passed);
        assert!(!result.negative_passed);
        assert!(result.error.is_some());
    }

    #[test]
    fn policy_teardown_failure_forces_non_blocked_failure_status() {
        let mut result = policy_live_blocked(
            "blocked stale-artifact diagnostic: nvx-agent-probe lacks required policy subcommands [policy-network]"
                .to_string(),
        );
        append_policy_teardown_failure(
            &mut result,
            "live session VM teardown failed: exit timeout".to_string(),
        );
        assert!(!result.blocked);
        assert!(!result.positive_passed);
        assert!(!result.negative_passed);
        assert!(result.error.as_deref().is_some_and(|error| {
            error.contains("blocked stale-artifact diagnostic")
                && error.contains("teardown failed: live session VM teardown failed: exit timeout")
        }));
    }
}
