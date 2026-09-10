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
};
#[cfg(windows)]
use agent_protocol::{PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES, PROTOCOL_VERSION};

const LIVE_TIMEOUT: Duration = Duration::from_secs(8);
#[cfg(windows)]
const PROBE_PATH: &str = "/sbin/nvx-agent-probe";

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
    baseline_ready: ReadyStatus,
    baseline_health: agent_protocol::messages::HealthStatus,
}

#[cfg(windows)]
struct ExecObservation {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    messages: Vec<AgentControlMessage>,
    disposition: Option<ExecDisposition>,
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
        7..=12 => fail_check(format!(
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
        let overrides = options.launch_overrides.clone().unwrap_or_default();
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
        let root = CanonicalHostMappingRoot::parse("/sandbox-root".to_string())
            .map_err(|error| format!("invalid canonical root for req1 probe: {error}"))?;
        let containment = MappingContainmentPolicy {
            symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        };
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
                mappings: vec![],
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
            baseline_ready: ready_status,
            baseline_health: health_status,
        });
        Ok(())
    }
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
            mappings: vec![],
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
            mappings: vec![],
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
            mappings: vec![],
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
    std::thread::sleep(Duration::from_millis(200));
    let health_ok = match session.client.request_health(LIVE_TIMEOUT) {
        Ok(AgentControlMessage::Health(status)) => status.active_exec_id == Some(exec_id),
        _ => false,
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
        && terminal_order_ok(
            &stdin_observed.messages,
            stdin_exec,
            ExecDisposition::ExitCode(0),
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
            "normal exit, signaled exit, graceful cancel, forced-cancel escalation, and timeout dispositions were all observed".to_string(),
            "each terminal arrived exactly once and only after stdout/stderr EOF plus descendants-cleaned; child+grandchild PIDs were gone before cancel/timeout completion".to_string(),
        ])
    } else {
        fail_check("terminal semantics invariants failed".to_string())
    }
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
        && terminal_order_ok(&observed.messages, exec_id, expected))
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
        || !terminal_order_ok(&observed.messages, exec_id, ExecDisposition::Cancelled)
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
        || !terminal_order_ok(&observed.messages, exec_id, ExecDisposition::TimedOut)
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
            } => {
                messages.push(AgentControlMessage::ExecTerminal {
                    exec_id: terminal_exec_id,
                    disposition: terminal_disposition,
                });
                if terminal_exec_id == exec_id {
                    disposition = Some(terminal_disposition);
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
        stdout_chunk_max,
        stderr_chunk_max,
    })
}

#[cfg(windows)]
fn terminal_order_ok(
    messages: &[AgentControlMessage],
    exec_id: u32,
    expected: ExecDisposition,
) -> bool {
    let terminal_positions: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter_map(|(index, message)| match message {
            AgentControlMessage::ExecTerminal {
                exec_id: id,
                disposition,
            } if *id == exec_id && *disposition == expected => Some(index),
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
