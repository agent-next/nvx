use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
use agent_protocol::messages::{
    AgentControlMessage, BuildStatus, ExecDisposition, FlowCreditRequest, IsolationStatus,
    LaunchIdentity, NetworkMode, NetworkStatus, SERVICE_IDENTITY, WorkloadIdentityStatus,
};
use agent_protocol::service::{
    AuthenticateChannelRequest, CancelReason, ConfigureSessionRequest, CreateProcessRequest,
    FilesystemStatus, LaunchBinding, MxcControlService, ProcessSupervisor, ServiceError,
    ServiceErrorCode, SessionConfiguration, SupervisorEvent, WaitReadyRequest,
};
use agent_protocol::state::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};

const REPORT_SCHEMA: &str = "nvx.mxc.agent.harness.report.v1";
const REPORT_VERSION: u32 = 1;
const MAX_DIAGNOSTIC_LINES: usize = 200;
const DEFAULT_IMAGE_VERSION: &str = "mxc-prototype-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessMode {
    LiveWhp,
    StaticOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessBackend {
    Whp,
}

impl HarnessBackend {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "whp" => Ok(Self::Whp),
            other => Err(format!(
                "unsupported backend {other:?}; this harness supports only whp"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Whp => "whp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScenarioDefinition {
    requirement_number: u8,
    id: &'static str,
    name: &'static str,
}

const CANONICAL_SCENARIOS: [ScenarioDefinition; 12] = [
    ScenarioDefinition {
        requirement_number: 1,
        id: "01-launch-readiness",
        name: "launch readiness",
    },
    ScenarioDefinition {
        requirement_number: 2,
        id: "02-immutable-config",
        name: "immutable config",
    },
    ScenarioDefinition {
        requirement_number: 3,
        id: "03-repeated-exec",
        name: "repeated exec",
    },
    ScenarioDefinition {
        requirement_number: 4,
        id: "04-binary-stream-separation",
        name: "separate binary streams",
    },
    ScenarioDefinition {
        requirement_number: 5,
        id: "05-bounded-flow-backpressure",
        name: "bounded flow and backpressure",
    },
    ScenarioDefinition {
        requirement_number: 6,
        id: "06-terminal-ordering-cleanup",
        name: "terminal semantics after cleanup",
    },
    ScenarioDefinition {
        requirement_number: 7,
        id: "07-fixed-mxc-identity",
        name: "fixed mxc identity",
    },
    ScenarioDefinition {
        requirement_number: 8,
        id: "08-full-isolation-verification",
        name: "full isolation verification",
    },
    ScenarioDefinition {
        requirement_number: 9,
        id: "09-mapping-containment",
        name: "mapping containment and mutation checks",
    },
    ScenarioDefinition {
        requirement_number: 10,
        id: "10-network-status",
        name: "network status",
    },
    ScenarioDefinition {
        requirement_number: 11,
        id: "11-health-quiesce-resume-shutdown",
        name: "health quiesce resume shutdown",
    },
    ScenarioDefinition {
        requirement_number: 12,
        id: "12-channel-loss-generation",
        name: "channel-loss cleanup and new generation",
    },
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioStatus {
    Pass,
    Fail,
    Unsupported,
    Skipped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioResult {
    pub requirement_number: u8,
    pub id: String,
    pub name: String,
    pub status: ScenarioStatus,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessReport {
    pub schema: String,
    pub version: u32,
    pub mode: HarnessMode,
    pub platform: String,
    pub backend: String,
    pub service_identity: String,
    pub protocol_version: u32,
    pub build_identity: String,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub scenarios: Vec<ScenarioResult>,
    pub artifact_paths: BTreeMap<String, String>,
    pub diagnostics_tail: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct HarnessOptions {
    pub backend: HarnessBackend,
    pub mode: HarnessMode,
    pub output_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct HarnessRun {
    pub report: HarnessReport,
    pub report_path: PathBuf,
    pub diagnostics_path: PathBuf,
}

impl HarnessRun {
    pub fn exit_code(&self) -> ExitCode {
        if has_all_scenarios_passed(&self.report) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

pub fn execute_harness(options: HarnessOptions) -> Result<HarnessRun, String> {
    validate_canonical_scenarios()?;
    fs::create_dir_all(&options.output_dir).map_err(|error| {
        format!(
            "failed to create harness output directory {}: {error}",
            options.output_dir.display()
        )
    })?;

    let mut diagnostics = Diagnostics::new(MAX_DIAGNOSTIC_LINES);
    diagnostics.push(format!(
        "starting deterministic harness mode={:?} backend={}",
        options.mode,
        options.backend.as_str()
    ));
    let started = unix_ms_now();
    let mut scenarios = Vec::with_capacity(CANONICAL_SCENARIOS.len());
    let mut stop_after: Option<String> = None;
    for definition in CANONICAL_SCENARIOS {
        let scenario_start = Instant::now();
        let mut result = if let Some(reason) = stop_after.as_ref() {
            ScenarioResult {
                requirement_number: definition.requirement_number,
                id: definition.id.to_string(),
                name: definition.name.to_string(),
                status: ScenarioStatus::Skipped,
                duration_ms: 0,
                error: Some(format!("skipped because a prior scenario failed: {reason}")),
                evidence: vec![],
            }
        } else {
            run_scenario(&options, definition, &mut diagnostics)
        };
        result.duration_ms = scenario_start
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        if stop_after.is_none() && result.status != ScenarioStatus::Pass {
            stop_after = Some(format!(
                "{} ({}) finished with {:?}",
                result.id, result.name, result.status
            ));
            diagnostics.push(format!("halting subsequent scenarios after {}", result.id));
        }
        scenarios.push(result);
    }

    let finished = unix_ms_now();
    diagnostics.push(format!(
        "completed scenarios={} passing={}",
        scenarios.len(),
        scenarios
            .iter()
            .filter(|scenario| scenario.status == ScenarioStatus::Pass)
            .count()
    ));

    let mut report = HarnessReport {
        schema: REPORT_SCHEMA.to_string(),
        version: REPORT_VERSION,
        mode: options.mode,
        platform: std::env::consts::OS.to_string(),
        backend: options.backend.as_str().to_string(),
        service_identity: SERVICE_IDENTITY.to_string(),
        protocol_version: PROTOCOL_VERSION,
        build_identity: env!("CARGO_PKG_VERSION").to_string(),
        started_unix_ms: started,
        finished_unix_ms: finished,
        scenarios,
        artifact_paths: BTreeMap::new(),
        diagnostics_tail: diagnostics.snapshot(),
    };

    let diagnostics_path = options.output_dir.join("diagnostics.log");
    let report_path = options.output_dir.join("report.json");
    write_text_atomic(&diagnostics_path, &report.diagnostics_tail.join("\n"))?;
    report
        .artifact_paths
        .insert("report".to_string(), report_path.display().to_string());
    report.artifact_paths.insert(
        "diagnostics".to_string(),
        diagnostics_path.display().to_string(),
    );
    write_json_atomic(&report_path, &report)?;

    Ok(HarnessRun {
        report,
        report_path,
        diagnostics_path,
    })
}

fn run_scenario(
    options: &HarnessOptions,
    definition: ScenarioDefinition,
    diagnostics: &mut Diagnostics,
) -> ScenarioResult {
    diagnostics.push(format!(
        "running {} {}",
        definition.requirement_number, definition.id
    ));
    let outcome = match options.mode {
        HarnessMode::StaticOnly => run_static_scenario(definition),
        HarnessMode::LiveWhp => run_live_scenario(definition),
    };
    diagnostics.push(format!(
        "scenario {} => {:?}",
        definition.id, outcome.status
    ));
    outcome
}

fn run_live_scenario(definition: ScenarioDefinition) -> ScenarioResult {
    #[cfg(not(windows))]
    {
        if definition.requirement_number == 1 {
            return unsupported(definition, "live WHP harness requires Windows host APIs");
        }
        skipped(definition, "live run blocked by Windows prerequisite")
    }
    #[cfg(windows)]
    {
        let invariant = crate::windows_security::validate_live_security_prerequisites();
        if let Err(error) = invariant {
            if definition.requirement_number == 1 {
                return unsupported(definition, &error);
            }
            return skipped(definition, "launch prerequisites failed in scenario 1");
        }
        fail(
            definition,
            "live scenario execution is not available in this environment; rerun with --static-only for deterministic in-process coverage",
        )
    }
}

fn run_static_scenario(definition: ScenarioDefinition) -> ScenarioResult {
    match definition.requirement_number {
        1 => scenario_launch_readiness(definition),
        2 => scenario_immutable_configuration(definition),
        3 => scenario_repeated_exec(definition),
        4 => scenario_binary_stream_separation(definition),
        5 => scenario_backpressure_record_cap(definition),
        6 => scenario_terminal_semantics(definition),
        7 => scenario_fixed_identity(definition),
        8 => scenario_isolation(definition),
        9 => scenario_mapping_containment(definition),
        10 => scenario_network_status(definition),
        11 => scenario_health_lifecycle(definition),
        12 => scenario_channel_loss_cleanup(definition),
        _ => fail(definition, "unknown requirement number"),
    }
}

fn scenario_launch_readiness(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = MxcControlService::new(sample_binding(7, 44));
    let capabilities = service.get_capabilities();
    let auth = service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some("10.0.0.2/24".to_string()),
        },
    );
    if let Err(error) = auth {
        return fail(definition, &format!("authenticate_channel failed: {error}"));
    }
    if let Err(error) = service.configure_session(configure_request()) {
        return fail(definition, &format!("configure_session failed: {error}"));
    }
    let wrong_nonce = WaitReadyRequest {
        launch: LaunchIdentity {
            generation: 7,
            nonce: [9; 16],
        },
        ..wait_ready_request()
    };
    let wrong_nonce_rejected = matches!(
        service.wait_ready(wrong_nonce),
        Err(ServiceError {
            code: ServiceErrorCode::LaunchNonceMismatch,
            ..
        })
    );
    let first = service.wait_ready(wait_ready_request());
    let second = service.wait_ready(wait_ready_request());
    let passed = wrong_nonce_rejected
        && capabilities.protocol_version == PROTOCOL_VERSION
        && capabilities
            .available_operations
            .iter()
            .any(|name| name == "WaitReady")
        && first.is_ok()
        && second.is_ok()
        && first == second;
    if passed {
        pass(
            definition,
            vec![
                "wait_ready rejects wrong launch nonce".to_string(),
                "wait_ready remains level-triggered across repeated calls".to_string(),
            ],
        )
    } else {
        fail(definition, "launch-bound readiness invariants failed")
    }
}

fn scenario_immutable_configuration(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = MxcControlService::new(sample_binding(7, 44));
    if let Err(error) = service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    ) {
        return fail(definition, &format!("authenticate_channel failed: {error}"));
    }
    if let Err(error) = service.configure_session(configure_request()) {
        return fail(
            definition,
            &format!("first configure_session failed: {error}"),
        );
    }
    let replay_without_flag = service.configure_session(configure_request());
    let replay_with_flag = service.configure_session(ConfigureSessionRequest {
        idempotent_replay: true,
        ..configure_request()
    });
    let mut conflicting = ConfigureSessionRequest {
        idempotent_replay: true,
        ..configure_request()
    };
    conflicting.configuration.filesystem.detail = "mutated".to_string();
    let conflicting_result = service.configure_session(conflicting);
    let passed = matches!(
        replay_without_flag,
        Err(ServiceError {
            code: ServiceErrorCode::ConfigurationConflict,
            ..
        })
    ) && replay_with_flag.is_ok()
        && matches!(
            conflicting_result,
            Err(ServiceError {
                code: ServiceErrorCode::ConfigurationConflict,
                ..
            })
        );
    if passed {
        pass(
            definition,
            vec![
                "configure_session accepts exact idempotent replay only".to_string(),
                "mutated replay is rejected with ConfigurationConflict".to_string(),
            ],
        )
    } else {
        fail(definition, "immutable configure_session checks failed")
    }
}

fn scenario_repeated_exec(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = activated_service();
    let mut supervisor = FakeSupervisor::default();
    let mut outcomes = Vec::new();
    for (exec_id, exit_code) in [(300_u32, 10_i32), (301_u32, 11_i32), (302_u32, 12_i32)] {
        supervisor.plan_exec(
            exec_id,
            vec![
                SupervisorEvent::StdoutEof,
                SupervisorEvent::StderrEof,
                SupervisorEvent::Exited(exit_code),
                SupervisorEvent::DescendantsCleaned,
            ],
        );
    }
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id: 300,
            argv: vec!["/bin/true".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(
            definition,
            &format!("create_process for exec 300 failed: {error}"),
        );
    }
    let overlap = service.create_process(
        CreateProcessRequest {
            exec_id: 399,
            argv: vec!["/bin/true".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    );
    let overlap_rejected = matches!(
        overlap,
        Err(ServiceError {
            code: ServiceErrorCode::WorkloadBusy,
            ..
        })
    );
    if let Err(error) = grant_all_stream_credits(&mut service, 300) {
        return fail(definition, &error);
    }
    match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => outcomes.push(first_terminal_disposition(&messages)),
        Err(error) => return fail(definition, &error),
    }

    for exec_id in [301_u32, 302_u32] {
        if let Err(error) = service.create_process(
            CreateProcessRequest {
                exec_id,
                argv: vec!["/bin/true".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        ) {
            return fail(
                definition,
                &format!("create_process for exec {exec_id} failed: {error}"),
            );
        }
        if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
            return fail(definition, &error);
        }
        match collect_exec_messages(&mut service, &mut supervisor) {
            Ok(messages) => outcomes.push(first_terminal_disposition(&messages)),
            Err(error) => return fail(definition, &error),
        }
    }

    let passed = overlap_rejected
        && outcomes
            == vec![
                Some(ExecDisposition::ExitCode(10)),
                Some(ExecDisposition::ExitCode(11)),
                Some(ExecDisposition::ExitCode(12)),
            ];
    if passed {
        pass(
            definition,
            vec![
                "one active execution enforced with WorkloadBusy".to_string(),
                "sequential executions observed deterministic terminal dispositions".to_string(),
            ],
        )
    } else {
        fail(definition, "sequential exec invariants failed")
    }
}

fn scenario_binary_stream_separation(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = activated_service();
    let mut supervisor = FakeSupervisor::default();
    let exec_id = 401_u32;
    supervisor.plan_exec(
        exec_id,
        vec![
            SupervisorEvent::StdoutChunk(vec![b'A', 0, b'B', 255, b'C']),
            SupervisorEvent::StderrChunk(vec![b'X', 0, b'Y', 254, b'Z']),
            SupervisorEvent::StdoutEof,
            SupervisorEvent::StderrEof,
            SupervisorEvent::Exited(0),
            SupervisorEvent::DescendantsCleaned,
        ],
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec!["/bin/echo".to_string(), "binary".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(definition, &format!("create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
        return fail(definition, &error);
    }
    let messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return fail(definition, &error),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for message in &messages {
        match message {
            AgentControlMessage::StdoutChunk(record) => stdout.extend_from_slice(&record.chunk),
            AgentControlMessage::StderrChunk(record) => stderr.extend_from_slice(&record.chunk),
            _ => {}
        }
    }
    if stdout == vec![b'A', 0, b'B', 255, b'C'] && stderr == vec![b'X', 0, b'Y', 254, b'Z'] {
        pass(
            definition,
            vec![
                "stdout bytes preserved with embedded NUL and 0xFF".to_string(),
                "stderr bytes preserved independently with embedded NUL and 0xFE".to_string(),
            ],
        )
    } else {
        fail(definition, "binary stream separation check failed")
    }
}

fn scenario_backpressure_record_cap(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = activated_service();
    let mut supervisor = FakeSupervisor::default();
    let exec_id = 501_u32;
    supervisor.plan_exec(exec_id, vec![SupervisorEvent::StdoutChunk(vec![1_u8])]);
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec!["/bin/echo".to_string(), "backpressure".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(definition, &format!("create_process failed: {error}"));
    }
    let credit_exhausted = matches!(
        service.pump_supervisor(&mut supervisor),
        Err(ServiceError {
            code: ServiceErrorCode::LifecycleError,
            ..
        })
    );
    if !credit_exhausted {
        return fail(
            definition,
            "expected stdout flow-credit exhaustion before any stdout credits were granted",
        );
    }

    let mut service = activated_service();
    let mut supervisor = FakeSupervisor::default();
    let exec_id = 502_u32;
    supervisor.plan_exec(
        exec_id,
        vec![SupervisorEvent::StdoutChunk(vec![
            7_u8;
            agent_protocol::PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES
                + 1
        ])],
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec!["/bin/echo".to_string(), "oversized".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(definition, &format!("create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
        return fail(definition, &error);
    }
    let oversized_chunk_rejected = matches!(
        service.pump_supervisor(&mut supervisor),
        Err(ServiceError {
            code: ServiceErrorCode::StreamChunkTooLarge,
            ..
        })
    );

    let mut service = activated_service();
    let mut supervisor = FakeSupervisor::default();
    let exec_id = 503_u32;
    supervisor.plan_exec(
        exec_id,
        vec![
            SupervisorEvent::StdoutChunk(vec![
                2_u8;
                agent_protocol::PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES
            ]),
            SupervisorEvent::StdoutEof,
            SupervisorEvent::StderrEof,
            SupervisorEvent::Exited(0),
            SupervisorEvent::DescendantsCleaned,
        ],
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec!["/bin/cat".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(definition, &format!("create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
        return fail(definition, &error);
    }
    if let Err(error) = service.grant_flow_credits(FlowCreditRequest {
        exec_id,
        stream: agent_protocol::messages::StreamName::Stdin,
        credits: 1,
    }) {
        return fail(definition, &format!("grant stdin credits failed: {error}"));
    }
    if let Err(error) = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id,
            sequence: 0,
            chunk: vec![3_u8; agent_protocol::PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES],
        },
        &mut supervisor,
    ) {
        return fail(
            definition,
            &format!("max-sized stdin chunk failed: {error}"),
        );
    }
    let queued_limit_enforced = matches!(
        service.stdin_chunk(
            agent_protocol::StdinChunkRecord {
                exec_id,
                sequence: 1,
                chunk: vec![4_u8; 1],
            },
            &mut supervisor,
        ),
        Err(ServiceError {
            code: ServiceErrorCode::Backpressure,
            ..
        })
    );
    if let Err(error) = collect_exec_messages(&mut service, &mut supervisor) {
        return fail(definition, &error);
    }
    let health_responsive = service.health().configured;

    if oversized_chunk_rejected && queued_limit_enforced && health_responsive {
        pass(
            definition,
            vec![
                "stdout requires granted flow credits".to_string(),
                "stream chunk size never exceeds protocol-safe cap".to_string(),
                "stdin queue enforces bounded byte cap".to_string(),
            ],
        )
    } else {
        fail(
            definition,
            "backpressure/record-cap invariants failed for deterministic fake runtime",
        )
    }
}

fn scenario_terminal_semantics(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = activated_service();
    let mut supervisor = FakeSupervisor::default();

    let normal_exec = 601_u32;
    supervisor.plan_exec(
        normal_exec,
        vec![
            SupervisorEvent::StdoutChunk(vec![b'o', b'k', b'\n']),
            SupervisorEvent::StdoutEof,
            SupervisorEvent::StderrEof,
            SupervisorEvent::Exited(0),
            SupervisorEvent::DescendantsCleaned,
        ],
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id: normal_exec,
            argv: vec!["/bin/true".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(
            definition,
            &format!("normal create_process failed: {error}"),
        );
    }
    if let Err(error) = grant_all_stream_credits(&mut service, normal_exec) {
        return fail(definition, &error);
    }
    let normal_messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return fail(definition, &error),
    };
    let normal_ok = terminal_after_cleanup(&normal_messages, ExecDisposition::ExitCode(0));

    let cancelled_exec = 602_u32;
    supervisor.plan_exec(
        cancelled_exec,
        vec![
            SupervisorEvent::StdoutEof,
            SupervisorEvent::StderrEof,
            SupervisorEvent::DescendantsCleaned,
            SupervisorEvent::Exited(0),
        ],
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id: cancelled_exec,
            argv: vec!["/bin/sleep".to_string(), "10".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return fail(
            definition,
            &format!("cancel create_process failed: {error}"),
        );
    }
    if let Err(error) = grant_all_stream_credits(&mut service, cancelled_exec) {
        return fail(definition, &error);
    }
    if let Err(error) =
        service.cancel_exec(cancelled_exec, CancelReason::Cancelled, &mut supervisor)
    {
        return fail(definition, &format!("cancel_exec failed: {error}"));
    }
    let cancelled_messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return fail(definition, &error),
    };
    let cancelled_ok = terminal_after_cleanup(&cancelled_messages, ExecDisposition::Cancelled);

    let timeout_exec = 603_u32;
    supervisor.plan_exec(
        timeout_exec,
        vec![
            SupervisorEvent::StdoutEof,
            SupervisorEvent::StderrEof,
            SupervisorEvent::DescendantsCleaned,
            SupervisorEvent::Exited(0),
        ],
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id: timeout_exec,
            argv: vec!["/bin/sleep".to_string(), "10".to_string()],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: Some(50),
        },
        &mut supervisor,
    ) {
        return fail(
            definition,
            &format!("timeout create_process failed: {error}"),
        );
    }
    if let Err(error) = grant_all_stream_credits(&mut service, timeout_exec) {
        return fail(definition, &error);
    }
    if let Err(error) = service.cancel_exec(timeout_exec, CancelReason::TimedOut, &mut supervisor) {
        return fail(definition, &format!("timeout cancel_exec failed: {error}"));
    }
    let timeout_messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return fail(definition, &error),
    };
    let timeout_ok = terminal_after_cleanup(&timeout_messages, ExecDisposition::TimedOut);

    if normal_ok && cancelled_ok && timeout_ok {
        pass(
            definition,
            vec![
                "normal, cancelled, and timed-out dispositions observed".to_string(),
                "terminal event emitted only after stdout/stderr EOF and descendant cleanup"
                    .to_string(),
            ],
        )
    } else {
        fail(definition, "terminal ordering invariants failed")
    }
}

fn scenario_fixed_identity(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = configured_runtime_service();
    let ready = match service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    ) {
        Ok(status) => status,
        Err(error) => return fail(definition, &format!("authenticate_channel failed: {error}")),
    };
    if ready.workload_identity == WorkloadIdentityStatus::mxc_fixed() {
        pass(
            definition,
            vec![
                format!(
                    "identity user={} uid={}",
                    ready.workload_identity.user, ready.workload_identity.uid
                ),
                format!(
                    "identity group={} gid={}",
                    ready.workload_identity.group, ready.workload_identity.gid
                ),
            ],
        )
    } else {
        fail(definition, "workload identity is not fixed mxc identity")
    }
}

fn scenario_isolation(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = configured_runtime_service();
    let ready = match service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    ) {
        Ok(status) => status,
        Err(error) => return fail(definition, &format!("authenticate_channel failed: {error}")),
    };
    let iso = ready.isolation;
    let passed = iso.pid_namespace
        && iso.mount_namespace
        && iso.uts_namespace
        && iso.ipc_namespace
        && iso.private_proc
        && iso.private_dev
        && iso.private_devpts
        && iso.private_shm
        && iso.read_only_sys
        && iso.capabilities_dropped
        && iso.no_new_privs
        && iso.cgroup_separation
        && iso.orphan_reaping;
    if passed {
        pass(
            definition,
            vec!["all isolation booleans are true in Ready status".to_string()],
        )
    } else {
        fail(definition, "one or more isolation booleans are false")
    }
}

fn scenario_mapping_containment(definition: ScenarioDefinition) -> ScenarioResult {
    let traversal_rejected = RelativeChildPath::parse("../escape".to_string()).is_err();
    let overlap_request = ConfigureSessionRequest {
        configuration: SessionConfiguration {
            mappings: vec![
                ChildMapping {
                    child: RelativeChildPath::parse("runtime".to_string()).expect("runtime"),
                    access: AccessMode::ReadOnly,
                },
                ChildMapping {
                    child: RelativeChildPath::parse("runtime/sub".to_string()).expect("sub"),
                    access: AccessMode::ReadWrite,
                },
            ],
            ..session_configuration()
        },
        ..configure_request()
    };
    let mut service = MxcControlService::new(sample_binding(7, 44));
    if let Err(error) = service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    ) {
        return fail(definition, &format!("authenticate_channel failed: {error}"));
    }
    let overlap_rejected = matches!(
        service.configure_session(overlap_request),
        Err(ServiceError {
            code: ServiceErrorCode::InvalidMappings,
            ..
        })
    );
    if let Err(error) = service.configure_session(configure_request()) {
        return fail(definition, &format!("configure_session failed: {error}"));
    }
    let mutated = ConfigureSessionRequest {
        idempotent_replay: true,
        configuration: SessionConfiguration {
            containment: MappingContainmentPolicy {
                symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            },
            labels: vec!["runtime".to_string(), "mutation".to_string()],
            ..session_configuration()
        },
        ..configure_request()
    };
    let mutation_rejected = matches!(
        service.configure_session(mutated),
        Err(ServiceError {
            code: ServiceErrorCode::ConfigurationConflict,
            ..
        })
    );
    if traversal_rejected && overlap_rejected && mutation_rejected {
        pass(
            definition,
            vec![
                "relative path traversal is rejected".to_string(),
                "overlapping mapping roots are rejected".to_string(),
                "post-config mapping mutation is rejected".to_string(),
            ],
        )
    } else {
        fail(definition, "mapping containment/mutation checks failed")
    }
}

fn scenario_network_status(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = MxcControlService::new(sample_binding(7, 44));
    let admitted_network = NetworkStatus {
        mode: NetworkMode::PortableNetwork,
        detail: Some("10.0.0.2/24".to_string()),
    };
    let ready = match service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        admitted_network.clone(),
    ) {
        Ok(status) => status,
        Err(error) => return fail(definition, &format!("authenticate_channel failed: {error}")),
    };
    if let Err(error) = service.configure_session(configure_request()) {
        return fail(definition, &format!("configure_session failed: {error}"));
    }
    let health = service.health();
    if ready.network == admitted_network
        && health
            .network
            .as_ref()
            .is_some_and(|network| network.mode == NetworkMode::PortableNetwork)
    {
        pass(
            definition,
            vec![
                "ready status reports admitted network mode/detail".to_string(),
                "health snapshot retains configured network status".to_string(),
            ],
        )
    } else {
        fail(definition, "network status snapshot mismatch")
    }
}

fn scenario_health_lifecycle(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = activated_service();
    let before = service.health();
    let quiesce = service.quiesce();
    let resume = service.resume();
    let shutdown = service.shutdown();
    let capabilities = service.get_capabilities();
    let unavailable = capabilities
        .unavailable_operations
        .iter()
        .map(|entry| entry.operation.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let passed = before.configured
        && matches!(
            quiesce,
            Err(ServiceError {
                code: ServiceErrorCode::UnsupportedOperation,
                ..
            })
        )
        && matches!(
            resume,
            Err(ServiceError {
                code: ServiceErrorCode::UnsupportedOperation,
                ..
            })
        )
        && matches!(
            shutdown,
            Err(ServiceError {
                code: ServiceErrorCode::UnsupportedOperation,
                ..
            })
        )
        && unavailable.contains("Quiesce")
        && unavailable.contains("Resume")
        && unavailable.contains("Shutdown");
    if passed {
        pass(
            definition,
            vec![
                "health remains responsive while configured".to_string(),
                "quiesce/resume/shutdown are explicitly unavailable with typed errors".to_string(),
            ],
        )
    } else {
        fail(
            definition,
            "health/quiesce/resume/shutdown invariants failed",
        )
    }
}

fn scenario_channel_loss_cleanup(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = MxcControlService::new(sample_binding(7, 44));
    if let Err(error) = service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    ) {
        return fail(definition, &format!("initial authenticate failed: {error}"));
    }
    if let Err(error) = service.configure_session(configure_request()) {
        return fail(definition, &format!("configure_session failed: {error}"));
    }
    let mut supervisor = FakeSupervisor::default();
    if let Err(error) = service.begin_disconnect_cleanup(10, &mut supervisor) {
        return fail(
            definition,
            &format!("begin_disconnect_cleanup failed: {error}"),
        );
    }
    let same_generation = service.authenticate_channel(
        authenticate_request(7, 45, [7; 32]),
        30,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    );
    let newer_generation = service.authenticate_channel(
        authenticate_request(8, 45, [7; 32]),
        30,
        NetworkStatus {
            mode: NetworkMode::NoNic,
            detail: None,
        },
    );
    let same_rejected = matches!(
        same_generation,
        Err(ServiceError {
            code: ServiceErrorCode::LifecycleError,
            ..
        })
    );
    let newer_admitted = newer_generation.is_ok();
    if same_rejected && newer_admitted {
        pass(
            definition,
            vec![
                "disconnect cleanup clears session and blocks stale generation".to_string(),
                "strictly newer launch generation is admitted".to_string(),
            ],
        )
    } else {
        fail(
            definition,
            "channel-loss cleanup generation monotonicity check failed",
        )
    }
}

fn collect_exec_messages(
    service: &mut MxcControlService,
    supervisor: &mut impl ProcessSupervisor,
) -> Result<Vec<AgentControlMessage>, String> {
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match service.pump_supervisor(supervisor) {
            Ok(batch) => {
                if !batch.is_empty() {
                    out.extend(batch);
                }
            }
            Err(error) => return Err(format!("pump_supervisor failed: {error}")),
        }
        if service.active_exec_id().is_none() {
            return Ok(out);
        }
    }
    Err("timed out waiting for deterministic supervisor execution".to_string())
}

fn first_terminal_disposition(messages: &[AgentControlMessage]) -> Option<ExecDisposition> {
    messages.iter().find_map(|message| match message {
        AgentControlMessage::ExecTerminal { disposition, .. } => Some(*disposition),
        _ => None,
    })
}

fn terminal_after_cleanup(messages: &[AgentControlMessage], expected: ExecDisposition) -> bool {
    let terminal_index = messages
        .iter()
        .position(|message| {
            matches!(
                message,
                AgentControlMessage::ExecTerminal { disposition, .. } if *disposition == expected
            )
        })
        .unwrap_or(usize::MAX);
    let stdout_eof_index = messages
        .iter()
        .position(|message| matches!(message, AgentControlMessage::StdoutEof(_)));
    let stderr_eof_index = messages
        .iter()
        .position(|message| matches!(message, AgentControlMessage::StderrEof(_)));
    let cleanup_index = messages
        .iter()
        .position(|message| matches!(message, AgentControlMessage::DescendantsCleaned { .. }));
    terminal_index != usize::MAX
        && stdout_eof_index.is_some_and(|index| index < terminal_index)
        && stderr_eof_index.is_some_and(|index| index < terminal_index)
        && cleanup_index.is_some_and(|index| index < terminal_index)
        && messages
            .iter()
            .filter(|message| matches!(message, AgentControlMessage::ExecTerminal { .. }))
            .count()
            == 1
}

fn grant_all_stream_credits(service: &mut MxcControlService, exec_id: u32) -> Result<(), String> {
    for stream in [
        agent_protocol::messages::StreamName::Stdout,
        agent_protocol::messages::StreamName::Stderr,
    ] {
        service
            .grant_flow_credits(FlowCreditRequest {
                exec_id,
                stream,
                credits: 64,
            })
            .map_err(|error| format!("grant_flow_credits failed for {exec_id}: {error}"))?;
    }
    Ok(())
}

fn activated_service() -> MxcControlService {
    let mut service = MxcControlService::new_pid1_runtime(sample_binding(7, 44), 4242);
    service
        .authenticate_channel(
            authenticate_request(7, 44, [7; 32]),
            1,
            NetworkStatus {
                mode: NetworkMode::PortableNetwork,
                detail: Some("10.0.0.2/24".to_string()),
            },
        )
        .expect("authenticate");
    service
        .configure_session(configure_request())
        .expect("configure");
    service
        .activate_full_lifecycle()
        .expect("activate lifecycle");
    service
}

fn configured_runtime_service() -> MxcControlService {
    MxcControlService::new_pid1_runtime_with_status(
        sample_binding(7, 44),
        BuildStatus {
            agent_version: "test".to_string(),
            kernel_release: "test".to_string(),
            profile: "mxc-prototype".to_string(),
        },
        NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some("10.0.0.2/24".to_string()),
        },
        IsolationStatus {
            pid_namespace: true,
            mount_namespace: true,
            uts_namespace: true,
            ipc_namespace: true,
            private_proc: true,
            private_dev: true,
            private_devpts: true,
            private_shm: true,
            read_only_sys: true,
            capabilities_dropped: true,
            no_new_privs: true,
            cgroup_separation: true,
            orphan_reaping: true,
        },
        WorkloadIdentityStatus::mxc_fixed(),
        4242,
    )
}

fn sample_binding(generation: u64, channel_generation: u64) -> LaunchBinding {
    LaunchBinding {
        protocol_version: PROTOCOL_VERSION,
        image_version: DEFAULT_IMAGE_VERSION.to_string(),
        launch: LaunchIdentity {
            generation,
            nonce: [generation as u8; 16],
        },
        channel_generation,
    }
}

fn session_configuration() -> SessionConfiguration {
    SessionConfiguration {
        root: CanonicalHostMappingRoot::parse("/sandbox".to_string()).expect("root"),
        mappings: vec![ChildMapping {
            child: RelativeChildPath::parse("runtime".to_string()).expect("child"),
            access: AccessMode::ReadOnly,
        }],
        containment: MappingContainmentPolicy {
            symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        },
        labels: vec!["runtime".to_string()],
        attributes: BTreeMap::from([("profile".to_string(), "mxc".to_string())]),
        filesystem: FilesystemStatus {
            rootfs_ready: true,
            detail: "sandbox ready".to_string(),
        },
        network: NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some("10.0.0.2/24".to_string()),
        },
    }
}

fn configure_request() -> ConfigureSessionRequest {
    ConfigureSessionRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: DEFAULT_IMAGE_VERSION.to_string(),
        launch: LaunchIdentity {
            generation: 7,
            nonce: [7; 16],
        },
        channel_generation: 44,
        idempotent_replay: false,
        configuration: session_configuration(),
    }
}

fn wait_ready_request() -> WaitReadyRequest {
    WaitReadyRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: DEFAULT_IMAGE_VERSION.to_string(),
        launch: LaunchIdentity {
            generation: 7,
            nonce: [7; 16],
        },
        channel_generation: 44,
    }
}

fn authenticate_request(
    generation: u64,
    channel_generation: u64,
    capability_proof: [u8; 32],
) -> AuthenticateChannelRequest {
    AuthenticateChannelRequest {
        service: SERVICE_IDENTITY.to_string(),
        protocol_version: PROTOCOL_VERSION,
        launch: LaunchIdentity {
            generation,
            nonce: [generation as u8; 16],
        },
        channel_generation,
        capability_proof,
    }
}

fn pass(definition: ScenarioDefinition, evidence: Vec<String>) -> ScenarioResult {
    ScenarioResult {
        requirement_number: definition.requirement_number,
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        status: ScenarioStatus::Pass,
        duration_ms: 0,
        error: None,
        evidence,
    }
}

fn fail(definition: ScenarioDefinition, error: &str) -> ScenarioResult {
    ScenarioResult {
        requirement_number: definition.requirement_number,
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        status: ScenarioStatus::Fail,
        duration_ms: 0,
        error: Some(error.to_string()),
        evidence: vec![],
    }
}

fn unsupported(definition: ScenarioDefinition, error: &str) -> ScenarioResult {
    ScenarioResult {
        requirement_number: definition.requirement_number,
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        status: ScenarioStatus::Unsupported,
        duration_ms: 0,
        error: Some(error.to_string()),
        evidence: vec![],
    }
}

fn skipped(definition: ScenarioDefinition, reason: &str) -> ScenarioResult {
    ScenarioResult {
        requirement_number: definition.requirement_number,
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        status: ScenarioStatus::Skipped,
        duration_ms: 0,
        error: Some(reason.to_string()),
        evidence: vec![],
    }
}

fn write_json_atomic(path: &Path, report: &HarnessReport) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("failed to serialize harness report: {error}"))?;
    write_bytes_atomic(path, &payload)
}

fn write_text_atomic(path: &Path, text: &str) -> Result<(), String> {
    write_bytes_atomic(path, text.as_bytes())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|error| {
        format!(
            "failed to write temporary artifact {}: {error}",
            temporary.display()
        )
    })?;
    fs::rename(&temporary, path).map_err(|error| {
        format!(
            "failed to atomically persist artifact {}: {error}",
            path.display()
        )
    })
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn validate_canonical_scenarios() -> Result<(), String> {
    if CANONICAL_SCENARIOS.len() != 12 {
        return Err("canonical scenario list must contain exactly 12 entries".to_string());
    }
    let mut seen_ids = std::collections::BTreeSet::new();
    for (index, scenario) in CANONICAL_SCENARIOS.iter().enumerate() {
        let expected_number = (index + 1) as u8;
        if scenario.requirement_number != expected_number {
            return Err(format!(
                "scenario order mismatch at index {index}: requirement_number={} expected={expected_number}",
                scenario.requirement_number
            ));
        }
        if !seen_ids.insert(scenario.id) {
            return Err(format!("duplicate scenario id {}", scenario.id));
        }
    }
    Ok(())
}

pub fn is_passing_report(report: &HarnessReport) -> bool {
    if report.schema != REPORT_SCHEMA || report.version != REPORT_VERSION {
        return false;
    }
    if report.mode != HarnessMode::LiveWhp {
        return false;
    }
    if report.backend != HarnessBackend::Whp.as_str() {
        return false;
    }
    if report.platform != "windows" {
        return false;
    }
    if report.scenarios.len() != CANONICAL_SCENARIOS.len() {
        return false;
    }
    for (scenario, canonical) in report.scenarios.iter().zip(CANONICAL_SCENARIOS.iter()) {
        if scenario.requirement_number != canonical.requirement_number
            || scenario.id != canonical.id
            || scenario.name != canonical.name
        {
            return false;
        }
        if scenario.status != ScenarioStatus::Pass {
            return false;
        }
    }
    true
}

pub fn has_all_scenarios_passed(report: &HarnessReport) -> bool {
    if report.scenarios.len() != CANONICAL_SCENARIOS.len() {
        return false;
    }
    for (scenario, canonical) in report.scenarios.iter().zip(CANONICAL_SCENARIOS.iter()) {
        if scenario.requirement_number != canonical.requirement_number
            || scenario.id != canonical.id
            || scenario.name != canonical.name
            || scenario.status != ScenarioStatus::Pass
        {
            return false;
        }
    }
    true
}

pub fn report_exit_code(report: &HarnessReport) -> ExitCode {
    if has_all_scenarios_passed(report) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[derive(Default)]
struct Diagnostics {
    lines: VecDeque<String>,
}

impl Diagnostics {
    fn new(_max_lines: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(MAX_DIAGNOSTIC_LINES),
        }
    }

    fn push(&mut self, line: String) {
        if self.lines.len() == MAX_DIAGNOSTIC_LINES {
            let _ = self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

#[derive(Clone, Debug, Default)]
struct FakeSupervisor {
    plans: BTreeMap<u32, VecDeque<SupervisorEvent>>,
    stdin_pending_bytes: usize,
    stdin_drained_bytes: usize,
}

impl FakeSupervisor {
    fn plan_exec(&mut self, exec_id: u32, events: Vec<SupervisorEvent>) {
        self.plans.insert(exec_id, VecDeque::from(events));
    }
}

impl ProcessSupervisor for FakeSupervisor {
    fn spawn(&mut self, request: &CreateProcessRequest) -> Result<(), ServiceError> {
        self.plans.entry(request.exec_id).or_default();
        Ok(())
    }

    fn queue_stdin(&mut self, _exec_id: u32, chunk: Vec<u8>) -> Result<(), ServiceError> {
        self.stdin_pending_bytes = self.stdin_pending_bytes.saturating_add(chunk.len());
        Ok(())
    }

    fn close_stdin(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        if self.stdin_pending_bytes != 0 {
            return Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                message: "stdin queue is not drained".to_string(),
            });
        }
        Ok(())
    }

    fn take_stdin_drain_bytes(&mut self, _exec_id: u32) -> Result<usize, ServiceError> {
        let drained = self.stdin_drained_bytes.min(self.stdin_pending_bytes);
        self.stdin_pending_bytes -= drained;
        self.stdin_drained_bytes = 0;
        Ok(drained)
    }

    fn peek_event(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
        Ok(self
            .plans
            .get(&exec_id)
            .and_then(|events| events.front().cloned()))
    }

    fn ack_event(&mut self, exec_id: u32) -> Result<(), ServiceError> {
        if let Some(events) = self.plans.get_mut(&exec_id) {
            let _ = events.pop_front();
        }
        Ok(())
    }

    fn terminate(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        Ok(())
    }

    fn kill(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        Ok(())
    }

    fn poll(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
        let event = self.peek_event(exec_id)?;
        if event.is_some() {
            self.ack_event(exec_id)?;
        }
        Ok(event)
    }

    fn cleanup_for_disconnect(
        &mut self,
        _exec_id: u32,
        _deadline: Duration,
    ) -> Result<bool, ServiceError> {
        Ok(true)
    }
}

#[cfg(windows)]
mod windows_security {
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    pub fn generate_capability() -> Result<[u8; 32], String> {
        let mut capability = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut capability)
            .map_err(|error| format!("os random capability generation failed: {error}"))?;
        Ok(capability)
    }

    pub fn parse_inherited_handle_decimal(value: &str) -> Result<isize, String> {
        if value.is_empty() || !value.chars().all(|character| character.is_ascii_digit()) {
            return Err("inherited handle must be a non-empty decimal integer".to_string());
        }
        let parsed: u64 = value
            .parse()
            .map_err(|error| format!("invalid inherited handle decimal value: {error}"))?;
        if parsed == 0 || parsed > i32::MAX as u64 {
            return Err("inherited handle is outside the supported decimal range".to_string());
        }
        Ok(parsed as isize)
    }

    pub fn sid_matches_owner(expected_sid: &str, actual_sid: &str) -> bool {
        expected_sid.eq_ignore_ascii_case(actual_sid)
    }

    pub fn validate_live_security_prerequisites() -> Result<(), String> {
        let capability = generate_capability()?;
        if capability.iter().all(|byte| *byte == 0) {
            return Err("capability generator returned all-zero payload".to_string());
        }
        let _ = parse_inherited_handle_decimal("1")?;
        if !sid_matches_owner("S-1-5-18", "s-1-5-18") {
            return Err("owner/client SID comparison abstraction failed".to_string());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn capability_is_32_random_bytes() {
            let first = generate_capability().expect("capability");
            let second = generate_capability().expect("capability");
            assert_eq!(first.len(), 32);
            assert_eq!(second.len(), 32);
            assert_ne!(first, second);
        }

        #[test]
        fn inherited_handle_decimal_bounds_are_enforced() {
            assert!(parse_inherited_handle_decimal("1").is_ok());
            assert!(parse_inherited_handle_decimal(&(i32::MAX as u64).to_string()).is_ok());
            assert!(parse_inherited_handle_decimal("0").is_err());
            assert!(parse_inherited_handle_decimal(&(u64::MAX.to_string())).is_err());
            assert!(parse_inherited_handle_decimal("1.2").is_err());
            assert!(parse_inherited_handle_decimal("-4").is_err());
        }

        #[test]
        fn sid_check_abstraction_is_case_insensitive() {
            assert!(sid_matches_owner("S-1-5-21-1234", "s-1-5-21-1234"));
            assert!(!sid_matches_owner("S-1-5-21-1234", "S-1-5-18"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_scenarios_are_unique_and_ordered() {
        validate_canonical_scenarios().expect("canonical scenarios");
        assert_eq!(CANONICAL_SCENARIOS.len(), 12);
    }

    #[test]
    fn static_mode_never_satisfies_live_gate() {
        let root = std::env::temp_dir().join("nvx-agent-harness-static-gate");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::StaticOnly,
            output_dir: root,
        })
        .expect("run");
        assert!(!is_passing_report(&run.report));
        assert_eq!(run.exit_code(), ExitCode::SUCCESS);
        assert_eq!(run.report.scenarios.len(), 12);
    }

    #[test]
    fn non_windows_live_mode_is_prerequisite_failure() {
        if cfg!(windows) {
            return;
        }
        let root = std::env::temp_dir().join("nvx-agent-harness-live-prereq");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::LiveWhp,
            output_dir: root,
        })
        .expect("run");
        assert_eq!(run.report.scenarios[0].status, ScenarioStatus::Unsupported);
        assert!(
            run.report
                .scenarios
                .iter()
                .skip(1)
                .all(|scenario| scenario.status == ScenarioStatus::Skipped)
        );
    }
}
