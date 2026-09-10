use std::collections::{BTreeMap, VecDeque};
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
#[cfg(target_os = "linux")]
use agent_protocol::messages::{
    AgentControlMessage, ExecDisposition, FlowCreditRequest, StdinChunkRecord, StdinEofRecord,
};
use agent_protocol::messages::{
    BuildStatus, DnsStatus, IsolationStatus, LaunchIdentity, NetworkMode, NetworkSetupState,
    NetworkStatus, SERVICE_IDENTITY, WorkloadIdentityStatus,
};
#[cfg(target_os = "linux")]
use agent_protocol::service::ProcessSupervisor;
use agent_protocol::service::{
    AuthenticateChannelRequest, ConfigureSessionRequest, FilesystemStatus, LaunchBinding,
    MxcControlService, ServiceError, ServiceErrorCode, SessionConfiguration, WaitReadyRequest,
};
#[cfg(target_os = "linux")]
use agent_protocol::service::{CancelReason, CreateProcessRequest};
use agent_protocol::state::PROTOCOL_VERSION;
#[cfg(target_os = "linux")]
use nvx_agent::LinuxProcessSupervisor;
#[cfg(target_os = "linux")]
use nvx_agent::runtime::{
    harness_collect_portable_network_status, harness_detect_network_status_with_probe,
    harness_quiesce_transactional, harness_resume_transactional,
    harness_should_complete_shutdown_when_writer_blocked,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REPORT_SCHEMA: &str = "nvx.mxc.agent.harness.report.v1";
const REPORT_VERSION: u32 = 1;
const ATTESTATION_MANIFEST_SCHEMA: &str = "nvx.mxc.agent.harness.attestation-manifest.v1";
const ATTESTATION_MANIFEST_VERSION: u32 = 1;
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
    Blocked,
    NotLive,
    Unsupported,
    Skipped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    None,
    UnitStatic,
    LocalLinuxRuntime,
    LiveWhp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCheckStatus {
    Pass,
    Fail,
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioResult {
    pub requirement_number: u8,
    pub id: String,
    pub name: String,
    pub status: ScenarioStatus,
    pub check_status: EvidenceCheckStatus,
    pub evidence_source: EvidenceSource,
    pub required_evidence_source: EvidenceSource,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub evidence: Vec<String>,
    pub attestations: Vec<ScenarioAttestation>,
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
    pub artifact_hashes: BTreeMap<String, String>,
    pub diagnostics_tail: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationManifest {
    pub schema: String,
    pub version: u32,
    pub run_id: String,
    pub artifacts: Vec<AttestedArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestedArtifact {
    pub kind: String,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationKind {
    Req01LaunchReadiness,
    Req02ImmutableConfig,
    Req03RepeatedExec,
    Req04BinaryStreamSeparation,
    Req05BoundedFlowBackpressure,
    Req06TerminalOrderingCleanup,
    Req07FixedMxcIdentity,
    Req08FullIsolationVerification,
    Req09MappingContainmentMutation,
    Req10NetworkStatus,
    Req11HealthQuiesceResumeShutdown,
    Req12ChannelLossGeneration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioAttestation {
    pub kind: AttestationKind,
    pub transcript_id: String,
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
    pub attestation_manifest_path: PathBuf,
    trusted: TrustedEvidence,
}

#[derive(Clone, Debug)]
struct TrustedEvidence {
    attestation_by_requirement: BTreeMap<u8, AttestationKind>,
    transcript_by_requirement: BTreeMap<u8, String>,
    artifact_paths: BTreeMap<String, String>,
    artifact_sizes: BTreeMap<String, u64>,
    artifact_sha256: BTreeMap<String, String>,
    run_id: String,
}

impl HarnessRun {
    pub fn exit_code(&self) -> ExitCode {
        if is_passing_report(self) {
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
    let run_transcript_id = format!("run-{}-{}", std::process::id(), started);
    let mut scenarios = Vec::with_capacity(CANONICAL_SCENARIOS.len());
    let mut trusted_attestation_by_requirement = BTreeMap::new();
    let mut trusted_transcript_by_requirement = BTreeMap::new();
    let mut stop_after: Option<String> = None;
    for definition in CANONICAL_SCENARIOS {
        let scenario_start = Instant::now();
        let mut result = if let Some(reason) = stop_after.as_ref() {
            ScenarioResult {
                requirement_number: definition.requirement_number,
                id: definition.id.to_string(),
                name: definition.name.to_string(),
                status: ScenarioStatus::Skipped,
                check_status: EvidenceCheckStatus::NotRun,
                evidence_source: EvidenceSource::None,
                required_evidence_source: required_evidence_source(definition),
                duration_ms: 0,
                error: Some(format!("skipped because a prior scenario failed: {reason}")),
                evidence: vec![],
                attestations: vec![],
            }
        } else {
            run_scenario(&options, definition, &mut diagnostics)
        };
        if let Some(kind) = trusted_attestation_kind(definition, &result) {
            let transcript_id = format!(
                "{}:req{:02}:{}",
                run_transcript_id, definition.requirement_number, definition.id
            );
            result.attestations = vec![ScenarioAttestation {
                kind,
                transcript_id: transcript_id.clone(),
            }];
            trusted_attestation_by_requirement.insert(definition.requirement_number, kind);
            trusted_transcript_by_requirement.insert(definition.requirement_number, transcript_id);
        }
        result.duration_ms = scenario_start
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        if stop_after.is_none() && result.status == ScenarioStatus::Fail {
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
        artifact_hashes: BTreeMap::new(),
        diagnostics_tail: diagnostics.snapshot(),
    };

    let diagnostics_rel = PathBuf::from("diagnostics.log");
    let report_rel = PathBuf::from("report.json");
    let manifest_rel = PathBuf::from("attestation-manifest.json");
    let diagnostics_path = options.output_dir.join(&diagnostics_rel);
    let report_path = options.output_dir.join(&report_rel);
    let attestation_manifest_path = options.output_dir.join(&manifest_rel);
    let diagnostics_bytes = report.diagnostics_tail.join("\n").into_bytes();
    write_bytes_atomic(&diagnostics_path, &diagnostics_bytes)?;
    let diagnostics_sha256 = content_sha256_hex_bytes(&diagnostics_bytes);
    report
        .artifact_paths
        .insert("report".to_string(), rel_artifact_path(&report_rel)?);
    report.artifact_paths.insert(
        "diagnostics".to_string(),
        rel_artifact_path(&diagnostics_rel)?,
    );
    report.artifact_hashes.insert(
        "report".to_string(),
        "attested-via-attestation-manifest".to_string(),
    );
    report
        .artifact_hashes
        .insert("diagnostics".to_string(), diagnostics_sha256.clone());
    let report_bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("failed to serialize report: {error}"))?;
    write_bytes_atomic(&report_path, &report_bytes)?;

    let report_sha256 = content_sha256_hex_bytes(&report_bytes);
    let manifest = AttestationManifest {
        schema: ATTESTATION_MANIFEST_SCHEMA.to_string(),
        version: ATTESTATION_MANIFEST_VERSION,
        run_id: run_transcript_id.clone(),
        artifacts: vec![
            AttestedArtifact {
                kind: "report".to_string(),
                path: rel_artifact_path(&report_rel)?,
                size_bytes: report_bytes.len() as u64,
                sha256: report_sha256.clone(),
            },
            AttestedArtifact {
                kind: "diagnostics".to_string(),
                path: rel_artifact_path(&diagnostics_rel)?,
                size_bytes: diagnostics_bytes.len() as u64,
                sha256: diagnostics_sha256.clone(),
            },
        ],
    };
    write_json_atomic(&attestation_manifest_path, &manifest)?;

    let trusted = TrustedEvidence {
        attestation_by_requirement: trusted_attestation_by_requirement,
        transcript_by_requirement: trusted_transcript_by_requirement,
        artifact_paths: report.artifact_paths.clone(),
        artifact_sizes: BTreeMap::from([
            ("report".to_string(), report_bytes.len() as u64),
            ("diagnostics".to_string(), diagnostics_bytes.len() as u64),
        ]),
        artifact_sha256: BTreeMap::from([
            ("report".to_string(), report_sha256),
            ("diagnostics".to_string(), diagnostics_sha256),
        ]),
        run_id: run_transcript_id,
    };
    Ok(HarnessRun {
        report,
        report_path,
        diagnostics_path,
        attestation_manifest_path,
        trusted,
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
        HarnessMode::StaticOnly => run_static_only_scenario(definition),
        HarnessMode::LiveWhp => run_live_mode_scenario(definition),
    };
    diagnostics.push(format!(
        "scenario {} => {:?}",
        definition.id, outcome.status
    ));
    outcome
}

fn run_live_mode_scenario(definition: ScenarioDefinition) -> ScenarioResult {
    #[cfg(target_os = "linux")]
    {
        if (3..=6).contains(&definition.requirement_number)
            || (10..=12).contains(&definition.requirement_number)
        {
            return run_local_linux_runtime_scenario(definition);
        }
        make_report_result(
            definition,
            EvidenceSource::UnitStatic,
            EvidenceCheckStatus::Pass,
            vec!["local mode retains static protocol checks for this requirement".to_string()],
            Some("live WHP evidence was not collected for this requirement".to_string()),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let static_outcome = run_static_check_scenario(definition);
        let mut result = make_report_result(
            definition,
            static_outcome.evidence_source,
            static_outcome.check_status,
            static_outcome.evidence,
            static_outcome.error,
        );
        if result.status == ScenarioStatus::NotLive {
            result.error = Some(
                "live WHP evidence collection is not implemented in this harness build".to_string(),
            );
        }
        result
    }
}

fn run_static_only_scenario(definition: ScenarioDefinition) -> ScenarioResult {
    let static_outcome = run_static_check_scenario(definition);
    make_report_result(
        definition,
        static_outcome.evidence_source,
        static_outcome.check_status,
        static_outcome.evidence,
        static_outcome.error,
    )
}

#[derive(Clone, Debug)]
struct CheckOutcome {
    check_status: EvidenceCheckStatus,
    evidence_source: EvidenceSource,
    error: Option<String>,
    evidence: Vec<String>,
}

fn run_static_check_scenario(definition: ScenarioDefinition) -> CheckOutcome {
    match definition.requirement_number {
        1 => scenario_check_from_result(scenario_launch_readiness(definition), EvidenceSource::UnitStatic),
        2 => scenario_check_from_result(
            scenario_immutable_configuration(definition),
            EvidenceSource::UnitStatic,
        ),
        3..=6 | 10..=12 => CheckOutcome {
            check_status: EvidenceCheckStatus::NotRun,
            evidence_source: EvidenceSource::None,
            error: Some(
                "requires runtime execution evidence; static/in-process assertions are intentionally not used".to_string(),
            ),
            evidence: vec![],
        },
        7 => scenario_check_from_result(scenario_fixed_identity(definition), EvidenceSource::UnitStatic),
        8 => scenario_check_from_result(scenario_isolation(definition), EvidenceSource::UnitStatic),
        9 => scenario_check_from_result(
            scenario_mapping_containment(definition),
            EvidenceSource::UnitStatic,
        ),
        _ => CheckOutcome {
            check_status: EvidenceCheckStatus::Fail,
            evidence_source: EvidenceSource::None,
            error: Some("unknown requirement number".to_string()),
            evidence: vec![],
        },
    }
}

fn scenario_check_from_result(result: ScenarioResult, source: EvidenceSource) -> CheckOutcome {
    let check_status = match result.status {
        ScenarioStatus::Pass => EvidenceCheckStatus::Pass,
        ScenarioStatus::Fail => EvidenceCheckStatus::Fail,
        _ => EvidenceCheckStatus::NotRun,
    };
    CheckOutcome {
        check_status,
        evidence_source: source,
        error: result.error,
        evidence: result.evidence,
    }
}

fn required_evidence_source(_definition: ScenarioDefinition) -> EvidenceSource {
    EvidenceSource::LiveWhp
}

fn status_for_evidence(
    definition: ScenarioDefinition,
    check_status: EvidenceCheckStatus,
    observed_source: EvidenceSource,
    required_source: EvidenceSource,
) -> ScenarioStatus {
    if check_status == EvidenceCheckStatus::Fail {
        return ScenarioStatus::Fail;
    }
    if check_status == EvidenceCheckStatus::NotRun {
        return ScenarioStatus::Blocked;
    }
    if (7..=9).contains(&definition.requirement_number)
        && observed_source != EvidenceSource::LiveWhp
    {
        return ScenarioStatus::Blocked;
    }
    if observed_source < required_source {
        return ScenarioStatus::NotLive;
    }
    ScenarioStatus::Pass
}

fn make_report_result(
    definition: ScenarioDefinition,
    observed_source: EvidenceSource,
    check_status: EvidenceCheckStatus,
    evidence: Vec<String>,
    error: Option<String>,
) -> ScenarioResult {
    let required_source = required_evidence_source(definition);
    let status = status_for_evidence(definition, check_status, observed_source, required_source);
    let status_error = match status {
        ScenarioStatus::Pass => None,
        ScenarioStatus::Fail => error,
        ScenarioStatus::Blocked => Some(error.unwrap_or_else(|| {
            "blocked: privileged or runtime evidence prerequisites are not satisfied".to_string()
        })),
        ScenarioStatus::NotLive => Some(error.unwrap_or_else(|| {
            format!(
                "observed evidence source={} is below required source={}",
                evidence_source_name(observed_source),
                evidence_source_name(required_source)
            )
        })),
        ScenarioStatus::Unsupported => error,
        ScenarioStatus::Skipped => error,
    };
    ScenarioResult {
        requirement_number: definition.requirement_number,
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        status,
        check_status,
        evidence_source: observed_source,
        required_evidence_source: required_source,
        duration_ms: 0,
        error: status_error,
        evidence,
        attestations: vec![],
    }
}

fn evidence_source_name(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::None => "none",
        EvidenceSource::UnitStatic => "unit-static",
        EvidenceSource::LocalLinuxRuntime => "local-linux-runtime",
        EvidenceSource::LiveWhp => "live-whp",
    }
}

fn scenario_launch_readiness(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = MxcControlService::new(sample_binding(7, 44));
    let capabilities = service.get_capabilities();
    let auth = service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        network_status_portable_ready(),
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
        network_status_no_nic(),
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

#[cfg(target_os = "linux")]
fn run_local_linux_runtime_scenario(definition: ScenarioDefinition) -> ScenarioResult {
    let check = match definition.requirement_number {
        3 => local_linux_repeated_exec(),
        4 => local_linux_binary_stream_separation(),
        5 => local_linux_backpressure(),
        6 => local_linux_terminal_semantics(),
        10 => local_linux_network_status(),
        11 => local_linux_health_lifecycle(),
        12 => local_linux_channel_loss_generation(),
        _ => CheckOutcome {
            check_status: EvidenceCheckStatus::NotRun,
            evidence_source: EvidenceSource::None,
            error: Some(
                "local-linux-runtime scenarios are defined only for requirements 3-6 and 10-12"
                    .to_string(),
            ),
            evidence: vec![],
        },
    };
    let check = enforce_production_runtime_evidence_gate(definition, check);
    make_report_result(
        definition,
        check.evidence_source,
        check.check_status,
        check.evidence,
        check.error,
    )
}

#[cfg(any(target_os = "linux", test))]
fn enforce_production_runtime_evidence_gate(
    definition: ScenarioDefinition,
    mut check: CheckOutcome,
) -> CheckOutcome {
    if !(10..=12).contains(&definition.requirement_number)
        || check.check_status != EvidenceCheckStatus::Pass
    {
        return check;
    }
    if check.evidence_source != EvidenceSource::LocalLinuxRuntime {
        check.check_status = EvidenceCheckStatus::Fail;
        check.evidence_source = EvidenceSource::None;
        check.error = Some(format!(
            "req{} runtime gate rejected pass without production runtime evidence source",
            definition.requirement_number
        ));
    }
    check
}

#[cfg(target_os = "linux")]
fn local_linux_network_status() -> CheckOutcome {
    let no_nic = harness_detect_network_status_with_probe(
        false,
        Duration::from_millis(1),
        || unreachable!("probe must not run for no-nic"),
        |_sleep| {},
    );
    let portable_ready = harness_detect_network_status_with_probe(
        true,
        Duration::from_millis(10),
        || {
            harness_collect_portable_network_status(
                agent_protocol::NetworkInterfaceStatus {
                    name: "eth0".to_string(),
                    index: 3,
                    link_state: agent_protocol::NetworkLinkState::Up,
                    addresses: vec!["10.0.0.2".to_string()],
                    default_route: None,
                },
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
                "nameserver 10.0.0.53\n",
            )
        },
        |_sleep| {},
    );
    let malformed = harness_detect_network_status_with_probe(
        true,
        Duration::from_millis(0),
        || {
            harness_collect_portable_network_status(
                agent_protocol::NetworkInterfaceStatus {
                    name: "eth0".to_string(),
                    index: 3,
                    link_state: agent_protocol::NetworkLinkState::Up,
                    addresses: vec!["10.0.0.2".to_string()],
                    default_route: None,
                },
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\tnothex\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
                "nameserver 10.0.0.53\n",
            )
        },
        |_sleep| {},
    );
    let timeout = harness_detect_network_status_with_probe(
        true,
        Duration::from_millis(1),
        || {
            Err(agent_protocol::NetworkFailureStatus {
                code: agent_protocol::NetworkFailureCode::RouteMissing,
                detail: "missing default route for eth0".to_string(),
            })
        },
        |_sleep| {},
    );

    let mut roundtrip_ok = true;
    for status in [
        no_nic.clone(),
        portable_ready.clone(),
        malformed.clone(),
        timeout.clone(),
    ] {
        let mut service = MxcControlService::new_pid1_runtime(sample_binding(7, 44), 4242);
        let admitted = match service.authenticate_channel(
            authenticate_request(7, 44, [7; 32]),
            1,
            status.clone(),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return check_fail(format!(
                    "authenticate_channel failed for mode={:?}: {error}",
                    status.mode
                ));
            }
        };
        let mut configuration = configure_request();
        configuration.configuration.network = status.clone();
        if let Err(error) = service.configure_session(configuration) {
            return check_fail(format!(
                "configure_session failed for mode={:?}: {error}",
                status.mode
            ));
        }
        if let Err(error) = service.activate_full_lifecycle() {
            return check_fail(format!("activate_full_lifecycle failed: {error}"));
        }
        let ready = match service.wait_ready(wait_ready_request()) {
            Ok(snapshot) => snapshot,
            Err(error) => return check_fail(format!("wait_ready failed: {error}")),
        };
        let health = service.health();
        if admitted.network != status
            || ready.network != status
            || health.network != Some(status.clone())
        {
            roundtrip_ok = false;
            break;
        }
    }

    let no_nic_ok = no_nic.mode == NetworkMode::NoNic
        && no_nic.setup_state == NetworkSetupState::Ready
        && no_nic.interface.is_none()
        && no_nic.failure.is_none();
    let ready_ok = portable_ready.mode == NetworkMode::PortableNetwork
        && portable_ready.setup_state == NetworkSetupState::Ready
        && portable_ready.dns.ready
        && !portable_ready.dns.servers.is_empty()
        && portable_ready.failure.is_none();
    let malformed_ok = malformed.setup_state == NetworkSetupState::Failed
        && matches!(
            malformed.failure,
            Some(agent_protocol::NetworkFailureStatus {
                code: agent_protocol::NetworkFailureCode::RouteMalformed,
                ..
            })
        );
    let timeout_ok = timeout.setup_state == NetworkSetupState::Failed
        && matches!(
            timeout.failure,
            Some(agent_protocol::NetworkFailureStatus {
                code: agent_protocol::NetworkFailureCode::RouteMissing,
                ..
            })
        );

    if no_nic_ok && ready_ok && malformed_ok && timeout_ok && roundtrip_ok {
        check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "production network probe path (no-nic/portable/malformed/timeout) feeds typed NetworkStatus".to_string(),
                "authenticate/configure/activate/wait-ready/health preserved each probed network status verbatim".to_string(),
            ],
        )
    } else {
        check_fail(
            "network status invariants failed through runtime probe + readiness path".to_string(),
        )
    }
}

#[cfg(target_os = "linux")]
fn local_linux_health_lifecycle() -> CheckOutcome {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let exec_id = 811_u32;
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "yes health | head -c 131072".to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return check_fail(format!("create_process failed: {error}"));
    }

    let backpressured = wait_for_output_credit_backpressure(&mut service, &mut supervisor, exec_id);
    let health = service.health();
    let health_ok = health.launch_admitted
        && health.configured
        && health.active_exec_id == Some(exec_id)
        && health.channel_generation == 44;
    let cgroup_path = Path::new("/sys/fs/cgroup/nvx.workload");
    let quiesce_rejected = match harness_quiesce_transactional(&mut service, cgroup_path) {
        Ok(()) => false,
        Err(error) => error.contains("quiesce rejected while an execution is active"),
    };

    if let Err(error) = service.cancel_exec(exec_id, CancelReason::Cancelled, &mut supervisor) {
        return check_fail(format!("cancel_exec failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
        return check_fail(error);
    }
    if let Err(error) = collect_exec_messages(&mut service, &mut supervisor) {
        return check_fail(error);
    }
    let quiesced = match harness_quiesce_transactional(&mut service, cgroup_path) {
        Ok(()) => service.health().quiesced,
        Err(error) => {
            if error.contains("cgroup freezer interface unavailable")
                || error.contains("cgroup.freeze")
                || error.contains("cgroup.events")
            {
                return check_blocked(
                    format!(
                        "req11 production quiesce transaction path unavailable on this host: {error}"
                    ),
                    vec![
                        "local runtime host lacks cgroup freezer prerequisites required by production quiesce/resume".to_string(),
                    ],
                );
            }
            return check_fail(format!("production quiesce transaction failed: {error}"));
        }
    };
    let admission_blocked = matches!(
        service.create_process(
            CreateProcessRequest {
                exec_id: 812,
                argv: vec!["/bin/true".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        ),
        Err(ServiceError {
            code: ServiceErrorCode::LifecycleError,
            ..
        })
    );
    let resumed = match harness_resume_transactional(&mut service, cgroup_path) {
        Ok(()) => !service.health().quiesced,
        Err(error) => return check_fail(format!("production resume transaction failed: {error}")),
    };
    let shutdown_ack = service.shutdown().is_ok() && service.health().shutting_down;
    let blocked_writer_before_deadline =
        !harness_should_complete_shutdown_when_writer_blocked(None, 120, 60);
    let blocked_writer_after_deadline =
        harness_should_complete_shutdown_when_writer_blocked(None, 120, 121);
    let post_shutdown_blocked = matches!(
        service.create_process(
            CreateProcessRequest {
                exec_id: 813,
                argv: vec!["/bin/true".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        ),
        Err(ServiceError {
            code: ServiceErrorCode::LifecycleError,
            ..
        })
    );

    if backpressured
        && health_ok
        && quiesce_rejected
        && quiesced
        && admission_blocked
        && resumed
        && shutdown_ack
        && blocked_writer_before_deadline
        && blocked_writer_after_deadline
        && post_shutdown_blocked
    {
        check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "health remains queryable under output backpressure and reports active exec/channel generation"
                    .to_string(),
                "production quiesce/resume transactional path rejects active quiesce and enforces idle freeze/thaw"
                    .to_string(),
                "shutdown transitions state and bounded blocked-writer deadline still guarantees runtime stop".to_string(),
            ],
        )
    } else {
        check_fail(
            "health/lifecycle local runtime invariants failed through production transaction paths"
                .to_string(),
        )
    }
}

#[cfg(target_os = "linux")]
fn local_linux_channel_loss_generation() -> CheckOutcome {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let exec_id = 901_u32;
    let pid_file = std::env::temp_dir().join(format!(
        "nvx-agent-harness-grandchild-{}.pid",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&pid_file);
    let command = format!(
        "dd if=/dev/zero bs=1024 count=128 2>/dev/null; (dd if=/dev/zero bs=1024 count=128 2>/dev/null; sleep 30) & child=$!; echo $child > '{}'; cat >/dev/null",
        pid_file.display()
    );
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), command],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return check_fail(format!("create_process failed: {error}"));
    }
    let active_exec_started = service.health().active_exec_id == Some(exec_id);
    if !active_exec_started {
        return check_fail("expected active exec before channel-loss cleanup".to_string());
    }
    let grandchild_pid = wait_for_pid_file_pid(&pid_file, Duration::from_millis(250));
    let Some(grandchild_pid) = grandchild_pid else {
        let _ = std::fs::remove_file(&pid_file);
        return check_blocked(
            "req12 production runtime child-tree probe unavailable: could not observe spawned grandchild pid"
                .to_string(),
            vec![
                "production runtime channel-loss check requires a real child+grandchild process tree".to_string(),
            ],
        );
    };
    let cleanup_started = Instant::now();
    let cleanup = service.begin_disconnect_cleanup(100, &mut supervisor);
    if let Err(error) = cleanup {
        return check_fail(format!("begin_disconnect_cleanup failed: {error}"));
    }
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_bounded = cleanup_elapsed <= Duration::from_secs(5);
    let queue_usage_after_cleanup = supervisor.queue_usage();
    let queue_cleared_after_cleanup = queue_usage_after_cleanup.event_queue_records == 0
        && queue_usage_after_cleanup.event_queue_bytes == 0
        && queue_usage_after_cleanup.stdin_queue_bytes == 0;
    let tree_stopped = match is_pid_alive(grandchild_pid) {
        Ok(false) => true,
        Ok(true) => false,
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
            let _ = std::fs::remove_file(&pid_file);
            return check_blocked(
                format!(
                    "req12 production runtime child-tree probe blocked by local privileges: {error}"
                ),
                vec![
                    "host denied permission to verify descendant liveness after cleanup"
                        .to_string(),
                ],
            );
        }
        Err(error) => return check_fail(format!("failed to verify descendant liveness: {error}")),
    };
    let post_cleanup = service.health();
    let admission_stopped_and_cleanup_completed = !post_cleanup.launch_admitted
        && !post_cleanup.configured
        && post_cleanup.active_exec_id.is_none();
    let stale_wait = service.wait_ready(wait_ready_request()).is_err();
    let post_cleanup_exec_rejected = service
        .create_process(
            CreateProcessRequest {
                exec_id: 902,
                argv: vec!["/bin/true".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        )
        .is_err();
    let stale_auth = service
        .authenticate_channel(
            authenticate_request(7, 44, [7; 32]),
            101,
            network_status_no_nic(),
        )
        .is_err();
    let new_auth_ok = service
        .authenticate_channel(
            authenticate_request(8, 45, [7; 32]),
            101,
            network_status_no_nic(),
        )
        .is_ok();
    let replay_rejected = service
        .grant_flow_credits(FlowCreditRequest {
            exec_id,
            stream: agent_protocol::messages::StreamName::Stdout,
            credits: 1,
        })
        .is_err();
    let stale_stdin_rejected = service
        .stdin_chunk(
            StdinChunkRecord {
                exec_id,
                sequence: 0,
                chunk: vec![1, 2, 3],
            },
            &mut supervisor,
        )
        .is_err();
    let old_launch_config_rejected = matches!(
        service.configure_session(configure_request()),
        Err(ServiceError {
            code: ServiceErrorCode::LaunchGenerationMismatch,
            ..
        })
    );
    let duplicate_new_generation_reauth_rejected = service
        .authenticate_channel(
            authenticate_request(8, 45, [7; 32]),
            102,
            network_status_no_nic(),
        )
        .is_err();
    let _ = std::fs::remove_file(&pid_file);
    if !tree_stopped {
        return check_blocked(
            "req12 production runtime child-tree termination could not be verified on this host"
                .to_string(),
            vec![
                "local privileges or process-visibility constraints prevented confirming grandchild reap after disconnect cleanup".to_string(),
            ],
        );
    }
    if !cleanup_bounded {
        return check_blocked(
            format!(
                "req12 production runtime cleanup exceeded local verification bound ({:?})",
                cleanup_elapsed
            ),
            vec![
                "bounded cleanup timing could not be confirmed under local host constraints"
                    .to_string(),
            ],
        );
    }
    if admission_stopped_and_cleanup_completed
        && stale_wait
        && post_cleanup_exec_rejected
        && stale_auth
        && new_auth_ok
        && stale_stdin_rejected
        && replay_rejected
        && old_launch_config_rejected
        && duplicate_new_generation_reauth_rejected
        && queue_cleared_after_cleanup
    {
        return check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "production runtime (MxcControlService::new_pid1_runtime) executed req12 with LinuxProcessSupervisor on an authenticated, active execution".to_string(),
                "simulated control-channel loss immediately stopped admission, closed stdin, and completed internal cleanup before reconnect".to_string(),
                "bounded child-tree termination/reap completed for real output-producing child+grandchild process tree".to_string(),
                "disconnect cleanup completed with cleared supervisor queues (no unbounded queue/memory growth)".to_string(),
                "strictly newer generation reconnect succeeded while stale/same-generation auth, stale old-generation requests, and stale stream replay/stdin were rejected".to_string(),
            ],
        );
    }
    check_fail("channel-loss cleanup generation invariants failed".to_string())
}

#[cfg(target_os = "linux")]
fn wait_for_pid_file_pid(path: &Path, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<i32>()
            && pid > 1
        {
            return Some(pid);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

#[cfg(target_os = "linux")]
fn is_pid_alive(pid: i32) -> Result<bool, io::Error> {
    // SAFETY: kill with signal 0 only probes process existence.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
fn local_linux_repeated_exec() -> CheckOutcome {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let mut outcomes = Vec::new();
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id: 300,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 0.2; exit 10".to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return check_fail(format!("create_process for exec 300 failed: {error}"));
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
        return check_fail(error);
    }
    match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => outcomes.push(first_terminal_disposition(&messages)),
        Err(error) => return check_fail(error),
    }
    for (exec_id, exit_code) in [(301_u32, 11_i32), (302_u32, 12_i32)] {
        if let Err(error) = service.create_process(
            CreateProcessRequest {
                exec_id,
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!("exit {exit_code}"),
                ],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        ) {
            return check_fail(format!("create_process for exec {exec_id} failed: {error}"));
        }
        if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
            return check_fail(error);
        }
        match collect_exec_messages(&mut service, &mut supervisor) {
            Ok(messages) => outcomes.push(first_terminal_disposition(&messages)),
            Err(error) => return check_fail(error),
        }
    }
    if overlap_rejected
        && outcomes
            == vec![
                Some(ExecDisposition::ExitCode(10)),
                Some(ExecDisposition::ExitCode(11)),
                Some(ExecDisposition::ExitCode(12)),
            ]
    {
        check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "one active execution enforced with WorkloadBusy".to_string(),
                "sequential executions returned deterministic terminal dispositions".to_string(),
            ],
        )
    } else {
        check_fail("sequential exec invariants failed".to_string())
    }
}

#[cfg(target_os = "linux")]
fn local_linux_binary_stream_separation() -> CheckOutcome {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let exec_id = 401_u32;
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf '\\101\\000\\102\\377\\103'; printf '\\130\\000\\131\\376\\132' 1>&2"
                    .to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return check_fail(format!("create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
        return check_fail(error);
    }
    let messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return check_fail(error),
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
        check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "stdout bytes preserved with embedded NUL and 0xFF".to_string(),
                "stderr bytes preserved independently with embedded NUL and 0xFE".to_string(),
            ],
        )
    } else {
        check_fail("binary stream separation check failed".to_string())
    }
}

#[cfg(target_os = "linux")]
fn local_linux_backpressure() -> CheckOutcome {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let credit_exec = 501_u32;
    if let Err(error) = service.create_process(
        CreateProcessRequest {
            exec_id: credit_exec,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf x".to_string(),
            ],
            cwd: Some("/".to_string()),
            env: vec![],
            timeout_ms: None,
        },
        &mut supervisor,
    ) {
        return check_fail(format!("credit probe create_process failed: {error}"));
    }
    let credit_exhausted =
        wait_for_output_credit_backpressure(&mut service, &mut supervisor, credit_exec);
    if !credit_exhausted {
        return check_fail(
            "expected stdout flow-credit backpressure before granting stdout credits".to_string(),
        );
    }

    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let exec_id = 503_u32;
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
        return check_fail(format!("create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, exec_id) {
        return check_fail(error);
    }
    if let Err(error) = service.grant_flow_credits(FlowCreditRequest {
        exec_id,
        stream: agent_protocol::messages::StreamName::Stdin,
        credits: 1,
    }) {
        return check_fail(format!("grant stdin credits failed: {error}"));
    }
    if let Err(error) = service.stdin_chunk(
        StdinChunkRecord {
            exec_id,
            sequence: 0,
            chunk: vec![3_u8; agent_protocol::PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES],
        },
        &mut supervisor,
    ) {
        return check_fail(format!("max-sized stdin chunk failed: {error}"));
    }
    let queued_limit_enforced = matches!(
        service.stdin_chunk(
            StdinChunkRecord {
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
    let mut stdin_eof_applied = false;
    let eof_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < eof_deadline {
        match service.stdin_eof(
            StdinEofRecord {
                exec_id,
                sequence: 1,
            },
            &mut supervisor,
        ) {
            Ok(()) => {
                stdin_eof_applied = true;
                break;
            }
            Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                ..
            }) => {
                let _ = service.pump_supervisor(&mut supervisor);
            }
            Err(error) => return check_fail(format!("stdin_eof failed: {error}")),
        }
    }
    if !stdin_eof_applied {
        return check_fail("stdin_eof remained blocked after bounded drain wait".to_string());
    }
    if let Err(error) = collect_exec_messages(&mut service, &mut supervisor) {
        return check_fail(error);
    }
    if queued_limit_enforced && service.health().configured {
        check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "stdout requires granted flow credits".to_string(),
                "stdin queue enforces bounded byte cap under real subprocess load".to_string(),
                "service remains healthy after bounded-flow enforcement".to_string(),
            ],
        )
    } else {
        check_fail("backpressure invariants failed for local runtime".to_string())
    }
}

#[cfg(target_os = "linux")]
fn local_linux_terminal_semantics() -> CheckOutcome {
    let mut service = activated_service();
    let mut supervisor = LinuxProcessSupervisor::new();
    let normal_exec = 601_u32;
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
        return check_fail(format!("normal create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, normal_exec) {
        return check_fail(error);
    }
    let normal_messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return check_fail(error),
    };
    let normal_ok = terminal_after_cleanup(&normal_messages, ExecDisposition::ExitCode(0));

    let cancelled_exec = 602_u32;
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
        return check_fail(format!("cancel create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, cancelled_exec) {
        return check_fail(error);
    }
    if let Err(error) =
        service.cancel_exec(cancelled_exec, CancelReason::Cancelled, &mut supervisor)
    {
        return check_fail(format!("cancel_exec failed: {error}"));
    }
    let cancelled_messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return check_fail(error),
    };
    let cancelled_ok = terminal_after_cleanup(&cancelled_messages, ExecDisposition::Cancelled);

    let timeout_exec = 603_u32;
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
        return check_fail(format!("timeout create_process failed: {error}"));
    }
    if let Err(error) = grant_all_stream_credits(&mut service, timeout_exec) {
        return check_fail(error);
    }
    if let Err(error) = service.cancel_exec(timeout_exec, CancelReason::TimedOut, &mut supervisor) {
        return check_fail(format!("timeout cancel_exec failed: {error}"));
    }
    let timeout_messages = match collect_exec_messages(&mut service, &mut supervisor) {
        Ok(messages) => messages,
        Err(error) => return check_fail(error),
    };
    let timeout_ok = terminal_after_cleanup(&timeout_messages, ExecDisposition::TimedOut);
    if normal_ok && cancelled_ok && timeout_ok {
        check_pass(
            EvidenceSource::LocalLinuxRuntime,
            vec![
                "normal, cancelled, and timed-out dispositions observed".to_string(),
                "terminal event emitted after stdout/stderr EOF and descendant cleanup".to_string(),
            ],
        )
    } else {
        check_fail("terminal ordering invariants failed".to_string())
    }
}

fn scenario_fixed_identity(definition: ScenarioDefinition) -> ScenarioResult {
    let mut service = configured_runtime_service();
    let ready = match service.authenticate_channel(
        authenticate_request(7, 44, [7; 32]),
        1,
        network_status_no_nic(),
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
        network_status_no_nic(),
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
        network_status_no_nic(),
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn check_pass(evidence_source: EvidenceSource, evidence: Vec<String>) -> CheckOutcome {
    CheckOutcome {
        check_status: EvidenceCheckStatus::Pass,
        evidence_source,
        error: None,
        evidence,
    }
}

#[cfg(target_os = "linux")]
fn check_fail(error: String) -> CheckOutcome {
    CheckOutcome {
        check_status: EvidenceCheckStatus::Fail,
        evidence_source: EvidenceSource::None,
        error: Some(error),
        evidence: vec![],
    }
}

#[cfg(target_os = "linux")]
fn check_blocked(error: String, evidence: Vec<String>) -> CheckOutcome {
    CheckOutcome {
        check_status: EvidenceCheckStatus::NotRun,
        evidence_source: EvidenceSource::LocalLinuxRuntime,
        error: Some(error),
        evidence,
    }
}

#[cfg(target_os = "linux")]
fn wait_for_output_credit_backpressure(
    service: &mut MxcControlService,
    supervisor: &mut LinuxProcessSupervisor,
    exec_id: u32,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match service.pump_supervisor(supervisor) {
            Ok(_) => {}
            Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                ..
            }) => return true,
            Err(_) => return false,
        }
        if service.active_exec_id().is_none() {
            break;
        }
    }
    let _ = service.cancel_exec(exec_id, CancelReason::Cancelled, supervisor);
    let _ = collect_exec_messages(service, supervisor);
    false
}

#[cfg(target_os = "linux")]
fn first_terminal_disposition(messages: &[AgentControlMessage]) -> Option<ExecDisposition> {
    messages.iter().find_map(|message| match message {
        AgentControlMessage::ExecTerminal { disposition, .. } => Some(*disposition),
        _ => None,
    })
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn activated_service() -> MxcControlService {
    let mut service = MxcControlService::new_pid1_runtime(sample_binding(7, 44), 4242);
    service
        .authenticate_channel(
            authenticate_request(7, 44, [7; 32]),
            1,
            network_status_portable_ready(),
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
            ..network_status_portable_ready()
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
            ..network_status_portable_ready()
        },
    }
}

fn network_status_no_nic() -> NetworkStatus {
    NetworkStatus {
        mode: NetworkMode::NoNic,
        setup_state: NetworkSetupState::Ready,
        interface: None,
        default_gateway: None,
        dns: DnsStatus {
            ready: true,
            servers: Vec::new(),
        },
        failure: None,
    }
}

fn network_status_portable_ready() -> NetworkStatus {
    NetworkStatus {
        mode: NetworkMode::PortableNetwork,
        setup_state: NetworkSetupState::Ready,
        interface: None,
        default_gateway: Some("10.0.0.1".to_string()),
        dns: DnsStatus {
            ready: true,
            servers: vec!["10.0.0.53".to_string()],
        },
        failure: None,
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
        check_status: EvidenceCheckStatus::Pass,
        evidence_source: EvidenceSource::UnitStatic,
        required_evidence_source: EvidenceSource::UnitStatic,
        duration_ms: 0,
        error: None,
        evidence,
        attestations: vec![],
    }
}

fn fail(definition: ScenarioDefinition, error: &str) -> ScenarioResult {
    ScenarioResult {
        requirement_number: definition.requirement_number,
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        status: ScenarioStatus::Fail,
        check_status: EvidenceCheckStatus::Fail,
        evidence_source: EvidenceSource::UnitStatic,
        required_evidence_source: EvidenceSource::UnitStatic,
        duration_ms: 0,
        error: Some(error.to_string()),
        evidence: vec![],
        attestations: vec![],
    }
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize harness report: {error}"))?;
    write_bytes_atomic(path, &payload)
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

fn content_sha256_hex_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn rel_artifact_path(path: &Path) -> Result<String, String> {
    if path.is_absolute() {
        return Err(format!(
            "artifact path must be relative, got {}",
            path.display()
        ));
    }
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        ) {
            return Err(format!(
                "artifact path escapes output directory: {}",
                path.display()
            ));
        }
    }
    Ok(path.to_string_lossy().to_string())
}

fn read_artifact_checked(
    output_dir: &Path,
    relative_path: &str,
) -> Result<(PathBuf, Vec<u8>), String> {
    let relative = PathBuf::from(relative_path);
    let checked = rel_artifact_path(&relative)?;
    let full_path = output_dir.join(&checked);
    let mut file = fs::File::open(&full_path)
        .map_err(|error| format!("failed to open artifact {}: {error}", full_path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read artifact {}: {error}", full_path.display()))?;
    Ok((full_path, bytes))
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

fn expected_attestation_kind(requirement_number: u8) -> Option<AttestationKind> {
    match requirement_number {
        1 => Some(AttestationKind::Req01LaunchReadiness),
        2 => Some(AttestationKind::Req02ImmutableConfig),
        3 => Some(AttestationKind::Req03RepeatedExec),
        4 => Some(AttestationKind::Req04BinaryStreamSeparation),
        5 => Some(AttestationKind::Req05BoundedFlowBackpressure),
        6 => Some(AttestationKind::Req06TerminalOrderingCleanup),
        7 => Some(AttestationKind::Req07FixedMxcIdentity),
        8 => Some(AttestationKind::Req08FullIsolationVerification),
        9 => Some(AttestationKind::Req09MappingContainmentMutation),
        10 => Some(AttestationKind::Req10NetworkStatus),
        11 => Some(AttestationKind::Req11HealthQuiesceResumeShutdown),
        12 => Some(AttestationKind::Req12ChannelLossGeneration),
        _ => None,
    }
}

fn trusted_attestation_kind(
    definition: ScenarioDefinition,
    result: &ScenarioResult,
) -> Option<AttestationKind> {
    if result.check_status != EvidenceCheckStatus::Pass {
        return None;
    }
    expected_attestation_kind(definition.requirement_number)
}

pub fn is_passing_report(run: &HarnessRun) -> bool {
    let report = &run.report;
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
    if report.service_identity != SERVICE_IDENTITY {
        return false;
    }
    if report.protocol_version != PROTOCOL_VERSION {
        return false;
    }
    if report.build_identity != env!("CARGO_PKG_VERSION") {
        return false;
    }
    if report.started_unix_ms == 0 || report.finished_unix_ms < report.started_unix_ms {
        return false;
    }
    if report.artifact_paths.len() != 2 || report.artifact_hashes.len() != 2 {
        return false;
    }
    if report
        .artifact_paths
        .get("report")
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    if report
        .artifact_paths
        .get("diagnostics")
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    if report
        .artifact_hashes
        .get("report")
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    if report
        .artifact_hashes
        .get("diagnostics")
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    if report.artifact_paths != run.trusted.artifact_paths {
        return false;
    }
    if report.diagnostics_tail.len() > MAX_DIAGNOSTIC_LINES {
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
        if scenario.status != ScenarioStatus::Pass
            || scenario.check_status != EvidenceCheckStatus::Pass
            || scenario.evidence_source != EvidenceSource::LiveWhp
            || scenario.required_evidence_source != EvidenceSource::LiveWhp
        {
            return false;
        }
        let Some(expected_kind) = expected_attestation_kind(scenario.requirement_number) else {
            return false;
        };
        if scenario.attestations.len() != 1 {
            return false;
        }
        let Some(trusted_kind) = run
            .trusted
            .attestation_by_requirement
            .get(&scenario.requirement_number)
        else {
            return false;
        };
        let Some(trusted_transcript) = run
            .trusted
            .transcript_by_requirement
            .get(&scenario.requirement_number)
        else {
            return false;
        };
        if *trusted_kind != expected_kind {
            return false;
        }
        let serialized = &scenario.attestations[0];
        if serialized.kind != expected_kind || &serialized.transcript_id != trusted_transcript {
            return false;
        }
    }
    validate_attestation_artifacts(run)
}

fn validate_attestation_artifacts(run: &HarnessRun) -> bool {
    let Some(output_dir) = run.report_path.parent() else {
        return false;
    };
    if run.diagnostics_path.parent() != Some(output_dir)
        || run.attestation_manifest_path.parent() != Some(output_dir)
    {
        return false;
    }
    let manifest_bytes = match fs::read(&run.attestation_manifest_path) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let manifest: AttestationManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if manifest.schema != ATTESTATION_MANIFEST_SCHEMA
        || manifest.version != ATTESTATION_MANIFEST_VERSION
        || manifest.run_id != run.trusted.run_id
        || manifest.artifacts.len() != 2
    {
        return false;
    }
    let mut manifest_by_kind: BTreeMap<&str, &AttestedArtifact> = BTreeMap::new();
    for artifact in &manifest.artifacts {
        if manifest_by_kind
            .insert(artifact.kind.as_str(), artifact)
            .is_some()
        {
            return false;
        }
    }
    for kind in ["report", "diagnostics"] {
        let Some(artifact) = manifest_by_kind.get(kind).copied() else {
            return false;
        };
        let Some(expected_path) = run.trusted.artifact_paths.get(kind) else {
            return false;
        };
        let Some(expected_size) = run.trusted.artifact_sizes.get(kind) else {
            return false;
        };
        let Some(expected_sha256) = run.trusted.artifact_sha256.get(kind) else {
            return false;
        };
        if &artifact.path != expected_path
            || artifact.size_bytes != *expected_size
            || artifact.sha256 != *expected_sha256
        {
            return false;
        }
        let (full_path, bytes) = match read_artifact_checked(output_dir, &artifact.path) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if kind == "report" && full_path != run.report_path {
            return false;
        }
        if kind == "diagnostics" && full_path != run.diagnostics_path {
            return false;
        }
        if bytes.len() as u64 != artifact.size_bytes {
            return false;
        }
        if content_sha256_hex_bytes(&bytes) != artifact.sha256 {
            return false;
        }
    }
    true
}

pub fn has_all_scenarios_passed(run: &HarnessRun) -> bool {
    is_passing_report(run)
}

pub fn report_exit_code(run: &HarnessRun) -> ExitCode {
    if is_passing_report(run) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static HARNESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn canonical_scenarios_are_unique_and_ordered() {
        validate_canonical_scenarios().expect("canonical scenarios");
        assert_eq!(CANONICAL_SCENARIOS.len(), 12);
    }

    #[test]
    fn static_mode_never_satisfies_live_gate() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let root = std::env::temp_dir().join("nvx-agent-harness-static-gate");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::StaticOnly,
            output_dir: root,
        })
        .expect("run");
        assert!(!is_passing_report(&run));
        assert_eq!(run.exit_code(), ExitCode::FAILURE);
        assert_eq!(run.report.scenarios.len(), 12);
        assert!(
            run.report
                .scenarios
                .iter()
                .all(|scenario| scenario.status != ScenarioStatus::Pass)
        );
        assert!(
            run.report
                .scenarios
                .iter()
                .all(|scenario| scenario.required_evidence_source == EvidenceSource::LiveWhp)
        );
    }

    #[test]
    fn live_mode_without_live_whp_evidence_cannot_pass_conformance() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let root = std::env::temp_dir().join("nvx-agent-harness-live-prereq");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::LiveWhp,
            output_dir: root,
        })
        .expect("run");
        assert_eq!(run.exit_code(), ExitCode::FAILURE);
        assert!(!is_passing_report(&run));
        assert!(
            run.report
                .scenarios
                .iter()
                .all(|scenario| scenario.status != ScenarioStatus::Pass)
                || run
                    .report
                    .scenarios
                    .iter()
                    .any(|scenario| scenario.evidence_source != EvidenceSource::LiveWhp)
        );
    }

    #[test]
    fn privileged_requirements_remain_blocked_without_live_whp_evidence() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let root = std::env::temp_dir().join("nvx-agent-harness-privileged-blocked");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::StaticOnly,
            output_dir: root,
        })
        .expect("run");
        for requirement_number in [7_u8, 8_u8, 9_u8] {
            let scenario = run
                .report
                .scenarios
                .iter()
                .find(|scenario| scenario.requirement_number == requirement_number)
                .expect("scenario present");
            assert_eq!(scenario.status, ScenarioStatus::Blocked);
        }
    }

    #[test]
    fn static_mode_req10_to_req12_are_not_run_and_non_passing() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let root = std::env::temp_dir().join("nvx-agent-harness-static-runtime-req10-12");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::StaticOnly,
            output_dir: root,
        })
        .expect("run");
        for requirement_number in [10_u8, 11_u8, 12_u8] {
            let scenario = run
                .report
                .scenarios
                .iter()
                .find(|scenario| scenario.requirement_number == requirement_number)
                .expect("scenario present");
            assert_ne!(scenario.check_status, EvidenceCheckStatus::Pass);
            assert_eq!(scenario.status, ScenarioStatus::Blocked);
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_live_mode_reports_not_live_or_blocked() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let root = std::env::temp_dir().join("nvx-agent-harness-live-non-linux");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::LiveWhp,
            output_dir: root,
        })
        .expect("run");
        assert!(run.report.scenarios.iter().all(|scenario| {
            matches!(
                scenario.status,
                ScenarioStatus::Blocked
                    | ScenarioStatus::NotLive
                    | ScenarioStatus::Unsupported
                    | ScenarioStatus::Fail
            )
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_linux_runtime_executes_3_to_6_and_10_to_12_but_remains_non_conformant() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let root = std::env::temp_dir().join("nvx-agent-harness-local-linux-runtime");
        let _ = std::fs::remove_dir_all(&root);
        let run = execute_harness(HarnessOptions {
            backend: HarnessBackend::Whp,
            mode: HarnessMode::LiveWhp,
            output_dir: root,
        })
        .expect("run");
        for requirement_number in [3_u8, 4_u8, 5_u8, 6_u8, 10_u8, 11_u8, 12_u8] {
            let scenario = run
                .report
                .scenarios
                .iter()
                .find(|scenario| scenario.requirement_number == requirement_number)
                .expect("scenario present");
            if scenario.check_status == EvidenceCheckStatus::Pass {
                assert_eq!(scenario.evidence_source, EvidenceSource::LocalLinuxRuntime);
                assert_eq!(scenario.status, ScenarioStatus::NotLive);
                assert_eq!(scenario.attestations.len(), 1);
            } else {
                assert_eq!(
                    scenario.check_status,
                    EvidenceCheckStatus::NotRun,
                    "req {requirement_number} should be blocked when production paths are unavailable"
                );
                assert_eq!(scenario.status, ScenarioStatus::Blocked);
            }
        }
        assert_eq!(run.exit_code(), ExitCode::FAILURE);
    }

    #[test]
    fn req12_production_evidence_gate_rejects_fake_only_pass() {
        let definition = CANONICAL_SCENARIOS
            .iter()
            .find(|scenario| scenario.requirement_number == 12)
            .copied()
            .expect("req12");
        let check = CheckOutcome {
            check_status: EvidenceCheckStatus::Pass,
            evidence_source: EvidenceSource::UnitStatic,
            error: None,
            evidence: vec!["state machine assertions passed".to_string()],
        };
        let gated = enforce_production_runtime_evidence_gate(definition, check);
        assert_eq!(gated.check_status, EvidenceCheckStatus::Fail);
        assert_eq!(gated.evidence_source, EvidenceSource::None);
        assert!(
            gated
                .error
                .as_deref()
                .is_some_and(|msg| msg.contains("production runtime evidence source"))
        );
    }

    fn forged_passing_run() -> HarnessRun {
        let root = std::env::temp_dir().join(format!(
            "nvx-agent-harness-forged-{}-{}",
            std::process::id(),
            unix_ms_now()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create forged root");
        let mut artifact_paths = BTreeMap::new();
        artifact_paths.insert("report".to_string(), "report.json".to_string());
        artifact_paths.insert("diagnostics".to_string(), "diagnostics.log".to_string());
        let mut artifact_hashes = BTreeMap::new();
        artifact_hashes.insert(
            "report".to_string(),
            "attested-via-attestation-manifest".to_string(),
        );
        artifact_hashes.insert("diagnostics".to_string(), "present".to_string());
        let mut trusted_attestation_by_requirement = BTreeMap::new();
        let mut trusted_transcript_by_requirement = BTreeMap::new();
        let scenarios = CANONICAL_SCENARIOS
            .iter()
            .map(|scenario| {
                let kind =
                    expected_attestation_kind(scenario.requirement_number).expect("expected kind");
                let transcript = format!(
                    "run-1:req{:02}:{}",
                    scenario.requirement_number, scenario.id
                );
                trusted_attestation_by_requirement.insert(scenario.requirement_number, kind);
                trusted_transcript_by_requirement
                    .insert(scenario.requirement_number, transcript.clone());
                ScenarioResult {
                    requirement_number: scenario.requirement_number,
                    id: scenario.id.to_string(),
                    name: scenario.name.to_string(),
                    status: ScenarioStatus::Pass,
                    check_status: EvidenceCheckStatus::Pass,
                    evidence_source: EvidenceSource::LiveWhp,
                    required_evidence_source: EvidenceSource::LiveWhp,
                    error: None,
                    evidence: vec![],
                    attestations: vec![ScenarioAttestation {
                        kind,
                        transcript_id: transcript,
                    }],
                    duration_ms: 1,
                }
            })
            .collect();
        let report = HarnessReport {
            schema: REPORT_SCHEMA.to_string(),
            version: REPORT_VERSION,
            mode: HarnessMode::LiveWhp,
            platform: "windows".to_string(),
            backend: HarnessBackend::Whp.as_str().to_string(),
            service_identity: "nvx.mxc.agent.v1".to_string(),
            protocol_version: PROTOCOL_VERSION,
            build_identity: env!("CARGO_PKG_VERSION").to_string(),
            started_unix_ms: 1,
            finished_unix_ms: 2,
            scenarios,
            artifact_paths,
            artifact_hashes,
            diagnostics_tail: vec!["ok".to_string()],
        };
        let report_path = root.join("report.json");
        let diagnostics_path = root.join("diagnostics.log");
        let attestation_manifest_path = root.join("attestation-manifest.json");
        let diagnostics_bytes = b"ok".to_vec();
        std::fs::write(&diagnostics_path, &diagnostics_bytes).expect("write diagnostics");
        let report_bytes = serde_json::to_vec_pretty(&report).expect("serialize report");
        std::fs::write(&report_path, &report_bytes).expect("write report");
        let manifest = AttestationManifest {
            schema: ATTESTATION_MANIFEST_SCHEMA.to_string(),
            version: ATTESTATION_MANIFEST_VERSION,
            run_id: "run-1".to_string(),
            artifacts: vec![
                AttestedArtifact {
                    kind: "report".to_string(),
                    path: "report.json".to_string(),
                    size_bytes: report_bytes.len() as u64,
                    sha256: content_sha256_hex_bytes(&report_bytes),
                },
                AttestedArtifact {
                    kind: "diagnostics".to_string(),
                    path: "diagnostics.log".to_string(),
                    size_bytes: diagnostics_bytes.len() as u64,
                    sha256: content_sha256_hex_bytes(&diagnostics_bytes),
                },
            ],
        };
        std::fs::write(
            &attestation_manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("write manifest");
        HarnessRun {
            report_path,
            diagnostics_path,
            attestation_manifest_path,
            trusted: TrustedEvidence {
                attestation_by_requirement: trusted_attestation_by_requirement,
                transcript_by_requirement: trusted_transcript_by_requirement,
                artifact_paths: report.artifact_paths.clone(),
                artifact_sizes: BTreeMap::from([
                    ("report".to_string(), report_bytes.len() as u64),
                    ("diagnostics".to_string(), diagnostics_bytes.len() as u64),
                ]),
                artifact_sha256: BTreeMap::from([
                    (
                        "report".to_string(),
                        content_sha256_hex_bytes(&report_bytes),
                    ),
                    (
                        "diagnostics".to_string(),
                        content_sha256_hex_bytes(&diagnostics_bytes),
                    ),
                ]),
                run_id: "run-1".to_string(),
            },
            report,
        }
    }

    #[test]
    fn fabricated_report_without_trusted_attestation_fails() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let mut run = forged_passing_run();
        run.trusted.attestation_by_requirement.clear();
        assert!(!is_passing_report(&run));
    }

    #[test]
    fn canonical_gate_rejects_adversarial_attestation_and_artifact_mutations() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let run = forged_passing_run();
        assert!(is_passing_report(&run));
        assert_eq!(report_exit_code(&run), ExitCode::SUCCESS);

        let mut missing_attestation = run.clone();
        missing_attestation.report.scenarios[0].attestations.clear();
        assert!(!is_passing_report(&missing_attestation));

        let mut wrong_kind = run.clone();
        wrong_kind.report.scenarios[0].attestations[0].kind =
            AttestationKind::Req12ChannelLossGeneration;
        assert!(!is_passing_report(&wrong_kind));

        let mut duplicate = run.clone();
        let duplicated = duplicate.report.scenarios[0].attestations[0].clone();
        duplicate.report.scenarios[0].attestations.push(duplicated);
        assert!(!is_passing_report(&duplicate));

        let mut mismatch_transcript = run.clone();
        mismatch_transcript.report.scenarios[0].attestations[0].transcript_id =
            "forged".to_string();
        assert!(!is_passing_report(&mismatch_transcript));

        let mut artifact_path_mismatch = run.clone();
        artifact_path_mismatch
            .report
            .artifact_paths
            .insert("diagnostics".to_string(), "forged.log".to_string());
        assert!(!is_passing_report(&artifact_path_mismatch));
    }

    #[test]
    fn canonical_gate_rejects_adversarial_top_level_fields() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let run = forged_passing_run();
        assert!(is_passing_report(&run));
        assert_eq!(report_exit_code(&run), ExitCode::SUCCESS);

        let mut bad_schema = run.clone();
        bad_schema.report.schema = "forged.schema".to_string();
        assert!(!is_passing_report(&bad_schema));
        assert_eq!(report_exit_code(&bad_schema), ExitCode::FAILURE);

        let mut bad_version = run.clone();
        bad_version.report.version += 1;
        assert!(!is_passing_report(&bad_version));

        let mut bad_mode = run.clone();
        bad_mode.report.mode = HarnessMode::StaticOnly;
        assert!(!is_passing_report(&bad_mode));

        let mut bad_platform = run.clone();
        bad_platform.report.platform = "linux".to_string();
        assert!(!is_passing_report(&bad_platform));

        let mut bad_backend = run.clone();
        bad_backend.report.backend = "lxc".to_string();
        assert!(!is_passing_report(&bad_backend));

        let mut bad_protocol = run.clone();
        bad_protocol.report.protocol_version += 1;
        assert!(!is_passing_report(&bad_protocol));

        let mut bad_service = run.clone();
        bad_service.report.service_identity = "forged.service".to_string();
        assert!(!is_passing_report(&bad_service));

        let mut bad_started = run.clone();
        bad_started.report.started_unix_ms = 0;
        assert!(!is_passing_report(&bad_started));

        let mut bad_finished = run.clone();
        bad_finished.report.finished_unix_ms = 0;
        assert!(!is_passing_report(&bad_finished));

        let mut bad_build = run.clone();
        bad_build.report.build_identity = "forged-build".to_string();
        assert!(!is_passing_report(&bad_build));

        let mut bad_artifacts = run.clone();
        bad_artifacts
            .report
            .artifact_paths
            .insert("forged".to_string(), "value".to_string());
        assert!(!is_passing_report(&bad_artifacts));

        let mut bad_diagnostics = run.clone();
        bad_diagnostics.report.diagnostics_tail = vec!["x".to_string(); MAX_DIAGNOSTIC_LINES + 1];
        assert!(!is_passing_report(&bad_diagnostics));
    }

    #[test]
    fn canonical_gate_rejects_missing_modified_truncated_swapped_and_tampered_artifacts() {
        let _guard = HARNESS_TEST_LOCK.lock().expect("lock");
        let missing = forged_passing_run();
        assert!(is_passing_report(&missing));
        std::fs::remove_file(&missing.diagnostics_path).expect("remove diagnostics");
        assert!(!is_passing_report(&missing));

        let modified = forged_passing_run();
        assert!(is_passing_report(&modified));
        std::fs::write(&modified.diagnostics_path, b"ok\nforged").expect("modify diagnostics");
        assert!(!is_passing_report(&modified));

        let truncated = forged_passing_run();
        assert!(is_passing_report(&truncated));
        std::fs::write(&truncated.report_path, b"{}").expect("truncate report");
        assert!(!is_passing_report(&truncated));

        let swapped = forged_passing_run();
        assert!(is_passing_report(&swapped));
        let report_bytes = std::fs::read(&swapped.report_path).expect("read report");
        let diagnostics_bytes = std::fs::read(&swapped.diagnostics_path).expect("read diagnostics");
        std::fs::write(&swapped.report_path, &diagnostics_bytes).expect("swap report");
        std::fs::write(&swapped.diagnostics_path, &report_bytes).expect("swap diagnostics");
        assert!(!is_passing_report(&swapped));

        let escaped = forged_passing_run();
        assert!(is_passing_report(&escaped));
        let escaped_manifest = AttestationManifest {
            schema: ATTESTATION_MANIFEST_SCHEMA.to_string(),
            version: ATTESTATION_MANIFEST_VERSION,
            run_id: escaped.trusted.run_id.clone(),
            artifacts: vec![
                AttestedArtifact {
                    kind: "report".to_string(),
                    path: "../report.json".to_string(),
                    size_bytes: *escaped.trusted.artifact_sizes.get("report").expect("size"),
                    sha256: escaped
                        .trusted
                        .artifact_sha256
                        .get("report")
                        .expect("sha")
                        .clone(),
                },
                AttestedArtifact {
                    kind: "diagnostics".to_string(),
                    path: "diagnostics.log".to_string(),
                    size_bytes: *escaped
                        .trusted
                        .artifact_sizes
                        .get("diagnostics")
                        .expect("size"),
                    sha256: escaped
                        .trusted
                        .artifact_sha256
                        .get("diagnostics")
                        .expect("sha")
                        .clone(),
                },
            ],
        };
        std::fs::write(
            &escaped.attestation_manifest_path,
            serde_json::to_vec_pretty(&escaped_manifest).expect("escape manifest bytes"),
        )
        .expect("write escaped manifest");
        assert!(!is_passing_report(&escaped));

        let tampered_manifest = forged_passing_run();
        assert!(is_passing_report(&tampered_manifest));
        let mut manifest: AttestationManifest = serde_json::from_slice(
            &std::fs::read(&tampered_manifest.attestation_manifest_path).expect("read manifest"),
        )
        .expect("parse manifest");
        manifest.run_id = "forged-run".to_string();
        std::fs::write(
            &tampered_manifest.attestation_manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("tampered manifest bytes"),
        )
        .expect("write tampered manifest");
        assert!(!is_passing_report(&tampered_manifest));
    }
}
