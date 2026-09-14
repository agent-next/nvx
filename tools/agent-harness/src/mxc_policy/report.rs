use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use super::PolicyError;
use super::adapter::adapt_policy;
use super::cases::{
    ExpectedDisposition, PolicyCase, StaticCaseResult, live_profile_for_path, load_corpus,
    load_single_config, run_static_cases, validate_case_disposition_contract, validate_corpus,
};
use super::catalog::{CatalogEntry, EvidenceRequirement, PolicyDisposition, catalog, catalog_hash};
use super::live::{
    LiveExecuteCleanup, LiveExecuteEvidence, LiveProfileResult, LiveProfileStatus,
    execute_live_config, run_live_profiles,
};
use super::schema::{normalized_sha256, provenance, raw_sha256};
use crate::launch::LaunchOverrides;
use crate::{HarnessBackend, content_sha256_hex_bytes, write_bytes_atomic, write_json_atomic};
#[cfg(windows)]
use agent_protocol::messages::ExecDisposition;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REPORT_SCHEMA: &str = "nvx.mxc.policy.harness.report.v1";
const REPORT_VERSION: u32 = 1;
const MANIFEST_SCHEMA: &str = "nvx.mxc.policy.harness.attestation-manifest.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyHarnessMode {
    LiveWhp,
    StaticOnly,
}

#[derive(Clone, Debug)]
pub struct PolicyHarnessOptions {
    pub backend: HarnessBackend,
    pub mode: PolicyHarnessMode,
    pub output_dir: PathBuf,
    pub config: Option<PathBuf>,
    pub execute_config: bool,
    pub launch_overrides: LaunchOverrides,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshnessPins {
    pub schema_version: String,
    pub schema_source_commit: String,
    pub schema_raw_sha256: String,
    pub schema_normalized_sha256: String,
    pub catalog_sha256: String,
    pub catalog_source_sha256: String,
    pub adapter_sha256: String,
    pub protocol_version: u32,
    pub protocol_source_sha256: String,
    pub case_corpus_sha256: String,
    pub live_profile_inputs_sha256: String,
    pub kernel_sha256: Option<String>,
    pub initramfs_sha256: Option<String>,
    pub probe_sha256: Option<String>,
    pub openvmm_sha256: Option<String>,
    pub harness_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogResult {
    pub key: String,
    pub schema_path: String,
    pub disposition: PolicyDisposition,
    pub phases: Vec<super::catalog::MxcPhase>,
    pub case_ids: Vec<String>,
    pub expected_outcome: String,
    pub expected_instance_outcome: String,
    pub actual_outcome: String,
    pub evidence_tier: EvidenceRequirement,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub artifact_references: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyHarnessReport {
    pub schema: String,
    pub version: u32,
    pub mode: PolicyHarnessMode,
    pub backend: String,
    pub freshness: FreshnessPins,
    pub catalog_results: Vec<CatalogResult>,
    pub static_cases: Vec<StaticCaseResult>,
    pub live_profiles: BTreeMap<String, LiveProfileResult>,
    pub execute_config: Option<ExecuteConfigReport>,
    pub uncovered: Vec<String>,
    pub unexpected: Vec<String>,
    pub blocked: Vec<String>,
    pub failed: Vec<String>,
    pub rejection_effects_zero: bool,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteConfigArtifact {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteConfigTerminal {
    #[cfg(windows)]
    pub disposition: ExecDisposition,
    #[cfg(not(windows))]
    pub disposition: String,
    #[cfg(windows)]
    pub termination: Option<agent_protocol::messages::TerminationOutcome>,
    #[cfg(not(windows))]
    pub termination: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteConfigReport {
    pub tier: String,
    pub exec_id: u32,
    pub terminal: ExecuteConfigTerminal,
    pub stdout: ExecuteConfigArtifact,
    pub stderr: ExecuteConfigArtifact,
    pub outcome: ExecuteConfigArtifact,
    pub cleanup: LiveExecuteCleanup,
    pub passed: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyManifest {
    pub schema: String,
    pub version: u32,
    pub artifacts: Vec<PolicyAttestedArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAttestedArtifact {
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct PolicyHarnessRun {
    pub report: PolicyHarnessReport,
    pub report_path: PathBuf,
    pub diagnostics_path: PathBuf,
    pub attestation_manifest_path: PathBuf,
    trusted_artifacts: BTreeMap<String, (String, u64, String)>,
}

#[derive(Clone, Debug)]
struct PreparedExecuteConfig {
    case: PolicyCase,
    exec: super::NvxExecPolicy,
}

#[derive(Clone, Copy, Debug)]
struct OutcomeEvaluation {
    mode: PolicyHarnessMode,
    enforce_static_links: bool,
    execute_config_mode: bool,
}

impl PolicyHarnessRun {
    pub fn exit_code(&self) -> ExitCode {
        if self.report.passed && verify_policy_run(self).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

pub fn execute_policy_harness(
    options: PolicyHarnessOptions,
) -> Result<PolicyHarnessRun, PolicyError> {
    let started = Instant::now();
    let schema_provenance = provenance()?;
    if raw_sha256() != schema_provenance.raw_sha256
        || normalized_sha256()? != schema_provenance.normalized_sha256
        || super::schema::schema()?["$schema"] != schema_provenance.draft
    {
        return Err(PolicyError::new(
            "schema_provenance_mismatch",
            "$",
            "vendored schema bytes, normalized form, or Draft do not match provenance",
        ));
    }
    let execute_config = validate_execute_config_request(&options)?;
    let cases = match (&options.config, &execute_config) {
        (_, Some(prepared)) => vec![prepared.case.clone()],
        (Some(path), None) => vec![load_single_config(path)?],
        (None, None) => load_corpus()?,
    };
    let coverage = if options.config.is_none() {
        validate_corpus(&cases)?
    } else {
        BTreeMap::new()
    };
    let rejected_output = options.output_dir.join("rejected-cases");
    let static_root = options
        .launch_overrides
        .common_root
        .as_deref()
        .unwrap_or_else(|| Path::new(r"C:\nvx-policy-common"));
    let static_results = run_static_cases(&cases, static_root, &rejected_output);
    let rejection_effects_zero = static_results.iter().all(|result| {
        result.expected_disposition != ExpectedDisposition::Rejected
            || (result.effect_counters.is_zero() && !result.output_directory_created)
    });

    let live_profiles = if options.mode == PolicyHarnessMode::LiveWhp && !options.execute_config {
        run_live_profiles(&options)
    } else {
        BTreeMap::new()
    };
    let execute_config_report = match execute_config {
        Some(prepared) => Some(run_execute_config_live(&options, prepared.exec)?),
        None => None,
    };
    let catalog_entries = catalog()?;
    let mut uncovered = Vec::new();
    let mut unexpected = static_results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.id.clone())
        .collect::<Vec<_>>();
    let mut blocked = Vec::new();
    let mut failed = Vec::new();
    let static_results_by_id = static_results
        .iter()
        .map(|result| (result.id.as_str(), result))
        .collect::<BTreeMap<_, _>>();
    let case_by_id = cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut catalog_results = Vec::with_capacity(catalog_entries.len());
    for entry in catalog_entries {
        let case_ids = coverage.get(entry.key).cloned().unwrap_or_default();
        if options.config.is_none() && case_ids.is_empty() {
            uncovered.push(entry.key.to_string());
        }
        let (actual_outcome, error, artifacts) = actual_outcome(
            &entry,
            &case_ids,
            &case_by_id,
            &static_results_by_id,
            &live_profiles,
            OutcomeEvaluation {
                mode: options.mode,
                enforce_static_links: options.config.is_none(),
                execute_config_mode: options.execute_config,
            },
        );
        match actual_outcome.as_str() {
            "blocked" => blocked.push(entry.key.to_string()),
            "failed" => failed.push(entry.key.to_string()),
            "unexpected" => unexpected.push(entry.key.to_string()),
            _ => {}
        }
        let expected_instance_outcome =
            linked_expected_instance_outcome(&case_ids, &case_by_id).to_string();
        catalog_results.push(CatalogResult {
            key: entry.key.to_string(),
            schema_path: entry.schema_path.to_string(),
            disposition: entry.disposition,
            phases: entry.phases.to_vec(),
            case_ids,
            expected_outcome: expected_outcome(entry.disposition).to_string(),
            expected_instance_outcome,
            actual_outcome,
            evidence_tier: entry.required_evidence(),
            duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            error,
            artifact_references: artifacts,
        });
    }

    let freshness = freshness_pins(&options)?;
    let freshness_complete = options.mode == PolicyHarnessMode::StaticOnly
        || (freshness.kernel_sha256.is_some()
            && freshness.initramfs_sha256.is_some()
            && freshness.probe_sha256.is_some()
            && freshness.openvmm_sha256.is_some()
            && freshness.harness_sha256.is_some()
            && freshness.protocol_source_sha256 != "missing");
    if !freshness_complete {
        failed.push("freshness-identities".to_string());
    }
    let live_profiles_complete = live_profiles_complete(options.mode, &live_profiles);
    if let Some(execute_result) = &execute_config_report
        && !execute_result.passed
    {
        failed.push("execute-config".to_string());
    }
    let passed = uncovered.is_empty()
        && unexpected.is_empty()
        && failed.is_empty()
        && blocked.is_empty()
        && rejection_effects_zero
        && live_profiles_complete
        && execute_config_report
            .as_ref()
            .is_none_or(|result| result.passed);
    let report = PolicyHarnessReport {
        schema: REPORT_SCHEMA.to_string(),
        version: REPORT_VERSION,
        mode: options.mode,
        backend: options.backend.as_str().to_string(),
        freshness,
        catalog_results,
        static_cases: static_results,
        live_profiles,
        execute_config: execute_config_report,
        uncovered,
        unexpected,
        blocked,
        failed,
        rejection_effects_zero,
        passed,
    };

    fs::create_dir_all(&options.output_dir).map_err(|error| {
        PolicyError::new(
            "report_io",
            "$",
            format!(
                "failed to create policy output {}: {error}",
                options.output_dir.display()
            ),
        )
    })?;
    let diagnostics_path = options.output_dir.join("diagnostics.log");
    let report_path = options.output_dir.join("report.json");
    let manifest_path = options.output_dir.join("attestation-manifest.json");
    let diagnostics = diagnostics_text(&report);
    write_bytes_atomic(&diagnostics_path, diagnostics.as_bytes())
        .map_err(|error| PolicyError::new("report_io", "$", error))?;
    write_json_atomic(&report_path, &report)
        .map_err(|error| PolicyError::new("report_io", "$", error))?;
    let manifest = build_manifest(&options.output_dir)?;
    let trusted_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                (
                    artifact.kind.clone(),
                    artifact.size_bytes,
                    artifact.sha256.clone(),
                ),
            )
        })
        .collect();
    write_json_atomic(&manifest_path, &manifest)
        .map_err(|error| PolicyError::new("report_io", "$", error))?;
    let run = PolicyHarnessRun {
        report,
        report_path,
        diagnostics_path,
        attestation_manifest_path: manifest_path,
        trusted_artifacts,
    };
    verify_policy_run(&run)?;
    Ok(run)
}

fn validate_execute_config_request(
    options: &PolicyHarnessOptions,
) -> Result<Option<PreparedExecuteConfig>, PolicyError> {
    if !options.execute_config {
        return Ok(None);
    }
    if options.backend != HarnessBackend::Whp {
        return Err(PolicyError::new(
            "execute_config_requires_whp",
            "/backend",
            "--execute-config requires --backend whp",
        ));
    }
    if options.mode != PolicyHarnessMode::LiveWhp {
        return Err(PolicyError::new(
            "execute_config_requires_live_mode",
            "/mode",
            "--execute-config cannot be combined with --static-only",
        ));
    }
    let config_path = options.config.as_ref().ok_or_else(|| {
        PolicyError::new(
            "execute_config_requires_config",
            "/config",
            "--execute-config requires --config <path>",
        )
    })?;
    let case = load_single_config(config_path)?;
    let static_root = options
        .launch_overrides
        .common_root
        .as_deref()
        .unwrap_or_else(|| Path::new(r"C:\nvx-policy-common"));
    let adapted = adapt_policy(case.id.clone(), &case.config, static_root).map_err(|errors| {
        errors.first().cloned().unwrap_or_else(|| {
            PolicyError::new(
                "execute_config_rejected",
                "$",
                "policy adaptation rejected execute-config input",
            )
        })
    })?;
    if adapted.phase != super::MxcPhase::Exec {
        return Err(PolicyError::new(
            "execute_config_invalid_phase",
            "/phase",
            format!(
                "--execute-config requires an accepted phase=exec policy, got {}",
                adapted.phase.as_str()
            ),
        ));
    }
    let exec = adapted.exec.ok_or_else(|| {
        PolicyError::new(
            "execute_config_missing_exec",
            "/process",
            "accepted phase=exec policy did not produce an exec plan",
        )
    })?;
    Ok(Some(PreparedExecuteConfig { case, exec }))
}

fn run_execute_config_live(
    options: &PolicyHarnessOptions,
    exec: super::NvxExecPolicy,
) -> Result<ExecuteConfigReport, PolicyError> {
    let evidence = execute_live_config(options, exec).map_err(|error| {
        PolicyError::new(
            "execute_config_live_failed",
            "$",
            format!("live execute-config run failed: {error}"),
        )
    })?;
    fs::create_dir_all(&options.output_dir).map_err(|error| {
        PolicyError::new(
            "report_io",
            "$",
            format!(
                "failed to create policy output {}: {error}",
                options.output_dir.display()
            ),
        )
    })?;
    let stdout = write_execute_artifact(
        &options.output_dir,
        Path::new("execute-config").join("stdout.bin"),
        &evidence.stdout,
    )?;
    let stderr = write_execute_artifact(
        &options.output_dir,
        Path::new("execute-config").join("stderr.bin"),
        &evidence.stderr,
    )?;
    let terminal = ExecuteConfigTerminal {
        #[cfg(windows)]
        disposition: evidence.disposition,
        #[cfg(not(windows))]
        disposition: evidence.disposition,
        #[cfg(windows)]
        termination: evidence.termination,
        #[cfg(not(windows))]
        termination: evidence.termination,
    };
    let outcome_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "tier": &evidence.tier,
        "execId": evidence.exec_id,
        "terminal": &terminal,
        "cleanup": &evidence.cleanup,
        "stdoutArtifactPath": &stdout.path,
        "stderrArtifactPath": &stderr.path,
    }))
    .map_err(|error| {
        PolicyError::new(
            "report_io",
            "$",
            format!("serialize execute-config outcome: {error}"),
        )
    })?;
    let outcome = write_execute_artifact(
        &options.output_dir,
        Path::new("execute-config").join("outcome.json"),
        &outcome_bytes,
    )?;
    let cleanup_ok = evidence.cleanup.shutdown_acknowledged
        && evidence.cleanup.channel_closed
        && evidence.cleanup.process_exited
        && evidence.cleanup.explicit_teardown_succeeded
        && evidence.cleanup.cleanup_error.is_none();
    let exit_zero = execute_disposition_is_success(&evidence);
    let passed = cleanup_ok && exit_zero;
    let mut errors = Vec::new();
    if !exit_zero {
        errors.push("ExecTerminal disposition was not ExitCode(0)".to_string());
    }
    if !cleanup_ok {
        errors.push("cleanup verification did not complete successfully".to_string());
    }
    if let Some(cleanup_error) = &evidence.cleanup.cleanup_error {
        errors.push(format!("explicit teardown error: {cleanup_error}"));
    }
    Ok(ExecuteConfigReport {
        tier: evidence.tier,
        exec_id: evidence.exec_id,
        terminal,
        stdout,
        stderr,
        outcome,
        cleanup: evidence.cleanup,
        passed,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    })
}

fn write_execute_artifact(
    output_dir: &Path,
    relative: PathBuf,
    bytes: &[u8],
) -> Result<ExecuteConfigArtifact, PolicyError> {
    let path = output_dir.join(&relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            PolicyError::new(
                "report_io",
                "$",
                format!(
                    "failed to create execute-config artifact directory {}: {error}",
                    parent.display()
                ),
            )
        })?;
    }
    write_bytes_atomic(&path, bytes).map_err(|error| PolicyError::new("report_io", "$", error))?;
    Ok(ExecuteConfigArtifact {
        path: relative.to_string_lossy().replace('\\', "/"),
        size_bytes: bytes.len() as u64,
        sha256: content_sha256_hex_bytes(bytes),
    })
}

#[cfg(windows)]
fn execute_disposition_is_success(evidence: &LiveExecuteEvidence) -> bool {
    evidence.disposition == ExecDisposition::ExitCode(0)
}

#[cfg(not(windows))]
fn execute_disposition_is_success(evidence: &LiveExecuteEvidence) -> bool {
    evidence.disposition == "ExitCode(0)"
}

fn live_profiles_complete(
    mode: PolicyHarnessMode,
    profiles: &BTreeMap<String, LiveProfileResult>,
) -> bool {
    mode == PolicyHarnessMode::StaticOnly
        || profiles.values().all(|profile| {
            profile.status == LiveProfileStatus::Pass
                && profile.positive_passed
                && profile.negative_passed
        })
}

fn actual_outcome(
    entry: &CatalogEntry,
    case_ids: &[String],
    cases: &BTreeMap<&str, &PolicyCase>,
    static_results: &BTreeMap<&str, &StaticCaseResult>,
    live: &BTreeMap<String, LiveProfileResult>,
    evaluation: OutcomeEvaluation,
) -> (String, Option<String>, Vec<String>) {
    let (static_status, static_error, mut artifacts) = static_outcome(
        entry,
        case_ids,
        cases,
        static_results,
        evaluation.enforce_static_links,
    );
    if static_status != "passed" {
        return (static_status, static_error, artifacts);
    }
    if entry.required_evidence() != EvidenceRequirement::LiveWhpPositiveNegative {
        return ("passed".to_string(), None, artifacts);
    }
    if evaluation.execute_config_mode {
        return ("passed".to_string(), None, artifacts);
    }
    if evaluation.mode == PolicyHarnessMode::StaticOnly {
        return (
            "blocked".to_string(),
            Some("live WHP positive/negative evidence was not requested".to_string()),
            artifacts,
        );
    }
    let Some(profile_id) = live_profile_for_path(entry.key) else {
        return (
            "failed".to_string(),
            Some("no live profile maps this honored construct".to_string()),
            artifacts,
        );
    };
    let Some(profile) = live.get(profile_id) else {
        return (
            "failed".to_string(),
            Some(format!("live profile {profile_id} did not run")),
            artifacts,
        );
    };
    let status = match profile.status {
        LiveProfileStatus::Pass if profile.positive_passed && profile.negative_passed => "passed",
        LiveProfileStatus::Pass => "failed",
        LiveProfileStatus::Fail => "failed",
        LiveProfileStatus::Blocked => "blocked",
    };
    artifacts.push(format!("live-canonical-evidence:{}", profile.id));
    (status.to_string(), profile.error.clone(), artifacts)
}

fn static_outcome(
    entry: &CatalogEntry,
    case_ids: &[String],
    cases: &BTreeMap<&str, &PolicyCase>,
    static_results: &BTreeMap<&str, &StaticCaseResult>,
    enforce_static_links: bool,
) -> (String, Option<String>, Vec<String>) {
    let artifacts = case_ids
        .iter()
        .map(|id| format!("static-case:{id}"))
        .collect::<Vec<_>>();
    if case_ids.is_empty() {
        if enforce_static_links {
            return (
                "failed".to_string(),
                Some("catalog entry has no linked static case results".to_string()),
                artifacts,
            );
        }
        return ("passed".to_string(), None, artifacts);
    }

    let mut missing = Vec::new();
    let mut unexpected = Vec::new();
    for case_id in case_ids {
        let Some(case) = cases.get(case_id.as_str()) else {
            missing.push(case_id.clone());
            continue;
        };
        if let Err(message) = validate_case_disposition_contract(entry, case.expected_disposition) {
            unexpected.push(format!("{case_id}:contract:{message}"));
            continue;
        }
        let Some(result) = static_results.get(case_id.as_str()) else {
            missing.push(case_id.clone());
            continue;
        };
        if !result.passed {
            let detail = match &result.error {
                Some(error) => format!(
                    "{}:{}@{}",
                    case_id,
                    error.code,
                    if error.instance_path.is_empty() {
                        "$"
                    } else {
                        error.instance_path.as_str()
                    }
                ),
                None => case_id.clone(),
            };
            unexpected.push(detail);
        }
    }
    if !missing.is_empty() {
        return (
            "failed".to_string(),
            Some(format!(
                "linked static cases did not run: {}",
                missing.join(", ")
            )),
            artifacts,
        );
    }
    if !unexpected.is_empty() {
        return (
            "unexpected".to_string(),
            Some(format!(
                "linked static cases had unexpected outcomes: {}",
                unexpected.join(", ")
            )),
            artifacts,
        );
    }
    ("passed".to_string(), None, artifacts)
}

fn linked_expected_instance_outcome(
    case_ids: &[String],
    cases: &BTreeMap<&str, &PolicyCase>,
) -> &'static str {
    let mut accepted = false;
    let mut rejected = false;
    for case_id in case_ids {
        match cases
            .get(case_id.as_str())
            .map(|case| case.expected_disposition)
        {
            Some(ExpectedDisposition::Accepted) => accepted = true,
            Some(ExpectedDisposition::Rejected) => rejected = true,
            None => return "missing",
        }
    }
    match (accepted, rejected) {
        (true, false) => "accepted",
        (false, true) => "rejected",
        (true, true) => "mixed",
        (false, false) => "missing",
    }
}

fn expected_outcome(disposition: PolicyDisposition) -> &'static str {
    match disposition {
        PolicyDisposition::Honored => "honored",
        PolicyDisposition::AcceptedInert => "accepted-inert",
        PolicyDisposition::Rejected => "rejected-pre-effects",
        PolicyDisposition::Control => "validated-control",
    }
}

fn freshness_pins(options: &PolicyHarnessOptions) -> Result<FreshnessPins, PolicyError> {
    let provenance = provenance()?;
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let schema_raw_sha256 = hash_checked_source(
        &repo_root,
        Path::new("tools/agent-harness/schemas/mxc-config.schema.0.9.0-dev.json"),
        super::schema::schema_bytes(),
        "MXC schema",
    )?;
    let catalog_source_sha256 = hash_checked_source(
        &repo_root,
        Path::new("tools/agent-harness/src/mxc_policy/catalog.rs"),
        include_bytes!("catalog.rs"),
        "policy catalog source",
    )?;
    let adapter_sha256 = hash_checked_source(
        &repo_root,
        Path::new("tools/agent-harness/src/mxc_policy/adapter.rs"),
        include_bytes!("adapter.rs"),
        "policy adapter source",
    )?;
    let protocol_source_sha256 = hash_checked_source(
        &repo_root,
        Path::new("agent-protocol/src/messages.rs"),
        include_bytes!("../../../../agent-protocol/src/messages.rs"),
        "agent protocol source",
    )?;
    let case_corpus_sha256 = hash_checked_source(
        &repo_root,
        Path::new("tools/agent-harness/fixtures/mxc-policy/cases.json"),
        super::cases::corpus_bytes(),
        "policy case corpus",
    )?;
    let probe_path = repo_root
        .join("build")
        .join("nvx-agent-probe-mxc-prototype");
    Ok(FreshnessPins {
        schema_version: "0.9.0-dev".to_string(),
        schema_source_commit: provenance.source_commit,
        schema_raw_sha256,
        schema_normalized_sha256: normalized_sha256()?,
        catalog_sha256: catalog_hash()?,
        catalog_source_sha256,
        adapter_sha256,
        protocol_version: agent_protocol::PROTOCOL_VERSION,
        protocol_source_sha256,
        case_corpus_sha256,
        live_profile_inputs_sha256: live_profile_inputs_hash()?,
        kernel_sha256: options
            .launch_overrides
            .kernel
            .as_deref()
            .and_then(hash_optional),
        initramfs_sha256: options
            .launch_overrides
            .mxc_initramfs
            .as_deref()
            .and_then(hash_optional),
        probe_sha256: hash_optional(&probe_path),
        openvmm_sha256: options
            .launch_overrides
            .openvmm_exe
            .as_deref()
            .and_then(hash_optional),
        harness_sha256: std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(hash_optional),
    })
}

fn hash_checked_source(
    repo_root: &Path,
    relative: &Path,
    embedded: &[u8],
    label: &str,
) -> Result<String, PolicyError> {
    let relative_string = relative.to_string_lossy();
    let (_, reopened) =
        crate::read_artifact_checked(repo_root, &relative_string).map_err(|error| {
            PolicyError::new(
                "freshness_io",
                relative.display().to_string(),
                format!("reading {label}: {error}"),
            )
        })?;
    let reopened_hash = content_sha256_hex_bytes(&reopened);
    let embedded_hash = content_sha256_hex_bytes(embedded);
    if reopened_hash != embedded_hash {
        return Err(PolicyError::new(
            "freshness_drift",
            relative.display().to_string(),
            format!(
                "{label} differs from the bytes embedded in this harness: embedded={embedded_hash}, checkout={reopened_hash}"
            ),
        ));
    }
    Ok(reopened_hash)
}

fn live_profile_inputs_hash() -> Result<String, PolicyError> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("mxc-policy")
        .join("live");
    let mut hasher = Sha256::new();
    for name in [
        "provision.json",
        "start.json",
        "exec.json",
        "stop.json",
        "deprovision.json",
    ] {
        let path = root.join(name);
        let bytes = fs::read(&path).map_err(|error| {
            PolicyError::new(
                "freshness_io",
                path.display().to_string(),
                format!("reading live policy input: {error}"),
            )
        })?;
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_optional(path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| content_sha256_hex_bytes(&bytes))
}

fn diagnostics_text(report: &PolicyHarnessReport) -> String {
    format!(
        "schema={} version={} mode={:?} passed={}\nuncovered={:?}\nunexpected={:?}\nblocked={:?}\nfailed={:?}\n",
        report.schema,
        report.version,
        report.mode,
        report.passed,
        report.uncovered,
        report.unexpected,
        report.blocked,
        report.failed
    )
}

fn build_manifest(root: &Path) -> Result<PolicyManifest, PolicyError> {
    let mut paths = Vec::new();
    collect_attested_files(root, root, &mut paths)?;
    paths.sort();
    let mut artifacts = Vec::new();
    for path in &paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PolicyError::new("report_io", "$", "attested path escaped output root"))?;
        let relative = relative.to_string_lossy().replace('\\', "/");
        let (_, bytes) = crate::read_artifact_checked(root, &relative)
            .map_err(|error| PolicyError::new("report_io", relative.clone(), error))?;
        artifacts.push(PolicyAttestedArtifact {
            path: relative,
            kind: "file".to_string(),
            size_bytes: bytes.len() as u64,
            sha256: content_sha256_hex_bytes(&bytes),
        });
    }
    Ok(PolicyManifest {
        schema: MANIFEST_SCHEMA.to_string(),
        version: 1,
        artifacts,
    })
}

fn collect_attested_files(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), PolicyError> {
    crate::reject_symlink_or_reparse_metadata(directory, root)
        .map_err(|error| PolicyError::new("report_io", "$", error))?;
    for entry in fs::read_dir(directory).map_err(|error| {
        PolicyError::new(
            "report_io",
            "$",
            format!(
                "failed to enumerate {} for attestation: {error}",
                directory.display()
            ),
        )
    })? {
        let entry = entry.map_err(|error| PolicyError::new("report_io", "$", error.to_string()))?;
        let path = entry.path();
        if path == root.join("attestation-manifest.json") {
            continue;
        }
        crate::reject_symlink_or_reparse_metadata(&path, root)
            .map_err(|error| PolicyError::new("report_io", "$", error))?;
        let file_type = entry.file_type().map_err(|error| {
            PolicyError::new(
                "report_io",
                "$",
                format!(
                    "failed to inspect {} for attestation: {error}",
                    path.display()
                ),
            )
        })?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PolicyError::new("report_io", "$", "attested path escaped output root"))?;
        if is_excluded_runtime_common_root(relative) {
            if !file_type.is_dir() {
                return Err(PolicyError::new(
                    "report_io",
                    "$",
                    "excluded common-root artifact must be a real directory",
                ));
            }
            continue;
        }
        if file_type.is_dir() {
            collect_attested_files(root, &path, paths)?;
        } else if file_type.is_file() {
            paths.push(path);
        } else {
            return Err(PolicyError::new(
                "report_io",
                "$",
                format!("unsupported attestation input type {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn is_excluded_runtime_common_root(relative: &Path) -> bool {
    matches!(
        relative.to_string_lossy().replace('\\', "/").as_str(),
        "live-network-evidence/network-allow-profile/common-root"
            | "live-network-evidence/network-block-profile/common-root"
            | "live-network-evidence/network-default-absent-profile/common-root"
    )
}

pub fn verify_policy_run(run: &PolicyHarnessRun) -> Result<(), PolicyError> {
    let root = run.report_path.parent().ok_or_else(|| {
        PolicyError::new("attestation_failed", "$", "report has no parent directory")
    })?;
    let (_, bytes) = crate::read_artifact_checked(root, "attestation-manifest.json")
        .map_err(|error| PolicyError::new("attestation_failed", "$", error))?;
    let manifest: PolicyManifest = serde_json::from_slice(&bytes).map_err(|error| {
        PolicyError::new(
            "attestation_failed",
            "$",
            format!("invalid attestation manifest: {error}"),
        )
    })?;
    if manifest.schema != MANIFEST_SCHEMA || manifest.version != 1 {
        return Err(PolicyError::new(
            "attestation_failed",
            "$",
            "unexpected attestation schema/version",
        ));
    }
    let manifest_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                (
                    artifact.kind.clone(),
                    artifact.size_bytes,
                    artifact.sha256.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if manifest_artifacts != run.trusted_artifacts {
        return Err(PolicyError::new(
            "attestation_failed",
            "$",
            "manifest differs from in-memory trusted artifact identities",
        ));
    }
    let mut current_paths = Vec::new();
    collect_attested_files(root, root, &mut current_paths)
        .map_err(|error| PolicyError::new("attestation_failed", "$", error.message))?;
    let current_paths = current_paths
        .into_iter()
        .map(|path| {
            path.strip_prefix(root)
                .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                .map_err(|_| {
                    PolicyError::new(
                        "attestation_failed",
                        "$",
                        "attested path escaped output root",
                    )
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let manifest_paths = manifest_artifacts.keys().cloned().collect::<BTreeSet<_>>();
    if current_paths != manifest_paths {
        return Err(PolicyError::new(
            "attestation_failed",
            "$",
            format!(
                "output artifact set differs from manifest: expected {manifest_paths:?}, actual {current_paths:?}"
            ),
        ));
    }
    for artifact in manifest.artifacts {
        let relative = Path::new(&artifact.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(PolicyError::new(
                "attestation_failed",
                "$",
                "attestation path is not a contained relative path",
            ));
        }
        if artifact.kind != "file" {
            return Err(PolicyError::new(
                "attestation_failed",
                artifact.path,
                "unsupported artifact type",
            ));
        }
        let (_, bytes) = crate::read_artifact_checked(root, &artifact.path)
            .map_err(|error| PolicyError::new("attestation_failed", "$", error))?;
        if bytes.len() as u64 != artifact.size_bytes
            || content_sha256_hex_bytes(&bytes) != artifact.sha256
        {
            return Err(PolicyError::new(
                "attestation_failed",
                artifact.path,
                "artifact size or SHA-256 mismatch",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::mxc_policy::cases::default_static_common_root;
    use crate::mxc_policy::schema::schema_bytes;

    fn test_output(name: &str) -> PathBuf {
        PathBuf::from("target").join(format!(
            "{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn live_report_requires_every_positive_and_negative_profile_assertion() {
        let mut profiles = BTreeMap::from([(
            "process-shell".to_string(),
            LiveProfileResult {
                id: "process-shell".to_string(),
                status: LiveProfileStatus::Pass,
                positive_passed: true,
                negative_passed: true,
                evidence: Vec::new(),
                error: None,
            },
        )]);
        assert!(live_profiles_complete(
            PolicyHarnessMode::LiveWhp,
            &profiles
        ));
        profiles
            .get_mut("process-shell")
            .expect("profile")
            .positive_passed = false;
        assert!(!live_profiles_complete(
            PolicyHarnessMode::LiveWhp,
            &profiles
        ));
        assert!(live_profiles_complete(
            PolicyHarnessMode::StaticOnly,
            &profiles
        ));
    }

    #[test]
    fn static_report_is_fresh_and_tamper_evident() {
        let output = test_output("policy-report");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        verify_policy_run(&run).expect("valid report");
        fs::write(&run.diagnostics_path, b"tampered").expect("tamper diagnostics");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn manifest_covers_nested_live_evidence_artifacts() {
        let output = test_output("policy-nested-evidence");
        let evidence = output.join("live-profile").join("boot-console.log");
        fs::create_dir_all(evidence.parent().expect("evidence parent")).expect("create evidence");
        fs::write(&evidence, b"trusted live evidence").expect("write evidence");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        verify_policy_run(&run).expect("nested evidence is attested");
        fs::write(&evidence, b"tampered live evidence").expect("tamper evidence");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn manifest_rejects_missing_live_evidence_artifacts() {
        let output = test_output("policy-missing-evidence");
        let evidence = output.join("live-profile").join("boot-console.log");
        fs::create_dir_all(evidence.parent().expect("evidence parent")).expect("create evidence");
        fs::write(&evidence, b"trusted live evidence").expect("write evidence");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        fs::remove_file(&evidence).expect("remove attested evidence");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn manifest_rejects_unreferenced_output_artifacts() {
        let output = test_output("policy-unreferenced-evidence");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        fs::write(output.join("unreferenced.log"), b"not attested")
            .expect("write unreferenced artifact");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn manifest_rejects_escaping_artifact_paths() {
        let output = test_output("policy-escaping-evidence");
        let mut run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        let bytes = fs::read(&run.attestation_manifest_path).expect("read manifest");
        let mut manifest: PolicyManifest = serde_json::from_slice(&bytes).expect("parse manifest");
        let artifact = manifest.artifacts.first_mut().expect("manifest artifact");
        let old_path = std::mem::replace(&mut artifact.path, "../escape.log".to_string());
        let identity = run
            .trusted_artifacts
            .remove(&old_path)
            .expect("trusted identity");
        run.trusted_artifacts
            .insert("../escape.log".to_string(), identity);
        fs::write(
            &run.attestation_manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write forged manifest");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn manifest_does_not_ignore_nested_common_root_artifacts() {
        let output = test_output("policy-nested-common-root");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        let nested = output.join("evidence").join("common-root");
        fs::create_dir_all(&nested).expect("create nested directory");
        fs::write(nested.join("forged.log"), b"unreferenced").expect("write nested artifact");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn report_distinguishes_invalid_controls_from_absent_unsupported_fields() {
        let output = test_output("policy-instance-outcomes");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        for key in [
            "version#absent",
            "cross.version.must_equal_0.9.0-dev",
            "containment#nullable",
            "containment#enum=process",
        ] {
            let result = run
                .report
                .catalog_results
                .iter()
                .find(|result| result.key == key)
                .expect("invalid control result");
            assert_eq!(result.expected_instance_outcome, "rejected", "{key}");
            assert_eq!(
                result.evidence_tier,
                EvidenceRequirement::UnitStatic,
                "{key}"
            );
        }
        for key in ["experimental#absent", "network.proxy#absent"] {
            let result = run
                .report
                .catalog_results
                .iter()
                .find(|result| result.key == key)
                .expect("unsupported omission result");
            assert_eq!(result.expected_instance_outcome, "accepted", "{key}");
            assert_eq!(result.expected_outcome, "accepted-inert", "{key}");
        }
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn freshness_pins_schema_catalog_adapter_protocol_and_corpus() {
        let pins = freshness_pins(&PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: default_static_common_root(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("pins");
        assert_eq!(
            pins.schema_raw_sha256,
            "ad4a080ced7b73a4bcbe294551b5d61f703a1603bc85c161fa9a94e7a20e5c52"
        );
        assert_ne!(pins.catalog_sha256, pins.adapter_sha256);
        assert_ne!(pins.protocol_source_sha256, "missing");
        assert_eq!(
            pins.live_profile_inputs_sha256,
            "4f2edf717254c782aa5cf4ec693390735470116cf6924ddd77671857babe9b28"
        );
        assert_eq!(schema_bytes().len(), 41_154);
    }

    #[test]
    fn freshness_inputs_fail_closed_when_checkout_bytes_drift() {
        let root = test_output("policy-freshness-inputs");
        fs::create_dir_all(&root).expect("create freshness root");
        for (name, label) in [
            ("schema.json", "MXC schema"),
            ("catalog.rs", "policy catalog source"),
            ("adapter.rs", "policy adapter source"),
            ("messages.rs", "agent protocol source"),
            ("cases.json", "policy case corpus"),
        ] {
            let path = root.join(name);
            fs::write(&path, b"embedded bytes").expect("write matching input");
            hash_checked_source(&root, Path::new(name), b"embedded bytes", label)
                .expect("matching source");
            fs::write(&path, b"tampered checkout bytes").expect("tamper source input");
            let error = hash_checked_source(&root, Path::new(name), b"embedded bytes", label)
                .expect_err("drift must fail closed");
            assert_eq!(error.code, "freshness_drift", "{label}");
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn report_rejects_manifest_tampering() {
        let output = test_output("policy-manifest");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        fs::write(&run.attestation_manifest_path, b"{}").expect("tamper manifest");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    fn write_test_config(name: &str, value: &serde_json::Value) -> PathBuf {
        let root = test_output(name);
        fs::create_dir_all(&root).expect("create config root");
        let path = root.join("policy.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(value).expect("serialize config"),
        )
        .expect("write config");
        path
    }

    #[test]
    fn execute_config_requires_config_before_output_creation() {
        let output = test_output("policy-execute-config-requires-config");
        assert!(!output.exists());
        let error = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::LiveWhp,
            output_dir: output.clone(),
            config: None,
            execute_config: true,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect_err("missing --config must fail");
        assert_eq!(error.code, "execute_config_requires_config");
        assert!(!output.exists());
    }

    #[test]
    fn execute_config_rejects_static_only_before_output_creation() {
        let output = test_output("policy-execute-config-static-only");
        let config_path = write_test_config(
            "policy-execute-config-static-only-config",
            &serde_json::json!({
                "version": "0.9.0-dev",
                "containment": "vm",
                "phase": "exec",
                "sandboxId": "sandbox",
                "process": {"commandLine": "echo ok", "env": []}
            }),
        );
        let error = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: Some(config_path),
            execute_config: true,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect_err("static-only execute-config must fail");
        assert_eq!(error.code, "execute_config_requires_live_mode");
        assert!(!output.exists());
    }

    #[test]
    fn execute_config_rejects_non_exec_phase_before_output_creation() {
        let output = test_output("policy-execute-config-non-exec");
        let config_path = write_test_config(
            "policy-execute-config-non-exec-config",
            &serde_json::json!({
                "version": "0.9.0-dev",
                "containment": "vm",
                "phase": "start",
                "sandboxId": "sandbox-start"
            }),
        );
        let error = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::LiveWhp,
            output_dir: output.clone(),
            config: Some(config_path),
            execute_config: true,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect_err("non-exec phase must fail");
        assert_eq!(error.code, "execute_config_invalid_phase");
        assert!(!output.exists());
    }

    #[test]
    fn execute_config_rejected_policy_produces_no_output() {
        let output = test_output("policy-execute-config-rejected");
        let config_path = write_test_config(
            "policy-execute-config-rejected-config",
            &serde_json::json!({
                "version": "0.9.0-dev",
                "containment": "process",
                "phase": "exec",
                "sandboxId": "sandbox",
                "process": {"commandLine": "echo blocked", "env": []}
            }),
        );
        let _ = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::LiveWhp,
            output_dir: output.clone(),
            config: Some(config_path),
            execute_config: true,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect_err("rejected policy must fail");
        assert!(!output.exists());
    }

    #[test]
    fn manifest_attests_execute_config_stream_artifacts() {
        let output = test_output("policy-execute-config-artifacts");
        let execute_dir = output.join("execute-config");
        fs::create_dir_all(&execute_dir).expect("create execute-config directory");
        fs::write(execute_dir.join("stdout.bin"), b"hello stdout").expect("write stdout");
        fs::write(execute_dir.join("stderr.bin"), b"").expect("write stderr");
        fs::write(execute_dir.join("outcome.json"), b"{\"ok\":true}").expect("write outcome");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            execute_config: false,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        let paths = run
            .trusted_artifacts
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(paths.contains("execute-config/stdout.bin"));
        assert!(paths.contains("execute-config/stderr.bin"));
        assert!(paths.contains("execute-config/outcome.json"));
        verify_policy_run(&run).expect("manifest remains valid");
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn contradictory_linked_static_result_cannot_report_passed() {
        let entry = CatalogEntry {
            key: "process.commandLine",
            schema_path: "/properties/process/anyOf/0/properties/commandLine",
            disposition: PolicyDisposition::Honored,
            phases: &[crate::mxc_policy::MxcPhase::Exec],
            evidence: EvidenceRequirement::UnitStatic,
            reason: "test",
        };
        let case = PolicyCase {
            id: "contradictory-case".to_string(),
            config: serde_json::json!({
                "version": "0.9.0-dev",
                "containment": "vm",
                "phase": "exec",
                "sandboxId": "sandbox-1",
                "process": { "commandLine": "echo ok" }
            }),
            expected_disposition: ExpectedDisposition::Rejected,
            expected_plan: None,
            expected_code: Some("invalid_value".to_string()),
            expected_path: Some("/process/commandLine".to_string()),
            required_evidence: EvidenceRequirement::UnitStatic,
            catalog_keys: vec![entry.key.to_string()],
        };
        let failing = StaticCaseResult {
            id: "contradictory-case".to_string(),
            passed: true,
            expected_disposition: ExpectedDisposition::Rejected,
            actual_disposition: ExpectedDisposition::Rejected,
            error: None,
            effect_counters: super::super::effects::EffectCounters::default(),
            output_directory_created: false,
            catalog_keys: vec![entry.key.to_string()],
        };
        let case_map = [(&case.id[..], &case)]
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let static_results = [(&failing.id[..], &failing)]
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let (outcome, error, _) = actual_outcome(
            &entry,
            std::slice::from_ref(&failing.id),
            &case_map,
            &static_results,
            &BTreeMap::new(),
            OutcomeEvaluation {
                mode: PolicyHarnessMode::StaticOnly,
                enforce_static_links: true,
                execute_config_mode: false,
            },
        );
        assert_eq!(outcome, "unexpected");
        assert!(error.is_some_and(|message| {
            message.contains("contradictory-case") && message.contains("contract")
        }));
    }

    #[test]
    fn execute_config_mode_does_not_require_live_profile_catalog_bindings() {
        let entry = CatalogEntry {
            key: "network.defaultPolicy",
            schema_path: "/properties/network/properties/defaultPolicy",
            disposition: PolicyDisposition::Honored,
            phases: &[crate::mxc_policy::MxcPhase::Provision],
            evidence: EvidenceRequirement::LiveWhpPositiveNegative,
            reason: "test",
        };
        let (outcome, error, artifacts) = actual_outcome(
            &entry,
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            OutcomeEvaluation {
                mode: PolicyHarnessMode::LiveWhp,
                enforce_static_links: false,
                execute_config_mode: true,
            },
        );
        assert_eq!(outcome, "passed");
        assert!(error.is_none());
        assert!(artifacts.is_empty());
    }
}
