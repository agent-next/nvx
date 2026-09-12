use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use super::PolicyError;
use super::cases::{
    ExpectedDisposition, PolicyCase, StaticCaseResult, live_profile_for_path, load_corpus,
    load_single_config, run_static_cases, validate_case_disposition_contract, validate_corpus,
};
use super::catalog::{CatalogEntry, EvidenceRequirement, PolicyDisposition, catalog, catalog_hash};
use super::live::{LiveProfileResult, LiveProfileStatus, run_live_profiles};
use super::schema::{normalized_sha256, provenance, raw_sha256};
use crate::launch::LaunchOverrides;
use crate::{HarnessBackend, content_sha256_hex_bytes, write_bytes_atomic, write_json_atomic};
use serde::{Deserialize, Serialize};

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
    pub adapter_sha256: String,
    pub protocol_version: u32,
    pub protocol_source_sha256: String,
    pub case_corpus_sha256: String,
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
    pub uncovered: Vec<String>,
    pub unexpected: Vec<String>,
    pub blocked: Vec<String>,
    pub failed: Vec<String>,
    pub rejection_effects_zero: bool,
    pub passed: bool,
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
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct PolicyHarnessRun {
    pub report: PolicyHarnessReport,
    pub report_path: PathBuf,
    pub diagnostics_path: PathBuf,
    pub attestation_manifest_path: PathBuf,
    trusted_artifacts: BTreeMap<String, (u64, String)>,
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
    let cases = match &options.config {
        Some(path) => vec![load_single_config(path)?],
        None => load_corpus()?,
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

    let live_profiles = if options.mode == PolicyHarnessMode::LiveWhp {
        run_live_profiles(&options)
    } else {
        BTreeMap::new()
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
            options.mode,
            options.config.is_none(),
        );
        match actual_outcome.as_str() {
            "blocked" => blocked.push(entry.key.to_string()),
            "failed" => failed.push(entry.key.to_string()),
            "unexpected" => unexpected.push(entry.key.to_string()),
            _ => {}
        }
        catalog_results.push(CatalogResult {
            key: entry.key.to_string(),
            schema_path: entry.schema_path.to_string(),
            disposition: entry.disposition,
            phases: entry.phases.to_vec(),
            case_ids,
            expected_outcome: expected_outcome(entry.disposition).to_string(),
            actual_outcome,
            evidence_tier: entry.evidence,
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
    let passed = uncovered.is_empty()
        && unexpected.is_empty()
        && failed.is_empty()
        && blocked.is_empty()
        && rejection_effects_zero
        && live_profiles_complete;
    let report = PolicyHarnessReport {
        schema: REPORT_SCHEMA.to_string(),
        version: REPORT_VERSION,
        mode: options.mode,
        backend: options.backend.as_str().to_string(),
        freshness,
        catalog_results,
        static_cases: static_results,
        live_profiles,
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
    let manifest = build_manifest(&options.output_dir, &[&report_path, &diagnostics_path])?;
    let trusted_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                (artifact.size_bytes, artifact.sha256.clone()),
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
    mode: PolicyHarnessMode,
    enforce_static_links: bool,
) -> (String, Option<String>, Vec<String>) {
    let (static_status, static_error, mut artifacts) =
        static_outcome(entry, case_ids, cases, static_results, enforce_static_links);
    if static_status != "passed" {
        return (static_status, static_error, artifacts);
    }
    if entry.evidence != EvidenceRequirement::LiveWhpPositiveNegative {
        return ("passed".to_string(), None, artifacts);
    }
    if mode == PolicyHarnessMode::StaticOnly {
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
    let protocol_path = repo_root
        .join("agent-protocol")
        .join("src")
        .join("messages.rs");
    let probe_path = repo_root
        .join("build")
        .join("nvx-agent-probe-mxc-prototype");
    Ok(FreshnessPins {
        schema_version: "0.9.0-dev".to_string(),
        schema_source_commit: provenance.source_commit,
        schema_raw_sha256: raw_sha256(),
        schema_normalized_sha256: normalized_sha256()?,
        catalog_sha256: catalog_hash()?,
        adapter_sha256: content_sha256_hex_bytes(include_bytes!("adapter.rs")),
        protocol_version: agent_protocol::PROTOCOL_VERSION,
        protocol_source_sha256: hash_optional(&protocol_path)
            .unwrap_or_else(|| "missing".to_string()),
        case_corpus_sha256: content_sha256_hex_bytes(super::cases::corpus_bytes()),
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

fn build_manifest(root: &Path, paths: &[&Path]) -> Result<PolicyManifest, PolicyError> {
    let mut artifacts = Vec::new();
    for path in paths {
        let bytes = fs::read(path).map_err(|error| {
            PolicyError::new(
                "report_io",
                "$",
                format!("failed to read {} for attestation: {error}", path.display()),
            )
        })?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PolicyError::new("report_io", "$", "attested path escaped output root"))?;
        artifacts.push(PolicyAttestedArtifact {
            path: relative.to_string_lossy().replace('\\', "/"),
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

pub fn verify_policy_run(run: &PolicyHarnessRun) -> Result<(), PolicyError> {
    let root = run.report_path.parent().ok_or_else(|| {
        PolicyError::new("attestation_failed", "$", "report has no parent directory")
    })?;
    let bytes = fs::read(&run.attestation_manifest_path).map_err(|error| {
        PolicyError::new(
            "attestation_failed",
            "$",
            format!("failed reading attestation manifest: {error}"),
        )
    })?;
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
                (artifact.size_bytes, artifact.sha256.clone()),
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
        let bytes = fs::read(root.join(relative)).map_err(|error| {
            PolicyError::new(
                "attestation_failed",
                "$",
                format!("failed reading attested artifact: {error}"),
            )
        })?;
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
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        verify_policy_run(&run).expect("valid report");
        fs::write(&run.diagnostics_path, b"tampered").expect("tamper diagnostics");
        assert!(verify_policy_run(&run).is_err());
        fs::remove_dir_all(output).expect("cleanup");
    }

    #[test]
    fn freshness_pins_schema_catalog_adapter_protocol_and_corpus() {
        let pins = freshness_pins(&PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: default_static_common_root(),
            config: None,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("pins");
        assert_eq!(
            pins.schema_raw_sha256,
            "ad4a080ced7b73a4bcbe294551b5d61f703a1603bc85c161fa9a94e7a20e5c52"
        );
        assert_ne!(pins.catalog_sha256, pins.adapter_sha256);
        assert_ne!(pins.protocol_source_sha256, "missing");
        assert_eq!(schema_bytes().len(), 41_154);
    }

    #[test]
    fn report_rejects_manifest_tampering() {
        let output = test_output("policy-manifest");
        let run = execute_policy_harness(PolicyHarnessOptions {
            backend: HarnessBackend::Whp,
            mode: PolicyHarnessMode::StaticOnly,
            output_dir: output.clone(),
            config: None,
            launch_overrides: LaunchOverrides::default(),
        })
        .expect("static report");
        fs::write(&run.attestation_manifest_path, b"{}").expect("tamper manifest");
        assert!(verify_policy_run(&run).is_err());
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
            PolicyHarnessMode::StaticOnly,
            true,
        );
        assert_eq!(outcome, "unexpected");
        assert!(error.is_some_and(|message| {
            message.contains("contradictory-case") && message.contains("contract")
        }));
    }
}
