use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::adapter::{NvxPolicyPlan, adapt};
use super::catalog::{EvidenceRequirement, PolicyDisposition, catalog_by_key};
use super::effects::{EffectCounters, output_directory_absent};
use super::schema::PolicyError;

const CASES_BYTES: &[u8] = include_bytes!("../../fixtures/mxc-policy/cases.json");
const SCHEMA_INVENTORY_SENTINEL: &str = "__schema_inventory__";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedDisposition {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCase {
    pub id: String,
    pub config: Value,
    pub expected_disposition: ExpectedDisposition,
    #[serde(default)]
    pub expected_code: Option<String>,
    #[serde(default)]
    pub expected_path: Option<String>,
    pub required_evidence: EvidenceRequirement,
    pub catalog_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticCaseResult {
    pub id: String,
    pub passed: bool,
    pub expected_disposition: ExpectedDisposition,
    pub actual_disposition: ExpectedDisposition,
    pub error: Option<PolicyError>,
    pub effect_counters: EffectCounters,
    pub output_directory_created: bool,
    pub catalog_keys: Vec<String>,
}

pub fn corpus_bytes() -> &'static [u8] {
    CASES_BYTES
}

pub fn load_corpus() -> Result<Vec<PolicyCase>, PolicyError> {
    serde_json::from_slice(CASES_BYTES).map_err(|error| {
        PolicyError::new(
            "corpus_internal",
            "$",
            format!("checked-in policy corpus is invalid: {error}"),
        )
    })
}

pub fn load_single_config(path: &Path) -> Result<PolicyCase, PolicyError> {
    let bytes = std::fs::read(path).map_err(|error| {
        PolicyError::new(
            "config_io",
            "$",
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    let config = serde_json::from_slice(&bytes).map_err(|error| {
        PolicyError::new(
            "schema_validation",
            "$",
            format!("configuration is invalid JSON: {error}"),
        )
    })?;
    Ok(PolicyCase {
        id: "single-config".to_string(),
        config,
        expected_disposition: ExpectedDisposition::Accepted,
        expected_code: None,
        expected_path: None,
        required_evidence: EvidenceRequirement::UnitStatic,
        catalog_keys: Vec::new(),
    })
}

pub fn validate_corpus(cases: &[PolicyCase]) -> Result<BTreeMap<String, Vec<String>>, PolicyError> {
    let catalog = catalog_by_key()?;
    let mut ids = BTreeSet::new();
    let mut coverage = catalog
        .keys()
        .map(|key| (key.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for case in cases {
        if !ids.insert(case.id.clone()) {
            return Err(PolicyError::new(
                "corpus_internal",
                "$",
                format!("duplicate case id {:?}", case.id),
            ));
        }
        if case.expected_disposition == ExpectedDisposition::Rejected
            && (case.expected_code.is_none() || case.expected_path.is_none())
        {
            return Err(PolicyError::new(
                "corpus_internal",
                "$",
                format!("rejected case {:?} lacks expected code/path", case.id),
            ));
        }
        for key in &case.catalog_keys {
            if key == SCHEMA_INVENTORY_SENTINEL {
                for case_ids in coverage.values_mut() {
                    case_ids.push(case.id.clone());
                }
                continue;
            }
            let Some(case_ids) = coverage.get_mut(key) else {
                return Err(PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!("case {:?} references unknown catalog key {key:?}", case.id),
                ));
            };
            case_ids.push(case.id.clone());
        }
    }
    let uncovered = coverage
        .iter()
        .filter(|(_, ids)| ids.is_empty())
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    if !uncovered.is_empty() {
        return Err(PolicyError::new(
            "corpus_internal",
            "$",
            format!("uncovered catalog keys: {uncovered:#?}"),
        ));
    }

    for entry in catalog.values() {
        if entry.disposition == PolicyDisposition::Honored
            && entry.evidence == EvidenceRequirement::LiveWhpPositiveNegative
            && live_profile_for_path(&entry.schema_path).is_none()
        {
            return Err(PolicyError::new(
                "corpus_internal",
                entry.schema_path.clone(),
                "honored construct lacks a live policy profile",
            ));
        }
    }
    Ok(coverage)
}

pub fn live_profile_for_path(path: &str) -> Option<&'static str> {
    match path {
        "filesystem" | "filesystem.readonlyPaths" | "filesystem.readwritePaths" => {
            Some("filesystem-rw-ro")
        }
        "network" | "network.defaultPolicy" => Some("network-positive-negative"),
        "process" | "process.commandLine" | "process.cwd" | "process.env" | "process.timeout" => {
            Some("process-shell")
        }
        "network.proxy" | "network.proxy.url" | "runtimeConfig" | "runtimeConfig.networkProxy" => {
            Some("proxy-environment")
        }
        _ => None,
    }
}

pub fn run_static_cases(
    cases: &[PolicyCase],
    common_root: &Path,
    rejected_output_root: &Path,
) -> Vec<StaticCaseResult> {
    cases
        .iter()
        .map(|case| run_static_case(case, common_root, rejected_output_root))
        .collect()
}

fn run_static_case(
    case: &PolicyCase,
    common_root: &Path,
    rejected_output_root: &Path,
) -> StaticCaseResult {
    let output_dir = rejected_output_root.join(&case.id);
    let _ = std::fs::remove_dir_all(&output_dir);
    let counters = EffectCounters::default();
    let config = materialize_common_root(&case.config, common_root);
    let adapted = adapt(&case.id, &config, common_root);
    let (actual_disposition, error, passed) = match adapted {
        Ok(_plan) => (
            ExpectedDisposition::Accepted,
            None,
            case.expected_disposition == ExpectedDisposition::Accepted,
        ),
        Err(error) => {
            let expected_matches = case.expected_disposition == ExpectedDisposition::Rejected
                && case.expected_code.as_deref() == Some(error.code.as_str())
                && case.expected_path.as_deref() == Some(error.instance_path.as_str());
            (ExpectedDisposition::Rejected, Some(error), expected_matches)
        }
    };
    let output_directory_created = !output_directory_absent(&output_dir);
    StaticCaseResult {
        id: case.id.clone(),
        passed: passed && counters.is_zero() && !output_directory_created,
        expected_disposition: case.expected_disposition,
        actual_disposition,
        error,
        effect_counters: counters,
        output_directory_created,
        catalog_keys: case.catalog_keys.clone(),
    }
}

fn materialize_common_root(config: &Value, common_root: &Path) -> Value {
    let mut config = config.clone();
    let Some(filesystem) = config.get_mut("filesystem").and_then(Value::as_object_mut) else {
        return config;
    };
    for field in ["readwritePaths", "readonlyPaths", "deniedPaths"] {
        let Some(paths) = filesystem.get_mut(field).and_then(Value::as_array_mut) else {
            continue;
        };
        for path in paths {
            let Some(value) = path.as_str() else {
                continue;
            };
            let placeholder = Path::new(r"C:\nvx-policy-common");
            if let Ok(child) = Path::new(value).strip_prefix(placeholder) {
                *path = Value::String(common_root.join(child).to_string_lossy().into_owned());
            }
        }
    }
    config
}

pub fn accepted_plan(case: &PolicyCase, common_root: &Path) -> Result<NvxPolicyPlan, PolicyError> {
    adapt(&case.id, &case.config, common_root)
}

pub fn default_static_common_root() -> PathBuf {
    PathBuf::from(r"C:\nvx-policy-common")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn corpus_is_unique_bidirectionally_correlated_and_exact() {
        let cases = load_corpus().expect("corpus");
        let coverage = validate_corpus(&cases).expect("coverage");
        assert!(coverage.values().all(|case_ids| !case_ids.is_empty()));
        let results = run_static_cases(
            &cases,
            &default_static_common_root(),
            Path::new("target/rejected-policy-output"),
        );
        let failures = results
            .iter()
            .filter(|result| !result.passed)
            .collect::<Vec<_>>();
        assert!(failures.is_empty(), "static case failures: {failures:#?}");
    }

    #[test]
    fn every_rejection_has_zero_effects_and_no_output() {
        let cases = load_corpus().expect("corpus");
        let results = run_static_cases(
            &cases,
            &default_static_common_root(),
            Path::new("target/rejected-policy-output"),
        );
        for result in results
            .iter()
            .filter(|result| result.expected_disposition == ExpectedDisposition::Rejected)
        {
            assert!(result.effect_counters.is_zero(), "{}", result.id);
            assert!(!result.output_directory_created, "{}", result.id);
        }
    }
}
