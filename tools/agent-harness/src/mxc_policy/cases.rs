use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use super::adapter::{NvxExecPolicy, NvxPolicyPlan, NvxProvisionPolicy, adapt_policy};
use super::catalog::{
    CatalogEntry, EvidenceRequirement, ExpectedInstanceBehavior, PolicyDisposition, catalog_entries,
};
use super::effects::{CountingHostEffects, EffectCounters, PolicyExecutionError, run_with_effects};
use super::{MxcPhase, PolicyError};

const CASES_BYTES: &[u8] = include_bytes!("../../fixtures/mxc-policy/cases.json");
const SCHEMA_VERSION: &str = "0.9.0-dev";
const SCHEMA_BYTES: &[u8] = include_bytes!("../../schemas/mxc-config.schema.0.9.0-dev.json");
static CORPUS_OUTPUT_NONCE: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static CORPUS_SCHEMA_VALIDATOR: OnceLock<Result<jsonschema::Validator, PolicyError>> =
    OnceLock::new();
static CORPUS_SCHEMA_VALUE: OnceLock<Value> = OnceLock::new();

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedDisposition {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCase {
    pub id: String,
    pub config: Value,
    pub expected_disposition: ExpectedDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_plan: Option<NvxPolicyPlan>,
    #[serde(default)]
    pub expected_code: Option<String>,
    #[serde(default)]
    pub expected_path: Option<String>,
    pub required_evidence: EvidenceRequirement,
    pub catalog_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyQualifier<'a> {
    Plain,
    Absent,
    Nullable,
    Enum(&'a str),
    Union {
        kind: &'a str,
        index: usize,
        label: &'a str,
    },
    Default(&'a str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathSegment<'a> {
    name: &'a str,
    is_array: bool,
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
        expected_plan: None,
        expected_code: None,
        expected_path: None,
        required_evidence: EvidenceRequirement::UnitStatic,
        catalog_keys: Vec::new(),
    })
}

pub fn validate_corpus(cases: &[PolicyCase]) -> Result<BTreeMap<String, Vec<String>>, PolicyError> {
    let catalog = catalog_by_key();
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
        match (case.expected_disposition, &case.expected_plan) {
            (ExpectedDisposition::Accepted, None) => {
                return Err(PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!("accepted case {:?} lacks an expected typed plan", case.id),
                ));
            }
            (ExpectedDisposition::Rejected, Some(_)) => {
                return Err(PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!(
                        "rejected case {:?} unexpectedly declares a typed plan",
                        case.id
                    ),
                ));
            }
            _ => {}
        }

        let observed = observe_catalog_keys(&case.config, &catalog);
        for key in &case.catalog_keys {
            if !catalog.contains_key(key) {
                return Err(PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!("case {:?} references unknown catalog key {key:?}", case.id),
                ));
            }
            if !observed.contains(key) {
                return Err(PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!(
                        "case {:?} declares catalog key {key:?} but config does not observe it",
                        case.id
                    ),
                ));
            }
        }
        for key in &case.catalog_keys {
            if observed.contains(key)
                && let Some(case_ids) = coverage.get_mut(key)
            {
                case_ids.push(case.id.clone());
            }
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
            && entry.required_evidence() == EvidenceRequirement::LiveWhpPositiveNegative
            && live_profile_for_path(entry.key).is_none()
        {
            return Err(PolicyError::new(
                "corpus_internal",
                entry.schema_path,
                "honored construct lacks a live policy profile",
            ));
        }
    }
    validate_catalog_case_semantics(cases, &coverage, &catalog)?;
    Ok(coverage)
}

fn validate_catalog_case_semantics(
    cases: &[PolicyCase],
    coverage: &BTreeMap<String, Vec<String>>,
    catalog: &BTreeMap<String, CatalogEntry>,
) -> Result<(), PolicyError> {
    let case_by_id = cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    for (key, case_ids) in coverage {
        let Some(entry) = catalog.get(key) else {
            continue;
        };
        for case_id in case_ids {
            let case = case_by_id.get(case_id.as_str()).ok_or_else(|| {
                PolicyError::new(
                    "corpus_internal",
                    entry.schema_path,
                    format!("catalog key {key:?} links unknown case id {case_id:?}"),
                )
            })?;
            if case.required_evidence != entry.required_evidence() {
                return Err(PolicyError::new(
                    "corpus_internal",
                    entry.schema_path,
                    format!(
                        "catalog key {key:?} evidence mismatch: entry={:?}, case {:?}={:?}",
                        entry.required_evidence(),
                        case.id,
                        case.required_evidence
                    ),
                ));
            }
            if let Err(message) =
                validate_case_disposition_contract(entry, case.expected_disposition)
            {
                return Err(PolicyError::new(
                    "corpus_internal",
                    entry.schema_path,
                    format!(
                        "catalog key {key:?} is incompatible with case {:?}: {message}",
                        case.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_case_disposition_contract(
    entry: &CatalogEntry,
    expected_disposition: ExpectedDisposition,
) -> Result<(), String> {
    if disposition_contract_allows(entry, expected_disposition) {
        return Ok(());
    }
    Err(format!(
        "entry disposition {:?} for key {:?} forbids expected disposition {:?}",
        entry.disposition, entry.key, expected_disposition
    ))
}

fn disposition_contract_allows(entry: &CatalogEntry, expected: ExpectedDisposition) -> bool {
    match entry.disposition {
        PolicyDisposition::Rejected => expected == ExpectedDisposition::Rejected,
        PolicyDisposition::AcceptedInert => expected == ExpectedDisposition::Accepted,
        PolicyDisposition::Honored => {
            expected == ExpectedDisposition::Accepted
                || (expected == ExpectedDisposition::Rejected
                    && honored_key_allows_rejection(entry.key))
        }
        PolicyDisposition::Control => match entry.expected_instance_behavior() {
            ExpectedInstanceBehavior::Accepted => expected == ExpectedDisposition::Accepted,
            ExpectedInstanceBehavior::Rejected => expected == ExpectedDisposition::Rejected,
            ExpectedInstanceBehavior::Derived => true,
        },
    }
}

fn honored_key_allows_rejection(key: &str) -> bool {
    matches!(
        parse_key(key).1,
        KeyQualifier::Absent | KeyQualifier::Nullable | KeyQualifier::Union { label: "null", .. }
    )
}

pub fn live_profile_for_path(key: &str) -> Option<&'static str> {
    LIVE_PROFILE_MAPPINGS
        .iter()
        .find(|(mapped_key, _)| *mapped_key == key)
        .map(|(_, profile)| *profile)
}

#[cfg(test)]
fn mapped_live_profile_keys() -> BTreeSet<&'static str> {
    LIVE_PROFILE_MAPPINGS
        .iter()
        .map(|(key, _)| *key)
        .collect::<BTreeSet<_>>()
}

const LIVE_PROFILE_MAPPINGS: &[(&str, &str)] = &[
    ("filesystem.readonlyPaths", "filesystem-rw-ro"),
    ("filesystem.readonlyPaths#absent", "filesystem-rw-ro"),
    ("filesystem.readonlyPaths#nullable", "filesystem-rw-ro"),
    ("filesystem.readonlyPaths[]", "filesystem-rw-ro"),
    ("filesystem.readwritePaths", "filesystem-rw-ro"),
    ("filesystem.readwritePaths#absent", "filesystem-rw-ro"),
    ("filesystem.readwritePaths#nullable", "filesystem-rw-ro"),
    ("filesystem.readwritePaths[]", "filesystem-rw-ro"),
    (
        "cross.phase.provision_uses_filesystem_rw_and_network_allow_block",
        "filesystem-rw-ro",
    ),
    ("network", "network-positive-negative"),
    ("network#absent", "network-positive-negative"),
    ("network#nullable", "network-positive-negative"),
    (
        "network#anyOf[0]=#/definitions/Network",
        "network-positive-negative",
    ),
    ("network#anyOf[1]=null", "network-positive-negative"),
    ("network.defaultPolicy", "network-positive-negative"),
    ("network.defaultPolicy#absent", "network-positive-negative"),
    (
        "network.defaultPolicy#nullable",
        "network-positive-negative",
    ),
    (
        "network.defaultPolicy#anyOf[0]=#/definitions/NetworkPolicy",
        "network-positive-negative",
    ),
    (
        "network.defaultPolicy#enum=allow",
        "network-positive-negative",
    ),
    (
        "network.defaultPolicy#enum=block",
        "network-positive-negative",
    ),
    (
        "network.defaultPolicy#anyOf[1]=null",
        "network-positive-negative",
    ),
    ("process", "process-shell"),
    ("process#absent", "process-shell"),
    ("process#nullable", "process-shell"),
    ("process#anyOf[0]=#/definitions/Process", "process-shell"),
    ("process#anyOf[1]=null", "process-shell"),
    ("process.commandLine", "process-shell"),
    ("process.commandLine#absent", "process-shell"),
    ("process.commandLine#nullable", "process-shell"),
    ("process.cwd", "process-shell"),
    ("process.cwd#absent", "process-shell"),
    ("process.cwd#nullable", "process-shell"),
    ("process.env", "process-shell"),
    ("process.env#absent", "process-shell"),
    ("process.env#nullable", "process-shell"),
    ("process.env[]", "process-shell"),
    ("process.timeout", "process-shell"),
    ("process.timeout#absent", "process-shell"),
    ("process.timeout#nullable", "process-shell"),
    ("cross.phase.exec_uses_process_fields", "process-shell"),
    ("runtimeConfig.networkProxy", "proxy-environment"),
    ("runtimeConfig.networkProxy#absent", "proxy-environment"),
    ("runtimeConfig.networkProxy#nullable", "proxy-environment"),
    (
        "cross.phase.exec_uses_runtime_config_network_proxy",
        "proxy-environment",
    ),
    ("version", "control-lifecycle"),
    ("version#absent", "control-lifecycle"),
    ("version#nullable", "control-lifecycle"),
    ("containment", "control-lifecycle"),
    ("containment#absent", "control-lifecycle"),
    ("containment#nullable", "control-lifecycle"),
    (
        "containment#anyOf[0]=#/definitions/Containment",
        "control-lifecycle",
    ),
    ("containment#oneOf[0]=string", "control-lifecycle"),
    ("containment#enum=process", "control-lifecycle"),
    ("containment#oneOf[1]=string", "control-lifecycle"),
    ("containment#enum=processcontainer", "control-lifecycle"),
    ("containment#oneOf[2]=string", "control-lifecycle"),
    ("containment#enum=vm", "control-lifecycle"),
    ("containment#oneOf[3]=string", "control-lifecycle"),
    ("containment#enum=windows_sandbox", "control-lifecycle"),
    ("containment#oneOf[4]=string", "control-lifecycle"),
    ("containment#enum=lxc", "control-lifecycle"),
    ("containment#oneOf[5]=string", "control-lifecycle"),
    ("containment#enum=microvm", "control-lifecycle"),
    ("containment#oneOf[6]=string", "control-lifecycle"),
    ("containment#enum=hyperlight", "control-lifecycle"),
    ("containment#oneOf[7]=string", "control-lifecycle"),
    ("containment#enum=wslc", "control-lifecycle"),
    ("containment#oneOf[8]=string", "control-lifecycle"),
    ("containment#enum=seatbelt", "control-lifecycle"),
    ("containment#oneOf[9]=string", "control-lifecycle"),
    ("containment#enum=isolation_session", "control-lifecycle"),
    ("containment#oneOf[10]=string", "control-lifecycle"),
    ("containment#enum=bubblewrap", "control-lifecycle"),
    ("containment#anyOf[1]=null", "control-lifecycle"),
    ("phase", "control-lifecycle"),
    ("phase#absent", "control-lifecycle"),
    ("phase#nullable", "control-lifecycle"),
    ("phase#anyOf[0]=#/definitions/Phase", "control-lifecycle"),
    ("phase#enum=provision", "control-lifecycle"),
    ("phase#enum=start", "control-lifecycle"),
    ("phase#enum=exec", "control-lifecycle"),
    ("phase#enum=stop", "control-lifecycle"),
    ("phase#enum=deprovision", "control-lifecycle"),
    ("phase#anyOf[1]=null", "control-lifecycle"),
    ("sandboxId", "control-lifecycle"),
    ("sandboxId#absent", "control-lifecycle"),
    ("sandboxId#nullable", "control-lifecycle"),
    ("containerId", "control-lifecycle"),
    ("containerId#absent", "control-lifecycle"),
    ("containerId#nullable", "control-lifecycle"),
    (
        "cross.phase.non_provision_requires_sandbox_id",
        "control-lifecycle",
    ),
];

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
    let output_dir = unique_case_output_dir(rejected_output_root, &case.id);
    if output_dir.exists() {
        return StaticCaseResult {
            id: case.id.clone(),
            passed: false,
            expected_disposition: case.expected_disposition,
            actual_disposition: ExpectedDisposition::Rejected,
            error: Some(PolicyError::new(
                "corpus_output_conflict",
                "$",
                format!(
                    "rejected output path must be absent before execution: {}",
                    output_dir.display()
                ),
            )),
            effect_counters: EffectCounters::default(),
            output_directory_created: true,
            catalog_keys: case.catalog_keys.clone(),
        };
    }
    let config = materialize_common_root(&case.config, common_root);
    let mut effects = CountingHostEffects::default();
    let result = run_with_effects(&case.id, &config, common_root, &output_dir, &mut effects);
    let counters = effects.counters().clone();
    let (actual_disposition, error, passed) = match result {
        Ok(_session) => {
            let expected_plan = case
                .expected_plan
                .as_ref()
                .map(|plan| materialize_expected_plan(plan, common_root));
            let plan_matches = expected_plan
                .as_ref()
                .is_none_or(|expected| effects.prepared_plan() == Some(expected));
            let error = (!plan_matches).then(|| {
                PolicyError::new(
                    "unexpected_plan",
                    "$",
                    format!(
                        "adapted plan differs from corpus oracle: expected {expected_plan:?}, actual {:?}",
                        effects.prepared_plan()
                    ),
                )
            });
            (
                ExpectedDisposition::Accepted,
                error,
                case.expected_disposition == ExpectedDisposition::Accepted && plan_matches,
            )
        }
        Err(PolicyExecutionError::Policy(errors)) => {
            let actual = errors.first().cloned();
            let expected_matches = case.expected_disposition == ExpectedDisposition::Rejected
                && actual.as_ref().is_some_and(|error| {
                    case.expected_code.as_deref() == Some(error.code.as_str())
                })
                && actual.as_ref().is_some_and(|error| {
                    case.expected_path.as_deref() == Some(error.instance_path.as_str())
                });
            (ExpectedDisposition::Rejected, actual, expected_matches)
        }
        Err(PolicyExecutionError::Run(run_error)) => (
            ExpectedDisposition::Rejected,
            Some(PolicyError::new(run_error.code, "", run_error.message)),
            false,
        ),
    };
    let output_directory_created = output_dir.exists();
    let rejection_effects_clear =
        actual_disposition != ExpectedDisposition::Rejected || counters.is_zero();
    StaticCaseResult {
        id: case.id.clone(),
        passed: passed && rejection_effects_clear && !output_directory_created,
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

fn materialize_expected_plan(plan: &NvxPolicyPlan, common_root: &Path) -> NvxPolicyPlan {
    let mut plan = plan.clone();
    if let Some(provision) = &mut plan.provision {
        provision.common_root = common_root.to_path_buf();
    }
    plan
}

pub fn accepted_plan(case: &PolicyCase, common_root: &Path) -> Result<NvxPolicyPlan, PolicyError> {
    adapt_policy(&case.id, &case.config, common_root).map_err(|errors| {
        errors.into_iter().next().unwrap_or_else(|| {
            PolicyError::new(
                "policy_internal",
                "",
                "adapt_policy rejected without an error payload",
            )
        })
    })
}

pub fn default_static_common_root() -> PathBuf {
    PathBuf::from(r"C:\nvx-policy-common")
}

pub fn generated_corpus() -> Vec<PolicyCase> {
    let schema = corpus_schema_value();
    catalog_entries()
        .iter()
        .enumerate()
        .map(|(index, entry)| generated_case_for_entry(index, entry, schema))
        .collect()
}

fn generated_case_for_entry(index: usize, entry: &CatalogEntry, schema: &Value) -> PolicyCase {
    let mut config = base_config_for_entry(entry, entry.key);
    apply_catalog_entry_to_config(&mut config, entry, schema);
    complete_instance_against_schema(&mut config, schema, schema);
    let expected = expected_outcome_for_entry(entry);
    let id = format!("{index:04}-{}", sanitize_id(entry.key));
    let expected_plan = (expected.0 == ExpectedDisposition::Accepted).then(|| {
        contract_expected_plan(&id, &config, &default_static_common_root())
            .expect("accepted generated case must have an independent typed-plan oracle")
    });
    PolicyCase {
        id,
        config,
        expected_disposition: expected.0,
        expected_plan,
        expected_code: expected.1,
        expected_path: expected.2,
        required_evidence: entry.required_evidence(),
        catalog_keys: vec![entry.key.to_string()],
    }
}

fn contract_expected_plan(
    case_id: &str,
    config: &Value,
    common_root: &Path,
) -> Result<NvxPolicyPlan, String> {
    let object = config
        .as_object()
        .ok_or_else(|| "policy must be an object".to_string())?;
    let phase = match object.get("phase").and_then(Value::as_str) {
        Some("provision") => MxcPhase::Provision,
        Some("start") => MxcPhase::Start,
        Some("exec") => MxcPhase::Exec,
        Some("stop") => MxcPhase::Stop,
        Some("deprovision") => MxcPhase::Deprovision,
        value => return Err(format!("unsupported phase in accepted oracle: {value:?}")),
    };
    let sandbox_id = oracle_optional_string(object.get("sandboxId"));
    let container_id = oracle_optional_string(object.get("containerId"));
    let provision = (phase == MxcPhase::Provision)
        .then(|| contract_expected_provision(config, common_root))
        .transpose()?;
    let exec = (phase == MxcPhase::Exec)
        .then(|| contract_expected_exec(config))
        .transpose()?;
    Ok(NvxPolicyPlan {
        case_id: case_id.to_string(),
        phase,
        sandbox_id,
        container_id,
        provision,
        exec,
    })
}

fn contract_expected_provision(
    config: &Value,
    common_root: &Path,
) -> Result<NvxProvisionPolicy, String> {
    let mut mappings = Vec::new();
    if let Some(filesystem) = config.get("filesystem").and_then(Value::as_object) {
        for (field, access) in [
            ("readonlyPaths", agent_protocol::AccessMode::ReadOnly),
            ("readwritePaths", agent_protocol::AccessMode::ReadWrite),
        ] {
            for source in filesystem
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let child = oracle_mapping_child(source)?;
                let child = agent_protocol::RelativeChildPath::parse(child)
                    .map_err(|error| format!("invalid oracle mapping child: {error}"))?;
                mappings.push(agent_protocol::ChildMapping { child, access });
            }
        }
    }
    let default_network_policy = config
        .get("network")
        .and_then(Value::as_object)
        .and_then(|network| oracle_optional_string(network.get("defaultPolicy")));
    Ok(NvxProvisionPolicy {
        common_root: common_root.to_path_buf(),
        mappings,
        default_network_policy,
    })
}

fn oracle_mapping_child(source: &str) -> Result<String, String> {
    const ROOT: &str = r"C:\nvx-policy-common";
    let suffix = source
        .strip_prefix(ROOT)
        .ok_or_else(|| format!("oracle source is outside common root: {source}"))?;
    Ok(suffix.trim_start_matches(['\\', '/']).replace('\\', "/"))
}

fn contract_expected_exec(config: &Value) -> Result<NvxExecPolicy, String> {
    let process = config
        .get("process")
        .and_then(Value::as_object)
        .ok_or_else(|| "accepted exec case lacks process".to_string())?;
    let command_line = process
        .get("commandLine")
        .and_then(Value::as_str)
        .ok_or_else(|| "accepted exec case lacks commandLine".to_string())?;
    let cwd = oracle_optional_string(process.get("cwd"));
    let mut env = process
        .get("env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Some(proxy) = config
        .get("runtimeConfig")
        .and_then(Value::as_object)
        .and_then(|runtime| runtime.get("networkProxy"))
        .and_then(Value::as_str)
    {
        let proxy = Url::parse(proxy)
            .map_err(|error| format!("invalid accepted oracle proxy: {error}"))?
            .to_string();
        env.push(format!("HTTP_PROXY={proxy}"));
        env.push(format!("HTTPS_PROXY={proxy}"));
    }
    Ok(NvxExecPolicy {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            command_line.to_string(),
        ],
        cwd,
        env,
        timeout_ms: process.get("timeout").and_then(Value::as_u64),
    })
}

fn oracle_optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_string)
}

fn catalog_by_key() -> BTreeMap<String, CatalogEntry> {
    catalog_entries()
        .iter()
        .copied()
        .map(|entry| (entry.key.to_string(), entry))
        .collect()
}

fn observe_catalog_keys(
    config: &Value,
    catalog: &BTreeMap<String, CatalogEntry>,
) -> BTreeSet<String> {
    catalog
        .values()
        .filter(|entry| config_observes_catalog_entry(config, entry))
        .map(|entry| entry.key.to_string())
        .collect()
}

fn config_observes_catalog_entry(config: &Value, entry: &CatalogEntry) -> bool {
    let key = entry.key;
    if key.starts_with("cross.") {
        return observes_cross_field(config, key);
    }
    let (path, qualifier) = parse_key(key);
    match qualifier {
        KeyQualifier::Plain => path_present(config, path),
        KeyQualifier::Absent => path_absent_with_existing_parent(config, path),
        KeyQualifier::Nullable => path_has_null(config, path),
        KeyQualifier::Enum(value) => path_has_string_value(config, path, value),
        KeyQualifier::Union { label: "null", .. } => path_has_null(config, path),
        KeyQualifier::Union { kind, index, label } => {
            union_branch_present(config, path, kind, index, label, entry.schema_path)
        }
        KeyQualifier::Default(default_value) => {
            default_omission_present(config, path, default_value, entry.schema_path)
        }
    }
}

fn union_branch_present(
    config: &Value,
    path: &str,
    kind: &str,
    index: usize,
    label: &str,
    schema_path: &str,
) -> bool {
    if !schema_path.ends_with(&format!("/{kind}/{index}")) {
        return false;
    }
    let Some(branch) = schema_node_at_path(corpus_schema_value(), schema_path) else {
        return false;
    };
    if label.starts_with("#/definitions/") {
        return path_values(config, path)
            .into_iter()
            .any(|value| schema_branch_matches_instance(branch, value, corpus_schema_value()));
    }
    let expected = minimal_schema_value(branch, corpus_schema_value());
    let type_matches_label = match label {
        "null" => expected.is_null(),
        "string" => expected.is_string(),
        "integer" => expected.as_i64().is_some() || expected.as_u64().is_some(),
        "number" => expected.is_number(),
        "boolean" => expected.is_boolean(),
        _ => true,
    };
    type_matches_label && path_values(config, path).contains(&&expected)
}

fn observes_cross_field(config: &Value, key: &str) -> bool {
    let phase = config
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("provision");
    match key {
        "cross.version.must_equal_0.9.0-dev" => {
            config.get("version").and_then(Value::as_str) != Some(SCHEMA_VERSION)
        }
        "cross.phase.non_provision_requires_sandbox_id" => phase != "provision",
        "cross.phase.exec_uses_process_fields" => {
            phase == "exec" && path_present(config, "process")
        }
        "cross.phase.exec_uses_runtime_config_network_proxy" => {
            phase == "exec" && path_present(config, "runtimeConfig.networkProxy")
        }
        "cross.phase.provision_uses_filesystem_rw_and_network_allow_block" => {
            phase == "provision"
                && (path_present(config, "filesystem.readonlyPaths")
                    || path_present(config, "filesystem.readwritePaths"))
                && path_present(config, "network.defaultPolicy")
        }
        _ => false,
    }
}

fn parse_key(key: &str) -> (&str, KeyQualifier<'_>) {
    let mut split = key.splitn(2, '#');
    let path = split.next().unwrap_or(key);
    let Some(qualifier) = split.next() else {
        return (path, KeyQualifier::Plain);
    };
    if qualifier == "absent" {
        return (path, KeyQualifier::Absent);
    }
    if qualifier == "nullable" {
        return (path, KeyQualifier::Nullable);
    }
    if let Some(value) = qualifier.strip_prefix("enum=") {
        return (path, KeyQualifier::Enum(value));
    }
    if let Some(value) = qualifier.strip_prefix("default=") {
        return (path, KeyQualifier::Default(value));
    }
    if let Some((kind, rest)) = qualifier.split_once('[')
        && (kind == "anyOf" || kind == "oneOf")
        && let Some((index_text, label)) = rest.split_once("]=")
        && let Ok(index) = index_text.parse::<usize>()
    {
        return (path, KeyQualifier::Union { kind, index, label });
    }
    (path, KeyQualifier::Plain)
}

fn parse_segments(path: &str) -> Vec<PathSegment<'_>> {
    path.split('.')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if let Some(stripped) = segment.strip_suffix("[]") {
                PathSegment {
                    name: stripped,
                    is_array: true,
                }
            } else {
                PathSegment {
                    name: segment,
                    is_array: false,
                }
            }
        })
        .collect()
}

fn path_values<'a>(config: &'a Value, path: &str) -> Vec<&'a Value> {
    path_values_for_segments(config, &parse_segments(path))
}

fn path_values_for_segments<'a>(config: &'a Value, segments: &[PathSegment<'_>]) -> Vec<&'a Value> {
    let mut frontier = vec![config];
    for segment in segments {
        let mut next = Vec::new();
        for value in frontier {
            let Some(object) = value.as_object() else {
                continue;
            };
            let Some(child) = object.get(segment.name) else {
                continue;
            };
            if segment.is_array {
                if let Some(items) = child.as_array() {
                    next.extend(items.iter());
                }
                continue;
            }
            next.push(child);
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    frontier
}

fn default_omission_present(
    config: &Value,
    path: &str,
    default_value: &str,
    schema_path: &str,
) -> bool {
    if !declared_default_matches_schema_path(schema_path, default_value) {
        return false;
    }

    let segments = parse_segments(path);
    if segments.is_empty() {
        return false;
    }
    let parent_segments = &segments[..segments.len() - 1];
    let child_segment = &segments[segments.len() - 1];
    let parent_values = path_values_for_segments(config, parent_segments);
    parent_values.into_iter().any(|parent| {
        parent
            .as_object()
            .is_some_and(|object| !object.contains_key(child_segment.name))
    })
}

fn declared_default_matches_schema_path(schema_path: &str, default_value: &str) -> bool {
    match schema_path {
        "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0"
        | "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0" => {
            default_value == "exec"
        }
        "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/nestedPty"
        | "/properties/lifecycle/anyOf/0/properties/destroyOnExit"
        | "/properties/seatbelt/anyOf/0/properties/nestedPty"
        | "/properties/ui/anyOf/0/properties/disable" => default_value == "true",
        "/properties/lifecycle/anyOf/0/properties/preservePolicy"
        | "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/retainEtl" => {
            default_value == "false"
        }
        "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/image" => {
            default_value == "alpine:latest"
        }
        "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol"
        | "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol" => {
            default_value == "any"
        }
        "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default" => {
            default_value == "deny"
        }
        "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode" => {
            default_value == "block"
        }
        "/properties/telemetry/anyOf/0/properties/enabled" => default_value == "off",
        _ => false,
    }
}

fn path_present(config: &Value, path: &str) -> bool {
    !path_values(config, path).is_empty()
}

fn path_absent_with_existing_parent(config: &Value, path: &str) -> bool {
    let segments = parse_segments(path);
    if segments.is_empty() {
        return false;
    }
    if segments.len() == 1 {
        return !path_present(config, path);
    }
    let parent_segments = &segments[..segments.len() - 1];
    let child_segment = &segments[segments.len() - 1];
    path_values_for_segments(config, parent_segments)
        .into_iter()
        .any(|parent| parent_absent_child(parent, child_segment))
}

fn parent_absent_child(parent: &Value, child: &PathSegment<'_>) -> bool {
    let Some(object) = parent.as_object() else {
        return false;
    };
    let Some(value) = object.get(child.name) else {
        return true;
    };
    if child.is_array {
        return value.as_array().is_none_or(|items| items.is_empty());
    }
    false
}

fn path_has_null(config: &Value, path: &str) -> bool {
    path_values(config, path).into_iter().any(Value::is_null)
}

fn path_has_string_value(config: &Value, path: &str, expected: &str) -> bool {
    path_values(config, path)
        .into_iter()
        .any(|value| value.as_str() == Some(expected))
}

fn sanitize_id(key: &str) -> String {
    key.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
}

fn base_config_for_entry(entry: &CatalogEntry, key: &str) -> Value {
    if key == "cross.version.must_equal_0.9.0-dev" {
        return base_provision();
    }
    if key == "cross.phase.non_provision_requires_sandbox_id" {
        return json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "exec",
            "process": { "commandLine": "echo generated" }
        });
    }
    if key.starts_with("process")
        || key.starts_with("runtimeConfig")
        || key.starts_with("cross.phase.exec_")
    {
        return base_exec();
    }
    if key.starts_with("phase#enum=") {
        let mut config = base_provision();
        if let Some(value) = key.split("#enum=").nth(1) {
            config
                .as_object_mut()
                .expect("base config object")
                .insert("phase".to_string(), Value::String(value.to_string()));
            if value != "provision" {
                config.as_object_mut().expect("base config object").insert(
                    "sandboxId".to_string(),
                    Value::String("sandbox-1".to_string()),
                );
                if value == "exec" {
                    set_path_value(
                        &mut config,
                        "process.commandLine",
                        Value::String("echo generated".to_string()),
                    );
                }
            }
        }
        return config;
    }
    if entry.phases.contains(&MxcPhase::Exec) && !entry.phases.contains(&MxcPhase::Provision) {
        return base_exec();
    }
    base_provision()
}

fn apply_catalog_entry_to_config(config: &mut Value, entry: &CatalogEntry, schema: &Value) {
    let key = entry.key;
    if key.starts_with("cross.") {
        apply_cross_field_case(config, key);
        return;
    }

    let (path, qualifier) = parse_key(key);
    let value = match qualifier {
        KeyQualifier::Absent => None,
        KeyQualifier::Nullable => Some(Value::Null),
        KeyQualifier::Default(_) => None,
        KeyQualifier::Enum(enum_value) => Some(Value::String(enum_value.to_string())),
        KeyQualifier::Union { label: "null", .. } => Some(Value::Null),
        KeyQualifier::Union { label, .. }
            if label.starts_with("#/definitions/") && path_present(config, path) =>
        {
            None
        }
        KeyQualifier::Union { .. } => Some(
            schema_node_at_path(schema, entry.schema_path)
                .map(|node| minimal_schema_value(node, schema))
                .unwrap_or_else(|| value_for_path(path)),
        ),
        KeyQualifier::Plain => Some(value_for_entry_path(path, entry.schema_path, schema)),
    };

    if matches!(qualifier, KeyQualifier::Default(_) | KeyQualifier::Absent) {
        ensure_parent_path_exists(config, path);
        remove_path(config, path);
    } else if let Some(value) = value {
        set_path_value(config, path, value);
    }
}

fn value_for_entry_path(path: &str, schema_path: &str, schema: &Value) -> Value {
    match path {
        "$schema"
        | "_comment"
        | "version"
        | "containment"
        | "phase"
        | "sandboxId"
        | "containerId"
        | "filesystem"
        | "filesystem.readonlyPaths"
        | "filesystem.readonlyPaths[]"
        | "filesystem.readwritePaths"
        | "filesystem.readwritePaths[]"
        | "filesystem.deniedPaths"
        | "filesystem.deniedPaths[]"
        | "network"
        | "network.allowedHosts"
        | "network.allowedHosts[]"
        | "network.blockedHosts"
        | "network.blockedHosts[]"
        | "network.defaultPolicy"
        | "network.proxy.url"
        | "runtimeConfig.networkProxy"
        | "process"
        | "process.commandLine"
        | "process.cwd"
        | "process.env"
        | "process.env[]"
        | "process.timeout" => value_for_path(path),
        _ => schema_node_at_path(schema, schema_path)
            .map(|node| minimal_schema_value(node, schema))
            .unwrap_or_else(|| value_for_path(path)),
    }
}

fn schema_node_at_path<'a>(schema: &'a Value, schema_path: &str) -> Option<&'a Value> {
    let mut node = schema;
    for encoded in schema_path.trim_start_matches('/').split('/') {
        node = resolve_schema_ref(node, schema).unwrap_or(node);
        let token = encoded.replace("~1", "/").replace("~0", "~");
        node = match node {
            Value::Object(object) => object.get(&token)?,
            Value::Array(values) => values.get(token.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(resolve_schema_ref(node, schema).unwrap_or(node))
}

fn resolve_schema_ref<'a>(node: &'a Value, schema: &'a Value) -> Option<&'a Value> {
    let reference = node.get("$ref").and_then(Value::as_str)?;
    schema.pointer(reference.strip_prefix('#')?)
}

fn minimal_schema_value(node: &Value, schema: &Value) -> Value {
    let resolved = resolve_schema_ref(node, schema).unwrap_or(node);
    if let Some(value) = resolved.get("const") {
        return value.clone();
    }
    if let Some(value) = resolved
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return value.clone();
    }
    for union in ["anyOf", "oneOf"] {
        if let Some(branch) = resolved
            .get(union)
            .and_then(Value::as_array)
            .and_then(|branches| {
                branches
                    .iter()
                    .find(|branch| schema_type(branch, schema) != Some("null"))
                    .or_else(|| branches.first())
            })
        {
            return minimal_schema_value(branch, schema);
        }
    }
    match schema_type(resolved, schema) {
        Some("object") | None if resolved.get("properties").is_some() => {
            let mut object = Map::new();
            if let Some(required) = resolved.get("required").and_then(Value::as_array)
                && let Some(properties) = resolved.get("properties").and_then(Value::as_object)
            {
                for name in required.iter().filter_map(Value::as_str) {
                    if let Some(property) = properties.get(name) {
                        object.insert(name.to_string(), minimal_schema_value(property, schema));
                    }
                }
            }
            Value::Object(object)
        }
        Some("array") => {
            let minimum = resolved
                .get("minItems")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let item = resolved
                .get("items")
                .map(|items| minimal_schema_value(items, schema));
            Value::Array(item.into_iter().cycle().take(minimum).collect())
        }
        Some("string") => Value::String("generated".to_string()),
        Some("integer") | Some("number") => {
            Value::from(resolved.get("minimum").and_then(Value::as_i64).unwrap_or(1))
        }
        Some("boolean") => Value::Bool(false),
        Some("null") => Value::Null,
        _ => Value::Object(Map::new()),
    }
}

fn schema_type<'a>(node: &'a Value, schema: &'a Value) -> Option<&'a str> {
    let resolved = resolve_schema_ref(node, schema).unwrap_or(node);
    match resolved.get("type")? {
        Value::String(value) => Some(value),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .find(|value| *value != "null")
            .or_else(|| values.iter().find_map(Value::as_str)),
        _ => None,
    }
}

fn complete_instance_against_schema(instance: &mut Value, node: &Value, schema: &Value) {
    let resolved = resolve_schema_ref(node, schema).unwrap_or(node);
    for union in ["anyOf", "oneOf"] {
        if let Some(branches) = resolved.get(union).and_then(Value::as_array)
            && let Some(branch) = branches
                .iter()
                .find(|branch| schema_branch_matches_instance(branch, instance, schema))
        {
            complete_instance_against_schema(instance, branch, schema);
            return;
        }
    }
    if let Some(object) = instance.as_object_mut() {
        let Some(properties) = resolved.get("properties").and_then(Value::as_object) else {
            return;
        };
        if let Some(required) = resolved.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(name)
                    && let Some(property) = properties.get(name)
                {
                    object.insert(name.to_string(), minimal_schema_value(property, schema));
                }
            }
        }
        for (name, value) in object {
            if let Some(property) = properties.get(name) {
                complete_instance_against_schema(value, property, schema);
            }
        }
    } else if let Some(values) = instance.as_array_mut()
        && let Some(items) = resolved.get("items")
    {
        for value in values {
            complete_instance_against_schema(value, items, schema);
        }
    }
}

fn schema_branch_matches_instance(branch: &Value, instance: &Value, schema: &Value) -> bool {
    let resolved = resolve_schema_ref(branch, schema).unwrap_or(branch);
    if let Some(values) = resolved.get("enum").and_then(Value::as_array) {
        return values.contains(instance);
    }
    match schema_type(resolved, schema) {
        Some("object") => instance.is_object(),
        Some("array") => instance.is_array(),
        Some("string") => instance.is_string(),
        Some("integer") => instance.as_i64().is_some() || instance.as_u64().is_some(),
        Some("number") => instance.is_number(),
        Some("boolean") => instance.is_boolean(),
        Some("null") => instance.is_null(),
        None => true,
        _ => false,
    }
}

fn apply_cross_field_case(config: &mut Value, key: &str) {
    match key {
        "cross.version.must_equal_0.9.0-dev" => {
            set_path_value(config, "version", Value::String("0.8.0".to_string()));
        }
        "cross.phase.non_provision_requires_sandbox_id" => {
            remove_path(config, "sandboxId");
            set_path_value(config, "phase", Value::String("exec".to_string()));
            set_path_value(
                config,
                "process.commandLine",
                Value::String("echo generated".to_string()),
            );
        }
        "cross.phase.exec_uses_process_fields" => {
            set_path_value(config, "phase", Value::String("exec".to_string()));
            set_path_value(config, "sandboxId", Value::String("sandbox-1".to_string()));
            set_path_value(
                config,
                "process.commandLine",
                Value::String("echo generated".to_string()),
            );
        }
        "cross.phase.exec_uses_runtime_config_network_proxy" => {
            set_path_value(config, "phase", Value::String("exec".to_string()));
            set_path_value(config, "sandboxId", Value::String("sandbox-1".to_string()));
            set_path_value(
                config,
                "process.commandLine",
                Value::String("echo generated".to_string()),
            );
            set_path_value(
                config,
                "runtimeConfig.networkProxy",
                Value::String("http://127.0.0.1:8080".to_string()),
            );
        }
        "cross.phase.provision_uses_filesystem_rw_and_network_allow_block" => {
            set_path_value(config, "phase", Value::String("provision".to_string()));
            remove_path(config, "sandboxId");
            set_path_value(
                config,
                "filesystem.readwritePaths",
                json!([r"C:\nvx-policy-common\rw"]),
            );
            set_path_value(
                config,
                "filesystem.readonlyPaths",
                json!([r"C:\nvx-policy-common\ro"]),
            );
            set_path_value(
                config,
                "network.defaultPolicy",
                Value::String("block".to_string()),
            );
        }
        _ => {}
    }
}

fn value_for_path(path: &str) -> Value {
    match path {
        "$schema" => Value::String("https://example.invalid/mxc.json".to_string()),
        "_comment" => json!({"generated": true}),
        "version" => Value::String(SCHEMA_VERSION.to_string()),
        "containment" => Value::String("vm".to_string()),
        "phase" => Value::String("provision".to_string()),
        "sandboxId" => Value::String("sandbox-1".to_string()),
        "containerId" => Value::String("container-1".to_string()),
        "filesystem" => json!({}),
        "filesystem.readonlyPaths" => json!([r"C:\nvx-policy-common\ro"]),
        "filesystem.readonlyPaths[]" => Value::String(r"C:\nvx-policy-common\ro".to_string()),
        "filesystem.readwritePaths" => json!([r"C:\nvx-policy-common\rw"]),
        "filesystem.readwritePaths[]" => Value::String(r"C:\nvx-policy-common\rw".to_string()),
        "filesystem.deniedPaths" => json!([r"C:\nvx-policy-common\secret"]),
        "filesystem.deniedPaths[]" => Value::String(r"C:\nvx-policy-common\secret".to_string()),
        "network" => json!({}),
        "network.allowedHosts" => json!(["example.com"]),
        "network.allowedHosts[]" => Value::String("example.com".to_string()),
        "network.blockedHosts" => json!(["blocked.example"]),
        "network.blockedHosts[]" => Value::String("blocked.example".to_string()),
        "network.defaultPolicy" => Value::String("block".to_string()),
        "network.proxy.url" | "runtimeConfig.networkProxy" => {
            Value::String("http://127.0.0.1:8080".to_string())
        }
        "process" => json!({"commandLine": "echo generated"}),
        "process.commandLine" => Value::String("echo generated".to_string()),
        "process.cwd" => Value::String("/work".to_string()),
        "process.env" => json!(["A=B"]),
        "process.env[]" => Value::String("A=B".to_string()),
        "process.timeout" => Value::from(1000),
        _ if path.ends_with("[]") => json!(["generated"]),
        _ if path.ends_with(".enabled")
            || path.ends_with(".localhost")
            || path.ends_with(".destroyOnExit")
            || path.ends_with(".preservePolicy")
            || path.ends_with(".disable") =>
        {
            Value::Bool(true)
        }
        _ if path.ends_with(".mode")
            || path.ends_with(".url")
            || path.ends_with(".kind")
            || path.ends_with(".image")
            || path.ends_with(".name")
            || path.ends_with(".commandLine")
            || path.ends_with(".cwd")
            || path.ends_with(".value")
            || path.ends_with(".to")
            || path.ends_with(".from")
            || path.ends_with(".path")
            || path.ends_with(".cidr") =>
        {
            Value::String("generated".to_string())
        }
        _ => json!({}),
    }
}

fn base_provision() -> Value {
    json!({
        "version": SCHEMA_VERSION,
        "containment": "vm",
        "phase": "provision"
    })
}

fn base_exec() -> Value {
    json!({
        "version": SCHEMA_VERSION,
        "containment": "vm",
        "phase": "exec",
        "sandboxId": "sandbox-1",
        "process": { "commandLine": "echo generated" }
    })
}

fn set_path_value(config: &mut Value, path: &str, value: Value) {
    let segments = parse_segments(path);
    if segments.is_empty() {
        return;
    }
    set_path_segments(config, &segments, value);
}

fn set_path_segments(target: &mut Value, segments: &[PathSegment<'_>], value: Value) {
    if segments.is_empty() {
        *target = value;
        return;
    }
    let head = &segments[0];
    let object = ensure_object(target);
    if segments.len() == 1 {
        if head.is_array {
            object.insert(head.name.to_string(), Value::Array(vec![value]));
        } else {
            object.insert(head.name.to_string(), value);
        }
        return;
    }
    let child = object
        .entry(head.name.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if head.is_array {
        let array = ensure_array(child);
        if array.is_empty() {
            array.push(Value::Object(Map::new()));
        }
        set_path_segments(&mut array[0], &segments[1..], value);
        return;
    }
    set_path_segments(child, &segments[1..], value);
}

fn remove_path(config: &mut Value, path: &str) {
    let segments = parse_segments(path);
    remove_path_segments(config, &segments);
}

fn remove_path_segments(target: &mut Value, segments: &[PathSegment<'_>]) {
    if segments.is_empty() {
        return;
    }
    let Some(object) = target.as_object_mut() else {
        return;
    };
    if segments.len() == 1 {
        let _ = object.remove(segments[0].name);
        return;
    }
    let Some(child) = object.get_mut(segments[0].name) else {
        return;
    };
    if segments[0].is_array {
        let Some(items) = child.as_array_mut() else {
            return;
        };
        if let Some(first) = items.first_mut() {
            remove_path_segments(first, &segments[1..]);
        }
        return;
    }
    remove_path_segments(child, &segments[1..]);
}

fn ensure_object(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().expect("value is object")
}

fn ensure_array(value: &mut Value) -> &mut Vec<Value> {
    if !value.is_array() {
        *value = Value::Array(Vec::new());
    }
    value.as_array_mut().expect("value is array")
}

fn ensure_parent_path_exists(config: &mut Value, path: &str) {
    let segments = parse_segments(path);
    if segments.len() < 2 {
        return;
    }
    ensure_path_segments(config, &segments[..segments.len() - 1]);
}

fn ensure_path_segments(target: &mut Value, segments: &[PathSegment<'_>]) {
    if segments.is_empty() {
        return;
    }
    let head = &segments[0];
    let object = ensure_object(target);
    let child = object
        .entry(head.name.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if head.is_array {
        let array = ensure_array(child);
        if array.is_empty() {
            array.push(Value::Object(Map::new()));
        }
        ensure_path_segments(&mut array[0], &segments[1..]);
        return;
    }
    ensure_path_segments(child, &segments[1..]);
}

fn unique_case_output_dir(root: &Path, case_id: &str) -> PathBuf {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let nonce = CORPUS_OUTPUT_NONCE.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    root.join(format!("{case_id}-{process_id}-{now_nanos}-{nonce}"))
}

fn corpus_schema_value() -> &'static Value {
    CORPUS_SCHEMA_VALUE.get_or_init(|| {
        serde_json::from_slice(SCHEMA_BYTES).expect("embedded MXC corpus schema must parse")
    })
}

#[cfg(test)]
fn corpus_schema_validator() -> Result<&'static jsonschema::Validator, PolicyError> {
    CORPUS_SCHEMA_VALIDATOR
        .get_or_init(|| {
            let schema: Value = serde_json::from_slice(SCHEMA_BYTES).map_err(|error| {
                PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!("failed to parse embedded schema bytes for oracle validation: {error}"),
                )
            })?;
            jsonschema::draft7::new(&schema).map_err(|error| {
                PolicyError::new(
                    "corpus_internal",
                    "$",
                    format!("failed to compile embedded schema for oracle validation: {error}"),
                )
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
fn first_direct_schema_error(config: &Value) -> Option<PolicyError> {
    let validator = match corpus_schema_validator() {
        Ok(validator) => validator,
        Err(error) => return Some(error),
    };
    validator.iter_errors(config).next().map(|error| {
        PolicyError::new(
            "schema_validation",
            error.instance_path().to_string(),
            error.to_string(),
        )
    })
}

fn expected_outcome_for_entry(
    entry: &CatalogEntry,
) -> (ExpectedDisposition, Option<String>, Option<String>) {
    let key = entry.key;
    if key == "cross.version.must_equal_0.9.0-dev"
        || key == "version#absent"
        || key == "version#nullable"
    {
        return rejected_expectation("invalid_value", "/version");
    }
    if key.starts_with("containment#")
        && entry
            .expected_instance_behavior()
            .eq(&ExpectedInstanceBehavior::Rejected)
    {
        return rejected_expectation("invalid_value", "/containment");
    }
    if matches!(
        key,
        "phase#absent" | "phase#nullable" | "phase#anyOf[1]=null"
    ) {
        return rejected_expectation("invalid_phase", "/phase");
    }
    if matches!(
        key,
        "process#absent" | "process#nullable" | "process#anyOf[1]=null"
    ) {
        return rejected_expectation("invalid_phase", "/process");
    }
    if matches!(
        key,
        "process.commandLine#absent" | "process.commandLine#nullable"
    ) {
        return rejected_expectation("invalid_value", "/process/commandLine");
    }
    if key == "sandboxId" || key == "cross.phase.non_provision_requires_sandbox_id" {
        return rejected_expectation("invalid_phase", "/sandboxId");
    }
    if entry.disposition == PolicyDisposition::Rejected {
        let (path, _) = parse_key(key);
        return rejected_expectation("unsupported_field", &unsupported_contract_path(path));
    }
    (ExpectedDisposition::Accepted, None, None)
}

fn rejected_expectation(
    code: &str,
    path: &str,
) -> (ExpectedDisposition, Option<String>, Option<String>) {
    (
        ExpectedDisposition::Rejected,
        Some(code.to_string()),
        Some(path.to_string()),
    )
}

fn unsupported_contract_path(path: &str) -> String {
    if path.starts_with("filesystem.deniedPaths") {
        return "/filesystem/deniedPaths".to_string();
    }
    if let Some(network_path) = path.strip_prefix("network.") {
        let field = network_path
            .split(['.', '['])
            .next()
            .unwrap_or(network_path);
        return format!("/network/{field}");
    }
    format!("/{}", path.split(['.', '[']).next().unwrap_or(path))
}

#[cfg(test)]
fn expected_outcome_from_contract(
    config: &Value,
) -> (ExpectedDisposition, Option<String>, Option<String>) {
    if let Some(first) = first_direct_schema_error(config) {
        return (
            ExpectedDisposition::Rejected,
            Some("schema_validation".to_string()),
            Some(first.instance_path),
        );
    }
    if let Some(error) = contract_error(config) {
        return (
            ExpectedDisposition::Rejected,
            Some(error.code),
            Some(error.instance_path),
        );
    }
    (ExpectedDisposition::Accepted, None, None)
}

#[cfg(test)]
fn contract_error(config: &Value) -> Option<PolicyError> {
    let object = config.as_object()?;
    if object.get("version").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
        return Some(PolicyError::new(
            "invalid_value",
            "/version",
            format!("version must be {SCHEMA_VERSION}"),
        ));
    }
    if object.get("containment").and_then(Value::as_str) != Some("vm") {
        return Some(PolicyError::new(
            "invalid_value",
            "/containment",
            "containment must be vm",
        ));
    }

    for field in [
        "experimental",
        "fallback",
        "lifecycle",
        "lxc",
        "processContainer",
        "seatbelt",
        "telemetry",
        "ui",
    ] {
        if object.contains_key(field) {
            return Some(PolicyError::new(
                "unsupported_field",
                format!("/{field}"),
                format!("field `{field}` is not supported"),
            ));
        }
    }

    let phase = object
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(
        phase,
        "provision" | "start" | "exec" | "stop" | "deprovision"
    ) {
        return Some(PolicyError::new("invalid_phase", "/phase", "unknown phase"));
    }
    let sandbox_present = object
        .get("sandboxId")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if phase == "provision" && sandbox_present {
        return Some(PolicyError::new(
            "invalid_phase",
            "/sandboxId",
            "sandboxId identifies a prior provision and must be null or absent",
        ));
    }
    if phase != "provision" && !sandbox_present {
        return Some(PolicyError::new(
            "invalid_phase",
            "/sandboxId",
            "sandboxId is required after provision",
        ));
    }

    match phase {
        "provision" => {
            for field in ["process", "runtimeConfig"] {
                if object.contains_key(field) {
                    return Some(PolicyError::new(
                        "invalid_phase",
                        format!("/{field}"),
                        format!("field `{field}` is not supported in this phase"),
                    ));
                }
            }

            if let Some(filesystem) = object.get("filesystem").and_then(Value::as_object)
                && filesystem.contains_key("deniedPaths")
            {
                return Some(PolicyError::new(
                    "unsupported_field",
                    "/filesystem/deniedPaths",
                    "field `deniedPaths` is not supported",
                ));
            }
            if let Some(network) = object.get("network").and_then(Value::as_object) {
                for field in [
                    "allowLocalNetwork",
                    "allowedHosts",
                    "blockedHosts",
                    "egress",
                    "enforcementMode",
                    "ingress",
                    "proxy",
                ] {
                    if network.contains_key(field) {
                        return Some(PolicyError::new(
                            "unsupported_field",
                            format!("/network/{field}"),
                            format!("field `{field}` is not supported"),
                        ));
                    }
                }
            }
        }
        "exec" => {
            for field in ["filesystem", "network"] {
                if object.contains_key(field) {
                    return Some(PolicyError::new(
                        "invalid_phase",
                        format!("/{field}"),
                        format!("field `{field}` is not supported in this phase"),
                    ));
                }
            }
            let Some(process) = object.get("process").and_then(Value::as_object) else {
                return Some(PolicyError::new(
                    "invalid_phase",
                    "/process",
                    "exec requires process",
                ));
            };
            let command_line = process
                .get("commandLine")
                .and_then(Value::as_str)
                .unwrap_or("");
            if command_line.is_empty() {
                return Some(PolicyError::new(
                    "invalid_value",
                    "/process/commandLine",
                    "exec requires a non-empty command line",
                ));
            }
            if let Some(env) = process.get("env").and_then(Value::as_array) {
                for (index, item) in env.iter().enumerate() {
                    let Some(entry) = item.as_str() else {
                        return Some(PolicyError::new(
                            "invalid_value",
                            format!("/process/env/{index}"),
                            "environment entries must be non-empty KEY=VALUE strings without NUL",
                        ));
                    };
                    if entry
                        .split_once('=')
                        .is_none_or(|(name, _)| name.is_empty())
                        || entry.contains('\0')
                    {
                        return Some(PolicyError::new(
                            "invalid_value",
                            format!("/process/env/{index}"),
                            "environment entries must be non-empty KEY=VALUE strings without NUL",
                        ));
                    }
                    if is_proxy_environment_key(entry) {
                        return Some(PolicyError::new(
                            "cross_field_conflict",
                            "/process/env",
                            "caller environment may not set reserved proxy variables",
                        ));
                    }
                }
            }
            if let Some(runtime) = object.get("runtimeConfig").and_then(Value::as_object)
                && let Some(proxy) = runtime.get("networkProxy").and_then(Value::as_str)
                && !is_valid_loopback_proxy(proxy)
            {
                return Some(PolicyError::new(
                    "invalid_value",
                    "/runtimeConfig/networkProxy",
                    "networkProxy must be an HTTP/S loopback endpoint with an explicit port",
                ));
            }
        }
        "start" | "stop" | "deprovision" => {
            for field in ["filesystem", "network", "process", "runtimeConfig"] {
                if object.contains_key(field) {
                    return Some(PolicyError::new(
                        "invalid_phase",
                        format!("/{field}"),
                        format!("field `{field}` is not supported in this phase"),
                    ));
                }
            }
        }
        _ => {}
    }

    None
}

#[cfg(test)]
fn is_valid_loopback_proxy(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let host_is_loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    let endpoint_only = url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    let explicit_port = explicit_url_port(value);
    matches!(url.scheme(), "http" | "https")
        && host_is_loopback
        && explicit_port.is_some_and(|port| port > 0)
        && endpoint_only
}

#[cfg(test)]
fn explicit_url_port(value: &str) -> Option<u16> {
    let authority = value.split_once("://")?.1.split(['/', '?', '#']).next()?;
    let port = if authority.starts_with('[') {
        authority.split_once("]:")?.1
    } else {
        authority.rsplit_once(':')?.1
    };
    port.parse().ok()
}

#[cfg(test)]
fn is_proxy_environment_key(entry: &str) -> bool {
    entry
        .split_once('=')
        .map(|(key, _)| {
            matches!(
                key.to_ascii_uppercase().as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::content_sha256_hex_bytes;

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
    fn generated_structural_cases_are_schema_valid() {
        let cases = generated_corpus();
        for case in cases {
            assert_eq!(
                first_direct_schema_error(&case.config),
                None,
                "generated structural case {} must satisfy the vendored MXC schema",
                case.id
            );
            assert_ne!(case.expected_code.as_deref(), Some("schema_validation"));
        }
    }

    #[test]
    fn reviewed_expectations_match_independent_contract_oracle() {
        for case in generated_corpus() {
            let actual = expected_outcome_from_contract(&case.config);
            let expected = (
                case.expected_disposition,
                case.expected_code.clone(),
                case.expected_path.clone(),
            );
            assert_eq!(
                expected, actual,
                "reviewed expectation drifted for generated case {}",
                case.id
            );
        }
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

    #[test]
    fn accepted_case_rejects_typed_plan_drift() {
        let mut cases = load_corpus().expect("corpus");
        let case = cases
            .iter_mut()
            .find(|case| {
                case.expected_plan
                    .as_ref()
                    .and_then(|plan| plan.exec.as_ref())
                    .is_some()
            })
            .expect("accepted exec case");
        case.expected_plan
            .as_mut()
            .and_then(|plan| plan.exec.as_mut())
            .expect("exec plan")
            .argv
            .push("forged".to_string());

        let result = run_static_case(
            case,
            &default_static_common_root(),
            Path::new("target/rejected-policy-output"),
        );
        assert!(!result.passed);
        assert_eq!(
            result.error.as_ref().map(|error| error.code.as_str()),
            Some("unexpected_plan")
        );
    }

    #[test]
    fn ad_hoc_accepted_config_does_not_require_a_corpus_oracle() {
        let case = PolicyCase {
            id: "single-config".to_string(),
            config: json!({
                "version": SCHEMA_VERSION,
                "containment": "vm",
                "phase": "provision"
            }),
            expected_disposition: ExpectedDisposition::Accepted,
            expected_plan: None,
            expected_code: None,
            expected_path: None,
            required_evidence: EvidenceRequirement::UnitStatic,
            catalog_keys: Vec::new(),
        };
        let result = run_static_case(
            &case,
            &default_static_common_root(),
            Path::new("target/rejected-policy-output"),
        );
        assert!(result.passed, "{:?}", result.error);
    }

    #[test]
    fn generated_corpus_matches_checked_in_fixture_exactly() {
        let checked_in = load_corpus().expect("corpus fixture");
        let generated = generated_corpus();
        assert_eq!(
            checked_in, generated,
            "fixture drifted from deterministic generator"
        );
    }

    #[test]
    fn checked_in_corpus_hash_is_pinned() {
        assert_eq!(
            content_sha256_hex_bytes(CASES_BYTES),
            "bc25ea50fc99d8003ffe02df4e841f2b1509ff48741c6c38898242f279aab052",
            "corpus hash changed: regenerate fixture and update pin"
        );
    }

    #[test]
    fn one_of_branch_observation_does_not_cover_sibling_branches() {
        let catalog = catalog_by_key();
        let config = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision"
        });

        let vm_entry = catalog
            .get("containment#oneOf[2]=string")
            .expect("vm branch exists");
        let process_entry = catalog
            .get("containment#oneOf[0]=string")
            .expect("process branch exists");

        assert!(config_observes_catalog_entry(&config, vm_entry));
        assert!(!config_observes_catalog_entry(&config, process_entry));
    }

    #[test]
    fn any_of_null_branch_does_not_cover_non_null_branch() {
        let catalog = catalog_by_key();
        let null_branch = catalog
            .get("network.defaultPolicy#anyOf[1]=null")
            .expect("null anyOf branch exists");
        let non_null_branch = catalog
            .get("network.defaultPolicy#anyOf[0]=#/definitions/NetworkPolicy")
            .expect("non-null anyOf branch exists");
        let config = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision",
            "network": { "defaultPolicy": null }
        });

        assert!(config_observes_catalog_entry(&config, null_branch));
        assert!(!config_observes_catalog_entry(&config, non_null_branch));
    }

    #[test]
    fn any_of_non_null_branch_does_not_cover_null_branch() {
        let catalog = catalog_by_key();
        let null_branch = catalog
            .get("network.defaultPolicy#anyOf[1]=null")
            .expect("null anyOf branch exists");
        let non_null_branch = catalog
            .get("network.defaultPolicy#anyOf[0]=#/definitions/NetworkPolicy")
            .expect("non-null anyOf branch exists");
        let config = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision",
            "network": { "defaultPolicy": "block" }
        });

        assert!(!config_observes_catalog_entry(&config, null_branch));
        assert!(config_observes_catalog_entry(&config, non_null_branch));
    }

    #[test]
    fn default_omission_requires_existing_parent_object() {
        let catalog = catalog_by_key();
        let entry = catalog
            .get("lifecycle.destroyOnExit#default=true")
            .expect("default key exists");

        let parent_absent = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision"
        });
        assert!(
            !config_observes_catalog_entry(&parent_absent, entry),
            "missing parent must not satisfy default omission"
        );

        let parent_present = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision",
            "lifecycle": {}
        });
        assert!(
            config_observes_catalog_entry(&parent_present, entry),
            "existing parent with omitted child must satisfy default omission"
        );
    }

    #[test]
    fn absent_nested_array_field_requires_parent_element() {
        let catalog = catalog_by_key();
        let entry = catalog
            .get("network.egress.allow[].ports[].protocol#absent")
            .expect("nested absent key exists");

        let parent_absent = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision"
        });
        assert!(
            !config_observes_catalog_entry(&parent_absent, entry),
            "missing nested parents must not satisfy absent key"
        );

        let parent_present = json!({
            "version": SCHEMA_VERSION,
            "containment": "vm",
            "phase": "provision",
            "network": {
                "egress": {
                    "allow": [
                        { "to": "example.com", "ports": [{}] }
                    ]
                }
            }
        });
        assert!(
            config_observes_catalog_entry(&parent_present, entry),
            "present nested parent element with omitted child must satisfy absent key"
        );
    }

    #[test]
    fn coverage_requires_declared_catalog_key_intersection() {
        let mut cases = load_corpus().expect("corpus");
        for case in &mut cases {
            case.catalog_keys.retain(|key| key != "$schema#absent");
        }

        let error = validate_corpus(&cases).expect_err("must fail uncovered declaration");
        assert!(
            error.message.contains("$schema#absent"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn rejected_catalog_keys_require_rejected_linked_cases() {
        let mut cases = load_corpus().expect("corpus");
        let accepted_plan = cases
            .iter()
            .find_map(|case| case.expected_plan.clone())
            .expect("accepted plan exists");
        let case = cases
            .iter_mut()
            .find(|case| case.catalog_keys.contains(&"network.egress".to_string()))
            .expect("network.egress case exists");
        case.expected_disposition = ExpectedDisposition::Accepted;
        case.expected_plan = Some(accepted_plan);
        case.expected_code = None;
        case.expected_path = None;

        let error = validate_corpus(&cases).expect_err("must fail rejected semantic gate");
        assert!(
            error.message.contains("network.egress"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn honored_presence_keys_must_not_be_only_rejected_cases() {
        let mut cases = load_corpus().expect("corpus");
        let case = cases
            .iter_mut()
            .find(|case| {
                case.catalog_keys
                    .contains(&"process.commandLine".to_string())
            })
            .expect("process.commandLine case exists");
        case.expected_disposition = ExpectedDisposition::Rejected;
        case.expected_plan = None;
        case.expected_code = Some("invalid_value".to_string());
        case.expected_path = Some("/process/commandLine".to_string());

        let error = validate_corpus(&cases).expect_err("must fail honored semantic gate");
        assert!(
            error.message.contains("process.commandLine"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn live_required_catalog_keys_map_exactly_and_rejected_keys_do_not_map() {
        let catalog = catalog_entries();
        let required_live = catalog
            .iter()
            .filter(|entry| {
                entry.required_evidence() == EvidenceRequirement::LiveWhpPositiveNegative
            })
            .map(|entry| entry.key)
            .collect::<BTreeSet<_>>();
        let mapped = mapped_live_profile_keys();
        let missing = required_live
            .difference(&mapped)
            .copied()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "live-required keys missing profile mapping: {missing:?}"
        );

        let rejected = catalog
            .iter()
            .filter(|entry| entry.disposition == PolicyDisposition::Rejected)
            .map(|entry| entry.key)
            .collect::<BTreeSet<_>>();
        let mapped_rejected = mapped.intersection(&rejected).copied().collect::<Vec<_>>();
        assert!(
            mapped_rejected.is_empty(),
            "rejected keys must not map to live profiles: {mapped_rejected:?}"
        );
    }

    #[test]
    fn live_profile_mapping_does_not_alias_qualifier_variants() {
        assert_eq!(
            live_profile_for_path("network.defaultPolicy#anyOf[1]=null"),
            Some("network-positive-negative")
        );
        assert_eq!(
            live_profile_for_path("network.defaultPolicy"),
            Some("network-positive-negative")
        );
        assert_eq!(
            live_profile_for_path("network.defaultPolicy[]"),
            None,
            "array-qualified alias must not map"
        );
        assert_eq!(
            live_profile_for_path("network.defaultPolicy#nullable "),
            None,
            "whitespace alias must not map"
        );
    }
}
