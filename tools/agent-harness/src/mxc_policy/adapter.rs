use std::path::{Component, Path, PathBuf};

use agent_protocol::{
    AccessMode, ChildMapping, MAX_EXEC_TIMEOUT_MS, RelativeChildPath, validate_mapping_set,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::{MxcPhase, PolicyError, validate_config};

const SCHEMA_VERSION: &str = "0.9.0-dev";
const SHELL: &str = "/bin/sh";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NvxPolicyPlan {
    pub case_id: String,
    pub phase: MxcPhase,
    pub sandbox_id: Option<String>,
    pub container_id: Option<String>,
    pub provision: Option<NvxProvisionPolicy>,
    pub exec: Option<NvxExecPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NvxProvisionPolicy {
    pub common_root: PathBuf,
    pub mappings: Vec<ChildMapping>,
    pub default_network_policy: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NvxExecPolicy {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<String>,
    pub timeout_ms: Option<u64>,
}

pub fn adapt_policy(
    case_id: impl Into<String>,
    config: &Value,
    common_root: &Path,
) -> Result<NvxPolicyPlan, Vec<PolicyError>> {
    validate_config(config).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| PolicyError {
                code: "schema_validation".to_string(),
                ..error
            })
            .collect::<Vec<_>>()
    })?;

    let object = config.as_object().ok_or_else(|| {
        vec![error(
            "schema_validation",
            "",
            "MXC policy must be a JSON object",
        )]
    })?;
    require_string(object.get("version"), "/version", SCHEMA_VERSION)?;
    require_string(object.get("containment"), "/containment", "vm")?;
    reject_unsupported_top_level(object)?;

    let phase = parse_phase(object.get("phase"))?;
    let sandbox_id = optional_non_empty_string(object.get("sandboxId"), "/sandboxId")?;
    if phase == MxcPhase::Provision && sandbox_id.is_some() {
        return Err(vec![error(
            "invalid_phase",
            "/sandboxId",
            "sandboxId identifies a prior provision and must be null or absent",
        )]);
    }
    if phase != MxcPhase::Provision && sandbox_id.is_none() {
        return Err(vec![error(
            "invalid_phase",
            "/sandboxId",
            "sandboxId is required after provision",
        )]);
    }
    let container_id = optional_non_empty_string(object.get("containerId"), "/containerId")?;

    let (provision, exec) = match phase {
        MxcPhase::Provision => {
            reject_present(object, "process", "invalid_phase")?;
            reject_present(object, "runtimeConfig", "invalid_phase")?;
            (
                Some(adapt_provision(
                    object.get("filesystem"),
                    object.get("network"),
                    common_root,
                )?),
                None,
            )
        }
        MxcPhase::Exec => {
            reject_present(object, "filesystem", "invalid_phase")?;
            reject_present(object, "network", "invalid_phase")?;
            (
                None,
                Some(adapt_exec(
                    object.get("process"),
                    object.get("runtimeConfig"),
                )?),
            )
        }
        MxcPhase::Start | MxcPhase::Stop | MxcPhase::Deprovision => {
            for field in ["filesystem", "network", "process", "runtimeConfig"] {
                reject_present(object, field, "invalid_phase")?;
            }
            (None, None)
        }
    };

    Ok(NvxPolicyPlan {
        case_id: case_id.into(),
        phase,
        sandbox_id,
        container_id,
        provision,
        exec,
    })
}

fn adapt_provision(
    filesystem: Option<&Value>,
    network: Option<&Value>,
    common_root: &Path,
) -> Result<NvxProvisionPolicy, Vec<PolicyError>> {
    let mut mappings = Vec::new();
    if let Some(filesystem) = non_null(filesystem) {
        let object = filesystem.as_object().ok_or_else(|| {
            vec![error(
                "schema_validation",
                "/filesystem",
                "filesystem must be an object",
            )]
        })?;
        reject_nested_present(object, "deniedPaths", "/filesystem", "unsupported_field")?;
        append_mappings(
            &mut mappings,
            object.get("readonlyPaths"),
            AccessMode::ReadOnly,
            "/filesystem/readonlyPaths",
            common_root,
        )?;
        append_mappings(
            &mut mappings,
            object.get("readwritePaths"),
            AccessMode::ReadWrite,
            "/filesystem/readwritePaths",
            common_root,
        )?;
    }
    validate_mapping_set(&mappings).map_err(|mapping_error| {
        vec![error(
            "cross_field_conflict",
            "/filesystem",
            format!("mapping declarations overlap or repeat: {mapping_error}"),
        )]
    })?;
    validate_windows_mapping_equivalence(&mappings)?;

    let mut default_network_policy = None;
    if let Some(network) = non_null(network) {
        let object = network.as_object().ok_or_else(|| {
            vec![error(
                "schema_validation",
                "/network",
                "network must be an object",
            )]
        })?;
        for field in [
            "allowLocalNetwork",
            "allowedHosts",
            "blockedHosts",
            "egress",
            "enforcementMode",
            "ingress",
            "proxy",
        ] {
            reject_nested_present(object, field, "/network", "unsupported_field")?;
        }
        default_network_policy =
            optional_non_empty_string(object.get("defaultPolicy"), "/network/defaultPolicy")?;
    }

    Ok(NvxProvisionPolicy {
        common_root: common_root.to_path_buf(),
        mappings,
        default_network_policy,
    })
}

fn append_mappings(
    mappings: &mut Vec<ChildMapping>,
    value: Option<&Value>,
    access: AccessMode,
    path: &str,
    common_root: &Path,
) -> Result<(), Vec<PolicyError>> {
    for (index, source) in string_array(value, path)?.iter().enumerate() {
        let source_path = Path::new(source);
        let child = mapping_child(common_root, source_path).map_err(|message| {
            vec![error(
                "mapping_outside_root",
                format!("{path}/{index}"),
                message,
            )]
        })?;
        let child = RelativeChildPath::parse(child).map_err(|mapping_error| {
            vec![error(
                "invalid_value",
                format!("{path}/{index}"),
                format!("invalid mapping child path: {mapping_error}"),
            )]
        })?;
        mappings.push(ChildMapping { child, access });
    }
    Ok(())
}

fn mapping_child(common_root: &Path, source: &Path) -> Result<String, String> {
    if !common_root.is_absolute() || !source.is_absolute() {
        return Err("mapping root and source must be absolute paths".to_string());
    }
    let root_components = canonical_windows_components(common_root)?;
    let source_components = canonical_windows_components(source)?;
    if source_components.len() < root_components.len()
        || !root_components
            .iter()
            .zip(&source_components)
            .all(|((root_key, _), (source_key, _))| root_key == source_key)
    {
        return Err(format!(
            "mapping source `{}` is outside the selected common root",
            source.display()
        ));
    }
    let child_components = &source_components[root_components.len()..];
    if child_components.is_empty() {
        return Err("mapping the common root itself is not allowed".to_string());
    }
    Ok(child_components
        .iter()
        .map(|(_, original)| original.as_str())
        .collect::<Vec<_>>()
        .join("/"))
}

fn canonical_windows_components(path: &Path) -> Result<Vec<(String, String)>, String> {
    path.components()
        .map(|component| {
            let original = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| "mapping path is not valid UTF-8".to_string())?;
            if matches!(component, Component::ParentDir | Component::CurDir) {
                return Err("mapping paths must not contain traversal components".to_string());
            }
            if !original.is_ascii() {
                return Err(
                    "mapping paths must use ASCII to preserve Windows case-equivalence checks"
                        .to_string(),
                );
            }
            if matches!(component, Component::Normal(_))
                && (original.ends_with(['.', ' ']) || original.contains(':'))
            {
                return Err(
                    "mapping source contains a non-canonical Windows path segment".to_string(),
                );
            }
            Ok((original.to_ascii_lowercase(), original.to_string()))
        })
        .collect()
}

fn validate_windows_mapping_equivalence(mappings: &[ChildMapping]) -> Result<(), Vec<PolicyError>> {
    let mut normalized = mappings
        .iter()
        .map(|mapping| mapping.child.as_str().to_ascii_lowercase())
        .collect::<Vec<_>>();
    normalized.sort();
    for pair in normalized.windows(2) {
        if pair[0] == pair[1] || pair[1].starts_with(&format!("{}/", pair[0])) {
            return Err(vec![error(
                "cross_field_conflict",
                "/filesystem",
                format!(
                    "mapping declarations alias or overlap on Windows: `{}` and `{}`",
                    pair[0], pair[1]
                ),
            )]);
        }
    }
    Ok(())
}

fn adapt_exec(
    process: Option<&Value>,
    runtime_config: Option<&Value>,
) -> Result<NvxExecPolicy, Vec<PolicyError>> {
    let process = non_null(process)
        .and_then(Value::as_object)
        .ok_or_else(|| vec![error("invalid_phase", "/process", "exec requires process")])?;
    let command_line =
        optional_non_empty_string(process.get("commandLine"), "/process/commandLine")?.ok_or_else(
            || {
                vec![error(
                    "invalid_value",
                    "/process/commandLine",
                    "exec requires a non-empty command line",
                )]
            },
        )?;
    let cwd = optional_non_empty_string(process.get("cwd"), "/process/cwd")?;
    let mut env = string_array(process.get("env"), "/process/env")?;
    validate_environment(&env)?;
    if env.iter().any(|entry| is_proxy_environment_key(entry)) {
        return Err(vec![error(
            "cross_field_conflict",
            "/process/env",
            "caller environment may not set reserved proxy variables",
        )]);
    }
    let timeout_ms = process.get("timeout").and_then(Value::as_u64);
    if timeout_ms.is_some_and(|timeout| timeout == 0 || timeout > MAX_EXEC_TIMEOUT_MS) {
        return Err(vec![error(
            "invalid_value",
            "/process/timeout",
            format!("timeout must be between 1 and {MAX_EXEC_TIMEOUT_MS} milliseconds"),
        )]);
    }

    if let Some(runtime_config) = non_null(runtime_config) {
        let runtime_config = runtime_config.as_object().ok_or_else(|| {
            vec![error(
                "schema_validation",
                "/runtimeConfig",
                "runtimeConfig must be an object",
            )]
        })?;
        if let Some(proxy) = optional_non_empty_string(
            runtime_config.get("networkProxy"),
            "/runtimeConfig/networkProxy",
        )? {
            let proxy = normalize_loopback_proxy(&proxy)?;
            env.push(format!("HTTP_PROXY={proxy}"));
            env.push(format!("HTTPS_PROXY={proxy}"));
        }
    }

    Ok(NvxExecPolicy {
        argv: vec![
            SHELL.to_string(),
            "-c".to_string(),
            command_line.to_string(),
        ],
        cwd,
        env,
        timeout_ms,
    })
}

fn validate_environment(env: &[String]) -> Result<(), Vec<PolicyError>> {
    for (index, entry) in env.iter().enumerate() {
        let valid = entry
            .split_once('=')
            .is_some_and(|(key, _)| !key.is_empty())
            && !entry.contains('\0');
        if !valid {
            return Err(vec![error(
                "invalid_value",
                format!("/process/env/{index}"),
                "environment entries must be non-empty KEY=VALUE strings without NUL",
            )]);
        }
    }
    Ok(())
}

fn normalize_loopback_proxy(value: &str) -> Result<String, Vec<PolicyError>> {
    let url = Url::parse(value).map_err(|parse_error| {
        vec![error(
            "invalid_value",
            "/runtimeConfig/networkProxy",
            format!("networkProxy is not a valid URL: {parse_error}"),
        )]
    })?;
    let host_is_loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    let endpoint_only = url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    let explicit_port = explicit_url_port(value);
    if !matches!(url.scheme(), "http" | "https")
        || !host_is_loopback
        || explicit_port.is_none_or(|port| port == 0)
        || !endpoint_only
    {
        return Err(vec![error(
            "invalid_value",
            "/runtimeConfig/networkProxy",
            "networkProxy must be an HTTP/S loopback endpoint with an explicit port",
        )]);
    }
    Ok(url.to_string())
}

fn explicit_url_port(value: &str) -> Option<u16> {
    let authority = value.split_once("://")?.1.split(['/', '?', '#']).next()?;
    let port = if authority.starts_with('[') {
        authority.split_once("]:")?.1
    } else {
        authority.rsplit_once(':')?.1
    };
    port.parse().ok()
}

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

fn reject_unsupported_top_level(
    object: &serde_json::Map<String, Value>,
) -> Result<(), Vec<PolicyError>> {
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
        reject_present(object, field, "unsupported_field")?;
    }
    Ok(())
}

fn parse_phase(value: Option<&Value>) -> Result<MxcPhase, Vec<PolicyError>> {
    match value.and_then(Value::as_str) {
        Some("provision") => Ok(MxcPhase::Provision),
        Some("start") => Ok(MxcPhase::Start),
        Some("exec") => Ok(MxcPhase::Exec),
        Some("stop") => Ok(MxcPhase::Stop),
        Some("deprovision") => Ok(MxcPhase::Deprovision),
        _ => Err(vec![error(
            "invalid_phase",
            "/phase",
            "a supported state-aware phase is required",
        )]),
    }
}

fn require_string(
    value: Option<&Value>,
    path: &str,
    expected: &str,
) -> Result<(), Vec<PolicyError>> {
    if value.and_then(Value::as_str) == Some(expected) {
        return Ok(());
    }
    Err(vec![error(
        "invalid_value",
        path,
        format!("expected `{expected}`"),
    )])
}

fn optional_non_empty_string(
    value: Option<&Value>,
    path: &str,
) -> Result<Option<String>, Vec<PolicyError>> {
    let Some(value) = non_null(value) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or_else(|| {
        vec![error(
            "schema_validation",
            path,
            "expected a string or null",
        )]
    })?;
    if value.is_empty() || value.contains('\0') {
        return Err(vec![error(
            "invalid_value",
            path,
            "value must be a non-empty string without NUL",
        )]);
    }
    Ok(Some(value.to_string()))
}

fn string_array(value: Option<&Value>, path: &str) -> Result<Vec<String>, Vec<PolicyError>> {
    let Some(value) = non_null(value) else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        vec![error(
            "schema_validation",
            path,
            "expected an array or null",
        )]
    })?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                vec![error(
                    "schema_validation",
                    format!("{path}/{index}"),
                    "expected a string",
                )]
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

fn reject_present(
    object: &serde_json::Map<String, Value>,
    field: &str,
    code: &str,
) -> Result<(), Vec<PolicyError>> {
    if !object.contains_key(field) {
        return Ok(());
    }
    Err(vec![error(
        code,
        format!("/{field}"),
        format!("field `{field}` is not supported in this phase"),
    )])
}

fn reject_nested_present(
    object: &serde_json::Map<String, Value>,
    field: &str,
    parent_path: &str,
    code: &str,
) -> Result<(), Vec<PolicyError>> {
    if !object.contains_key(field) {
        return Ok(());
    }
    Err(vec![error(
        code,
        format!("{parent_path}/{field}"),
        format!("field `{field}` is not supported"),
    )])
}

fn non_null(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

fn error(
    code: impl Into<String>,
    instance_path: impl Into<String>,
    message: impl Into<String>,
) -> PolicyError {
    PolicyError {
        code: code.into(),
        instance_path: instance_path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_protocol::{AccessMode, MAX_EXEC_TIMEOUT_MS};
    use serde_json::{Value, json};

    use super::{MxcPhase, adapt_policy};

    const ROOT: &str = r"C:\mxc-root";

    fn base(phase: &str) -> Value {
        json!({
            "version": "0.9.0-dev",
            "containment": "vm",
            "phase": phase,
            "sandboxId": if phase == "provision" { Value::Null } else { json!("sandbox-1") }
        })
    }

    fn adapt(config: &Value) -> Result<super::NvxPolicyPlan, Vec<super::PolicyError>> {
        adapt_policy("case", config, Path::new(ROOT))
    }

    fn insert(config: &mut Value, field: &str, value: Value) {
        config
            .as_object_mut()
            .expect("test config is an object")
            .insert(field.to_string(), value);
    }

    #[test]
    fn provision_maps_children_and_network_posture() {
        let mut config = base("provision");
        insert(
            &mut config,
            "filesystem",
            json!({
                "readonlyPaths": [r"C:\mxc-root\read"],
                "readwritePaths": [r"C:\mxc-root\write"]
            }),
        );
        insert(
            &mut config,
            "network",
            json!({
                "defaultPolicy": "block"
            }),
        );
        let plan = adapt(&config).expect("supported provision policy");
        let provision = plan.provision.expect("provision plan");
        assert_eq!(plan.phase, MxcPhase::Provision);
        assert_eq!(provision.mappings[0].child.as_str(), "read");
        assert_eq!(provision.mappings[0].access, AccessMode::ReadOnly);
        assert_eq!(provision.mappings[1].child.as_str(), "write");
        assert_eq!(provision.mappings[1].access, AccessMode::ReadWrite);
        assert_eq!(provision.default_network_policy.as_deref(), Some("block"));
    }

    #[test]
    fn exec_preserves_shell_text_and_environment_and_injects_proxy() {
        let mut config = base("exec");
        insert(
            &mut config,
            "process",
            json!({
                "commandLine": "printf '%s' \"$VALUE\"",
                "cwd": "/work",
                "env": ["VALUE=a b"],
                "timeout": 42
            }),
        );
        insert(
            &mut config,
            "runtimeConfig",
            json!({"networkProxy": "http://127.0.0.1:8080"}),
        );
        let plan = adapt(&config).expect("supported exec policy");
        let exec = plan.exec.expect("exec plan");
        assert_eq!(exec.argv, ["/bin/sh", "-c", "printf '%s' \"$VALUE\""]);
        assert_eq!(
            exec.env,
            [
                "VALUE=a b",
                "HTTP_PROXY=http://127.0.0.1:8080/",
                "HTTPS_PROXY=http://127.0.0.1:8080/"
            ]
        );
        assert_eq!(exec.cwd.as_deref(), Some("/work"));
        assert_eq!(exec.timeout_ms, Some(42));
    }

    #[test]
    fn required_contract_fields_are_exact() {
        for (field, value, expected_path) in [
            ("version", json!("0.8.0"), "/version"),
            ("containment", json!("process"), "/containment"),
            ("phase", Value::Null, "/phase"),
        ] {
            let mut config = base("provision");
            insert(&mut config, field, value);
            let errors = adapt(&config).expect_err("invalid contract field");
            assert_eq!(errors[0].instance_path, expected_path);
        }
    }

    #[test]
    fn minimal_valid_config_accepts_all_unsupported_sections_absent() {
        let config = base("provision");
        let object = config.as_object().expect("base config object");
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
            assert!(!object.contains_key(field), "{field} must be absent");
        }
        assert!(adapt(&config).is_ok());
    }

    #[test]
    fn phase_payloads_are_restricted() {
        let mut provision = base("provision");
        insert(&mut provision, "process", json!({"commandLine": "true"}));
        assert_eq!(
            adapt(&provision).expect_err("exec field at provision")[0].code,
            "invalid_phase"
        );

        let mut exec = base("exec");
        insert(&mut exec, "process", json!({"commandLine": "true"}));
        insert(&mut exec, "filesystem", json!({"readonlyPaths": []}));
        assert_eq!(
            adapt(&exec).expect_err("provision field at exec")[0].code,
            "invalid_phase"
        );

        let start = base("start");
        assert!(adapt(&start).is_ok());

        let mut start_with_null_policy = base("start");
        insert(&mut start_with_null_policy, "network", Value::Null);
        assert_eq!(
            adapt(&start_with_null_policy).expect_err("policy presence after provision")[0].code,
            "invalid_phase"
        );
    }

    #[test]
    fn provision_rejects_non_null_sandbox_id() {
        let mut config = base("provision");
        insert(&mut config, "sandboxId", json!("sandbox-1"));
        let error = &adapt(&config).expect_err("provision sandboxId must be null/absent")[0];
        assert_eq!(error.code, "invalid_phase");
        assert_eq!(error.instance_path, "/sandboxId");
    }

    #[test]
    fn exec_rejects_missing_null_and_empty_command_lines() {
        for process in [
            json!({}),
            json!({"commandLine": null}),
            json!({"commandLine": ""}),
        ] {
            let mut config = base("exec");
            insert(&mut config, "process", process);
            let error = &adapt(&config).expect_err("invalid command line")[0];
            assert_eq!(error.code, "invalid_value");
            assert_eq!(error.instance_path, "/process/commandLine");
        }
    }

    #[test]
    fn mappings_reject_outside_traversal_duplicate_and_overlap() {
        let cases = [
            (json!([r"C:\other\file"]), "mapping_outside_root"),
            (json!([r"C:\mxc-root\..\escape"]), "mapping_outside_root"),
            (
                json!([r"C:\mxc-root\same", r"C:\mxc-root\same"]),
                "cross_field_conflict",
            ),
            (
                json!([r"C:\mxc-root\parent", r"C:\mxc-root\parent\child"]),
                "cross_field_conflict",
            ),
        ];
        for (paths, expected_code) in cases {
            let mut config = base("provision");
            insert(&mut config, "filesystem", json!({"readonlyPaths": paths}));
            assert_eq!(
                adapt(&config).expect_err("invalid mappings")[0].code,
                expected_code
            );
        }
    }

    #[test]
    fn mappings_reject_windows_aliases_and_noncanonical_segments() {
        for paths in [
            json!([r"C:\mxc-root\Foo", r"C:\mxc-root\foo"]),
            json!([r"C:\mxc-root\Parent", r"C:\mxc-root\parent\child"]),
            json!([r"C:\mxc-root\file.", r"C:\mxc-root\other"]),
            json!([r"C:\mxc-root\file ", r"C:\mxc-root\other"]),
            json!([r"C:\mxc-root\É", r"C:\mxc-root\é"]),
        ] {
            let mut config = base("provision");
            insert(&mut config, "filesystem", json!({"readonlyPaths": paths}));
            assert!(adapt(&config).is_err(), "mapping aliases must reject");
        }

        let mut mixed_case_root = base("provision");
        insert(
            &mut mixed_case_root,
            "filesystem",
            json!({"readonlyPaths": [r"c:\MXC-ROOT\Child"]}),
        );
        let plan = adapt(&mixed_case_root).expect("Windows roots compare case-insensitively");
        assert_eq!(
            plan.provision.expect("provision").mappings[0]
                .child
                .as_str(),
            "Child"
        );
    }

    #[test]
    fn environment_and_proxy_conflicts_are_rejected() {
        for env in [
            json!([""]),
            json!(["NOVALUE"]),
            json!(["=empty-key"]),
            json!(["BAD=\u{0}"]),
        ] {
            let mut config = base("exec");
            insert(
                &mut config,
                "process",
                json!({"commandLine": "true", "env": env}),
            );
            assert_eq!(
                adapt(&config).expect_err("invalid environment")[0].code,
                "invalid_value"
            );
        }

        for key in ["HTTP_PROXY", "https_proxy", "No_PrOxY"] {
            let mut config = base("exec");
            insert(
                &mut config,
                "process",
                json!({"commandLine": "true", "env": [format!("{key}=caller")]}),
            );
            let without_runtime_proxy = adapt(&config).expect_err("reserved proxy environment");
            assert_eq!(without_runtime_proxy[0].code, "cross_field_conflict");
            assert_eq!(without_runtime_proxy[0].instance_path, "/process/env");

            insert(
                &mut config,
                "runtimeConfig",
                json!({"networkProxy": "https://127.0.0.1:8443"}),
            );
            assert_eq!(
                adapt(&config).expect_err("proxy conflict")[0].code,
                "cross_field_conflict"
            );
        }
    }

    #[test]
    fn unsupported_policy_surfaces_are_rejected() {
        let top_level = [
            ("telemetry", json!({"enabled": true})),
            ("ui", json!({"disable": true})),
            ("lifecycle", json!({"destroyOnExit": true})),
            ("lxc", json!({"distribution": "ubuntu"})),
            ("processContainer", json!({"learningMode": true})),
            ("seatbelt", json!({"guiAccess": true})),
            ("experimental", json!({"test": {"message": "x"}})),
            ("fallback", json!({"allowDaclMutation": true})),
        ];
        for (field, value) in top_level {
            let mut config = base("provision");
            insert(&mut config, field, value);
            let error = &adapt(&config).expect_err("unsupported field")[0];
            assert_eq!(error.code, "unsupported_field");
            assert_eq!(error.instance_path, format!("/{field}"));
        }

        let mut null_telemetry = base("provision");
        insert(&mut null_telemetry, "telemetry", Value::Null);
        assert_eq!(
            adapt(&null_telemetry).expect_err("nullable rejected field")[0].instance_path,
            "/telemetry"
        );

        let mut config = base("provision");
        insert(&mut config, "filesystem", json!({"deniedPaths": []}));
        let error = &adapt(&config).expect_err("unsupported filesystem")[0];
        assert_eq!(error.code, "unsupported_field");
        assert_eq!(error.instance_path, "/filesystem/deniedPaths");

        for (field, value) in [
            ("allowLocalNetwork", json!(true)),
            ("allowedHosts", json!(["allowed.example"])),
            ("blockedHosts", json!(["blocked.example"])),
            ("egress", json!({})),
            ("enforcementMode", json!("firewall")),
            ("ingress", json!({})),
            ("proxy", json!({"url": "http://127.0.0.1:8080"})),
        ] {
            let mut config = base("provision");
            insert(&mut config, "network", json!({field: value}));
            let error = &adapt(&config).expect_err("unsupported network field")[0];
            assert_eq!(error.code, "unsupported_field");
            assert_eq!(error.instance_path, format!("/network/{field}"));
        }
    }

    #[test]
    fn proxy_must_be_a_normalized_loopback_endpoint() {
        for proxy in [
            "http://",
            "https://example.com:443",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:8080/path",
            "http://user@127.0.0.1:8080",
        ] {
            let mut config = base("exec");
            insert(&mut config, "process", json!({"commandLine": "true"}));
            insert(&mut config, "runtimeConfig", json!({"networkProxy": proxy}));
            let error = &adapt(&config).expect_err("invalid proxy endpoint")[0];
            assert_eq!(error.code, "invalid_value");
            assert_eq!(error.instance_path, "/runtimeConfig/networkProxy");
        }

        for proxy in ["http://127.0.0.1:80", "https://localhost:443"] {
            let mut config = base("exec");
            insert(&mut config, "process", json!({"commandLine": "true"}));
            insert(&mut config, "runtimeConfig", json!({"networkProxy": proxy}));
            assert!(adapt(&config).is_ok(), "explicit default port should work");
        }
    }

    #[test]
    fn timeout_matches_protocol_bounds() {
        for timeout in [1, MAX_EXEC_TIMEOUT_MS] {
            let mut config = base("exec");
            insert(
                &mut config,
                "process",
                json!({"commandLine": "true", "timeout": timeout}),
            );
            assert!(adapt(&config).is_ok());
        }
        for timeout in [0, MAX_EXEC_TIMEOUT_MS + 1] {
            let mut config = base("exec");
            insert(
                &mut config,
                "process",
                json!({"commandLine": "true", "timeout": timeout}),
            );
            let error = &adapt(&config).expect_err("invalid timeout")[0];
            assert_eq!(error.code, "invalid_value");
            assert_eq!(error.instance_path, "/process/timeout");
        }
    }
}
