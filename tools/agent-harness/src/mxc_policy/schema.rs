use std::collections::BTreeMap;
use std::sync::OnceLock;

use jsonschema::error::ValidationErrorKind;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::PolicyError;

const SCHEMA_BYTES: &[u8] = include_bytes!("../../schemas/mxc-config.schema.0.9.0-dev.json");
#[cfg(test)]
const REPO_GITATTRIBUTES: &str = include_str!("../../../../.gitattributes");
const SCHEMA_PROVENANCE: &str =
    include_str!("../../schemas/mxc-config.schema.0.9.0-dev.provenance.json");
const DRAFT7_META_SCHEMA: &str = "http://json-schema.org/draft-07/schema#";
const POLICY_SCHEMA_CODE: &str = "policy_schema";
const POLICY_VALIDATION_CODE: &str = "policy_validation";
const POLICY_UNKNOWN_FIELD_CODE: &str = "policy_unknown_field";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum MxcPhase {
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

impl MxcPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Start => "start",
            Self::Exec => "exec",
            Self::Stop => "stop",
            Self::Deprovision => "deprovision",
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledSchema {
    schema: Value,
    validator: jsonschema::Validator,
    raw_sha256: String,
    normalized_sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct SchemaProvenanceFile {
    #[serde(rename = "sourceCommit")]
    source_commit: String,
    #[serde(rename = "rawSha256")]
    raw_sha256: String,
    #[serde(rename = "normalizedSha256")]
    normalized_sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct SchemaProvenance {
    #[serde(default = "default_draft_value")]
    pub draft: Value,
    #[serde(rename = "sourceCommit")]
    pub source_commit: String,
    #[serde(rename = "rawSha256")]
    pub raw_sha256: String,
    #[serde(rename = "normalizedSha256")]
    pub normalized_sha256: String,
}

fn default_draft_value() -> Value {
    Value::String(DRAFT7_META_SCHEMA.to_string())
}

static COMPILED_SCHEMA: OnceLock<Result<CompiledSchema, PolicyError>> = OnceLock::new();

fn compiled_schema() -> Result<&'static CompiledSchema, PolicyError> {
    COMPILED_SCHEMA
        .get_or_init(compile_schema)
        .as_ref()
        .map_err(Clone::clone)
}

pub fn schema() -> Result<Value, PolicyError> {
    compiled_schema().map(|compiled| compiled.schema.clone())
}

pub fn schema_bytes() -> &'static [u8] {
    SCHEMA_BYTES
}

fn compile_schema() -> Result<CompiledSchema, PolicyError> {
    let schema: Value = serde_json::from_slice(SCHEMA_BYTES).map_err(|error| PolicyError {
        code: POLICY_SCHEMA_CODE.to_string(),
        instance_path: String::new(),
        message: format!("failed to parse embedded MXC schema JSON: {error}"),
    })?;
    let validator = jsonschema::draft7::new(&schema).map_err(|error| PolicyError {
        code: POLICY_SCHEMA_CODE.to_string(),
        instance_path: location_to_pointer(error.instance_path()),
        message: format!("failed to compile embedded MXC Draft 7 schema: {error}"),
    })?;
    Ok(CompiledSchema {
        raw_sha256: sha256_hex(SCHEMA_BYTES),
        normalized_sha256: sha256_hex(&normalized_schema_bytes(&schema)?),
        schema,
        validator,
    })
}

pub fn schema_raw_sha256() -> Result<String, PolicyError> {
    compiled_schema().map(|compiled| compiled.raw_sha256.clone())
}

pub fn raw_sha256() -> String {
    sha256_hex(SCHEMA_BYTES)
}

pub fn normalized_sha256() -> Result<String, PolicyError> {
    schema_normalized_sha256()
}

pub fn provenance() -> Result<SchemaProvenance, PolicyError> {
    let parsed: SchemaProvenanceFile =
        serde_json::from_str(SCHEMA_PROVENANCE).map_err(|error| {
            PolicyError::new(
                POLICY_SCHEMA_CODE,
                "",
                format!("failed to parse embedded schema provenance: {error}"),
            )
        })?;
    Ok(SchemaProvenance {
        draft: Value::String(DRAFT7_META_SCHEMA.to_string()),
        source_commit: parsed.source_commit,
        raw_sha256: parsed.raw_sha256,
        normalized_sha256: parsed.normalized_sha256,
    })
}

pub fn schema_normalized_sha256() -> Result<String, PolicyError> {
    compiled_schema().map(|compiled| compiled.normalized_sha256.clone())
}

pub fn schema_declares_draft7() -> Result<bool, PolicyError> {
    compiled_schema().map(|compiled| {
        compiled
            .schema
            .get("$schema")
            .and_then(Value::as_str)
            .is_some_and(|value| value == DRAFT7_META_SCHEMA)
    })
}

pub fn validate_config(config: &Value) -> Result<(), Vec<PolicyError>> {
    let compiled = compiled_schema().map_err(|error| vec![error])?;
    let mut errors = unknown_field_errors(config, &compiled.schema);
    errors.extend(
        compiled
            .validator
            .iter_errors(config)
            .flat_map(policy_errors_from_validation),
    );
    if errors.is_empty() {
        return Ok(());
    }
    Err(errors)
}

fn policy_errors_from_validation(error: jsonschema::ValidationError<'_>) -> Vec<PolicyError> {
    let parent_path = location_to_pointer(error.instance_path());
    if matches!(
        error.kind(),
        ValidationErrorKind::AdditionalProperties { .. }
    ) {
        return Vec::new();
    }
    vec![PolicyError {
        code: POLICY_VALIDATION_CODE.to_string(),
        instance_path: parent_path,
        message: error.to_string(),
    }]
}

fn unknown_field_errors(config: &Value, schema: &Value) -> Vec<PolicyError> {
    let Some(definitions) = schema.get("definitions").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut errors = BTreeMap::new();
    collect_unknown_fields(config, schema, definitions, "", &mut errors);
    errors.into_values().collect()
}

fn collect_unknown_fields(
    instance: &Value,
    schema: &Value,
    definitions: &Map<String, Value>,
    instance_path: &str,
    errors: &mut BTreeMap<String, PolicyError>,
) {
    if let Some(instance_array) = instance.as_array() {
        let item_schemas = array_item_schemas(schema, definitions);
        for (index, item) in instance_array.iter().enumerate() {
            let item_path = join_pointer_path(instance_path, &index.to_string());
            for item_schema in &item_schemas {
                collect_unknown_fields(item, item_schema, definitions, &item_path, errors);
            }
        }
        return;
    }
    let Some(instance_object) = instance.as_object() else {
        return;
    };
    let candidates = object_schema_candidates(schema, definitions);
    if candidates.is_empty() {
        return;
    }

    for (field, child) in instance_object {
        let child_path = join_pointer_path(instance_path, field);
        let child_schemas = candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get(field))
            })
            .collect::<Vec<_>>();
        if child_schemas.is_empty()
            && candidates
                .iter()
                .all(|candidate| candidate.get("additionalProperties") == Some(&Value::Bool(false)))
        {
            errors.insert(
                child_path.clone(),
                PolicyError {
                    code: POLICY_UNKNOWN_FIELD_CODE.to_string(),
                    instance_path: child_path,
                    message: format!("unknown policy field `{field}`"),
                },
            );
            continue;
        }
        for child_schema in child_schemas {
            collect_unknown_fields(child, child_schema, definitions, &child_path, errors);
        }
    }
}

fn object_schema_candidates<'a>(
    schema: &'a Value,
    definitions: &'a Map<String, Value>,
) -> Vec<&'a Value> {
    if let Some(name) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/definitions/"))
    {
        return definitions.get(name).map_or_else(Vec::new, |definition| {
            object_schema_candidates(definition, definitions)
        });
    }
    if schema.get("properties").is_some() {
        return vec![schema];
    }
    for union_key in ["anyOf", "oneOf"] {
        if let Some(branches) = schema.get(union_key).and_then(Value::as_array) {
            return branches
                .iter()
                .flat_map(|branch| object_schema_candidates(branch, definitions))
                .collect();
        }
    }
    Vec::new()
}

fn array_item_schemas<'a>(
    schema: &'a Value,
    definitions: &'a Map<String, Value>,
) -> Vec<&'a Value> {
    if let Some(name) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/definitions/"))
    {
        return definitions.get(name).map_or_else(Vec::new, |definition| {
            array_item_schemas(definition, definitions)
        });
    }
    if let Some(items) = schema.get("items") {
        return vec![items];
    }
    for union_key in ["anyOf", "oneOf"] {
        if let Some(branches) = schema.get(union_key).and_then(Value::as_array) {
            return branches
                .iter()
                .flat_map(|branch| array_item_schemas(branch, definitions))
                .collect();
        }
    }
    Vec::new()
}

fn normalized_schema_bytes(schema: &Value) -> Result<Vec<u8>, PolicyError> {
    let canonical_schema = normalize_value(schema);
    serde_json::to_vec(&canonical_schema).map_err(|error| PolicyError {
        code: POLICY_SCHEMA_CODE.to_string(),
        instance_path: String::new(),
        message: format!("failed to serialize normalized MXC schema JSON: {error}"),
    })
}

fn normalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, child)| (key.clone(), normalize_value(child)))
                .collect::<BTreeMap<_, _>>();
            let mut normalized_map = Map::with_capacity(sorted.len());
            for (key, child) in sorted {
                normalized_map.insert(key, child);
            }
            Value::Object(normalized_map)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize_value).collect()),
        _ => value.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn location_to_pointer(location: &jsonschema::paths::Location) -> String {
    location.to_string()
}

fn join_pointer_path(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        return format!("/{}", escape_json_pointer_token(field));
    }
    format!("{parent}/{}", escape_json_pointer_token(field))
}

fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;
    use serde_json::{Map, Value};

    use super::{
        MxcPhase, REPO_GITATTRIBUTES, SCHEMA_PROVENANCE, SchemaProvenance, schema_declares_draft7,
        schema_normalized_sha256, schema_raw_sha256, validate_config,
    };

    #[test]
    fn schema_declares_draft7_meta_schema() {
        assert!(schema_declares_draft7().expect("schema compiles"));
    }

    #[test]
    fn schema_hashes_match_provenance() {
        let provenance: SchemaProvenance =
            serde_json::from_str(SCHEMA_PROVENANCE).expect("embedded provenance must parse");
        assert_eq!(
            provenance.raw_sha256,
            "ad4a080ced7b73a4bcbe294551b5d61f703a1603bc85c161fa9a94e7a20e5c52"
        );
        assert_eq!(
            provenance.normalized_sha256,
            "9bdc64c7ff1c3b520cde841776b260e6816328f92a835b09f1a054e068b25652"
        );
        assert_eq!(
            schema_raw_sha256().expect("schema compiles"),
            provenance.raw_sha256
        );
        assert_eq!(
            schema_normalized_sha256().expect("schema compiles"),
            provenance.normalized_sha256
        );
    }

    #[test]
    fn schema_has_explicit_non_normalizing_gitattributes_rule() {
        let required_rule = "tools/agent-harness/schemas/mxc-config.schema.0.9.0-dev.json -text";
        assert!(
            REPO_GITATTRIBUTES
                .lines()
                .any(|line| line.trim() == required_rule),
            "missing required .gitattributes rule: {required_rule}"
        );
    }

    #[test]
    fn mxc_phase_enum_matches_schema_phase_enum_exactly() {
        let schema_json: Value =
            serde_json::from_slice(super::SCHEMA_BYTES).expect("schema parses");
        let schema_phases = schema_json
            .get("definitions")
            .and_then(|value| value.get("Phase"))
            .and_then(|value| value.get("enum"))
            .and_then(Value::as_array)
            .expect("schema definitions.Phase.enum is present");
        let schema_phase_set = schema_phases
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("phase enum values are strings")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();

        let rust_phases = [
            MxcPhase::Provision,
            MxcPhase::Start,
            MxcPhase::Exec,
            MxcPhase::Stop,
            MxcPhase::Deprovision,
        ];
        let rust_phase_set = rust_phases
            .into_iter()
            .map(|phase| phase.as_str().to_string())
            .collect::<BTreeSet<_>>();

        let missing_in_rust = schema_phase_set
            .difference(&rust_phase_set)
            .map(String::as_str)
            .collect::<Vec<_>>();
        let missing_in_schema = rust_phase_set
            .difference(&schema_phase_set)
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(
            missing_in_rust.is_empty() && missing_in_schema.is_empty(),
            "MxcPhase/schema Phase drift. missing in rust: [{}]; missing in schema: [{}]",
            missing_in_rust.join(", "),
            missing_in_schema.join(", ")
        );
    }

    fn required_null_config() -> Value {
        let schema_json: Value =
            serde_json::from_slice(super::SCHEMA_BYTES).expect("schema parses");
        let mut config = Value::Object(Map::new());
        if let Some(required) = schema_json.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                config
                    .as_object_mut()
                    .expect("config object")
                    .insert(key.to_string(), json!(null));
            }
        }
        config
    }

    #[test]
    fn multiple_unknown_top_level_fields_report_each_instance_path() {
        let mut config = required_null_config();
        config
            .as_object_mut()
            .expect("config object")
            .insert("firstUnexpectedField".to_string(), json!(true));
        config
            .as_object_mut()
            .expect("config object")
            .insert("secondUnexpectedField".to_string(), json!(true));
        let errors = validate_config(&config).expect_err("expected validation failure");
        let paths = errors
            .iter()
            .filter(|error| error.code == super::POLICY_UNKNOWN_FIELD_CODE)
            .map(|error| error.instance_path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            paths,
            BTreeSet::from(["/firstUnexpectedField", "/secondUnexpectedField"])
        );
    }

    #[test]
    fn unknown_nested_field_reports_its_instance_path() {
        let mut config = required_null_config();
        config.as_object_mut().expect("config object").insert(
            "runtimeConfig".to_string(),
            json!({"unexpected/nested~field": true}),
        );
        let errors = validate_config(&config).expect_err("expected validation failure");
        assert!(
            errors.iter().any(|error| {
                error.code == super::POLICY_UNKNOWN_FIELD_CODE
                    && error.instance_path == "/runtimeConfig/unexpected~1nested~0field"
            }),
            "validation errors: {errors:#?}"
        );
    }

    #[test]
    fn unknown_field_in_array_element_reports_its_instance_path() {
        let mut config = required_null_config();
        config.as_object_mut().expect("config object").insert(
            "network".to_string(),
            json!({"egress": {"allow": [{"to": "example.com", "unexpected": true}]}}),
        );
        let errors = validate_config(&config).expect_err("expected validation failure");
        assert!(
            errors.iter().any(|error| {
                error.code == super::POLICY_UNKNOWN_FIELD_CODE
                    && error.instance_path == "/network/egress/allow/0/unexpected"
            }),
            "validation errors: {errors:#?}"
        );
    }
}
