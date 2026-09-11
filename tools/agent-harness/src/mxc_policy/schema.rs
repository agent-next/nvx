use std::collections::BTreeMap;
use std::sync::OnceLock;

use jsonschema::error::ValidationErrorKind;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::PolicyError;

const SCHEMA_BYTES: &[u8] = include_bytes!("../../schemas/mxc-config.schema.0.9.0-dev.json");
#[cfg(test)]
const SCHEMA_PROVENANCE: &str =
    include_str!("../../schemas/mxc-config.schema.0.9.0-dev.provenance.json");
const DRAFT7_META_SCHEMA: &str = "http://json-schema.org/draft-07/schema#";
const POLICY_SCHEMA_CODE: &str = "policy_schema";
const POLICY_VALIDATION_CODE: &str = "policy_validation";
const POLICY_UNKNOWN_FIELD_CODE: &str = "policy_unknown_field";

#[derive(Clone, Debug)]
struct CompiledSchema {
    schema: Value,
    validator: jsonschema::Validator,
    raw_sha256: String,
    normalized_sha256: String,
}

#[cfg(test)]
#[derive(Clone, Debug, serde::Deserialize)]
struct SchemaProvenance {
    #[serde(rename = "rawSha256")]
    raw_sha256: String,
    #[serde(rename = "normalizedSha256")]
    normalized_sha256: String,
}

static COMPILED_SCHEMA: OnceLock<Result<CompiledSchema, PolicyError>> = OnceLock::new();

fn compiled_schema() -> Result<&'static CompiledSchema, PolicyError> {
    COMPILED_SCHEMA
        .get_or_init(compile_schema)
        .as_ref()
        .map_err(Clone::clone)
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
    let errors = compiled
        .validator
        .iter_errors(config)
        .map(policy_error_from_validation)
        .collect::<Vec<_>>();
    if errors.is_empty() {
        return Ok(());
    }
    Err(errors)
}

fn policy_error_from_validation(error: jsonschema::ValidationError<'_>) -> PolicyError {
    let mut instance_path = location_to_pointer(error.instance_path());
    let code = match error.kind() {
        ValidationErrorKind::AdditionalProperties { unexpected } => {
            if instance_path.is_empty() && unexpected.len() == 1 {
                instance_path = join_pointer_path("", &unexpected[0]);
            }
            POLICY_UNKNOWN_FIELD_CODE
        }
        _ => POLICY_VALIDATION_CODE,
    };
    PolicyError {
        code: code.to_string(),
        instance_path,
        message: error.to_string(),
    }
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
    use serde_json::json;
    use serde_json::{Map, Value};

    use super::{
        SCHEMA_PROVENANCE, SchemaProvenance, schema_declares_draft7, schema_normalized_sha256,
        schema_raw_sha256, validate_config,
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
    fn unknown_top_level_field_reports_its_instance_path() {
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
            .as_object_mut()
            .expect("config object")
            .insert("unexpectedTopLevelField".to_string(), json!(true));
        let errors = validate_config(&config).expect_err("expected validation failure");
        assert!(
            errors
                .iter()
                .any(|error| error.instance_path == "/unexpectedTopLevelField")
        );
    }
}
