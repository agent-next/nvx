// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
/// Canonical absolute UNIX host root path for mapping declarations.
///
/// Construction is intentionally validation-gated through [`Self::parse`].
///
/// ```compile_fail
/// use agent_protocol::CanonicalHostMappingRoot;
///
/// // Tuple field is private: external callers must use CanonicalHostMappingRoot::parse.
/// let _root = CanonicalHostMappingRoot("/workspace".to_string());
/// ```
pub struct CanonicalHostMappingRoot(String);

impl CanonicalHostMappingRoot {
    pub fn parse(value: String) -> Result<Self, MappingError> {
        validate_canonical_root_path(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CanonicalHostMappingRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct RelativeChildPath(String);

impl RelativeChildPath {
    pub fn parse(value: String) -> Result<Self, MappingError> {
        validate_relative_child_path(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn components(&self) -> Vec<&str> {
        self.0.split('/').collect()
    }
}

impl<'de> Deserialize<'de> for RelativeChildPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildMapping {
    pub child: RelativeChildPath,
    pub access: AccessMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SymlinkContainmentPolicy {
    DeclaredForHostGuestEnforcement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MappingContainmentPolicy {
    pub symlink_policy: SymlinkContainmentPolicy,
    pub reparse_policy: SymlinkContainmentPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappingError {
    EmptyPath,
    AbsolutePath(String),
    NonAbsoluteCanonicalRoot(String),
    DotSegment(String),
    DotDotSegment(String),
    EmptySegment(String),
    WindowsSeparator(String),
    WindowsDrivePrefix(String),
    DuplicateChildPath(String),
    OverlapConflict { left: String, right: String },
}

impl core::fmt::Display for MappingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for MappingError {}

pub fn validate_mapping_set(mappings: &[ChildMapping]) -> Result<(), MappingError> {
    let mut seen = BTreeSet::new();
    for mapping in mappings {
        let value = mapping.child.as_str();
        validate_relative_child_path(value)?;
        if !seen.insert(value.to_string()) {
            return Err(MappingError::DuplicateChildPath(value.to_string()));
        }
    }

    let mut sorted = mappings.to_vec();
    sorted.sort_by(|left, right| left.child.cmp(&right.child));
    for pair in sorted.windows(2) {
        let left = &pair[0].child;
        let right = &pair[1].child;
        if is_ancestor(left, right) {
            return Err(MappingError::OverlapConflict {
                left: left.as_str().to_string(),
                right: right.as_str().to_string(),
            });
        }
    }
    Ok(())
}

pub fn validate_canonical_root_path(value: &str) -> Result<(), MappingError> {
    validate_common_path_rules(value)?;
    if !value.starts_with('/') {
        return Err(MappingError::NonAbsoluteCanonicalRoot(value.to_string()));
    }
    validate_components(value, true)
}

fn validate_relative_child_path(value: &str) -> Result<(), MappingError> {
    validate_common_path_rules(value)?;
    if value.starts_with('/') {
        return Err(MappingError::AbsolutePath(value.to_string()));
    }
    validate_components(value, false)
}

fn validate_common_path_rules(value: &str) -> Result<(), MappingError> {
    if value.is_empty() {
        return Err(MappingError::EmptyPath);
    }
    if value.contains('\\') {
        return Err(MappingError::WindowsSeparator(value.to_string()));
    }
    Ok(())
}

fn validate_components(value: &str, absolute: bool) -> Result<(), MappingError> {
    let mut segments = value.split('/');
    if absolute {
        let _root = segments.next();
    }
    for segment in segments {
        if segment.is_empty() {
            return Err(MappingError::EmptySegment(value.to_string()));
        }
        if segment == "." {
            return Err(MappingError::DotSegment(value.to_string()));
        }
        if segment == ".." {
            return Err(MappingError::DotDotSegment(value.to_string()));
        }
        if has_windows_drive_prefix(segment) {
            return Err(MappingError::WindowsDrivePrefix(value.to_string()));
        }
    }
    Ok(())
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_ancestor(left: &RelativeChildPath, right: &RelativeChildPath) -> bool {
    let left_components = left.components();
    let right_components = right.components();
    left_components.len() < right_components.len()
        && left_components
            .iter()
            .zip(right_components.iter())
            .all(|(l, r)| l == r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(child: &str) -> ChildMapping {
        ChildMapping {
            child: RelativeChildPath::parse(child.to_string()).expect("valid child path"),
            access: AccessMode::ReadWrite,
        }
    }

    #[test]
    fn canonical_root_requires_absolute_clean_unix_path() {
        assert!(CanonicalHostMappingRoot::parse("/workspace/root".to_string()).is_ok());
        assert!(matches!(
            CanonicalHostMappingRoot::parse("workspace/root".to_string()),
            Err(MappingError::NonAbsoluteCanonicalRoot(_))
        ));
        assert!(matches!(
            CanonicalHostMappingRoot::parse("/workspace\\root".to_string()),
            Err(MappingError::WindowsSeparator(_))
        ));
    }

    #[test]
    fn child_path_rejects_empty_dot_dotdot_and_double_separator() {
        assert!(matches!(
            RelativeChildPath::parse("".to_string()),
            Err(MappingError::EmptyPath)
        ));
        assert!(matches!(
            RelativeChildPath::parse("./bin".to_string()),
            Err(MappingError::DotSegment(_))
        ));
        assert!(matches!(
            RelativeChildPath::parse("../bin".to_string()),
            Err(MappingError::DotDotSegment(_))
        ));
        assert!(matches!(
            RelativeChildPath::parse("bin//tool".to_string()),
            Err(MappingError::EmptySegment(_))
        ));
    }

    #[test]
    fn child_path_rejects_absolute_and_windows_forms() {
        assert!(matches!(
            RelativeChildPath::parse("/etc/passwd".to_string()),
            Err(MappingError::AbsolutePath(_))
        ));
        assert!(matches!(
            RelativeChildPath::parse("a\\b".to_string()),
            Err(MappingError::WindowsSeparator(_))
        ));
        assert!(matches!(
            RelativeChildPath::parse("C:/temp".to_string()),
            Err(MappingError::WindowsDrivePrefix(_))
        ));
    }

    #[test]
    fn drive_prefix_is_rejected_in_any_component() {
        assert!(matches!(
            RelativeChildPath::parse("foo/C:/bar".to_string()),
            Err(MappingError::WindowsDrivePrefix(_))
        ));
        assert!(matches!(
            CanonicalHostMappingRoot::parse("/foo/D:/bar".to_string()),
            Err(MappingError::WindowsDrivePrefix(_))
        ));
    }

    #[test]
    fn canonical_root_serde_round_trip_uses_validated_deserialization() {
        let root = CanonicalHostMappingRoot::parse("/workspace/root".to_string()).expect("root");
        let encoded = serde_json::to_string(&root).expect("serialize root");
        assert_eq!(encoded, "\"/workspace/root\"");
        let decoded: CanonicalHostMappingRoot =
            serde_json::from_str(&encoded).expect("deserialize root");
        assert_eq!(decoded, root);
    }

    #[test]
    fn canonical_root_deserialization_rejects_unchecked_values() {
        let err = serde_json::from_str::<CanonicalHostMappingRoot>("\"workspace/root\"")
            .expect_err("relative path must fail");
        assert!(err.to_string().contains("NonAbsoluteCanonicalRoot"));
    }

    #[test]
    fn mapping_set_rejects_duplicate_children() {
        let result = validate_mapping_set(&[rw("workspace"), rw("workspace")]);
        assert!(matches!(result, Err(MappingError::DuplicateChildPath(_))));
    }

    #[test]
    fn mapping_set_rejects_ancestor_descendant_overlap() {
        let result = validate_mapping_set(&[rw("workspace"), rw("workspace/bin")]);
        assert!(matches!(result, Err(MappingError::OverlapConflict { .. })));

        let reverse = validate_mapping_set(&[rw("workspace/bin"), rw("workspace")]);
        assert!(matches!(reverse, Err(MappingError::OverlapConflict { .. })));
    }

    #[test]
    fn mapping_set_allows_distinct_non_overlapping_children() {
        let result = validate_mapping_set(&[rw("workspace/bin"), rw("workspace-lib")]);
        assert!(result.is_ok());
    }

    #[test]
    fn containment_checks_are_schema_only_and_fs_symlink_checks_are_deferred() {
        let result = validate_mapping_set(&[ChildMapping {
            child: RelativeChildPath("workspace/../escape".to_string()),
            access: AccessMode::ReadOnly,
        }]);
        assert!(matches!(result, Err(MappingError::DotDotSegment(_))));
        // Symlink/reparse filesystem traversal checks are intentionally deferred.
    }
}
