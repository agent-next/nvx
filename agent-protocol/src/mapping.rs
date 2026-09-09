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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CanonicalHostMappingRoot(pub String);

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

fn validate_relative_child_path(value: &str) -> Result<(), MappingError> {
    if value.is_empty() {
        return Err(MappingError::EmptyPath);
    }
    if value.starts_with('/') {
        return Err(MappingError::AbsolutePath(value.to_string()));
    }
    if value.contains('\\') {
        return Err(MappingError::WindowsSeparator(value.to_string()));
    }
    if has_windows_drive_prefix(value) {
        return Err(MappingError::WindowsDrivePrefix(value.to_string()));
    }
    for segment in value.split('/') {
        if segment.is_empty() {
            return Err(MappingError::EmptySegment(value.to_string()));
        }
        if segment == "." {
            return Err(MappingError::DotSegment(value.to_string()));
        }
        if segment == ".." {
            return Err(MappingError::DotDotSegment(value.to_string()));
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
