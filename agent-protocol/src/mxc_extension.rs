// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Phase-0 MXC extension boundary.
//!
//! This module intentionally models the service contract only. It does not claim ACI-04
//! protobuf/TTRPC compatibility and keeps host-integration behind an explicit unsupported stub
//! until exact schemas and fixtures are wired in.

use ::serde::{Deserialize, Serialize};

/// Pinned ACI source revision required before any wire-compatibility claim.
pub const ACI_PINNED_REVISION: &str = "cbd276763e099aa17b3d10addcce8dc23800c9e2";

/// Version for this MXC extension model.
pub const MXC_EXTENSION_VERSION: u32 = 1;

/// Phase-0 modeled requirements.
///
/// These model the distinct operations called out in the guest-agent architecture design.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MxcRequirement {
    Ready,
    Bootstrap,
    ExecuteCommand,
    InteractiveShell,
    StreamLogs,
    Signal,
    WaitContainerExited,
    Probe,
    PrepareSnapshot,
    PostRestore,
    Checkpoint,
    Shutdown,
}

/// Stable list of modeled requirements for deterministic harness assertions.
pub const MODELED_REQUIREMENTS: [MxcRequirement; 12] = [
    MxcRequirement::Ready,
    MxcRequirement::Bootstrap,
    MxcRequirement::ExecuteCommand,
    MxcRequirement::InteractiveShell,
    MxcRequirement::StreamLogs,
    MxcRequirement::Signal,
    MxcRequirement::WaitContainerExited,
    MxcRequirement::Probe,
    MxcRequirement::PrepareSnapshot,
    MxcRequirement::PostRestore,
    MxcRequirement::Checkpoint,
    MxcRequirement::Shutdown,
];

/// Extension request envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MxcRequest {
    pub version: u32,
    pub requirement: MxcRequirement,
}

/// Extension response envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MxcResponse {
    pub version: u32,
    pub requirement: MxcRequirement,
    pub state: MxcRequirementState,
}

/// Outcome for one requirement in this phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MxcRequirementState {
    Modeled,
    Unsupported,
}

/// Typed service error.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MxcServiceError {
    pub code: MxcServiceErrorCode,
    pub message: String,
}

/// Stable error code set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MxcServiceErrorCode {
    UnsupportedVersion,
    UnsupportedAciAdapter,
}

/// Host-facing MXC boundary.
pub trait MxcExtensionService {
    fn call(&self, request: MxcRequest) -> Result<MxcResponse, MxcServiceError>;
}

/// Adapter state for ACI integration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AciAdapterStatus {
    Unsupported {
        required_revision: &'static str,
        reason: &'static str,
    },
}

/// Explicit phase-0 service stub.
pub struct UnsupportedAciAdapter;

impl UnsupportedAciAdapter {
    pub const fn status() -> AciAdapterStatus {
        AciAdapterStatus::Unsupported {
            required_revision: ACI_PINNED_REVISION,
            reason: "ACI schemas/fixtures are not integrated in this repository",
        }
    }
}

impl MxcExtensionService for UnsupportedAciAdapter {
    fn call(&self, request: MxcRequest) -> Result<MxcResponse, MxcServiceError> {
        if request.version != MXC_EXTENSION_VERSION {
            return Err(MxcServiceError {
                code: MxcServiceErrorCode::UnsupportedVersion,
                message: format!(
                    "unsupported MXC extension version {}; expected {}",
                    request.version, MXC_EXTENSION_VERSION
                ),
            });
        }
        Err(MxcServiceError {
            code: MxcServiceErrorCode::UnsupportedAciAdapter,
            message: format!(
                "ACI adapter is blocked pending exact schema/fixture integration at revision {ACI_PINNED_REVISION}"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn models_exactly_twelve_requirements() {
        assert_eq!(MODELED_REQUIREMENTS.len(), 12);
    }

    #[test]
    fn unsupported_adapter_reports_typed_status() {
        let status = UnsupportedAciAdapter::status();
        assert_eq!(
            status,
            AciAdapterStatus::Unsupported {
                required_revision: ACI_PINNED_REVISION,
                reason: "ACI schemas/fixtures are not integrated in this repository",
            }
        );
    }

    #[test]
    fn unsupported_adapter_rejects_calls_with_explicit_error() {
        let adapter = UnsupportedAciAdapter;
        let result = adapter.call(MxcRequest {
            version: MXC_EXTENSION_VERSION,
            requirement: MxcRequirement::Ready,
        });
        assert_eq!(
            result.unwrap_err().code,
            MxcServiceErrorCode::UnsupportedAciAdapter
        );
    }
}
