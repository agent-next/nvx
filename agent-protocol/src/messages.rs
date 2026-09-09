// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};

use crate::mapping::{CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy};

pub const SERVICE_IDENTITY: &str = "nvx.mxc.agent.v1";
pub const WORKLOAD_USER_MXC: &str = "mxc";
pub const WORKLOAD_GROUP_MXC: &str = "mxc";
pub const WORKLOAD_UID_MXC: u32 = 1000;
pub const WORKLOAD_GID_MXC: u32 = 1000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchIdentity {
    pub generation: u64,
    pub nonce: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityProofMaterial([u8; 32]);

impl CapabilityProofMaterial {
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl TryFrom<Vec<u8>> for CapabilityProofMaterial {
    type Error = ProtocolErrorDetail;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let len = value.len();
        let bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| ProtocolErrorDetail::capability_proof_length(len))?;
        Ok(Self(bytes))
    }
}

impl Serialize for CapabilityProofMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityProofMaterial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HostControlMessage {
    #[serde(rename_all = "camelCase")]
    HostHello {
        service: String,
        protocol_version: u32,
        launch: LaunchIdentity,
        capability_proof: CapabilityProofMaterial,
    },
    #[serde(rename_all = "camelCase")]
    Configure {
        launch: LaunchIdentity,
        root: CanonicalHostMappingRoot,
        mappings: Vec<ChildMapping>,
        containment: MappingContainmentPolicy,
    },
    #[serde(rename_all = "camelCase")]
    CreateProcess {
        exec_id: u32,
        argv: Vec<String>,
        cwd: Option<String>,
        env: Vec<String>,
        timeout_ms: Option<u64>,
    },
    Health,
    Quiesce,
    Resume,
    #[serde(rename_all = "camelCase")]
    Shutdown {
        grace_timeout_ms: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AgentControlMessage {
    #[serde(rename_all = "camelCase")]
    Ready {
        launch: LaunchIdentity,
        status: ReadyStatus,
    },
    Error(ProtocolErrorDetail),
    Health(HealthStatus),
    Quiesced,
    Resumed,
    ShuttingDown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StreamName {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadyStatus {
    pub service: String,
    pub protocol_version: u32,
    pub build: BuildStatus,
    pub network: NetworkStatus,
    pub isolation: IsolationStatus,
    pub workload_identity: WorkloadIdentityStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildStatus {
    pub agent_version: String,
    pub kernel_release: String,
    pub profile: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub mode: NetworkMode,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkMode {
    NoNic,
    PortableNetwork,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsolationStatus {
    pub pid_namespace: bool,
    pub mount_namespace: bool,
    pub uts_namespace: bool,
    pub ipc_namespace: bool,
    pub private_proc: bool,
    pub private_dev: bool,
    pub private_devpts: bool,
    pub private_shm: bool,
    pub read_only_sys: bool,
    pub capabilities_dropped: bool,
    pub no_new_privs: bool,
    pub cgroup_separation: bool,
    pub orphan_reaping: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadIdentityStatus {
    pub user: String,
    pub group: String,
    pub uid: u32,
    pub gid: u32,
}

impl WorkloadIdentityStatus {
    pub fn mxc_fixed() -> Self {
        Self {
            user: WORKLOAD_USER_MXC.to_string(),
            group: WORKLOAD_GROUP_MXC.to_string(),
            uid: WORKLOAD_UID_MXC,
            gid: WORKLOAD_GID_MXC,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatus {
    pub quiesced: bool,
    pub launch_admitted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolErrorCode {
    UnsupportedService,
    UnsupportedProtocolVersion,
    CapabilityProofLength,
    LaunchGenerationConflict,
    CleanupInProgress,
    ConfigureAlreadyApplied,
    ConfigureAfterExec,
    InvalidMappingPath,
    MappingConflict,
    ActiveExecExists,
    ExecIdReusedInGeneration,
    UnknownExecId,
    StreamSequenceMismatch,
    StreamAlreadyClosed,
    MissingTerminalPrerequisites,
    ChannelAuthenticationRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolErrorDetail {
    pub code: ProtocolErrorCode,
    pub message: String,
}

impl ProtocolErrorDetail {
    pub fn capability_proof_length(actual: usize) -> Self {
        Self {
            code: ProtocolErrorCode::CapabilityProofLength,
            message: format!("capability proof must be 32 bytes, got {actual}"),
        }
    }
}

impl core::fmt::Display for ProtocolErrorDetail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_and_capability_length_are_pinned() {
        assert_eq!(SERVICE_IDENTITY, "nvx.mxc.agent.v1");
        assert!(CapabilityProofMaterial::try_from(vec![0; 32]).is_ok());
        assert!(CapabilityProofMaterial::try_from(vec![0; 31]).is_err());
    }
}
