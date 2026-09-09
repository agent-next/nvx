// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Immutable launch/session configuration for the guest agent.

use ::agent_protocol::{
    CanonicalHostMappingRoot, ChildMapping, LaunchIdentity, NetworkMode, WorkloadIdentityStatus,
    validate_mapping_set,
};

use crate::error::{AgentError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestMountRoot(String);

impl GuestMountRoot {
    pub fn parse(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(AgentError::config("guest mount root is empty"));
        }
        if !value.starts_with('/') {
            return Err(AgentError::config(format!(
                "guest mount root must be an absolute path: {value}"
            )));
        }
        if value.contains('\\') {
            return Err(AgentError::config(format!(
                "guest mount root must be a canonical Unix path: {value}"
            )));
        }
        for segment in value.trim_start_matches('/').split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(AgentError::config(format!(
                    "guest mount root must be canonical and must not contain traversal components: {value}"
                )));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionConfiguration {
    pub launch: LaunchIdentity,
    pub canonical_host_root: CanonicalHostMappingRoot,
    pub guest_mount_root: GuestMountRoot,
    pub mappings: Vec<ChildMapping>,
    pub network_mode: NetworkMode,
    pub workload_identity: WorkloadIdentityStatus,
}

impl SessionConfiguration {
    pub fn new(
        launch: LaunchIdentity,
        canonical_host_root: CanonicalHostMappingRoot,
        guest_mount_root: GuestMountRoot,
        mappings: Vec<ChildMapping>,
        network_mode: NetworkMode,
        workload_identity: WorkloadIdentityStatus,
    ) -> Result<Self> {
        validate_mapping_set(&mappings)
            .map_err(|error| AgentError::config(format!("invalid mapping set: {error}")))?;
        if workload_identity != WorkloadIdentityStatus::mxc_fixed() {
            return Err(AgentError::config(format!(
                "workload identity must be fixed to mxc: expected {:?}, got {:?}",
                WorkloadIdentityStatus::mxc_fixed(),
                workload_identity
            )));
        }
        Ok(Self {
            launch,
            canonical_host_root,
            guest_mount_root,
            mappings,
            network_mode,
            workload_identity,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionConfigurationGate {
    sealed: Option<SessionConfiguration>,
}

impl SessionConfigurationGate {
    pub fn new() -> Self {
        Self { sealed: None }
    }

    pub fn apply_once(&mut self, configuration: SessionConfiguration) -> Result<()> {
        if self.sealed.is_some() {
            return Err(AgentError::config(
                "configuration was already applied and is immutable for this launch",
            ));
        }
        self.sealed = Some(configuration);
        Ok(())
    }

    pub fn sealed(&self) -> Option<&SessionConfiguration> {
        self.sealed.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use ::agent_protocol::{AccessMode, ChildMapping, RelativeChildPath};

    use super::*;

    fn mapping(child: &str, access: AccessMode) -> ChildMapping {
        ChildMapping {
            child: RelativeChildPath::parse(child.to_string()).expect("child path"),
            access,
        }
    }

    fn launch() -> LaunchIdentity {
        LaunchIdentity {
            generation: 9,
            nonce: [7; 16],
        }
    }

    #[test]
    fn guest_mount_root_must_be_absolute_and_canonical() {
        assert!(GuestMountRoot::parse("/mnt/virtiofs".to_string()).is_ok());
        assert!(GuestMountRoot::parse("mnt/virtiofs".to_string()).is_err());
        assert!(GuestMountRoot::parse("/mnt/../virtiofs".to_string()).is_err());
    }

    #[test]
    fn session_configuration_reuses_protocol_mapping_validation() {
        let error = SessionConfiguration::new(
            launch(),
            CanonicalHostMappingRoot::parse("/workspace".to_string()).expect("root"),
            GuestMountRoot::parse("/mnt/virtiofs".to_string()).expect("guest root"),
            vec![
                mapping("work", AccessMode::ReadOnly),
                mapping("work/bin", AccessMode::ReadWrite),
            ],
            NetworkMode::NoNic,
            WorkloadIdentityStatus::mxc_fixed(),
        )
        .expect_err("ancestor overlap should fail");
        assert!(format!("{error}").contains("invalid mapping set"));
    }

    #[test]
    fn session_configuration_requires_fixed_mxc_identity() {
        let mut identity = WorkloadIdentityStatus::mxc_fixed();
        identity.uid += 1;
        let error = SessionConfiguration::new(
            launch(),
            CanonicalHostMappingRoot::parse("/workspace".to_string()).expect("root"),
            GuestMountRoot::parse("/mnt/virtiofs".to_string()).expect("guest root"),
            vec![mapping("work", AccessMode::ReadOnly)],
            NetworkMode::PortableNetwork,
            identity,
        )
        .expect_err("identity mismatch");
        assert!(format!("{error}").contains("must be fixed to mxc"));
    }

    #[test]
    fn gate_accepts_single_configuration_and_then_seals() {
        let mut gate = SessionConfigurationGate::new();
        let first = SessionConfiguration::new(
            launch(),
            CanonicalHostMappingRoot::parse("/workspace".to_string()).expect("root"),
            GuestMountRoot::parse("/mnt/virtiofs".to_string()).expect("guest root"),
            vec![mapping("work", AccessMode::ReadWrite)],
            NetworkMode::NoNic,
            WorkloadIdentityStatus::mxc_fixed(),
        )
        .expect("config");
        gate.apply_once(first).expect("first apply");
        assert!(gate.sealed().is_some());

        let second = SessionConfiguration::new(
            launch(),
            CanonicalHostMappingRoot::parse("/workspace".to_string()).expect("root"),
            GuestMountRoot::parse("/mnt/virtiofs".to_string()).expect("guest root"),
            vec![mapping("other", AccessMode::ReadOnly)],
            NetworkMode::NoNic,
            WorkloadIdentityStatus::mxc_fixed(),
        )
        .expect("config");
        let error = gate
            .apply_once(second)
            .expect_err("configuration should be immutable");
        assert!(format!("{error}").contains("already applied"));
    }
}
