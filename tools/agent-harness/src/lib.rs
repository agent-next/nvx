use ::std::collections::BTreeMap;
use ::std::process::ExitCode;

use ::agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
use ::agent_protocol::messages::{LaunchIdentity, NetworkMode, NetworkStatus, SERVICE_IDENTITY};
use ::agent_protocol::mxc_extension::{
    AciAdapterStatus, MODELED_REQUIREMENTS, MxcRequirement, UnsupportedAciAdapter,
};
use ::agent_protocol::service::{
    AuthenticateChannelRequest, ConfigureSessionRequest, FilesystemStatus, LaunchBinding,
    MxcControlService, ServiceErrorCode, SessionConfiguration, WaitReadyRequest,
};
use ::agent_protocol::state::PROTOCOL_VERSION;
use ::serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementStatus {
    Pass,
    Fail,
    Blocked,
    NotImplemented,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequirementResult {
    pub name: String,
    pub requirement: MxcRequirement,
    pub status: RequirementStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceReadiness {
    Ready,
    NotReady,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterState {
    pub kind: String,
    pub status: RequirementStatus,
    pub required_revision: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessReport {
    pub phase: String,
    pub service_readiness: ServiceReadiness,
    pub adapter: AdapterState,
    pub requirements: Vec<RequirementResult>,
}

fn launch_identity() -> LaunchIdentity {
    LaunchIdentity {
        generation: 7,
        nonce: [7; 16],
    }
}

fn launch_binding() -> LaunchBinding {
    LaunchBinding {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
    }
}

fn session_configuration() -> SessionConfiguration {
    SessionConfiguration {
        root: CanonicalHostMappingRoot::parse("/sandbox".to_string()).expect("root"),
        mappings: vec![ChildMapping {
            child: RelativeChildPath::parse("runtime".to_string()).expect("child"),
            access: AccessMode::ReadOnly,
        }],
        containment: MappingContainmentPolicy {
            symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        },
        labels: vec!["runtime".to_string()],
        attributes: BTreeMap::from([("profile".to_string(), "mxc".to_string())]),
        filesystem: FilesystemStatus {
            rootfs_ready: true,
            detail: "sandbox layers mounted".to_string(),
        },
        network: NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some("10.0.0.2/24".to_string()),
        },
    }
}

fn wait_ready_request() -> WaitReadyRequest {
    WaitReadyRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
    }
}

fn configure_request(idempotent_replay: bool) -> ConfigureSessionRequest {
    ConfigureSessionRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
        idempotent_replay,
        configuration: session_configuration(),
    }
}

fn authenticate(service: &mut MxcControlService) {
    service
        .authenticate_channel(
            AuthenticateChannelRequest {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: launch_identity(),
                channel_generation: 44,
                capability_proof: [7; 32],
            },
            1,
            session_configuration().network.clone(),
        )
        .expect("authenticate");
}

fn run_launch_bound_readiness() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    let capabilities = service.get_capabilities();
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");

    let wrong_nonce = WaitReadyRequest {
        launch: LaunchIdentity {
            generation: 7,
            nonce: [1; 16],
        },
        ..wait_ready_request()
    };
    let wrong_nonce_rejected = matches!(
        service.wait_ready(wrong_nonce).map(|_| ()),
        Err(error) if error.code == ServiceErrorCode::LaunchNonceMismatch
    );
    let first = service.wait_ready(wait_ready_request());
    let second = service.wait_ready(wait_ready_request());
    let health = service.health();
    let unavailable_operations = capabilities
        .unavailable_operations
        .iter()
        .map(|entry| entry.operation.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let passed = wrong_nonce_rejected
        && capabilities.protocol_version == PROTOCOL_VERSION
        && capabilities.available_operations
            == vec![
                "GetCapabilities".to_string(),
                "AuthenticateChannel".to_string(),
                "ConfigureSession".to_string(),
                "WaitReady".to_string(),
                "Health".to_string(),
            ]
        && unavailable_operations
            == std::collections::BTreeSet::from([
                "Exec", "Streams", "Cancel", "Quiesce", "Resume", "Shutdown",
            ])
        && capabilities
            .unavailable_operations
            .iter()
            .all(|entry| !entry.capability_flag.is_empty() && !entry.reason.is_empty())
        && first.is_ok()
        && second.is_ok()
        && first == second
        && health.configured
        && health
            .filesystem
            .as_ref()
            .is_some_and(|status| status.rootfs_ready);
    RequirementResult {
        name: MxcRequirement::Ready.name().to_string(),
        requirement: MxcRequirement::Ready,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "WaitReady is launch-bound to nonce/version/channel generation and GetCapabilities truthfully reports the phase-0 operational slice.".to_string()
        } else {
            "WaitReady launch binding, level-trigger behavior, or capability truthfulness failed."
                .to_string()
        },
    }
}

fn run_immutable_configuration() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("first configure");
    let same_without_idempotent = service.configure_session(configure_request(false));
    let same_with_idempotent = service.configure_session(configure_request(true));
    let mut conflicting_request = configure_request(true);
    conflicting_request.configuration.filesystem.detail = "changed".to_string();
    let conflicting = service.configure_session(conflicting_request);
    let passed = matches!(
        same_without_idempotent.map(|_| ()),
        Err(error) if error.code == ServiceErrorCode::ConfigurationConflict
    ) && same_with_idempotent.is_ok()
        && matches!(
            conflicting.map(|_| ()),
            Err(error) if error.code == ServiceErrorCode::ConfigurationConflict
        );
    RequirementResult {
        name: MxcRequirement::Bootstrap.name().to_string(),
        requirement: MxcRequirement::Bootstrap,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "ConfigureSession applies once; non-idempotent replay/conflict is rejected.".to_string()
        } else {
            "Immutable ConfigureSession rules failed.".to_string()
        },
    }
}

fn run_health_probe() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    let before = service.health();
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");
    let after = service.health();
    let passed = !before.launch_admitted
        && !before.configured
        && after.launch_admitted
        && after.configured
        && after.network.is_some()
        && after.filesystem.is_some();
    RequirementResult {
        name: MxcRequirement::Probe.name().to_string(),
        requirement: MxcRequirement::Probe,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Health reports launch admission plus filesystem/network readiness snapshots."
                .to_string()
        } else {
            "Health readiness snapshot behavior failed.".to_string()
        },
    }
}

fn unsupported_result(requirement: MxcRequirement) -> RequirementResult {
    RequirementResult {
        name: requirement.name().to_string(),
        requirement,
        status: RequirementStatus::NotImplemented,
        reason: "Operational slice intentionally excludes this runtime requirement.".to_string(),
    }
}

pub fn phase0_report() -> HarnessReport {
    let adapter = match UnsupportedAciAdapter::status() {
        AciAdapterStatus::Unsupported {
            required_revision,
            reason,
        } => AdapterState {
            kind: "aci".to_string(),
            status: RequirementStatus::Blocked,
            required_revision: required_revision.to_string(),
            reason: reason.to_string(),
        },
    };

    let readiness = run_launch_bound_readiness();
    let bootstrap = run_immutable_configuration();
    let probe = run_health_probe();

    let mut requirements = Vec::with_capacity(MODELED_REQUIREMENTS.len());
    for requirement in MODELED_REQUIREMENTS {
        if requirement == MxcRequirement::Ready {
            requirements.push(readiness.clone());
        } else if requirement == MxcRequirement::Bootstrap {
            requirements.push(bootstrap.clone());
        } else if requirement == MxcRequirement::Probe {
            requirements.push(probe.clone());
        } else {
            requirements.push(unsupported_result(requirement));
        }
    }

    let service_readiness = if requirements
        .iter()
        .any(|result| result.status != RequirementStatus::Pass)
    {
        ServiceReadiness::NotReady
    } else {
        ServiceReadiness::Ready
    };

    HarnessReport {
        phase: "phase0-operational-slice".to_string(),
        service_readiness,
        adapter,
        requirements,
    }
}

pub fn is_passing_report(report: &HarnessReport) -> bool {
    if report.service_readiness != ServiceReadiness::Ready {
        return false;
    }
    if report.requirements.len() != MODELED_REQUIREMENTS.len() {
        return false;
    }
    report
        .requirements
        .iter()
        .all(|result| result.status == RequirementStatus::Pass)
}

pub fn report_exit_code(report: &HarnessReport) -> ExitCode {
    if is_passing_report(report) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::std::collections::BTreeSet;

    #[test]
    fn phase0_report_has_exactly_twelve_named_results() {
        let report = phase0_report();
        assert_eq!(report.requirements.len(), 12);
        let names: BTreeSet<_> = report
            .requirements
            .iter()
            .map(|result| result.name.as_str())
            .collect();
        let expected_names: BTreeSet<_> = MODELED_REQUIREMENTS
            .iter()
            .map(|requirement| requirement.name())
            .collect();
        assert_eq!(names, expected_names);
    }

    #[test]
    fn phase0_report_remains_nonzero_until_all_requirements_pass() {
        let report = phase0_report();
        assert_eq!(report.service_readiness, ServiceReadiness::NotReady);
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn harness_executes_real_launch_configure_and_probe_scenarios() {
        let report = phase0_report();
        let readiness = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Ready)
            .unwrap();
        assert_eq!(readiness.status, RequirementStatus::Pass);

        let bootstrap = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Bootstrap)
            .unwrap();
        assert_eq!(bootstrap.status, RequirementStatus::Pass);

        let probe = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Probe)
            .unwrap();
        assert_eq!(probe.status, RequirementStatus::Pass);
    }
}
