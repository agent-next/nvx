use ::std::process::ExitCode;

use ::agent_protocol::mxc_extension::{
    AciAdapterStatus, MODELED_REQUIREMENTS, MxcRequirement, UnsupportedAciAdapter,
};
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

fn phase0_requirement_result(requirement: MxcRequirement) -> RequirementResult {
    match requirement {
        MxcRequirement::Ready => RequirementResult {
            name: requirement.name().to_string(),
            requirement,
            status: RequirementStatus::Blocked,
            reason: "MXC readiness is blocked because the ACI adapter is unsupported in Phase 0."
                .to_string(),
        },
        _ => RequirementResult {
            name: requirement.name().to_string(),
            requirement,
            status: RequirementStatus::NotImplemented,
            reason:
                "Phase 0 delivers protocol/build scaffolding only; runtime operation is not implemented."
                    .to_string(),
        },
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

    HarnessReport {
        phase: "phase0".to_string(),
        service_readiness: ServiceReadiness::NotReady,
        adapter,
        requirements: MODELED_REQUIREMENTS
            .into_iter()
            .map(phase0_requirement_result)
            .collect(),
    }
}

pub fn is_passing_report(report: &HarnessReport) -> bool {
    if report.service_readiness != ServiceReadiness::Ready {
        return false;
    }

    if report.requirements.len() != MODELED_REQUIREMENTS.len() {
        return false;
    }

    if report
        .requirements
        .iter()
        .any(|result| result.status != RequirementStatus::Pass)
    {
        return false;
    }

    if report
        .requirements
        .iter()
        .any(|result| !MODELED_REQUIREMENTS.contains(&result.requirement))
    {
        return false;
    }

    for requirement in MODELED_REQUIREMENTS {
        let mut matches = report
            .requirements
            .iter()
            .filter(|result| result.requirement == requirement);
        let Some(result) = matches.next() else {
            return false;
        };
        if matches.next().is_some() {
            return false;
        }
        if result.name != requirement.name() {
            return false;
        }
    }

    true
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

    fn ready_report_with_all_passes() -> HarnessReport {
        HarnessReport {
            phase: "phaseX".to_string(),
            service_readiness: ServiceReadiness::Ready,
            adapter: AdapterState {
                kind: "aci".to_string(),
                status: RequirementStatus::Pass,
                required_revision: "rev".to_string(),
                reason: "ready".to_string(),
            },
            requirements: MODELED_REQUIREMENTS
                .iter()
                .copied()
                .map(|requirement| RequirementResult {
                    name: requirement.name().to_string(),
                    requirement,
                    status: RequirementStatus::Pass,
                    reason: "ok".to_string(),
                })
                .collect(),
        }
    }

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
    fn phase0_report_is_not_ready_and_exits_nonzero() {
        let report = phase0_report();
        assert_eq!(report.phase, "phase0");
        assert_eq!(report.service_readiness, ServiceReadiness::NotReady);
        assert_eq!(report.adapter.status, RequirementStatus::Blocked);
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn phase0_report_never_marks_runtime_requirements_as_pass() {
        let report = phase0_report();
        assert!(
            report
                .requirements
                .iter()
                .all(|result| result.status != RequirementStatus::Pass)
        );
    }

    #[test]
    fn success_gate_rejects_empty_requirements() {
        let mut report = ready_report_with_all_passes();
        report.requirements.clear();
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn success_gate_rejects_subset_requirements() {
        let mut report = ready_report_with_all_passes();
        report.requirements.truncate(3);
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn success_gate_rejects_duplicate_requirement_identity() {
        let mut report = ready_report_with_all_passes();
        report.requirements[1] = report.requirements[0].clone();
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn success_gate_rejects_missing_one_requirement() {
        let mut report = ready_report_with_all_passes();
        report.requirements.pop();
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn success_gate_rejects_name_mismatch() {
        let mut report = ready_report_with_all_passes();
        report.requirements[0].name = "wrong-stable-name".to_string();
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn success_gate_accepts_exactly_all_modeled_passes() {
        let report = ready_report_with_all_passes();
        assert_eq!(report_exit_code(&report), ExitCode::SUCCESS);
    }
}
