use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::report::PolicyHarnessOptions;
#[cfg(not(target_os = "linux"))]
use crate::scenarios::{
    PolicyLiveEvidence, run_live_policy_network_profile, run_live_policy_process_profiles,
};
use crate::{EvidenceCheckStatus, HarnessMode, HarnessOptions, ScenarioStatus, execute_harness};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveProfileStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveProfileResult {
    pub id: String,
    pub status: LiveProfileStatus,
    pub positive_passed: bool,
    pub negative_passed: bool,
    pub evidence: Vec<String>,
    pub error: Option<String>,
}

pub fn run_live_profiles(options: &PolicyHarnessOptions) -> BTreeMap<String, LiveProfileResult> {
    let canonical_output = options.output_dir.join("live-canonical-evidence");
    let canonical = execute_harness(HarnessOptions {
        backend: options.backend,
        mode: HarnessMode::LiveWhp,
        output_dir: canonical_output,
        launch_overrides: Some(options.launch_overrides.clone()),
    });
    let mut profiles = BTreeMap::new();
    match canonical {
        Err(error) => {
            for id in [
                "filesystem-rw-ro",
                "network-positive-negative",
                "process-shell",
                "proxy-environment",
            ] {
                profiles.insert(
                    id.to_string(),
                    blocked(id, format!("live WHP bootstrap failed: {error}")),
                );
            }
        }
        Ok(run) => {
            profiles.insert(
                "filesystem-rw-ro".to_string(),
                from_scenarios(
                    "filesystem-rw-ro",
                    &run,
                    &[9],
                    "req09 proves RW success, RO read plus write/metadata denial, undeclared sibling denial, raw-root hiding, and mapping validation",
                ),
            );
            #[cfg(not(target_os = "linux"))]
            profiles.insert(
                "network-positive-negative".to_string(),
                from_policy_evidence(
                    "network-positive-negative",
                    run_live_policy_network_profile(&HarnessOptions {
                        backend: options.backend,
                        mode: HarnessMode::LiveWhp,
                        output_dir: options.output_dir.join("live-network-evidence"),
                        launch_overrides: Some(options.launch_overrides.clone()),
                    }),
                ),
            );
            #[cfg(target_os = "linux")]
            profiles.insert(
                "network-positive-negative".to_string(),
                blocked(
                    "network-positive-negative",
                    "live WHP policy profiles require Windows".to_string(),
                ),
            );
            #[cfg(not(target_os = "linux"))]
            let process_profiles = run_live_policy_process_profiles(&HarnessOptions {
                backend: options.backend,
                mode: HarnessMode::LiveWhp,
                output_dir: options.output_dir.join("live-process-evidence"),
                launch_overrides: Some(options.launch_overrides.clone()),
            });
            #[cfg(not(target_os = "linux"))]
            for id in ["process-shell", "proxy-environment"] {
                profiles.insert(
                    id.to_string(),
                    from_policy_evidence(
                        id,
                        process_profiles
                            .get(id)
                            .cloned()
                            .unwrap_or(PolicyLiveEvidence {
                                passed: false,
                                evidence: Vec::new(),
                                error: Some(format!("profile {id} did not run")),
                            }),
                    ),
                );
            }
            #[cfg(target_os = "linux")]
            for id in ["process-shell", "proxy-environment"] {
                profiles.insert(
                    id.to_string(),
                    blocked(id, "live WHP policy profiles require Windows".to_string()),
                );
            }
        }
    }
    profiles
}

#[cfg(not(target_os = "linux"))]
fn from_policy_evidence(id: &str, result: PolicyLiveEvidence) -> LiveProfileResult {
    LiveProfileResult {
        id: id.to_string(),
        status: if result.passed {
            LiveProfileStatus::Pass
        } else {
            LiveProfileStatus::Fail
        },
        positive_passed: result.passed,
        negative_passed: result.passed,
        evidence: result.evidence,
        error: result.error,
    }
}

fn from_scenarios(
    id: &str,
    run: &crate::HarnessRun,
    requirements: &[u8],
    claim: &str,
) -> LiveProfileResult {
    let selected = run
        .report
        .scenarios
        .iter()
        .filter(|result| requirements.contains(&result.requirement_number))
        .collect::<Vec<_>>();
    let passed = selected.len() == requirements.len()
        && selected.iter().all(|result| {
            result.status == ScenarioStatus::Pass
                && result.check_status == EvidenceCheckStatus::Pass
        });
    let blocked = selected
        .iter()
        .any(|result| result.status == ScenarioStatus::Blocked);
    let mut evidence = vec![claim.to_string()];
    evidence.extend(selected.iter().flat_map(|result| {
        result
            .evidence
            .iter()
            .map(move |line| format!("req{:02}: {line}", result.requirement_number))
    }));
    LiveProfileResult {
        id: id.to_string(),
        status: if passed {
            LiveProfileStatus::Pass
        } else if blocked {
            LiveProfileStatus::Blocked
        } else {
            LiveProfileStatus::Fail
        },
        positive_passed: passed,
        negative_passed: passed,
        evidence,
        error: if passed {
            None
        } else {
            Some(
                selected
                    .iter()
                    .filter_map(|result| result.error.as_deref())
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        },
    }
}

fn blocked(id: &str, error: String) -> LiveProfileResult {
    LiveProfileResult {
        id: id.to_string(),
        status: LiveProfileStatus::Blocked,
        positive_passed: false,
        negative_passed: false,
        evidence: Vec::new(),
        error: Some(error),
    }
}
