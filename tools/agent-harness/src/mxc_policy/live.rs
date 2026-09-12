use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::report::PolicyHarnessOptions;
#[cfg(not(target_os = "linux"))]
use crate::scenarios::{
    PolicyLiveEvidence, run_live_policy_network_profile, run_live_policy_process_profiles,
};
#[cfg(not(target_os = "linux"))]
use crate::{HarnessMode, HarnessOptions};

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
    let mut profiles = BTreeMap::new();
    #[cfg(not(target_os = "linux"))]
    {
        let shared_profiles = run_live_policy_process_profiles(&HarnessOptions {
            backend: options.backend,
            mode: HarnessMode::LiveWhp,
            output_dir: options.output_dir.join("live-shared-evidence"),
            launch_overrides: Some(options.launch_overrides.clone()),
        });
        for id in [
            "filesystem-rw-ro",
            "process-shell",
            "proxy-environment",
            "control-lifecycle",
        ] {
            profiles.insert(
                id.to_string(),
                from_policy_evidence(
                    id,
                    shared_profiles
                        .get(id)
                        .cloned()
                        .unwrap_or(PolicyLiveEvidence {
                            positive_passed: false,
                            negative_passed: false,
                            blocked: true,
                            evidence: Vec::new(),
                            error: Some(format!("profile {id} did not run")),
                        }),
                ),
            );
        }
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
    }
    #[cfg(target_os = "linux")]
    for id in [
        "filesystem-rw-ro",
        "network-positive-negative",
        "process-shell",
        "proxy-environment",
        "control-lifecycle",
    ] {
        profiles.insert(
            id.to_string(),
            blocked(id, "live WHP policy profiles require Windows".to_string()),
        );
    }
    profiles
}

#[cfg(not(target_os = "linux"))]
fn from_policy_evidence(id: &str, result: PolicyLiveEvidence) -> LiveProfileResult {
    let profile_passed = result.positive_passed && result.negative_passed;
    LiveProfileResult {
        id: id.to_string(),
        status: if profile_passed {
            LiveProfileStatus::Pass
        } else if result.blocked {
            LiveProfileStatus::Blocked
        } else {
            LiveProfileStatus::Fail
        },
        positive_passed: result.positive_passed,
        negative_passed: result.negative_passed,
        evidence: result.evidence,
        error: result.error,
    }
}

#[cfg(target_os = "linux")]
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
