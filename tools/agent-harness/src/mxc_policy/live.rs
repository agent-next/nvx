use std::collections::BTreeMap;

#[cfg(windows)]
use agent_protocol::messages::{ExecDisposition, TerminationOutcome};
use serde::{Deserialize, Serialize};

use super::NvxExecPolicy;
use super::report::PolicyHarnessOptions;
#[cfg(windows)]
use crate::scenarios::{PolicyExecLiveResult, run_live_execute_config_policy};
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveExecuteCleanup {
    pub shutdown_acknowledged: bool,
    pub channel_closed: bool,
    pub process_exited: bool,
    pub explicit_teardown_succeeded: bool,
    pub cleanup_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveExecuteEvidence {
    pub tier: String,
    pub exec_id: u32,
    #[cfg(windows)]
    pub disposition: ExecDisposition,
    #[cfg(not(windows))]
    pub disposition: String,
    #[cfg(windows)]
    pub termination: Option<TerminationOutcome>,
    #[cfg(not(windows))]
    pub termination: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub cleanup: LiveExecuteCleanup,
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

pub fn execute_live_config(
    options: &PolicyHarnessOptions,
    exec: NvxExecPolicy,
) -> Result<LiveExecuteEvidence, String> {
    #[cfg(windows)]
    {
        let run = run_live_execute_config_policy(
            &HarnessOptions {
                backend: options.backend,
                mode: HarnessMode::LiveWhp,
                output_dir: options.output_dir.join("live-execute-config"),
                launch_overrides: Some(options.launch_overrides.clone()),
            },
            exec,
        )?;
        Ok(from_execute_result(run))
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        let _ = exec;
        Err("live WHP policy profiles require Windows".to_string())
    }
}

#[cfg(windows)]
fn from_execute_result(result: PolicyExecLiveResult) -> LiveExecuteEvidence {
    LiveExecuteEvidence {
        tier: "live-whp".to_string(),
        exec_id: result.exec_id,
        #[cfg(windows)]
        disposition: result.disposition,
        #[cfg(not(windows))]
        disposition: format!("{:?}", result.disposition),
        #[cfg(windows)]
        termination: result.termination,
        #[cfg(not(windows))]
        termination: result.termination.map(|value| format!("{value:?}")),
        stdout: result.stdout,
        stderr: result.stderr,
        cleanup: LiveExecuteCleanup {
            shutdown_acknowledged: result.cleanup.shutdown_acknowledged,
            channel_closed: result.cleanup.channel_closed,
            process_exited: result.cleanup.process_exited,
            explicit_teardown_succeeded: result.cleanup.explicit_teardown_succeeded,
            cleanup_error: result.cleanup.cleanup_error,
        },
    }
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
