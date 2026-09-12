use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::launch::{
    LaunchArtifacts, LaunchOverrides, LaunchPlan, LaunchedVm, build_launch_plan,
    discover_artifacts, launch_whp_vm,
};

use super::{NvxPolicyPlan, PolicyError, adapt_policy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRunError {
    pub code: String,
    pub message: String,
}

impl core::fmt::Display for PolicyRunError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PolicyRunError {}

pub trait HostEffects {
    type Session;

    fn prepare_common_root(
        &mut self,
        plan: &NvxPolicyPlan,
        common_root: &Path,
    ) -> Result<(), PolicyRunError>;
    fn discover_artifacts(&mut self) -> Result<LaunchArtifacts, PolicyRunError>;
    fn build_launch_plan(
        &mut self,
        output_dir: &Path,
        artifacts: LaunchArtifacts,
    ) -> Result<LaunchPlan, PolicyRunError>;
    fn launch(&mut self, plan: LaunchPlan) -> Result<Self::Session, PolicyRunError>;
}

pub fn run_with_effects<E: HostEffects>(
    case_id: impl Into<String>,
    config: &Value,
    common_root: &Path,
    output_dir: &Path,
    effects: &mut E,
) -> Result<E::Session, PolicyExecutionError> {
    let plan = adapt_policy(case_id, config, common_root).map_err(PolicyExecutionError::Policy)?;
    effects
        .prepare_common_root(&plan, common_root)
        .map_err(PolicyExecutionError::Run)?;
    let artifacts = effects
        .discover_artifacts()
        .map_err(PolicyExecutionError::Run)?;
    let launch_plan = effects
        .build_launch_plan(output_dir, artifacts)
        .map_err(PolicyExecutionError::Run)?;
    effects
        .launch(launch_plan)
        .map_err(PolicyExecutionError::Run)
}

pub fn run_policy_production(
    case_id: impl Into<String>,
    config: &Value,
    common_root: &Path,
    output_dir: &Path,
    overrides: LaunchOverrides,
) -> Result<LaunchedVm, PolicyExecutionError> {
    let mut effects = ProductionHostEffects::new(output_dir.to_path_buf(), overrides);
    run_with_effects(case_id, config, common_root, output_dir, &mut effects)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyExecutionError {
    Policy(Vec<PolicyError>),
    Run(PolicyRunError),
}

impl core::fmt::Display for PolicyExecutionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy(errors) => write!(
                formatter,
                "policy rejected: {}",
                errors
                    .first()
                    .map(|error| error.message.as_str())
                    .unwrap_or("unknown policy error")
            ),
            Self::Run(error) => write!(formatter, "host effect failed: {error}"),
        }
    }
}

impl std::error::Error for PolicyExecutionError {}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct EffectCounters {
    pub root_preparations: usize,
    pub fixture_creations: usize,
    pub artifact_discoveries: usize,
    pub launch_plan_constructions: usize,
    pub process_launches: usize,
    pub output_artifact_creations: usize,
}

impl EffectCounters {
    pub fn is_zero(&self) -> bool {
        self.root_preparations == 0
            && self.fixture_creations == 0
            && self.artifact_discoveries == 0
            && self.launch_plan_constructions == 0
            && self.process_launches == 0
            && self.output_artifact_creations == 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct CountingHostEffects {
    counters: EffectCounters,
}

impl CountingHostEffects {
    pub fn counters(&self) -> &EffectCounters {
        &self.counters
    }
}

impl HostEffects for CountingHostEffects {
    type Session = ();

    fn prepare_common_root(
        &mut self,
        _plan: &NvxPolicyPlan,
        _common_root: &Path,
    ) -> Result<(), PolicyRunError> {
        self.counters.root_preparations += 1;
        self.counters.fixture_creations += 1;
        Ok(())
    }

    fn discover_artifacts(&mut self) -> Result<LaunchArtifacts, PolicyRunError> {
        self.counters.artifact_discoveries += 1;
        Ok(LaunchArtifacts {
            openvmm_exe: PathBuf::from("counting-openvmm"),
            kernel: PathBuf::from("counting-kernel"),
            mxc_initramfs: PathBuf::from("counting-initramfs"),
            common_root: PathBuf::from("counting-common-root"),
            portable_network: None,
        })
    }

    fn build_launch_plan(
        &mut self,
        output_dir: &Path,
        artifacts: LaunchArtifacts,
    ) -> Result<LaunchPlan, PolicyRunError> {
        self.counters.launch_plan_constructions += 1;
        Ok(build_launch_plan(output_dir, artifacts))
    }

    fn launch(&mut self, _plan: LaunchPlan) -> Result<Self::Session, PolicyRunError> {
        self.counters.process_launches += 1;
        self.counters.output_artifact_creations += 1;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ProductionHostEffects {
    output_dir: PathBuf,
    overrides: LaunchOverrides,
}

impl ProductionHostEffects {
    pub fn new(output_dir: PathBuf, overrides: LaunchOverrides) -> Self {
        Self {
            output_dir,
            overrides,
        }
    }
}

impl HostEffects for ProductionHostEffects {
    type Session = LaunchedVm;

    fn prepare_common_root(
        &mut self,
        plan: &NvxPolicyPlan,
        common_root: &Path,
    ) -> Result<(), PolicyRunError> {
        if let Some(provision) = &plan.provision
            && provision.common_root != common_root
        {
            return Err(PolicyRunError {
                code: "common_root_conflict".to_string(),
                message: "adapted provision root differs from execution root".to_string(),
            });
        }
        if let Some(configured_root) = self.overrides.common_root.as_deref()
            && configured_root != common_root
        {
            return Err(PolicyRunError {
                code: "common_root_conflict".to_string(),
                message: format!(
                    "policy root `{}` does not match launch root `{}`",
                    common_root.display(),
                    configured_root.display()
                ),
            });
        }
        self.overrides.common_root = Some(common_root.to_path_buf());
        std::fs::create_dir_all(common_root).map_err(|error| PolicyRunError {
            code: "prepare_common_root".to_string(),
            message: format!("failed to prepare `{}`: {error}", common_root.display()),
        })
    }

    fn discover_artifacts(&mut self) -> Result<LaunchArtifacts, PolicyRunError> {
        discover_artifacts(&self.output_dir, &self.overrides).map_err(|missing| PolicyRunError {
            code: "missing_prerequisite".to_string(),
            message: format!(
                "{} `{}`: {}",
                missing.field,
                missing.path.display(),
                missing.reason
            ),
        })
    }

    fn build_launch_plan(
        &mut self,
        output_dir: &Path,
        artifacts: LaunchArtifacts,
    ) -> Result<LaunchPlan, PolicyRunError> {
        Ok(build_launch_plan(output_dir, artifacts))
    }

    fn launch(&mut self, plan: LaunchPlan) -> Result<Self::Session, PolicyRunError> {
        launch_whp_vm(plan).map_err(|message| PolicyRunError {
            code: "launch_failed".to_string(),
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::{CountingHostEffects, EffectCounters, PolicyExecutionError, run_with_effects};

    #[test]
    fn rejected_policy_performs_zero_host_effects_and_creates_no_output() {
        let uniqueness = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let output_dir = std::env::temp_dir().join(format!("nvx-rejected-policy-{uniqueness}"));
        assert!(!output_dir.exists());
        let common_root = output_dir.join("common");
        let config = json!({
            "version": "0.9.0-dev",
            "containment": "vm",
            "phase": "provision",
            "telemetry": {"enabled": true}
        });
        let mut effects = CountingHostEffects::default();

        let result = run_with_effects(
            "rejected.telemetry",
            &config,
            &common_root,
            &output_dir,
            &mut effects,
        );

        assert!(matches!(result, Err(PolicyExecutionError::Policy(_))));
        assert_eq!(effects.counters(), &EffectCounters::default());
        assert!(!output_dir.exists());
    }

    #[test]
    fn accepted_policy_crosses_each_counted_boundary_once() {
        let output_dir = std::env::temp_dir().join("nvx-counted-policy-output");
        let common_root = std::env::temp_dir().join("nvx-counted-policy-common");
        let config = json!({
            "version": "0.9.0-dev",
            "containment": "vm",
            "phase": "provision"
        });
        let mut effects = CountingHostEffects::default();
        run_with_effects(
            "accepted.provision",
            &config,
            &common_root,
            &output_dir,
            &mut effects,
        )
        .expect("counting effects succeed");
        assert_eq!(
            effects.counters(),
            &EffectCounters {
                root_preparations: 1,
                fixture_creations: 1,
                artifact_discoveries: 1,
                launch_plan_constructions: 1,
                process_launches: 1,
                output_artifact_creations: 1,
            }
        );
    }
}
