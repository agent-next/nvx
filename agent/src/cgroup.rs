// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Cgroup v2 layout plan and validation helpers.

use ::std::path::PathBuf;

use crate::error::{AgentError, Result};

pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const AGENT_CGROUP_NAME: &str = "nvx.agent";
pub const WORKLOAD_CGROUP_NAME: &str = "nvx.workload";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupPlan {
    pub root: PathBuf,
    pub agent: PathBuf,
    pub workload: PathBuf,
}

impl CgroupPlan {
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            agent: root.join(AGENT_CGROUP_NAME),
            workload: root.join(WORKLOAD_CGROUP_NAME),
            root,
        }
    }
}

pub fn verify_cgroup_v2_support(plan: &CgroupPlan) -> Result<()> {
    let controllers = plan.root.join("cgroup.controllers");
    if !controllers.exists() {
        return Err(AgentError::isolation(format!(
            "cgroup v2 hierarchy is required at {}",
            plan.root.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_plan_layout_is_deterministic() {
        let plan = CgroupPlan::under("/sys/fs/cgroup");
        assert_eq!(
            plan.agent,
            ::std::path::Path::new("/sys/fs/cgroup/nvx.agent")
        );
        assert_eq!(
            plan.workload,
            ::std::path::Path::new("/sys/fs/cgroup/nvx.workload")
        );
    }

    #[test]
    fn cgroup_support_check_fails_closed_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let plan = CgroupPlan::under(temp.path());
        let error = verify_cgroup_v2_support(&plan).expect_err("missing controllers");
        assert!(format!("{error}").contains("cgroup v2 hierarchy is required"));
    }
}
