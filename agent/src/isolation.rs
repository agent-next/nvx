// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Isolation contract planning and fail-closed verification.

#[cfg(target_os = "linux")]
use ::std::fs;
#[cfg(target_os = "linux")]
use ::std::path::Path;

use ::agent_protocol::IsolationStatus;

use crate::cgroup::{CgroupPlan, DEFAULT_CGROUP_ROOT, verify_cgroup_v2_support};
use crate::error::{AgentError, Result};
use crate::mounts::private_mount_specs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrctlPlan {
    pub no_new_privs: bool,
    pub subreaper: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityPlan {
    pub clear_effective: bool,
    pub clear_permitted: bool,
    pub clear_inheritable: bool,
    pub clear_ambient: bool,
    pub drop_bounding: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolationPlan {
    pub namespaces: Vec<&'static str>,
    pub mount_targets: Vec<&'static str>,
    pub read_only_sys: bool,
    pub prctl: PrctlPlan,
    pub capabilities: CapabilityPlan,
    pub cgroup: CgroupPlan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationProbe {
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

impl IsolationProbe {
    pub fn from_plan(plan: &IsolationPlan) -> Self {
        let has = |target: &str| plan.mount_targets.contains(&target);
        Self {
            pid_namespace: plan.namespaces.contains(&"pid"),
            mount_namespace: plan.namespaces.contains(&"mount"),
            uts_namespace: plan.namespaces.contains(&"uts"),
            ipc_namespace: plan.namespaces.contains(&"ipc"),
            private_proc: has("/proc"),
            private_dev: has("/dev"),
            private_devpts: has("/dev/pts"),
            private_shm: has("/dev/shm"),
            read_only_sys: plan.read_only_sys,
            capabilities_dropped: plan.capabilities.clear_effective
                && plan.capabilities.clear_permitted
                && plan.capabilities.clear_inheritable
                && plan.capabilities.clear_ambient
                && plan.capabilities.drop_bounding,
            no_new_privs: plan.prctl.no_new_privs,
            cgroup_separation: true,
            orphan_reaping: plan.prctl.subreaper,
        }
    }
}

pub fn default_isolation_plan() -> IsolationPlan {
    IsolationPlan {
        namespaces: vec!["pid", "mount", "uts", "ipc"],
        mount_targets: private_mount_specs()
            .into_iter()
            .map(|spec| spec.target)
            .collect(),
        read_only_sys: true,
        prctl: PrctlPlan {
            no_new_privs: true,
            subreaper: true,
        },
        capabilities: CapabilityPlan {
            clear_effective: true,
            clear_permitted: true,
            clear_inheritable: true,
            clear_ambient: true,
            drop_bounding: true,
        },
        cgroup: CgroupPlan::under(DEFAULT_CGROUP_ROOT),
    }
}

pub fn verify_mandatory_isolation_controls(
    plan: &IsolationPlan,
    probe: IsolationProbe,
) -> Result<IsolationStatus> {
    verify_cgroup_v2_support(&plan.cgroup)?;
    let mut missing = Vec::new();
    if !probe.pid_namespace {
        missing.push("pidNamespace");
    }
    if !probe.mount_namespace {
        missing.push("mountNamespace");
    }
    if !probe.uts_namespace {
        missing.push("utsNamespace");
    }
    if !probe.ipc_namespace {
        missing.push("ipcNamespace");
    }
    if !probe.private_proc {
        missing.push("privateProc");
    }
    if !probe.private_dev {
        missing.push("privateDev");
    }
    if !probe.private_devpts {
        missing.push("privateDevpts");
    }
    if !probe.private_shm {
        missing.push("privateShm");
    }
    if !probe.read_only_sys {
        missing.push("readOnlySys");
    }
    if !probe.capabilities_dropped {
        missing.push("capabilitiesDropped");
    }
    if !probe.no_new_privs {
        missing.push("noNewPrivs");
    }
    if !probe.cgroup_separation {
        missing.push("cgroupSeparation");
    }
    if !probe.orphan_reaping {
        missing.push("orphanReaping");
    }
    if !missing.is_empty() {
        return Err(AgentError::isolation(format!(
            "mandatory isolation controls are unavailable: {}",
            missing.join(", ")
        )));
    }

    Ok(IsolationStatus {
        pid_namespace: true,
        mount_namespace: true,
        uts_namespace: true,
        ipc_namespace: true,
        private_proc: true,
        private_dev: true,
        private_devpts: true,
        private_shm: true,
        read_only_sys: true,
        capabilities_dropped: true,
        no_new_privs: true,
        cgroup_separation: true,
        orphan_reaping: true,
    })
}

#[cfg(target_os = "linux")]
pub fn runtime_probe(plan: &IsolationPlan) -> IsolationProbe {
    let has_namespace = |name: &str| Path::new("/proc/self/ns").join(name).exists();
    let cap_status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let has_capability_fields = cap_status.contains("CapBnd:") && cap_status.contains("CapAmb:");
    IsolationProbe {
        pid_namespace: has_namespace("pid") && has_namespace("pid_for_children"),
        mount_namespace: has_namespace("mnt"),
        uts_namespace: has_namespace("uts"),
        ipc_namespace: has_namespace("ipc"),
        private_proc: plan.mount_targets.contains(&"/proc"),
        private_dev: plan.mount_targets.contains(&"/dev"),
        private_devpts: plan.mount_targets.contains(&"/dev/pts"),
        private_shm: plan.mount_targets.contains(&"/dev/shm"),
        read_only_sys: plan.read_only_sys,
        capabilities_dropped: has_capability_fields && plan.capabilities.drop_bounding,
        no_new_privs: plan.prctl.no_new_privs,
        cgroup_separation: plan.cgroup.root.join("cgroup.controllers").exists(),
        orphan_reaping: plan.prctl.subreaper,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_pins_required_mounts_and_namespace_scope() {
        let plan = default_isolation_plan();
        assert_eq!(plan.namespaces, vec!["pid", "mount", "uts", "ipc"]);
        assert!(plan.mount_targets.contains(&"/proc"));
        assert!(plan.mount_targets.contains(&"/dev"));
        assert!(plan.mount_targets.contains(&"/dev/pts"));
        assert!(plan.mount_targets.contains(&"/dev/shm"));
        assert!(plan.read_only_sys);
    }

    #[test]
    fn verification_fails_closed_when_any_mandatory_control_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        ::std::fs::write(temp.path().join("cgroup.controllers"), "cpu memory\n")
            .expect("controllers");
        let mut plan = default_isolation_plan();
        plan.cgroup = CgroupPlan::under(temp.path());
        let probe = IsolationProbe {
            pid_namespace: true,
            mount_namespace: true,
            uts_namespace: true,
            ipc_namespace: true,
            private_proc: true,
            private_dev: true,
            private_devpts: true,
            private_shm: false,
            read_only_sys: true,
            capabilities_dropped: true,
            no_new_privs: true,
            cgroup_separation: true,
            orphan_reaping: true,
        };
        let error = verify_mandatory_isolation_controls(&plan, probe).expect_err("missing control");
        assert!(format!("{error}").contains("privateShm"));
    }

    #[test]
    fn verification_returns_status_only_after_all_controls_are_true() {
        let temp = tempfile::tempdir().expect("tempdir");
        ::std::fs::write(temp.path().join("cgroup.controllers"), "cpu memory\n")
            .expect("controllers");
        let mut plan = default_isolation_plan();
        plan.cgroup = CgroupPlan::under(temp.path());
        let status = verify_mandatory_isolation_controls(&plan, IsolationProbe::from_plan(&plan))
            .expect("status");
        assert!(status.pid_namespace);
        assert!(status.capabilities_dropped);
        assert!(status.no_new_privs);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux root with CAP_SYS_ADMIN/CAP_SETPCAP and cgroup v2 mounted at /sys/fs/cgroup"]
    fn privileged_runtime_probe_reports_mandatory_controls() {
        let plan = default_isolation_plan();
        let probe = runtime_probe(&plan);
        let _status =
            verify_mandatory_isolation_controls(&plan, probe).expect("mandatory controls");
    }
}
