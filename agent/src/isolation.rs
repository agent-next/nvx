// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Linux workload-isolation setup and fail-closed verification.

use ::agent_protocol::IsolationStatus;
#[cfg(target_os = "linux")]
use ::agent_protocol::{WORKLOAD_GID_MXC, WORKLOAD_UID_MXC};

#[cfg(target_os = "linux")]
use crate::cgroup::verify_cgroup_v2_support;
use crate::cgroup::{CgroupPlan, DEFAULT_CGROUP_ROOT};
use crate::error::{AgentError, Result};

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
    pub workload_identity_mxc: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceIdentity {
    dev: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceSnapshot {
    pid: NamespaceIdentity,
    mnt: NamespaceIdentity,
    uts: NamespaceIdentity,
    ipc: NamespaceIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolationSetupResult {
    pub holder_pid: libc::pid_t,
    pub status: IsolationStatus,
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolationSetupResult;

impl IsolationProbe {
    pub fn to_status(self) -> IsolationStatus {
        IsolationStatus {
            pid_namespace: self.pid_namespace,
            mount_namespace: self.mount_namespace,
            uts_namespace: self.uts_namespace,
            ipc_namespace: self.ipc_namespace,
            private_proc: self.private_proc,
            private_dev: self.private_dev,
            private_devpts: self.private_devpts,
            private_shm: self.private_shm,
            read_only_sys: self.read_only_sys,
            capabilities_dropped: self.capabilities_dropped,
            no_new_privs: self.no_new_privs,
            cgroup_separation: self.cgroup_separation,
            orphan_reaping: self.orphan_reaping,
        }
    }
}

pub fn default_isolation_plan() -> IsolationPlan {
    IsolationPlan {
        namespaces: vec!["pid", "mount", "uts", "ipc"],
        mount_targets: vec!["/proc", "/dev", "/dev/pts", "/dev/shm", "/sys"],
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

pub fn verify_mandatory_isolation_controls(probe: IsolationProbe) -> Result<IsolationStatus> {
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
    if !probe.workload_identity_mxc {
        missing.push("workloadIdentityMxc");
    }
    if !missing.is_empty() {
        return Err(AgentError::isolation(format!(
            "mandatory isolation controls are unavailable: {}",
            missing.join(", ")
        )));
    }
    Ok(probe.to_status())
}

#[cfg(target_os = "linux")]
const HOLDER_REPORT_READY: u8 = 1;
#[cfg(target_os = "linux")]
const HOLDER_REPORT_ERROR: u8 = 2;
#[cfg(target_os = "linux")]
const HOLDER_REPORT_SIZE: usize = 16;

#[cfg(target_os = "linux")]
const PROBE_PID_NAMESPACE: u32 = 1 << 0;
#[cfg(target_os = "linux")]
const PROBE_MOUNT_NAMESPACE: u32 = 1 << 1;
#[cfg(target_os = "linux")]
const PROBE_UTS_NAMESPACE: u32 = 1 << 2;
#[cfg(target_os = "linux")]
const PROBE_IPC_NAMESPACE: u32 = 1 << 3;
#[cfg(target_os = "linux")]
const PROBE_PRIVATE_PROC: u32 = 1 << 4;
#[cfg(target_os = "linux")]
const PROBE_PRIVATE_DEV: u32 = 1 << 5;
#[cfg(target_os = "linux")]
const PROBE_PRIVATE_DEVPTS: u32 = 1 << 6;
#[cfg(target_os = "linux")]
const PROBE_PRIVATE_SHM: u32 = 1 << 7;
#[cfg(target_os = "linux")]
const PROBE_READ_ONLY_SYS: u32 = 1 << 8;
#[cfg(target_os = "linux")]
const PROBE_CAPABILITIES_DROPPED: u32 = 1 << 9;
#[cfg(target_os = "linux")]
const PROBE_NO_NEW_PRIVS: u32 = 1 << 10;
#[cfg(target_os = "linux")]
const PROBE_CGROUP_SEPARATION: u32 = 1 << 11;
#[cfg(target_os = "linux")]
const PROBE_ORPHAN_REAPING: u32 = 1 << 12;
#[cfg(target_os = "linux")]
const PROBE_WORKLOAD_IDENTITY_MXC: u32 = 1 << 13;

#[cfg(target_os = "linux")]
const CAPABILITY_STATUS_KEYS: [&str; 5] = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"];

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static DROP_BOUNDING_CAP_FAIL_AT: ::std::cell::Cell<i32> = const { ::std::cell::Cell::new(-1) };
}

#[cfg(target_os = "linux")]
const REPORT_ERROR_UNSHARE: u32 = 1;
#[cfg(target_os = "linux")]
const REPORT_ERROR_NS_INODE: u32 = 2;
#[cfg(target_os = "linux")]
const REPORT_ERROR_FORK: u32 = 3;
#[cfg(target_os = "linux")]
const REPORT_ERROR_MOUNT: u32 = 4;
#[cfg(target_os = "linux")]
const REPORT_ERROR_CGROUP: u32 = 5;
#[cfg(target_os = "linux")]
const REPORT_ERROR_CAPS: u32 = 6;
#[cfg(target_os = "linux")]
const REPORT_ERROR_IDENTITY: u32 = 7;
#[cfg(target_os = "linux")]
const REPORT_ERROR_VERIFY: u32 = 8;
#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
#[cfg(target_os = "linux")]
const DEV_PTS_MODE: libc::mode_t = 0o755;
#[cfg(target_os = "linux")]
const DEV_SHM_MODE: libc::mode_t = 0o1777;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupStep {
    MoveToWorkloadCgroup,
    MakeRootPrivate,
    MountPrivateProc,
    MountPrivateDev,
    CreatePrivateDevLayout,
    MountPrivateDevpts,
    MountPrivateShm,
    BindPrivatePtmx,
    MountReadOnlySys,
    DropBoundingAndAmbientCaps,
    SwitchToMxcIdentity,
    ClearRemainingCaps,
    SetNoNewPrivs,
    VerifyIsolation,
}

#[cfg(target_os = "linux")]
fn setup_step_sequence() -> &'static [SetupStep] {
    &[
        SetupStep::MoveToWorkloadCgroup,
        SetupStep::MakeRootPrivate,
        SetupStep::MountPrivateProc,
        SetupStep::MountPrivateDev,
        SetupStep::CreatePrivateDevLayout,
        SetupStep::MountPrivateDevpts,
        SetupStep::MountPrivateShm,
        SetupStep::BindPrivatePtmx,
        SetupStep::MountReadOnlySys,
        SetupStep::DropBoundingAndAmbientCaps,
        SetupStep::SwitchToMxcIdentity,
        SetupStep::ClearRemainingCaps,
        SetupStep::SetNoNewPrivs,
        SetupStep::VerifyIsolation,
    ]
}

#[cfg(target_os = "linux")]
struct WorkloadSetupContext<'a> {
    plan: &'a IsolationPlan,
    parent_namespace: &'a NamespaceSnapshot,
    parent_cgroup: &'a str,
    probe: Option<IsolationProbe>,
}

#[cfg(target_os = "linux")]
trait SetupStepExecutor {
    fn run_step(&mut self, step: SetupStep, context: &mut WorkloadSetupContext<'_>) -> Result<()>;
}

#[cfg(target_os = "linux")]
struct SyscallSetupExecutor;

#[cfg(target_os = "linux")]
impl SetupStepExecutor for SyscallSetupExecutor {
    fn run_step(&mut self, step: SetupStep, context: &mut WorkloadSetupContext<'_>) -> Result<()> {
        match step {
            SetupStep::MoveToWorkloadCgroup => move_pid_to_cgroup(1, &context.plan.cgroup.workload),
            SetupStep::MakeRootPrivate => make_root_private(),
            SetupStep::MountPrivateProc => mount_call("proc", "/proc", "proc", 0, None),
            SetupStep::MountPrivateDev => mount_call(
                "tmpfs",
                "/dev",
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                Some("mode=755"),
            ),
            SetupStep::CreatePrivateDevLayout => ensure_minimal_private_dev_layout(),
            SetupStep::MountPrivateDevpts => mount_call(
                "devpts",
                "/dev/pts",
                "devpts",
                0,
                Some("newinstance,ptmxmode=0666,mode=620"),
            ),
            SetupStep::MountPrivateShm => mount_call(
                "tmpfs",
                "/dev/shm",
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                Some("mode=1777"),
            ),
            SetupStep::BindPrivatePtmx => ensure_ptmx_binding(),
            SetupStep::MountReadOnlySys => ensure_read_only_sysfs_mount(),
            SetupStep::DropBoundingAndAmbientCaps => drop_bounding_and_ambient_capabilities(),
            SetupStep::SwitchToMxcIdentity => switch_to_mxc_identity(),
            SetupStep::ClearRemainingCaps => clear_remaining_capabilities(),
            SetupStep::SetNoNewPrivs => set_no_new_privs(),
            SetupStep::VerifyIsolation => {
                let probe = isolated_child_probe(context.parent_namespace, context.parent_cgroup)?;
                let _ = verify_mandatory_isolation_controls(probe)?;
                context.probe = Some(probe);
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn execute_setup_steps_with_executor(
    context: &mut WorkloadSetupContext<'_>,
    executor: &mut impl SetupStepExecutor,
) -> Result<IsolationProbe> {
    for step in setup_step_sequence() {
        executor.run_step(*step, context)?;
    }
    context.probe.ok_or_else(|| {
        AgentError::isolation(
            "setup step dispatch completed without isolation verification".to_string(),
        )
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HolderReport {
    holder_pid: libc::pid_t,
    probe_bits: u32,
}

#[cfg(target_os = "linux")]
pub fn apply_and_verify_workload_isolation(plan: &IsolationPlan) -> Result<IsolationSetupResult> {
    verify_cgroup_v2_support(&plan.cgroup)?;
    ensure_subreaper()?;

    ensure_cgroup_directories(&plan.cgroup)?;
    move_pid_to_cgroup(::std::process::id() as libc::pid_t, &plan.cgroup.agent)?;
    let parent_cgroup = current_cgroup_path()?;

    let parent_namespace = namespace_snapshot()?;
    let mut report_pipe = [0_i32; 2];
    // SAFETY: report_pipe points to valid writable memory for two fds.
    if unsafe { libc::pipe2(report_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(AgentError::io(
            "creating isolation status pipe",
            ::std::io::Error::last_os_error(),
        ));
    }
    let report_read = report_pipe[0];
    let report_write = report_pipe[1];

    // SAFETY: fork is called in single-threaded test/runtime setup path, and both branches avoid
    // touching shared synchronization primitives before exec/exit.
    let stage_one = unsafe { libc::fork() };
    if stage_one < 0 {
        close_fd(report_read);
        close_fd(report_write);
        return Err(AgentError::io(
            "forking stage-1 isolation process",
            ::std::io::Error::last_os_error(),
        ));
    }
    if stage_one == 0 {
        close_fd(report_read);
        stage_one_child(plan, parent_namespace, parent_cgroup, report_write);
    }
    close_fd(report_write);

    let holder_report = finalize_stage_one(stage_one, report_read)?;
    let probe = decode_probe(holder_report.probe_bits);
    let status = verify_mandatory_isolation_controls(probe)?;
    Ok(IsolationSetupResult {
        holder_pid: holder_report.holder_pid,
        status,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn apply_and_verify_workload_isolation(_plan: &IsolationPlan) -> Result<IsolationSetupResult> {
    Err(AgentError::isolation(
        "workload isolation setup is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn finalize_stage_one(stage_one_pid: libc::pid_t, report_read_fd: i32) -> Result<HolderReport> {
    finalize_stage_one_with(stage_one_pid, report_read_fd, read_holder_report, wait_pid)
}

#[cfg(target_os = "linux")]
fn finalize_stage_one_with(
    stage_one_pid: libc::pid_t,
    report_read_fd: i32,
    read_report: impl FnOnce(i32) -> Result<HolderReport>,
    wait_for_stage_one: impl FnOnce(libc::pid_t) -> Result<()>,
) -> Result<HolderReport> {
    let report_result = read_report(report_read_fd);
    let wait_result = wait_for_stage_one(stage_one_pid);
    match (report_result, wait_result) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(report_error), Ok(())) => Err(report_error),
        (Ok(_), Err(wait_error)) => Err(wait_error),
        (Err(report_error), Err(wait_error)) => Err(AgentError::isolation(format!(
            "failed reading stage-1 holder report: {report_error}; additionally failed waiting for stage-1 process {stage_one_pid}: {wait_error}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn stage_one_child(
    plan: &IsolationPlan,
    parent_namespace: NamespaceSnapshot,
    parent_cgroup: String,
    report_fd: i32,
) -> ! {
    let unshare_flags =
        libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC | libc::CLONE_NEWPID;
    // SAFETY: unshare called with constant namespace flags.
    if unsafe { libc::unshare(unshare_flags) } != 0 {
        write_error_report(report_fd, REPORT_ERROR_UNSHARE);
        close_fd(report_fd);
        exit_immediately(1);
    }

    let mut child_report_pipe = [0_i32; 2];
    // SAFETY: child_report_pipe points to valid writable memory for two fds.
    if unsafe { libc::pipe2(child_report_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        write_error_report(report_fd, REPORT_ERROR_FORK);
        close_fd(report_fd);
        exit_immediately(1);
    }
    let child_report_read = child_report_pipe[0];
    let child_report_write = child_report_pipe[1];

    // SAFETY: second fork enters the new pid namespace as PID 1 child.
    let holder_pid = unsafe { libc::fork() };
    if holder_pid < 0 {
        close_fd(child_report_read);
        close_fd(child_report_write);
        write_error_report(report_fd, REPORT_ERROR_FORK);
        close_fd(report_fd);
        exit_immediately(1);
    }
    if holder_pid > 0 {
        close_fd(child_report_write);
        let child_bits = read_child_probe_bits(child_report_read);
        close_fd(child_report_read);
        match child_bits {
            Ok(bits) => write_ready_report(report_fd, holder_pid as u32, bits),
            Err(_) => write_error_report(report_fd, REPORT_ERROR_VERIFY),
        }
        close_fd(report_fd);
        exit_immediately(0);
    }

    close_fd(child_report_read);
    let probe = match apply_workload_controls(plan, &parent_namespace, &parent_cgroup) {
        Ok(probe) => probe,
        Err(error) => {
            eprintln!("NVX-AGENT-ISOLATION-SETUP-ERROR: {error}");
            let _ = write_all_fd(child_report_write, &[HOLDER_REPORT_ERROR, 0, 0, 0]);
            close_fd(child_report_write);
            close_fd(report_fd);
            exit_immediately(1);
        }
    };
    let bits = encode_probe(probe);
    if send_child_probe_and_close_report_fd(report_fd, child_report_write, bits).is_err() {
        exit_immediately(1);
    }
    holder_reap_loop();
}

#[cfg(target_os = "linux")]
fn apply_workload_controls(
    plan: &IsolationPlan,
    parent_namespace: &NamespaceSnapshot,
    parent_cgroup: &str,
) -> Result<IsolationProbe> {
    let mut context = WorkloadSetupContext {
        plan,
        parent_namespace,
        parent_cgroup,
        probe: None,
    };
    let mut executor = SyscallSetupExecutor;
    execute_setup_steps_with_executor(&mut context, &mut executor)
}

#[cfg(target_os = "linux")]
fn isolated_child_probe(
    parent_namespace: &NamespaceSnapshot,
    parent_cgroup: &str,
) -> Result<IsolationProbe> {
    let child_namespace = namespace_snapshot()?;
    let mountinfo = read_to_string("/proc/self/mountinfo", "reading mountinfo")?;
    let status = read_to_string("/proc/self/status", "reading child status")?;
    let child_cgroup = current_cgroup_path()?;
    let subreaper = query_subreaper()?;
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    Ok(IsolationProbe {
        pid_namespace: child_namespace.pid != parent_namespace.pid,
        mount_namespace: child_namespace.mnt != parent_namespace.mnt,
        uts_namespace: child_namespace.uts != parent_namespace.uts,
        ipc_namespace: child_namespace.ipc != parent_namespace.ipc,
        private_proc: mountinfo_has_mount(&mountinfo, "/proc", "proc", false),
        private_dev: mountinfo_has_mount(&mountinfo, "/dev", "tmpfs", false),
        private_devpts: mountinfo_has_mount(&mountinfo, "/dev/pts", "devpts", false),
        private_shm: mountinfo_has_mount(&mountinfo, "/dev/shm", "tmpfs", false),
        read_only_sys: mountinfo_has_mount(&mountinfo, "/sys", "sysfs", true)
            && root_propagation_private(&mountinfo),
        capabilities_dropped: capabilities_are_zero(&status),
        no_new_privs: parse_status_value(&status, "NoNewPrivs:")
            .map(|value| value == "1")
            .unwrap_or(false),
        cgroup_separation: child_cgroup != parent_cgroup,
        orphan_reaping: subreaper || unsafe { libc::getpid() } == 1,
        workload_identity_mxc: euid == WORKLOAD_UID_MXC && egid == WORKLOAD_GID_MXC,
    })
}

#[cfg(target_os = "linux")]
fn ensure_subreaper() -> Result<()> {
    // SAFETY: prctl called with documented command and integer argument.
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(AgentError::io(
            "setting PR_SET_CHILD_SUBREAPER",
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn query_subreaper() -> Result<bool> {
    let mut enabled = 0_i32;
    // SAFETY: enabled points to writable i32 for PR_GET_CHILD_SUBREAPER output.
    let rc = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut enabled as *mut i32) };
    if rc != 0 {
        return Err(AgentError::io(
            "reading PR_GET_CHILD_SUBREAPER",
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(enabled == 1)
}

#[cfg(target_os = "linux")]
fn drop_bounding_and_ambient_capabilities() -> Result<()> {
    // SAFETY: prctl ambient clear has no pointer args.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(AgentError::io(
            "clearing ambient capabilities",
            ::std::io::Error::last_os_error(),
        ));
    }

    let last_cap = read_last_capability_index()?;
    let mut cap = 0_i32;
    while cap <= last_cap {
        #[cfg(all(test, target_os = "linux"))]
        if DROP_BOUNDING_CAP_FAIL_AT.with(|slot| slot.get() == cap) {
            return Err(AgentError::isolation(format!(
                "injected failure dropping capability {cap} from bounding set"
            )));
        }
        // SAFETY: prctl drop with valid cap index; kernel validates support.
        let drop_result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if drop_result != 0 {
            return Err(AgentError::io(
                format!("dropping capability {cap} from bounding set"),
                ::std::io::Error::last_os_error(),
            ));
        }
        cap += 1;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_remaining_capabilities() -> Result<()> {
    let cap_header = LinuxCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut cap_data = [LinuxCapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: syscall receives valid pointers to initialized capability header/data.
    let capset_result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &cap_header as *const LinuxCapHeader,
            cap_data.as_mut_ptr(),
        )
    };
    if capset_result != 0 {
        return Err(AgentError::io(
            "clearing effective/permitted/inheritable capabilities after mxc identity switch",
            ::std::io::Error::last_os_error(),
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl no_new_privs has no pointer args.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(AgentError::io(
            "setting PR_SET_NO_NEW_PRIVS",
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_last_capability_index() -> Result<i32> {
    let raw = read_to_string(
        "/proc/sys/kernel/cap_last_cap",
        "reading /proc/sys/kernel/cap_last_cap",
    )?;
    raw.trim().parse::<i32>().map_err(|error| {
        AgentError::isolation(format!(
            "failed to parse cap_last_cap value {raw:?}: {error}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn switch_to_mxc_identity() -> Result<()> {
    // SAFETY: setgroups called with zero groups and null pointer by contract.
    if unsafe { libc::setgroups(0, ::std::ptr::null()) } != 0 {
        return Err(AgentError::io(
            "clearing supplementary groups for mxc identity",
            ::std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: setgid/setuid use fixed configured IDs.
    if unsafe { libc::setgid(WORKLOAD_GID_MXC) } != 0 {
        return Err(AgentError::io(
            "switching to workload gid",
            ::std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: setuid uses fixed configured ID.
    if unsafe { libc::setuid(WORKLOAD_UID_MXC) } != 0 {
        return Err(AgentError::io(
            "switching to workload uid",
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_minimal_private_dev_layout() -> Result<()> {
    mkdir_if_missing("/dev/pts", DEV_PTS_MODE)?;
    mkdir_if_missing("/dev/shm", DEV_SHM_MODE)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_ptmx_binding() -> Result<()> {
    let _ = ::std::fs::remove_file("/dev/ptmx");
    let link_target = to_cstring("pts/ptmx", "ptmx symlink target")?;
    let link_name = to_cstring("/dev/ptmx", "ptmx symlink path")?;
    // SAFETY: both pointers are valid NUL-terminated paths.
    if unsafe { libc::symlink(link_target.as_ptr(), link_name.as_ptr()) } != 0 {
        return Err(AgentError::io(
            "creating /dev/ptmx -> pts/ptmx symlink in private /dev",
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_read_only_sysfs_mount() -> Result<()> {
    let mountinfo_before = read_to_string(
        "/proc/self/mountinfo",
        "reading mountinfo before read-only /sys setup",
    )?;
    if mountinfo_has_mount(&mountinfo_before, "/sys", "sysfs", false) {
        mount_call("none", "/sys", "", libc::MS_REMOUNT | libc::MS_RDONLY, None)?;
    } else {
        mount_call("sysfs", "/sys", "sysfs", libc::MS_RDONLY, None)?;
    }
    let mountinfo_after = read_to_string(
        "/proc/self/mountinfo",
        "reading mountinfo after read-only /sys setup",
    )?;
    if !mountinfo_has_mount(&mountinfo_after, "/sys", "sysfs", true) {
        return Err(AgentError::isolation(
            "read-only sysfs is required at /sys after isolation mount setup",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mkdir_if_missing(path: &str, mode: libc::mode_t) -> Result<()> {
    let c_path = to_cstring(path, "mkdir path")?;
    // SAFETY: c_path is a valid NUL-terminated path string.
    let mkdir_result = unsafe { libc::mkdir(c_path.as_ptr(), mode) };
    if mkdir_result == 0 {
        return Ok(());
    }
    let error = ::std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EEXIST) {
        return Ok(());
    }
    Err(AgentError::io(
        format!("creating required directory {path}"),
        error,
    ))
}

#[cfg(target_os = "linux")]
fn make_root_private() -> Result<()> {
    mount_call("none", "/", "", libc::MS_PRIVATE | libc::MS_REC, None)
}

#[cfg(target_os = "linux")]
fn mount_call(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let source = to_cstring(source, "mount source")?;
    let target = to_cstring(target, "mount target")?;
    let fstype = to_cstring(fstype, "mount fstype")?;
    let data = data
        .map(|value| to_cstring(value, "mount data"))
        .transpose()?;
    // SAFETY: pointers are valid C strings for duration of syscall; null pointers are used only
    // when fstype/data are intentionally omitted.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            if fstype.as_bytes().is_empty() {
                ::std::ptr::null()
            } else {
                fstype.as_ptr()
            },
            flags,
            data.as_ref()
                .map_or(::std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if rc != 0 {
        return Err(AgentError::io(
            format!("mounting {source:?} on {target:?}"),
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn to_cstring(value: &str, context: &str) -> Result<::std::ffi::CString> {
    ::std::ffi::CString::new(value)
        .map_err(|_| AgentError::config(format!("{context} contains interior NUL byte")))
}

#[cfg(target_os = "linux")]
fn ensure_cgroup_directories(plan: &CgroupPlan) -> Result<()> {
    ::std::fs::create_dir_all(&plan.agent).map_err(|error| {
        AgentError::io(
            format!("creating agent cgroup {}", plan.agent.display()),
            error,
        )
    })?;
    ::std::fs::create_dir_all(&plan.workload).map_err(|error| {
        AgentError::io(
            format!("creating workload cgroup {}", plan.workload.display()),
            error,
        )
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn move_pid_to_cgroup(pid: libc::pid_t, cgroup_dir: &::std::path::Path) -> Result<()> {
    let path = cgroup_dir.join("cgroup.procs");
    ::std::fs::write(&path, format!("{pid}\n"))
        .map_err(|error| AgentError::io(format!("writing pid {pid} to {}", path.display()), error))
}

#[cfg(target_os = "linux")]
fn current_cgroup_path() -> Result<String> {
    let cgroup = read_to_string("/proc/self/cgroup", "reading /proc/self/cgroup")?;
    for line in cgroup.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Ok(path.trim().to_string());
        }
    }
    Err(AgentError::isolation(
        "could not parse cgroup v2 path from /proc/self/cgroup",
    ))
}

#[cfg(target_os = "linux")]
fn read_cgroup_of_pid(pid: libc::pid_t) -> Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let cgroup = read_to_string(&path, format!("reading cgroup for pid {pid}"))?;
    for line in cgroup.lines() {
        if let Some(value) = line.strip_prefix("0::") {
            return Ok(value.trim().to_string());
        }
    }
    Err(AgentError::isolation(format!(
        "could not parse cgroup v2 entry for pid {pid}"
    )))
}

#[cfg(target_os = "linux")]
fn namespace_snapshot() -> Result<NamespaceSnapshot> {
    Ok(NamespaceSnapshot {
        pid: namespace_identity("pid")?,
        mnt: namespace_identity("mnt")?,
        uts: namespace_identity("uts")?,
        ipc: namespace_identity("ipc")?,
    })
}

#[cfg(target_os = "linux")]
fn namespace_identity(name: &str) -> Result<NamespaceIdentity> {
    let path = format!("/proc/self/ns/{name}");
    let c_path = to_cstring(&path, "namespace path")?;
    let mut stat_buffer = ::std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat_buffer points to valid uninitialized memory for libc::stat fill.
    if unsafe { libc::stat(c_path.as_ptr(), stat_buffer.as_mut_ptr()) } != 0 {
        return Err(AgentError::io(
            format!("stat on namespace path {path}"),
            ::std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: libc::stat succeeded and fully initialized stat_buffer.
    let stat_buffer = unsafe { stat_buffer.assume_init() };
    Ok(NamespaceIdentity {
        dev: stat_buffer.st_dev,
        inode: stat_buffer.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn read_holder_report(report_read_fd: i32) -> Result<HolderReport> {
    let mut report = [0_u8; HOLDER_REPORT_SIZE];
    let mut offset = 0_usize;
    loop {
        // SAFETY: report buffer slice is valid and writable.
        let read_size = unsafe {
            libc::read(
                report_read_fd,
                report[offset..].as_mut_ptr().cast(),
                (HOLDER_REPORT_SIZE - offset) as libc::size_t,
            )
        };
        if read_size < 0 {
            close_fd(report_read_fd);
            return Err(AgentError::io(
                "reading isolation holder report",
                ::std::io::Error::last_os_error(),
            ));
        }
        if read_size == 0 {
            break;
        }
        offset += read_size as usize;
        if offset >= HOLDER_REPORT_SIZE {
            break;
        }
    }
    close_fd(report_read_fd);
    if offset < HOLDER_REPORT_SIZE {
        return Err(AgentError::isolation(
            "isolation holder exited before writing full status report",
        ));
    }
    if report[0] == HOLDER_REPORT_ERROR {
        let code = u32::from_ne_bytes([report[4], report[5], report[6], report[7]]);
        return Err(AgentError::isolation(format!(
            "isolation holder setup failed with report code {code}"
        )));
    }
    if report[0] != HOLDER_REPORT_READY {
        return Err(AgentError::isolation(format!(
            "isolation holder returned unknown report type {}",
            report[0]
        )));
    }
    let pid = u32::from_ne_bytes([report[8], report[9], report[10], report[11]]) as libc::pid_t;
    if pid <= 0 {
        return Err(AgentError::isolation(
            "isolation holder report did not include a valid pid",
        ));
    }
    let probe_bits = u32::from_ne_bytes([report[12], report[13], report[14], report[15]]);
    Ok(HolderReport {
        holder_pid: pid,
        probe_bits,
    })
}

#[cfg(target_os = "linux")]
fn write_ready_report(report_fd: i32, holder_pid: u32, probe_bits: u32) {
    let mut report = [0_u8; HOLDER_REPORT_SIZE];
    report[0] = HOLDER_REPORT_READY;
    report[8..12].copy_from_slice(&holder_pid.to_ne_bytes());
    report[12..16].copy_from_slice(&probe_bits.to_ne_bytes());
    let _ = write_all_fd(report_fd, &report);
}

#[cfg(target_os = "linux")]
fn write_error_report(report_fd: i32, code: u32) {
    let mut report = [0_u8; HOLDER_REPORT_SIZE];
    report[0] = HOLDER_REPORT_ERROR;
    report[4..8].copy_from_slice(&code.to_ne_bytes());
    let _ = write_all_fd(report_fd, &report);
}

#[cfg(target_os = "linux")]
fn send_child_probe_and_close_report_fd(
    report_fd: i32,
    child_report_write: i32,
    probe_bits: u32,
) -> Result<()> {
    let mut payload = [0_u8; 8];
    payload[0] = HOLDER_REPORT_READY;
    payload[4..8].copy_from_slice(&probe_bits.to_ne_bytes());
    let write_result = write_all_fd(child_report_write, &payload);
    close_fd(child_report_write);
    close_fd(report_fd);
    write_result
}

#[cfg(target_os = "linux")]
fn read_child_probe_bits(child_report_read: i32) -> Result<u32> {
    let mut payload = [0_u8; 8];
    let mut offset = 0_usize;
    while offset < payload.len() {
        // SAFETY: payload buffer slice is valid and writable.
        let read_size = unsafe {
            libc::read(
                child_report_read,
                payload[offset..].as_mut_ptr().cast(),
                (payload.len() - offset) as libc::size_t,
            )
        };
        if read_size < 0 {
            return Err(AgentError::io(
                "reading child isolation probe report",
                ::std::io::Error::last_os_error(),
            ));
        }
        if read_size == 0 {
            break;
        }
        offset += read_size as usize;
    }
    if offset < payload.len() || payload[0] != HOLDER_REPORT_READY {
        return Err(AgentError::isolation(
            "child isolation setup did not return a complete success probe",
        ));
    }
    Ok(u32::from_ne_bytes([
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

#[cfg(target_os = "linux")]
fn encode_probe(probe: IsolationProbe) -> u32 {
    let mut bits = 0_u32;
    if probe.pid_namespace {
        bits |= PROBE_PID_NAMESPACE;
    }
    if probe.mount_namespace {
        bits |= PROBE_MOUNT_NAMESPACE;
    }
    if probe.uts_namespace {
        bits |= PROBE_UTS_NAMESPACE;
    }
    if probe.ipc_namespace {
        bits |= PROBE_IPC_NAMESPACE;
    }
    if probe.private_proc {
        bits |= PROBE_PRIVATE_PROC;
    }
    if probe.private_dev {
        bits |= PROBE_PRIVATE_DEV;
    }
    if probe.private_devpts {
        bits |= PROBE_PRIVATE_DEVPTS;
    }
    if probe.private_shm {
        bits |= PROBE_PRIVATE_SHM;
    }
    if probe.read_only_sys {
        bits |= PROBE_READ_ONLY_SYS;
    }
    if probe.capabilities_dropped {
        bits |= PROBE_CAPABILITIES_DROPPED;
    }
    if probe.no_new_privs {
        bits |= PROBE_NO_NEW_PRIVS;
    }
    if probe.cgroup_separation {
        bits |= PROBE_CGROUP_SEPARATION;
    }
    if probe.orphan_reaping {
        bits |= PROBE_ORPHAN_REAPING;
    }
    if probe.workload_identity_mxc {
        bits |= PROBE_WORKLOAD_IDENTITY_MXC;
    }
    bits
}

#[cfg(target_os = "linux")]
fn decode_probe(bits: u32) -> IsolationProbe {
    IsolationProbe {
        pid_namespace: bits & PROBE_PID_NAMESPACE != 0,
        mount_namespace: bits & PROBE_MOUNT_NAMESPACE != 0,
        uts_namespace: bits & PROBE_UTS_NAMESPACE != 0,
        ipc_namespace: bits & PROBE_IPC_NAMESPACE != 0,
        private_proc: bits & PROBE_PRIVATE_PROC != 0,
        private_dev: bits & PROBE_PRIVATE_DEV != 0,
        private_devpts: bits & PROBE_PRIVATE_DEVPTS != 0,
        private_shm: bits & PROBE_PRIVATE_SHM != 0,
        read_only_sys: bits & PROBE_READ_ONLY_SYS != 0,
        capabilities_dropped: bits & PROBE_CAPABILITIES_DROPPED != 0,
        no_new_privs: bits & PROBE_NO_NEW_PRIVS != 0,
        cgroup_separation: bits & PROBE_CGROUP_SEPARATION != 0,
        orphan_reaping: bits & PROBE_ORPHAN_REAPING != 0,
        workload_identity_mxc: bits & PROBE_WORKLOAD_IDENTITY_MXC != 0,
    }
}

#[cfg(target_os = "linux")]
fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        // SAFETY: bytes pointer remains valid for the requested write length.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            return Err(AgentError::io(
                "writing isolation report",
                ::std::io::Error::last_os_error(),
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn holder_reap_loop() -> ! {
    let mut set = ::std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: set points to valid memory.
    let _ = unsafe { libc::sigemptyset(set.as_mut_ptr()) };
    // SAFETY: set is initialized by sigemptyset above.
    let mut set = unsafe { set.assume_init() };
    // SAFETY: mut set is valid.
    let _ = unsafe { libc::sigaddset(&mut set, libc::SIGCHLD) };
    // SAFETY: mut set is valid.
    let _ = unsafe { libc::sigaddset(&mut set, libc::SIGTERM) };
    // SAFETY: mut set is valid.
    let _ = unsafe { libc::sigaddset(&mut set, libc::SIGINT) };
    // SAFETY: blocking signal mask with valid set pointer.
    let _ = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, ::std::ptr::null_mut()) };

    loop {
        let mut signal = 0_i32;
        // SAFETY: set points to initialized sigset_t and signal output pointer is valid.
        let wait_rc = unsafe { libc::sigwait(&set, &mut signal) };
        if wait_rc != 0 {
            exit_immediately(1);
        }
        if signal == libc::SIGTERM || signal == libc::SIGINT {
            reap_all_children();
            exit_immediately(0);
        }
        if signal == libc::SIGCHLD {
            reap_all_children();
        }
    }
}

#[cfg(target_os = "linux")]
pub fn reap_all_children() {
    loop {
        let mut status = 0_i32;
        // SAFETY: waitpid called with WNOHANG and valid status pointer.
        let child = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if child <= 0 {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_pid(pid: libc::pid_t) -> Result<()> {
    let mut status = 0_i32;
    // SAFETY: waitpid called for a known direct child and valid status pointer.
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err(AgentError::io(
            format!("waiting for pid {pid}"),
            ::std::io::Error::last_os_error(),
        ));
    }
    if !wifexited_success(status) {
        return Err(AgentError::isolation(format!(
            "child process {pid} did not exit successfully (status={status})"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wifexited_success(status: i32) -> bool {
    (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0
}

#[cfg(target_os = "linux")]
fn close_fd(fd: i32) {
    // SAFETY: closing an fd is safe; ignore errors in cleanup path.
    let _ = unsafe { libc::close(fd) };
}

#[cfg(target_os = "linux")]
fn exit_immediately(code: i32) -> ! {
    // SAFETY: _exit terminates current process without invoking unwinding in post-fork paths.
    unsafe { libc::_exit(code) }
}

#[cfg(target_os = "linux")]
fn read_to_string(path: &str, context: impl Into<String>) -> Result<String> {
    ::std::fs::read_to_string(path).map_err(|error| AgentError::io(context, error))
}

#[cfg(target_os = "linux")]
fn parse_status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key).map(str::trim))
}

#[cfg(target_os = "linux")]
fn capabilities_are_zero(status: &str) -> bool {
    CAPABILITY_STATUS_KEYS.iter().all(|key| {
        parse_status_value(status, key)
            .map(|value| value == "0000000000000000")
            .unwrap_or(false)
    })
}

#[cfg(target_os = "linux")]
fn mountinfo_has_mount(
    mountinfo: &str,
    mount_point: &str,
    fstype: &str,
    require_read_only: bool,
) -> bool {
    mountinfo.lines().any(|line| {
        let mut parts = line.split(" - ");
        let pre = parts.next().unwrap_or_default();
        let post = parts.next().unwrap_or_default();
        if post.is_empty() {
            return false;
        }
        let pre_fields: Vec<&str> = pre.split_whitespace().collect();
        if pre_fields.len() < 6 || pre_fields[4] != mount_point {
            return false;
        }
        let post_fields: Vec<&str> = post.split_whitespace().collect();
        if post_fields.is_empty() || post_fields[0] != fstype {
            return false;
        }
        if !require_read_only {
            return true;
        }
        pre_fields[5].split(',').any(|flag| flag == "ro")
    })
}

#[cfg(target_os = "linux")]
fn root_propagation_private(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let mut parts = line.split(" - ");
        let pre = parts.next().unwrap_or_default();
        let fields: Vec<&str> = pre.split_whitespace().collect();
        if fields.len() < 6 || fields[4] != "/" {
            return false;
        }
        let optional = if fields.len() > 6 { &fields[6..] } else { &[] };
        !optional
            .iter()
            .any(|value| value.starts_with("shared:") || value.starts_with("master:"))
    })
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
            workload_identity_mxc: true,
        };
        let error = verify_mandatory_isolation_controls(probe).expect_err("missing control");
        assert!(format!("{error}").contains("privateShm"));
    }

    #[test]
    fn verification_returns_status_only_after_all_controls_are_true() {
        let status = verify_mandatory_isolation_controls(IsolationProbe {
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
            workload_identity_mxc: true,
        })
        .expect("status");
        assert!(status.pid_namespace);
        assert!(status.capabilities_dropped);
        assert!(status.no_new_privs);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_propagation_parser_rejects_shared_root() {
        let mountinfo = "10 1 0:10 / / rw,relatime shared:2 - ext4 /dev/root rw";
        assert!(!root_propagation_private(mountinfo));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_propagation_parser_accepts_private_root() {
        let mountinfo = "10 1 0:10 / / rw,relatime - ext4 /dev/root rw";
        assert!(root_propagation_private(mountinfo));
    }

    #[cfg(target_os = "linux")]
    struct OrderingInvariantExecutor {
        seen: Vec<SetupStep>,
    }

    #[cfg(target_os = "linux")]
    impl OrderingInvariantExecutor {
        fn has_seen(&self, step: SetupStep) -> bool {
            self.seen.contains(&step)
        }
    }

    #[cfg(target_os = "linux")]
    impl SetupStepExecutor for OrderingInvariantExecutor {
        fn run_step(
            &mut self,
            step: SetupStep,
            context: &mut WorkloadSetupContext<'_>,
        ) -> Result<()> {
            match step {
                SetupStep::MountReadOnlySys => {
                    assert!(
                        self.has_seen(SetupStep::MoveToWorkloadCgroup),
                        "workload cgroup move must happen before read-only /sys replacement"
                    );
                }
                SetupStep::MountPrivateDevpts | SetupStep::MountPrivateShm => {
                    assert!(
                        self.has_seen(SetupStep::CreatePrivateDevLayout),
                        "private /dev directories must exist before /dev submounts"
                    );
                }
                SetupStep::SwitchToMxcIdentity => {
                    assert!(
                        self.has_seen(SetupStep::DropBoundingAndAmbientCaps),
                        "bounding capabilities must be dropped before mxc identity transition"
                    );
                }
                SetupStep::ClearRemainingCaps => {
                    assert!(
                        self.has_seen(SetupStep::SwitchToMxcIdentity),
                        "final capability clear must follow mxc identity transition"
                    );
                }
                SetupStep::SetNoNewPrivs => {
                    assert!(
                        self.has_seen(SetupStep::ClearRemainingCaps),
                        "no_new_privs must be set after final capability clearing"
                    );
                }
                SetupStep::VerifyIsolation => {
                    context.probe = Some(IsolationProbe {
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
                        workload_identity_mxc: true,
                    });
                }
                _ => {}
            }
            self.seen.push(step);
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setup_dispatch_enforces_critical_ordering_invariants() {
        let plan = default_isolation_plan();
        let namespace = NamespaceSnapshot {
            pid: NamespaceIdentity { dev: 1, inode: 1 },
            mnt: NamespaceIdentity { dev: 1, inode: 2 },
            uts: NamespaceIdentity { dev: 1, inode: 3 },
            ipc: NamespaceIdentity { dev: 1, inode: 4 },
        };
        let mut context = WorkloadSetupContext {
            plan: &plan,
            parent_namespace: &namespace,
            parent_cgroup: "/nvx.agent",
            probe: None,
        };
        let mut executor = OrderingInvariantExecutor { seen: Vec::new() };
        let probe = execute_setup_steps_with_executor(&mut context, &mut executor).expect("probe");
        assert!(probe.no_new_privs);
        assert_eq!(executor.seen.len(), setup_step_sequence().len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capabilities_are_zero_requires_all_five_capability_sets() {
        let baseline = [
            "CapInh:\t0000000000000000",
            "CapPrm:\t0000000000000000",
            "CapEff:\t0000000000000000",
            "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000",
        ]
        .join("\n");
        assert!(capabilities_are_zero(&baseline));

        for key in CAPABILITY_STATUS_KEYS {
            let mutated = baseline.replace(
                &format!("{key}\t0000000000000000"),
                &format!("{key}\t0000000000000001"),
            );
            assert!(
                !capabilities_are_zero(&mutated),
                "{key} must be zero in /proc/self/status"
            );
        }
        assert!(!capabilities_are_zero("CapInh:\t0000000000000000"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drop_bounding_failure_is_fatal() {
        DROP_BOUNDING_CAP_FAIL_AT.with(|slot| slot.set(0));
        let result = drop_bounding_and_ambient_capabilities();
        DROP_BOUNDING_CAP_FAIL_AT.with(|slot| slot.set(-1));
        let error = result.expect_err("bounding-set drop failure must be fatal");
        assert!(
            error
                .to_string()
                .contains("injected failure dropping capability 0"),
            "unexpected error: {error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalize_stage_one_waits_even_if_report_read_fails() {
        use ::std::sync::Arc;
        use ::std::sync::atomic::{AtomicBool, Ordering};

        let waited = Arc::new(AtomicBool::new(false));
        let waited_clone = Arc::clone(&waited);
        let result = finalize_stage_one_with(
            1234,
            -1,
            |_| Err(AgentError::isolation("report read failed".to_string())),
            |_| {
                waited_clone.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(result.is_err(), "report failure must fail setup");
        assert!(
            waited.load(Ordering::SeqCst),
            "stage-one process must still be waited/reaped after report failure"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalize_stage_one_reports_both_report_and_wait_failures() {
        let result = finalize_stage_one_with(
            9876,
            -1,
            |_| Err(AgentError::isolation("report read failed".to_string())),
            |_| Err(AgentError::isolation("waitpid failed".to_string())),
        )
        .expect_err("combined error");
        let message = format!("{result}");
        assert!(message.contains("report read failed"));
        assert!(message.contains("waitpid failed"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_child_probe_bits_fails_on_early_eof() {
        let mut pipe_fds = [0_i32; 2];
        // SAFETY: pipe_fds points to valid storage for pipe2 output.
        let pipe_result = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(pipe_result, 0, "pipe2 failed");
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];
        close_fd(write_fd);
        let result = read_child_probe_bits(read_fd);
        close_fd(read_fd);
        assert!(result.is_err(), "early EOF must be rejected");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_holder_report_fails_on_early_eof() {
        let mut pipe_fds = [0_i32; 2];
        // SAFETY: pipe_fds points to valid storage for pipe2 output.
        let pipe_result = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(pipe_result, 0, "pipe2 failed");
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];
        close_fd(write_fd);
        let result = read_holder_report(read_fd);
        assert!(
            result.is_err(),
            "short/empty holder report must be rejected"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sending_child_probe_closes_report_writer_and_emits_payload() {
        let mut report_pipe = [0_i32; 2];
        let mut child_pipe = [0_i32; 2];
        // SAFETY: arrays point to valid storage for pipe2 output.
        assert_eq!(
            unsafe { libc::pipe2(report_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: arrays point to valid storage for pipe2 output.
        assert_eq!(
            unsafe { libc::pipe2(child_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let report_read = report_pipe[0];
        let report_write = report_pipe[1];
        let child_read = child_pipe[0];
        let child_write = child_pipe[1];

        send_child_probe_and_close_report_fd(report_write, child_write, 0xAA55_AA55)
            .expect("send child probe");

        let mut report_marker = [0_u8; 1];
        // SAFETY: report_marker points to writable buffer and read fd is valid.
        let report_read_size =
            unsafe { libc::read(report_read, report_marker.as_mut_ptr().cast(), 1) };
        assert_eq!(report_read_size, 0, "report pipe should be at EOF");
        close_fd(report_read);

        let mut child_payload = [0_u8; 8];
        // SAFETY: child_payload points to writable buffer and read fd is valid.
        let child_read_size = unsafe {
            libc::read(
                child_read,
                child_payload.as_mut_ptr().cast(),
                child_payload.len(),
            )
        };
        assert_eq!(child_read_size, 8, "child payload must contain full report");
        assert_eq!(child_payload[0], HOLDER_REPORT_READY);
        assert_eq!(
            u32::from_ne_bytes([
                child_payload[4],
                child_payload[5],
                child_payload[6],
                child_payload[7],
            ]),
            0xAA55_AA55
        );
        close_fd(child_read);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux root privileges and cgroup v2 write access in disposable helper process"]
    fn linux_isolation_setup_runs_in_disposable_helper_process() {
        use ::std::process::Command;

        let current_exe = ::std::env::current_exe().expect("current exe");
        let output = Command::new(current_exe)
            .arg("--nocapture")
            .arg("--exact")
            .arg("--ignored")
            .arg("tests::linux_isolation_setup_helper_entrypoint")
            .env("NVX_AGENT_ISOLATION_HELPER", "1")
            .output()
            .expect("helper output");
        assert!(
            output.status.success(),
            "helper failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "helper subprocess entrypoint for full isolation setup test"]
    fn linux_isolation_setup_helper_entrypoint() {
        if ::std::env::var_os("NVX_AGENT_ISOLATION_HELPER").is_none() {
            return;
        }
        let plan = default_isolation_plan();
        let result = apply_and_verify_workload_isolation(&plan).expect("isolation setup");
        assert!(result.holder_pid > 0, "holder pid must be positive");
        assert!(
            result.status.pid_namespace,
            "pid namespace isolation missing"
        );
        assert!(
            result.status.mount_namespace,
            "mount namespace isolation missing"
        );
        assert!(
            result.status.uts_namespace,
            "uts namespace isolation missing"
        );
        assert!(
            result.status.ipc_namespace,
            "ipc namespace isolation missing"
        );
        assert!(result.status.private_proc, "private /proc missing");
        assert!(result.status.private_dev, "private /dev missing");
        assert!(result.status.private_devpts, "private /dev/pts missing");
        assert!(result.status.private_shm, "private /dev/shm missing");
        assert!(result.status.read_only_sys, "read-only /sys missing");
        assert!(
            result.status.capabilities_dropped,
            "capability clearing missing"
        );
        assert!(result.status.no_new_privs, "no_new_privs missing");
        assert!(
            result.status.cgroup_separation,
            "cgroup separation not verified"
        );
        assert!(result.status.orphan_reaping, "orphan reaping not enabled");
    }
}
