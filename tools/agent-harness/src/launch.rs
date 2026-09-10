use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation,
};
#[cfg(windows)]
use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::WriteFile;
#[cfg(windows)]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
#[cfg(windows)]
use windows::Win32::System::Pipes::CreatePipe;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, WaitForSingleObject,
};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};

const DEFAULT_INITRAMFS: &str = "initramfs-mxc-agent.cpio.gz";

#[derive(Clone, Debug, Default)]
pub struct LaunchOverrides {
    pub openvmm_exe: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub mxc_initramfs: Option<PathBuf>,
    pub common_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct MissingPrerequisite {
    pub field: &'static str,
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct LaunchArtifacts {
    pub openvmm_exe: PathBuf,
    pub kernel: PathBuf,
    pub mxc_initramfs: PathBuf,
    pub common_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct LaunchPlan {
    pub artifacts: LaunchArtifacts,
    pub control_pipe_name: String,
    pub boot_pipe_name: String,
    pub launch_capability: [u8; 32],
    pub channel_generation: u64,
    pub launch_nonce: [u8; 16],
    pub process_log_path: PathBuf,
}

pub struct LaunchedVm {
    pub plan: LaunchPlan,
    #[cfg(not(windows))]
    child: Child,
    #[cfg(windows)]
    process_handle: OwnedHandle,
    #[cfg(windows)]
    job_handle: Option<OwnedHandle>,
    #[cfg(windows)]
    pid: u32,
}

impl Drop for LaunchedVm {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            let _ = close_job_handle_and_kill(self);
        }
        #[cfg(not(windows))]
        {
            let _ = kill_child_process_tree(&mut self.child);
        }
    }
}

impl LaunchedVm {
    pub fn wait_for_exit(&mut self) {
        #[cfg(windows)]
        {
            // SAFETY: process handle belongs to this launched VM instance.
            let _ = unsafe {
                WaitForSingleObject(HANDLE(self.process_handle.as_raw_handle()), INFINITE)
            };
        }
        #[cfg(not(windows))]
        let _ = self.child.wait();
    }

    pub fn kill(&mut self) {
        #[cfg(windows)]
        {
            let _ = close_job_handle_and_kill(self);
        }
        #[cfg(not(windows))]
        {
            let _ = kill_child_process_tree(&mut self.child);
        }
    }

    pub fn process_id(&self) -> u32 {
        #[cfg(windows)]
        {
            self.pid
        }
        #[cfg(not(windows))]
        self.child.id()
    }
}

pub fn discover_artifacts(
    output_dir: &Path,
    overrides: &LaunchOverrides,
) -> Result<LaunchArtifacts, MissingPrerequisite> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..");
    let openvmm_exe = overrides.openvmm_exe.clone().unwrap_or_else(|| {
        repo_root
            .join("openvmm")
            .join("target")
            .join("release")
            .join(if cfg!(windows) {
                "openvmm.exe"
            } else {
                "openvmm"
            })
    });
    let kernel = overrides
        .kernel
        .clone()
        .unwrap_or_else(|| repo_root.join("build").join("vmlinux"));
    let mxc_initramfs = overrides
        .mxc_initramfs
        .clone()
        .unwrap_or_else(|| repo_root.join("build").join(DEFAULT_INITRAMFS));
    let common_root = overrides
        .common_root
        .clone()
        .unwrap_or_else(|| output_dir.join("common-root"));

    for (field, path) in [
        ("openvmm_exe", &openvmm_exe),
        ("kernel", &kernel),
        ("mxc_initramfs", &mxc_initramfs),
    ] {
        if !path.is_file() {
            return Err(MissingPrerequisite {
                field,
                path: path.clone(),
                reason: "required file is missing".to_string(),
            });
        }
    }
    if !common_root.exists() {
        std::fs::create_dir_all(&common_root).map_err(|error| MissingPrerequisite {
            field: "common_root",
            path: common_root.clone(),
            reason: format!("failed to create directory: {error}"),
        })?;
    }
    if !common_root.is_dir() {
        return Err(MissingPrerequisite {
            field: "common_root",
            path: common_root,
            reason: "must be a directory".to_string(),
        });
    }

    Ok(LaunchArtifacts {
        openvmm_exe,
        kernel,
        mxc_initramfs,
        common_root,
    })
}

pub fn build_launch_plan(output_dir: &Path, artifacts: LaunchArtifacts) -> LaunchPlan {
    let mut launch_capability = [0_u8; 32];
    rand::rng().fill(&mut launch_capability);
    let mut launch_nonce = [0_u8; 16];
    rand::rng().fill(&mut launch_nonce);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let owner = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "owner".to_string());
    let run_id = format!("{}-{}-{}", owner, std::process::id(), stamp);

    LaunchPlan {
        artifacts,
        control_pipe_name: format!(r"\\.\pipe\nvx-mxc-control-{run_id}"),
        boot_pipe_name: format!(r"\\.\pipe\nvx-mxc-boot-{run_id}"),
        launch_capability,
        channel_generation: 1,
        launch_nonce,
        process_log_path: output_dir.join("openvmm-process.log"),
    }
}

pub fn launch_whp_vm(plan: LaunchPlan) -> Result<LaunchedVm, String> {
    let capability_hex = hex_encode(&plan.launch_capability);
    let cmdline = format!(
        "nvx.launch_capability={capability_hex} nvx.channel_generation={}",
        plan.channel_generation
    );
    let args = vec![
        "--single-process".to_string(),
        "--machine".to_string(),
        "microvm".to_string(),
        "--hypervisor".to_string(),
        "whp".to_string(),
        "--memory".to_string(),
        "256M".to_string(),
        "--kernel".to_string(),
        os_arg(&plan.artifacts.kernel),
        "--initrd".to_string(),
        os_arg(&plan.artifacts.mxc_initramfs),
        "--virtio-console".to_string(),
        format!("listen={}", plan.boot_pipe_name),
        "--microvm-control-console".to_string(),
        format!("listen={}", plan.control_pipe_name),
        "--cmdline".to_string(),
        cmdline,
    ];
    #[cfg(windows)]
    {
        launch_whp_vm_windows(plan, args)
    }
    #[cfg(not(windows))]
    {
        let log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&plan.process_log_path)
            .map_err(|error| {
                format!(
                    "failed to create OpenVMM process log {}: {error}",
                    plan.process_log_path.display()
                )
            })?;
        let log2 = log
            .try_clone()
            .map_err(|error| format!("failed to clone OpenVMM log handle: {error}"))?;
        let child = Command::new(&plan.artifacts.openvmm_exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|error| {
                format!(
                    "failed to launch OpenVMM {}: {error}",
                    plan.artifacts.openvmm_exe.display()
                )
            })?;
        Ok(LaunchedVm { plan, child })
    }
}

pub fn startupinfoex_handle_allowlist(
    capability_read_handle: usize,
    inherited_stdio_handles: &[usize],
) -> Vec<usize> {
    let mut handles = Vec::with_capacity(1 + inherited_stdio_handles.len());
    handles.push(capability_read_handle);
    handles.extend_from_slice(inherited_stdio_handles);
    handles.sort_unstable();
    handles.dedup();
    handles
}

#[cfg(windows)]
struct InheritedAuthPipe {
    read: HANDLE,
    write: HANDLE,
}

#[cfg(windows)]
struct ProcThreadAttributeList {
    storage: Vec<u8>,
}

#[cfg(windows)]
impl ProcThreadAttributeList {
    fn with_handle_allowlist(allowlist: &[HANDLE]) -> Result<Self, String> {
        let mut bytes = 0usize;
        // SAFETY: size probe call with null list follows Win32 contract.
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, Some(0), &mut bytes) };
        if bytes == 0 {
            return Err("InitializeProcThreadAttributeList size probe failed".to_string());
        }
        let mut storage = vec![0_u8; bytes];
        let list_ptr = windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(
            storage.as_mut_ptr().cast(),
        );
        // SAFETY: storage is valid for the requested attribute-list allocation.
        let init =
            unsafe { InitializeProcThreadAttributeList(Some(list_ptr), 1, Some(0), &mut bytes) };
        if init.is_err() {
            return Err("InitializeProcThreadAttributeList allocation failed".to_string());
        }
        // SAFETY: list pointer and handle array are valid through the call.
        let updated = unsafe {
            windows::Win32::System::Threading::UpdateProcThreadAttribute(
                list_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(allowlist.as_ptr().cast::<c_void>()),
                core::mem::size_of_val(allowlist),
                None,
                None,
            )
        };
        if updated.is_err() {
            // SAFETY: list_ptr was initialized above.
            unsafe { DeleteProcThreadAttributeList(list_ptr) };
            return Err(
                "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST) failed".to_string(),
            );
        }
        Ok(Self { storage })
    }

    fn as_mut_ptr(&mut self) -> windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(
            self.storage.as_mut_ptr().cast(),
        )
    }
}

#[cfg(windows)]
impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        // SAFETY: attribute list is initialized when struct is constructed.
        unsafe {
            DeleteProcThreadAttributeList(
                windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(
                    self.storage.as_mut_ptr().cast(),
                ),
            )
        };
    }
}

#[cfg(windows)]
fn launch_whp_vm_windows(plan: LaunchPlan, mut args: Vec<String>) -> Result<LaunchedVm, String> {
    validate_openvmm_image_path(&plan.artifacts.openvmm_exe)?;
    let mut auth_pipe = create_inherited_auth_pipe()?;
    args.insert(args.len() - 2, "--microvm-control-auth-handle".to_string());
    args.insert(args.len() - 2, format!("{}", auth_pipe.read.0 as usize));

    let stdout_log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&plan.process_log_path)
        .map_err(|error| {
            format!(
                "failed to create OpenVMM process log {}: {error}",
                plan.process_log_path.display()
            )
        })?;
    let stderr_log = stdout_log
        .try_clone()
        .map_err(|error| format!("failed to clone OpenVMM process log handle: {error}"))?;
    let stdin_null = OpenOptions::new()
        .read(true)
        .open("NUL")
        .map_err(|error| format!("failed to open NUL for OpenVMM stdin: {error}"))?;

    let stdio_handles = vec![
        stdin_null.as_raw_handle() as usize,
        stdout_log.as_raw_handle() as usize,
        stderr_log.as_raw_handle() as usize,
    ];
    let allowlist_usize = startupinfoex_handle_allowlist(auth_pipe.read.0 as usize, &stdio_handles);
    let allowlist: Vec<HANDLE> = allowlist_usize
        .iter()
        .map(|value| HANDLE(*value as *mut c_void))
        .collect();
    let mut attr_list = ProcThreadAttributeList::with_handle_allowlist(&allowlist)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = HANDLE(stdin_null.as_raw_handle());
    startup.StartupInfo.hStdOutput = HANDLE(stdout_log.as_raw_handle());
    startup.StartupInfo.hStdError = HANDLE(stderr_log.as_raw_handle());
    startup.lpAttributeList = attr_list.as_mut_ptr();

    let mut process_info = PROCESS_INFORMATION::default();
    let app = wide_null(&os_arg(&plan.artifacts.openvmm_exe));
    let mut command_line = build_windows_command_line(&plan.artifacts.openvmm_exe, &args);
    // SAFETY: all pointers remain valid for the duration of CreateProcessW.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            PROCESS_CREATION_FLAGS(EXTENDED_STARTUPINFO_PRESENT.0),
            None,
            None,
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    if let Err(error) = created {
        let _ = close_handle_if_valid(&mut auth_pipe.read);
        let _ = close_handle_if_valid(&mut auth_pipe.write);
        return Err(format!("CreateProcessW failed for OpenVMM: {error}"));
    }
    // SAFETY: thread handle is returned by CreateProcessW and is no longer needed.
    let _ = unsafe { CloseHandle(process_info.hThread) };

    write_auth_capability_and_close(&mut auth_pipe, &plan.launch_capability)?;
    let job_handle = create_kill_on_close_job(process_info.hProcess)?;
    let process_handle = owned_from_handle(process_info.hProcess)?;

    Ok(LaunchedVm {
        plan,
        process_handle,
        job_handle: Some(job_handle),
        pid: process_info.dwProcessId,
    })
}

#[cfg(windows)]
fn validate_openvmm_image_path(path: &Path) -> Result<(), String> {
    let expected = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "OpenVMM executable path must end with a file name".to_string())?;
    if !expected.eq_ignore_ascii_case("openvmm.exe") {
        return Err(format!(
            "unexpected OpenVMM executable image name {expected:?}; expected openvmm.exe"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn create_inherited_auth_pipe() -> Result<InheritedAuthPipe, String> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut::<SECURITY_DESCRIPTOR>() as *mut _,
        bInheritHandle: true.into(),
    };
    // SAFETY: read/write pointers and SECURITY_ATTRIBUTES are valid for CreatePipe.
    let ok = unsafe { CreatePipe(&mut read, &mut write, Some(&security), 0) };
    if ok.is_err() {
        return Err("CreatePipe for OpenVMM auth handle failed".to_string());
    }
    // SAFETY: write handle is valid and owned by this process.
    let non_inherit_write =
        unsafe { SetHandleInformation(write, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) };
    if non_inherit_write.is_err() {
        let _ = close_handle_if_valid(&mut read);
        let _ = close_handle_if_valid(&mut write);
        return Err("failed to clear inheritance on auth pipe write handle".to_string());
    }
    Ok(InheritedAuthPipe { read, write })
}

#[cfg(windows)]
fn write_auth_capability_and_close(
    pipe: &mut InheritedAuthPipe,
    capability: &[u8; 32],
) -> Result<(), String> {
    let mut bytes_written = 0_u32;
    // SAFETY: handle and fixed-size byte slice are valid for WriteFile.
    let write_result = unsafe {
        WriteFile(
            pipe.write,
            Some(capability.as_slice()),
            Some(&mut bytes_written),
            None,
        )
    };
    let read_close = close_handle_if_valid(&mut pipe.read);
    let write_close = close_handle_if_valid(&mut pipe.write);
    if write_result.is_err()
        || bytes_written != capability.len() as u32
        || read_close.is_err()
        || write_close.is_err()
    {
        return Err("failed to write complete OpenVMM control capability".to_string());
    }
    Ok(())
}

fn os_arg(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(not(windows))]
pub fn kill_child_process_tree(child: &mut Child) -> Result<(), String> {
    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Ok(());
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

#[cfg(windows)]
fn close_job_handle_and_kill(vm: &mut LaunchedVm) -> Result<(), String> {
    if let Some(job) = vm.job_handle.take() {
        let raw = HANDLE(job.as_raw_handle());
        std::mem::forget(job);
        // SAFETY: close the job handle; KILL_ON_JOB_CLOSE tears down attached process tree.
        let closed_job = unsafe { CloseHandle(raw) };
        if closed_job.is_err() {
            return Err("failed to close OpenVMM job handle".to_string());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn create_kill_on_close_job(process: HANDLE) -> Result<OwnedHandle, String> {
    // SAFETY: CreateJobObjectW returns a valid handle or null.
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|error| format!("CreateJobObjectW failed: {error}"))?;
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION::default(),
        ..Default::default()
    };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: info pointer/size are valid for this info class.
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured.is_err() {
        // SAFETY: job handle is valid and local.
        let _ = unsafe { CloseHandle(job) };
        return Err("SetInformationJobObject(KILL_ON_JOB_CLOSE) failed".to_string());
    }
    // SAFETY: job and process handles are valid and owned by this process.
    let assigned = unsafe { AssignProcessToJobObject(job, process) };
    if assigned.is_err() {
        let _ = unsafe { CloseHandle(job) };
        return Err("AssignProcessToJobObject failed".to_string());
    }
    owned_from_handle(job)
}

#[cfg(windows)]
fn close_handle_if_valid(handle: &mut HANDLE) -> Result<(), String> {
    if handle.0.is_null() {
        return Ok(());
    }
    // SAFETY: handle is process-owned and valid when non-null.
    let result = unsafe { CloseHandle(*handle) };
    handle.0 = std::ptr::null_mut();
    result
        .map_err(|error| format!("CloseHandle failed: {error}"))
        .map(|_| ())
}

#[cfg(windows)]
fn owned_from_handle(raw: HANDLE) -> Result<OwnedHandle, String> {
    if raw.0.is_null() {
        return Err("unexpected null Win32 handle".to_string());
    }
    // SAFETY: raw comes from a successful Win32 handle-creation call and is uniquely owned.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw.0) })
}

#[cfg(windows)]
fn build_windows_command_line(exe: &Path, args: &[String]) -> Vec<u16> {
    let mut rendered = quote_windows_arg(&os_arg(exe));
    for arg in args {
        rendered.push(' ');
        rendered.push_str(&quote_windows_arg(arg));
    }
    wide_null(&rendered)
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_arg(arg: &str) -> String {
    if !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut slashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                if slashes > 0 {
                    out.push_str(&"\\".repeat(slashes));
                    slashes = 0;
                }
                out.push(ch);
            }
        }
    }
    if slashes > 0 {
        out.push_str(&"\\".repeat(slashes * 2));
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_artifact_discovery_reports_missing_openvmm() {
        let root = std::env::temp_dir().join(format!("launch-discovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        let result = discover_artifacts(&root, &LaunchOverrides::default());
        assert!(result.is_err());
        let error = result.expect_err("missing openvmm expected");
        assert!(!error.field.is_empty());
    }

    #[test]
    fn plan_produces_pipe_names_and_32_byte_capability() {
        let root = std::env::temp_dir().join(format!("launch-plan-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let artifacts = LaunchArtifacts {
            openvmm_exe: PathBuf::from("openvmm"),
            kernel: PathBuf::from("vmlinux"),
            mxc_initramfs: PathBuf::from("initramfs"),
            common_root: root.join("common"),
        };
        let plan = build_launch_plan(&root, artifacts);
        assert_eq!(plan.launch_capability.len(), 32);
        assert!(plan.control_pipe_name.starts_with(r"\\.\pipe\"));
        assert!(plan.boot_pipe_name.starts_with(r"\\.\pipe\"));
    }

    #[test]
    fn startupinfoex_allowlist_contains_only_capability_read_handle() {
        let handles = startupinfoex_handle_allowlist(77, &[]);
        assert_eq!(handles, vec![77]);
    }
}
