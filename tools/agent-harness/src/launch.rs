use std::fs::OpenOptions;
#[cfg(windows)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::thread::JoinHandle;
#[cfg(not(windows))]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use crate::named_pipe::NamedPipeClient;
use rand::Rng;
#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use windows::Win32::Foundation::DUPLICATE_SAME_ACCESS;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
#[cfg(all(windows, test))]
use windows::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::WriteFile;
#[cfg(windows)]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
#[cfg(windows)]
use windows::Win32::System::Pipes::CreatePipe;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetCurrentProcess, INFINITE, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};

const DEFAULT_INITRAMFS: &str = "initramfs-mxc-agent.cpio.gz";
const OPENVMM_MICROVM_PIPE_PREFIX: &str = "//./pipe/openvmm-microvm-";
#[cfg(windows)]
const TEARDOWN_WAIT_MS: u32 = 5_000;
#[cfg(windows)]
const BOOT_CONSOLE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const BOOT_CONSOLE_CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const BOOT_CONSOLE_POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(windows)]
const BOOT_CONSOLE_MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct LaunchOverrides {
    pub openvmm_exe: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub mxc_initramfs: Option<PathBuf>,
    pub common_root: Option<PathBuf>,
    pub portable_network: Option<String>,
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
    pub portable_network: Option<String>,
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
    pub boot_console_log_path: PathBuf,
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
    #[cfg(windows)]
    boot_console_capture: Option<BootConsoleCapture>,
}

impl Drop for LaunchedVm {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            let _ = self.kill();
        }
        #[cfg(not(windows))]
        {
            let _ = self.kill();
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

    pub fn kill(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        {
            close_job_handle_and_kill(self)
        }
        #[cfg(not(windows))]
        {
            kill_child_process_tree(&mut self.child)
        }
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.kill()
    }

    pub fn process_id(&self) -> u32 {
        #[cfg(windows)]
        {
            self.pid
        }
        #[cfg(not(windows))]
        self.child.id()
    }

    pub fn wait_for_exit_with_timeout(&mut self, timeout: Duration) -> Result<bool, String> {
        #[cfg(windows)]
        {
            let timeout_ms = timeout.as_millis().min(u128::from(u32::MAX)) as u32;
            wait_for_process_exit(HANDLE(self.process_handle.as_raw_handle()), timeout_ms)
        }
        #[cfg(not(windows))]
        {
            let deadline = Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now);
            loop {
                if self
                    .child
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_some()
                {
                    return Ok(true);
                }
                if Instant::now() >= deadline {
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
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
        openvmm_exe: absolute_artifact_path("openvmm_exe", &openvmm_exe)?,
        kernel: absolute_artifact_path("kernel", &kernel)?,
        mxc_initramfs: absolute_artifact_path("mxc_initramfs", &mxc_initramfs)?,
        common_root: absolute_artifact_path("common_root", &common_root)?,
        portable_network: overrides.portable_network.clone(),
    })
}

fn absolute_artifact_path(
    field: &'static str,
    path: &Path,
) -> Result<PathBuf, MissingPrerequisite> {
    std::path::absolute(path).map_err(|error| MissingPrerequisite {
        field,
        path: path.to_path_buf(),
        reason: format!("failed to make path absolute: {error}"),
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
    let owner = sanitize_pipe_name_component(&owner);
    let mut uniqueness = [0_u8; 8];
    rand::rng().fill(&mut uniqueness);
    let run_id = format!(
        "{owner}-{}-{stamp:x}-{:016x}",
        std::process::id(),
        u64::from_le_bytes(uniqueness)
    );

    LaunchPlan {
        artifacts,
        control_pipe_name: format!("{OPENVMM_MICROVM_PIPE_PREFIX}control-{run_id}"),
        boot_pipe_name: format!("{OPENVMM_MICROVM_PIPE_PREFIX}boot-{run_id}"),
        launch_capability,
        channel_generation: 1,
        launch_nonce,
        process_log_path: output_dir.join("openvmm-process.log"),
        boot_console_log_path: output_dir.join("boot-console.log"),
    }
}

fn sanitize_pipe_name_component(input: &str) -> String {
    let mut sanitized = String::with_capacity(input.len());
    let mut previous_dash = false;
    for byte in input.bytes() {
        let mapped = match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' => byte as char,
            b'A'..=b'Z' => (byte as char).to_ascii_lowercase(),
            b'-' => '-',
            _ => '-',
        };
        if mapped == '-' {
            if previous_dash {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }
        sanitized.push(mapped);
    }
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "owner".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn launch_whp_vm(plan: LaunchPlan) -> Result<LaunchedVm, String> {
    let cmdline = format!("nvx.channel_generation={}", plan.channel_generation);
    let mount = mount_argument_for_common_root(&plan.artifacts.common_root)?;
    let mut args = vec![
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
        "--mount".to_string(),
        mount,
        "--virtio-console".to_string(),
        format!("listen={}", plan.boot_pipe_name),
        "--microvm-control-console".to_string(),
        format!("listen={}", plan.control_pipe_name),
        "--cmdline".to_string(),
        cmdline,
    ];
    if let Some(network) = &plan.artifacts.portable_network {
        args.extend([
            "--net".to_string(),
            network.clone(),
            "--network-profile".to_string(),
            "portable".to_string(),
        ]);
    }
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

fn mount_argument_for_common_root(common_root: &Path) -> Result<String, String> {
    let host_path = os_arg(common_root);
    if host_path.contains(',') {
        return Err(format!(
            "common-root path cannot contain commas for --mount: {}",
            common_root.display()
        ));
    }
    Ok(format!("/mnt/virtiofs,{host_path},rw"))
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
struct InheritedStdIoHandles {
    stdin: HANDLE,
    stdout: HANDLE,
    stderr: HANDLE,
}

#[cfg(windows)]
struct LaunchFailureGuard {
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    job: Option<OwnedHandle>,
    auth_pipe: Option<InheritedAuthPipe>,
}

#[cfg(windows)]
impl LaunchFailureGuard {
    fn new(process: OwnedHandle, thread: OwnedHandle, auth_pipe: InheritedAuthPipe) -> Self {
        Self {
            process: Some(process),
            thread: Some(thread),
            job: None,
            auth_pipe: Some(auth_pipe),
        }
    }

    fn process_handle(&self) -> Result<HANDLE, String> {
        let Some(process) = self.process.as_ref() else {
            return Err("launch failure guard lost process handle".to_string());
        };
        Ok(HANDLE(process.as_raw_handle()))
    }

    fn set_job(&mut self, job: OwnedHandle) {
        self.job = Some(job);
    }

    fn auth_pipe_mut(&mut self) -> Result<&mut InheritedAuthPipe, String> {
        self.auth_pipe
            .as_mut()
            .ok_or_else(|| "launch failure guard lost auth pipe".to_string())
    }

    fn take_success(mut self) -> Result<(OwnedHandle, OwnedHandle, u32), String> {
        let process = self
            .process
            .take()
            .ok_or_else(|| "launch success missing process handle".to_string())?;
        let job = self
            .job
            .take()
            .ok_or_else(|| "launch success missing kill-on-close job".to_string())?;
        let pid = unsafe {
            windows::Win32::System::Threading::GetProcessId(HANDLE(process.as_raw_handle()))
        };
        if pid == 0 {
            return Err("launch success missing valid process id".to_string());
        }
        self.thread.take();
        if let Some(mut pipe) = self.auth_pipe.take() {
            let _ = close_handle_if_valid(&mut pipe.read);
            let _ = close_handle_if_valid(&mut pipe.write);
        }
        Ok((process, job, pid))
    }
}

#[cfg(windows)]
impl Drop for LaunchFailureGuard {
    fn drop(&mut self) {
        if let Some(mut pipe) = self.auth_pipe.take() {
            let _ = close_handle_if_valid(&mut pipe.read);
            let _ = close_handle_if_valid(&mut pipe.write);
        }
        if let Some(job) = self.job.take() {
            drop(job);
        } else if let Some(process) = self.process.as_ref() {
            let process_handle = HANDLE(process.as_raw_handle());
            let _ = unsafe { TerminateProcess(process_handle, 1) };
        }
        if let Some(process) = self.process.as_ref() {
            let _ = unsafe { WaitForSingleObject(HANDLE(process.as_raw_handle()), 5_000) };
        }
    }
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
    let auth_pipe = create_auth_pipe()?;

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
    let mut inherited_stdio =
        duplicate_inheritable_stdio_handles(&stdin_null, &stdout_log, &stderr_log)?;
    let mut inherited_auth_read = duplicate_inheritable_handle(auth_pipe.read)?;
    args.insert(args.len() - 2, "--microvm-control-auth-handle".to_string());
    args.insert(
        args.len() - 2,
        format!("{}", inherited_auth_read.0 as usize),
    );

    let stdio_handles = vec![
        inherited_stdio.stdin.0 as usize,
        inherited_stdio.stdout.0 as usize,
        inherited_stdio.stderr.0 as usize,
    ];
    let allowlist_usize =
        startupinfoex_handle_allowlist(inherited_auth_read.0 as usize, &stdio_handles);
    let allowlist: Vec<HANDLE> = allowlist_usize
        .iter()
        .map(|value| HANDLE(*value as *mut c_void))
        .collect();
    let mut attr_list = ProcThreadAttributeList::with_handle_allowlist(&allowlist)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_stdio.stdin;
    startup.StartupInfo.hStdOutput = inherited_stdio.stdout;
    startup.StartupInfo.hStdError = inherited_stdio.stderr;
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
            PROCESS_CREATION_FLAGS(EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_SUSPENDED.0),
            None,
            None,
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    let _ = close_handle_if_valid(&mut inherited_auth_read);
    let _ = close_handle_if_valid(&mut inherited_stdio.stdin);
    let _ = close_handle_if_valid(&mut inherited_stdio.stdout);
    let _ = close_handle_if_valid(&mut inherited_stdio.stderr);
    if let Err(error) = created {
        return Err(format!("CreateProcessW failed for OpenVMM: {error}"));
    }
    let process_handle = owned_from_handle(process_info.hProcess)?;
    let thread_handle = owned_from_handle(process_info.hThread)?;
    let mut failure_guard = LaunchFailureGuard::new(process_handle, thread_handle, auth_pipe);

    failpoint(Failpoint::JobCreate)?;
    let job_handle = create_kill_on_close_job(failure_guard.process_handle()?)?;
    failure_guard.set_job(job_handle);

    failpoint(Failpoint::CapabilityWrite)?;
    write_auth_capability_and_close(failure_guard.auth_pipe_mut()?, &plan.launch_capability)?;

    let pid =
        unsafe { windows::Win32::System::Threading::GetProcessId(failure_guard.process_handle()?) };
    if pid == 0 {
        return Err("launched OpenVMM process has no valid process id".to_string());
    }
    let mut boot_console_capture = BootConsoleCapture::start(
        &plan.boot_pipe_name,
        &plan.boot_console_log_path,
        pid,
        &plan.artifacts.openvmm_exe,
    )?;
    if let Err(error) = failpoint(Failpoint::ResumeThread)
        .and_then(|()| resume_thread(failure_guard.thread.as_ref().expect("thread present")))
    {
        let capture_error = boot_console_capture.stop_and_join().err();
        return Err(match capture_error {
            Some(capture_error) => format!("{error}; {capture_error}"),
            None => error,
        });
    }
    let (process_handle, job_handle, pid) = match failure_guard.take_success() {
        Ok(success) => success,
        Err(error) => {
            let capture_error = boot_console_capture.stop_and_join().err();
            return Err(match capture_error {
                Some(capture_error) => format!("{error}; {capture_error}"),
                None => error,
            });
        }
    };

    Ok(LaunchedVm {
        plan,
        process_handle,
        job_handle: Some(job_handle),
        pid,
        boot_console_capture: Some(boot_console_capture),
    })
}

#[cfg(windows)]
struct BootConsoleCapture {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

#[cfg(windows)]
impl BootConsoleCapture {
    fn start(
        pipe_name: &str,
        artifact_path: &Path,
        expected_pid: u32,
        expected_image: &Path,
    ) -> Result<Self, String> {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(artifact_path)
            .map_err(|error| {
                format!(
                    "failed to create boot-console artifact {}: {error}",
                    artifact_path.display()
                )
            })?;

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let pipe_name = pipe_name.to_string();
        let artifact_path = artifact_path.to_path_buf();
        let expected_image = expected_image.to_string_lossy().into_owned();
        let worker = std::thread::Builder::new()
            .name("nvx-boot-console-capture".to_string())
            .spawn(move || {
                capture_boot_console(
                    &pipe_name,
                    &artifact_path,
                    expected_pid,
                    &expected_image,
                    &worker_stop,
                )
            })
            .map_err(|error| format!("failed to start boot-console capture worker: {error}"))?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    fn stop_and_join(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| "boot-console capture worker panicked".to_string())?
    }
}

#[cfg(windows)]
fn capture_boot_console(
    pipe_name: &str,
    artifact_path: &Path,
    expected_pid: u32,
    expected_image: &str,
    stop: &AtomicBool,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    let mut artifact = OpenOptions::new()
        .append(true)
        .open(artifact_path)
        .map_err(|error| {
            format!(
                "failed to open boot-console artifact {}: {error}",
                artifact_path.display()
            )
        })?;
    let mut pipe = match NamedPipeClient::connect(
        pipe_name,
        BOOT_CONSOLE_CONNECT_TIMEOUT,
        Some(expected_pid),
        Some(expected_image),
    ) {
        Ok(pipe) => pipe,
        Err(error) => {
            let message = format!("[boot-console capture failed: {error}]\n");
            artifact
                .write_all(&message.as_bytes()[..message.len().min(BOOT_CONSOLE_MAX_BYTES)])
                .map_err(|write_error| {
                    format!(
                        "boot-console connection failed ({error}); failed writing diagnostic artifact: {write_error}"
                    )
                })?;
            return Err(format!("failed to connect boot-console pipe: {error}"));
        }
    };
    let header = format!(
        "[boot-console connected pid={expected_pid} image={expected_image:?} max_bytes={BOOT_CONSOLE_MAX_BYTES} timeout_ms={}]\n",
        BOOT_CONSOLE_CAPTURE_TIMEOUT.as_millis()
    );
    let header_bytes = &header.as_bytes()[..header.len().min(BOOT_CONSOLE_MAX_BYTES)];
    artifact
        .write_all(header_bytes)
        .map_err(|error| format!("failed writing boot-console capture header: {error}"))?;
    drain_boot_console(
        &mut pipe,
        &mut artifact,
        stop,
        started,
        BOOT_CONSOLE_CAPTURE_TIMEOUT,
        BOOT_CONSOLE_MAX_BYTES - header_bytes.len(),
    )
}

#[cfg(windows)]
fn drain_boot_console(
    reader: &mut impl Read,
    writer: &mut impl Write,
    stop: &AtomicBool,
    started: std::time::Instant,
    timeout: Duration,
    max_bytes: usize,
) -> Result<(), String> {
    let mut captured = 0_usize;
    let mut buffer = [0_u8; 4096];
    while !stop.load(Ordering::Acquire) && started.elapsed() < timeout && captured < max_bytes {
        let remaining = max_bytes - captured;
        let read_len = buffer.len().min(remaining);
        match reader.read(&mut buffer[..read_len]) {
            Ok(0) => break,
            Ok(bytes_read) => {
                writer
                    .write_all(&buffer[..bytes_read])
                    .map_err(|error| format!("failed writing boot-console artifact: {error}"))?;
                captured += bytes_read;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(BOOT_CONSOLE_POLL_INTERVAL);
            }
            Err(error) => return Err(format!("failed reading boot-console pipe: {error}")),
        }
    }
    writer
        .flush()
        .map_err(|error| format!("failed flushing boot-console artifact: {error}"))
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
fn create_auth_pipe() -> Result<InheritedAuthPipe, String> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    // SAFETY: read/write pointers are valid for CreatePipe.
    let ok = unsafe { CreatePipe(&mut read, &mut write, None, 0) };
    if ok.is_err() {
        return Err("CreatePipe for OpenVMM auth handle failed".to_string());
    }
    Ok(InheritedAuthPipe { read, write })
}

#[cfg(windows)]
fn duplicate_inheritable_stdio_handles(
    stdin_null: &std::fs::File,
    stdout_log: &std::fs::File,
    stderr_log: &std::fs::File,
) -> Result<InheritedStdIoHandles, String> {
    Ok(InheritedStdIoHandles {
        stdin: duplicate_inheritable_handle(HANDLE(stdin_null.as_raw_handle()))?,
        stdout: duplicate_inheritable_handle(HANDLE(stdout_log.as_raw_handle()))?,
        stderr: duplicate_inheritable_handle(HANDLE(stderr_log.as_raw_handle()))?,
    })
}

#[cfg(windows)]
fn duplicate_inheritable_handle(source: HANDLE) -> Result<HANDLE, String> {
    let current = unsafe { GetCurrentProcess() };
    let mut duplicated = HANDLE::default();
    let duplicated_ok = unsafe {
        windows::Win32::Foundation::DuplicateHandle(
            current,
            source,
            current,
            &mut duplicated,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated_ok.is_err() {
        return Err("DuplicateHandle failed while creating inheritable launch handle".to_string());
    }
    Ok(duplicated)
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
    let close_injected_error = failpoint(Failpoint::CapabilityPipeClose).err();
    let read_close = close_handle_if_valid(&mut pipe.read);
    let write_close = close_handle_if_valid(&mut pipe.write);
    if close_injected_error.is_some()
        || write_result.is_err()
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
    if let Some(capture) = vm.boot_console_capture.as_ref() {
        capture.stop.store(true, Ordering::Release);
    }
    let teardown_result = terminate_openvmm_process_tree(vm);
    let capture_result = match vm.boot_console_capture.as_mut() {
        Some(capture) => capture.stop_and_join(),
        None => Ok(()),
    };
    vm.boot_console_capture = None;

    match (teardown_result, capture_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(teardown_error), Ok(())) => Err(teardown_error),
        (Ok(()), Err(capture_error)) => Err(capture_error),
        (Err(teardown_error), Err(capture_error)) => {
            Err(format!("{teardown_error}; {capture_error}"))
        }
    }
}

#[cfg(windows)]
fn terminate_openvmm_process_tree(vm: &mut LaunchedVm) -> Result<(), String> {
    let process = HANDLE(vm.process_handle.as_raw_handle());
    let mut uncertainty = None::<String>;

    if let Some(job) = vm.job_handle.as_ref() {
        let injected_close_failure = failpoint(Failpoint::TeardownCloseHandle).is_err();
        let raw = HANDLE(job.as_raw_handle());
        // SAFETY: close the job handle; KILL_ON_JOB_CLOSE tears down attached process tree.
        let closed_job = if injected_close_failure {
            Err(windows::core::Error::new(
                windows::core::HRESULT(0x8000_4005_u32 as i32),
                "injected teardown close failure",
            ))
        } else {
            unsafe { CloseHandle(raw) }
        };
        if let Err(error) = closed_job {
            uncertainty = Some(format!("failed to close OpenVMM job handle: {error}"));
            let terminate_job = unsafe { TerminateJobObject(raw, 1) };
            if let Err(terminate_error) = terminate_job {
                let _ = fallback_terminate_process(process);
                let detail = uncertainty.unwrap_or_default();
                uncertainty = Some(format!(
                    "{detail}; fallback TerminateJobObject also failed: {terminate_error}"
                ));
            }
        } else {
            let owned = vm
                .job_handle
                .take()
                .ok_or_else(|| "OpenVMM job handle disappeared during teardown".to_string())?;
            std::mem::forget(owned);
        }
    } else {
        let _ = fallback_terminate_process(process);
    }

    if !wait_for_process_exit(process, TEARDOWN_WAIT_MS)? {
        let _ = fallback_terminate_process(process);
        if !wait_for_process_exit(process, TEARDOWN_WAIT_MS)? {
            let base = uncertainty.unwrap_or_else(|| "OpenVMM teardown uncertain".to_string());
            return Err(format!(
                "{base}; OpenVMM process did not exit within {TEARDOWN_WAIT_MS} ms"
            ));
        }
    }

    if let Some(detail) = uncertainty {
        return Err(format!(
            "{detail}; fallback termination completed but teardown certainty is lost"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn fallback_terminate_process(process: HANDLE) -> Result<(), String> {
    if process_exited(process)? {
        return Ok(());
    }
    // SAFETY: process handle belongs to this launched VM instance.
    unsafe { TerminateProcess(process, 1) }
        .map_err(|error| format!("fallback TerminateProcess failed: {error}"))?;
    Ok(())
}

#[cfg(windows)]
fn process_exited(process: HANDLE) -> Result<bool, String> {
    // SAFETY: process handle belongs to this launched VM instance.
    let status = unsafe { WaitForSingleObject(process, 0) };
    match status {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err("WaitForSingleObject(0) failed while probing process exit".to_string()),
        other => Err(format!(
            "unexpected WaitForSingleObject(0) status while probing process exit: {other:?}"
        )),
    }
}

#[cfg(windows)]
fn wait_for_process_exit(process: HANDLE, timeout_ms: u32) -> Result<bool, String> {
    if failpoint(Failpoint::TeardownExitTimeout).is_err() {
        return Ok(false);
    }
    // SAFETY: process handle belongs to this launched VM instance.
    let status = unsafe { WaitForSingleObject(process, timeout_ms) };
    match status {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(format!(
            "WaitForSingleObject({timeout_ms}) failed while waiting for OpenVMM exit"
        )),
        other => Err(format!(
            "unexpected WaitForSingleObject({timeout_ms}) status while waiting for OpenVMM exit: {other:?}"
        )),
    }
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
    failpoint(Failpoint::JobAssign)?;
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
fn resume_thread(thread: &OwnedHandle) -> Result<(), String> {
    let thread_handle = HANDLE(thread.as_raw_handle());
    let resumed = unsafe { ResumeThread(thread_handle) };
    if resumed == u32::MAX {
        return Err("ResumeThread failed for OpenVMM process".to_string());
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failpoint {
    JobCreate,
    JobAssign,
    CapabilityWrite,
    CapabilityPipeClose,
    ResumeThread,
    TeardownCloseHandle,
    TeardownExitTimeout,
}

#[cfg(windows)]
fn failpoint(kind: Failpoint) -> Result<(), String> {
    let _ = kind;
    #[cfg(test)]
    {
        if launch_failpoint::should_fail(kind) {
            return Err(format!("injected launch failure at {kind:?}"));
        }
    }
    Ok(())
}

#[cfg(all(windows, test))]
mod launch_failpoint {
    use super::Failpoint;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Mutex, OnceLock};

    static FAILPOINT: AtomicU8 = AtomicU8::new(0);
    static FAILPOINT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub fn set(kind: Option<Failpoint>) {
        let id = match kind {
            Some(Failpoint::JobCreate) => 1,
            Some(Failpoint::JobAssign) => 2,
            Some(Failpoint::CapabilityWrite) => 3,
            Some(Failpoint::CapabilityPipeClose) => 4,
            Some(Failpoint::ResumeThread) => 5,
            Some(Failpoint::TeardownCloseHandle) => 6,
            Some(Failpoint::TeardownExitTimeout) => 7,
            None => 0,
        };
        FAILPOINT.store(id, Ordering::SeqCst);
    }

    pub fn should_fail(kind: Failpoint) -> bool {
        let want = match kind {
            Failpoint::JobCreate => 1,
            Failpoint::JobAssign => 2,
            Failpoint::CapabilityWrite => 3,
            Failpoint::CapabilityPipeClose => 4,
            Failpoint::ResumeThread => 5,
            Failpoint::TeardownCloseHandle => 6,
            Failpoint::TeardownExitTimeout => 7,
        };
        FAILPOINT.load(Ordering::SeqCst) == want
    }

    pub fn run_with<T>(kind: Option<Failpoint>, action: impl FnOnce() -> T) -> T {
        let lock = FAILPOINT_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock.lock().expect("failpoint lock");
        set(kind);
        let result = action();
        set(None);
        result
    }
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
    #[cfg(windows)]
    use std::process::Command;

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
    fn artifact_discovery_normalizes_relative_overrides_to_absolute_paths() {
        let relative_root =
            PathBuf::from("target").join(format!("launch-relative-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&relative_root);
        std::fs::create_dir_all(&relative_root).expect("create relative root");
        let openvmm = relative_root.join(if cfg!(windows) {
            "openvmm.exe"
        } else {
            "openvmm"
        });
        let kernel = relative_root.join("vmlinux");
        let initramfs = relative_root.join(DEFAULT_INITRAMFS);
        std::fs::write(&openvmm, b"openvmm").expect("openvmm");
        std::fs::write(&kernel, b"kernel").expect("kernel");
        std::fs::write(&initramfs, b"initramfs").expect("initramfs");
        let overrides = LaunchOverrides {
            openvmm_exe: Some(openvmm),
            kernel: Some(kernel),
            mxc_initramfs: Some(initramfs),
            common_root: Some(relative_root.join("common")),
            portable_network: None,
        };

        let artifacts =
            discover_artifacts(&relative_root.join("output"), &overrides).expect("artifacts");

        assert!(artifacts.openvmm_exe.is_absolute());
        assert!(artifacts.kernel.is_absolute());
        assert!(artifacts.mxc_initramfs.is_absolute());
        assert!(artifacts.common_root.is_absolute());
        std::fs::remove_dir_all(relative_root).expect("cleanup");
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
            portable_network: None,
        };
        let plan = build_launch_plan(&root, artifacts);
        assert_eq!(plan.launch_capability.len(), 32);
        assert!(
            plan.control_pipe_name
                .starts_with(OPENVMM_MICROVM_PIPE_PREFIX)
        );
        assert!(plan.boot_pipe_name.starts_with(OPENVMM_MICROVM_PIPE_PREFIX));
        assert_ne!(plan.control_pipe_name, plan.boot_pipe_name);
        assert!(plan.control_pipe_name.contains("-control-"));
        assert!(plan.boot_pipe_name.contains("-boot-"));
        assert_eq!(plan.boot_console_log_path, root.join("boot-console.log"));
    }

    #[test]
    fn sanitize_pipe_name_component_emits_openvmm_safe_charset() {
        let safe = sanitize_pipe_name_component("Moda Nish/DEV@123");
        assert_eq!(safe, "moda-nish-dev-123");
        assert_eq!(sanitize_pipe_name_component("$$$"), "owner");
    }

    #[test]
    fn mount_argument_uses_microvm_tagged_root() {
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\tmp\common-root")
        } else {
            PathBuf::from("/tmp/common-root")
        };
        let mount = mount_argument_for_common_root(&root).expect("mount");
        assert!(mount.starts_with("/mnt/virtiofs,"));
        assert!(mount.ends_with(",rw"));
    }

    #[test]
    fn mount_argument_rejects_comma_in_host_path() {
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\tmp\comma,path")
        } else {
            PathBuf::from("/tmp/comma,path")
        };
        let error = mount_argument_for_common_root(&root).expect_err("comma path must fail");
        assert!(error.contains("cannot contain commas"));
    }

    #[test]
    fn startupinfoex_allowlist_contains_only_capability_read_handle() {
        let handles = startupinfoex_handle_allowlist(77, &[]);
        assert_eq!(handles, vec![77]);
    }

    #[cfg(windows)]
    #[test]
    fn boot_console_drain_enforces_byte_bound() {
        let payload = vec![0x5a; BOOT_CONSOLE_MAX_BYTES + 4096];
        let mut reader = std::io::Cursor::new(payload);
        let mut writer = Vec::new();
        drain_boot_console(
            &mut reader,
            &mut writer,
            &AtomicBool::new(false),
            std::time::Instant::now(),
            Duration::from_secs(1),
            BOOT_CONSOLE_MAX_BYTES,
        )
        .expect("bounded capture");
        assert_eq!(writer.len(), BOOT_CONSOLE_MAX_BYTES);
    }

    #[cfg(windows)]
    #[test]
    fn boot_console_drain_honors_teardown_stop() {
        let mut reader = std::io::Cursor::new(b"must not be captured".to_vec());
        let mut writer = Vec::new();
        drain_boot_console(
            &mut reader,
            &mut writer,
            &AtomicBool::new(true),
            std::time::Instant::now(),
            Duration::from_secs(1),
            BOOT_CONSOLE_MAX_BYTES,
        )
        .expect("stopped capture");
        assert!(writer.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn boot_console_capture_joins_worker_on_teardown() {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(())
        });
        let mut capture = BootConsoleCapture {
            stop,
            worker: Some(worker),
        };
        capture.stop_and_join().expect("join capture worker");
        assert!(capture.worker.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn startupinfoex_allowlist_is_exact_sorted_and_deduped() {
        let handles = startupinfoex_handle_allowlist(55, &[99, 55, 42, 99]);
        assert_eq!(handles, vec![42, 55, 99]);
    }

    #[cfg(windows)]
    #[test]
    fn duplicated_stdio_handles_are_inheritable() {
        let log_path = std::env::temp_dir().join(format!(
            "agent-harness-dup-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let stdout_log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_path)
            .expect("stdout log");
        let stderr_log = stdout_log.try_clone().expect("stderr log");
        let stdin_null = OpenOptions::new().read(true).open("NUL").expect("stdin");
        let mut duplicates =
            duplicate_inheritable_stdio_handles(&stdin_null, &stdout_log, &stderr_log)
                .expect("duplicate inheritable stdio handles");
        assert!(handle_is_inheritable(duplicates.stdin));
        assert!(handle_is_inheritable(duplicates.stdout));
        assert!(handle_is_inheritable(duplicates.stderr));
        let _ = close_handle_if_valid(&mut duplicates.stdin);
        let _ = close_handle_if_valid(&mut duplicates.stdout);
        let _ = close_handle_if_valid(&mut duplicates.stderr);
        let _ = std::fs::remove_file(log_path);
    }

    #[cfg(windows)]
    fn handle_is_inheritable(handle: HANDLE) -> bool {
        let mut flags = 0_u32;
        let ok = unsafe { GetHandleInformation(handle, &mut flags) };
        ok.is_ok() && (flags & HANDLE_FLAG_INHERIT.0) != 0
    }

    #[cfg(windows)]
    #[test]
    fn launch_failpoint_injects_job_create_failure() {
        let result = launch_failpoint::run_with(Some(Failpoint::JobCreate), || {
            failpoint(Failpoint::JobCreate)
        });
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn launch_failpoint_injects_capability_pipe_close_failure() {
        let result = launch_failpoint::run_with(Some(Failpoint::CapabilityPipeClose), || {
            failpoint(Failpoint::CapabilityPipeClose)
        });
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn launch_failpoint_injects_job_assign_failure() {
        let result = launch_failpoint::run_with(Some(Failpoint::JobAssign), || {
            failpoint(Failpoint::JobAssign)
        });
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn launch_failpoint_injects_resume_failure() {
        let result = launch_failpoint::run_with(Some(Failpoint::ResumeThread), || {
            failpoint(Failpoint::ResumeThread)
        });
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn capability_pipe_write_close_failpoint_closes_handles() {
        let mut pipe = create_auth_pipe().expect("auth pipe");
        let result = launch_failpoint::run_with(Some(Failpoint::CapabilityPipeClose), || {
            write_auth_capability_and_close(&mut pipe, &[0xAB; 32])
        });
        assert!(result.is_err());
        assert!(pipe.read.0.is_null());
        assert!(pipe.write.0.is_null());
    }

    #[cfg(windows)]
    #[test]
    fn capability_pipe_write_failpoint_is_reported() {
        let mut pipe = create_auth_pipe().expect("auth pipe");
        let result = launch_failpoint::run_with(Some(Failpoint::CapabilityWrite), || {
            failpoint(Failpoint::CapabilityWrite)
        });
        assert!(result.is_err());
        let _ = close_handle_if_valid(&mut pipe.read);
        let _ = close_handle_if_valid(&mut pipe.write);
    }

    #[cfg(windows)]
    #[test]
    fn launch_failure_guard_take_success_preserves_process_and_job_ownership() {
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 10 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn child");
        let process = owned_from_handle(
            duplicate_inheritable_handle(HANDLE(child.as_raw_handle())).expect("dup process"),
        )
        .expect("owned process");
        let thread = owned_from_handle(
            duplicate_inheritable_handle(HANDLE(child.as_raw_handle())).expect("dup thread"),
        )
        .expect("owned thread");
        let auth_pipe = create_auth_pipe().expect("auth pipe");
        let mut guard = LaunchFailureGuard::new(process, thread, auth_pipe);
        let job = create_kill_on_close_job(guard.process_handle().expect("process handle"))
            .expect("create job");
        guard.set_job(job);
        let (_process, _job, pid) = guard.take_success().expect("take success");
        assert_eq!(pid, child.id());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(windows)]
    #[test]
    fn vm_kill_reports_teardown_closehandle_uncertainty() {
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 10 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn child");
        let process_handle = owned_from_handle(
            duplicate_inheritable_handle(HANDLE(child.as_raw_handle())).expect("dup process"),
        )
        .expect("owned process");
        let job_handle = create_kill_on_close_job(HANDLE(process_handle.as_raw_handle()))
            .expect("create kill-on-close job");
        let plan = build_launch_plan(
            &std::env::temp_dir(),
            LaunchArtifacts {
                openvmm_exe: PathBuf::from("openvmm.exe"),
                kernel: PathBuf::from("vmlinux"),
                mxc_initramfs: PathBuf::from("initramfs-mxc-agent.cpio.gz"),
                common_root: std::env::temp_dir().join("common-root"),
                portable_network: None,
            },
        );
        let mut vm = LaunchedVm {
            plan,
            process_handle,
            job_handle: Some(job_handle),
            pid: child.id(),
            boot_console_capture: None,
        };
        let result = launch_failpoint::run_with(Some(Failpoint::TeardownCloseHandle), || vm.kill());
        assert!(result.is_err());
        let _ = child.wait();
    }

    #[cfg(windows)]
    #[test]
    fn vm_kill_reports_teardown_exit_timeout() {
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 5 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn child");
        let process_handle = owned_from_handle(
            duplicate_inheritable_handle(HANDLE(child.as_raw_handle())).expect("dup process"),
        )
        .expect("owned process");
        let job_handle = create_kill_on_close_job(HANDLE(process_handle.as_raw_handle()))
            .expect("create kill-on-close job");
        let plan = build_launch_plan(
            &std::env::temp_dir(),
            LaunchArtifacts {
                openvmm_exe: PathBuf::from("openvmm.exe"),
                kernel: PathBuf::from("vmlinux"),
                mxc_initramfs: PathBuf::from("initramfs-mxc-agent.cpio.gz"),
                common_root: std::env::temp_dir().join("common-root"),
                portable_network: None,
            },
        );
        let mut vm = LaunchedVm {
            plan,
            process_handle,
            job_handle: Some(job_handle),
            pid: child.id(),
            boot_console_capture: None,
        };
        let result = launch_failpoint::run_with(Some(Failpoint::TeardownExitTimeout), || vm.kill());
        assert!(result.is_err());
        let _ = child.wait();
    }

    #[cfg(windows)]
    #[test]
    fn process_exit_wait_respects_deadline_and_observes_real_exit() {
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn child");
        let process = HANDLE(child.as_raw_handle());
        let timed_out = wait_for_process_exit(process, 1).expect("short wait");
        assert!(!timed_out);
        let _ = child.kill();
        let _ = child.wait();
        assert!(wait_for_process_exit(process, TEARDOWN_WAIT_MS).expect("post-kill wait"));
    }
}
