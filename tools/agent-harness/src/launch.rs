use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

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
    child: Child,
}

impl Drop for LaunchedVm {
    fn drop(&mut self) {
        let _ = kill_child_process_tree(&mut self.child);
    }
}

impl LaunchedVm {
    pub fn wait_for_exit(&mut self) {
        let _ = self.child.wait();
    }

    pub fn kill(&mut self) {
        let _ = kill_child_process_tree(&mut self.child);
    }

    pub fn process_id(&self) -> u32 {
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

pub fn startupinfoex_handle_allowlist(capability_read_handle: usize) -> Vec<usize> {
    vec![capability_read_handle]
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

pub fn kill_child_process_tree(child: &mut Child) -> Result<(), String> {
    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Stop-Process -Id {} -Force", child.id()),
            ])
            .status()
            .map_err(|error| format!("failed to execute Stop-Process: {error}"))?;
        if !status.success() {
            return Err(format!("Stop-Process failed for pid {}", child.id()));
        }
    }
    #[cfg(not(windows))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
    Ok(())
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
        let handles = startupinfoex_handle_allowlist(77);
        assert_eq!(handles, vec![77]);
    }
}
