use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(std::io::stderr(), "nvx-agent-probe error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err("missing subcommand".to_string());
    };
    match command.as_str() {
        "seq" => run_seq(args.collect()),
        "stream-split" => run_stream_split(),
        "stdin-roundtrip" => run_stdin_roundtrip(),
        "flood" => run_flood(args.collect()),
        "wait-stdin-eof" => run_wait_stdin_eof(),
        "signal-self" => run_signal_self(args.collect()),
        "spawn-tree" => run_spawn_tree(args.collect()),
        "check-pids-gone" => run_check_pids_gone(args.collect()),
        "child-loop" => run_child_loop(args.collect()),
        "grandchild-loop" => run_grandchild_loop(args.collect()),
        "identity-json" => run_identity_json(),
        "isolation-json" => run_isolation_json(args.collect()),
        "mapping-check" => run_mapping_check(args.collect()),
        other => Err(format!("unknown subcommand {other:?}")),
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct IdentityReport {
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    supplementary_gids: Vec<u32>,
    username: Option<String>,
    groupname: Option<String>,
}

#[cfg(target_os = "linux")]
fn run_identity_json() -> Result<()> {
    let mut ruid = 0_u32;
    let mut euid = 0_u32;
    let mut suid = 0_u32;
    let mut rgid = 0_u32;
    let mut egid = 0_u32;
    let mut sgid = 0_u32;
    // SAFETY: pointers are valid and point to initialized storage.
    let uid_rc = unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) };
    // SAFETY: pointers are valid and point to initialized storage.
    let gid_rc = unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) };
    if uid_rc != 0 || gid_rc != 0 {
        // SAFETY: direct process identity syscalls.
        ruid = unsafe { libc::getuid() };
        // SAFETY: direct process identity syscalls.
        euid = unsafe { libc::geteuid() };
        suid = euid;
        // SAFETY: direct process identity syscalls.
        rgid = unsafe { libc::getgid() };
        // SAFETY: direct process identity syscalls.
        egid = unsafe { libc::getegid() };
        sgid = egid;
    }
    let supplementary_gids = read_groups()?;
    let report = IdentityReport {
        real_uid: ruid,
        effective_uid: euid,
        saved_uid: suid,
        real_gid: rgid,
        effective_gid: egid,
        saved_gid: sgid,
        supplementary_gids,
        username: username_for_uid(euid),
        groupname: group_for_gid(egid),
    };
    write_json(&report)
}

#[cfg(not(target_os = "linux"))]
fn run_identity_json() -> Result<()> {
    Err("identity-json requires Linux guest runtime".to_string())
}

#[derive(Serialize)]
struct NamespaceIds {
    pid: String,
    mount: String,
    uts: String,
    ipc: String,
}

#[derive(Serialize)]
struct ProcIdentity {
    name: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[derive(Serialize)]
struct CapabilityReport {
    inheritable: String,
    permitted: String,
    effective: String,
    bounding: String,
    ambient: String,
    all_zero: bool,
}

#[derive(Clone, Serialize)]
struct MountInfo {
    path: String,
    fs_type: String,
    read_only: bool,
    options: String,
}

#[derive(Serialize)]
struct FdEntry {
    fd: i32,
    target: String,
}

#[derive(Serialize)]
struct IsolationReport {
    pid: u32,
    host_pid_visible: bool,
    namespaces: NamespaceIds,
    proc1: ProcIdentity,
    pid_namespace_matches_proc1: bool,
    root_mount: Option<MountInfo>,
    proc_mount: Option<MountInfo>,
    dev_mount: Option<MountInfo>,
    devpts_mount: Option<MountInfo>,
    shm_mount: Option<MountInfo>,
    sys_mount: Option<MountInfo>,
    private_proc: bool,
    private_dev: bool,
    private_devpts: bool,
    private_shm: bool,
    read_only_sys: bool,
    no_new_privs: bool,
    capabilities: CapabilityReport,
    open_fds: Vec<FdEntry>,
    raw_export_root_visible: bool,
    agent_initramfs_visible: bool,
    mountinfo_has_raw_virtiofs_root: bool,
}

fn run_isolation_json(args: Vec<String>) -> Result<()> {
    let mut host_pid = 0_u32;
    let mut raw_root = "/mnt/virtiofs".to_string();
    let mut expected_rw = "rw".to_string();
    let mut expected_ro = "ro".to_string();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--host-pid" => {
                host_pid = required_value(&args, index + 1, "--host-pid")?
                    .parse::<u32>()
                    .map_err(|error| format!("invalid --host-pid value: {error}"))?;
                index += 2;
            }
            "--raw-root" => {
                raw_root = required_value(&args, index + 1, "--raw-root")?.to_string();
                index += 2;
            }
            "--expected-rw" => {
                expected_rw = required_value(&args, index + 1, "--expected-rw")?.to_string();
                index += 2;
            }
            "--expected-ro" => {
                expected_ro = required_value(&args, index + 1, "--expected-ro")?.to_string();
                index += 2;
            }
            flag => return Err(format!("unknown isolation-json flag {flag:?}")),
        }
    }
    let status = proc_status_map("/proc/self/status")?;
    let cap_inh = status.get("CapInh").cloned().unwrap_or_default();
    let cap_prm = status.get("CapPrm").cloned().unwrap_or_default();
    let cap_eff = status.get("CapEff").cloned().unwrap_or_default();
    let cap_bnd = status.get("CapBnd").cloned().unwrap_or_default();
    let cap_amb = status.get("CapAmb").cloned().unwrap_or_default();
    let cap_all_zero = [
        cap_inh.as_str(),
        cap_prm.as_str(),
        cap_eff.as_str(),
        cap_bnd.as_str(),
        cap_amb.as_str(),
    ]
    .iter()
    .all(|value| u64::from_str_radix(value.trim(), 16).unwrap_or(u64::MAX) == 0);
    let no_new_privs = status
        .get("NoNewPrivs")
        .map(|value| value.trim() == "1")
        .unwrap_or(false);
    let self_pid_ns = read_link_string("/proc/self/ns/pid")?;
    let proc1_pid_ns = read_link_string("/proc/1/ns/pid")?;
    let root_mount = mount_for_path("/")?;
    let proc_mount = mount_for_path("/proc")?;
    let dev_mount = mount_for_path("/dev")?;
    let devpts_mount = mount_for_path("/dev/pts")?;
    let shm_mount = mount_for_path("/dev/shm")?;
    let sys_mount = mount_for_path("/sys")?;
    let raw_entries = fs::read_dir(&raw_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(std::result::Result::ok))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    let expected = [expected_rw.as_str(), expected_ro.as_str()];
    let raw_export_root_visible = raw_entries
        .iter()
        .any(|entry| !expected.contains(&entry.as_str()));
    let report = IsolationReport {
        pid: process::id(),
        host_pid_visible: host_pid != 0 && Path::new(&format!("/proc/{host_pid}")).exists(),
        namespaces: NamespaceIds {
            pid: self_pid_ns.clone(),
            mount: read_link_string("/proc/self/ns/mnt")?,
            uts: read_link_string("/proc/self/ns/uts")?,
            ipc: read_link_string("/proc/self/ns/ipc")?,
        },
        proc1: proc_identity("/proc/1/status")?,
        pid_namespace_matches_proc1: self_pid_ns == proc1_pid_ns,
        root_mount,
        proc_mount: proc_mount.clone(),
        dev_mount: dev_mount.clone(),
        devpts_mount: devpts_mount.clone(),
        shm_mount: shm_mount.clone(),
        sys_mount: sys_mount.clone(),
        private_proc: proc_mount
            .as_ref()
            .is_some_and(|mount| mount.path == "/proc" && mount.fs_type == "proc"),
        private_dev: dev_mount.as_ref().is_some_and(|mount| mount.path == "/dev"),
        private_devpts: devpts_mount
            .as_ref()
            .is_some_and(|mount| mount.path == "/dev/pts" && mount.fs_type == "devpts"),
        private_shm: shm_mount
            .as_ref()
            .is_some_and(|mount| mount.path == "/dev/shm" && mount.fs_type == "tmpfs"),
        read_only_sys: sys_mount.as_ref().is_some_and(|mount| mount.read_only),
        no_new_privs,
        capabilities: CapabilityReport {
            inheritable: cap_inh,
            permitted: cap_prm,
            effective: cap_eff,
            bounding: cap_bnd,
            ambient: cap_amb,
            all_zero: cap_all_zero,
        },
        open_fds: list_open_fds(),
        raw_export_root_visible,
        agent_initramfs_visible: Path::new("/initramfs-mxc-agent.cpio.gz").exists(),
        mountinfo_has_raw_virtiofs_root: proc_mountinfo_contains(" /mnt/virtiofs ", " virtiofs ")?,
    };
    write_json(&report)
}

#[derive(Serialize)]
struct MappingReport {
    rw_output_path: String,
    rw_bytes_hex: String,
    ro_seed_hex: String,
    ro_write_blocked: bool,
    ro_metadata_mutation_blocked: bool,
    undeclared_hidden: bool,
    raw_root_has_only_declared_destinations: bool,
    guest_destinations_exact: bool,
    ro_recursive_mount_read_only: bool,
}

fn run_mapping_check(args: Vec<String>) -> Result<()> {
    let mut rw_dir = None::<String>;
    let mut ro_file = None::<String>;
    let mut undeclared = None::<String>;
    let mut raw_root = "/mnt/virtiofs".to_string();
    let mut output_name = "guest-rw.bin".to_string();
    let mut expected_rw = "rw".to_string();
    let mut expected_ro = "ro".to_string();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--rw-dir" => {
                rw_dir = Some(required_value(&args, index + 1, "--rw-dir")?.to_string());
                index += 2;
            }
            "--ro-file" => {
                ro_file = Some(required_value(&args, index + 1, "--ro-file")?.to_string());
                index += 2;
            }
            "--undeclared-path" => {
                undeclared =
                    Some(required_value(&args, index + 1, "--undeclared-path")?.to_string());
                index += 2;
            }
            "--raw-root" => {
                raw_root = required_value(&args, index + 1, "--raw-root")?.to_string();
                index += 2;
            }
            "--output-name" => {
                output_name = required_value(&args, index + 1, "--output-name")?.to_string();
                index += 2;
            }
            "--expected-rw" => {
                expected_rw = required_value(&args, index + 1, "--expected-rw")?.to_string();
                index += 2;
            }
            "--expected-ro" => {
                expected_ro = required_value(&args, index + 1, "--expected-ro")?.to_string();
                index += 2;
            }
            flag => return Err(format!("unknown mapping-check flag {flag:?}")),
        }
    }
    let rw_dir = rw_dir.ok_or_else(|| "--rw-dir is required".to_string())?;
    let ro_file = ro_file.ok_or_else(|| "--ro-file is required".to_string())?;
    let undeclared = undeclared.ok_or_else(|| "--undeclared-path is required".to_string())?;

    let ro_seed =
        fs::read(&ro_file).map_err(|error| format!("reading ro seed file failed: {error}"))?;
    let ro_write_blocked = fs::OpenOptions::new()
        .write(true)
        .open(&ro_file)
        .and_then(|mut file| file.write_all(b"mutate"))
        .is_err();
    let ro_metadata_mutation_blocked = metadata_mutation_fails(Path::new(&ro_file));

    let payload = vec![0x00, 0x7F, 0x80, 0xFF, 0x13, 0x37, 0x2A, 0x00, 0x42];
    let output_path = Path::new(&rw_dir).join(&output_name);
    fs::write(&output_path, &payload)
        .map_err(|error| format!("writing rw output payload failed: {error}"))?;

    let raw_entries = fs::read_dir(&raw_root)
        .map_err(|error| format!("reading raw root failed: {error}"))?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    let expected = [expected_rw.as_str(), expected_ro.as_str()];
    let raw_root_has_only_declared_destinations = raw_entries
        .iter()
        .all(|entry| expected.contains(&entry.as_str()));

    let report = MappingReport {
        rw_output_path: output_path.display().to_string(),
        rw_bytes_hex: hex_bytes(&payload),
        ro_seed_hex: hex_bytes(&ro_seed),
        ro_write_blocked,
        ro_metadata_mutation_blocked,
        undeclared_hidden: !Path::new(&undeclared).exists(),
        raw_root_has_only_declared_destinations,
        guest_destinations_exact: Path::new(&rw_dir).exists()
            && Path::new(&ro_file).exists()
            && rw_dir.starts_with(&raw_root)
            && ro_file.starts_with(&raw_root),
        ro_recursive_mount_read_only: subtree_mounts_read_only(
            Path::new(&ro_file)
                .parent()
                .ok_or_else(|| "ro file has no parent".to_string())?,
        )?,
    };
    write_json(&report)
}

fn write_json<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    let encoded =
        serde_json::to_vec(value).map_err(|error| format!("serializing json: {error}"))?;
    stdout
        .write_all(&encoded)
        .map_err(|error| format!("writing json output: {error}"))?;
    stdout
        .write_all(b"\n")
        .map_err(|error| format!("writing json newline: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing json output: {error}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_groups() -> Result<Vec<u32>> {
    // SAFETY: probe call with size 0 follows getgroups contract.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err("getgroups size probe failed".to_string());
    }

    #[cfg(not(target_os = "linux"))]
    fn read_groups() -> Result<Vec<u32>> {
        Ok(Vec::new())
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: vector has capacity for count gids.
    let rc = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if rc < 0 {
        return Err("getgroups collection failed".to_string());
    }
    Ok(groups.into_iter().collect())
}

#[cfg(target_os = "linux")]
fn username_for_uid(uid: u32) -> Option<String> {
    passwd_lookup("/etc/passwd", uid)
}

#[cfg(target_os = "linux")]
fn group_for_gid(gid: u32) -> Option<String> {
    passwd_lookup("/etc/group", gid)
}

#[cfg(target_os = "linux")]
fn passwd_lookup(path: &str, id: u32) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[2].parse::<u32>().ok()? == id {
            return Some(fields[0].to_string());
        }
    }
    None
}

fn proc_status_map(path: &str) -> Result<BTreeMap<String, String>> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("reading {path} failed: {error}"))?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(map)
}

fn proc_identity(status_path: &str) -> Result<ProcIdentity> {
    let map = proc_status_map(status_path)?;
    let uid = map
        .get("Uid")
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok());
    let gid = map
        .get("Gid")
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok());
    Ok(ProcIdentity {
        name: map.get("Name").cloned(),
        uid,
        gid,
    })
}

fn read_link_string(path: &str) -> Result<String> {
    fs::read_link(path)
        .map(|target| target.display().to_string())
        .map_err(|error| format!("reading symlink {path} failed: {error}"))
}

fn mount_for_path(path: &str) -> Result<Option<MountInfo>> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("reading /proc/self/mountinfo failed: {error}"))?;
    let wanted = Path::new(path);
    let mut best: Option<(usize, MountInfo)> = None;
    for line in mountinfo.lines() {
        if let Some(entry) = parse_mountinfo_line(line)? {
            let mount_path = Path::new(&entry.path);
            if wanted.starts_with(mount_path) {
                let depth = mount_path.components().count();
                if best
                    .as_ref()
                    .is_none_or(|(best_depth, _)| depth >= *best_depth)
                {
                    best = Some((depth, entry));
                }
            }
        }
    }
    Ok(best.map(|(_, info)| info))
}

fn parse_mountinfo_line(line: &str) -> Result<Option<MountInfo>> {
    let Some((left, right)) = line.split_once(" - ") else {
        return Ok(None);
    };
    let left_fields: Vec<&str> = left.split_whitespace().collect();
    if left_fields.len() < 6 {
        return Ok(None);
    }
    let right_fields: Vec<&str> = right.split_whitespace().collect();
    if right_fields.is_empty() {
        return Ok(None);
    }
    let path = decode_mountinfo_path(left_fields[4])?;
    let options = left_fields[5].to_string();
    Ok(Some(MountInfo {
        path,
        fs_type: right_fields[0].to_string(),
        read_only: options.split(',').any(|opt| opt == "ro"),
        options,
    }))
}

fn decode_mountinfo_path(encoded: &str) -> Result<String> {
    let mut out = String::new();
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 3 >= bytes.len() {
                return Err(format!("invalid mountinfo escape in {encoded}"));
            }
            match &bytes[i..i + 4] {
                b"\\040" => out.push(' '),
                b"\\011" => out.push('\t'),
                b"\\012" => out.push('\n'),
                b"\\134" => out.push('\\'),
                _ => return Err(format!("unsupported mountinfo escape in {encoded}")),
            }
            i += 4;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

fn proc_mountinfo_contains(path_marker: &str, fs_marker: &str) -> Result<bool> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("reading /proc/self/mountinfo failed: {error}"))?;
    Ok(mountinfo
        .lines()
        .any(|line| line.contains(path_marker) && line.contains(fs_marker)))
}

fn list_open_fds() -> Vec<FdEntry> {
    let self_fd_dir = format!("/proc/{}/fd", process::id());
    let mut entries = fs::read_dir("/proc/self/fd")
        .ok()
        .into_iter()
        .flat_map(|iter| iter.filter_map(std::result::Result::ok))
        .filter_map(|entry| {
            let fd = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
            let target = fs::read_link(entry.path())
                .map(|value| value.display().to_string())
                .unwrap_or_else(|_| "<unavailable>".to_string());
            if target == self_fd_dir {
                return None;
            }
            Some(FdEntry { fd, target })
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.fd);
    entries
}

#[cfg(target_os = "linux")]
fn metadata_mutation_fails(path: &Path) -> bool {
    let mut perms = match fs::metadata(path) {
        Ok(metadata) => metadata.permissions(),
        Err(_) => return true,
    };
    let mode = perms.mode();
    perms.set_mode(mode ^ 0o111);
    fs::set_permissions(path, perms).is_err()
}

#[cfg(not(target_os = "linux"))]
fn metadata_mutation_fails(_path: &Path) -> bool {
    true
}

fn subtree_mounts_read_only(root: &Path) -> Result<bool> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("reading /proc/self/mountinfo failed: {error}"))?;
    let mut saw = false;
    for line in mountinfo.lines() {
        let Some(entry) = parse_mountinfo_line(line)? else {
            continue;
        };
        let mount_path = PathBuf::from(&entry.path);
        if mount_path == root || mount_path.starts_with(root) {
            saw = true;
            if !entry.read_only {
                return Ok(false);
            }
        }
    }
    Ok(saw)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn run_seq(args: Vec<String>) -> Result<()> {
    let mut token = "default".to_string();
    let mut exit_code = 0_i32;
    let mut sleep_ms = 0_u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--token" => {
                token = required_value(&args, index + 1, "--token")?.to_string();
                index += 2;
            }
            "--exit" => {
                exit_code = required_value(&args, index + 1, "--exit")?
                    .parse::<i32>()
                    .map_err(|error| format!("invalid --exit value: {error}"))?;
                index += 2;
            }
            "--sleep-ms" => {
                sleep_ms = required_value(&args, index + 1, "--sleep-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --sleep-ms value: {error}"))?;
                index += 2;
            }
            flag => return Err(format!("unknown seq flag {flag:?}")),
        }
    }
    if sleep_ms > 0 {
        thread::sleep(Duration::from_millis(sleep_ms));
    }
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    stdout
        .write_all(format!("seq:{token}\n").as_bytes())
        .map_err(|error| format!("writing stdout: {error}"))?;
    stderr
        .write_all(format!("seq-err:{token}\n").as_bytes())
        .map_err(|error| format!("writing stderr: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))?;
    stderr
        .flush()
        .map_err(|error| format!("flushing stderr: {error}"))?;
    process::exit(exit_code);
}

fn run_stream_split() -> Result<()> {
    let stdout_bytes = [b'A', 0, b'B', 0xff, b'C'];
    let stderr_bytes = [b'X', 0, b'Y', 0xfe, b'Z'];
    std::io::stdout()
        .write_all(&stdout_bytes)
        .map_err(|error| format!("writing stdout: {error}"))?;
    std::io::stderr()
        .write_all(&stderr_bytes)
        .map_err(|error| format!("writing stderr: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))?;
    std::io::stderr()
        .flush()
        .map_err(|error| format!("flushing stderr: {error}"))?;
    Ok(())
}

fn run_stdin_roundtrip() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| format!("reading stdin: {error}"))?;
    std::io::stdout()
        .write_all(&input)
        .map_err(|error| format!("writing stdout: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))?;
    Ok(())
}

fn run_flood(args: Vec<String>) -> Result<()> {
    let mut total = 0_usize;
    let mut chunk = 4096_usize;
    let mut stream = "stdout";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bytes" => {
                total = required_value(&args, index + 1, "--bytes")?
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --bytes value: {error}"))?;
                index += 2;
            }
            "--chunk" => {
                chunk = required_value(&args, index + 1, "--chunk")?
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --chunk value: {error}"))?;
                index += 2;
            }
            "--stream" => {
                stream = required_value(&args, index + 1, "--stream")?;
                index += 2;
            }
            flag => return Err(format!("unknown flood flag {flag:?}")),
        }
    }
    if total == 0 || chunk == 0 {
        return Err("flood requires --bytes > 0 and --chunk > 0".to_string());
    }
    let mut sent = 0_usize;
    let mut pattern_index = 0_u8;
    let mut writer: Box<dyn Write> = match stream {
        "stdout" => Box::new(std::io::stdout().lock()),
        "stderr" => Box::new(std::io::stderr().lock()),
        other => return Err(format!("unsupported --stream value {other:?}")),
    };
    while sent < total {
        let take = chunk.min(total - sent);
        let mut buffer = vec![0_u8; take];
        for byte in &mut buffer {
            *byte = pattern_index;
            pattern_index = pattern_index.wrapping_add(1);
        }
        writer
            .write_all(&buffer)
            .map_err(|error| format!("writing flood bytes: {error}"))?;
        sent += take;
    }
    writer
        .flush()
        .map_err(|error| format!("flushing flood bytes: {error}"))?;
    Ok(())
}

fn run_wait_stdin_eof() -> Result<()> {
    let mut sink = Vec::new();
    std::io::stdin()
        .read_to_end(&mut sink)
        .map_err(|error| format!("reading stdin to EOF: {error}"))?;
    std::io::stdout()
        .write_all(b"stdin-eof-observed\n")
        .map_err(|error| format!("writing EOF marker: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing EOF marker: {error}"))?;
    Ok(())
}

fn run_signal_self(args: Vec<String>) -> Result<()> {
    if args.len() != 2 || args[0] != "--signal" {
        return Err("signal-self requires --signal <number>".to_string());
    }
    let signal = args[1]
        .parse::<i32>()
        .map_err(|error| format!("invalid signal value: {error}"))?;
    // SAFETY: raising a caller-provided signal on this process.
    let rc = unsafe { libc::raise(signal) };
    if rc != 0 {
        return Err(format!("raise({signal}) failed with {rc}"));
    }
    Ok(())
}

fn run_spawn_tree(args: Vec<String>) -> Result<()> {
    let mut hold_ms = 30_000_u64;
    let mut ignore_term = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hold-ms" => {
                hold_ms = required_value(&args, index + 1, "--hold-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --hold-ms value: {error}"))?;
                index += 2;
            }
            "--ignore-term" => {
                ignore_term = true;
                index += 1;
            }
            flag => return Err(format!("unknown spawn-tree flag {flag:?}")),
        }
    }
    let exe = std::env::current_exe().map_err(|error| format!("current_exe failed: {error}"))?;
    let mut child = Command::new(&exe)
        .arg("child-loop")
        .arg("--hold-ms")
        .arg(hold_ms.to_string())
        .arg(if ignore_term {
            "--ignore-term"
        } else {
            "--respect-term"
        })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("spawning child-loop failed: {error}"))?;
    let child_pid = child.id();
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child-loop stdout was unavailable".to_string())?;
    let mut reader = std::io::BufReader::new(child_stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line)
        .map_err(|error| format!("reading child-loop pid line failed: {error}"))?;
    if line.trim().is_empty() {
        return Err("child-loop did not publish grandchild pid".to_string());
    }
    let grandchild_pid = parse_keyed_u32(&line, "grandchild")
        .ok_or_else(|| format!("invalid child-loop pid line: {:?}", line.trim_end()))?;
    let parent_pid = process::id();
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "tree parent={parent_pid} child={child_pid} grandchild={grandchild_pid}"
    )
    .map_err(|error| format!("writing tree line failed: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing tree line failed: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(hold_ms))
        .ok_or_else(|| "hold-ms deadline overflowed".to_string())?;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    Ok(())
}

fn run_child_loop(args: Vec<String>) -> Result<()> {
    let mut hold_ms = 30_000_u64;
    let mut ignore_term = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hold-ms" => {
                hold_ms = required_value(&args, index + 1, "--hold-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --hold-ms value: {error}"))?;
                index += 2;
            }
            "--ignore-term" => {
                ignore_term = true;
                index += 1;
            }
            "--respect-term" => {
                index += 1;
            }
            flag => return Err(format!("unknown child-loop flag {flag:?}")),
        }
    }
    if ignore_term {
        // SAFETY: process-global handler set for this helper process only.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    }
    let exe = std::env::current_exe().map_err(|error| format!("current_exe failed: {error}"))?;
    let mut grandchild = Command::new(&exe)
        .arg("grandchild-loop")
        .arg("--hold-ms")
        .arg(hold_ms.to_string())
        .arg(if ignore_term {
            "--ignore-term"
        } else {
            "--respect-term"
        })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawning grandchild-loop failed: {error}"))?;
    let pid = process::id();
    let grandchild_pid = grandchild.id();
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "child={pid} grandchild={grandchild_pid}")
        .map_err(|error| format!("writing child line failed: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing child line failed: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(hold_ms))
        .ok_or_else(|| "hold-ms deadline overflowed".to_string())?;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = grandchild.wait();
    Ok(())
}

fn run_grandchild_loop(args: Vec<String>) -> Result<()> {
    let mut hold_ms = 30_000_u64;
    let mut ignore_term = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hold-ms" => {
                hold_ms = required_value(&args, index + 1, "--hold-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --hold-ms value: {error}"))?;
                index += 2;
            }
            "--ignore-term" => {
                ignore_term = true;
                index += 1;
            }
            "--respect-term" => {
                index += 1;
            }
            flag => return Err(format!("unknown grandchild-loop flag {flag:?}")),
        }
    }
    if ignore_term {
        // SAFETY: process-global handler set for this helper process only.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(hold_ms))
        .ok_or_else(|| "hold-ms deadline overflowed".to_string())?;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn run_check_pids_gone(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        return Err("check-pids-gone requires one or more pid values".to_string());
    }
    for raw in &args {
        let pid = raw
            .parse::<u32>()
            .map_err(|error| format!("invalid pid {raw:?}: {error}"))?;
        let probe = format!("/proc/{pid}");
        if std::path::Path::new(&probe).exists() {
            return Err(format!("pid {pid} is still alive"));
        }
    }
    std::io::stdout()
        .write_all(b"pids-gone\n")
        .map_err(|error| format!("writing pid check output failed: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing pid check output failed: {error}"))?;
    Ok(())
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_keyed_u32(input: &str, key: &str) -> Option<u32> {
    input
        .split_whitespace()
        .find_map(|field| field.strip_prefix(&format!("{key}=")))
        .and_then(|value| value.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keyed_u32_extracts_expected_value() {
        let line = "tree parent=1 child=22 grandchild=333";
        assert_eq!(parse_keyed_u32(line, "child"), Some(22));
        assert_eq!(parse_keyed_u32(line, "grandchild"), Some(333));
        assert_eq!(parse_keyed_u32(line, "missing"), None);
    }

    #[test]
    fn decode_mountinfo_path_decodes_supported_escapes() {
        let decoded = decode_mountinfo_path("/mnt/a\\040b\\011c\\012d\\134e").expect("decode");
        assert_eq!(decoded, "/mnt/a b\tc\nd\\e");
    }

    #[test]
    fn hex_bytes_preserves_exact_values() {
        assert_eq!(hex_bytes(&[0, 1, 0xAB, 0xFF]), "0001abff");
    }
}
