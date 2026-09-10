// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Secure mapping resolution rooted at one guest-visible virtio-fs directory.

use ::std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use ::std::ffi::CString;
#[cfg(target_os = "linux")]
use ::std::mem::size_of;
#[cfg(target_os = "linux")]
use ::std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use ::std::path::Path;
use ::std::path::PathBuf;

use ::agent_protocol::{AccessMode, ChildMapping, RelativeChildPath, validate_mapping_set};

use crate::error::{AgentError, Result};

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingEntryKind {
    File,
    Directory,
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingEntryKind {
    Unsupported,
}

#[derive(Debug)]
pub struct ResolvedMapping {
    pub child: RelativeChildPath,
    pub access: AccessMode,
    pub guest_path: PathBuf,
    pub entry_kind: MappingEntryKind,
    #[cfg(target_os = "linux")]
    pub guest_fd: OwnedFd,
}

#[derive(Debug)]
pub struct MappingResolver {
    guest_root: PathBuf,
    declared: BTreeMap<RelativeChildPath, AccessMode>,
    #[cfg(target_os = "linux")]
    root_fd: OwnedFd,
}

#[cfg(target_os = "linux")]
const MAPPING_ROOT_TMPFS_DATA: &str = "mode=755,nosuid,nodev";

impl MappingResolver {
    pub fn new(guest_root: impl Into<PathBuf>, mappings: Vec<ChildMapping>) -> Result<Self> {
        let guest_root = guest_root.into();
        if !guest_root.is_absolute() {
            return Err(AgentError::config(format!(
                "guest mapping root must be absolute: {}",
                guest_root.display()
            )));
        }
        validate_mapping_set(&mappings)
            .map_err(|error| AgentError::config(format!("invalid mapping set: {error}")))?;
        let declared: BTreeMap<RelativeChildPath, AccessMode> = mappings
            .into_iter()
            .map(|mapping| (mapping.child, mapping.access))
            .collect();

        #[cfg(target_os = "linux")]
        let root_fd = open_root_directory(&guest_root)?;

        Ok(Self {
            guest_root,
            declared,
            #[cfg(target_os = "linux")]
            root_fd,
        })
    }

    pub fn resolve_declared(&self, requested: &RelativeChildPath) -> Result<ResolvedMapping> {
        let access = self.declared.get(requested).copied().ok_or_else(|| {
            AgentError::config(format!("undeclared mapping path: {}", requested.as_str()))
        })?;
        #[cfg(target_os = "linux")]
        {
            let guest_fd = resolve_under_root(self.root_fd.as_raw_fd(), requested.as_str())?;
            let entry_kind = mapping_kind(guest_fd.as_raw_fd())?;
            Ok(ResolvedMapping {
                child: requested.clone(),
                access,
                guest_path: self.guest_root.join(requested.as_str()),
                entry_kind,
                guest_fd,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = access;
            let _ = requested;
            Err(AgentError::config(
                "secure mapping resolution is unsupported on non-Linux targets",
            ))
        }
    }

    pub fn resolve_declared_raw(&self, requested: &str) -> Result<ResolvedMapping> {
        let child = RelativeChildPath::parse(requested.to_string())
            .map_err(|error| AgentError::config(format!("invalid mapping path: {error}")))?;
        self.resolve_declared(&child)
    }
}

#[cfg(target_os = "linux")]
pub fn procfd_mount_source(fd: &OwnedFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

#[cfg(target_os = "linux")]
pub fn install_resolved_mappings_in_holder_mount_namespace(
    holder_pid: libc::pid_t,
    guest_root: &str,
    mappings: &[ResolvedMapping],
) -> Result<()> {
    if holder_pid <= 1 {
        return Err(AgentError::mount(format!(
            "holder pid {holder_pid} is invalid for mapping installation",
        )));
    }
    let mount_ns_fd = open_namespace_fd(holder_pid, "mnt")?;
    // SAFETY: fork is used to isolate setns+mount operations from the main runtime process.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        close_fd(mount_ns_fd);
        return Err(AgentError::io(
            "forking mapping installer helper",
            ::std::io::Error::last_os_error(),
        ));
    }
    if child_pid == 0 {
        let exit_code = match install_resolved_mappings_in_child(mount_ns_fd, guest_root, mappings)
        {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("NVX-MAPPING-INSTALL-ERROR: {error}");
                1
            }
        };
        // SAFETY: child must exit without unwinding parent state after fork.
        unsafe { libc::_exit(exit_code) };
    }
    close_fd(mount_ns_fd);
    wait_pid_success(child_pid, "mapping installer helper")
}

#[cfg(target_os = "linux")]
fn install_resolved_mappings_in_child(
    mount_ns_fd: i32,
    guest_root: &str,
    mappings: &[ResolvedMapping],
) -> Result<()> {
    setns_checked(
        mount_ns_fd,
        libc::CLONE_NEWNS,
        "joining holder mount namespace",
    )?;
    close_fd(mount_ns_fd);
    let guest_root_path = Path::new(guest_root);
    ::std::fs::create_dir_all(guest_root_path).map_err(|error| {
        AgentError::io(
            format!("creating guest mapping root {}", guest_root_path.display()),
            error,
        )
    })?;
    mount_call(
        "tmpfs",
        guest_root_path,
        "tmpfs",
        0,
        Some(MAPPING_ROOT_TMPFS_DATA),
        "hiding raw mapping export with private tmpfs root",
    )?;

    for mapping in mappings {
        let target_path = guest_root_path.join(mapping.child.as_str());
        prepare_mapping_target(&target_path, mapping.entry_kind)?;
        let source = procfd_mount_source(&mapping.guest_fd);
        bind_mount_mapping_source(&source, &target_path, mapping.entry_kind)?;
        if mapping.access == AccessMode::ReadOnly {
            harden_read_only_recursive(&target_path)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_mapping_target(target: &Path, kind: MappingEntryKind) -> Result<()> {
    let parent = target.parent().ok_or_else(|| {
        AgentError::mount(format!(
            "mapping target {} has no parent directory",
            target.display()
        ))
    })?;
    ::std::fs::create_dir_all(parent).map_err(|error| {
        AgentError::io(
            format!("creating mapping parent directory {}", parent.display()),
            error,
        )
    })?;
    match kind {
        MappingEntryKind::Directory => {
            ::std::fs::create_dir_all(target).map_err(|error| {
                AgentError::io(
                    format!("creating mapping target directory {}", target.display()),
                    error,
                )
            })?;
        }
        MappingEntryKind::File => {
            if !target.exists() {
                ::std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(target)
                    .map_err(|error| {
                        AgentError::io(
                            format!("creating mapping target file {}", target.display()),
                            error,
                        )
                    })?;
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount_mapping_source(source: &str, target: &Path, kind: MappingEntryKind) -> Result<()> {
    let flags = if kind == MappingEntryKind::Directory {
        libc::MS_BIND | libc::MS_REC
    } else {
        libc::MS_BIND
    };
    mount_call(
        source,
        target,
        "",
        flags,
        None,
        format!(
            "bind-mounting mapping source {source} to {}",
            target.display()
        ),
    )
}

#[cfg(target_os = "linux")]
fn harden_read_only_recursive(target: &Path) -> Result<()> {
    let mut mount_entries = collect_mount_points_under(target)?;
    if !mount_entries
        .iter()
        .any(|entry| entry.mount_point == target)
    {
        mount_entries.push(MountInfoEntry {
            mount_point: target.to_path_buf(),
            read_only: false,
        });
    }
    mount_entries.sort_by(|left, right| {
        right
            .mount_point
            .components()
            .count()
            .cmp(&left.mount_point.components().count())
            .then_with(|| {
                right
                    .mount_point
                    .as_os_str()
                    .len()
                    .cmp(&left.mount_point.as_os_str().len())
            })
    });
    mount_entries.dedup_by(|left, right| left.mount_point == right.mount_point);
    let expected_points: Vec<PathBuf> = mount_entries
        .iter()
        .map(|entry| entry.mount_point.clone())
        .collect();
    for mount_entry in &mount_entries {
        let mount_point = &mount_entry.mount_point;
        mount_call(
            "none",
            mount_point,
            "",
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
            None,
            format!("remounting {} read-only", mount_point.display()),
        )?;
    }
    let hardened_mounts = collect_mount_points_under(target)?;
    for expected_point in expected_points {
        let hardened = hardened_mounts
            .iter()
            .find(|entry| entry.mount_point == expected_point)
            .ok_or_else(|| {
                AgentError::mount(format!(
                    "mountpoint {} disappeared while enforcing read-only mappings",
                    expected_point.display(),
                ))
            })?;
        if !hardened.read_only {
            return Err(AgentError::mount(format!(
                "mountpoint {} remained writable after read-only hardening",
                expected_point.display(),
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfoEntry {
    mount_point: PathBuf,
    read_only: bool,
}

#[cfg(target_os = "linux")]
fn collect_mount_points_under(root: &Path) -> Result<Vec<MountInfoEntry>> {
    let mountinfo = ::std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| AgentError::io("reading /proc/self/mountinfo", error))?;
    collect_mount_points_under_from_mountinfo(root, &mountinfo)
}

#[cfg(target_os = "linux")]
fn collect_mount_points_under_from_mountinfo(
    root: &Path,
    mountinfo: &str,
) -> Result<Vec<MountInfoEntry>> {
    let mut points = Vec::new();
    for line in mountinfo.lines() {
        let entry = parse_mountinfo_entry(line)?;
        if entry.mount_point == root || entry.mount_point.starts_with(root) {
            points.push(entry);
        }
    }
    Ok(points)
}

#[cfg(target_os = "linux")]
fn parse_mountinfo_entry(line: &str) -> Result<MountInfoEntry> {
    let mut fields = line
        .split(" - ")
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let _mount_id = fields
        .next()
        .ok_or_else(|| AgentError::mount(format!("mountinfo line missing mount id: {line}")))?;
    let _parent_id = fields
        .next()
        .ok_or_else(|| AgentError::mount(format!("mountinfo line missing parent id: {line}")))?;
    let _major_minor = fields.next().ok_or_else(|| {
        AgentError::mount(format!("mountinfo line missing major:minor id: {line}"))
    })?;
    let root_raw = fields
        .next()
        .ok_or_else(|| AgentError::mount(format!("mountinfo line missing root path: {line}")))?;
    let mount_point_raw = fields.next().ok_or_else(|| {
        AgentError::mount(format!("mountinfo line missing mount point path: {line}"))
    })?;
    let mount_options = fields.next().ok_or_else(|| {
        AgentError::mount(format!("mountinfo line missing mount options: {line}"))
    })?;
    let _decoded_root = decode_mountinfo_path_field(root_raw)?;
    let decoded_mount_point = decode_mountinfo_path_field(mount_point_raw)?;
    let mount_point = PathBuf::from(decoded_mount_point);
    if !mount_point.is_absolute() {
        return Err(AgentError::mount(format!(
            "mountinfo mount point must be absolute: {line}",
        )));
    }
    let read_only = mount_options.split(',').any(|option| option == "ro");
    Ok(MountInfoEntry {
        mount_point,
        read_only,
    })
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path_field(encoded: &str) -> Result<String> {
    let mut decoded = String::with_capacity(encoded.len());
    let mut bytes = encoded.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            decoded.push(byte as char);
            continue;
        }
        let first = bytes.next().ok_or_else(|| {
            AgentError::mount(format!(
                "mountinfo path contains malformed escape (truncated): {encoded}",
            ))
        })?;
        let second = bytes.next().ok_or_else(|| {
            AgentError::mount(format!(
                "mountinfo path contains malformed escape (truncated): {encoded}",
            ))
        })?;
        let third = bytes.next().ok_or_else(|| {
            AgentError::mount(format!(
                "mountinfo path contains malformed escape (truncated): {encoded}",
            ))
        })?;
        match [first, second, third] {
            [b'0', b'4', b'0'] => decoded.push(' '),
            [b'0', b'1', b'1'] => decoded.push('\t'),
            [b'0', b'1', b'2'] => decoded.push('\n'),
            [b'1', b'3', b'4'] => decoded.push('\\'),
            [a, b, c] => {
                return Err(AgentError::mount(format!(
                    "mountinfo path contains unsupported escape \\{}{}{}: {encoded}",
                    a as char, b as char, c as char
                )));
            }
        }
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
fn mount_call(
    source: &str,
    target: &Path,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
    context: impl Into<String>,
) -> Result<()> {
    let c_source =
        CString::new(source).map_err(|_| AgentError::mount("mount source contains NUL byte"))?;
    let c_target = CString::new(target.to_string_lossy().as_ref())
        .map_err(|_| AgentError::mount("mount target contains NUL byte"))?;
    let c_fstype =
        CString::new(fstype).map_err(|_| AgentError::mount("mount fstype contains NUL byte"))?;
    let c_data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| AgentError::mount("mount data contains NUL byte"))?;
    // SAFETY: pointers point to NUL-terminated strings that outlive the syscall.
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            if fstype.is_empty() {
                ::std::ptr::null()
            } else {
                c_fstype.as_ptr()
            },
            flags,
            c_data
                .as_ref()
                .map_or(::std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if rc != 0 {
        return Err(AgentError::io(context, ::std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_namespace_fd(pid: libc::pid_t, ns_name: &str) -> Result<i32> {
    let path = CString::new(format!("/proc/{pid}/ns/{ns_name}"))
        .map_err(|_| AgentError::mount("namespace path contains interior NUL"))?;
    // SAFETY: path is NUL-terminated and flags are constants.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(AgentError::io(
            format!("opening namespace /proc/{pid}/ns/{ns_name}"),
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn setns_checked(fd: i32, nstype: i32, context: &str) -> Result<()> {
    // SAFETY: fd references a namespace descriptor and nstype is a Linux setns flag.
    let rc = unsafe { libc::setns(fd, nstype) };
    if rc != 0 {
        return Err(AgentError::io(context, ::std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_pid_success(pid: libc::pid_t, context: &str) -> Result<()> {
    let mut status = 0_i32;
    loop {
        // SAFETY: waiting on known child pid with valid status pointer.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let error = ::std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(AgentError::io(format!("waiting for {context}"), error));
        }
        if rc != pid {
            continue;
        }
        break;
    }
    if (status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0 {
        return Err(AgentError::mount(format!(
            "{context} failed with wait status {status}",
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_fd(fd: i32) {
    // SAFETY: best-effort close of process-owned descriptor.
    let _ = unsafe { libc::close(fd) };
}

#[cfg(target_os = "linux")]
fn open_root_directory(path: &::std::path::Path) -> Result<OwnedFd> {
    let bytes = path.to_string_lossy();
    let c_path = CString::new(bytes.as_bytes())
        .map_err(|_| AgentError::config("guest mapping root contains NUL byte"))?;
    let flags = libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC;
    // SAFETY: c_path points to a valid C string and flags request readonly dir open.
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return Err(AgentError::io(
            format!("opening mapping root {}", path.display()),
            ::std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fd is newly returned by open and owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn resolve_under_root(root_fd: RawFd, relative: &str) -> Result<OwnedFd> {
    if let Some(fd) = try_openat2(root_fd, relative)? {
        return Ok(fd);
    }
    openat_no_symlink_fallback(root_fd, relative)
}

#[cfg(target_os = "linux")]
fn try_openat2(root_fd: RawFd, relative: &str) -> Result<Option<OwnedFd>> {
    let path = CString::new(relative)
        .map_err(|_| AgentError::config("mapping path contains interior NUL byte"))?;
    let mut attempts = 0_u8;
    loop {
        attempts = attempts.saturating_add(1);
        match openat2_fd(root_fd, &path) {
            Ok(fd) => return Ok(Some(fd)),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code) if code == libc::ENOSYS || code == libc::EINVAL || code == libc::E2BIG
                ) =>
            {
                return Ok(None);
            }
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) && attempts < 4 => continue,
            Err(error) => {
                return Err(AgentError::config(format!(
                    "mapping path {relative} escaped mapping root or violated symlink policy: {error}"
                )));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn openat_no_symlink_fallback(root_fd: RawFd, relative: &str) -> Result<OwnedFd> {
    let mut current = dup_fd(root_fd)?;
    let segments: Vec<&str> = relative.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        let is_last = index + 1 == segments.len();
        let component = CString::new(*segment)
            .map_err(|_| AgentError::config("mapping path segment contains NUL byte"))?;
        let flags = libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_RDONLY
            | if is_last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: current fd and component pointer are valid for openat syscall.
        let next_fd = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
        if next_fd < 0 {
            return Err(AgentError::config(format!(
                "mapping path {relative} is not contained beneath mapping root: {}",
                ::std::io::Error::last_os_error()
            )));
        }
        // SAFETY: next_fd is a newly opened descriptor.
        let next = unsafe { OwnedFd::from_raw_fd(next_fd) };
        verify_not_symlink(relative, next.as_raw_fd())?;
        current = next;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn verify_not_symlink(relative: &str, fd: RawFd) -> Result<()> {
    let mut stat_buffer = ::std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat_buffer is valid writable storage for fstat result.
    if unsafe { libc::fstat(fd, stat_buffer.as_mut_ptr()) } != 0 {
        return Err(AgentError::config(format!(
            "fstat failed while validating mapping path {relative}: {}",
            ::std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fstat succeeded and initialized stat_buffer.
    let mode = unsafe { stat_buffer.assume_init().st_mode };
    if (mode & libc::S_IFMT) == libc::S_IFLNK {
        return Err(AgentError::config(format!(
            "mapping path {relative} resolves through a symlink, which is forbidden"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mapping_kind(fd: RawFd) -> Result<MappingEntryKind> {
    let mut stat_buffer = ::std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat_buffer is valid writable storage for fstat result.
    if unsafe { libc::fstat(fd, stat_buffer.as_mut_ptr()) } != 0 {
        return Err(AgentError::io(
            "fstat for mapping entry kind",
            ::std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fstat succeeded and initialized stat_buffer.
    let mode = unsafe { stat_buffer.assume_init().st_mode };
    let file_type = mode & libc::S_IFMT;
    if file_type == libc::S_IFDIR {
        return Ok(MappingEntryKind::Directory);
    }
    if file_type == libc::S_IFREG {
        return Ok(MappingEntryKind::File);
    }
    Err(AgentError::config(
        "mapping target must resolve to a regular file or directory",
    ))
}

#[cfg(target_os = "linux")]
fn dup_fd(fd: RawFd) -> Result<OwnedFd> {
    // SAFETY: fcntl duplicates the provided valid descriptor.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(AgentError::io(
            "duplicating mapping root descriptor",
            ::std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: duplicated fd is newly owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(target_os = "linux")]
fn openat2_fd(root_fd: RawFd, path: &CString) -> ::std::io::Result<OwnedFd> {
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    let how = OpenHow {
        flags: (libc::O_CLOEXEC | libc::O_RDONLY) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };

    // SAFETY: openat2 syscall arguments point to valid immutable structs/strings.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            path.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        ) as i32
    };
    if fd < 0 {
        return Err(::std::io::Error::last_os_error());
    }
    // SAFETY: fd is owned by caller after successful syscall.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use ::agent_protocol::{AccessMode, ChildMapping, RelativeChildPath};

    use super::*;

    fn mapping(child: &str, access: AccessMode) -> ChildMapping {
        ChildMapping {
            child: RelativeChildPath::parse(child.to_string()).expect("child"),
            access,
        }
    }

    #[test]
    fn rejects_undeclared_mappings() {
        let root = ::std::env::temp_dir();
        let resolver = MappingResolver::new(root, vec![mapping("work", AccessMode::ReadOnly)])
            .expect("resolver");
        let error = resolver
            .resolve_declared_raw("other")
            .expect_err("undeclared path");
        assert!(format!("{error}").contains("undeclared mapping path"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlink_escape_inside_declared_mapping() {
        use ::std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        ::std::fs::create_dir_all(root.join("safe")).expect("root");
        ::std::fs::create_dir_all(&outside).expect("outside");
        symlink(&outside, root.join("safe").join("jump")).expect("symlink");
        let resolver = MappingResolver::new(root, vec![mapping("safe/jump", AccessMode::ReadOnly)])
            .expect("resolver");

        let error = resolver
            .resolve_declared_raw("safe/jump")
            .expect_err("symlink must be rejected");
        assert!(format!("{error}").contains("symlink"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_descriptor_that_is_not_redirected_by_path_swap() {
        use ::std::io::Read;
        use ::std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        ::std::fs::create_dir_all(root.join("safe")).expect("root");
        ::std::fs::create_dir_all(&outside).expect("outside");
        let inside_file = root.join("safe").join("payload.txt");
        let outside_file = outside.join("payload.txt");
        ::std::fs::write(&inside_file, "inside").expect("inside");
        ::std::fs::write(&outside_file, "outside").expect("outside");

        let resolver = MappingResolver::new(
            root.clone(),
            vec![mapping("safe/payload.txt", AccessMode::ReadOnly)],
        )
        .expect("resolver");
        let resolved = resolver
            .resolve_declared_raw("safe/payload.txt")
            .expect("resolved");
        assert_eq!(resolved.entry_kind, MappingEntryKind::File);

        ::std::fs::remove_file(&inside_file).expect("remove inside");
        symlink(&outside_file, &inside_file).expect("replace with symlink");

        let mut text = String::new();
        let mut file: ::std::fs::File = resolved.guest_fd.try_clone().expect("clone").into();
        file.read_to_string(&mut text).expect("read held fd");
        assert_eq!(text, "inside");
        assert_eq!(
            ::std::fs::read_to_string(&inside_file).expect("path"),
            "outside"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_traversal_strings_before_resolution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        ::std::fs::create_dir_all(&root).expect("root");
        let resolver = MappingResolver::new(root, vec![mapping("safe", AccessMode::ReadWrite)])
            .expect("resolver");

        let error = resolver
            .resolve_declared_raw("safe/../escape")
            .expect_err("dot-dot must fail");
        assert!(format!("{error}").contains("invalid mapping path"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn decodes_mountinfo_space_tab_newline_and_backslash_escapes() {
        let decoded = decode_mountinfo_path_field("/mnt/space\\040tab\\011line\\012slash\\134name")
            .expect("decoded");
        assert_eq!(decoded, "/mnt/space tab\tline\nslash\\name");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_mountinfo_truncated_escape() {
        let error = decode_mountinfo_path_field("/mnt/bad\\04").expect_err("must reject");
        assert!(format!("{error}").contains("malformed escape"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_mountinfo_unknown_escape() {
        let error = decode_mountinfo_path_field("/mnt/bad\\141").expect_err("must reject");
        assert!(format!("{error}").contains("unsupported escape"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_mount_points_decodes_paths_before_prefix_comparison() {
        let mountinfo = concat!(
            "21 19 0:19 / / rw,relatime - tmpfs tmpfs rw\n",
            "82 21 0:47 / /mapping\\040root rw,nosuid,nodev - tmpfs tmpfs rw\n",
            "83 82 0:48 / /mapping\\040root/nested\\011tab ro,nosuid,nodev - tmpfs tmpfs rw\n",
            "84 82 0:49 / /mapping\\040root/nested\\134slash ro,nosuid,nodev - tmpfs tmpfs rw\n",
            "85 82 0:50 / /mapping\\040root/other rw,nosuid,nodev - tmpfs tmpfs rw\n",
            "86 82 0:51 / /mapping\\040other rw,nosuid,nodev - tmpfs tmpfs rw\n",
        );
        let entries =
            collect_mount_points_under_from_mountinfo(Path::new("/mapping root"), mountinfo)
                .expect("parsed");
        let points: Vec<PathBuf> = entries
            .iter()
            .map(|entry| entry.mount_point.clone())
            .collect();
        assert_eq!(
            points,
            vec![
                PathBuf::from("/mapping root"),
                PathBuf::from("/mapping root/nested\ttab"),
                PathBuf::from("/mapping root/nested\\slash"),
                PathBuf::from("/mapping root/other"),
            ]
        );
        assert!(!entries[0].read_only);
        assert!(entries[1].read_only);
        assert!(entries[2].read_only);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN and private mount namespace"]
    fn harden_read_only_recursive_handles_nested_mounts_under_space_path() {
        struct MountedPathGuard {
            mounted_paths: Vec<PathBuf>,
        }

        impl MountedPathGuard {
            fn new() -> Self {
                Self {
                    mounted_paths: Vec::new(),
                }
            }

            fn push(&mut self, path: PathBuf) {
                self.mounted_paths.push(path);
            }
        }

        impl Drop for MountedPathGuard {
            fn drop(&mut self) {
                for path in self.mounted_paths.iter().rev() {
                    if let Ok(c_path) = CString::new(path.to_string_lossy().as_bytes()) {
                        // SAFETY: best-effort cleanup for mounts created by this test.
                        let _ = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
                    }
                }
            }
        }

        fn mount_tmpfs(target: &Path) -> Result<()> {
            mount_call(
                "tmpfs",
                target,
                "tmpfs",
                0,
                Some("mode=755"),
                "mounting tmpfs for test",
            )
        }

        // SAFETY: unshare called with CLONE_NEWNS to isolate this test's mount mutations.
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNS) };
        if rc != 0 {
            panic!(
                "unshare(CLONE_NEWNS) failed: {}",
                ::std::io::Error::last_os_error()
            );
        }
        mount_call(
            "none",
            Path::new("/"),
            "",
            libc::MS_PRIVATE | libc::MS_REC,
            None,
            "making root private for mount test",
        )
        .expect("private root");

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("mapping root");
        let nested = root.join("nested mount");
        ::std::fs::create_dir_all(&nested).expect("create nested mount points");

        let mut guard = MountedPathGuard::new();
        mount_tmpfs(&root).expect("mount root tmpfs");
        guard.push(root.clone());
        mount_tmpfs(&nested).expect("mount nested tmpfs");
        guard.push(nested.clone());

        harden_read_only_recursive(&root).expect("harden mounts");

        let mountinfo = ::std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let entries = collect_mount_points_under_from_mountinfo(&root, &mountinfo).expect("parse");
        let root_entry = entries
            .iter()
            .find(|entry| entry.mount_point == root)
            .expect("root entry");
        let nested_entry = entries
            .iter()
            .find(|entry| entry.mount_point == nested)
            .expect("nested entry");
        assert!(root_entry.read_only, "root mount remained writable");
        assert!(nested_entry.read_only, "nested mount remained writable");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn declared_mapping_resolution_is_explicitly_unsupported_off_linux() {
        let root = ::std::env::temp_dir();
        let resolver = MappingResolver::new(root, vec![mapping("safe", AccessMode::ReadOnly)])
            .expect("resolver");
        let error = resolver
            .resolve_declared_raw("safe")
            .expect_err("non-linux must fail closed");
        assert!(format!("{error}").contains("unsupported on non-Linux"));
    }
}
