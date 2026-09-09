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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMapping {
    pub child: RelativeChildPath,
    pub access: AccessMode,
    pub guest_path: PathBuf,
}

#[derive(Debug)]
pub struct MappingResolver {
    guest_root: PathBuf,
    declared: BTreeMap<RelativeChildPath, AccessMode>,
    #[cfg(target_os = "linux")]
    root_fd: OwnedFd,
}

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
        self.resolve_verified_path(requested)?;
        Ok(ResolvedMapping {
            child: requested.clone(),
            access,
            guest_path: self.guest_root.join(requested.as_str()),
        })
    }

    pub fn resolve_declared_raw(&self, requested: &str) -> Result<ResolvedMapping> {
        let child = RelativeChildPath::parse(requested.to_string())
            .map_err(|error| AgentError::config(format!("invalid mapping path: {error}")))?;
        self.resolve_declared(&child)
    }

    fn resolve_verified_path(&self, requested: &RelativeChildPath) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            resolve_under_root(self.root_fd.as_raw_fd(), requested.as_str())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = requested;
            Err(AgentError::config(
                "secure mapping resolution is only implemented for Linux guests",
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn open_root_directory(path: &Path) -> Result<OwnedFd> {
    let bytes = path.to_string_lossy();
    let c_path = CString::new(bytes.as_bytes())
        .map_err(|_| AgentError::config("guest mapping root contains NUL byte"))?;
    let flags = libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return Err(AgentError::io(
            format!("opening mapping root {}", path.display()),
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn resolve_under_root(root_fd: RawFd, relative: &str) -> Result<()> {
    if try_openat2(root_fd, relative)? {
        return Ok(());
    }
    openat_no_symlink_fallback(root_fd, relative)
}

#[cfg(target_os = "linux")]
fn try_openat2(root_fd: RawFd, relative: &str) -> Result<bool> {
    let path = CString::new(relative)
        .map_err(|_| AgentError::config("mapping path contains interior NUL byte"))?;
    let mut attempts = 0_u8;
    loop {
        attempts = attempts.saturating_add(1);
        match openat2_fd(root_fd, &path) {
            Ok(fd) => {
                drop(fd);
                return Ok(true);
            }
            Err(error) if matches!(error.raw_os_error(), Some(code) if code == libc::ENOSYS || code == libc::EINVAL || code == libc::E2BIG) =>
            {
                return Ok(false);
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
fn openat_no_symlink_fallback(root_fd: RawFd, relative: &str) -> Result<()> {
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
        let next_fd = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
        if next_fd < 0 {
            return Err(AgentError::config(format!(
                "mapping path {relative} is not contained beneath mapping root: {}",
                ::std::io::Error::last_os_error()
            )));
        }
        let next = unsafe { OwnedFd::from_raw_fd(next_fd) };
        verify_not_symlink(relative, next.as_raw_fd())?;
        current = next;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_not_symlink(relative: &str, fd: RawFd) -> Result<()> {
    let mut stat_buffer = ::std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat_buffer.as_mut_ptr()) } != 0 {
        return Err(AgentError::config(format!(
            "fstat failed while validating mapping path {relative}: {}",
            ::std::io::Error::last_os_error()
        )));
    }
    let mode = unsafe { stat_buffer.assume_init().st_mode };
    if (mode & libc::S_IFMT) == libc::S_IFLNK {
        return Err(AgentError::config(format!(
            "mapping path {relative} resolves through a symlink, which is forbidden"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn dup_fd(fd: RawFd) -> Result<OwnedFd> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(AgentError::io(
            "duplicating mapping root descriptor",
            ::std::io::Error::last_os_error(),
        ));
    }
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
}
