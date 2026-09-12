// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Mount/isolation mount plan primitives.

#[cfg(target_os = "linux")]
use ::std::ffi::CString;
#[cfg(target_os = "linux")]
use ::std::path::Path;

use crate::error::{AgentError, Result};

#[cfg(target_os = "linux")]
const READ_ONLY_FLAG: libc::c_ulong = libc::MS_RDONLY;
#[cfg(not(target_os = "linux"))]
const READ_ONLY_FLAG: libc::c_ulong = 1;
#[cfg(target_os = "linux")]
const NOSUID_FLAG: libc::c_ulong = libc::MS_NOSUID;
#[cfg(not(target_os = "linux"))]
const NOSUID_FLAG: libc::c_ulong = 2;
#[cfg(target_os = "linux")]
const NODEV_FLAG: libc::c_ulong = libc::MS_NODEV;
#[cfg(not(target_os = "linux"))]
const NODEV_FLAG: libc::c_ulong = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountSpec {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    pub flags: libc::c_ulong,
    pub data: Option<&'static str>,
}

pub fn private_mount_specs() -> Vec<MountSpec> {
    vec![
        MountSpec {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            flags: 0,
            data: None,
        },
        MountSpec {
            source: "tmpfs",
            target: "/dev",
            fstype: "tmpfs",
            flags: NOSUID_FLAG | NODEV_FLAG,
            data: Some("mode=755"),
        },
        MountSpec {
            source: "devpts",
            target: "/dev/pts",
            fstype: "devpts",
            flags: 0,
            data: Some("newinstance,ptmxmode=0666,mode=620"),
        },
        MountSpec {
            source: "tmpfs",
            target: "/dev/shm",
            fstype: "tmpfs",
            flags: NOSUID_FLAG | NODEV_FLAG,
            data: Some("mode=1777"),
        },
        MountSpec {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            flags: READ_ONLY_FLAG,
            data: None,
        },
    ]
}

#[cfg(target_os = "linux")]
pub fn make_root_propagation_private() -> Result<()> {
    mount_internal(
        "none",
        Path::new("/"),
        "",
        libc::MS_PRIVATE | libc::MS_REC,
        None,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn make_root_propagation_private() -> Result<()> {
    Err(AgentError::isolation(
        "mount propagation isolation is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn mount_internal(
    source: &str,
    target: &Path,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let c_source =
        CString::new(source).map_err(|_| AgentError::mount("mount source contains NUL"))?;
    let c_target = CString::new(target.to_string_lossy().as_ref())
        .map_err(|_| AgentError::mount("mount target contains NUL"))?;
    let c_fstype =
        CString::new(fstype).map_err(|_| AgentError::mount("mount fstype contains NUL"))?;
    let c_data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| AgentError::mount("mount data contains NUL"))?;
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
        return Err(AgentError::io(
            format!("setting mount propagation on {}", target.display()),
            ::std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_plan_contains_expected_private_mount_targets() {
        let specs = private_mount_specs();
        let targets: Vec<&str> = specs.into_iter().map(|spec| spec.target).collect();
        assert_eq!(
            targets,
            vec!["/proc", "/dev", "/dev/pts", "/dev/shm", "/sys"]
        );
    }

    #[test]
    fn sys_mount_is_read_only() {
        let sys = private_mount_specs()
            .into_iter()
            .find(|spec| spec.target == "/sys")
            .expect("sys mount");
        assert_ne!(sys.flags & READ_ONLY_FLAG, 0);
    }

    #[test]
    fn tmpfs_mounts_use_kernel_flags_for_nosuid_and_nodev() {
        let specs = private_mount_specs();
        for target in ["/dev", "/dev/shm"] {
            let mount = specs
                .iter()
                .find(|spec| spec.target == target)
                .expect("tmpfs mount");
            assert_ne!(mount.flags & NOSUID_FLAG, 0);
            assert_ne!(mount.flags & NODEV_FLAG, 0);
            let data = mount.data.expect("tmpfs mount data");
            assert!(!data.contains("nosuid"));
            assert!(!data.contains("nodev"));
        }
    }
}
