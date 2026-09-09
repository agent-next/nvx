// Copyright(c) The microvm authors.
// Licensed under the MIT License.
#![allow(dead_code)]

//! Sandbox configuration carried on the kernel command line.
//!
//! The host publishes each disk's guest-visible serial rather than a `/dev/vdX` path. Linux
//! derives device names from its own bus enumeration and a global IDA inside `virtblk_probe`,
//! so a host that named them would be predicting guest-kernel behavior instead of stating a
//! fact it controls. The serial is a fact it controls: it is what the device reports for
//! `VIRTIO_BLK_T_GET_ID`, and Linux publishes it as `/sys/block/<dev>/serial`. The MMIO base
//! is not usable for this - command-line virtio-mmio devices are registered under
//! `virtio-mmio-cmdline`, which does not publish their address in sysfs.

use ::std::fs;
use ::std::path::{Path, PathBuf};

use ::agent_protocol::e2e_profile;

use crate::error::{AgentError, Result};

/// Command-line key enabling guest E2E profiling.
pub const E2E_PROFILE_KEY: &str = "nvx_e2e_profile";
/// Command-line key carrying the safe profile correlation id.
pub const PROFILE_ID_KEY: &str = "nvx_profile_id";
/// Command-line key naming the read-only image disk's serial.
pub const IMAGE_KEY: &str = "nvx_image_serial";
/// Command-line key naming the read-write scratch disk's serial.
pub const SCRATCH_KEY: &str = "nvx_scratch_serial";
/// Command-line key giving the image disk's expected size in bytes.
pub const IMAGE_BYTES_KEY: &str = "nvx_image_bytes";
/// Command-line key giving the scratch disk's expected size in bytes.
pub const SCRATCH_BYTES_KEY: &str = "nvx_scratch_bytes";
/// Command-line key carrying this launch's epoch.
pub const LAUNCH_EPOCH_KEY: &str = "nvx_launch_epoch";

/// Opt-in guest profiling configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E2eProfileConfig {
    /// Correlation id supplied by the sandbox runtime.
    pub correlation: String,
}

/// Parses and validates the opt-in guest profile flags.
pub fn e2e_profile(cmdline: &str) -> Result<Option<E2eProfileConfig>> {
    let mut enabled = None;
    let mut correlation = None;
    for token in cmdline.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            E2E_PROFILE_KEY => {
                if enabled.replace(value).is_some() {
                    return Err(AgentError::config(format!(
                        "{E2E_PROFILE_KEY} may be specified only once"
                    )));
                }
            }
            PROFILE_ID_KEY => {
                if correlation.replace(value).is_some() {
                    return Err(AgentError::config(format!(
                        "{PROFILE_ID_KEY} may be specified only once"
                    )));
                }
            }
            _ => {}
        }
    }

    match (enabled, correlation) {
        (None, None) => Ok(None),
        (Some("1"), Some(value)) if e2e_profile::is_safe_correlation(value) => {
            Ok(Some(E2eProfileConfig {
                correlation: value.to_string(),
            }))
        }
        (Some("1"), Some(_)) => Err(AgentError::config(format!(
            "{PROFILE_ID_KEY} is not a safe profile id"
        ))),
        (Some("1"), None) => Err(AgentError::config(format!(
            "{E2E_PROFILE_KEY}=1 requires {PROFILE_ID_KEY}=<safe-id>"
        ))),
        (Some(value), _) => Err(AgentError::config(format!(
            "{E2E_PROFILE_KEY}={value} is invalid; expected {E2E_PROFILE_KEY}=1"
        ))),
        (None, Some(_)) => Err(AgentError::config(format!(
            "{PROFILE_ID_KEY} requires {E2E_PROFILE_KEY}=1"
        ))),
    }
}

/// Resolved sandbox configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SandboxConfig {
    /// Serial of the read-only image disk, when one is attached.
    pub image_serial: Option<String>,
    /// Serial of the read-write scratch disk, when one is attached.
    pub scratch_serial: Option<String>,
    /// Expected size of the image disk, when the host stated one.
    ///
    /// Only meaningful for a restored guest, where the attached file is not the one the
    /// snapshot was captured against; see [`crate::snapshot::prepare_restored_device`].
    pub image_bytes: Option<u64>,
    /// Expected size of the scratch disk, when the host stated one.
    pub scratch_bytes: Option<u64>,
    /// This launch's epoch, when the host supplied one.
    ///
    /// A capture leaves no observable trace in CPU or memory state, so a *serving* agent
    /// cannot tell by inspection that it was restored: everything it could look at came back
    /// with `mem.bin` and therefore describes the capturing instance. The epoch is the one
    /// value that differs, because the VMM writes it fresh for every launch — so an epoch that
    /// disagrees with the one captured in memory is the evidence of a restore.
    ///
    /// The platform tier needs none of this: it captures before the agent serves anything, and
    /// reaching the instruction after the port write is itself the signal.
    pub launch_epoch: Option<u64>,
}

impl SandboxConfig {
    /// Parses the sandbox tokens out of a kernel command line.
    pub fn parse(cmdline: &str) -> Result<Self> {
        let mut config = Self::default();
        for token in cmdline.split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            match key {
                IMAGE_KEY => config.image_serial = Some(validated(IMAGE_KEY, value)?),
                SCRATCH_KEY => config.scratch_serial = Some(validated(SCRATCH_KEY, value)?),
                IMAGE_BYTES_KEY => {
                    config.image_bytes = Some(validated_size(IMAGE_BYTES_KEY, value)?)
                }
                SCRATCH_BYTES_KEY => {
                    config.scratch_bytes = Some(validated_size(SCRATCH_BYTES_KEY, value)?)
                }
                LAUNCH_EPOCH_KEY => {
                    config.launch_epoch = Some(validated_size(LAUNCH_EPOCH_KEY, value)?)
                }
                _ => {}
            }
        }
        Ok(config)
    }

    /// Reads the configuration from the running kernel.
    #[cfg(test)]
    pub fn from_proc() -> Result<Self> {
        Self::parse(&read_cmdline()?)
    }
}

/// Reads the kernel command line.
pub fn read_cmdline() -> Result<String> {
    fs::read_to_string("/proc/cmdline")
        .map_err(|error| AgentError::io("reading /proc/cmdline", error))
}

fn validated_size(key: &str, value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| AgentError::config(format!("{key}={value} is not a byte count")))
}

fn validated(key: &str, value: &str) -> Result<String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(AgentError::config(format!(
            "{key}={value} is not a valid disk serial"
        )));
    }
    Ok(value.to_string())
}

/// Resolves the block device whose serial is `serial`.
pub fn resolve_block_device(serial: &str) -> Result<PathBuf> {
    let entries =
        fs::read_dir("/sys/block").map_err(|error| AgentError::io("listing /sys/block", error))?;

    let mut seen = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| AgentError::io("listing /sys/block", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(found) = read_serial(&entry.path()) else {
            seen.push(format!("{name}: no serial"));
            continue;
        };
        if found == serial {
            let device = PathBuf::from("/dev").join(&name);
            if !device.exists() {
                return Err(AgentError::mount(format!(
                    "{name} was enumerated but {} is missing; devtmpfs may not be mounted",
                    device.display()
                )));
            }
            return Ok(device);
        }
        seen.push(format!("{name}: {found}"));
    }

    Err(AgentError::mount(format!(
        "no block device reports the serial '{serial}' (saw: {})",
        seen.join(", ")
    )))
}

fn read_serial(block: &Path) -> Option<String> {
    let raw = fs::read_to_string(block.join("serial")).ok()?;
    let serial = raw.trim_end_matches(['\n', '\0']).trim().to_string();
    if serial.is_empty() {
        None
    } else {
        Some(serial)
    }
}

/// Returns the partitions of `device` in on-disk order, or the device itself when it has
/// none.
pub fn partitions_of(device: &Path) -> Result<Vec<PathBuf>> {
    let name = device
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AgentError::mount("block device has no name"))?;
    let sysfs = Path::new("/sys/class/block").join(name);
    let entries = fs::read_dir(&sysfs)
        .map_err(|error| AgentError::io(format!("listing {}", sysfs.display()), error))?;

    let mut partitions = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| AgentError::io("listing block partitions", error))?;
        let partition = entry.file_name().to_string_lossy().into_owned();
        if partition.starts_with(name) && entry.path().join("partition").exists() {
            partitions.push(partition);
        }
    }
    // Partition directories are enumerated in filesystem order, so sorting by the partition
    // index is what actually reproduces the on-disk order.
    partitions.sort_by_key(|partition| partition_index(partition, name));
    if partitions.is_empty() {
        return Ok(vec![device.to_path_buf()]);
    }
    Ok(partitions
        .into_iter()
        .map(|partition| PathBuf::from("/dev").join(partition))
        .collect())
}

fn partition_index(partition: &str, device: &str) -> u32 {
    partition
        .strip_prefix(device)
        .and_then(|index| index.parse().ok())
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_disk_serials_from_the_command_line() {
        let config = SandboxConfig::parse(
            "console=hvc0 nvx_image_serial=nvximage nvx_scratch_serial=nvxscratch quiet",
        )
        .unwrap();

        assert_eq!(config.image_serial.as_deref(), Some("nvximage"));
        assert_eq!(config.scratch_serial.as_deref(), Some("nvxscratch"));
    }

    #[test]
    fn parses_opt_in_e2e_profile_flags() {
        let profile =
            e2e_profile("console=hvc0 nvx_e2e_profile=1 nvx_profile_id=runtimeSandbox-123 quiet")
                .unwrap()
                .unwrap();

        assert_eq!(profile.correlation, "runtimeSandbox-123");
    }

    #[test]
    fn ordinary_command_line_disables_e2e_profile() {
        assert_eq!(e2e_profile("console=hvc0 quiet").unwrap(), None);
    }

    #[test]
    fn e2e_profile_requires_both_safe_flags() {
        assert!(e2e_profile("nvx_e2e_profile=1").is_err());
        assert!(e2e_profile("nvx_profile_id=sandbox").is_err());
        assert!(e2e_profile("nvx_e2e_profile=0 nvx_profile_id=sandbox").is_err());
        assert!(e2e_profile("nvx_e2e_profile=1 nvx_profile_id=bad/id").is_err());
    }

    #[test]
    fn accepts_a_command_line_without_disks() {
        let config = SandboxConfig::parse("console=hvc0 quiet").unwrap();

        assert_eq!(config, SandboxConfig::default());
    }

    #[test]
    fn rejects_a_malformed_serial() {
        let error = SandboxConfig::parse("nvx_image_serial=bad/serial").unwrap_err();

        assert!(format!("{error}").contains("not a valid disk serial"));
    }

    #[test]
    fn orders_partitions_numerically_rather_than_lexically() {
        let mut partitions = vec!["vda10".to_string(), "vda2".to_string(), "vda1".to_string()];
        partitions.sort_by_key(|partition| partition_index(partition, "vda"));

        assert_eq!(partitions, vec!["vda1", "vda2", "vda10"]);
    }
}
