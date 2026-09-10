// Copyright(c) The microvm authors.
// Licensed under the MIT License.

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "launcher.rs"]
mod launcher;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "cgroup.rs"]
mod cgroup;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "config.rs"]
mod config;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "error.rs"]
mod error;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "isolation.rs"]
mod isolation;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "mappings.rs"]
mod mappings;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "supervisor.rs"]
pub mod supervisor;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
#[path = "runtime.rs"]
pub mod runtime;

#[cfg(all(target_os = "linux", feature = "harness-supervisor"))]
pub use supervisor::{LinuxProcessSupervisor, SupervisorQueueUsage};
