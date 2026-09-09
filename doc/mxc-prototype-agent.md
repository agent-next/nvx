# MXC prototype agent (Phase 0 scaffolding)

The Phase-0 MXC prototype restores a repository-local Rust workspace with three
separate crates:

- `agent-protocol` (shared framing + extension model),
- `agent` (PID-1 binary `nvx-agent` that reports `NOT READY` and waits for termination for boot diagnostics),
- `tools/agent-harness` (deterministic scenario/result harness that reports blocked/not-implemented runtime requirements).

This image/harness pair is **build/protocol scaffolding**, not an operational MXC runtime agent.

## Provenance

The port selectively reuses proven logic and tests from
`origin/esaurez/e2e-startup-profiling` at revision
`3ea1f05d1731300b4c1e8fb14058424a9bbe4bee`:

- `agent-protocol/src/lib.rs`
- `agent-protocol/src/e2e_profile.rs`
- `agent/src/config.rs`
- `agent/src/error.rs`

The divergent branch was not merged wholesale.

## MXC extension boundary

`agent-protocol::mxc_extension` defines a versioned Phase-0 boundary
(`mxc-extension-v1`) and models 12 requirements as typed operations.

ACI integration is intentionally blocked behind an unsupported adapter stub.
This repository does not claim ACI-04 protobuf/TTRPC compatibility.

- Required upstream pin for future integration:
  `cbd276763e099aa17b3d10addcce8dc23800c9e2`
- Current status: unsupported until exact schemas and fixtures are present.
- Runtime truthfulness: Phase 0 does not exercise the 12 operations; it reports
  runtime as blocked/not-implemented until later phases wire the real transport/service.

## Distinct PID-1 image profile

The new profile name is `mxc-prototype`.

- Build command: `python3 scripts/nvx.py build-mxc-prototype-initramfs`
- Artifact: `build/initramfs-mxc-agent.cpio.gz`
- PID-1 layout: `/init -> sbin/nvx-agent` with `/sbin/nvx-agent` as the only executable payload.

`legacy` and `broker-ttrpc` artifacts remain unchanged.

## What makes it runnable later

Phase 0 intentionally stops at deterministic build/protocol scaffolding. Later
phases are responsible for:

1. Wiring real MXC transport/service integration for host control.
2. Implementing and validating all 12 runtime requirements as true pass/fail outcomes.

Until those phases land, do not treat `mxc-prototype` as an operational guest agent.
