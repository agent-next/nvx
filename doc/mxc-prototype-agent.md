# MXC prototype agent (Phase 0)

The Phase-0 MXC prototype restores a repository-local Rust workspace with three
separate crates:

- `agent-protocol` (shared framing + extension model),
- `agent` (PID-1 binary `nvx-agent`),
- `tools/agent-harness` (deterministic scenario/result harness).

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

## Distinct PID-1 image profile

The new profile name is `mxc-prototype`.

- Build command: `python3 scripts/nvx.py build-mxc-prototype-initramfs`
- Artifact: `build/initramfs-mxc-agent.cpio.gz`
- PID-1 layout: `/init -> sbin/nvx-agent` with `/sbin/nvx-agent` as the only executable payload.

`legacy` and `broker-ttrpc` artifacts remain unchanged.
