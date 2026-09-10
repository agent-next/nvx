# MXC prototype agent runtime status

The `mxc-prototype` guest image now runs an operational PID1 control runtime for
`nvx.mxc.agent.v1`.

## What is live now

- PID1 opens `/dev/hvc1` read/write, switches the device to raw mode, and
  exchanges encoded protocol frames through `HvcFramedChannel`.
- Launch authentication now validates a trusted 32-byte capability loaded once
  from an out-of-band boot configuration key (`nvx.launch_capability` /
  `nvx_launch_capability`) with strict single-key parsing and exact 64-hex
  decoding. The expected capability is never derived from host requests.
- Capability comparison is constant-time. Successful authentication binds the
  admitted generation+nonce to the authenticated session, and stale/same
  generations remain rejected across reconnect cleanup boundaries.
- Session configuration remains immutable after the first successful apply
  (idempotent replay only).
- The Task2 namespace-holder/container setup is built only after valid
  configuration input, and execution enters the holder namespace path before
  fixed `mxc` identity execution.
- Process execution is supervised with one active exec at a time, unlimited
  sequential execs, argv/env/cwd execution without shell expansion, bounded
  stdin queueing, and non-destructive credit-aware output streaming.
- `tools/agent-harness` scenarios 3–6 now exercise the production
  `MxcControlService` + `LinuxProcessSupervisor` path with real subprocesses on
  Linux/WSL (sequential exec + typed busy, binary stdout/stderr separation,
  backpressure/credits, and terminal-order invariants). On non-Linux hosts
  these scenarios report `Blocked` rather than synthetic pass results.
- Post-config capability advertisement now exposes `Exec`, `Streams`, and
  `Cancel` only. `Quiesce`, `Resume`, and `Shutdown` remain explicitly
  unavailable until reviewed.
- Cancellation, timeout escalation, descendant termination, channel-loss cleanup,
  and graceful shutdown all execute with fail-closed behavior.
- Quiesce/resume now drives cgroup freezer state (`cgroup.freeze` +
  `cgroup.events:frozen`) with bounded waits and fail-closed transitions.

## Scope notes

- The service still reserves `OPENVMM_OUTER_FRAME_OVERHEAD_BYTES = 64` as a
  conservative framing budget until OpenVMM framing metadata is imported
  directly.
- Stream payload and stdin queue bounds are pinned to one protocol-safe limit:
  `PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES` (currently 65,452 bytes), derived from
  the conservative OpenVMM outer-record cap after inner-record framing.
- Security boundary: launch capability trust comes only from mxc profile boot
  configuration; host control traffic proves possession but cannot redefine the
  trusted expected value.
- `legacy` and `broker-ttrpc` paths remain out of scope for this profile.

## Deterministic WHP harness command

- Canonical host harness command:
  `python scripts\nvx.py test-mxc-agent --backend whp`
- Optional deterministic in-process mode for CI/unit coverage (not a live WHP
  proof): `--static-only`
- The harness always writes a machine-readable JSON report and bounded
  diagnostics to `build/mxc-agent-harness` (or `--output-dir` override), halts
  on the first failing invariant, and keeps the output directory on failures.
