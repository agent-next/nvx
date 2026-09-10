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
  stdin queueing, and non-destructive credit-aware output streaming. Output
  credit exhaustion is handled as explicit backpressure (WouldBlock) until
  `FlowCredits` arrives; PID1 stays alive and replays the same front event
  losslessly.
- `tools/agent-harness` reports explicit evidence source tiers
  (`unit-static`, `local-linux-runtime`, `live-whp`) and a separate conformance
  status. Static or local-runtime evidence can satisfy subchecks, but canonical
  WHP conformance never passes without `live-whp` evidence for all requirements.
- Scenarios 3–6 and 10–12 exercise the production `MxcControlService` +
  `LinuxProcessSupervisor` path with real subprocesses on Linux/WSL
  (`local-linux-runtime` evidence: sequential exec + typed busy, binary
  stdout/stderr separation, backpressure/credits, terminal-order invariants,
  runtime network-readiness/health paths (including deterministic no-NIC,
  portable-ready, malformed, and timeout probes), production
  quiesce/resume/shutdown lifecycle transactions with bounded blocked-writer
  shutdown semantics, and channel-loss cleanup/new-generation enforcement).
  If the production runtime prerequisites are unavailable on the local host,
  req10/req11/req12 are reported as `Blocked` instead of passing. req12 pass
  evidence is accepted only when the production runtime executes channel-loss
  cleanup with a real output-producing child+grandchild process tree and
  bounded queue cleanup.
  Any local runtime
  pass remains non-conformance (`NotLive`) until observed on live WHP.
- Post-config capability advertisement now exposes `Exec`, `Streams`, `Cancel`,
  `Quiesce`, `Resume`, and `Shutdown` after full lifecycle activation.
- Cancellation, timeout escalation, descendant termination, channel-loss cleanup,
  and graceful shutdown all execute with fail-closed behavior.
- `Shutdown.grace_timeout_ms` is now strictly validated: it must be greater
  than zero and no larger than `MAX_SHUTDOWN_GRACE_TIMEOUT_MS` (30,000 ms).
  Runtime shutdown derives one absolute deadline from this caller value and
  spends that remaining budget across disconnect cleanup, sync, best-effort
  acknowledgement delivery, and runtime stop; no fixed post-deadline extension
  is applied.
- Disconnect cleanup now uses deterministic TERM→KILL budget partitioning under
  one absolute deadline, always reserves post-KILL verification/drain time, and
  enters bounded output-discard mode on channel loss (clears queued events,
  drains stdout/stderr to EOF under byte/time caps, escalates to KILL on
  overflow, and fails closed if termination/cleanup cannot be verified).
- Harness conformance gating now uses typed per-requirement probe attestations
  plus retained artifact metadata (paths + validated report/diagnostic IDs and
  hashes) produced in-memory by the harness runtime; user-crafted JSON strings
  cannot satisfy `is_passing_report`.
- Runtime `Health` now returns typed session state (`phase0/active/quiesced/
  shutting-down/cleanup-in-progress/fatal-session`), channel generation, active
  exec id, last failure detail, and configured filesystem/network snapshots.
- Runtime network reporting is now structured and bounded: mode, setup state,
  interface/index/link state, assigned addresses, default gateway/route, DNS
  readiness/servers, and typed setup failure (`NetworkFailureCode` + detail)
  with no freeform boot-log parsing.
- Fatal-session shutdown now starts fail-closed cleanup immediately, then attempts
  typed fatal error delivery only within a bounded runtime deadline
  (`FATAL_SESSION_DELIVERY_DEADLINE`, currently 250 ms). PID1 stops by that
  deadline even under persistent outbound backpressure.
- Timeout/cancel terminal disposition is now committed only after stdin close and
  termination initiation succeed. If those actions report uncertain process-tree
  state, the session is promoted to `FatalSession`; recoverable timeout
  enforcement failures retain timeout state for retry instead of being silently
  cleared.
- Quiesce/resume now drives cgroup freezer state (`cgroup.freeze` +
  `cgroup.events:frozen`) with bounded waits and fail-closed transitions.
  Current explicit policy: quiesce is rejected when an exec is active; callers
  must retry after workload completion.
- Post-spawn rollback now distinguishes successful cleanup (retryable spawn
  failure) from cleanup-uncertain rollback failures. Cleanup uncertainty is
  promoted to a typed fatal-session protocol error and PID1 stops accepting
  further work before fail-closed shutdown.

## Scope notes

- The service still reserves `OPENVMM_OUTER_FRAME_OVERHEAD_BYTES = 64` as a
  conservative framing budget until OpenVMM framing metadata is imported
  directly.
- Stream payload and stdin queue bounds are pinned to one protocol-safe limit:
  `PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES` (currently 65,452 bytes), derived from
  the conservative OpenVMM outer-record cap after inner-record framing.
- `CreateProcess.timeout_ms` is now strictly validated: it must be greater than
  zero and no larger than `MAX_EXEC_TIMEOUT_MS` (24h / 86,400,000 ms). Invalid
  values are rejected before spawn/state mutation.
- Security boundary: launch capability trust comes only from mxc profile boot
  configuration; host control traffic proves possession but cannot redefine the
  trusted expected value.
- `legacy` and `broker-ttrpc` paths remain out of scope for this profile.

## Deterministic WHP harness command

- Canonical host harness command:
  `python scripts\nvx.py test-mxc-agent --backend whp`
- Optional deterministic/static validation mode for CI/unit coverage:
  `--static-only` (always non-conformance and exits nonzero for canonical WHP
  conformance).
- The harness always writes a machine-readable JSON report and bounded
  diagnostics to `build/mxc-agent-harness` (or `--output-dir` override), halts
  on the first failing invariant, and keeps the output directory on failures.
