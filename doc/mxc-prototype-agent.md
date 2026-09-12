# MXC prototype agent runtime status

The `mxc-prototype` guest image now runs an operational PID1 control runtime for
`nvx.mxc.agent.v1`.

## What is live now

- PID1 fail-closed startup now idempotently ensures `/proc` (procfs), `/sys`
  (sysfs), and `/sys/fs/cgroup` (cgroup2) before launch binding/service
  initialization. Existing mounts are accepted only after filesystem-type and
  required-path verification (`/proc/cmdline`, `/sys/kernel`,
  `/sys/fs/cgroup/cgroup.controllers`). It then discovers the reserved control
  tty from `nvx_control_tty=<hvcN>`, rejects any boot-console overlap (`hvc1`),
  opens that `/dev/hvcN` device read/write in raw nonblocking mode, and now
  speaks the frozen OpenVMM outer control-session wire contract (`NVXS` magic,
  version 1, fixed 44-byte little-endian header, record types 1..8). The guest
  control leg sends `GuestAttach`, waits for `Reset`, acknowledges exactly
  after `Reset`, then carries inner MXC records through outer `Data`.
- Broker launch capability is no longer present on kernel/OpenVMM command
  lines. It exists only in host harness memory, the inherited anonymous auth
  pipe, and the outer `HostAttach` payload handled by the broker.
- Guest launch identity is bound through inner `HostHello` / `Configure` /
  `WaitReady` (`generation` + random `nonce`) rather than any broker capability
  value.
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
  and live req07 fixed-identity probes (real/effective/saved uid/gid + groups),
  req08 namespace/isolation probes (namespace IDs, `/proc`/mount isolation, zero
  capabilities, `no_new_privs`, FD inventory, host-pid invisibility, and orphan
  cleanup), and req09 mapping containment probes (rw/ro behavior, undeclared/
  raw-export invisibility, recursive ro flags, traversal/symlink/overlap
  rejection, and post-config mutation rejection),
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
- Live WHP scenario execution now implements req10/req11/req12 directly instead
  of hardcoded harness failures: req10 validates runtime-emitted
  `WaitReady`/`Health` network status by observed launch mode, req11 runs
  health/quiesce/resume on the shared session plus a dedicated shutdown
  validation VM (tracked auxiliary launch lifecycle, typed invalid-shutdown
  request checks, and one absolute grace-rooted shutdown budget), and req12
  validates control-channel loss cleanup + strictly newer-generation reconnect
  with ordered handle-close-then-connect, stale auth/config/flow/stdin rejection
  correlation, and exec-ID reuse exactly once per generation.
- Post-config capability advertisement now exposes `Exec`, `Streams`, `Cancel`,
  `Quiesce`, `Resume`, and `Shutdown` after full lifecycle activation.
- Cancellation, timeout escalation, descendant termination, channel-loss cleanup,
  and graceful shutdown all execute with fail-closed behavior.
- `Shutdown.grace_timeout_ms` is now strictly validated: it must be greater
  than zero and no larger than `MAX_SHUTDOWN_GRACE_TIMEOUT_MS` (30,000 ms).
  Runtime shutdown derives one absolute deadline from this caller value and
  spends that remaining budget across admission stop, disconnect cleanup
  (TERM→KILL→verification/output discard), bounded mapping sync, best-effort
  acknowledgement delivery, and runtime stop; no fixed post-deadline extension
  is applied, and each phase uses the same absolute deadline rooted at request
  receipt.
- Mapping sync now runs in a disposable helper with parent-death SIGKILL
  behavior, explicit workload-cgroup exclusion checks, and nonblocking-only
  reaping on timeout paths. PID1 never performs a blocking `waitpid` after the
  shutdown deadline; if a helper cannot be reaped in-budget, PID1 logs the
  unreaped helper PID as fail-closed shutdown context and still proceeds to
  deadline-bounded stop/poweroff.
- Disconnect cleanup now uses deterministic TERM→KILL budget partitioning under
  one absolute deadline, always reserves post-KILL verification/drain time, and
  enters bounded output-discard mode on channel loss (clears queued events,
  drains stdout/stderr to EOF under byte/time caps, escalates to KILL on
  overflow, checks deadline expiry before TERM/KILL and each poll/sleep cycle,
  and fails closed immediately when budget is exhausted or cleanup state cannot
  be verified).
- Harness conformance gating now uses typed per-requirement probe attestations
  plus cryptographic artifact attestation. The harness writes a detached
  `attestation-manifest.json` (schema/version, run id, relative artifact paths,
  sizes, SHA-256 digests for the exact `report.json` and `diagnostics.log`
  bytes) and keeps trusted digests/sizes/run-id in-memory. Canonical exit
  validation reopens `report.json`, `diagnostics.log`, and the manifest and
  rejects missing/modified/truncated/swapped/path-escaped/manifest-tampered
  artifacts; user-crafted JSON strings cannot satisfy `is_passing_report`.
  Artifact verification rejects symlinked/reparse components (including
  junctions where available), opens files without following final links, and
  verifies canonical containment plus stable file identity under the trusted
  output directory to fail closed on link-swap races.
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
- Terminal outcomes now carry explicit termination metadata when cancellation or
  timeout requested process-tree termination: `gracefulTerm` means the tree
  exited after TERM without escalation, and `forcedKill` means SIGKILL/cgroup.kill
  escalation was successfully initiated. Normal/signal exits that were not
  termination-managed report no termination metadata.
- Quiesce/resume now drives cgroup freezer state (`cgroup.freeze` +
  `cgroup.events:frozen`) with bounded waits and fail-closed transitions.
  Current explicit policy: quiesce is rejected when an exec is active; callers
  must retry after workload completion.
- Post-spawn rollback now distinguishes successful cleanup (retryable spawn
  failure) from cleanup-uncertain rollback failures. Cleanup uncertainty is
  promoted to a typed fatal-session protocol error and PID1 stops accepting
  further work before fail-closed shutdown.

## Scope notes

- OpenVMM outer-frame accounting now uses the exact frozen header size
  (`OPENVMM_OUTER_FRAME_OVERHEAD_BYTES = 44`) instead of a guessed reserve.
- On Windows, the live harness launcher uses native `CreateProcessW` with
  `EXTENDED_STARTUPINFO_PRESENT`, `CREATE_SUSPENDED`, and
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The inherited handle list contains only
  duplicated inheritable stdin/stdout/stderr log handles plus the duplicated
  control-auth read handle. The process is assigned to a KILL_ON_CLOSE job
  before resume; capability pipe delivery/close happens while suspended.
- Stream payload and stdin queue bounds are pinned to one protocol-safe limit:
  `PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES` (currently 65,452 bytes), derived from
  the conservative OpenVMM outer-record cap after inner-record framing.
- `CreateProcess.timeout_ms` is now strictly validated: it must be greater than
  zero and no larger than `MAX_EXEC_TIMEOUT_MS` (24h / 86,400,000 ms). Invalid
  values are rejected before spawn/state mutation.
- Security boundary: broker launch capability trust is enforced by the outer
  broker attach path only; inner launch identity trust comes from authenticated
  protocol state (launch nonce/generation/version checks), not boot cmdline
  secrets.
- `legacy` and `broker-ttrpc` paths remain out of scope for this profile.

## Deterministic WHP harness command

- Canonical host harness command:
  `python scripts\nvx.py test-mxc-agent --backend whp`
- Optional artifact overrides:
  `--openvmm-exe <path> --kernel <path> --mxc-initramfs <path> --common-root <path> --output-dir <path>`
- Optional deterministic/static validation mode for CI/unit coverage:
  `--static-only` (always non-conformance and exits nonzero for canonical WHP
  conformance).
- Live prerequisites: Windows host with WHP, OpenVMM release executable,
  `build/vmlinux`, and `build/initramfs-mxc-agent.cpio.gz` (unless overrides
  are supplied). Missing inputs fail with machine-readable
  `missing-prerequisite` errors.
- Live launcher machine profile is the pinned OpenVMM-compatible
  `--machine microvm`; this canonical profile owns
  control-console enumeration and publishes `nvx_control_tty` for the fixed
  control device; NVX does not inject a duplicate control-tty token.
- The guest kernel pins the boot console at `hvc1` and the authenticated
  control console at `hvc2` from their fixed MMIO identities. This avoids
  probe-order races that can swap the channels even when command-line device
  discovery is ordered.
- PID1 mounts the fixed `virtfs_tag=microvm` export at the OpenVMM-owned
  `virtfs_dir` before accepting configuration, and adapts the service's
  length-prefixed HVC frames to the broker's one-inner-record-per-`Data`
  contract in both directions.
- OpenVMM preserves a connected but not-yet-observed host endpoint across the
  Linux driver's initial virtio reset. Established broker sessions retain the
  existing reset behavior and require a fresh attachment.
- The harness always writes a machine-readable JSON report and bounded
  diagnostics to `build/mxc-agent-harness` (or `--output-dir` override),
  including a PID/image-attested, asynchronous, one-MiB/30-second bounded
  `boot-console.log`. It halts on the first failing invariant, explicitly tears
  down the live session and joins the console capture worker on the first
  failure (and after the final canonical scenario on success), and keeps the
  output directory on failures.
- No run may be claimed as `live-whp` conformance unless all 12 live invariants
  pass and canonical attestations are emitted.

## Future state-aware MXC policy verification

`test-mxc-policy` is a separate compatibility suite. It verifies the proposed
state-aware NVX contract against real MXC `0.9.0-dev` JSON; it does not claim
legacy NanVix behavior or byte-for-byte parity with MXC's current parser.
`test-mxc-agent` and req01–req12 retain their existing command and semantics.

The suite vendors `schemas/dev/mxc-config.schema.0.9.0-dev.json` from
`microsoft/mxc@20960eeba8627e5e9e5f4249f89e757368f32094` as Draft 7. Its raw
SHA-256 is
`ad4a080ced7b73a4bcbe294551b5d61f703a1603bc85c161fa9a94e7a20e5c52`;
its recursively key-sorted compact-JSON SHA-256 is
`9bdc64c7ff1c3b520cde841776b260e6816328f92a835b09f1a054e068b25652`.
Refreshing the source requires updating provenance, reviewing every generated
inventory/catalog diff, extending the checked-in case corpus, and collecting
new live evidence.

| Disposition | NVX contract |
|---|---|
| Honored | Provision: RO/RW child mappings and allow/block network posture. Exec: `commandLine`, `cwd`, `env`, timeout, and URL proxy. |
| Accepted inert | Only `$schema` and `_comment`. |
| Control | Exact version, phase, IDs, and `containment: "vm"`; `--backend whp` selects NVX. |
| Rejected | Telemetry, UI, denied paths, host/directional rules, lifecycle, fallback, process-container, LXC, Seatbelt, experimental backend fields, and non-URL proxy variants. |

Provision is the only phase that may set filesystem or network posture. Exec is
the only phase that may set process or cooperative proxy values. Start, stop,
and deprovision accept no policy mutation. Post-provision phases require a
non-empty safe `sandboxId`; provision forbids one.

`process.commandLine` is deliberately lowered without interpretation to
`["/bin/sh", "-c", commandLine]`. Null and empty strings reject. Shell quoting,
expansion, exit status, timeout/tree termination, cwd, and environment behavior
are therefore part of the NVX contract. URL proxy configuration rejects
conflicting caller proxy variables and injects only `HTTP_PROXY` and
`HTTPS_PROXY`; an absent proxy injects nothing. Only exec-phase
`runtimeConfig.networkProxy` is honored. Any legacy `network.proxy` object,
including `network.proxy.url`, rejects as `unsupported_field` at
`/network/proxy`.

The MXC initramfs includes the pinned Alpine BusyBox `/bin/sh` and its musl
runtime because shell execution is part of this contract. Portable networking
strictly parses OpenVMM's `virtnet_ip`, `virtnet_mask`, and `virtnet_gw`
kernel parameters, configures the guest interface and default route before
Ready, and publishes the gateway as the guest DNS resolver.

Schema validation and semantic adaptation finish before the `HostEffects`
boundary. Rejected corpus cases mechanically assert zero root preparation,
fixture creation, discovery, launch-plan construction, process launch, and
output creation, and assert that no per-case output directory exists.

Evidence is reported as `unit-static`, `local-linux-runtime`, or paired
`live-whp-positive-negative`. A policy report passes only with no uncovered
catalog constructs, unexpected results, failed/blocked required live profiles,
or rejection effects. `blocked` means required infrastructure could not
produce evidence and is never treated as a pass.

Live Configure and CreateProcess requests are derived from checked-in MXC JSON
under `tools/agent-harness/fixtures/mxc-policy/live/`, validated, and adapted
before protocol messages are created. The freshness pins cover those inputs;
the detached manifest recursively attests the report, diagnostics, and all
live-profile evidence files under the output directory.

```powershell
# Full corpus and required live WHP evidence
python scripts\nvx.py test-mxc-policy --backend whp `
  --output-dir A:\Temp\nvx-mxc-policy-all-pass `
  --openvmm-exe openvmm\target\release\openvmm.exe `
  --kernel build\vmlinux `
  --mxc-initramfs build\initramfs-mxc-agent.cpio.gz `
  --common-root A:\Temp\nvx-mxc-policy-common

# Static catalog/corpus diagnostics, or one real MXC JSON document
python scripts\nvx.py test-mxc-policy --backend whp --static-only
python scripts\nvx.py test-mxc-policy --backend whp --static-only --config policy.json
```

The report schema is `nvx.mxc.policy.harness.report.v1`. Freshness pins include
the source schema and commit, raw/normalized schema hashes, catalog, adapter,
protocol source/version, case corpus, kernel, initramfs, workload probe,
OpenVMM, and harness identities. `report.json` and `diagnostics.log` are covered
by a detached SHA-256 manifest.
