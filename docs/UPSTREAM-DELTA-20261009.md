# Upstream delta: agent-next/nvx `prod/hybrid-cpu-affinity` vs microsoft/nvx — 2026-10-09

Analysis only; no rebase was performed and no code was changed upstream or here beyond
this document.

**Method.** Upstream remote added as `upstream` (https://github.com/microsoft/nvx.git) and
fetched 2026-10-09. microsoft/nvx has **no `main`/`master` branch**; its default branch is
`dev`, so `upstream/dev` is the comparison line throughout. Merge-base of
`prod/hybrid-cpu-affinity` and `upstream/dev`:

- merge-base: `fc6fea5c0d6a4627c40b11174b47f18e04542d3a` ("Merge pull request #311 from
  microsoft/code-documentation/benchmark-warmups-default-20261002-…", 2026-10-02)
- upstream ahead: **537 commits** (448 direct + **89 PR merges**; PRs #66–#442), tip
  `33bd2fe5` = `v0.1.0-dev.60b22d98647d-1-g33bd2fe5`, 55 dev-release tags since the fork
  point
- fork ahead: **13 commits** (12 direct + merge #3), tip `07adc613`

Both trees still report `VERSION` = 0.1.0. Upstream landed heavy machinery in one week:
the time ABI v1, CPU profiles, an edge/agent backend, generation-bound snapshots, and a
provenance-hardened release pipeline.

---

## 1. Upstream changes since the fork point

### 1.1 Features

- **Time ABI v1** — PR #325 (merge `86661676`, branch tip `a453866e`; 81 files,
  +19,716/−1,971; largest single theme).
  Guest-visible time discipline for snapshots: `nvx-time` guest agent + probe
  (`ead100cc`, `4fd86484`), deferred boot/restore checks (`0e03977d`, `10b331d8`),
  spec under `doc/` (`9d2c04b3` "specify NVX time ABI v1"), host qualification via
  `nvx.py doctor` (`8de77c62`), `nvx-exit` as a single static musl exec (`facd91e1`),
  kernel STRICT_MODULE_RWX (`81ab71be`), and OpenVMM pins carrying the ABI
  (`96a0ed0c`, `aa75ec5d`, `a453866e`, `70efa17f`, `dcab8cd1`).
- **CPU profiles** — PRs #394 (`02ba24ba`; `33aa16ae` adds `run --cpu-profile` and
  `E_PROFILE_HOST_UNKNOWN`; `16237e29` pins the Alder Lake profile + opt-in host
  profiles; `38825056` doctor takes CPU generation/profile from OpenVMM's catalog),
  #404 (`57eabdc5`; AMD EPYC Milan, `ee6758c4`), #412 (`c0f099d0`; Genoa + Turin,
  `119841b4`), #411 (`5ee89788`; MSHV `--cpu-fingerprint` unlisted-CPUID handling,
  `c2e166fb`), #435 (`a399b7b1`; `auto` falls back to the host CPU profile —
  `00f8884d`, `c917dad1`, exercised by `7398ceb0`). Profiles double as a
  host-information-hiding measure (`8eb36f6c`, `84eeea41`).
- **Live virtio-fs share controls** — PR #401 multiple shares with independent modes
  (`2ec01e59`, `c2200425`, OpenVMM pin `b0ba7786`), PR #391 `--mount-owner`
  (`262b394e`, `7d103aa6`, pin `fc846c6a`), PR #413 per-subtree access policy:
  `--mount-write` / `--mount-allow` (`be859aa7`, `c0961d83`, pin `3c03d939`, CI
  coverage `71ced492`).
- **Azure Linux 3 guest** — PR #110 (`d54b8c3b`; `f85bb718` guest support, `a4c35d57`
  pinned RPMs + BusyBox, `c8f94c32` reproducible initramfs, `d420c6f3` 512 MiB
  default).
- **Kernel config** — PR #112 (`d561c430`): Unix-domain sockets for microVMs
  (`8565c086`); built-in VETH (`64d7ff6f`, `112ad896`, `2560afc4`); PR #113
  (`62178bd4`): `kernel: enforce generic sandbox capabilities` (`d9796f7d`).
- **Managed execution config** — PR #288 (`165b768b`; `78d80d18` "configure managed
  execution", `8802773b` static managed helper, `0fa92a7a` sealed workload config,
  `095496e9` documented guest env defaults) and PR #328 (`beaee18b`) per-execution
  environments (`e7a8bf06`, `69ae011a`, `bc763ff0`; doc `f3ba5206` "extended EXEC
  payload").
- **ACI edge sandbox Rust API** — PR #307 (`4c8954ce`, `a2c9006a`): new crate, see §1.7.
- **Doctor hardening** — `1941f631` fail closed on unreadable host facts, `c143b4b0`
  fail H7 when w32tm names no time source (both #325).

### 1.2 Performance

- **Baseline churn is mechanical**: ~60 "data: update performance baselines" commits
  (latest `33bd2fe5`) land fresh p50 series into `data/*.csv` on every merged PR;
  numbers are extracted in §4 below. CI contract work around them: gate thresholds
  `4bd3e790` (#400), `349ec8cb` detect minority snapshot regimes (#118 `b2380065` snapshot
  bimodality), `95182ab1`/`0e652612` remeasure unstable lifecycle benchmarks,
  `fae872ec` reject non-finite floats (#310).
- **Restore CPU budgets quantified in the time ABI spec**: `32849acb`/`c4f04995` set
  KVM's restore `cpu_us` budget to **6.5 + 1.5 ms** (CI enforces at `c4f04995`);
  `91849f78` publishes the final per-backend `cpu_us` budgets; MSHV per-VP creation
  cost and root-driver restore costs recorded (`d365de0e`, `ac3d8108`). Wall-clock
  convergence bounds measured on bare-metal WHP (`fb35745c`).
- **OpenVMM pins with perf effect**: `f25abfa5` flush portb output before snapshot
  capture (#308, issue #231), `82d944ab` RAM-backed microVM overlays without scratch
  (#418), `ba5bc7ff` WHP nested-UEFI timer-interrupt fix, `51b7c98b` generation-bound
  snapshot support (#261).
- **First-command cost attributed**: `97ce2b3c`/`ddbc8c4c` disclose that the static
  `nvx-exit` offsets the first command's cost and that post-restore exit cost comes
  from cold process paths; `7f1eff12` settles direct-mode execs only once processes
  are reaped (#363).
- **Benchmark correctness (affects measurements, not just CI)**: `7e050bc0` read
  benchmark output to its end (#330), `8ddcad5b` separate OpenVMM stderr from the
  guest console, `083dd2f2` count canary connections queued at close (#323).

### 1.3 Security

- **Release/provenance chain** — PR #114 (`b29aac0f`): `26fcdab7` bind artifacts to
  build provenance, `de333552` enforce immutable artifact publication, `2fa680ff`
  verify staged archive contents, `8e375fec` archive a pinned source snapshot,
  `bacca2cd` require exact development asset digests, `a4711d0c` close provenance
  validation races; follow-ups `7792aa9d` harden authenticated release downloads
  (#71 `3644cbc1` context) and `a4276a29` reject symlinks/special files in
  SHA256SUMS (#385 `f1a1ee40`).
- **Share isolation** — PR #413 write narrowing / read masking / allowed-path CI
  coverage (`71ced492`) on top of the per-subtree policy pins.
- **Kernel/guest hardening** — `81ab71be` STRICT_MODULE_RWX + `bb75e931` boot check
  fails on writable+executable kernel mapping (#325); `d9796f7d` generic sandbox
  capabilities (#113); `4d7052ab` verify the sandbox security profile in the smoke
  probe (#437).
- **CPUID/host-info leakage** — reserved unlisted entries verified to hide host
  features (`8eb36f6c`, `84eeea41`), effective-CPUID as single source (#325).
- **Process identity** — `9c39d401` identify OpenVMM by PID + start time (#378
  `e33c0bab`, issue #369): prevents acting on a recycled PID after a crash.

### 1.4 CLI / API / config

See §3 for the gateway-facing detail with file:line. Highlights: new
`run --cpu-profile` (#394); new share flags `--mount-owner` (#391),
`--mount-write`/`--mount-allow` (#413); `auto` CPU-profile fallback with a new error
class (#435); control contract advanced to `nvx-microvm-v2-control-v2` (`58ad42cd`,
#328); doctor exits non-zero on unreadable host facts (#325); commands that cannot
start now report `ScriptError` (`87406b00`, #399); nvx-exit 32-bit wrap pinned
(`59b7c448`, #325, test-only).

### 1.5 Snapshot format

- **Generation-bound snapshot storage** — PR #261 (merge `2a1819ff`); implementation
  ships in the OpenVMM submodule pin (`51b7c98b`: `3fa00eb6`→`0eccda89`). Snapshots
  can be addressed by an immutable **storage generation** instead of whole-file
  SHA-256: capture passes `--snapshot-block-identity generation
  --snapshot-generation-id <32-HEX>`, binding every consumed block to that
  generation; restore then compares block metadata (roles, sizes, geometry) without
  rehashing bytes. Docs: `doc/design/snapshot-and-restore.md:47-52` (default identity
  remains `sha256`), admission rules in `doc/design/snapshot-sharing-and-host-storage.md:32-54`
  (`3469ba18`). On-disk layout (state.bin/memory.bin/manifest **v6**) is unchanged,
  but the manifest records a paired-scratch **materialization policy** with three
  restore modes — `private-copy`, `copy-on-write` (reflink, Linux-only),
  `direct-claimed` (hard-link from an exclusively claimed instance checkpoint) —
  `snapshot-and-restore.md:259-276`, `:379-395`; limits at
  `doc/design/current-limits.md:17-20`. Harness use:
  `scripts/nvx_tools/microvm_tests.py:5171-5189`. Manifest v6 is mandatory; anything
  else fails with `E_SNAPSHOT_VERSION` (`snapshot-and-restore.md:272-273`).
  `a187ed6e` verifies direct-claimed restores *mutate* the claimed scratch artifact
  (`microvm_tests.py:5001-5002`, `5168-5175`).
- **Restore packet v4** — replaces the `--restore-entropy` OpenVMM argument with a
  64-byte entropy field inside the restore packet (all via #325, merge `86661676`).
  Guest side: `guest/common/nvx-time.c` — `struct restore_packet` at :1117-1127 with
  `uint8_t entropy[64]` at :1126 (`PACKET_ENTROPY_SIZE 64` at :97); header parse at
  :1129-1197 checks magic `"OVR"` (:1136) and **rejects version != 4** (:1141-1144);
  entropy lands in `/run/nvx/restore-entropy` (`repair_restore` :4161-4166) for the
  caller, consumed by `guest/common/nvx-snapshot:288`. v1–v3 are no longer produced
  or accepted (`doc/design/time-abi.md:1181-1183`); v4 also replaces tier-based ACK
  gating with an `ACK_REQUIRED` flag. Repo side: `5a92c86f` removes the argument nvx
  internally appended to the OpenVMM restore command built at `scripts/nvx.py:483`
  (and from `scripts/nvx_tools/benchmark.py:5062`) — it was never an nvx CLI flag;
  see §1.8 item 5; `d3d76646` rewrites
  the snapshot-core scenario (`scripts/nvx_tools/microvm_test_scripts/snapshot-core.sh:42`);
  `a3e250ce` specifies the 4-byte `inl` read (CPL-3 `rep insl` raises #GP on
  MSHV/WHP).
- **RAM-backed microVM overlays without scratch** — `82d944ab` (#418): OpenVMM pin
  `96e2363b1`→`f12dcf5e8` (openvmm#121 rebased). The edge runtime boots from one
  read-only image with the writable overlay **upper in RAM and no scratch disk**.
  Submodule-only; no repo-side format change in this commit.
- **portb flush before capture** — `f25abfa5` (#308, issue #231): OpenVMM pin
  `2728f33ea`→`4355c010e` (openvmm#107). Guest bytes written just before a snapshot
  request are flushed to the open endpoint (bounded by the quiesce timeout) instead
  of being lost/trapped in the snapshot.
- **New optional capture flags**: `--snapshot-block-identity`, `--snapshot-generation-id`,
  `--snapshot-scratch-restore-mode` (`microvm_tests.py:5183-5188`; defaults keep the
  old SHA-256 behavior). No REST/HTTP snapshot client exists in `scripts/`; the
  management RPC lives in the OpenVMM submodule and cannot restore snapshots
  containing sandbox blocks (`doc/design/current-limits.md:22`) (unverified beyond
  the repo-side docs).
- Unmerged branches signal more format churn coming:
  `esaurez/streamed-snapshot-preprofile-20261006` (immutable streamed distro
  snapshot attachments; filesystem-only workload restores without process identity),
  `esaurez/nvx-snapshot-image-slots-20261007` (merges generation-bound storage with
  microVM image slots), `esaurez/nvx-image-slots-20261005` (bind-once image slots,
  "ABI 3"), `esaurez/microvm-state-control`, `esaurez/snapshot-restore-dev-20261007`
  — none merged into `dev` as of 2026-10-09.

### 1.6 Sandbox one-shot path

- `8513233b` — hand OpenVMM its control capability **before** it starts (#441
  `60b22d98`, issue #440: capability-pipe race at start).
- `bb2ba395` — a failed start's OpenVMM publishes its outcome report (#439
  `91acc751`, issue #438): start failures now diagnosable instead of hanging.
- `e8030bfb` — treat a Linux process as running until its **last thread** exits
  (#418): fixes premature exit reporting for multi-threaded one-shot workloads.
- `9c39d401` — OpenVMM identified by PID + start time (#378).
- `7f1eff12` — direct-mode execs settle only once reaped (#363 `2508acd8`).
- `9ebc6f96`/`f503854f` — unusable working directories refused before direct launch,
  reported distinctly (#333 `0f95ddbc`, issue #273).
- `d816655d` — stop OpenVMM output readers before closing descriptors (#330, issue
  #317); `ea0abfbf` — suppress SIGPIPE during barrier release (#288).
- `ed46e7d3` — managed **dry runs rejected** and PWD aligned (#380 `3617108e`).
- `d240b183` + `4d7052ab` — end-to-end managed sandbox lifecycle test + security
  profile in the smoke probe (#437 `d3eb15fd`).

### 1.7 nvxhost / edge backend (#418)

PR #418 (merge `c90c60b2`, branch `esaurez/nvxhost-edge-backend`, merged 2026-10-08,
+7526/−299, 5 commits): `82d944ab` (OpenVMM submodule pin for RAM-backed overlays),
`e8030bfb` (Linux process runs until its last thread exits: `src/openvmm/platform/linux.rs`,
`src/openvmm/process.rs`), `28ecbb5a` (data model moved to a new `aci_edge_sandboxes/model/`
crate; public API re-exported unchanged), `aefb92d5` (setup/sandbox-spec/native-ABI model
types), `2113c65b` (the bulk: `src/agent/`, `examples/agent_lifecycle.rs` 409 lines,
`tests/agent_guest.rs` 2663 lines).

**What it is.** "nvxhost" is the branch codename; it appears nowhere in the tree
(`git grep -i nvxhost upstream/dev` is empty). The feature is a native host library,
**`aci_edge_agent`** (`libaci_edge_agent.so` / `.dll`), that owns the whole edge-sandbox
lifecycle in-process — state root and records, OpenVMM processes and boot consoles,
guest sessions, image registry. The crate gains an **opt-in `agent` backend** that is a
thin client of that library: it verifies the library's SHA-256 and sandbox ABI version,
dlopens it (sealed memfd on Linux, `F_ADD_SEALS`; locked handle on Windows —
`aci_edge_sandboxes/src/agent/library.rs:195`, ABI check at `:325` against
`SANDBOX_ABI_VERSION = 1`, `model/src/wire.rs:19`), opens a "host" from a `SetupConfig`,
and forwards each lifecycle op through the C ABI (JSON via the model crate).

**Public API surface** (file:line in upstream/dev):
- `src/client.rs:24` `pub struct AciEdgeSandbox` — `openvmm(OpenVmmConfig)` :43
  (default), `agent(AgentConfig)` :49 (feature `agent`); `provision` :69,
  `provision_with(SandboxSpec)` :75, `start` :107, `exec` :112, `stop` :146,
  `deprovision` :151.
- `src/backend.rs:28` `pub trait Backend` (default `OpenVmmBackend`); `src/exec.rs:123`
  `Execution` (streaming exec, `wait_with_output`, `take_stdout/stderr`); outcomes
  `Exited/Signaled/TimedOut/Cancelled/Failed` (`src/exec.rs:79`).
- `src/agent/mod.rs:54` `AgentConfig {setup, library, library_sha256}`; `:119`
  `AgentBackend::new`; image-registry ops `register_image` :164, `verify_image` :184;
  diagnostics `guest_logs` :197, `outcome_report_path` :208-223.
- `src/async_api.rs:50` `AsyncAciEdgeSandbox` / `:288` `OutputStream` (Tokio, feature
  `async`).
- `model/src/setup.rs:116` `SetupConfig` — `stateRoot`, `runtime` (format-1
  `SOURCE-MANIFEST.json` of the `edge` profile: `bin/openvmm`, `guest/vmlinux`,
  `guest/initramfs-edge.cpio.gz`), `cpuProfile` :310, `timeouts` :321; defaults
  `DEFAULT_MEMORY_MIB=256`, `DEFAULT_VCPUS=1` (:451-453).

The crate itself landed post-fork-point in PR #307 (`4c8954ce`, `a2c9006a` "Add ACI
edge sandbox Rust API") and grew via #331/#332/#338/#340/#347/#348/#354/#355/#361/#363/#367
before #418.

**Opt-in, default path untouched.** `agent` is not in `default = ["openvmm"]`
(`aci_edge_sandboxes/Cargo.toml`); PR #418 touches zero files under `scripts/`; the
python CLI only gained an opt-in `test-aci-edge-sandboxes` subcommand
(`scripts/nvx.py:1000`, driver `scripts/nvx_tools/aci_edge_sandboxes_tests.py`, env
`ACI_EDGE_SANDBOXES_E2E_*`) from #307. `sandbox.py`/`sandbox_lifecycle.py` were not
modified by any crate PR.

**New external requirements (no daemon, no socket):** the library must be installed
separately and pinned by SHA-256 — missing/wrong-digest/wrong-ABI fails hard; guest
tests need `EDGE_AGENT_TEST_{OPENVMM,KERNEL,INITRD,IMAGE,LIBRARY,SHA256}`; building
from git now fetches the bumped `openvmm` submodule (`96e2363b1`→`f12dcf5e8`); MSRV
1.89. New guest policy: 1 vCPU only, ~a dozen host-path mounts, ≤64 forwarded ports,
immutable proxy env. An MXC `StatefulSandboxBackend` mapping is documented
(`aci_edge_sandboxes/README.md:739`) with a proof-of-concept `nvx_backend` adapter not
yet wired into MXC's wire contract.

**Sibling `esaurez/*nvxhost*` branches** (`edge-nvxhost-proxy`/`nvxhost-edge-proxy`,
`*-fsnet`, `*-denied-aliases`, `*-pre-time-abi`, `nvxhost-edge-host-cpu-profile`) look
pending but their content was folded into #418 — verified via `log -S` on the README
sections; they are history, not pending work. Actually-open next work:
`esaurez/microvm-state-control`, the image-slot and streamed-snapshot branches (§1.5).

### 1.8 Breaking changes (caller-facing)

1. `sandbox --dry-run` is now **only valid for `sandbox run`** — provision/start/exec/
   stop/deprovision with it exit 1 (`ed46e7d3`, #380; `scripts/nvx.py:571-572`).
   Previously those operations silently *executed* while the caller believed it was a
   preview; scripts relying on that (buggy) behavior break.
2. Control contract renamed `nvx-microvm-v2-control-v1` → **`nvx-microvm-v2-control-v2`**
   (`58ad42cd`, #328): `scripts/nvx_tools/build_constants.py:145`,
   `aci_edge_sandboxes/src/openvmm/contract.rs:11`, `SOURCE-MANIFEST.json:10`. Callers
   that pin/check the revision string break.
3. Guest agents must advertise `EXEC_ENVIRONMENT` (bit 4) and `EXEC_CWD` (bit 5) at
   start or the start fails `backend_unavailable`
   (`aci_edge_sandboxes/src/openvmm/protocol.rs:336-352`, #333/#328): **pre-existing
   guest images no longer start**.
4. Exec outcome shape: new `WorkingDirectory` failure variant / `cwd-failed` category
   (`model/src/outcome.rs:58-63`) replaces what previously looked like exit 125.
5. Direct-OpenVMM callers: `--restore-entropy` is rejected by the flipped OpenVMM
   (restore packet v4 replaces it; `5a92c86f`) and `--x-time-abi-v1` is rejected
   (`e93fdc09`). Correction: neither was ever an nvx.py argparse flag — nvx appended
   `--restore-entropy` to the OpenVMM restore command it builds internally, so only
   callers that invoke `openvmm` directly are affected.
6. `auto` CPU profile can now fall back to the host profile and surface
   `E_PROFILE_HOST_UNKNOWN` (`33aa16ae`/`c917dad1`, #394/#435; `doc/usage.md:541`) —
   callers must handle the new error path; `run --mount` with >2 commas rejected
   (`nvx.py:513-514`); `check-required-ci`'s two new flags are required (#436).
7. `smp-lapic` test scenario and its benchmark precheck removed (`263f9a48`, #325) —
   CI/oracle configs referencing it break.
8. Commands that cannot start now return `ScriptError` (`87406b00`, #399) — message
   contract change (exit status is still 1).
9. Kernel/guest requirements moved: built-in VETH required by the NVX guest
   (`64d7ff6f`+`2560afc4`), kernel drops dormant KVM guest options (`a0a65df5`) —
   custom guest kernels must be rebuilt.

---

## 2. Our patches on `prod/hybrid-cpu-affinity` vs upstream

Our 13 commits (fork → tip `07adc613`):

| Commit | What it does | Upstream status of the same problem |
|---|---|---|
| `ec38aa01` fix(affinity) | Pin the nvx process tree to one CPU class (P-cores) on hybrid parts; `NVX_CPU_CLASS=efficiency|all` override; fixes OpenVMM destination-CPU-contract failures when a vCPU migrates between P and E cores between capture and restore (`scripts/nvx.py` `apply_hybrid_process_affinity`, ~line 967). | **Not fixed the same way.** Upstream's parallel answer is CPU *profiles*: Alder Lake profile pin `16237e29` (#394), host profiles (#404/#412), fingerprint checks `c2e166fb` (#411), `auto`→host fallback `00f8884d` (#435). Upstream stabilizes what CPUID the guest sees but has no process/class affinity pinning (`sched_setaffinity` appears only in `scripts/nvx_tools/host_time_probe.rs:45` for the probe itself). Whether profiles alone prevent the hybrid capture/restore mismatch on an i9-14900K is (unverified). |
| `a4811e5e` test(provenance) | Isolate provenance fixture repos from host default-branch policy. | No direct equivalent found; upstream reworked provenance fixtures in #114 (`7407c3bd` aligns fixture with the current OpenVMM gitlink). (unverified) that it covers the same failure. |
| `ac82a417` feat(setup) | `setup-submodule`: stage the installed release binary, `git submodule update --init openvmm`, restore — works around "download leaves `openvmm/` non-empty → submodule init fails" (PRODUCTION-NOTES §2). | **Still broken upstream as of `33bd2fe5`**: no commit touches the install-vs-submodule collision (searched `log -S'openvmm/target/release'`; nearest are #428 `2257313d` — release *selection order* — and `20fe103c` removing undeclared guest artifacts). Our workaround remains fork-only. |
| `fa60c840` test(tree-kill) | Wait for async process-tree kills in contained-runner oracles (`scripts/test_adversarial.py`). | **Fixed upstream, more deeply**: PR #323 (`554fc45b`) `df532ce2` "wait for killed descendants in Linux process-tree cleanup" fixes the *oracle* (`scripts/nvx_tools/adversarial_oracles.py`) as well as the test. Upstream supersedes ours; drop ours on rebase. |
| `5363c84e`, `141159c9`, `8430675` docs | Fork roadmap, one-shot operational facts, restore-under-load SLO + concurrency bug notes. | Documentation of our private measurements; no upstream equivalent. |
| `3af39256` fix(benchmark) | `contains_output_line`: `rstrip(b"\r")` so `\r\r\n` console lines don't hide markers (~1/2000 false restore failures). | **Still broken upstream**: `upstream/dev:scripts/nvx_tools/benchmark.py:1294` still `removesuffix(b"\r")`. Candidate to upstream. |
| `041c67a7` feat(warmpool) | Pre-captured snapshot pool manager (`scripts/nvx_tools/warmpool.py`, 313 lines) + `05695641` CPU-class portability matrix and pool class tags. | **No upstream equivalent** (no warm-pool/pool-manager code in `upstream/dev`); upstream #117 "pooled benchmark retry" is CI-side only. Fork-only feature. |
| `a065aa3c` feat(sandbox) | EPIPE retry on provision/start + persistent exec daemon (`execd`, `scripts/nvx_tools/sandbox_lifecycle.py`). | **Partially overlapping, not equivalent**: upstream suppresses SIGPIPE at a barrier (`ea0abfbf`, #288), retries transient *Windows* pipe reconnects (`aa1f8ca4`, #67), stops output readers before closing descriptors (`d816655d`, #330). None is a provision/start EPIPE retry and there is no persistent exec daemon upstream; `7f1eff12` (#363) reaps direct-mode execs but per-exec, not via a daemon. |
| `9f9277af` fix(sandbox) | Retry `sandbox start` once with the full timeout when the managed control endpoint stalls (bounded first wait `NVX_START_FIRST_WAIT_S`=8 s; measured 0.2–0.46 % of starts). | **Different mitigation upstream for the same symptom family**: #441 `8513233b` fixes a capability-pipe start race and #439 `bb2ba395` makes failed starts publish an outcome report. Neither bounds/retries the endpoint-stall hang; whether #441 eliminates our 0.2–0.46 % stall is (unverified). |
| `07adc613` | Merge #3 (boot-tail retry). | — |

Also documented-but-unfixed in our notes: `guest_exit_prequeued` footgun (SIGABRT in
~1 % of tight-loop restores when omitted). Upstream still requires the explicit flag
(`upstream/dev:scripts/nvx_tools/benchmark.py:1780,1914,1919,1977,2001`); related but
narrower hardening landed in #379 (`f748476b`, monitor `measure_once`'s console to its
end).

---

## 3. Client-visible changes for a gateway calling nvx

The CLI is `scripts/nvx.py` (argparse; 96 `add_argument` calls now vs 78 at the fork
point). All citations are `upstream/dev` file:line.

**New flags / subcommands**

| Change | Commit / PR | Location | What a gateway observes |
|---|---|---|---|
| `run --cpu-profile {auto, built-in ID, host}` | `33aa16ae` #394 | `scripts/nvx.py:1055`, passed at `:511` | Per-run CPU profile; restore ignores it (snapshot's profile wins). |
| `--mount-owner {vmm,caller}` (run + sandbox) | `7d103aa6` #391 | `nvx.py:1094` (run), `:1255` (sandbox); choices `scripts/nvx_tools/sandbox.py:34` | Host identity for virtio-fs file ops; requires `--mount` (`nvx.py:519,646`). |
| `--mount-allow`, `--mount-write` (run + sandbox) | `c0961d83` #413 | `nvx.py:1075/:1083` (run), `:1234/:1244` (sandbox) | Per-path re-exposure inside a `--mount-deny`; writable subpaths of an `rw` share. |
| `sandbox exec --cwd`, `--environment`, `--environment-file`, `--inherit-default-environment` | `78d80d18` #288; `e7a8bf06` #328 | `nvx.py:1187,1191,1198,1204`; validation `:574-612` | Per-execution cwd and exact/layered env. |
| `run --mount` repeatable (≤ `MAX_MOUNTS = 2`, optional mode) | `c2200425` #401 | `sandbox.py:31`; validation `nvx.py:513-514` | Two shares with independent modes; `--mount-deny/allow/write` bind to the preceding `--mount`. |
| `--guest azurelinux` | `f85bb718` #110 | `scripts/nvx_tools/guests.py:87` | New guest OS enum value. |
| `build-kernel --debug`, `build-initramfs --debug-kernel` | `b267c472` | `nvx.py:852`, `:815` | CI debug kernel with watchdogs. |
| New subcommand `doctor` (host qualification H1–H3) | `8de77c62` #325 | `nvx.py:994-998`; `scripts/nvx_tools/doctor.py` | Fails closed on unreadable host facts. |
| New subcommand `test-aci-edge-sandboxes` | PR #307/#418 area | `nvx.py:1000-1005` | Runs the Rust crate lifecycle test (§1.7). |
| `classify-ci-changes`; `check-required-ci --run-openvmm-unit-tests/--run-openvmm-vmm-tests` (both `required=True`) | `8bf8a891` #436 | `nvx.py:930,939,945,967-968` | CI-helper surface only; invoking check-required-ci without the new flags now fails. |

**Changed semantics**

- `--cpu-profile auto` falls back to a **host profile** on unserved Intel/AMD CPUs
  (with an OpenVMM warning) instead of failing — `c917dad1` #435, guidance at
  `nvx.py:545-565`; `E_PROFILE_HOST_UNKNOWN` remains for other vendors/ambiguous
  catalogs (`doc/usage.md:541`, error table `doc/design/time-abi.md:1775`; catalog:
  skylake-sp, icelake-sp, emeraldrapids, alderlake, milan, genoa, turin —
  `doc/ci.md:464`). `benchmark` now refuses unidentifiable CPUs before measuring.
- Extended EXEC payload: header flags bit 0 = absolute cwd (≤4096 B), bit 1 =
  environment (≤256 entries, unique keys, **replaces** default), bit 2 = layer over
  default — spec `doc/design/sandbox-filesystem-and-agent-architecture.md:291-307`
  (`f3ba5206`); Python encoder `scripts/nvx_tools/control_session.py:456-530`
  (`encode_exec_environment` `:51`); Rust `WorkloadEnvironment::{Default,Replaced,
  Layered}` `aci_edge_sandboxes/src/openvmm/protocol.rs:189-199`. Omitted vs
  explicitly-empty env are distinct (`69ae011a` #328).
- Unusable working directory now a **typed failure** (`ExecFailure::WorkingDirectory`,
  `aci_edge_sandboxes/model/src/outcome.rs:58-63`; protocol category `cwd-failed`,
  `protocol.rs:44`) instead of looking like the workload exiting 125; direct launches
  refuse before starting (`9ebc6f96` #333, `guest/common/nvx-managed-agent.c`);
  `ExecRequest::with_cwd` `model/src/model.rs:443-447`.
- Managed workloads now see a correct `PWD`; failure to set it exits 125 (`ed46e7d3`).
- Failed managed `start` surfaces OpenVMM's outcome report (e.g. "guest-exit status
  125") instead of "endpoint closed", and no longer leaks `.tmpXXXXXX` staging files
  that blocked `deprovision` — `bb2ba395` #439, `scripts/nvx_tools/sandbox_lifecycle.py:477-499`.
- A subprocess that cannot start (missing executable, EACCES) prints
  `error: failed to run command <cmd>: <oserror>` and exits 1 instead of a Python
  traceback — `87406b00` #399, `scripts/nvx_tools/common.py:120-121,124,310`.
- Stop/exec refuse to act on a recycled PID; new error `cannot determine whether
  OpenVMM process N is running` — `9c39d401` #378, `sandbox_lifecycle.py:332-430`.
- The 32-byte control capability is written to a pipe handed as OpenVMM's stdin
  *before* spawn — removes the `control authentication writer was not closed` race /
  full-`--timeout` hang — `8513233b` #441, `sandbox_lifecycle.py:644-657`; new
  on-disk `state_dir/control.capability` (mode 0600, `sandbox_lifecycle.py:36,634-636`).
- No new env vars for CLI callers (the `scripts/` diff adds no `os.environ` reads).
  `59b7c448` (nvx-exit 32-bit wrap) is test-only, not gateway-visible.

## 4. Performance: upstream baselines vs our 2026-10-02 numbers

Our reference (PRODUCTION-NOTES §3, 128 MiB / 1 vCPU Alpine guest, p50 of 5,
i9-14900K bare metal P-pinned): **cold start 119 ms**, **snapshot restore 7.0–8.3 ms**
bare metal (nested-KVM cloud host: 480–578 ms / 53–61 ms); restore-under-load p50
7.5→14.3 ms from ~24 %→88 % host busy.

**Upstream's tracked numbers are CI-hosted, not bare metal.** `doc/benchmarks.md`'s
series table lists all three series as "Host type: Virtual machine" — "every CI
microVM runner is an Azure virtual machine with an Intel Xeon CPU (Ice Lake-SP or
Emerald Rapids)" — and warns "Bare-metal and virtual-machine results have separate
histories and must not be compared as one regression series". Upstream has **no
bare-metal baseline series**; its only bare-metal latency statements are attribution
notes inside `doc/design/time-abi.md`. The comparison below is therefore reference
context, not apples-to-apples.

Latest upstream blocks (data commit `33bd2fe5`, measured commit `60b22d98`, 2026-10-09;
CSV schema `platform,microvm_abi_version,processors,commit,metric,unit,direction,p50`;
only p50 is tracked — no p95):

| metric (p50, ms) | KVM 1vCPU | MSHV 1vCPU | WHP 1vCPU | ours (bare metal, KVM) |
|---|---|---|---|---|
| `openvmm_cold_start` (boot→`ALPINE-MICROVM-BOOT-OK`) | 272.3 | 229.0 | 464.8 | 119 (cold start) |
| `openvmm_snapshot_restore` | 66.4 | 36.4 | 125.2 | 7.0–8.3 |
| `shell_snapshot_restore_512_mib` | 57.6 | 44.3 | 132.3 | — |
| `openvmm_snapshot_restore_guest_exit_teardown` (first fork/exec/exit) | 46.6 | 8.4 | — | — |
| `openvmm_snapshot_generation` | 1.3 | 4.8 | — | — |

Even the fastest upstream CI restore (MSHV 36.4 ms) is ~4–5× our bare-metal 7–9 ms,
consistent with upstream's own nested-virt CI context; our warm-pool work targets
exactly the bare-metal tier upstream does not track. `restore-under-load` as a concept
exists only in our fork (`git grep` for under-load/contention over upstream `doc/`,
`scripts/`, `.github/` finds nothing).

**Movement since the fork point** (merge-base block vs `60b22d98` block):

| metric | KVM then→now | MSHV then→now |
|---|---|---|
| `cold_start_base` | 308.3 → 310.3 (+2.0) | 311.7 → 269.0 (**−42.7, −13.7 %**) |
| `openvmm_cold_start` | 275.5 → 272.3 (−3.2) | 230.8 → 229.0 (−1.7) |
| `openvmm_snapshot_restore` | 62.5 → 66.4 (+3.9) | 36.5 → 36.4 (−0.1) |
| `network_snapshot_restore` | 82.2 → 70.8 (−11.4) | 45.3 → 43.8 (−1.5) |
| `openvmm_snapshot_restore_guest_exit_teardown` | 56.0 → 46.6 (−9.4) | — |
| KVM 2vCPU `shell_snapshot_restore_512_mib` | 65.4 → 61.4 (−4.0) | — |

The MSHV cold-boot drop matches the time-ABI attribution in `doc/design/time-abi.md`:
"`no_timer_check` from the Hyper-V identity … About 43 to 52 ms (9 to 15 %) faster
`cold_start_base` … on MSHV and WHP; KVM unchanged"; also "an 8-vCPU cold boot takes
1,385 ms without the bit and 299 ms with it" on Azure MSHV. First-command costs are
attributed there too: on Azure WHP runners the first process after readiness takes
"about 5 to 9 ms longer than on the legacy path … one small process started ahead of
it removes 64 to 92 % of the difference"; "On bare metal the cost is a shift:
readiness comes 9.5 ms earlier, and readiness plus the first process takes 4.7 ms
less". The static `nvx-exit` "measured 20 % below the legacy path on bare metal and
30 % below on an Azure 8573C runner" for the exit-cost metric. Restore `cpu_us`
budgets (CI-enforced): KVM **6.5 + 1.5 ms** (`c4f04995`), final per-backend budgets in
`91849f78`; KVM restore CPU budget raised from an earlier value in `32849acb`.

Metric set: 37 p50 values per series — 34 at one vCPU, one at each higher count, 111
across the matrix (`doc/benchmarks.md:62-63`; #116 retired the 64 MiB rows →
`719fe8c1`; counts corrected by `0e22176f`). Regression gate: ">40 % worse and
>5 ms" for lower-is-better ms metrics (`4bd3e790`), minority-regime stability guard
p50 >25 % above p25 (`349ec8cb`), CI device contract "one warmup and ten retained
attempts" (`dc059809`).

---

## 5. Takeaways for the fork

1. Rebase is *not* trivial: #325 (time ABI), #394/#435 (CPU profiles) and #418 (edge
   backend) each touch the same files as our affinity/warmpool/execd work
   (`scripts/nvx.py`, `sandbox_lifecycle.py`, `benchmark.py`).
2. Drop `fa60c840` in favor of upstream #323 on any rebase.
3. `3af39256` (CR-stripping) is a clean upstream contribution candidate; nothing in
   the task authorizes sending it today.
4. Upstream has no warm pool and no persistent exec daemon — our two biggest
   latency-oriented features remain differentiators.
5. Watch the unmerged `esaurez/nvx-image-slots-*` and `streamed-snapshot-preprofile`
   branches: they will reshape the snapshot layout our warmpool depends on.
