# Upstream sync, 2026-10-14

## Target and method

Runtime target: microsoft/nvx `dev` at **4acf7eb0bb73b88cfb5a01bb6043592af1e96c61**,
release `v0.1.0-dev.4acf7eb0bb73`, OpenVMM gitlink
`7f225e2cd635bbd1e1839e587e659996433396c8`.
This sync also includes upstream's data-only child
`c073ebcd`, which updates performance CSVs without changing runtime inputs.
No fork history was rewritten.

Comparison since the previous analysis: `33bd2fe5..4acf7eb0`, not the old
fork's much larger merge-base delta. The old analysis is historical:
[`UPSTREAM-DELTA-20261009.md`](UPSTREAM-DELTA-20261009.md).

Sources below marked **upstream** refer to the
[exact 4acf7eb0 tree](https://github.com/microsoft/nvx/tree/4acf7eb0bb73b88cfb5a01bb6043592af1e96c61),
so their line numbers do not drift when fork patches add lines.
Disposition was checked against upstream log and code, using `git log`,
`git show`, and `git diff`; an absent equivalent means none was found in
the inspected upstream tree, not that every issue was searched.

## All 24 original commits

| Original SHA | Patch | Decision | Evidence and implementation |
| --- | --- | --- | --- |
| ec38aa01 | Hybrid affinity / NVX_CPU_CLASS | Rewrite | CPU-class placement is opt-in (`performance` or `efficiency`); unset, empty, or `all` preserves the default in both ordinary commands and benchmarks. Ordinary commands preserve SMT siblings; explicit benchmark `--cpus` overrides class selection. Upstream CPU profiles (16237e29, 00f8884d, PRs #394/#435) supersede the historical cross-class rejection: both auto and intel.host.v1 restored across P/E successfully. |
| a4811e5e | Provenance fixture isolation | Keep | Fixture repositories use an explicit nondefault branch for reproducible commits; retained as 6d890682. |
| ac82a417 | setup-submodule | Keep | Upstream release installs a binary into the uninitialized submodule directory; no preservation helper there. Retained as 5f0fd1a0; usage added in cc53b463. |
| fa60c840 | Wait for async process-tree kills in tests | Drop | Upstream df532ce2 (fixes microsoft/nvx #320) waits for killed descendants and repairs the same oracles. |
| 5363c84e | Operational notes | Drop | Only neutral technical observations retained in PRODUCTION-NOTES.md. |
| 141159c9 | One-shot operational facts | Keep | Historical technical observations, no upstream equivalent; 6f0503b9. |
| 3af39256 | Doubled CR marker fix | Keep | Upstream `contains_output_line` removed only one CR; retained rstrip correction as fa97deab. |
| 041c67a7 | Warm pool | Rewrite | Upstream has snapshot primitives but no fork pool CLI. Adapted capture signature as 34a0a8ef. Pool entries remain bare snapshots, not managed state directories. |
| 84306756 | SLO / warm-pool evidence | Keep | Fork-specific historical evidence; 7b61da8d. Not a fresh performance receipt. |
| 05695641 | CPU-class matrix / pool tags | Rewrite | Adapted capture API as 667f4adf. Replaced obsolete cross-class-refusal oracle with same- and cross-class readiness checks using the host profile; real KVM proves both succeed. Pool frequency tagging remains conservative placement metadata. |
| a065aa3c | execd / EPIPE retry, fork PR #1 | Rewrite | c1da7eb8 retains daemon and transport retries, reuses upstream `ManagedExecRefused`, capability pipe, PID/start-time identity, and lifecycle lock. cc53b463 excludes intentional endpoint closure from retries. |
| 9f9277af | Boot-tail retry | Rewrite | 1fafd679 retains unavailable-endpoint retry and threads its bound into upstream startup. Upstream start at :979-982 has no such retry; bb2ba395 supplies safe teardown, not retry. |
| 07adc613 | Merge fork PR #3 | Drop merge | No additional patch beyond 9f9277af. |
| 7cf6608e | 10-09 upstream analysis | Keep | Historical document, b108ad0a; this document supplies the newer delta. |
| e96fa381 | Correct analysis figures | Keep | Historical factual correction, 1ffa07cd. |
| 05203da5 | Correct analysis citations | Keep | Historical factual correction, 7c5f9e96. |
| 293a31ed | Merge fork PR #5 | Drop merge | No additional patch beyond the three analysis commits. |
| ced8288b | Snapshot / processors | Separate PR | [Snapshot/processors PR #7](https://github.com/agent-next/nvx/pull/7) adds format 7, not old fork format 3; upstream already owns formats 3-6. Not implemented in this branch. |
| 1f67500f | Snapshot config live share | Separate PR | PR #7's format 7 uses upstream's full `mounts` representation, including owners, policies, and file kind. Eleven snapshot regression oracles added there. |
| 82e93566 | Snapshot console namespace | Separate PR | In PR #7 the managed control endpoint lives beside the snapshot, with collision rejection and external-endpoint cleanup. |
| 80d21fd9 | Private snapshot parent | Separate PR | PR #7 validates plain parent, current owner and mode 0700 on POSIX; rejects symbolic links, missing restore directories and existing capture destinations. |
| 9fba310a | Capture before consuming scratch | Separate PR | In PR #7 the guest trigger runs after layer/rootfs/share assembly, before managed agent or one-shot workload handoff. Successful managed capture returns with no live runtime record. |
| 1b98bf53 | Instance-checkpoint tier | Separate PR | PR #7 reuses upstream `nvx-snapshot --tier instance-checkpoint`; platform/workload-start have different admission rules. |
| c9dc6828 | Paired scratch restore | Separate PR | [Snapshot/processors PR #7](https://github.com/agent-next/nvx/pull/7) omits scratch and workload-identity redeclarations on restore, preserves layers and live shares, removes obsolete `--restore-entropy` (upstream 5a92c86f), and validates complete capture publication without the original scratch. Not implemented in this branch. |

The seven PR #2 commits are consolidated in the separate
[PR #7](https://github.com/agent-next/nvx/pull/7), rather than cherry-picked over
incompatible schemas in this branch. Old fork snapshot-format-3 configs
must be reprovisioned; they are not interchangeable with upstream owner-format-3.

## What a CLI or control client notices since 10-09

### CLI and lifecycle

- The Python entry point remains `scripts/nvx.py`, with a flat
  `sandbox OPERATION` parser;
  no migration to the new Rust API is required merely to launch it.
- Upstream `ed60febb` serializes lifecycle transitions. Provision, start, stop,
  and deprovision now use lifecycle locks and a timeout; busy transitions can
  fail rather than race. **Upstream** `scripts/nvx_tools/sandbox_lifecycle.py:979-982`
  shows start holding the lock. CLI callers can set timeouts; direct
  Python callers must supply the new `provision(..., timeout=...)` argument.
- Upstream `d4f88afc` bounds managed control writes by the operation deadline.
  A partially transferred record closes the session
  (**upstream** `scripts/nvx_tools/control_session.py:433-446`); clients must not
  keep using a desynchronized session.
- `a787963b` supports single-file live shares, `74bb0529` represents several
  shares as children of one virtio-fs device, and `e1efd6a3` accepts commas in
  host-share paths. The final comma still separates access mode. These change
  share lowering, not EROFS block path syntax.
- `07c7506c` and `fd307668` extend policy-file compilation to IPv6 and MXC-shaped
  policy rules. `420f280e` adds bidirectional host-loopback behavior; `54b80b44`
  rejects forwards sharing a guest port and `5cfba311` rejects an unusable /30
  guest network in nvx-rs. These are not a general guest DNS/files API.
- Fork-only commands remain `warmpool`, `setup-submodule`, and `sandbox execd`.
  The stacked rewrite adds sandbox `--processors`, `--snapshot-destination`,
  and `--restore-snapshot`. These are not on pristine upstream's sandbox parser.
  Existing callers keep the one-vCPU default until they explicitly opt in.

### Wire and control protocol

The inspected 10-09 and 10-14 control clients keep the same framing:
outer `NVXS` version 1 and application `NVXC` version 1, with
`<4sHBB16sQQI` and `<4sBBHQiI` headers.
**Upstream** `scripts/nvx_tools/control_session.py:20-31`, `:448-489`, `:491-517`.
The changes since 10-09 harden transfer deadlines and session closure, rather
than introducing a new frame magic. Extended exec carries cwd/environment;
clients must explicitly supply those fields to use them.

The fork execd wire contract is unchanged:
`{"cmd":[...],"timeout_ms":N}` -> `{"rc":N,"out":"...","err":"...","b64":BOOL}`,
or a daemon error object. See
[`exec_daemon`](../scripts/nvx_tools/sandbox_lifecycle.py) for the implementation.
Transport/daemon errors are not guest exit statuses. An execd client timeout
must not trigger an overlapping cold exec while the command might still run
and violate command serialization.

### Snapshots

- The on-disk manifest remains **version 6** across the inspected delta.
  It binds backend, CPU profile, effective CPUID, RAM geometry, processor
  capacity, command line, device order, attachments, layers, scratch, and tier.
  **Upstream** `doc/design/snapshot-and-restore.md:248-283`.
  This is not permission to reuse old fork snapshots from before those contracts;
  recapture for the target binary.
- Upstream `29395bdf` fixes the snapshot VM-clock cut: restore advances VM time,
  RTC and PIT by downtime plus the pre-anchor stop interval. See **upstream**
  `doc/design/snapshot-and-restore.md:319-325`. No new manifest version is
  documented by that change.
- Restore packet v4 and entropy in that packet predate the 10-09 cutoff.
  The old PR #2 restore flag `--restore-entropy` is therefore obsolete, not
  a new 10-14 requirement. Upstream removal: `5a92c86f`.
- Upstream's guest helper already supports instance checkpoints
  (**upstream** `guest/common/nvx-snapshot:4-23`). The fork adds a sandbox
  pre-handoff trigger, not a second snapshot engine.
- The fork config file is distinct from the OpenVMM snapshot manifest.
  **Upstream** `scripts/nvx_tools/sandbox_lifecycle.py:59-87` reserves mount
  formats 2-6. The stacked branch adds config format 7 for snapshots or nondefault
  vCPUs while preserving full mount metadata.
- Instance checkpoints have resume/claim semantics. A bare benchmark pool
  snapshot is not automatically a provisioned managed sandbox, and must not be
  advertised as such. Integrations must provision managed state separately.

### Layer format

No EROFS layer format change was found in `33bd2fe5..4acf7eb0`.
Ubuntu layer content identities still use the EROFS input digest and
deterministic UUID (**upstream** `scripts/nvx_tools/ubuntu.py:1018-1045`).
Sandbox layers retain role/path/UUID, fixed block placement, and private ext4
scratch; see **upstream** `scripts/nvx_tools/sandbox.py:577-615`.
Live-share improvements must not be mistaken for a block-layer format change.
The OpenVMM snapshot contract still validates layer identity and paired scratch.

## Verification receipt

Historical checks from the initial sync head `39a987c7` are summarized below.
The current review-repair checks are recorded in
[PR #6](https://github.com/agent-next/nvx/pull/6).

```text
Pristine 4acf7eb0, all scripts: 2 failed, 1089 passed, 20 skipped
Product, all scripts: 1 failed, 1113 passed, 20 skipped
Rewritten stack, all scripts: 1 failed, 1124 passed, 20 skipped
```

The historical `test_ci_change_detector_classifies_real_git_paths` failure
was corrected by giving its fixture an explicit nondefault branch. The second
pristine failure is fixed by the retained provenance-fixture isolation.
Ruff lint and strict Pyright passed at the initial sync head; these results
did not include Ruff's formatting gate. Final static checking also corrected
retained warm-pool/test typing without changing the execd wire contract.
The retained `guest_exit_prequeued` benchmark argument is already upstream
(`scripts/nvx_tools/benchmark.py:1850`); the real warm-pool restore check exercises it.

Real KVM, matching release, i9-14900K, 128 MiB / 1 vCPU, CPU 0 (P core),
two excluded warmups and 20 retained samples per series:

| Tree | Cold p50 / p95 (ms) | Restore p50 / p95 (ms) |
| --- | --- | --- |
| Product | 174.178 / 222.572 | 9.682 / 12.152 |
| Pristine upstream | 172.800 / 201.723 | 11.747 / 15.426 |
| 10-02 baseline | 120 (p50; p95 not cited) | 7-9 (p50 range; p95 not cited) |

The cold p50 is 45% above the historical baseline, but pristine is nearly
identical on the same current host. This is not evidence of a fork regression.
The host falls back to `intel.host.v1`, with a measured 24.7-ms CPU fingerprint
step in the one-shot log. Time ABI work and shared-host load also differ from
the earlier evaluation; causal attribution is unverified. Two restore attempts were
remeasured by upstream's harness because peak RSS was missed at the marker.
These figures are historical measurements, not a fresh performance check of
the review repairs.

One-shot, managed exec, and three requests on one persistent execd session
passed on KVM, including a guest exit 7 with stderr followed by a successful
request. The full default `test-microvm --backend kvm` suite passed with CPU
affinity 0,2,4,6,8,10,12,14. Pinning the SMP suite to CPU 0 alone was invalid;
pristine reproduces that failure. The corrected CPU matrix also verifies
successful cross-class restore rather than the fork's obsolete rejection oracle.

The stacked branch additionally passed real two-vCPU instance-checkpoint
capture, deletion of the original scratch, paired-scratch restore without
`--scratch`, managed exec, and three requests on the same persistent execd.
Capture publication requires manifest, state, memory, and paired scratch.
The fork init-agent was repacked into the matching release initramfs with
upstream's packer, preserving executable and root-directory permissions.
Five affected default KVM scenarios passed again with that guest.
Warm-pool fill and restore churn also passed with zero leaked claims.

This verifies runtime against a digest-checked matching OpenVMM release, not an
OpenVMM source build. Windows and opt-in-only correctness scenarios were not run.
Fork-only PRs: [product #6](https://github.com/agent-next/nvx/pull/6) and
[stacked snapshot/processors #7](https://github.com/agent-next/nvx/pull/7).
