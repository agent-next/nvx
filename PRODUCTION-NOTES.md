# Production notes: NVX on hybrid desktop parts

Findings from a full evaluation (2026-10-02) of NVX 0.1.0
(`v0.1.0-dev.38e511648019`) on:

- bare-metal Intel i9-14900K (8 P-cores + 16 E-cores, Linux 6.14, KVM)
- DigitalOcean droplet, Xeon Platinum 8358, nested KVM

## 1. Snapshot restores fail on hybrid CPUs without core-type pinning (fixed here)

**Repro.** `test-microvm --backend kvm` aborts at the first restore scenario and every
benchmark snapshot stage fails with:

```
destination CPU contract does not match the snapshot; first CPUID difference:
CpuContractCpuidLeaf { function: 4, index: Some(0), ... 46137407 ... 29360191 ... }
```

**Root cause.** KVM exposes CPUID leaf 4 (deterministic cache parameters) per physical core
type. On a hybrid part the OpenVMM vCPU thread can migrate between P and E cores between
capture and restore, so the saved and destination CPU contracts differ and OpenVMM's
validation (correctly) rejects the restore. The default benchmark affinity set
("one logical CPU per physical core") spans both core types, and `test-microvm` applies no
affinity at all.

**Fix in this branch.** Hybrid-aware CPU selection:

- `cpu_frequency_classes()` groups logical CPUs by `cpuinfo_max_freq`, merging frequencies
  within 10% (turbo-favored cores of one type report slightly different maxima and must not
  split a class).
- `apply_hybrid_cpu_filter()` restricts the benchmark default affinity set to the
  performance class on hybrid parts. `NVX_CPU_CLASS=efficiency` selects the E-core class,
  `NVX_CPU_CLASS=all` restores the old behavior.
- `nvx.py` binds its own process (inherited by children) to the selected class for
  `run` / `test-microvm` / `sandbox`, except for `benchmark`, which manages per-process
  affinity itself.

**Verified by execution** on the i9-14900K: `test-microvm` (all 26 scenarios) and the e2e
benchmark pass with no external `taskset`/`--cpus`. Homogeneous hosts are unaffected (the
filter is a no-op with a single frequency class).

**Fleet implication.** Snapshot pools are portable only within one core type. Restore
workers must be pinned to the capture core type; a snapshot taken on a P core cannot be
restored on an E core even with this fix (that is OpenVMM's contract, not a bug).

## 2. `nvx.py download` install blocks later `git submodule update --init`

`download` installs the release binary into `openvmm/target/release/openvmm`, leaving
`openvmm/` non-empty. A later `git submodule update --init openvmm` then fails with
"destination path already exists and is not an empty directory", and every
`benchmark --skip-build` run errors on the missing `openvmm/Cargo.toml` (the submodule's
existence is used as the source-present gate). Workaround: move `openvmm/target` aside,
init the submodule, move the binary back. The installer should either leave the binary
outside the submodule path or the submodule init should tolerate the installed tree.

## 3. Measured numbers (128 MiB guest, 1 vCPU, Alpine, p50 of 5)

| metric | i9-14900K bare metal (P-pinned) | DO nested KVM (Xeon 8358) |
|---|---|---|
| cold start | 119 ms | 480-578 ms |
| snapshot restore | 7.0-8.3 ms | 53-61 ms |
| restore peak RSS | 33 MiB | 35-38 MiB |
| idle CPU per VM (256 idle) | confounded by desktop load | 0.0013 vCPU, 74 MiB RSS |
| parallel cold boots | 32-43/s (0 fails, 16/64 waves) | — |

Idle density on the cloud host: 256 concurrent idle microVMs at 2.1% of 16 vCPU.

## 4. One-shot sandbox path works end-to-end

`sandbox run` with the shipped `ubuntu-distro.erofs` layer + a preformatted ext4 scratch
boots Ubuntu 26.04.1 userland, assembles the overlayfs, runs the entrypoint as uid 65534
with dropped capabilities, and reports `NVX-SANDBOX-READY` / clean exit. Guest-side
failures (e.g. malformed scratch) surface as explicit `NVX-SANDBOX-ERROR` + non-zero
guest status, which is good honest failure.
