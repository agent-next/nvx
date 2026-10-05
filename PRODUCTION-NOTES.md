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

Restore latency under host load (P-core class, spinners + benchmark pinned to the same
cores, measured busy from /proc/stat, n=30 per level): ambient ~24% → p50 7.5 / p95 8.2;
53% → 9.1 / 10.8; 78% → 12.1 / 16.0; 88% → 14.3 / 20.3 ms. The warm path stays
p95 ≤ 21 ms at ~90% measured CPU busy.

## 4. One-shot sandbox path works end-to-end

`sandbox run` with the shipped `ubuntu-distro.erofs` layer + a preformatted ext4 scratch
boots Ubuntu 26.04.1 userland, assembles the overlayfs, runs the entrypoint as uid 65534
with dropped capabilities, and reports `NVX-SANDBOX-READY` / clean exit. Guest-side
failures (e.g. malformed scratch) surface as explicit `NVX-SANDBOX-ERROR` + non-zero
guest status, which is good honest failure.

## 5. One-shot sandbox operational facts (found driving real workloads)

Verified on the dedicated droplet with a debian:bookworm EROFS layer (python3, git, curl,
chromium, blender) running four real workload classes end-to-end:

- **`sandbox run` does not pass host environment variables into the workload** (documented
  upstream). The working pattern is a per-sandbox `env.sh` written into the rw `--mount`
  payload directory, sourced at the top of the workload script.
- **The portable network profile has no guest DNS resolver.** Real internet egress works via
  `--network-proxy 10.0.0.1:3128` plus a host-side forward proxy (tinyproxy): `curl -x` /
  `chromium --proxy-server`. DNS then resolves host-side. Without this, every name lookup
  in the guest fails.
- **The guest agent validates the workload home directory exists.** Debian's `nobody` user
  has home `/nonexistent`; a layer built from a debian rootfs must create that directory or
  every sandbox exits with `NVX-SANDBOX-ERROR: configured workload home is unavailable`.
- **Debian's blender is built without OpenImageDenoiser**; Cycles renders fail at denoise
  time unless `cycles.use_denoising = False`. Headless blender also needs libgl1/libegl1
  even for CPU renders (install them in the layer).
- **Layer build path that works**: docker container with the real toolchain → `docker
  export` → extract → `mkfs.erofs -z lz4hc -U <uuid>` → use as any layer role. A 975 MiB
  debian+blender+chromium layer boots and runs all four classes.

## 6. Latent benchmark bugs found at concurrency (fixed here)

Both surfaced only when restoring in a tight multi-worker loop (warm-pool bench), never
in the sequential suites:

- **`guest_exit_prequeued` omission aborts OpenVMM.** Calling the restore path without
  `guest_exit_prequeued=True` makes the harness write `guest-exit.sh` into the guest
  console after the marker while the restored workload is already exiting on its own;
  the input race ends in `OpenVMM exited with status -6 (SIGABRT) during teardown` in
  ~1% of runs even though the marker fired and the restore succeeded. The
  shell-snapshot-restore suite passes the flag; any new caller must too (warmpool does).
- **Doubled carriage return hides a marker line.** The guest console occasionally emits
  `\r\r\n` after the marker; `contains_output_line` stripped only one `\r`, so a printed
  marker line was missed (~1/2000) and a successful restore reported as a failure.
  Fixed with `rstrip(b"\r")` + regression test.

## 7. Boot-storm EPIPE on the managed control pipe (fixed here)

A 128-simultaneous-boot thundering herd broke ~13% of `sandbox start` calls with
`error: [Errno 32] Broken pipe` at ~3.8s: the freshly spawned OpenVMM process dies or
drops the control endpoint before the auth handshake/ping completes (capability
stdin write, attach, or first ping all surface as `BrokenPipeError` /
`ConnectionResetError` or an endpoint-closed `ConnectionError`).

**Fix in this branch.** `sandbox start` retries through
`_with_control_retry` — 3 attempts with 0.5s/1.0s backoff — on `ConnectionError`
(which covers `BrokenPipeError` and `ConnectionResetError`; `provision` never
touches the control pipe, so it has no retry wrapper). Each start attempt tears
down the failed OpenVMM process and respawns it, so a retry is a clean boot. Retries
log `sandbox start attempt N failed: ...` to stderr. `sandbox exec` is deliberately
not retried: a managed exec failure stays honest.

**Boot-tail variant (fixed here).** A rarer start failure (measured 0.2-0.46%
of starts, ~30s each, occasionally a hard fail) is the endpoint never accepting:
`TimeoutError: managed control endpoint did not become available`. Waiting the
full `--timeout` (default 60s) for a boot that is already stalled wastes the
whole window, so `sandbox start` now bounds the first attempt's
`ControlSession.connect` window — the endpoint wait plus the attach handshake
that shares that timeout — to ~8s (`NVX_START_FIRST_WAIT_S`, default `8`; the
post-connect readiness ping still gets the full timeout). On the endpoint-unavailable
`TimeoutError` the failed process is torn down by the same cleanup path as any
other start failure (runtime/capability/socket state unlinked, process
terminated), then one retry boots a fresh process with the full timeout; a
second endpoint timeout propagates honestly. The inner retry sits inside
`_with_control_retry`, so pipe-class `ConnectionError` retries still compose —
each outer attempt is one short probe plus at most one full-timeout boot, and a
single start call never runs more than one live OpenVMM process. Other
`TimeoutError`s (e.g. `managed control response timed out` after the endpoint
accepted) are not in this class and still propagate without a retry.

## 8. Persistent exec daemon (`sandbox execd`)

`sandbox exec` pays a full Python cold start (~200 ms floor at low load) because it
re-imports the toolchain and re-opens a control session per call. `sandbox execd
--state-dir D --socket PATH` is a long-lived single-operator daemon that holds one
`ControlSession` and serves a one-line JSON protocol over a unix socket (mode 0600,
no auth — same trust boundary as `control.capability`):

- request: `{"cmd": ["/bin/sh","-c","..."], "timeout_ms": 30000}` (`timeout_ms`
  optional, 0 disables the guest timeout)
- response: `{"rc": int, "out": str, "err": str, "b64": bool}` — `out`/`err` are
  base64 only when `b64` is true (non-UTF-8 output); malformed requests and guest
  rejections get `{"error": str}`.

The daemon refuses to start when the sandbox is not running, execs through the same
`session.exec` path as `sandbox exec` (one request per connection, connections served
serially since the session is a sequenced protocol), exits non-zero when the VM dies
so clients re-provision, and removes the socket file on exit (SIGTERM unwinds through cleanup; only
SIGKILL leaves the socket file behind — remove it before restarting). While the
daemon lives it holds the control channel: external lifecycle ops such as
`sandbox stop` time out — kill the daemon first.
