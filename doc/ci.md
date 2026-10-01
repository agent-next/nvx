# Continuous integration

The GitHub Actions workflow has two microVM test layers on Azure-hosted
self-hosted KVM, MSHV, and WHP virtual machines. Each backend has a pool of
three runners labeled by operating system, backend, and `virtual-machine`.
Jobs target the shared backend labels so any available matching runner can
execute them. This allows the backend lanes to execute concurrently without
binding a workload to a specific host. `openvmm-vmm-tests` downloads the NVX
guest artifacts and uses the Linux-direct kernel and Alpine initramfs to
exercise OpenVMM's Linux MP-table lifecycle, TTRPC, and snapshot contracts.
`openvmm-unit-tests` runs the OpenVMM unit and documentation tests independently
on the same backend matrix.
Failed `openvmm-vmm-tests` jobs upload Petri's `test_results` directory,
including guest and VMM logs, screenshots, and watchdog inspection data.
These seven-day artifacts are named
`openvmm-vmm-tests-<os>-<backend>-<run-id>-<run-attempt>`, so a successful rerun
does not replace the failed attempt's diagnostics. Linux collects them from
`openvmm/target/vmm_tests/test_results`; Windows uses
`<runner-temp>/<backend>/test_results`.
The `nvx-microvm-tests-{kvm,mshv,whp}` jobs consume the NVX Linux kernel and
the NVX Linux kernel plus the selected Alpine or Ubuntu initramfs and exercises
Linux, SMP, virtio, sandbox, and snapshot behavior through the public OpenVMM
CLI. Alpine-control-only scenarios remain explicit and are rejected for the
Ubuntu initramfs. Failure logs from the NVX layer are uploaded per backend.
Every harness launch, in the tests and the benchmarks, scans the OpenVMM
console for the guest's [time ABI](design/time-abi.md) output. An
`NVX-TIME-ABI-VIOLATION` event or a failed `NVX-TIME-ABI` conformance line
fails the scenario at once with the guest's code and detail. An OpenVMM exit
status of 193, 194, or 195 is reported as the guest's time ABI conformance,
runtime-violation, or restore-repair power-off, together with the event that
preceded it, instead of as a generic exit status.
The restore-processor scenario also rejects Linux TSC instability diagnostics,
even if the requested CPUs came online, so clock skew cannot silently pass by
falling back to a different clocksource. After the 1/2/4/8-CPU restores, it
restores the same snapshot once without `--restore-processors`. Every restore
runs with OpenVMM lifecycle profiling and must report exactly one
`startup.vp_thread_bind` record. Its `startup.vp_bind_*` records must show that
an explicit MSHV target binds exactly VPs `0..N-1`, while untargeted MSHV
restores and all KVM and WHP restores bind the full capacity.
Captures do not wait for a clocksource: the time ABI registers `tsc` at
`device_initcall` on every backend, so the transitional `tsc-early` window that
once let the clocksource watchdog compare `tsc-early` with jiffies across a
restore (#253) never reaches the guest's userspace.
A restore fails as soon as its guest prints `NVX-RESTORE-PROCESSORS-FAIL`,
rather than waiting for the phase timeout. Restore logs also record OpenVMM's
`adjusted restored vCPU TSC` event for each VP, which includes the applied
snapshot downtime, and its `aligning restored AP TSCs to the BSP` event, which
reports how many created MSHV APs were aligned. When the guest reports
`unstable-tsc`, the harness boots a never-restored eight-vCPU guest with the
same forced warp check and reactivates each AP 20 times. The error then states
whether this control also found TSC instability, which points to host or
hypervisor clock skew rather than restore alignment, and whether the host CPU
exposes an invariant TSC. The control log is kept as
`restore-processors-tsc-control.log`. The control only classifies the
failure; the restore still fails.

Every job that uses the `validate-runner` action first qualifies its runner
for the time ABI with `nvx.py doctor --checks H1 H2 H4 --no-openvmm
--ci-schedule` (see [Host qualification](#host-qualification)): the backend,
the CPU fingerprint and generation, and the TSC rate stability on its short
schedule. The job has no OpenVMM binary yet, so H2 skips OpenVMM's CPU profile
check. This replaces the earlier `nonstop_tsc` check and takes a few seconds.
It reports the CPU generation, the CPU profile that `auto` selects, and the
measured TSC rate in the log and the job summary, and fails the job with a
stable code when the runner is not qualified, for example
`E_PROFILE_HOST_UNKNOWN` on an unknown CPU generation.
Qualification gates only on measured properties, alike on every backend: the
host OS's invariant-TSC flags and clocksource are recorded as evidence, and
the guest warp probe in the microVM scenarios measures the skew that a host
without an invariant TSC causes. On such an MSHV runner VM, never-restored
guests hit cross-vCPU TSC warps when an idle host CPU woke (#211, #265), which
is why the probe schedule includes idle gaps. Runner labels do not encode the
generation; per-PR CI captures and restores on one runner, so generations
never mix.

The `restore-tsc-sync` scenario repeats the restore-processor sequence with
the test-only kernel option `clearcpuid=tsc_adjust`. Linux normally skips its
cross-CPU TSC warp test when `IA32_TSC_ADJUST` is available and consistent
within a package. This scenario verifies that the feature is masked, forcing
the live CPU-online check even on those hosts, while retaining the existing
TSC-instability guard. It does not force a fallback clocksource or retry failed
restores. Its logs are kept in a separate `restore-tsc-sync` subdirectory.
Run it alone on Windows with:

```powershell
python scripts\nvx.py test-microvm --backend whp --scenario restore-tsc-sync
```

This regression targets the WHP clock instability tracked in #19; a passing
frozen-counter check is not sufficient to validate a fix.

The `console-exit` scenario delays host console reads for two seconds after
snapshot restore to exercise output backpressure. For each requested processor
count it requires byte-exact delivery of a 64 KiB payload and the final marker,
and preserves guest exit statuses 0 and 37. This checks both device and host-relay
draining without adding sleeps to the measured benchmark workloads.
The harness waits for the output reader's EOF notification even after the
process exits, so delayed final output chunks cannot create a false failure.

Shared guest artifacts are built with Docker on a GitHub-hosted Ubuntu runner.
The kernel, Alpine initramfs, Ubuntu initramfs, and Ubuntu EROFS layer use
separate cache keys. Ubuntu keys include the Canonical archive pin,
supplemental package lock, common guest sources, shared download and guest
descriptor modules, converter implementation, and Dockerfile. Artifact upload
retains the Alpine filenames and adds the distinct Ubuntu filenames. Each
backend also boots the Ubuntu initramfs and runs
`/sbin/nvx-sandbox-smoke` from the Ubuntu EROFS layer as UID/GID 65534 over a
fresh ext4 scratch copy. The same entrypoint then verifies a live virtio-fs
share inside the container: a read-write `/workspace` share with a denied
subdirectory must round-trip guest writes to the host, and a read-only
`/opt/hostedtoolcache` share must reject writes and symbolic links. In the
read-write share, the guest also exercises the symbolic-link primitives that
package managers use: it creates an npm-style relative `.bin` link to an
executable and runs it through the link, renames, replaces, and removes links,
and creates absolute, dangling, outside-the-share, and denied-path links. The
host then checks that every target is preserved exactly (on Windows, by
decoding each WSL-style reparse point, which Windows does not follow) and that
no link read or modified host data outside the share or in the denied path. A
managed sandbox then repeats
the read-write check through `provision`, `start`, `exec`, and `stop`, and must
report a successful outcome with a cleanly unmounted scratch filesystem, which
shows that `stop` unmounted the share and overlay first. Linux/KVM runs the
broader Ubuntu SMP, managed lifecycle, network snapshot, blockless snapshot,
and workload-identity set.

OpenVMM release executables and provenance are built once by the independently
addressable `build-openvmm-linux-gnu`, `build-openvmm-linux-musl`, and
`build-openvmm-windows-msvc` producer jobs. KVM workloads and MSHV microVM tests
consume the GNU artifact, MSHV platform workloads consume the musl artifact,
and WHP workloads consume the Windows MSVC artifact. Each workload can start
after its compatible OpenVMM producer and the shared guest-artifact job finish,
without waiting for unrelated OpenVMM targets.

All three producers call the same Python build workflow, passing the validated
runner backend explicitly through `build-openvmm --backend`. The backend is
carried in `OpenVmmBuildConfig`; the build workflow maps KVM, MSHV, or WHP to
GNU, musl, or MSVC without probing runtime devices. CI therefore retains its
musl build for MSHV without maintaining a separate shell build path.

The kernel and initramfs cache keys include
[`build_config.py`](../scripts/nvx_tools/build_config.py) and
[`build_constants.py`](../scripts/nvx_tools/build_constants.py), so shared build
configuration or constant changes invalidate cached guest artifacts and their
provenance. The Ubuntu distro layer shares the Ubuntu input hash.

The producer handoff uses one-day workflow artifacts rather than caches. Each
consumer downloads both the normalized executable and its build provenance,
then restores executable permissions on Linux. Once the required artifacts are
ready, benchmarks run in parallel with the NVX test layer and use any available
runner in the matching backend pool. All three use virtual-machine performance
series and the constrained eight-CPU affinity policy. Development releases and
performance baseline updates still require every applicable test and benchmark
lane to pass.
The microVM correctness jobs gate every use of benchmark results, so the
benchmark action runs no correctness scenario of its own (#286). `Required
status check` requires each `nvx-microvm-tests-*` job that the change schedules
to succeed. `Publish development release` and `Persist performance
baseline` run only on `dev` pushes in which every microVM test job succeeded or
was skipped. The pull-request `Performance regression gate` reads only the
platform jobs' results and publishes nothing. The counting LAPIC that the
benchmarks depend on is covered by the `smp` scenario of those jobs. The workflow uses the read-only OpenVMM deploy key stored in the
`OPENVMM_DEPLOY_KEY` Actions secret to fetch the private submodule at its pinned
commit. Shared guest binaries and development release packages move through
short-lived workflow artifacts alongside the OpenVMM handoff and benchmark
results. Caches only accelerate reproducible build inputs and outputs; consumers
do not depend on them as a handoff.
Pull requests gate regressions against recent matching-platform history, and
successful pushes to `dev` append their p50 values under `data/`. Metadata-only
performance jobs use GitHub-hosted Ubuntu runners. Provisioning instructions
are in the [runner bootstrap guide](../scripts/setup/README.md).

Persistent runners accept pushes and same-repository pull requests only. Fork
pull requests run the GitHub-hosted validation jobs but do not execute code on
the Azure runner fleet. A maintainer must stage an external contribution on a
trusted repository branch before running the backend matrices.

## Host qualification

`python3 scripts/nvx.py doctor --backend <kvm|mshv|whp>` qualifies a host for
the [time ABI](design/time-abi.md#host-qualification). It runs checks H1 to H7
in order, prints one `NVX-DOCTOR: check=<id> status=<pass|fail> detail="..."`
line per check, and exits with status 1 if any check fails. `--checks` selects
a subset, and `--summary` appends a Markdown table with the CPU generation,
profile, rates, and skew metrics to a file such as `$GITHUB_STEP_SUMMARY`. H4
and H6 run on the spec's long qualification schedules, which take about three
minutes; `--ci-schedule` selects CI's short ones. A failure that matches a time
ABI failure code starts its detail with the code in brackets, for example
`[E_PROFILE_HOST_UNKNOWN]`.

| Check | Implementation |
| --- | --- |
| H1 | `/dev/kvm` or `/dev/mshv` is readable and writable, and a KVM host has no `/dev/mshv`; on Windows, `WHvGetCapability` reports a hypervisor |
| H2 | Vendor, family, model, stepping, microcode, and OS build from `/proc/cpuinfo` or the Windows registry, and the generation and the profile that `auto` selects from the spec's catalog, which shares one profile per generation across backends: `skylake-sp` (6/85, steppings 0 to 4, `intel.skylake-sp.v1`), `icelake-sp` (6/106, `intel.icelake-sp.v1`), or `emeraldrapids` (6/207, `intel.emeraldrapids.v1`). Any other CPU, including Cascade Lake and Cooper Lake, fails with `E_PROFILE_HOST_UNKNOWN`. Then `openvmm --hypervisor <backend> --cpu-fingerprint <path>` writes the host's CPU fingerprint (by default `nvx-cpu-fingerprint-<backend>.json` in the probe directory; `--cpu-fingerprint` overrides it), checks it against the generation's profile, and prints one `NVX-CPU-PROFILE:` line. H2 requires exit status 0, `status=pass`, the same backend and generation, and a revision of the generation's profile, reports the profile and surface digests, and otherwise fails with OpenVMM's code, for example `[E_PROFILE_UNSUPPORTED]` naming every unsupported CPUID bit. The host OS's invariant-TSC flags (`constant_tsc nonstop_tsc`, or the CPUID bit on Windows) are recorded as evidence and never fail the check, because they don't decide what a guest observes: Azure WHP hosts show the CPUID bit but cannot offer invariant TSC to partitions, and their guests measure tens of nanoseconds of skew |
| H3 | `openvmm --x-time-abi-verify` builds the partition and runs the time ABI preflight without running the guest. Its `NVX-TIME-ABI-VERIFY:` line must report `status=ok` for the backend, plausible declared and native TSC rates, the backend's LAPIC rate, and a revision of the profile H2 names. A failed preflight reports OpenVMM's code, for example `[E_TSC_SYNC_UNSUPPORTED]`. Before the flip, pass `--openvmm-arg=--x-time-abi-v1` |
| H4 | Samples of the TSC against the host's monotonic clocks, with sleeps between them so the host's CPUs idle: 13 samples 10 s apart, or 3 samples 1 s apart with `--ci-schedule`. Each sample reads the TSC between two reads of a clock, keeping the tightest of 64 brackets; its uncertainty is half the bracket plus half the clock's resolution. A clock that returns the same value to consecutive reads is coarser than one read, so the probe takes its smallest step as its resolution: Hyper-V's reference TSC page advances the Linux clocks in 100 ns steps although `clock_getres` reports 1 ns. The interval stability is judged against a clock that time synchronization never steers, `CLOCK_MONOTONIC_RAW` on Linux and `QueryPerformanceCounter` on Windows: every interval between consecutive samples must be conclusive within 0.25 ppm, and the interval rates must agree within 1 ppm. chrony's frequency updates move `CLOCK_MONOTONIC`'s rate by up to several ppm between seconds on the Azure runners, which says nothing about the TSC. The rate over the whole window is measured against the disciplined clock, `CLOCK_MONOTONIC` on Linux, and must lie within 100 ppm of the rate H3 reports when H3 runs in the same invocation. A Linux host's clocksource is recorded as evidence |
| H5 | Pinned-thread ping-pong rounds over every pair of host CPUs; `max_abs_offset_ns` is at most 1,000, the measurement is conclusive, and no pair stalls |
| H6 | A microVM with the largest supported vCPU count up to 8 prints a valid `NVX-TIME-ABI` boot marker and runs `nvx-time-probe warp` over every CPU pair five times, with all vCPUs halted for 0.1, 1, 5, and 1 s between the runs, so that a host without an invariant TSC corrects the guest TSC as idle host CPUs wake (#265); then a 1-vCPU microVM runs it once. Every run stays within 1,000 ns. `--ci-schedule` runs CI's schedule instead: two runs 1 s apart |
| H7 | `adjtimex` reports no `STA_UNSYNC` on Linux; `w32tm /query /status` names a synchronized source on Windows |

H2, H4, and H5 use a dependency-free host probe,
[`host_time_probe.rs`](../scripts/nvx_tools/host_time_probe.rs), which the
doctor builds with `rustc` once per source version into
`$RUNNER_TOOL_CACHE/nvx-host-time-probe` (or `build/host-time-probe` outside
CI). H2's profile check, H3, and H6 need the OpenVMM binary, and H3 and H6
also need the guest artifacts; `--openvmm`, `--kernel`, and `--initrd`
override their default build paths. `--no-openvmm` qualifies a host without
OpenVMM: H2 then checks the CPU identity and generation only, and H3 and H6
cannot run.

Qualification gates on measured properties, alike on every backend: the guest
warp probe at 1 µs with its idle gaps (H6), the TSC rate stability (H4), and
the CPU profile (H2 and H3). The host OS's invariant-TSC flags and clocksource
are evidence only. In CI, `validate-runner` runs the cheap host-level checks
H1, H2, and H4 before every job, with `--no-openvmm`, because jobs download
OpenVMM and the guest artifacts only later, and with `--ci-schedule`. The
guest warp probe needs a time ABI boot, so it belongs in the microVM boot and
restore scenarios, which run CI's warp schedule after every boot and restore
and assert its verdict once OpenVMM boots the time ABI by default. Without H3,
H4 checks the rate stability without comparing it against the backend's rate.
H5 and H7 remain available for interactive qualification.

## Adversarial campaigns

The separate
[`adversarial.yml`](../.github/workflows/adversarial.yml) workflow runs
Copilot-driven campaigns only on trusted manual dispatches or schedules from
`dev`. It is not part of pull-request CI. The workflow's dedicated
`nvx-adversarial-controller` runner must already have an authenticated Copilot
CLI and an administrator-owned executor wrapper named by the
`NVX_ADVERSARIAL_EXECUTOR` repository variable. The workflow does not install
Copilot or initiate login.

The wrapper provisions a distinct disposable KVM, MSHV, or WHP target with no
production or GitHub credentials and forwards only the typed executor
protocol. Existing persistent microVM and performance runners are not valid
adversarial targets. Loss of the target heartbeat, a policy oracle, or a
teardown/post-campaign boot failure fails the job and requires quarantine and
reimage.

Normal Actions artifacts contain only the guest-text-free public summary,
catalogued case identifiers, and replay manifest. The external provisioner
must collect controller transcripts and complete target logs into
access-controlled security storage. See
[Copilot-driven adversarial testing](design/copilot-adversarial-testing.md)
for the architecture and operational contract.
