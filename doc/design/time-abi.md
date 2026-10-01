# Time ABI

[Design index](../design.md)

**Proposed.** This document specifies NVX time ABI v1, the single
guest-visible time, timer, and clock contract of the microVM profile on KVM,
MSHV, and WHP. It is authoritative for the `time-abi-v1` integration branches
of `microsoft/nvx` and `nanvix/openvmm`. When implemented, it replaces the
time rules in [Snapshot and restore](snapshot-and-restore.md#time-and-entropy)
and the clock tokens in [Cold boot](cold-boot.md#effective-command-line).
Entries marked `TBD(<agent>)` wait for that agent's backend implementation or
measurements.

Notation:

| Symbol | Meaning |
| --- | --- |
| `F` | Declared guest TSC rate in Hz, returned by MSR `0x40000022` |
| `F_s` | Declared rate recorded in a snapshot |
| `F_d` | Native TSC rate of the destination partition in Hz |
| `L` | LAPIC timer rate in Hz, returned by MSR `0x40000023` |
| `C` | VP capacity of the machine (1, 2, 4, or 8) |
| `D` | Snapshot downtime in nanoseconds |
| `T_c` | Guest TSC of VP 0 at the capture anchor |
| `g` | Restore generation counter of a VM process |

"Reject" means fail with the named error code and never fall back to another
behavior. Every check in this document is a hard check.

## Scope, goals, and non-goals

Goals:

- One time ABI on every backend: the same CPUID identity, synthetic MSRs,
  CPU time bits, clocksource, tick, timers, and restore semantics.
- No guest kernel patches and no clock command-line tokens.
- No implicit fallbacks. A host or snapshot that cannot meet the contract is
  rejected with a stable error code.
- Restore within one backend across hosts of the same CPU generation and CPU
  profile, including restores after a host reboot.
- Guest monotonic time advances by the snapshot downtime. Wall clock is set
  on every restore and disciplined afterwards.
- RCU-stall, soft-lockup, hung-task, clocksource, and TSC-warp detectors never
  trip across capture and restore. A detected violation fails fast.
- No performance regression beyond the gate in
  [Performance expectations and acceptance gate](#performance-expectations-and-acceptance-gate).

Non-goals:

- Restore across backends or across CPU generations. Both are rejected.
- TSC scaling and RDTSC trapping.
- Paravirtual clocks: kvmclock, the Hyper-V reference TSC page and reference
  counter, synthetic timers, VMGenID, and VMClock.
- A virtual PMU. AMD profiles are deferred until an AMD host is registered.
- Live migration, standard-machine guests, and guests other than the NVX
  Linux 6.18 kernel.
- Snapshots older than manifest version 6. They are rejected with a recapture
  error.

The time ABI is versioned independently of the microVM machine ABI:
`time_abi_version` is 1 in the manifest and in CPUID leaf `0x40000002`, while
the microVM ABI version stays 2. Performance history keys its baselines by
microVM ABI version, so the time ABI does not create a new baseline series.

## Guest-visible contract

### Hypervisor identity

Every VP sees a minimal Hyper-V frequency and invariant-TSC identity. OpenVMM
configures exactly these six leaves on every backend:

| Leaf | EAX | EBX | ECX | EDX |
| --- | --- | --- | --- | --- |
| `0x40000000` | `0x40000005` (maximum leaf) | `0x7263694d` (`"Micr"`) | `0x666f736f` (`"osof"`) | `0x76482074` (`"t Hv"`) |
| `0x40000001` | `0x31237648` (`"Hv#1"`) | 0 | 0 | 0 |
| `0x40000002` | `0x0058564e` (`"NVX"`, build) | `0x00010000` (time ABI 1.0) | 0 | 0 |
| `0x40000003` | `0x00008860` | 0 | 0 | `0x00000100` |
| `0x40000004` | 0 | `0xffffffff` | 0 | 0 |
| `0x40000005` | `C` | `C` | 0 | 0 |

`0x40000003` EAX grants exactly `AccessHypercallMsrs` (bit 5) and
`AccessVpIndex` (bit 6), which Linux requires to detect the platform, plus
`AccessFrequencyRegs` (bit 11) and `AccessTscInvariantControls` (bit 15). EDX
sets only `FrequencyRegsAvailable` (bit 8). `0x40000004` recommends nothing
and sets the spinlock retry count to "never notify".

OpenVMM also programs explicit zero results for `0x40000006..=0x4000000f`
and `0x40000080..=0x40000082`, so they read zero on every backend. The
contract promises zeros only for these leaves: every other leaf in
`0x40000006..=0x400000ff` returns either all zeros or the vendor's
architectural out-of-range result (on Intel, the result of the highest basic
leaf for the same subleaf). KVM returns that result for every leaf missing
from its CPUID table, whose 256 entries cannot list the whole range.

Every leaf beyond the identity leaves that Linux 6.18 reads with this
identity is an explicit zero. Built as NVX builds it (`CONFIG_HYPERVISOR_GUEST`
without `CONFIG_HYPERV`, `CONFIG_KVM_GUEST`, or Xen, ACRN, Jailhouse, and
bhyve guest support), Linux probes only VMware and Hyper-V, and these are all
its reads in the range:

| Leaf | Reader | Condition |
| --- | --- | --- |
| `0x40000000` | `vmware_platform`, `ms_hyperv_platform`, `ms_hyperv_init_platform` | Always |
| `0x40000003` to `0x40000005` | `ms_hyperv_platform`, `ms_hyperv_init_platform` | Always |
| `0x40000081` | `ms_hyperv_msi_ext_dest_id` | x2APIC available without interrupt remapping |
| `0x40000082` | `ms_hyperv_msi_ext_dest_id` | `0x40000081` EAX is `VS#1`: never |
| `0x4000000a` | `ms_hyperv_init_platform` | Maximum leaf at least `0x4000000a`: never |
| `0x4000000c` | `ms_hyperv_init_platform` | `HV_ISOLATION` in `0x40000003` EBX: never |
| `0x40000010` | `vmware_select_hypercall` | VMware signature at `0x40000000`: never |

The other explicit zeros serve Hyper-V-aware software that probes further.
No leaf returns Hyper-V feature data, a `VS#1` interface signature at
`0x40000081`, or any hypervisor signature. No base `0x40000100..=0x4000ff00`
(step `0x100`) carries a KVM, Xen, VMware, or other hypervisor signature, so
Linux selects only the Hyper-V platform.

### Synthetic MSRs

OpenVMM serves the identity MSR range `0x40000000..=0x400001ff` identically
on every backend:

| MSR | Name | Read | Write |
| --- | --- | --- | --- |
| `0x40000002` | `HV_X64_MSR_VP_INDEX` | VP index | #GP |
| `0x40000022` | `HV_X64_MSR_TSC_FREQUENCY` | `F` | #GP |
| `0x40000023` | `HV_X64_MSR_APIC_FREQUENCY` | `L` | #GP |
| `0x40000118` | `HV_X64_MSR_TSC_INVARIANT_CONTROL` | Last value written, 0 after reset | 0 or 1 accepted; any other value #GP |
| Any other MSR in the range | | #GP | #GP |

`HV_X64_MSR_TSC_INVARIANT_CONTROL` is one partition-wide value. It is guest
state: it is saved with the VM and restored with it. Linux writes 1 at boot
with an unchecked `wrmsrq`, so this write must never fault on any backend.
Clearing it after setting it is accepted.

The CPU time bits hide two architectural timer MSRs, and every backend makes
them raise #GP: `IA32_TSC_ADJUST` (`0x3b`) and `IA32_TSC_DEADLINE`
(`0x6e0`).

### CPU time bits

Every CPU profile fixes these bits. A profile that violates them is rejected.

| Leaf | Register and bits | Value |
| --- | --- | --- |
| `0x1` | ECX[31] hypervisor present | 1 |
| `0x1` | ECX[24] TSC-deadline timer | 0 |
| `0x1` | ECX[15] PDCM | 0 |
| `0x1` | EDX[4] TSC | 1 |
| `0x6` | EAX, EBX, ECX, EDX | `0x00000004` (ARAT only), 0, 0, 0 |
| `0x7.0` | EBX[1] `IA32_TSC_ADJUST` | 0 |
| `0xa` | EAX, EBX, ECX, EDX | 0 (no PMU) |
| `0x15`, `0x16` | EAX, EBX, ECX, EDX | 0, when within the maximum basic leaf |
| `0x80000001` | EDX[27] RDTSCP | 1 |
| `0x80000007` | EAX, EBX, ECX, EDX | 0, 0, 0, `0x00000100` (invariant TSC only) |

Leaves `0x15` and `0x16` are zeroed rather than synthesized. Linux takes both
rates from the frequency MSRs, and zero leaves keep the profile's CPUID
independent of any host's rate.

Linux trusts the TSC because of `AccessTscInvariantControls`, not because of
CPUID `0x80000007` EDX[8]; that bit only adds the `nonstop_tsc` flag and
spares each AP a delay-loop calibration (about 150 ms per AP on Azure MSHV).
The bit is policy, not a fingerprint feature: profiles set it even where a
nested hypervisor hides it from host fingerprints (Azure's MSHV and WHP L1
partitions), every backend exposes it (WHP through its CPUID override), and
host qualification backs it with measured invariance (see
[Host qualification](#host-qualification)).

### Rates

- **TSC.** The guest TSC runs at the destination's native rate `F_d` and is
  never scaled. The declared rate `F` is fixed for the life of a snapshot
  lineage: a cold boot declares its native rate, and every restored process
  keeps `F = F_s`, including when it is captured again. The kernel computes
  `tsc_khz = floor(F / 1000)` once and never recalibrates. The
  [rate policy](#tsc-rate-policy-and-lapic-rate-rule) bounds
  `|F_d - F| / F`.
- **LAPIC.** `L` is a per-backend constant: 1,000,000,000 Hz on KVM and
  200,000,000 Hz on MSHV and WHP. Linux sets `lapic_timer_period = L / HZ`
  (`0x989680` on KVM, `0x1e8480` on MSHV and WHP, with HZ=100) and never
  calibrates the LAPIC.

### Clocksource, tick, and PIT

With this identity, Linux 6.18 built without `CONFIG_HYPERV`:

- reads `F` from MSR `0x40000022`, sets `X86_FEATURE_TSC_KNOWN_FREQ`, and
  registers clocksource `tsc` at `device_initcall` with no refinement;
- writes 1 to MSR `0x40000118` and sets `X86_FEATURE_TSC_RELIABLE`, which
  disables the clocksource watchdog for `tsc` and the CPU-online TSC warp
  test;
- presets `lapic_timer_period` from MSR `0x40000023`, sets `no_timer_check`,
  and disables the hard-lockup detector; and
- disables the PIT at boot because the TSC rate is known, ARAT is present,
  and the LAPIC period is preset.

The guest must then be in this state:

- `/proc/cpuinfo` flags on every CPU include `tsc`, `constant_tsc`,
  `nonstop_tsc`, `tsc_known_freq`, `tsc_reliable`, `rdtscp`, `hypervisor`,
  and `arat`, and exclude `tsc_deadline_timer` and `tsc_adjust`.
- `current_clocksource` is `tsc`, and `available_clocksource` is `tsc`
  alone: Linux lists `refined-jiffies` and `jiffies` only while the reading
  CPU's tick is periodic, which ends at that CPU's first tick.
- Ticks are tickless-idle with high-resolution timers. Every online CPU's
  tick device is `lapic` in one-shot mode from its first tick onward. No
  `pit` or `hpet` clock event device and no broadcast device exist.
- The LAPIC timer is never periodic after boot and never in TSC-deadline mode.
- PIT channel 0 never counts after boot, and IRQ 0 has no timer handler.

Because the kernel no longer checks cross-vCPU TSC consistency, the
[skew bound](#cross-vcpu-skew-bound) is enforced outside the guest.

### Deviations from the Hyper-V TLFS

- `0x40000003` advertises `AccessHypercallMsrs` only for platform detection.
  `HV_X64_MSR_GUEST_OS_ID` (`0x40000000`) and `HV_X64_MSR_HYPERCALL`
  (`0x40000001`) raise #GP, and there is no hypercall page. The NVX kernel is
  built without `CONFIG_HYPERV` and never touches them. `VMCALL` behavior is
  outside the contract; the guest never executes it.
- `HV_X64_MSR_TSC_FREQUENCY` returns the declared rate `F`, which differs
  from the physical rate `F_d` by up to the rate tolerance after a restore.
- `HV_X64_MSR_TSC_INVARIANT_CONTROL` can be cleared after it is set; Hyper-V
  and KVM raise #GP instead.
- On MSHV and WHP, CPUID `0x80000007` EDX[8] is set by the CPU profile from
  boot; it does not wait for a write to `HV_X64_MSR_TSC_INVARIANT_CONTROL`.
  KVM 6.3 and newer follow the TLFS and hide the bit while KVM's own copy of
  the control is 0, so the KVM backend mirrors the guest-visible value into
  KVM (see [Backend obligations](#backend-obligations)). Linux writes 1 in
  `ms_hyperv_init_platform`, before `identify_boot_cpu` and the APs read the
  bit, so the booted guest is identical on every backend.
- `0x40000002` carries an NVX signature and the time ABI version, not a
  Hyper-V build number.
- `0x40000005` reports the VP capacity in both EAX and EBX.

Side effects on Linux are limited to selecting the Hyper-V platform: an
unknown-NMI handler is registered, `pv_info.name` is `Hyper-V`, the
hard-lockup detector is off, and `no_timer_check` is set. No KVM
paravirtual feature (kvmclock, PV EOI, steal time, async page faults, PV TLB
flush, or PV spinlocks) exists on any backend; `sched_clock` and the vDSO use
the raw TSC.

## Backend obligations

Each backend implements these mechanisms behind one OpenVMM interface. The
guest-visible result is identical; only the mechanism differs. The spikes
(`p1-spike-kvm`, `p1-spike-mshv`, `p1-spike-whp-tsc`) demonstrated every
settled cell on the registered hosts.

| Obligation | KVM | MSHV | WHP |
| --- | --- | --- | --- |
| Identity CPUID (exact leaves, out-of-range rule) | `KVM_SET_CPUID2` with the identity and explicit zero leaves; every KVM `0x4xxxxxxx` entry removed. Other leaves in the range return KVM's Intel out-of-range result | No synthetic processor features, so the hypervisor reports no `0x400000xx` leaves; CPUID intercept results (`always_override`) for the identity and explicit zero leaves, read back with `get_cpuid_values` at preflight | CPUID exits for the six identity leaves, served from OpenVMM's table; with synthetic features off, WHP returns zero natively for `0x40000006..=0x400000ff` and the bases from `0x40000100`, which preflight asserts |
| Profile CPUID and time bits | `KVM_SET_CPUID2` with the effective CPUID. KVM 6.3 and newer hide invariant TSC while KVM's own `HV_X64_MSR_TSC_INVARIANT_CONTROL` is 0, so the backend mirrors the guest-visible value, which core saves with the VM, into it with a host-initiated `KVM_SET_MSRS` after every accepted guest write and before a VP runs after a restore or reset; without it the guest loses `constant_tsc` and `nonstop_tsc` and boots about 160 ms slower | Processor feature banks derived from the profile (`hv_banks`), plus CPUID intercept results for leaves 1, 6, 7.0, `0xA`, and `0x80000007` | Processor feature banks derived from the profile (`hv_banks`), plus CPUID exits for leaves 1, 6, 7, `0xA`, `0x15`, `0x16`, and `0x80000007` |
| Identity MSRs routed to OpenVMM | `KVM_CAP_X86_USER_SPACE_MSR` (`UNKNOWN`, `FILTER`) and `KVM_X86_SET_MSR_FILTER` denying reads and writes of `0x40000000..=0x400001ff`; the filter takes precedence over KVM's in-kernel Hyper-V MSRs. A Linux boot takes four MSR exits, all on the BSP, at any vCPU count | MSR-index intercepts (`READ_WRITE`) for `0x40000002`, `0x40000022`, `0x40000023`, and `0x40000118`. The hypervisor itself raises #GP for writes to the three read-only MSRs and for every other MSR in the range. Native synthetic MSRs are never enabled: they pre-empt the intercepts | `X64MsrExitBitmap` with `UnhandledMsrs` (capability `0x3f` on every host) and the offloaded APIC, no synthetic features and no `hv1_emulator`: the identity MSRs exit to OpenVMM, which raises #GP for every other MSR in the range |
| Native rate `F_d` | `KVM_GET_TSC_KHZ` × 1000 on VP 0 (1 kHz granularity) | `ProcessorClockFrequency` partition property | `WHvCapabilityCodeProcessorClockFrequency` |
| No TSC scaling | Never `KVM_SET_TSC_KHZ`; every vCPU reports the host rate | No frequency override | No `ProcessorClockFrequency` partition property; the 1 GHz request is removed |
| LAPIC rate `L` | In-kernel LAPIC at 1 GHz; `KVM_CAP_X86_APIC_BUS_CYCLES_NS` never set | 200 MHz | Offloaded APIC at its fixed 200 MHz, verified at preflight (setting `InterruptClockFrequency` is not supported); the emulated APIC is not used |
| TSC-deadline and `TSC_ADJUST` hidden | CPUID bits cleared; the MSR filter also denies `IA32_TSC_ADJUST` (`0x3b`) and `IA32_TSC_DEADLINE` (`0x6e0`), which KVM would otherwise serve, and OpenVMM raises #GP | Feature-bank bits `tsc_deadline_tmr_support`, `tsc_adjust_support`, and `a_count_m_count_support` cleared, and CPUID bits cleared | Feature-bank bits `TscDeadlineTmr`, `TscAdjust`, and `ACountMCount` cleared, and CPUID bits cleared; the hypervisor raises #GP for `IA32_TSC_ADJUST` |
| Invariant TSC exposed | CPUID bit. KVM hides it from a guest with `"Hv#1"` until KVM's own `HV_X64_MSR_TSC_INVARIANT_CONTROL` is set, so OpenVMM writes 1 to it host-side at vCPU creation | Forced by the profile: Azure's nested MSHV does not pass the bit through, and without it each AP pays about 150 ms of calibration. Hosts without an invariant TSC fail qualification (`azure-azlinux-2`) | Set by the CPUID override: Azure WHP hosts cannot expose it through the feature banks (bank 1 lacks `TscInvariant`), so those hosts qualify on the warp probe and rate stability (the guest TSC matched the declared rate against host QPC within 0.001 ppm over 118 s) |
| No paravirtual or synthetic features | No KVM leaves; `KVM_CAP_ENFORCE_PV_FEATURE_CPUID`, so KVM's paravirtual MSRs raise #GP; KVM's in-kernel Hyper-V MSRs are unreachable behind the filter | No synthetic processor features | `--hv` stays rejected for the microVM |
| Capture anchor: VP 0 TSC paired with a host time sample within 100 µs, re-sampled a bounded number of times | Host `rdtsc` plus VP 0's `KVM_VCPU_TSC_OFFSET`, bracketed by two host `rdtsc` reads around the host clock reads; up to 16 attempts (0.06 to 0.4 µs) | The tightest of up to 64 brackets `[sample, HvCallGetVpRegisters(VP 0 TSC), sample]`, paired at the bracket midpoint (p50 3.5 µs on bare metal, 6.2 µs on Azure) | TBD(whp) |
| Synchronized TSC set at one host instant | One `KVM_VCPU_TSC_OFFSET` value for every vCPU, `target(t) - (h0 + h1) / 2` from a host clock read `t` bracketed by host `rdtsc` reads `h0` and `h1` (Linux 5.16 or newer); no `IA32_TSC` writes, which Linux 6.6 can discard | Freeze partition time, write the target to every created VP, read back, and thaw at the first VP run (56 to 312 µs for 1 to 8 VPs) | Suspend partition time, write the target to every VP, read back, and resume explicitly with `WHvResumePartitionTime`; `TscVirtualOffset` is unusable (writes fail) |
| Read-back before release | Every vCPU's `KVM_VCPU_TSC_OFFSET` equals the written value, and a host `rdtsc` bracket around VP 0's `IA32_TSC` shows no scaling | Every created VP's TSC equals the target while time is frozen | Every VP's TSC equals the target while time is suspended; live reads cannot verify 1 µs (a register read takes 9.5 to 21 µs) |
| Live cross-vCPU skew after release at most 1 µs | Equal offsets: skew is the host's TSC skew, bounded by qualification. Measured at most 63 ns | Measured 0 warps; offsets within 516 ns on dual-socket bare metal and 195 ns on Azure, both bounded by the probe's round trip | Measured at most 70 ns over 60 s on prometheus28, 8370C, and 8573C hosts |
| VP instantiation | All `C` VPs exist before the set | The created prefix exists before the set; no VP is created after it | All `C` VPs exist before the set |
| Partition capabilities | Derived from CPUID with the hypervisor range masked: `hv1` and `kvm_clock` are false | Same | Same |
| Unknown MSRs | #GP; the `MYSTERY_MSRS` stubs are TBD(profiles) | #GP from the hypervisor | #GP; the `MYSTERY_MSRS` stubs are TBD(profiles) |
| Removed | `KVM_GET_CLOCK`/`KVM_SET_CLOCK` in the microVM downtime path, kvmclock MSR state, leaf `0x15` synthesis, `KVM_SET_TSC_KHZ`, restore-time `IA32_TSC` writes | BSP-copy TSC alignment, exact-rate equality, leaf `0x15` synthesis | 1 GHz request and fallback, `RestoredTsc` and its RDTSC, RDTSCP, and `IA32_TSC` exits, leaf `0x15` synthesis |

**KVM common offset.** Restoring each VP's `IA32_TSC` is unreliable on KVM.
Linux 6.6 KVM, which the Azure KVM runners run, treats a host `IA32_TSC`
write within about 1 s of the TSC timeline started at vCPU creation as a
synchronization attempt and discards the written value, the first write of a
restore included; every CI shell snapshot is taken within a second of boot.
With the legacy restore path on `azure-kvm-5`, a restored guest's monotonic
clock advanced 54.7 ms across a 512.5 ms host interval, losing 458 ms. Linux
6.7 applies the heuristic only after a first user-space write
(`user_set_tsc`). `KVM_VCPU_TSC_OFFSET` sets the offset exactly on every
kernel from 5.16, so the backend never writes `IA32_TSC` and core omits the
saved per-VP TSC values from the VP restore.

**WHP decision gate: met.** Suspending partition time, writing the target,
verifying the frozen values, and resuming kept every pair of vCPUs within
70 ns over 60 s on bare metal and on both Azure runner generations, so WHP
never traps RDTSC. The emulated clock it replaces cost about 45 µs per guest
timestamp read on bare metal and 66 to 70 µs on Azure (p50), on every vCPU of
an SMP-restored VM for its lifetime.

## CPU profiles

A CPU profile is the complete guest-visible CPU surface of one vendor and CPU
generation, shared by every backend. The guest sees only profile values, never
host passthrough, except for a fixed, code-defined set of VMM-owned fields and
the fields the time ABI owns. Profiles are data: derived mechanically by
intersecting host fingerprints (`openvmm --cpu-fingerprint`, the Firecracker
`cpu-template-helper` workflow) per register, first within each backend and
then across backends, reviewed, checked in at
`vmm_core/cpu_profile/profiles/<id>.json`, embedded in the OpenVMM binary, and
immutable once released. A normative change creates a new revision; released
revisions are never deleted, so old snapshots stay restorable. One surface
serves all three backends: MSHV and WHP derive their processor feature banks
from the profile's CPUID (`cpu_profile::hv_banks`) instead of from the host's,
and each backend verifies at partition creation that it supports the profile.
A shared profile gives the same guest behavior on every backend; it does not
make snapshots portable, because cross-backend restore is rejected
(`E_BACKEND_MISMATCH`).

**Format.** Schema `openvmm-cpu-profile/v1`. The canonical encoding is
compact canonical JSON (object keys sorted by their UTF-8 bytes, no
whitespace, numbers as hexadecimal strings); the profile digest is the
SHA-256 of that encoding, and decoding accepts only canonical bytes, so a
profile has exactly one encoding and one digest. Pinned files use the same
document in pretty form.

| Field | Content |
| --- | --- |
| `schema` | `openvmm-cpu-profile/v1` |
| `id` | `<vendor>.<generation>.v<revision>`, each component `[a-z0-9-]+`, for example `intel.icelake-sp.v1` |
| `description` | Free text |
| `vendor` | The 12-byte CPUID vendor string |
| `generation` | The generation `name` (`skylake-sp`, `icelake-sp`, or `emeraldrapids`) and its `cpus`: `(family, model, stepping range)` display signatures; stepping ranges separate model 85's Skylake-SP (0 to 4), Cascade Lake, and Cooper Lake |
| `cpuid` | A dense table of every leaf and subleaf in `[0, max basic]` and `[0x80000000, max extended]` with a value and a mask per register; mask bit 1 pins the value, mask bit 0 marks a VMM-owned or runtime-owned bit |
| `xcr0`, `xss`, `xsave_components` | The XSAVE features the guest may enable, and the size, offset, and flags of every enabled component |
| `physical_address_width` | The guest physical address width |
| `msrs` | Pinned MSR values with masks; v1 pins `IA32_ARCH_CAPABILITIES` only |
| `provenance` | The derivation method and the source fingerprints' backends, host counts, and surface digests (informative) |

VMM-owned bits are a code table, not profile data: `CPUID.1:EBX[31:16]`
(logical count and initial APIC ID), x2APIC (`CPUID.1:ECX[21]`), the core
and cache-sharing counts in `CPUID.4:EAX[31:14]`, and the topology leaves
`0xB` and `0x1F`, which profiles omit. Runtime-owned bits mirror control
state: `OSXSAVE`, `OSPKE`, and the XSAVE sizes for the current XCR0 and XSS.
The time ABI owns `0x40000000..=0x4fffffff`, `0x15`, and `0x16`, and every
profile pins the [CPU time bits](#cpu-time-bits). Invariant TSC and ARAT are
pinned set and, with the hypervisor bit, exempt from host-support
verification, because nested Azure hypervisors hide them from fingerprints;
host qualification measures them instead. Profiles also pin policy zeros
(VMX and SVM, SGX, PT, RDT, PCONFIG, and the other features listed by the
profiles' derivation policy). `IA32_UCODE_REV` is not pinned in v1. The
effective guest CPUID is a pure function of the profile, the VM topology,
and the time ABI's identity leaves.

**Selection.** A microVM always has a profile. A cold boot uses
`--cpu-profile <id>`, or `auto` (the default), which selects the highest
revision of the single profile whose generation covers the host's vendor,
family, model, and stepping as the VMM's host OS sees them (the L1 view on
Azure). No match, or matches in more than one generation, is
`E_PROFILE_HOST_UNKNOWN`, naming the host's signature and the available IDs;
host CPUID passthrough does not exist. A restore always uses the profile
recorded in the snapshot; an explicit `--cpu-profile` must name the same
profile (`E_PROFILE_UNKNOWN`).

**Verification.** At partition creation, for cold boot and restore, OpenVMM
reports every violation at once, naming the leaf, subleaf, register, and bit:

1. The profile is valid: schema, canonical encoding, density, the VMM-owned
   and runtime-owned mask tables, and the [CPU time bits](#cpu-time-bits)
   (`E_PROFILE_TIME_BITS`; a catalog profile that fails is a build defect
   caught by unit tests).
2. The host's vendor, family, model, and stepping are in the profile's
   generation (`E_CPU_GENERATION`).
3. The backend supports the profile (`E_PROFILE_UNSUPPORTED`): every set
   feature bit is a supported bit, every limit (maximum leaves, address
   widths) is within the backend's, every enabled XSAVE component has the
   same size, offset, and flags, XCR0 and XSS are subsets, and every pinned
   MSR value can be presented (an `ARCH_CAPABILITIES` immunity the host lacks
   is a violation). The time policy bits are exempt.
4. On restore only: this OpenVMM pins a profile with the same ID and digest,
   and the recorded document hashes to it (`E_PROFILE_UNKNOWN`,
   `E_PROFILE_DIGEST`), and the recomputed effective CPUID equals the
   recorded one (`E_CPU_SURFACE`). The effective-CPUID record replaces the
   exact-equality CPU contract.

The catalog has three profiles, derived from the fingerprints of three
bare-metal hosts (one per backend) and fifteen Azure hosts:

| ID | Generation | Hosts | Source backends |
| --- | --- | --- | --- |
| `intel.skylake-sp.v1` | 6/85, steppings 0 to 4 | Bare-metal prometheus hosts | KVM, MSHV, WHP |
| `intel.icelake-sp.v1` | 6/106 | Xeon Platinum 8370C runners | KVM, MSHV, WHP |
| `intel.emeraldrapids.v1` | 6/207 | Xeon Platinum 8573C runners | MSHV, WHP (no KVM host exists) |

The fate of the `MYSTERY_MSRS` stubs is TBD(profiles).

## TSC rate policy and LAPIC rate rule

**TSC rate.** At restore, with integer arithmetic in at least 128 bits:

```text
accept  iff  |F_d - F_s| * 1_000_000  <=  250 * F_s
```

The boundary is accepted. Beyond it, restore is rejected
(`E_TSC_RATE_TOLERANCE`), reporting both rates and the deviation. The
tolerance is recorded in the manifest as `tsc_tolerance_ppm = 250`; any other
recorded value is rejected. Within the tolerance:

- the TSC is never scaled, and RDTSC is never trapped;
- MSR `0x40000022` keeps returning `F_s`, so the guest's `tsc_khz` is
  unchanged;
- guest clocks run fast or slow by at most the deviation (measured hosts
  differ by at most 1 ppm), and the restore packet reports the deviation so
  the guest pre-compensates it (see
  [Wall-clock discipline](#wall-clock-discipline)).

Every rate is also checked for plausibility, `500 MHz <= F <= 10 GHz`
(`E_TSC_RATE_IMPLAUSIBLE`). A backend that cannot report its native rate is
rejected at cold boot, capture, and restore alike (`E_TSC_RATE_UNAVAILABLE`);
there is no command-line or calibration fallback.

**Rate deviation.** The restore packet carries the deviation in the unit of
`adjtimex` frequency, ppm scaled by 2^16, rounded to nearest:

```text
rate_deviation = round((F_d - F_s) * 1_000_000 * 65_536 / F_s)
```

Within the tolerance its magnitude is at most 16,384,000.

**LAPIC rate.** `L` must equal the backend constant (1 GHz on KVM, 200 MHz on
MSHV and WHP), and on restore `L_d` must equal `L_s` exactly
(`E_LAPIC_RATE_MISMATCH`). A counting-mode one-shot timer advances over a
downtime `D` by exactly

```text
ticks = floor(D * L / 1_000_000_000 / divide)
```

where `divide` is the divide-configuration value (1 to 128). If `ticks` is at
least the current count, the count becomes 0 and the timer interrupt is queued
in the restored LAPIC state unless the LVT is masked; otherwise the current
count decreases by `ticks`. A periodic or TSC-deadline LAPIC timer is never
valid: capture and restore reject one that is armed (`E_LAPIC_PERIODIC`,
`E_LAPIC_TSC_DEADLINE`).

## Cross-vCPU skew bound

At every guest-observable instant, the TSCs of any two online VPs differ by
at most 1 µs, that is `F_s / 1,000,000` cycles. Linux no longer checks this
(`TSC_RELIABLE`), so it is enforced at four points:

1. **VMM synchronized set.** Restore writes one target to every instantiated
   VP at one host instant and verifies it by read-back before any VP runs
   (`E_TSC_SYNC_READBACK`). The VMM introduces no skew of its own.
2. **Host qualification.** `nvx.py doctor` and `validate-runner` run a host
   TSC skew probe and a guest warp probe; a host above 1 µs is not qualified.
3. **CI warp probe.** Conformance, restore-matrix, and soak runs execute the
   guest warp probe after boot and after every restore and fail above 1 µs.
4. **Backend live skew.** Each backend shows that live skew stays within the
   bound after release. The spikes measured at most 63 ns of ping-pong
   offset and 7.2 ns of backward step on KVM, at most 516 ns on MSHV
   (dual-socket bare metal, bounded by the probe's round trip), and at most
   70 ns on WHP.

The guest warp probe (`nvx-time-probe warp`, built from
`guest/common/nvx-time-probe.c` and installed as `/sbin/nvx-time-probe`)
runs two tests on every pair of online CPUs, each for at least 100 ms per
pair:

- `max_backward_ns`: the largest backward TSC step observed when the two CPUs
  alternately read the TSC under a shared spinlock (the Linux
  `check_tsc_warp` method); a lower bound on skew; and
- `max_abs_offset_ns`: the largest pairwise offset estimated by ping-pong
  rounds, `t2 - (t1 + t3) / 2` at the round with the minimum round trip.

Both must be at most 1,000 ns, and no pair may stall for more than 2 s.
Cycle values convert to nanoseconds with `F`.

## Downtime semantics and source selection

Guest monotonic time advances by the downtime `D`, the host time elapsed
between the capture anchor and the restore anchor, plus at most the restore
latency `R` defined below. The guest observes no other discontinuity between
the snapshot `out` and the first restored instruction.

Capture records, at the capture anchor:

- `T_c`, the guest TSC of VP 0;
- host UTC in nanoseconds since the Unix epoch;
- host monotonic time in nanoseconds: `CLOCK_BOOTTIME` on Linux, or
  `QueryInterruptTimePrecise` × 100 on Windows (both include host suspend);
- the host identity: `/etc/machine-id` on Linux, or the `MachineGuid`
  registry value on Windows, as 16 bytes; and
- the host boot identity: `/proc/sys/kernel/random/boot_id` on Linux, or the
  `PrefetchParameters\BootId` registry value on Windows (zero-extended), as
  16 bytes.

A host that cannot provide all of these rejects capture and restore
(`E_HOST_IDENTITY`). Restore takes the same sample at the restore anchor and
selects exactly one source:

| Condition | Source | `D` |
| --- | --- | --- |
| Same host identity, same boot identity, and same host clock kind | Host monotonic | `monotonic_now - monotonic_capture` |
| Anything else | UTC | `utc_now - utc_capture` |

`D` must satisfy `0 <= D <= 30 days` (2,592,000 s); otherwise restore is
rejected (`E_DOWNTIME_NEGATIVE`, `E_DOWNTIME_EXCESSIVE`). On the monotonic
path, a UTC delta that differs from `D` by more than 1 s is logged as a host
wall-clock step and does not change `D`. The packet reports the source, so
the guest and tests can tell the two paths apart.

The restore anchor is the instant of the synchronized TSC set. On KVM and
WHP the guest TSC runs from that instant (WHP resumes partition time right
after the read-back); on MSHV it is frozen until the first VP runs. Either
way, the guest monotonic advance across a restore lies in `[D, D + R]`, up
to the two anchors' pairing errors (each at most 100 µs), where `R` is the
time from the restore anchor to the first restored instruction. Wall-clock
repair absorbs `R` and the pairing errors for `CLOCK_REALTIME`. The KVM spike
kept guest `CLOCK_MONOTONIC` within −0.09 to +2.8 ms of the host interval
across restores with 0 s and 30 s of downtime at 1 to 8 vCPUs; its positive
part came from a host sample taken before the per-VP TSC save, which the
paired capture anchor removes.

## Restore algorithm

Restore runs these steps in order. Any failure rejects the restore before a
restored VP runs, with the named code.

Before worker construction:

1. Read the bounded manifest. Its version must be 6 with format magic
   `OPENVMM_SNAPSHOT_V6\0` (`E_SNAPSHOT_VERSION`, which asks for a
   recapture).
2. Validate the time contract and the CPU profile record: `time_abi_version`
   is 1, `tsc_tolerance_ppm` is 250, `F_s` is plausible, `L_s` is a backend
   constant, identities are 16 bytes, `capture_generation < 2^32 - 1`, and
   the embedded profile and effective-CPUID digests verify
   (`E_MANIFEST_TIME`, `E_PROFILE_DIGEST`).
3. Require the destination backend to equal `source_hypervisor`
   (`E_BACKEND_MISMATCH`).
4. Require a pinned profile with the recorded ID and digest
   (`E_PROFILE_UNKNOWN`, `E_PROFILE_DIGEST`), and the host's CPU generation
   to be in it (`E_CPU_GENERATION`).
5. Preflight the downtime: sample the host clocks, select the source, and
   check the bounds (`E_DOWNTIME_*`, `E_HOST_IDENTITY`). The authoritative
   `D` is measured again in step 12.
6. Validate the rest of the machine contract as today (topology, devices,
   attachments, command line, blocks). The command line must not contain
   `tsc_early_khz=` or `lapic_timer_hz=` (`E_CMDLINE_CLOCK_TOKEN`).
7. Generate the restore entropy and generation ID, and set
   `g = capture_generation + 1`.

In the worker, with every VP stopped:

8. Create the partition with the profile CPUID, the identity leaves, and the
   time platform declaring `F = F_s` and `L = L_s`. Preflight the backend:
   profile support and effective CPUID (`E_PROFILE_UNSUPPORTED`,
   `E_CPU_SURFACE`), identity routing (`E_IDENTITY_ROUTING`), the
   synchronized-set primitive (`E_TSC_SYNC_UNSUPPORTED`), and no scaling
   (`E_TSC_SCALING_ACTIVE`).
9. Read `F_d` and `L_d` and apply the
   [rate policy](#tsc-rate-policy-and-lapic-rate-rule)
   (`E_TSC_RATE_UNAVAILABLE`, `E_TSC_RATE_IMPLAUSIBLE`,
   `E_TSC_RATE_TOLERANCE`, `E_LAPIC_RATE_UNAVAILABLE`,
   `E_LAPIC_RATE_MISMATCH`).
10. Restore every state unit while stopped: VM time, chipset and virtio
    devices, the time platform (`HV_X64_MSR_TSC_INVARIANT_CONTROL`), the
    partition, and every VP.
11. Assert the saved timers: no armed periodic or TSC-deadline LAPIC timer on
    any VP (`E_LAPIC_PERIODIC`, `E_LAPIC_TSC_DEADLINE`), and PIT channel 0 not
    counting in a periodic mode (`E_PIT_ACTIVE`). Freeze the instantiated VP
    set; creating a VP after this point is an internal error
    (`E_VP_LATE_CREATION`).
12. Synchronized TSC set. The backend takes the restore anchor (one host
    instant) and passes its host sample to the orchestrator, which selects
    the downtime source, computes `D` and checks its bounds, and returns

    ```text
    TSC_target = T_c + floor(D * F_s / 1_000_000_000)
    ```

    (`E_TSC_TARGET_OVERFLOW` if it exceeds 64 bits). The backend writes
    `TSC_target` to every instantiated VP at that instant. Per-VP TSC values
    from saved VP state are omitted from the VP restore and never applied. A
    restore anchor that pairs a TSC read with host time (KVM's common offset)
    is re-sampled a bounded number of times and fails with `E_TSC_ANCHOR` if
    no pair is within 100 µs; a pairing error shifts every VP's TSC alike, by
    at most that amount. A frozen write needs no such pairing.
13. Read back: every instantiated VP holds the synchronized value as defined
    by its backend (`E_TSC_SYNC_READBACK`).
14. Advance every VP's counting-mode LAPIC timer by `D` at `L`, and set every
    VP's LAPIC state again after the synchronized set, even when no timer is
    armed: KVM derives its timer deadline from the guest TSC when the LAPIC
    state is set.
15. Advance VM time by `D` and the RTC's UTC by `D` (milliseconds). The PIT
    catches up from its saved VM-time cursor; it is idle.
16. Seal the time fields of the restore packet: `D`, its source, the rate
    deviation, `g`, and the test-hook flag.
17. Start the state units, with host input gated when the restore requires an
    acknowledgement; publish the readiness event; release the VPs. On MSHV,
    partition time thaws when the first VP runs.

The guest then repairs its clocks (see
[Snapshot agent](#snapshot-agent)) before acknowledging a gated restore.

## Snapshot manifest

New snapshots use manifest version 6 with format magic
`OPENVMM_SNAPSHOT_V6\0`. Restore accepts exactly version 6; versions 2
through 5 and every other value are rejected with `E_SNAPSHOT_VERSION`, whose
message tells the operator to recapture the snapshot. The legacy version
branches and their format constants are deleted.

**Capture.** After every VP has stopped at the snapshot boundary and the
state units are quiesced, capture:

1. asserts that no LAPIC timer is periodic or in TSC-deadline mode and that
   PIT channel 0 is not counting periodically (`E_LAPIC_PERIODIC`,
   `E_LAPIC_TSC_DEADLINE`, `E_PIT_ACTIVE`);
2. takes the capture anchor: VP 0's TSC paired with a host time sample taken
   within 100 µs of it, keeping the tightest of a bounded number of samples
   (`E_TSC_ANCHOR`), plus the host identities (`E_HOST_IDENTITY`); and
3. records the declared rates, the CPU profile, the effective CPUID, and the
   process's generation counter.

Each of these failures is a rollback-safe capture failure.

**Machine contract changes.** `SnapshotMachineContract` retires protobuf
fields 11 (`capture_wall_clock`), 12 (`tsc_frequency_hz`), 13
(`tsc_tolerance_ppm`), 14 (`cpu_contract`), 15 (`cpu_contract_sha256`), 17
(`clock_policy`), and 20 (`apic_frequency_hz`); their numbers are never
reused. It adds two required fields:

| Field | Number | Type |
| --- | --- | --- |
| `time` | 31 | `SnapshotTimeContract` |
| `cpu_profile` | 32 | `SnapshotCpuProfile` |

`SnapshotTimeContract` (package `openvmm.snapshot`):

| Number | Field | Type | Content |
| --- | --- | --- | --- |
| 1 | `time_abi_version` | `u32` | 1 |
| 2 | `tsc_frequency_hz` | `u64` | `F_s`, the declared rate |
| 3 | `tsc_tolerance_ppm` | `u32` | 250 |
| 4 | `apic_frequency_hz` | `u64` | `L_s` |
| 5 | `capture_tsc` | `u64` | `T_c` |
| 6 | `capture_utc_ns` | `u64` | Host UTC at the capture anchor, nanoseconds since the Unix epoch |
| 7 | `capture_monotonic_ns` | `u64` | Host monotonic time at the capture anchor |
| 8 | `host_clock` | `string` | `linux-boottime` or `windows-interrupt-time` |
| 9 | `host_id` | `bytes` | 16-byte host identity |
| 10 | `host_boot_id` | `bytes` | 16-byte host boot identity |
| 11 | `capture_generation` | `u32` | `g` of the captured process |

`SnapshotCpuProfile` (package `openvmm.snapshot`):

| Number | Field | Type | Content |
| --- | --- | --- | --- |
| 1 | `id` | `string` | Profile ID |
| 2 | `sha256` | `bytes` | Profile digest, 32 bytes |
| 3 | `profile` | `bytes` | Canonical profile encoding, at most 1 MiB |
| 4 | `effective_cpuid` | `bytes` | The effective guest CPUID in its canonical encoding, `openvmm-effective-cpuid/v1` (compact canonical JSON): the profile's pinned values, the topology fields, and the identity leaves |
| 5 | `effective_cpuid_sha256` | `bytes` | Digest of `effective_cpuid`, 32 bytes |
| 6 | `capture_cpu_signature` | `u32` | CPUID.1:EAX of the capture host, for diagnostics |

Other rules:

- The effective command line contains no `tsc_early_khz=` or
  `lapic_timer_hz=` token, and platform-tier validation no longer requires
  one (`E_CMDLINE_CLOCK_TOKEN`).
- The state-unit inventory gains the time platform unit, `time-abi`, which
  saves `HV_X64_MSR_TSC_INVARIANT_CONTROL`.
- `source_hypervisor` keeps its meaning and must match exactly.
- Nothing in the manifest depends on the capture host's native TSC rate
  except `F_s`, which is the lineage's declared rate.

## Restore packet v4 and the time-sample selector

Every byte the guest reads from portb is a port exit, so the time ABI keeps
records small and lets the guest read four bytes per exit.

### Portb registers

| Port | Access | Time ABI v1 behavior |
| ---: | --- | --- |
| `0xe9` | Read | With the restore packet or generation ID selected, a 1-, 2-, or 4-byte read returns that many bytes of the selected record, little-endian, zero-filled past its end. Console input reads are unchanged: one byte per read. |
| `0xea` | Read | Status bits 0 to 5 are unchanged. Bit 6 (`0x40`) is always set: the time-sample window exists. Bit 7 is zero. |
| `0xea` | Write | `0xa5` selects the restore packet and `0xa6` the generation ID, as today. `0xa7` latches a fresh time sample into the window at `0xeb` and does not change the `0xe9` selection. |
| `0xeb` | Read | A 1-, 2-, or 4-byte read returns the next bytes of the latched time sample, zero-filled past its end and when no sample is latched. |

Port `0xeb` belongs to the portb device, whose range becomes
`0xe9..=0xeb`. The time window is separate from `0xe9` because the console
driver polls `0xea` and reads `0xe9` from a timer thread; a sample on the
console stream could interleave with input bytes. The window is not saved
state: restore empties it. Guest users of selectors `0xa5`, `0xa6`, and
`0xa7` serialize their transactions with an exclusive `flock` on
`/run/nvx/portb.lock`. The snapshot agent holds it from its capture request
through repair step 8, and a discipline poll holds it from its first sample
to the published state, so a capture may wait for an in-flight poll, which
is bounded by three samples and two `adjtimex` calls.

### Restore packet

OpenVMM exposes a restore packet on every microVM restore, for every tier and
for untiered snapshots; status bit 1 advertises it. Version 4 replaces
versions 1 through 3, which are no longer produced or accepted.

```text
offset size field
     0    3 magic "OVR"
     3    1 version = 4
     4    1 flags
     5    1 online_vp_count      0 = no processor target, else 1, 2, 4, or 8
     6    1 memory_range_count   0 unless MEMORY_TARGET
     7    1 reserved = 0
     8    4 generation           u32, little-endian, g >= 1
    12    4 rate_deviation       i32, little-endian, ppm scaled by 2^16
    16    8 downtime_ns          u64, little-endian, D
    24    8 utc_ns               u64, little-endian, host UTC at selection
    32 16*n ranges               n x { u64 gpa_start, u64 length }, LE
 32+16n  64 entropy
```

Flags:

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | `DOWNTIME_UTC` | `D` came from the UTC delta; clear means same-boot host monotonic time |
| 1 | `MEMORY_TARGET` | An explicit RAM target was requested; `memory_range_count` is valid and may be 0 |
| 2 | `ACK_REQUIRED` | Host input is gated; the guest must acknowledge through `0x605` after repair |
| 3 | `TEST_HOOKS` | A test hook altered the downtime source, `D`, UTC, or the rate deviation |
| 4–7 | | Zero; the guest rejects a packet with any of them set |

`utc_ns` is latched when the guest first writes selector `0xa5` after the
restore; every other field is sealed before the first restored VP runs (step
16 of the [restore algorithm](#restore-algorithm)). A packet without ranges is
96 bytes, 24 four-byte reads. Status bits 2 to 4 remain and agree with the
packet; the packet is authoritative. `ACK_REQUIRED` replaces the guest's
inference of gating from the tier and targets, so an untiered guest never
writes `0x605` after an ungated restore.

A VM process exposes at most one packet, and reading its last byte consumes
it: status bits 1 to 4 clear and later `0xa5` writes select nothing. A guest
that is captured again in the same process, including after a rejected
capture, therefore never sees the earlier packet. It also ignores a packet
whose `g` equals its recorded `g`.

### Time sample

Writing `0xa7` to `0xea` latches a 16-byte sample into the window at `0xeb`:

```text
offset size field
     0    1 version = 1
     1    1 flags                bit 3 TEST_HOOKS; other bits zero
     2    2 reserved = 0
     4    4 generation           u32, little-endian, g of this VM process
     8    8 utc_ns               u64, little-endian, host UTC at the latch
```

The guest pairs `utc_ns` with its own clock: it reads `CLOCK_REALTIME` as
`t0` immediately before the selector write and as `t1` immediately after it.
The host instant lies in `[t0, t1]`, so the offset is

```text
theta = utc_ns - (t0 + t1) / 2      uncertainty epsilon = (t1 - t0) / 2
```

The same bracket applies to `utc_ns` in the restore packet, around the first
`0xa5` write. A sample costs one write and four reads. OpenVMM cannot observe
a running VP's TSC on every backend, and frozen time on MSHV thaws at an
unobservable instant, so the guest forms the UTC and TSC pair itself through
this bracket; its `CLOCK_REALTIME` is derived from the TSC.

### Uncertainty bounds

The guest accepts a pairing only if `epsilon` is within a bound, retries
otherwise, and then fails with a stable code:

| Use | Bound | Attempts | When every attempt exceeds the bound |
| --- | --- | --- | --- |
| Restore repair (packet bracket, then time samples) | 1 ms | 3 | `G_REPAIR_SAMPLE`: event and power-off with status 195 |
| Initial synchronization at boot (time samples) | 1 ms | 3 | `G_CONFORMANCE_C12`: event and power-off with status 193 |
| Discipline poll (time samples) | 50 µs | 3 | `G_SAMPLE_UNCERTAIN`: the poll is skipped and the code is recorded in the state file and on the console; never fatal |

`epsilon` is half the round trip of one PMIO write exit plus two
`CLOCK_REALTIME` reads, so it stays far below both bounds on every backend.
Measured from a guest with a release build of OpenVMM (`ea570db7e`) and a
probe that brackets each selector write with `CLOCK_REALTIME` reads, two runs
of 2,000 samples per boot at 1, 2, and 4 or 8 vCPUs, which made no
difference:

| Backend | Host | `epsilon` p50 / p99 | Worst sample |
| --- | --- | --- | --- |
| KVM | prometheus32 (bare metal, Linux 7.0) | 4.0 to 4.1 µs / 4 to 15 µs | 33 µs |
| KVM | `azure-kvm-5` (nested, Linux 6.6) | 3.8 to 4.1 µs / 4 to 9 µs | 75 µs |
| MSHV | prometheus30 (bare metal) | 6.3 to 6.4 µs / 6.8 to 7.1 µs | 37 µs |
| MSHV | `azure-azlinux-5` (nested) | 12.7 to 13.0 µs / 15 to 25 µs | 102 µs |
| WHP | | TBD(whp) | |

The second run of each boot overlaps the console's drain of the first run's
output, and it has the higher KVM p99s. A sample above the 50 µs discipline
bound is rare, and the poll retries it.

### Generation counter and generation ID

- The generation counter `g` is 0 in a cold-booted process and
  `capture_generation + 1` in a restored one. It orders restores within a
  snapshot lineage; clones of one snapshot share it. The packet and every
  time sample carry it, so a guest observes a restore between two samples as
  a change of `g`.
- The generation ID is unchanged: 16 random bytes, unique to each VM process,
  selected with `0xa6`, and equal to the first 16 entropy bytes when a
  restore packet exists. It distinguishes clones.
- After a restore, the guest requires `g` in the packet to equal its
  recorded `g` plus one, and the generation ID to differ from the recorded
  one. Either mismatch fails repair.

## Guest obligations

The guest's time component (`nvx-time` in `guest/common`) performs the
conformance checks, runs the violation watcher and the wall-clock discipline
as one daemon, and executes the snapshot agent's time steps. Every guest mode
starts it: init's interactive and test paths, `nvx_exec`, the sandbox agent,
and the managed agent.

### Conformance checks and the `NVX-TIME-ABI` marker

Init runs the boot check immediately after mounting `/proc`, `/sys`, and
`/dev`, before any other guest work, and starts the daemon only if it passes.
CPUID is executed on every online CPU (the checker pins itself to each CPU in
turn, or runs one thread pinned to each CPU), and MSRs are read through
`/dev/cpu/<n>/msr`. A CPU's VP index is its Linux CPU number, because CPUs
come online as a prefix in APIC-ID order. CPUID tables are per VP on KVM, so
`C1` and `C2` run on every CPU; the MSRs other than the VP index are
partition-wide on every backend, so `C3` reads them on CPU 0 only.

| ID | Check | Phases |
| --- | --- | --- |
| `C1` | Identity leaves `0x40000000..=0x40000005` equal the [identity table](#hypervisor-identity), with `C` equal to the number of possible CPUs; the explicit zero leaves `0x40000006..=0x4000000f` and `0x40000080..=0x40000082` are zero | boot, restore (new CPUs) |
| `C2` | The [CPU time bits](#cpu-time-bits) | boot, restore (new CPUs) |
| `C3` | MSR `0x40000002` equals the CPU's VP index on every CPU; on CPU 0, `0x40000022` equals `F` with `floor(F / 1000)` equal to the kernel's `cpu MHz` in kHz, `0x40000023` equals 1,000,000,000 or 200,000,000, `0x40000118` equals 1, and reads of `0x40000000`, `0x40000001`, and `0x40000020` fail with `EIO` | boot; restore (CPU 0 `0x40000022` only) |
| `C4` | The kernel log contains `Hypervisor detected: Microsoft Hyper-V`, `Hyper-V: privilege flags low 0x8860,`, `Hyper-V: LAPIC Timer Frequency: 0x989680` or `0x1e8480`, and `clocksource: Switched to clocksource tsc` as its last clocksource switch; it contains no record matching a watcher pattern other than `G_CLOCKSOURCE_SWITCH`, and none containing `Fast TSC calibration`, `Refined TSC clocksource calibration`, `kvm-clock`, or `APIC timer: using supplied frequency` | boot |
| `C5` | `/proc/cpuinfo` flags as listed in [Clocksource, tick, and PIT](#clocksource-tick-and-pit) on every CPU | boot, restore (new CPUs) |
| `C6` | `current_clocksource` is `tsc`; `available_clocksource` lists `tsc` and no other clocksource except `refined-jiffies` and `jiffies`, which Linux lists only before the reading CPU's first tick (after boot it is `tsc` alone) | boot, capture, restore |
| `C7` | `/proc/timer_list`: every online CPU's tick device is `lapic` with `hrtimer_interrupt` in one-shot mode; no `pit` or `hpet` device; no broadcast device | boot, capture, restore (deferred) |
| `C8` | `/sys/bus/vmbus` and `/sys/devices/system/cpu/cpufreq/policy0` are absent; `rcu_cpu_stall_suppress` is 0 and `rcu_cpu_stall_timeout` is 21 | boot |
| `C9` | `/proc/cmdline` contains none of `tsc_early_khz=`, `lapic_timer_hz=`, `notsc`, `nolapic`, `nolapic_timer`, `tsc=unstable`, `hpet=force`, or `clocksource=` with a value other than `tsc` | boot |
| `C10` | The time daemon is running and has recorded no violation; `/sys/kernel/rcu_stall_count` is 0; at boot, the state file is published and the daemon started | boot, capture, restore |
| `C11` | Debug kernel only: `/proc/sys/kernel/soft_watchdog` is 1 and `/proc/sys/kernel/hung_task_timeout_secs` is nonzero | boot |
| `C12` | A time sample within the [uncertainty bound](#uncertainty-bounds) is obtained, and the clock is stepped to host UTC | boot |
| `K1` | Kernel integrity, not a clock property: the kernel's boot-time W+X audit logged no `Found insecure W+X mapping` record | boot |

Capture and restore checks never wait. The boot `C7` check and the deferred
restore `C7` check may poll for at most 200 ms, because a CPU switches to
one-shot mode at its first tick.

**Exhaustive check (CI only).** The CI conformance suite also runs
`nvx-time exhaustive`, provided by the guest. It is a test tool: it reports
and exits instead of powering off, and production boots never run it. Every
check runs on every online CPU:

| ID | Check |
| --- | --- |
| `X1` | The explicit zero leaves are zero, and every other leaf in `0x40000006..=0x400000ff` returns all zeros or the Intel out-of-range result (the highest basic leaf's result for the same subleaf), as the [identity rules](#hypervisor-identity) require |
| `X2` | No base `0x40000100..=0x4000ff00` (step `0x100`) carries `KVMKVMKVM` or another hypervisor signature; the NVX kernel has no KVM guest support, so the boot check leaves this static backend property to CI |
| `X3` | Every `C3` MSR |
| `X4` | `0x40000118` accepts writes of 0 and 1, each read back, and rejects 2; the check leaves it at 1 |
| `X5` | Writes to every read-only identity MSR fail |
| `X6` | Reads of `IA32_TSC_ADJUST` and `IA32_TSC_DEADLINE` fail |

It prints one line per check and CPU, then a summary, and exits with status
0 if every check passed and 1 otherwise:

```text
NVX-TIME-ABI-EXHAUSTIVE: v=1 check=<ID> cpu=<n> status=<pass|fail> detail="<escaped text>"
NVX-TIME-ABI-EXHAUSTIVE: v=1 status=<ok|fail> cpus=<online> failures=<n>
```

On success the check prints one line to the console:

```text
NVX-TIME-ABI: v=1 phase=<boot|capture|restore> status=ok cpus=<online> tsc_hz=<F> lapic_hz=<L> generation=<g> elapsed_us=<duration>
```

`elapsed_us` covers the checks and, at boot, the daemon start. The line is
printed after it is taken, synchronously and before any workload starts, so
a harness sees the marker before workload output and an early power-off
cannot lose it; its console cost (one port exit per byte) is part of the
cold-boot cost the performance gate measures.

On failure it prints `status=fail check=<ID> detail="<text>"` in the same
format, emits a violation event with code `G_CONFORMANCE_<ID>` (`G_KERNEL_WX`
for `K1`), and powers
off with status 193. The boot step of `C12` steps the clock before any
workload starts and is not counted as a discontinuity. The only other line
with this prefix is the non-fatal `phase=runtime status=uncertain` line of
the [wall-clock discipline](#wall-clock-discipline).

**Report-only mode (test only).** The kernel token `nvx_time_abi=report-only`
makes the checks and the watcher report instead of powering off, so the guest
can be evaluated under an OpenVMM that does not implement the time ABI. It
prints `NVX-TIME-REPORT` and `NVX-TIME-REPORT-VIOLATION` lines with the same
fields, and its marker ends with ` failures=<n>`. These prefixes are reserved
for this mode; production images never set the token, and harnesses never
accept a report-only boot as conformant.

### Violation watcher

The boot check opens `/dev/kmsg`, seeks it to its end, and only then reads
the whole kernel log once with `syslog(SYSLOG_ACTION_READ_ALL)` for `C4`. The
daemon inherits that descriptor and follows it, so no record is missed;
records logged in between are seen twice, and identical lines are one event.
A log buffer that wrapped before the boot check fails `C4`, because its
required records are missing. The daemon sets `oom_score_adj` to -1000. A
record matches when its message text contains every substring of a row:

| Code | Substrings |
| --- | --- |
| `G_TSC_UNSTABLE` | `Marking TSC unstable due to ` |
| `G_CLOCKSOURCE_UNSTABLE` | `timekeeping watchdog on CPU` and `as unstable because the skew is too large` |
| `G_CLOCKSOURCE_SWITCH` | `clocksource: Switched to clocksource ` (any switch after the boot check) |
| `G_CLOCKSOURCE_SKEW` | `clocksource: ` and ` ahead of CPU `, or `clocksource: ` and ` behind CPU ` |
| `G_TSC_WARP` | `TSC synchronization [CPU#`, `cycles TSC warp between CPUs`, or `TSC warped randomly between CPUs` |
| `G_TSC_ADJUST` | `TSC ADJUST` |
| `G_RCU_STALL` | `rcu: INFO: ` and one of ` detected stalls on CPUs/tasks`, ` self-detected stall on CPU`, or ` detected expedited stalls` |
| `G_RCU_STARVED` | `rcu: ` and one of ` kthread starved for ` or ` kthread timer wakeup didn't happen for ` |
| `G_SOFT_LOCKUP` | `watchdog: BUG: soft lockup - CPU#` |
| `G_HARD_LOCKUP` | `Watchdog detected hard LOCKUP` |
| `G_HUNG_TASK` | `INFO: task ` and ` blocked for more than ` |
| `G_UNCHECKED_MSR` | `unchecked MSR access error` |
| `G_KMSG_OVERRUN` | A read of `/dev/kmsg` fails with `EPIPE` (records were lost) |

Before the boot check passes, a match is reported by `C4`. Afterwards it is
a runtime violation: the daemon emits the event and powers off with status
194. The daemon also reads `/sys/kernel/rcu_stall_count` at every discipline
poll and reports `G_RCU_STALL` if it is nonzero, so a stall is caught even if
its log record is lost.

A violation event is one line of at most 512 bytes:

```text
NVX-TIME-ABI-VIOLATION: v=1 code=<code> source=<conformance|watcher|repair> phase=<boot|capture|restore|runtime> generation=<g> boottime_ns=<CLOCK_BOOTTIME> detail="<escaped text>"
```

The guest writes it to `/dev/kmsg` at priority 2, to the portb data port
`0xe9` (through `/dev/port` or `outb`), and to the console. Consumers treat
identical lines as one event. The guest then writes the status to the
shutdown port `0x604` (directly, or through `nvx-exit`); its first byte
becomes the OpenVMM process exit status.

### Snapshot agent

`nvx-snapshot` performs these steps for every tier and for untiered
snapshots. Steps marked "debug" apply only to the CI debug kernel, which
builds the soft-lockup and hung-task detectors.

Before the capture request:

1. Run the capture checks (`C6`, `C7`, `C10`). They do not wait.
2. Save `/sys/module/rcupdate/parameters/rcu_cpu_stall_suppress` and write 1.
3. Debug: save and zero `/proc/sys/kernel/soft_watchdog` and
   `/proc/sys/kernel/hung_task_timeout_secs`.
4. Apply the existing freezer and scratch barriers.
5. Write the capture request to `0x605`.

If the write returns without a restore (no destination or a rejected
capture), the agent removes the barriers and then restores the values saved
in steps 2 and 3. Otherwise, in the restored process:

6. Read the status from `0xea`. Bit 1 is always set after a restore.
7. Read `CLOCK_REALTIME` as `t0`, write `0xa5` to `0xea`, read it as `t1`,
   and read the packet with four-byte reads. Validate the magic, version,
   reserved bits, counts, `g`, and the generation ID (`G_REPAIR_PACKET`,
   `G_REPAIR_GENERATION`).
8. Set the wall clock. Compute `theta` and `epsilon` from the bracket. If
   `epsilon` exceeds 1 ms, take up to two time samples and keep the one with
   the smallest uncertainty; if none is within 1 ms, fail
   (`G_REPAIR_SAMPLE`). Apply `adjtimex` with `ADJ_SETOFFSET | ADJ_NANO` and
   `time = theta`, then `ADJ_FREQUENCY | ADJ_STATUS` with
   `freq = -rate_deviation` (clamped to ±500 ppm) and
   `status = STA_PLL | STA_NANO` (`G_REPAIR_CLOCK`). Record the restore
   discontinuity and the new `g`.
9. Run the existing processor and memory activation.
10. Run the existing entropy and identity repair for the tier. The RTC-based
    wall-clock refresh is removed; `instance-checkpoint` restores also get
    step 8.
11. Run the restore checks (`C1`, `C2`, and `C5` on newly onlined CPUs; `C3`
    for CPU 0; `C6`; `C10`). They do not wait.
12. If `ACK_REQUIRED` is set, write the acknowledgement (2) to `0x605`.
13. Signal the daemon to finish the restore off the latency path: wait for
    the [grace period release](#rcu-grace-period-release); restore the
    values saved in steps 2 and 3 (`G_REPAIR_SUPPRESSION`); run the deferred
    `C7` check; print `NVX-TIME-ABI: v=1 phase=restore status=ok`; and restart
    the discipline at the fast cadence.

Steps 6, 7, and 8 run in one helper process. Repair failures emit a violation
event and power off with status 195.

### RCU grace period release

Stall suppression is required: on KVM, restores after 30 s of downtime
without it report `rcu_preempt self-detected stall` at 1 and 8 vCPUs, because
jiffies jump by `D`; with it, no stall appears at 1, 2, 4, or 8 vCPUs.

Stall suppression may be released only after the grace period that was in
flight at capture has ended, or the restored guest reports a false stall.
`membarrier(MEMBARRIER_CMD_GLOBAL)` does not guarantee this: Linux 6.18 skips
`synchronize_rcu()` when one CPU is online, and with `rcupdate.rcu_expedited=1`
it runs an expedited grace period, which does not end the in-flight normal
one. The daemon therefore:

1. saves `/sys/kernel/rcu_normal` and writes 1, so every synchronous grace
   period, expedited or not, waits for a normal grace period;
2. mounts a private `tmpfs` at `/run/nvx/rcu-sync` and unmounts it (on every
   unmount, Linux 6.18 `namespace_unlock()` waits in
   `synchronize_rcu_expedited()`, which now waits for a full normal grace
   period started after the call, on any number of CPUs);
3. restores `/sys/kernel/rcu_normal`; and
4. releases the suppression.

If step 2 has not returned after `rcu_cpu_stall_timeout` seconds, the daemon
releases the suppression anyway: the grace period is genuinely stuck, and the
kernel then reports the real stall.

### Wall-clock discipline

The daemon keeps `CLOCK_REALTIME` on host UTC through the kernel's PLL:

- **Cadence.** A poll every 16 s for the first four polls after the boot
  check or a restore, then every 64 s.
- **Sample.** Up to three time samples per poll; keep the first with
  `epsilon <= 50 µs`. Otherwise skip the poll, count a rejected sample, set
  `last_sample_error=G_SAMPLE_UNCERTAIN`, and print
  `NVX-TIME-ABI: v=1 phase=runtime status=uncertain code=G_SAMPLE_UNCERTAIN
  epsilon_ns=<smallest>` on the console, with `epsilon_ns=none` when no
  attempt produced a valid sample. The next accepted sample resets
  `last_sample_error` to `none`.
  A sample whose `g` differs from the recorded `g` is discarded: a restore
  happened, and restore repair resets the discipline.
- **Step.** If `|theta| >= 128 ms`, apply `ADJ_SETOFFSET | ADJ_NANO` with
  `time = theta`, count a discontinuity, and reapply the frequency and
  status.
- **Slew.** Otherwise apply `ADJ_OFFSET | ADJ_STATUS | ADJ_NANO |
  ADJ_TIMECONST | ADJ_MAXERROR | ADJ_ESTERROR` with `offset = theta`
  nanoseconds, `status = STA_PLL | STA_NANO` (clearing `STA_UNSYNC`),
  `constant = 4` at the 16 s cadence or 6 at the 64 s cadence,
  `maxerror = ceil((|theta| + epsilon) / 1000)` µs, and
  `esterror = ceil(epsilon / 1000)` µs.
- **Bounds.** The kernel limits the frequency to ±500 ppm; the declared rate
  tolerance uses at most 250 ppm of it.

The discipline never powers off the guest: a host wall-clock step is
followed, not reported as a violation.

**Discontinuity state.** The daemon publishes `/run/nvx/time/state`, replaced
atomically with `rename(2)` after every change. The sandbox agent bind-mounts
`/run/nvx/time` read-only into the container at the same path. The file holds
`key=value` lines:

| Key | Content |
| --- | --- |
| `version` | 1 |
| `generation` | `g` |
| `discontinuities` | Wall-clock discontinuities since cold boot: restores plus discipline steps |
| `last_discontinuity` | `none`, `restore`, or `step` |
| `last_step_ns` | Signed size of the last step |
| `last_step_realtime_ns` | `CLOCK_REALTIME` right after the last step |
| `last_downtime_ns` | `D` of the last restore |
| `last_downtime_source` | `monotonic` or `utc` |
| `synchronized` | 1 when the last accepted sample is at most 128 s old |
| `offset_ns` | Last measured `theta` |
| `uncertainty_ns` | Last accepted `epsilon` |
| `frequency_ppb` | Current kernel frequency correction |
| `samples`, `rejected_samples` | Sample counters |
| `last_sample_error` | `none` or `G_SAMPLE_UNCERTAIN` |
| `violations` | 0; a violation powers the guest off |

Workloads that need prompt notice of a step can also arm a `timerfd` with
`TFD_TIMER_CANCEL_ON_SET`, which the kernel cancels on every step.

## Failure codes

Codes are stable. OpenVMM errors put the code in brackets at the start of the
message, for example `[E_TSC_RATE_TOLERANCE] destination TSC rate ...`, and
the code survives error wrapping across the worker boundary. A rejected cold
boot or restore exits the OpenVMM process with status 1, the existing
fatal-error status; tests and orchestrators match the bracketed code. A
rejected capture is rollback-safe: the guest continues, and OpenVMM logs the
code.

| VMM code | Condition | Detected at |
| --- | --- | --- |
| `E_SNAPSHOT_VERSION` | Manifest version is not 6; the snapshot must be recaptured | Restore |
| `E_MANIFEST_TIME` | Time contract missing or malformed, `time_abi_version` not 1, or tolerance not 250 | Restore |
| `E_BACKEND_MISMATCH` | Snapshot taken on another backend | Restore |
| `E_PROFILE_UNKNOWN` | Profile ID not pinned in this OpenVMM, or a restore's explicit `--cpu-profile` names another profile than the snapshot's | Cold boot, restore |
| `E_PROFILE_DIGEST` | Recorded, embedded, and pinned profile digests disagree, or the effective-CPUID digest is wrong | Restore |
| `E_PROFILE_HOST_UNKNOWN` | `--cpu-profile auto` maps the host to no profile, or to profiles of more than one generation | Cold boot |
| `E_PROFILE_TIME_BITS` | The profile is invalid or violates the CPU time bits | Cold boot, restore |
| `E_CPU_GENERATION` | Host CPU vendor, family, model, or stepping not in the profile | Cold boot, restore |
| `E_PROFILE_UNSUPPORTED` | Backend lacks a feature, limit, XSAVE layout, MSR value, or feature-bank bit of the profile, or the host is not qualified | Cold boot, restore |
| `E_CPU_SURFACE` | Recomputed effective CPUID differs from the recorded one | Restore |
| `E_IDENTITY_ROUTING` | Backend cannot deliver the identity CPUID or MSRs | Cold boot, restore |
| `E_TSC_SYNC_UNSUPPORTED` | Backend lacks the synchronized TSC set | Cold boot, restore |
| `E_TSC_SCALING_ACTIVE` | The guest TSC would be scaled | Cold boot, restore |
| `E_TSC_RATE_UNAVAILABLE` | Backend cannot report its native TSC rate | Cold boot, capture, restore |
| `E_TSC_RATE_IMPLAUSIBLE` | A rate is outside 500 MHz to 10 GHz | Cold boot, capture, restore |
| `E_TSC_RATE_TOLERANCE` | `abs(F_d - F_s)` exceeds 250 ppm of `F_s` | Restore |
| `E_LAPIC_RATE_UNAVAILABLE` | Backend cannot report its LAPIC rate | Cold boot, capture, restore |
| `E_LAPIC_RATE_MISMATCH` | `L` is not the backend constant, or `L_d` differs from `L_s` | Cold boot, restore |
| `E_HOST_IDENTITY` | Host identity, boot identity, or clocks unavailable | Capture, restore |
| `E_DOWNTIME_NEGATIVE` | Downtime below zero | Restore |
| `E_DOWNTIME_EXCESSIVE` | Downtime above 30 days | Restore |
| `E_TSC_ANCHOR` | An anchor is unavailable, or no sample pairs within 100 µs after bounded re-sampling | Capture, restore |
| `E_TSC_TARGET_OVERFLOW` | `TSC_target` exceeds 64 bits | Restore |
| `E_TSC_SYNC_READBACK` | A VP does not hold the synchronized value | Restore |
| `E_VP_LATE_CREATION` | A VP was instantiated after the synchronized set | Restore |
| `E_LAPIC_PERIODIC` | A periodic LAPIC timer is armed | Capture, restore |
| `E_LAPIC_TSC_DEADLINE` | TSC-deadline mode or state is present | Capture, restore |
| `E_PIT_ACTIVE` | PIT channel 0 is counting in a periodic mode | Capture, restore |
| `E_GENERATION_EXHAUSTED` | `capture_generation + 1` overflows `u32` | Restore |
| `E_CMDLINE_CLOCK_TOKEN` | `tsc_early_khz=` or `lapic_timer_hz=` in a supplied or saved command line | Cold boot, restore |
| `E_TEST_HOOK` | A malformed or unknown test hook | Cold boot, restore |

Guest failures power off through `0x604` with a status distinct from the
statuses the guest already uses (0, 1, 37, 125, 126, 127, 128 to 192 for
signals, and 255):

| Status | Class | Guest codes |
| ---: | --- | --- |
| 193 | Conformance | `G_CONFORMANCE_C1` to `G_CONFORMANCE_C12`, `G_KERNEL_WX` |
| 194 | Runtime violation | `G_TSC_UNSTABLE`, `G_CLOCKSOURCE_UNSTABLE`, `G_CLOCKSOURCE_SWITCH`, `G_CLOCKSOURCE_SKEW`, `G_TSC_WARP`, `G_TSC_ADJUST`, `G_RCU_STALL`, `G_RCU_STARVED`, `G_SOFT_LOCKUP`, `G_HARD_LOCKUP`, `G_HUNG_TASK`, `G_UNCHECKED_MSR`, `G_KMSG_OVERRUN` |
| 195 | Restore repair | `G_REPAIR_PACKET`, `G_REPAIR_GENERATION`, `G_REPAIR_SAMPLE`, `G_REPAIR_CLOCK`, `G_REPAIR_SUPPRESSION` |

`G_SAMPLE_UNCERTAIN` is the only non-fatal guest code: the discipline records
it and continues (see [Uncertainty bounds](#uncertainty-bounds)).

A workload can exit with any 8-bit status, so a harness classifies a time
failure by the status together with its `NVX-TIME-ABI-VIOLATION` event.

## Host qualification

`nvx.py doctor --backend <backend>` qualifies a host interactively, and the
`validate-runner` action runs the same checks before every CI job. Both print
one `NVX-DOCTOR: check=<id> status=<pass|fail> detail=...` line per check and
fail if any check fails. The time checks replace the `nonstop_tsc` check.

| ID | Check |
| --- | --- |
| `H1` | The backend device or API is present and usable |
| `H2` | CPU fingerprint: vendor, family, model, stepping, microcode, host kernel or OS build, the generation name, and the profile that `auto` selects; an unmapped generation fails (`E_PROFILE_HOST_UNKNOWN`) |
| `H3` | OpenVMM preflight in verification mode: profile support, identity routing, synchronized TSC set, no scaling, and both rates, without booting a guest |
| `H4` | Host TSC rate stability: two 1 s measurements of the TSC against host monotonic time agree within 1 ppm and are within 100 ppm of `F_d`; on Linux the host clocksource is `tsc` (KVM rewrites per-vCPU TSC offsets on a host with an unstable TSC) |
| `H5` | Host cross-CPU TSC skew: a pinned-thread probe over all host CPU pairs, `max_abs_offset_ns <= 1000` |
| `H6` | Guest warp probe: a microVM with the host's largest supported vCPU count up to 8 boots, passes the boot check, and reports `max_backward_ns` and `max_abs_offset_ns` at most 1,000 |
| `H7` | Host UTC is synchronized: no `STA_UNSYNC` on Linux; a synchronized `w32tm` source on Windows |

Qualification gates on these measured properties and on the profile's
features. Hosts whose OS sees no invariant TSC (Azure WHP and nested MSHV
partitions) still expose the CPUID invariant-TSC bit through the profile, so
the warp probe (`H6`) and rate stability (`H4`) are the evidence for TSC
invariance there; a host that fails them, such as `azure-azlinux-2`, is not
qualified.

Generation names used in logs, reports, and job summaries are `skylake-sp`
(family 6, model 85), `icelake-sp` (6/106), and `emeraldrapids` (6/207).
`validate-runner` and `nvx.py doctor` detect the generation at run time and
report it, together with the selected profile, `F_d`, `L`, and the skew
metrics, in their log and the job summary; an unknown generation fails
qualification explicitly. Runner labels are not used and runners are not
re-registered: per-PR CI captures and restores on the same runner, and
same-generation cross-VM restore is validated by the fleet restore matrix
(`p6-restore-matrix`) on the hosts our account can use. Routing CI jobs by
generation labels is optional future work.

## Performance expectations and acceptance gate

**Gate.** Per backend and vCPU count, no p50 is worse than the base-branch
median by more than `max(5%, 2 ms)`. The gate covers all 36 one-vCPU metrics
and `shell_snapshot_restore_512_mib` at 2, 4, and 8 vCPUs.

Expected effects:

| Change | Expected effect |
| --- | --- |
| WHP restored SMP without RDTSC emulation | Removes the 1-to-2 vCPU restore jump (120.7 ms to 165.9 ms p50) and the 45 to 70 µs cost of every guest timestamp read after an SMP restore |
| Packet v4 with four-byte reads instead of 83 or more byte reads | Fewer restore exits, most visible on WHP |
| Wall clock from the packet instead of RTC polling | Removes at least 32 CMOS port exits and the update wait per tiered restore |
| No capture-time clocksource waits | Removes the harness's wait for `tsc-early` to become `tsc`: 0.73 to 0.92 s per capture on MSHV and 0.47 to 0.67 s on WHP; outside the gated metrics |
| `no_timer_check` from the Hyper-V identity, no LAPIC calibration, and no `tsc-early` window at cold boot | About 43 to 52 ms (9 to 15%) faster `cold_start_base` and other quiet cold boots on MSHV and WHP; KVM unchanged |
| MSHV VP creation | Serialized at about 14 ms per application processor on bare metal (27 and 85 ms at 4 and 8 vCPUs); the frozen synchronized TSC set adds 40 to 170 µs for 1 to 4 VPs and no per-VP serialized work |
| Boot check and daemon start | Added cold-boot cost, reported as the first run's `elapsed_us`; budget 2.5 ms at one vCPU plus 0.3 ms per additional vCPU on KVM and MSHV, and 5 ms plus 0.6 ms per additional vCPU on WHP; the gate is authoritative |
| Counting LAPIC instead of TSC-deadline on KVM | Different timer-programming exits; covered by the gate |
| Restore repair and checks before the acknowledgement | Run in one helper process; the RCU release and deferred checks run after the acknowledgement |

Expected wins are tracked separately and do not relax the gate.

**Attribution.** With `OPENVMM_STARTUP_PROFILE` set, OpenVMM's lifecycle
profile records three exclusive time ABI restore phases:
`restore.time_abi_clock` (restore steps 11 to 16), `restore.guest_resume`
(from the VP release to the guest's first selection of the restore packet),
and, for a restore with `ACK_REQUIRED`, `restore.guest_repair` (from that
selection to the arrival of the `0x605` acknowledgement). The
`restore.guest_repair_gate` milestone still spans from the VP release to the
release of the acknowledgement boundary. The guest reports its own repair
checks as the restore marker's `elapsed_us`, which covers ungated restores
too.

## Test matrix

**Unit tests (OpenVMM).** Rate boundary (250 ppm accepted, one hertz beyond
rejected) in both directions; downtime source selection and bounds, including
equal identities with a different clock kind; `TSC_target` arithmetic and
overflow; LAPIC tick arithmetic for every divide value, expiry, masking, and
periodic rejection; identity CPUID and MSR tables, including every #GP case
and `0x40000118` save and restore; capabilities derivation (`hv1` and
`kvm_clock` false); manifest version 6 validation and rejection of versions
2 through 5; packet v4 and time-sample golden vectors and their guest-side
parser; four-byte portb reads; and the generation counter.

**Conformance.** The boot and restore checks pass at 1, 2, 4, and 8 vCPUs on
all 18 registered hosts, plus the exhaustive CI check and the warp probe on
every backend. The fleet runs them on the hosts our SSH account can use,
which for KVM are prometheus32 and `azure-kvm-5` and for MSHV prometheus30
and `azure-azlinux-5`: the account cannot open `/dev/kvm` or `/dev/mshv` on
the other KVM and MSHV runners, which only CI jobs exercise.

**Restore matrix.** Every case runs with zero violations; rejected cases must
fail with the listed code. Per-PR CI runs the same-host cases on one runner;
the full matrix, including the cross-VM cases, runs on the hosts our account
can use as the fleet restore matrix.

| Case | Hosts | Expected |
| --- | --- | --- |
| Same host, immediate | All | Restored; `DOWNTIME_UTC` clear |
| Same host, downtime of 30 s (over the 21 s RCU stall timeout), at 1 and 8 vCPUs, with and without `rcupdate.rcu_expedited=1` | All | Restored; no RCU stall; `rcu_stall_count` stays 0 |
| Same host under DVFS load | prometheus32 | Restored |
| Simulated host reboot: hooks `force-utc-downtime`, `boot-id-mismatch`, and `dest-rate-offset-ppm=+200`, then `-200` | One host per backend | Restored; `DOWNTIME_UTC` and `TEST_HOOKS` set; rate deviation reported |
| Simulated rate beyond tolerance: `dest-rate-offset-ppm=+251` | One host per backend | `E_TSC_RATE_TOLERANCE` |
| Downtime bounds: `downtime-add-s=2592001`; `force-utc-downtime` with `utc-offset-ms=-<n>`, `n` above the elapsed time | One host per backend | `E_DOWNTIME_EXCESSIVE`; `E_DOWNTIME_NEGATIVE` |
| Sample uncertainty: `sample-delay-us=200`; then `sample-delay-us=3000` on restore and on cold boot | One host per backend | Restored, with `G_SAMPLE_UNCERTAIN` recorded and the guest running; `G_REPAIR_SAMPLE` (195); `G_CONFORMANCE_C12` (193) |
| Across VMs of one generation | `azure-windows-1` to `-2`; `azure-windows-3` to `-4`. KVM and MSHV have no usable pair of one generation, so the simulated host reboot covers their cross-host path | Restored |
| Across generations | `azure-windows-1` (8370C) to `-3` (8573C); prometheus32 to `azure-kvm-5` (KVM); prometheus30 to `azure-azlinux-5` (MSHV) | `E_CPU_GENERATION` |
| Host without invariant TSC at the host OS | `azure-azlinux-2` (out of CI rotation) | Qualified only if `H4` and `H6` pass; otherwise `nvx.py doctor` fails |
| Across backends | prometheus32 (KVM) to prometheus30 (MSHV) | `E_BACKEND_MISMATCH` |
| Pre-v1 snapshot | Any | `E_SNAPSHOT_VERSION` |
| Processor activation from one boot-online CPU to 2, 4, and 8 | All backends | Restored; warp probe passes |
| Every tier and an untiered snapshot; capture-restore chains | All backends | Restored; `g` increments by one per restore |

No test reboots a host. The orchestrator asks the user before any real
reboot.

**Reliability.** Repeated snapshot scenarios at 1, 2, 4, and 8 vCPUs on the
hosts the fleet can use (see Conformance), with the warp probe and the
watcher active, report no RCU, soft-lockup, hung-task, clocksource, or warp
message. The CI debug-kernel variant runs the same-host cases with the
soft-lockup and hung-task detectors enabled.

**Performance.** The gate above, computed by the performance agent from the
CI benchmark matrix.

Test hooks are hidden OpenVMM options (`--x-time-abi-test-hook <hook>`,
repeatable):

| Hook | Effect |
| --- | --- |
| `force-utc-downtime` | Select the UTC source even on the same host boot |
| `boot-id-mismatch` | Treat the destination boot identity as different |
| `dest-rate-offset-ppm=<n>` | Perturb the measured `F_d` used by the rate policy and the reported deviation; the TSC is never scaled |
| `downtime-add-s=<n>` | Add `n` seconds to the measured `D` before the bounds check |
| `utc-offset-ms=<n>` | Add `n` milliseconds to every destination UTC reading: the downtime sample, the packet, and time samples |
| `sample-delay-us=<n>` | Delay the handling of the first `0xa5` write and of every `0xa7` write by `n` µs, which widens the guest's bracket |

Every active hook is logged at warning level and sets `TEST_HOOKS` in the
packet and in every time sample.

## Removed mechanisms and migration

Removed from OpenVMM:

- Cold-boot clock tokens: `prepare_cold_boot_command_line` no longer injects
  `tsc_early_khz=` or `lapic_timer_hz=`, and their propagation, parsing, and
  platform-tier validation are deleted.
- The exact-equality CPU contract (`CpuCompatibilityContract`, including its
  `tsc_deadline` and `kvm_clock` fields) and host-derived CPUID, replaced by
  CPU profiles.
- Leaf `0x15` synthesis (`tsc_frequency_cpuid_leaves`) on every backend.
- Per-backend downtime paths (`advance_snapshot_time`), per-VP TSC
  advancement (`advance_tsc`), TSC-deadline advancement, periodic LAPIC
  advancement, wall-clock-only downtime (`calculate_snapshot_downtime`), and
  the per-VP TSC writes of saved VP state on restore.
- KVM: the microVM downtime use of `KVM_GET_CLOCK`/`KVM_SET_CLOCK` (the
  Hyper-V reference time source keeps them; it requires `hv1`, which the time
  ABI never enables), kvmclock MSR state, KVM CPUID leaves, `KVM_SET_TSC_KHZ`,
  and restore-time `IA32_TSC` writes.
- MSHV: BSP-copy TSC alignment and exact rate equality.
- WHP: the 1 GHz rate request and its silent fallback, and `RestoredTsc`
  with its RDTSC, RDTSCP, and `IA32_TSC` exits.
- Restore packets v1 to v3 and manifest versions 2 to 5.

Removed from NVX:

- Kernel: patch 0004 (`lapic_timer_hz`); `CONFIG_CPU_FREQ`,
  `CONFIG_X86_INTEL_PSTATE`, and `CONFIG_SCHED_MC_PRIO` (which selects both
  and needs ACPI CPPC data the microVM lacks); and `CONFIG_KVM_GUEST` with
  `CONFIG_PARAVIRT_CLOCK` and `CONFIG_HALTPOLL_CPUIDLE`, which are dormant
  without a KVM signature. `CONFIG_HYPERVISOR_GUEST` and `CONFIG_PARAVIRT`
  stay on and `CONFIG_HYPERV` stays off. The CI debug kernel adds
  `CONFIG_DEBUG_KERNEL` with the soft-lockup and hung-task detectors only.
- Guest: RTC polling in `nvx-reseed`, and the restore packet v1 to v3 parser
  in `nvx-port-io`.
- Harness: `tsc=reliable` and `no_timer_check` in `BASE_TUNING`; per-backend
  `clocksource=` tokens; `stable_clocksource_wait_script` and the
  capture-time clocksource waits; the KVM and WHP branches of
  `snapshot-core`; the `smp-lapic` scenarios (`lapic=notscdeadline`), which
  duplicate `smp`; `restore-tsc-sync`, `clearcpuid=tsc_adjust`, and the
  fresh-boot TSC control, which the warp probe replaces; and the dmesg greps
  in `restore-processors.sh`, which the watcher replaces. The
  `cold_start_clocksource` benchmark scenario passes `clocksource=tsc` on
  every backend.
- CI: the `nonstop_tsc` runner check, replaced by host qualification.

Migration impact:

- Every existing snapshot is rejected with `E_SNAPSHOT_VERSION`; templates
  must be recaptured.
- OpenVMM, the kernel, and the initramfs must be upgraded together. A new
  guest on an old OpenVMM fails the boot check (status 193); an old guest's
  snapshot agent cannot parse packet v4 and fails closed.
- The guest identifies as Hyper-V on every backend, including KVM.
- CPUID becomes profile-defined, so guests can lose host features that no
  profile of their generation pins.
- Hosts that fail qualification, such as `azure-azlinux-2`, cannot run
  microVMs until replaced.
- Per-PR CI captures and restores on the same runner. Same-generation
  cross-VM restore is validated by the fleet restore matrix on WHP only; no
  usable KVM or MSHV pair of one generation exists, so the simulated host
  reboot covers those backends.
- The `cold_start_clocksource` metric on KVM changes meaning (from
  `kvm-clock` to `tsc`). The change is accepted without an exemption; a gate
  failure on it is investigated as a regression.
- Documentation updates: this document, [Snapshot and
  restore](snapshot-and-restore.md), [Machine and device
  ABI](machine-and-device-abi.md), [Cold boot](cold-boot.md), the
  benchmarks and CI guides, and the OpenVMM Guide (see the appendix).

## Appendix: OpenVMM Guide update plan

`Guide/src/user_guide/openvmm/snapshots.md` changes as follows when the
implementation lands:

1. **Overview.** Note that microVM snapshots carry a time contract and a CPU
   profile, and that only manifest version 6 is accepted.
2. **Restoring a snapshot.** Replace the paragraphs on MSHV
   `IA32_TSC_ADJUST`, KVM TSC offset advancement, MSHV and WHP time freezing
   and BSP alignment, and the WHP partition-reference-time TSC with one
   paragraph on the synchronized TSC set and its read-back.
3. **Generation ID.** Extend the portb paragraph with selector `0xa7`, window
   port `0xeb`, status bit 6, four-byte reads, and packet v4.
4. **Device configuration on restore.** Replace the CPU contract, TSC
   frequency, and `lapic_timer_hz` paragraphs with a new **Time and CPU
   compatibility** section: the identity, the CPU profile and
   `--cpu-profile`, the 250 ppm rate rule, the exact LAPIC rule, the
   downtime sources and bounds, the restore steps, and the error codes.
5. **Limitations.** State that restore requires the same backend, CPU
   generation, and profile, and that older snapshots must be recaptured.
6. **CLI reference.** Document `--cpu-profile` and the doctor verification
   mode. The test hooks stay undocumented in the Guide; this document
   describes them.
