# Configuration boundary

[Design index](../design.md)

Machine identity is explicit rather than inferred from a kernel, device, or
hypervisor choice. OpenVMM carries it through the command line, management
RPC, worker, test harness, and snapshot configuration. The management RPC
exposes one microVM profile with numeric value 2; values 1, 3, and 4 are
reserved, and retired value 1 is rejected before host resources are opened.
Validation occurs before host resources are opened and again at the worker
boundary.

The microVM requires:

- an x86-64 guest;
- one NUMA node;
- Linux direct boot with Intel MP 1.4 tables;
- KVM, MSHV, or WHP;
- no VTL2, isolation, nested virtualization, or Hyper-V enlightenments;
- the [time ABI](time-abi.md), its only time path, with one CPU profile; and
- the exact [chipset and device inventory](machine-and-device-abi.md).

It accepts exactly 1, 2, 4, or 8 vCPUs
in one socket and one die, with one core per vCPU, no SMT, xAPIC mode, and
contiguous APIC IDs starting at zero. Its Linux direct layout places the MP
floating pointer at `0x0`, MP configuration table at `0x400`, GDT at `0x1000`,
zero page at `0x2000`, and reserves `0x30000..0x30fff` for interrupt status.

The guest sees a [CPU profile](time-abi.md#cpu-profiles), the complete CPUID
surface of one CPU generation, never host passthrough. The host selects it at
cold boot with `--cpu-profile`: a pinned profile ID, `auto`, or `host`, a
development profile derived from the host's CPU. `auto` is the default and is
the only choice of the management RPC; it selects the pinned profile that
serves the host's CPU and falls back, with a warning, to the `host` profile on
an Intel or AMD CPU that no pinned profile serves. The snapshot records the
selected profile.

Snapshot capture may declare an immutable RAM capacity at least as large as the
active base RAM. When it does, both values must be 128-MiB aligned. A snapshot
without a declared capacity cannot select a different RAM size at restore.

Only role-bearing block devices are supported; ordinary unroled `--virtio-blk`
is rejected. Blocks end with writable scratch unless the caller passes
`nvx_overlay_upper=ramfs` on the kernel command line, which requires exactly
one read-only `distro` block and no scratch, and rules out snapshot capture and
restore; see [Effective command line](cold-boot.md#effective-command-line).
Snapshot capture with blocks requires one to three
read-only lower layers followed by writable scratch, all backed by cached,
regular raw files with nonzero 512-byte-aligned geometry. Blockless
snapshots are also supported and do not use sandbox tier metadata. The
management RPC constructs only blockless microVMs without a NIC or control
console; it can attach portb, the boot console, and one HostFs export.

The microVM rejects UEFI, PCAT, IGVM, caller-supplied ACPI, SMBIOS, device
tree, PCI/PCIe, VPCI, VMBus, ISA DMA, IDE, floppy, VMGS, graphics, VGA
firmware, debugger resources, and devices outside the profile. The profile
itself emits the
[fixed Linux direct MP-table metadata](cold-boot.md#linux-direct-mp-table-loader).
This is an allowlist: the implementation builds a microVM directly instead of
constructing a standard PC and removing unwanted devices.

The host, not the guest or a workload request, fixes the workload policy of a
fresh boot. An optional nonzero numeric UID and GID become the fixed workload
identity, and an optional one-shot or managed lifecycle selects whether the
guest supervisor runs one workload or stays resident for sequential requests
over the control console. Both are profile-owned command-line tokens that
caller arguments cannot supply. A managed lifecycle requires a fixed workload
identity and a live, authenticated control console.

Restore is stricter than cold boot. Guest-visible configuration is read from
the snapshot's machine contract. Restore-time input may select the same backend
kind recorded by the snapshot, supply required attachments, and select
processor and RAM activation targets explicitly allowed by the contract. Those
process-local targets do not change processor capacity, RAM capacity, command
line, device placement, feature masks, or filesystem and network identity.
Restore always uses the snapshot's CPU profile, never falls back, and requires
the host's CPU to belong to that profile's generation; an explicit
`--cpu-profile` must be `auto`, the snapshot's profile ID, or `host` when the
snapshot used a host profile. The captured command line also fixes the network
addressing, workload identity, and lifecycle, so restore rejects
network-address, workload-identity, and lifecycle options, and a supplied
processor count may only repeat the captured capacity.
