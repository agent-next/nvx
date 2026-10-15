# Whole-device GPU passthrough: feasibility boundary

The pinned OpenVMM revision
`7f225e2cd635bbd1e1839e587e659996433396c8` implements experimental Linux
VFIO assignment. It is **not** available in the NVX microVM profile.

## Source-verified path

OpenVMM paths below are relative to the `openvmm/` submodule. Links pin
both the revision and line ranges, rather than following the moving submodule
checkout. The NVX kernel path is relative to the NVX repository root.

| Component | Source |
| --- | --- |
| Machine profiles `standard` and `microvm` | [MachineProfileCli, lines 21-28][machine-profiles] |
| Standard is the default | [Options::machine, lines 153-156][standard-default] |
| MicroVM rejects PCIe and VFIO | [microVM validation, lines 1300-1319][microvm-rejection] |
| Linux `--vfio host=<BDF>,port=<name>` | [Options::vfio, lines 1415-1433][vfio-cli] |
| Opens the IOMMU group and creates a PCIe resource | [legacy group path, lines 1194-1220][legacy-group] |
| Linux-only assignment implementation | [vfio_assigned_device, lines 4-15][vfio-implementation] |
| Legacy VFIO resolver, DMA and device construction | [resolver, lines 70-105][vfio-resolver] |
| Upstream instructions and experimental status | [VFIO guide, lines 1-33][vfio-overview] |

The NVX guest kernel is also unsuitable:
[`kernel/config-microvm`, line 913][nvx-kernel] disables `CONFIG_PCI`.

## Minimal standalone experiment

This is a source-derived recipe, not a claim of successful NVIDIA driver
initialization. It does not use the NVX microVM launcher or its snapshot path.

1. Use a Linux host with working KVM and an enabled IOMMU (VT-d/AMD-Vi).
   A cloud VM must expose both nested virtualization and a usable virtual
   IOMMU. Check before building or detaching devices:

   ```sh
   systemd-detect-virt
   ls -l /dev/kvm
   find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d
   lspci -Dnnk
   ```

2. On a dedicated test host only, inspect **every member** of the GPU's
   IOMMU group, not just the GPU function. This recipe requires a group
   containing only dedicated, assignable endpoint functions, such as the GPU
   and its HDMI audio function. Stop if it includes bridges, a host console,
   storage, networking, or anything still needed by the host. Confirm all
   members are idle, stop their users (including `nvidia-persistenced` if
   active), and disable GPU persistence mode before release.

   In a Bash shell, replace the example BDF and inspect the group and BARs:

   ```bash
   set -euo pipefail
   BDF=0000:01:00.0
   GROUP=$(readlink -e "/sys/bus/pci/devices/$BDF/iommu_group")
   test -d "$GROUP/devices"
   members=("$GROUP"/devices/*)
   for dev in "${members[@]}"; do
       lspci -Dnnk -s "${dev##*/}"
       sudo lspci -vv -s "${dev##*/}"
   done
   ```

   Check each `Region` size and whether it is 32-bit or 64-bit. The A10
   requires a 32 GiB 64-bit prefetchable BAR1, plus other BARs. Step 4 uses
   `high_mmio=64G` for that layout, leaving room for natural BAR alignment
   and the other high BARs. The default is only 1 GiB high and 64 MiB low
   ([CLI defaults, lines 1271-1278][mmio-defaults]). Recalculate both windows
   for the actual devices assigned, including extra functions; 64 GiB is
   not a universal GPU setting. OpenVMM [assigns PCI resources before boot,
   lines 3510-3516][cold-boot-assignment] and fails with
   [MmioExhaustion, lines 173-186][mmio-exhaustion] if they do not fit.

   After inspection, save every original driver **before any unbind**, then
   release and bind the whole group. Already-unbound members are supported.
   Refuse existing overrides so this recipe does not overwrite another
   assignment policy. Keep the printed state directory for step 5, including
   if preparation or launch fails:

   ```bash
   STATE=$(mktemp -d "$PWD/vfio-state.XXXXXX")
   printf 'Restore state: %s\n' "$STATE"
   for dev in "${members[@]}"; do
       override=$(<"$dev/driver_override")
       test -z "$override" || test "$override" = '(null)'
       driver=-
       if test -L "$dev/driver"; then
           driver=$(basename "$(readlink -e "$dev/driver")")
       fi
       printf '%s\t%s\n' "${dev##*/}" "$driver" >> "$STATE/drivers.tsv"
   done
   sudo modprobe vfio-pci
   sudo modprobe vfio_iommu_type1
   while IFS=$'\t' read -r bdf driver; do
       dev="/sys/bus/pci/devices/$bdf"
       printf '%s\n' vfio-pci | sudo tee "$dev/driver_override" >/dev/null
       if test -L "$dev/driver"; then
           printf '%s\n' "$bdf" | sudo tee "$dev/driver/unbind" >/dev/null
       fi
   done < "$STATE/drivers.tsv"
   while IFS=$'\t' read -r bdf driver; do
       printf '%s\n' "$bdf" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind >/dev/null
       test "$(basename "$(readlink -e "/sys/bus/pci/devices/$bdf/driver")")" = vfio-pci
   done < "$STATE/drivers.tsv"
   test -c "/dev/vfio/${GROUP##*/}"
   ls -l "/dev/vfio/${GROUP##*/}"
   ```

   This extends the [upstream binding steps, lines 63-97][vfio-binding]
   to the whole group. No-IOMMU mode is unsupported. Do not weaken interrupt
   remapping as an automatic fix. Bind companions to VFIO even if they will
   remain unused by the guest; add a separate root port and `--vfio` argument
   for each companion that the guest needs.

3. With the documented Linux build prerequisites installed, run
   `cargo xflowey restore-packages` then `cargo build -p openvmm --release`
   from the submodule directory. See
   [the pinned build guide, lines 14-38][build-guide].
   The commands in step 4 also run from that submodule directory and assume
   Cargo's default target directory (no `CARGO_TARGET_DIR` override).
   Use a separate general-purpose x86-64 guest kernel/initramfs with ACPI,
   PCI/PCIe, PCI MSI, PCI MMCONFIG, serial console and initramfs support.
   For `nvidia-smi`, include matching NVIDIA kernel modules, firmware and
   userspace tools. These guest-image requirements are proposed, untested
   here; the NVX microVM kernel is not reusable unchanged.

4. Launch the standard machine, with no emulated guest IOMMU:

   ```sh
   sudo ./target/release/openvmm --machine standard --hypervisor kvm \
     --pcie-root-complex rc0,high_mmio=64G --pcie-root-port rc0:rp0 \
     --vfio host="$BDF",port=rp0 \
     --kernel /path/to/vmlinux --initrd /path/to/initrd \
     --cmdline 'console=ttyS0' --com1 console \
     --memory 4GB --processors 2
   ```

   This follows [the upstream CLI, lines 99-120][vfio-launch], with the
   A10-sized high-MMIO window instead of the insufficient default.
   Inside the guest, compare `lspci -Dnn` vendor/device IDs with the host,
   then run `nvidia-smi`. Enumeration alone does not prove CUDA execution.

5. After OpenVMM exits and releases all VFIO handles, restore **every**
   member, even after a failed bind or boot. Use the state directory printed
   in step 2 (`STATE=/absolute/path/to/vfio-state.XXXXXX` if using a new
   Bash shell). Clear `driver_override` with a newline, not a zero-byte write,
   before restoring each saved driver. A GPU originally using `nvidia`
   returns explicitly to `nvidia`; an originally unbound member stays unbound.

   ```bash
   set -euo pipefail
   while IFS=$'\t' read -r bdf driver; do
       dev="/sys/bus/pci/devices/$bdf"
       if test -L "$dev/driver"; then
           printf '%s\n' "$bdf" | sudo tee "$dev/driver/unbind" >/dev/null
       fi
       printf '\n' | sudo tee "$dev/driver_override" >/dev/null
       if test "$driver" != -; then
           sudo modprobe "$driver"
           printf '%s\n' "$bdf" | sudo tee "/sys/bus/pci/drivers/$driver/bind" >/dev/null
           test "$(basename "$(readlink -e "$dev/driver")")" = "$driver"
       else
           test ! -L "$dev/driver"
       fi
       lspci -Dnnk -s "$bdf"
   done < "$STATE/drivers.tsv"
   ```

   Confirm `nvidia-smi` works on the host, then restore any services and
   persistence setting you changed. If rebinding fails, keep the state and
   kernel logs; do not claim the host recovered or resume GPU workloads.

VFIO guests cannot save/restore or hot-plug devices according to
[the upstream limitations, lines 328-332][vfio-limitations]. Sharing the OpenVMM executable
therefore does not imply sharing NVX's microVM lifecycle or snapshot contract.

## Measured cloud prerequisite failure

A dedicated Lambda on-demand A10 VM, running Ubuntu kernel
`6.8.0-60-generic`, produced:

```text
$ systemd-detect-virt
kvm
$ # KVM_GET_API_VERSION and KVM_CREATE_VM ioctls
{"KVM_GET_API_VERSION": 12, "KVM_CREATE_VM": "PASS"}
$ find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d | wc -l
0
$ lspci -Dnn -s 0000:06:00.0
0000:06:00.0 3D controller [0302]: NVIDIA Corporation GA102GL [A10] [10de:2236] (rev a1)
```

The cloud VM's kernel had `CONFIG_INTEL_IOMMU=y` and `CONFIG_VFIO_PCI=m`,
but no ACPI DMAR/IVRS tables or GPU `iommu_group` link. With unsafe
no-IOMMU mode disabled, detaching the idle GPU from `nvidia` succeeded;
binding it to `vfio-pci` failed with `EINVAL` (errno 22), and the kernel
reported `vfio-pci: probe of 0000:06:00.0 failed with error -22`.

This is a negative result for that VM as provisioned, not for OpenVMM on
IOMMU-capable hardware. No nested OpenVMM guest was built or booted, so
guest NVIDIA enumeration, driver initialization and CUDA remain unverified.

[machine-profiles]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args/microvm.rs#L21-L28
[standard-default]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args.rs#L153-L156
[microvm-rejection]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args/microvm.rs#L1300-L1319
[vfio-cli]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args.rs#L1415-L1433
[legacy-group]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/lib.rs#L1194-L1220
[vfio-implementation]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/pci/vfio_assigned_device/src/lib.rs#L4-L15
[vfio-resolver]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/pci/vfio_assigned_device/src/resolver.rs#L70-L105
[vfio-overview]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L1-L33
[nvx-kernel]: https://github.com/agent-next/nvx/blob/042a611bac05f416df206d6e5ca943e631a9ded9/kernel/config-microvm#L913
[mmio-defaults]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args.rs#L1271-L1278
[cold-boot-assignment]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_core/src/worker/dispatch.rs#L3510-L3516
[mmio-exhaustion]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/pci/pci_resource_assignment/src/lib.rs#L173-L186
[vfio-binding]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L63-L97
[build-guide]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/dev_guide/getting_started/build_openvmm.md#L14-L38
[vfio-launch]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L99-L120
[vfio-limitations]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L328-L332
