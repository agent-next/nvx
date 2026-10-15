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
Run the recipe blocks in Bash. Each block that enables strict error handling
runs in a subshell, so a failure stops that block without changing the parent
shell's options or closing the terminal. Stop on failure and restore from the
saved state after any device changes; do not continue to launch.
The [documentation regression checks](vfio-passthrough-tests.md) run these
blocks against fake sysfs without root, hardware access or a Cargo build.

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

   Replace the example BDF with the same GPU address in each block in steps
   2 and 4. Blocks do not share shell variables. Inspect the group and BARs:

   ```bash
   (
   set -euo pipefail
   BDF=0000:01:00.0
   [[ $BDF =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]]
   GROUP=$(readlink -e "/sys/bus/pci/devices/$BDF/iommu_group")
   test -d "$GROUP/devices"
   members=("$GROUP"/devices/*)
   for dev in "${members[@]}"; do
       lspci -Dnnk -s "${dev##*/}"
       sudo lspci -vv -s "${dev##*/}"
   done
   )
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
   (
   set -euo pipefail
   BDF=0000:01:00.0
   [[ $BDF =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]]
   GROUP=$(readlink -e "/sys/bus/pci/devices/$BDF/iommu_group")
   test -d "$GROUP/devices"
   members=("$GROUP"/devices/*)
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
   mapfile -t rows < "$STATE/drivers.tsv"
   test "${#rows[@]}" -gt 0
   declare -A seen=()
   for row in "${rows[@]}"; do
       IFS=$'\t' read -r bdf driver <<< "$row"
       [[ $bdf =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ &&
          $driver =~ ^(-|[a-zA-Z0-9_][a-zA-Z0-9_.-]*)$ &&
          $row = "$bdf"$'\t'"$driver" ]] || {
           printf 'Invalid saved state entry: %q\n' "$row" >&2; exit 1;
       }
       [[ -z ${seen[$bdf]+yes} ]] || {
           printf 'Duplicate saved BDF: %s\n' "$bdf" >&2; exit 1;
       }
       seen[$bdf]=yes
   done
   sudo modprobe vfio-pci
   sudo modprobe vfio_iommu_type1
   for row in "${rows[@]}"; do
       IFS=$'\t' read -r bdf driver <<< "$row"
       dev="/sys/bus/pci/devices/$bdf"
       printf '%s\n' vfio-pci | sudo tee "$dev/driver_override" >/dev/null
       if test -L "$dev/driver"; then
           printf '%s\n' "$bdf" | sudo tee "$dev/driver/unbind" >/dev/null
       fi
   done
   for row in "${rows[@]}"; do
       IFS=$'\t' read -r bdf driver <<< "$row"
       printf '%s\n' "$bdf" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind >/dev/null
       test "$(basename "$(readlink -e "/sys/bus/pci/devices/$bdf/driver")")" = vfio-pci
   done
   test -c "/dev/vfio/${GROUP##*/}"
   ls -l "/dev/vfio/${GROUP##*/}"
   )
   ```

   This extends the [upstream binding steps, lines 63-97][vfio-binding]
   to the whole group. No-IOMMU mode is unsupported. Do not weaken interrupt
   remapping as an automatic fix. Bind companions to VFIO even if they will
   remain unused by the guest; add a separate root port and `--vfio` argument
   for each companion that the guest needs.

3. With the documented Linux build prerequisites installed, run the following
   from the clean, pinned `openvmm/` submodule directory on x86-64 Linux. Do
   not run concurrently with NVX's patch-applying build commands. See
   [the pinned build guide, lines 14-38][build-guide].

   **`openvmm/target/release/openvmm` belongs to NVX.** Building the bare pin
   there would replace NVX's patched/downloaded binary and invalidate its
   recorded executable hash. This standalone experiment deliberately does not
   apply NVX's patches and must never supply NVX artifacts. Both Cargo commands
   below use a new, dedicated target directory; the explicit target triple
   also avoids inheriting a different build target.

   ```bash
   (
   set -euo pipefail
   CARGO_TARGET_DIR=$(mktemp -d "$PWD/../openvmm-vfio-target.XXXXXX")
   export CARGO_TARGET_DIR
   printf 'Standalone target directory: %s\n' "$CARGO_TARGET_DIR"
   cargo xflowey restore-packages
   cargo build -p openvmm --release --target x86_64-unknown-linux-gnu
   printf 'Standalone executable: %s/x86_64-unknown-linux-gnu/release/openvmm\n' "$CARGO_TARGET_DIR"
   )
   ```

   Keep the printed executable path for step 4. This directory is separate
   from NVX's target and provenance files; do not copy its binary over them.
   Use a separate general-purpose x86-64 guest kernel/initramfs with ACPI,
   PCI/PCIe, PCI MSI, PCI MMCONFIG, serial console and initramfs support.
   For `nvidia-smi`, include matching NVIDIA kernel modules, firmware and
   userspace tools. These guest-image requirements are proposed, untested
   here; the NVX microVM kernel is not reusable unchanged.

4. Launch the standard machine, with no emulated guest IOMMU. Set `BDF` to
   the same GPU inspected and bound in step 2. Replace `OPENVMM` with the
   absolute executable path printed in step 3, even in the same shell:

   ```bash
   (
   set -euo pipefail
   BDF=0000:01:00.0
   [[ $BDF =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]]
   OPENVMM=/absolute/path/to/openvmm-vfio-target.XXXXXX/x86_64-unknown-linux-gnu/release/openvmm
   test -x "$OPENVMM"
   sudo "$OPENVMM" --machine standard --hypervisor kvm \
     --pcie-root-complex rc0,high_mmio=64G --pcie-root-port rc0:rp0 \
     --vfio host="$BDF",port=rp0 \
     --kernel /path/to/vmlinux --initrd /path/to/initrd \
     --cmdline 'console=ttyS0' --com1 console \
     --memory 4GB --processors 2
   )
   ```

   This follows [the upstream CLI, lines 99-120][vfio-launch], with the
   A10-sized high-MMIO window instead of the insufficient default.
   Inside the guest, compare `lspci -Dnn` vendor/device IDs with the host,
   then run `nvidia-smi`. Enumeration alone does not prove CUDA execution.

5. After OpenVMM exits and releases all VFIO handles, restore **every**
   member, even after a failed bind or boot. Use the state directory printed
   in step 2: replace the `STATE` placeholder below, even in the same
   Bash shell. Clear `driver_override` with a newline, not a zero-byte write,
   before restoring each saved driver. A GPU originally using `nvidia`
   returns explicitly to `nvidia`; an originally unbound member stays unbound.

   ```bash
   (
   set -euo pipefail
   STATE=/absolute/path/to/vfio-state.XXXXXX
   test -r "$STATE/drivers.tsv"
   mapfile -t rows < "$STATE/drivers.tsv"
   test "${#rows[@]}" -gt 0
   declare -A seen=()
   for row in "${rows[@]}"; do
       IFS=$'\t' read -r bdf driver <<< "$row"
       [[ $bdf =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ &&
          $driver =~ ^(-|[a-zA-Z0-9_][a-zA-Z0-9_.-]*)$ &&
          $row = "$bdf"$'\t'"$driver" ]] || {
           printf 'Invalid saved state entry: %q\n' "$row" >&2; exit 1;
       }
       [[ -z ${seen[$bdf]+yes} ]] || {
           printf 'Duplicate saved BDF: %s\n' "$bdf" >&2; exit 1;
       }
       seen[$bdf]=yes
   done
   failed=0
   for row in "${rows[@]}"; do
       IFS=$'\t' read -r bdf driver <<< "$row"
       dev="/sys/bus/pci/devices/$bdf"
       if test -L "$dev/driver"; then
           if ! printf '%s\n' "$bdf" | sudo tee "$dev/driver/unbind" >/dev/null; then
               printf 'Unbind failed: %s\n' "$bdf" >&2
               failed=1
           fi
       fi
       if ! printf '\n' | sudo tee "$dev/driver_override" >/dev/null; then
           printf 'Override clear failed: %s\n' "$bdf" >&2
           failed=1
           continue
       fi
       if test "$driver" != -; then
           if ! test -d "/sys/bus/pci/drivers/$driver" ||
              ! printf '%s\n' "$bdf" | sudo tee "/sys/bus/pci/drivers/$driver/bind" >/dev/null ||
              ! test "$(basename "$(readlink -e "$dev/driver")")" = "$driver"; then
               printf 'Driver restore failed: %s -> %s\n' "$bdf" "$driver" >&2
               failed=1
           fi
       elif test -L "$dev/driver"; then
           printf 'Expected unbound device: %s\n' "$bdf" >&2
           failed=1
       fi
       if ! lspci -Dnnk -s "$bdf"; then
           printf 'Inspection failed: %s\n' "$bdf" >&2
           failed=1
       fi
   done
   exit "$failed"
   )
   ```

   The original drivers normally remain loaded. Check their registered sysfs
   directories rather than passing driver names to `modprobe`: for example,
   the `nvidia-gpu` driver belongs to module `i2c_nvidia_gpu`. If a directory
   is missing, reload the actual module for that driver before retrying.
   Restoration attempts every validated member, reports individual failures
   and exits non-zero if any operation failed. Keep the state, resolve the
   reported errors and rerun step 5; a non-zero result is not a recovered host.
   Both preparation and restoration validate the complete saved-state snapshot
   before any privileged writes. Do not edit that state or run competing
   device-management operations during the experiment.

   Confirm `nvidia-smi` works on the host, then restore any services and
   persistence setting you changed. If rebinding fails, keep the state and
   kernel logs; do not claim the host recovered or resume GPU workloads.

VFIO guests cannot save/restore or hot-plug devices according to
[the upstream limitations, lines 328-332][vfio-limitations]. Sharing the
OpenVMM codebase therefore does not imply sharing NVX's executable, microVM
lifecycle or snapshot contract.

## Measured cloud prerequisite failure

A dedicated Lambda on-demand A10 VM, running Ubuntu kernel
`6.8.0-60-generic`, was probed on 2026-10-15. The selected commands below ran
as root **inside the cloud VM**, not inside an OpenVMM guest. Commands and
original captured output from the two probe passes are grouped here for
readability; output values are not synthesized.

The original KVM probe program:

```bash
systemd-detect-virt
python3 - <<'PY'
import os, fcntl, json
try:
    fd=os.open("/dev/kvm",os.O_RDWR)
    version=fcntl.ioctl(fd,0xae00,0)
    vm=fcntl.ioctl(fd,0xae01,0)
    print(json.dumps({"KVM_GET_API_VERSION":version,"KVM_CREATE_VM":"PASS"}))
    os.close(vm)
    os.close(fd)
except OSError as exc:
    print(json.dumps({"KVM_CREATE_VM":"FAIL","errno":exc.errno,"error":str(exc)}))
PY
find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d | wc -l
```

Captured stdout:

```text
kvm
{"KVM_GET_API_VERSION": 12, "KVM_CREATE_VM": "PASS"}
0
```

Kernel support and firmware/device checks from those same probe passes:

```bash
grep -E '^CONFIG_(IOMMU_SUPPORT|INTEL_IOMMU|AMD_IOMMU|VFIO|VFIO_PCI|VFIO_IOMMU_TYPE1)=' "/boot/config-$(uname -r)"
ls -l /sys/firmware/acpi/tables/DMAR /sys/firmware/acpi/tables/IVRS
ls -l /sys/bus/pci/devices/0000:06:00.0/iommu_group
```

Captured stdout and stderr (interleaved stderr is separated for readability):

```text
CONFIG_VFIO=m
CONFIG_VFIO_IOMMU_TYPE1=m
CONFIG_VFIO_PCI=m
CONFIG_IOMMU_SUPPORT=y
CONFIG_AMD_IOMMU=y
CONFIG_INTEL_IOMMU=y
ls: cannot access '/sys/firmware/acpi/tables/DMAR': No such file or directory
ls: cannot access '/sys/firmware/acpi/tables/IVRS': No such file or directory
ls: cannot access '/sys/bus/pci/devices/0000:06:00.0/iommu_group': No such file or directory
```

For the bind diagnostic, the idle GPU originally used `nvidia`; its compute
process query returned no rows. The probe loaded `vfio-pci` and
`vfio_iommu_type1`, stopped `nvidia-persistenced`, and disabled persistence:

```bash
modprobe vfio-pci
modprobe vfio_iommu_type1
grep . /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
nvidia-smi --query-compute-apps=pid,process_name --format=csv,noheader
systemctl stop nvidia-persistenced
nvidia-smi --persistence-mode=0
```

Captured stdout (the module loads, process query and service stop were silent):

```text
N
Persistence mode is already Disabled for GPU 00000000:06:00.0.
All done.
```

The original bind program's body was not retained in the raw log. This
equivalent Python harness makes its recorded sysfs writes reproducible,
including errors on close; the JSON below is the **original captured output**.
This was a deliberate negative diagnostic on a disposable VM. The normal
recipe above must stop when the IOMMU group is absent, rather than repeat
this unbind:

```bash
python3 - <<'PY'
import json
from pathlib import Path

dev = Path("/sys/bus/pci/devices/0000:06:00.0")
bdf = dev.name
assert dev.joinpath("vendor").read_text().strip() == "0x10de"
assert dev.joinpath("device").read_text().strip() == "0x2236"
assert dev.joinpath("driver").resolve().name == "nvidia"
for path, value in (
    (dev / "driver/unbind", bdf),
    (dev / "driver_override", "vfio-pci"),
    (Path("/sys/bus/pci/drivers/vfio-pci/bind"), bdf),
):
    result = {"write": str(path), "value": value}
    try:
        with path.open("w") as stream:
            stream.write(value)
        result["result"] = "SUCCESS"
    except OSError as exc:
        result.update(result="FAIL", errno=exc.errno, error=str(exc))
    print(json.dumps(result))
print(json.dumps({
    "driver_symlink_exists": dev.joinpath("driver").is_symlink(),
    "driver": str(dev.joinpath("driver").resolve())
              if dev.joinpath("driver").exists() else None,
    "iommu_group_exists": dev.joinpath("iommu_group").exists(),
}))
PY
```

```text
{"write": "/sys/bus/pci/devices/0000:06:00.0/driver/unbind", "value": "0000:06:00.0", "result": "SUCCESS"}
{"write": "/sys/bus/pci/devices/0000:06:00.0/driver_override", "value": "vfio-pci", "result": "SUCCESS"}
{"write": "/sys/bus/pci/drivers/vfio-pci/bind", "value": "0000:06:00.0", "result": "FAIL", "errno": 22, "error": "[Errno 22] Invalid argument"}
{"driver_symlink_exists": false, "driver": null, "iommu_group_exists": false}
```

Kernel corroboration, with the full captured bind-pass filtered output:

```text
$ dmesg | grep -Ei 'vfio|06:00.0|DMAR|IOMMU' | tail -30
[    2.768956] pci 0000:06:00.0: [10de:2236] type 00 class 0x030200 PCIe Endpoint
[    3.685338] pci 0000:06:00.0: BAR 0 [mem 0xfc000000-0xfcffffff]
[    3.685904] pci 0000:06:00.0: BAR 1 [mem 0x4000000000-0x47ffffffff 64bit pref]
[    3.686835] pci 0000:06:00.0: BAR 3 [mem 0x4800000000-0x4801ffffff 64bit pref]
[    3.688246] pci 0000:06:00.0: Max Payload Size set to 128 (was 256, max 256)
[    3.688993] pci 0000:06:00.0: Enabling HDA controller
[    3.689942] pci 0000:06:00.0: PME# supported from D0 D3hot
[    3.690951] pci 0000:06:00.0: 32.000 Gb/s available PCIe bandwidth, limited by 2.5 GT/s PCIe x16 link at 0000:00:02.5 (capable of 252.048 Gb/s with 16.0 GT/s PCIe x16 link)
[    3.763920] iommu: Default domain type: Translated
[    3.764523] iommu: DMA domain TLB invalidation policy: lazy mode
[    7.311947] [drm] Initialized nvidia-drm 0.0.0 20160202 for 0000:06:00.0 on minor 1
[   28.199952] VFIO - User Level meta-driver version: 0.3
[   52.122000] vfio-pci: probe of 0000:06:00.0 failed with error -22
[   52.122048] vfio-pci: probe of 0000:06:00.0 failed with error -22
```

This bind-pass filter is not a comprehensive AMD IOMMU check. The missing
DMAR/IVRS tables are established by the explicit firmware checks above,
not by the absence of messages from this filter.

The cloud VM's kernel had `CONFIG_INTEL_IOMMU=y` and `CONFIG_VFIO_PCI=m`,
but no ACPI DMAR/IVRS tables or GPU `iommu_group` link. With unsafe
no-IOMMU mode disabled, detaching the idle GPU from `nvidia` succeeded;
binding it to `vfio-pci` failed with `EINVAL` (errno 22), and the kernel
reported `vfio-pci: probe of 0000:06:00.0 failed with error -22`.

This is a negative result for that VM as provisioned, not for OpenVMM on
IOMMU-capable hardware. The disposable VM was terminated after this failure;
restoration was not tested there. No nested OpenVMM guest was built or booted,
so guest NVIDIA enumeration, driver initialization and CUDA remain unverified.

[machine-profiles]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args/microvm.rs#L21-L28
[standard-default]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args.rs#L153-L156
[microvm-rejection]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args/microvm.rs#L1300-L1319
[vfio-cli]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args.rs#L1415-L1433
[legacy-group]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/lib.rs#L1194-L1220
[vfio-implementation]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/pci/vfio_assigned_device/src/lib.rs#L4-L15
[vfio-resolver]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/pci/vfio_assigned_device/src/resolver.rs#L70-L105
[vfio-overview]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L1-L33
[nvx-kernel]: https://github.com/microsoft/nvx/blob/3486790ea38a1addda9a9145f27627392192ff0d/kernel/config-microvm#L913
[mmio-defaults]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_entry/src/cli_args.rs#L1271-L1278
[cold-boot-assignment]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/openvmm/openvmm_core/src/worker/dispatch.rs#L3510-L3516
[mmio-exhaustion]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/pci/pci_resource_assignment/src/lib.rs#L173-L186
[vfio-binding]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L63-L97
[build-guide]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/dev_guide/getting_started/build_openvmm.md#L14-L38
[vfio-launch]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L99-L120
[vfio-limitations]: https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/Guide/src/user_guide/openvmm/vfio.md#L328-L332
