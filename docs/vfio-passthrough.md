# Whole-device GPU passthrough: feasibility boundary

The pinned OpenVMM revision
`7f225e2cd635bbd1e1839e587e659996433396c8` implements experimental Linux
VFIO assignment. It is **not** available in the NVX microVM profile.

## Source-verified path

Paths below are relative to `openvmm/` at that revision.

| Component | Source |
| --- | --- |
| Machine profiles `standard` and `microvm` | `openvmm/openvmm_entry/src/cli_args/microvm.rs:21-28` |
| Standard is the default | `openvmm/openvmm_entry/src/cli_args.rs:153-156` |
| MicroVM rejects PCIe and VFIO | `openvmm/openvmm_entry/src/cli_args/microvm.rs:1300-1319` |
| Linux `--vfio host=<BDF>,port=<name>` | `openvmm/openvmm_entry/src/cli_args.rs:1415-1433` |
| Opens the IOMMU group and creates a PCIe resource | `openvmm/openvmm_entry/src/lib.rs:1194-1220` |
| Linux-only assignment implementation | `vm/devices/pci/vfio_assigned_device/src/lib.rs:4-15` |
| Legacy VFIO resolver, DMA and device construction | `vm/devices/pci/vfio_assigned_device/src/resolver.rs:70-105` |
| Upstream instructions and experimental status | `Guide/src/user_guide/openvmm/vfio.md:1-33` |

The NVX guest kernel is also unsuitable: `kernel/config-microvm:913`
disables `CONFIG_PCI`.

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

2. On a dedicated test host only, confirm the GPU is idle and all functions
   in its IOMMU group can be released. Replace the example BDF, then:

   ```sh
   BDF=0000:01:00.0
   sudo modprobe vfio-pci
   sudo modprobe vfio_iommu_type1
   printf '%s' "$BDF" | sudo tee "/sys/bus/pci/devices/$BDF/driver/unbind"
   printf vfio-pci | sudo tee "/sys/bus/pci/devices/$BDF/driver_override"
   printf '%s' "$BDF" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
   readlink "/sys/bus/pci/devices/$BDF/driver"
   ls -l /dev/vfio/
   ```

   Follow `Guide/src/user_guide/openvmm/vfio.md:63-97`. No-IOMMU mode
   is unsupported. Do not weaken interrupt remapping as an automatic fix.

3. Build the `openvmm` binary using its documented Linux build prerequisites.
   Use a separate general-purpose x86-64 guest kernel/initramfs with ACPI,
   PCI/PCIe, PCI MSI, PCI MMCONFIG, serial console and initramfs support.
   For `nvidia-smi`, include matching NVIDIA kernel modules, firmware and
   userspace tools. These guest-image requirements are proposed, untested
   here; the NVX microVM kernel is not reusable unchanged.

4. Launch the standard machine, with no emulated guest IOMMU:

   ```sh
   sudo openvmm --machine standard --hypervisor kvm \
     --pcie-root-complex rc0 --pcie-root-port rc0:rp0 \
     --vfio host="$BDF",port=rp0 \
     --kernel /path/to/vmlinux --initrd /path/to/initrd \
     --cmdline 'console=ttyS0' --com1 console \
     --memory 4GB --processors 2
   ```

   This follows `Guide/src/user_guide/openvmm/vfio.md:99-120`.
   Inside the guest, compare `lspci -Dnn` vendor/device IDs with the host,
   then run `nvidia-smi`. Enumeration alone does not prove CUDA execution.

VFIO guests cannot save/restore or hot-plug devices according to
`Guide/src/user_guide/openvmm/vfio.md:328-332`. Sharing the OpenVMM executable
therefore does not imply sharing NVX's microVM lifecycle or snapshot contract.
