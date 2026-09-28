# Always OpenVMM Host User Implementation Plan

## Design Contract

For Linux read-write shares, require:

```text
workload UID:GID == export owner UID:GID == OpenVMM effective UID:GID
```

OpenVMM always uses its process credentials. NVX never automatically changes the export's ownership. Root-launched OpenVMM cannot satisfy the non-root sandbox policy, so writable shares are rejected clearly. Windows and read-only shares retain their existing permission behavior.

## Implementation Plan

1. **Remove the OpenVMM dependency**

   - Restore the `openvmm` gitlink to the revision pinned by `dev`, currently `c9f659c36`.
   - Drop the caller-ownership pin commit `d7d02a7`.
   - Make no nested OpenVMM source changes.
   - Confirm that the final pull request has no `openvmm` gitlink diff.

2. **Remove ownership modes**

   - In `scripts/nvx.py`, remove both `--mount-owner` options and all related forwarding and validation.
   - In `scripts/nvx_tools/sandbox.py`, remove `MOUNT_OWNERS`, `default_mount_owner()`, and `SandboxMount.owner`.
   - Emit only OpenVMM's existing `--mount` and `--mount-deny` arguments.

3. **Enforce writable-share identity alignment**

   - During `SandboxLaunch.validated()`, canonicalize and stat the export root.
   - For Linux read-write mounts, compare its owner with `os.geteuid()`/`os.getegid()` and `workload_identity`.
   - Reject root, mismatches, and unsupported identities with an actionable error.
   - Revalidate when managed state is started, catching ownership or launcher-user changes after provisioning.

4. **Retain the sandbox mount implementation**

   - Keep the secure target validation and `microvm` mount in `guest/common/nvx-init-agent`.
   - Keep `ro|rw`, `nosuid,nodev`, reserved-path rejection, symbolic-link rejection, fail-closed behavior, and teardown.
   - Keep command-line budget accounting and `--mount-deny`.

5. **Simplify managed state**

   - Remove `owner` from newly serialized mounts in `scripts/nvx_tools/sandbox_lifecycle.py`.
   - Continue loading `dev`-era state without a mount.
   - Accept branch-era `"owner": "process"` as legacy input but ignore it.
   - Reject `"owner": "caller"` with an instruction to reprovision, avoiding a silent semantic change.

6. **Adapt integration coverage**

   - Remove caller mode and the synthetic root-owned `12345:12345` path from `scripts/nvx_tools/microvm_tests.py`.
   - On non-root Linux, use the OpenVMM process UID/GID as the workload identity and assert that guest-created files have that ownership.
   - Preserve live visibility, host edits, denied paths, `chmod`, read-only behavior, unsafe-target rejection, and clean teardown tests.
   - Test root execution as an expected pre-launch rejection.
   - Retain `mkfs.ext4 -d` and `e2fsprogs`; they are still needed to define the host-matching account inside scratch.

7. **Update unit tests**

   - Remove all `--mount-owner` parser, forwarding, state, and platform tests.
   - Add matching, export-owner mismatch, workload mismatch, root, Windows, and legacy-state cases.
   - Ensure generated OpenVMM commands contain no `--mount-owner`.

8. **Rewrite documentation**

   - Remove caller mode, capability, root-squashing, and supplementary-group material.
   - Document process-owned requests and Linux read-write identity alignment.
   - Keep the cold-boot-only sandbox restore limitation.
   - Update `doc/run.md`, `doc/usage.md`, and the affected design and validation documents.

9. **Validate**

   - Run the focused sandbox and microVM unit suites first.
   - Run Ruff, formatting, Linux and Windows Pyright, ShellCheck, and shfmt.
   - Run `python scripts\nvx.py verify` on Windows or `python3 scripts/nvx.py verify` on Linux.
   - Rebuild the Alpine initramfs and run `sandbox-filesystem` on Linux/KVM, Linux/MSHV, and Windows/WHP where available.
