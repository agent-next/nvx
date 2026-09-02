# Continuous integration

The GitHub Actions workflow has two microVM test layers on self-hosted KVM,
MSHV, and WHP runners. `openvmm-tests` builds its Xen PVH probe entirely from
the OpenVMM checkout and exercises OpenVMM lifecycle, TTRPC, and snapshot
contracts without restoring NVX guest artifacts. `nvx-microvm-tests` consumes
the NVX Linux kernel and Alpine initramfs and exercises Linux, SMP, virtio,
sandbox, and snapshot behavior through the public OpenVMM CLI. Failure logs
from the NVX layer are uploaded per backend.

Benchmarks run only after both test layers pass (or are intentionally skipped)
on bare-metal KVM, MSHV, and WHP hosts and on nested-virtualization MSHV and WHP
virtual machines. Each host type has a distinct result cache and rolling
performance history. The workflow uses the read-only OpenVMM deploy key stored
in the `OPENVMM_DEPLOY_KEY` Actions secret to fetch the private submodule at its
pinned commit. Shared guest binaries, benchmark results, and development
release packages move between jobs through runner-compatible Actions caches.
Pull requests gate regressions against recent matching-host history, and
successful pushes to `dev` append their p50 values under `data/`. The runners
require the [platform prerequisites](setup.md#prerequisites).

CI caches only the pinned kernel and legacy initramfs. It does not restore or
save a broker initramfs cache, and the benchmark action does not claim to run
the broker profile. Development release jobs build and publish only explicit
`-legacy` packages.

Broker publication fails closed. A future privileged smoke/E2E job must build
the agent image afresh, boot that exact bundle, and supply an independently
authenticated live-gate proof accepted by `verify-broker-live-gate`. The
publish action rejects an unproved broker archive. Pull-request runs are
cancel-in-progress and do not publish releases.
