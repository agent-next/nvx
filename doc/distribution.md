# Package and source delivery

`package` stages a release directory, `dist/<version>` by default, from the
built OpenVMM binary and guest artifacts. [Build](build.md) lists the
artifacts and provenance it requires and the binary release layout. Every
package is either binary-only or source-inclusive, and you must choose one.

## Binary-only packages

Stage a binary release and SHA-256 manifest:

```bash
python3 scripts/nvx.py package --binary-only
```

Binary-only mode requires an explicit acknowledgement because the matching
Linux, Alpine, Ubuntu, and Azure Linux source must be published separately.

## Source-inclusive packages

First materialize the release sources:

```bash
python3 scripts/nvx.py collect-sources
```

`collect-sources` reads the package manifests of the built guest artifacts, so
run `build-guest --guest all` first. It requires the kernel, Alpine, and Ubuntu
artifacts, but not the Azure Linux ones. It also needs Docker with the Linux
engine, which fetches and verifies the Alpine upstream sources in an Alpine
container and builds the Linux source archive, and `gpgv`, which authenticates
the Ubuntu source indexes.

This produces a patched Linux corresponding-source archive under
`build/sources/linux`, exact Alpine recipes/upstream sources under
`build/sources/alpine`, and exact Ubuntu `.dsc` plus referenced source members
under `build/sources/ubuntu`. Then stage the binary release with four separate
source artifacts:

```bash
python3 scripts/nvx.py package --include-source
```

The release contains:

```text
source/nvx-project-source-0.1.0.tar.gz
source/nvx-linux-source-6.18.38.tar.gz
source/nvx-alpine-source-0.1.0.tar.gz
source/nvx-ubuntu-source-0.1.0.tar.gz
```

`collect-sources` does not collect Azure Linux corresponding source, so
`--include-source` omits `initramfs-azurelinux.cpio.gz` and its package
manifest from the staged release and from the packaged `SOURCE-MANIFEST.json`.
Distribute the Azure Linux guest only from a binary-only package while its
corresponding source is published separately.

Linux is GPL-2.0-only, so a distributor of `vmlinux` must make its complete
corresponding source available. Alpine packages retain their individual
licenses. The collector uses the exact aports commit embedded in every
installed APK and runs `abuild fetch` plus `abuild verify`. Its manifest lists
the executable recipe files, and the Alpine source archive takes its file modes
from that list rather than from the collecting host, which may not store them.

Ubuntu artifacts use Ubuntu userland with the NVX kernel. The collector
deduplicates exact source package name/version pairs from both Ubuntu
manifests, downloads the matching `.dsc` and source members from Canonical's
archive, verifies each source index through its signed `InRelease` file and the
pinned Ubuntu archive keyring, and then verifies the indexed SHA-256 metadata
before packaging. Source collection and release staging also require each
Ubuntu artifact to match the artifact name and SHA-256 embedded in its companion
manifest. Exact versions that have left the live suite indexes are located
through Canonical's Launchpad publishing history and resolved from a signed
historical `snapshot.ubuntu.com` index. The signed release metadata, keyring,
and raw Launchpad responses are retained with their URLs and SHA-256 digests.
Newer source versions are never substituted.

OpenVMM is MIT licensed: retain its notice, but its source does not have to be
published merely because it is aggregated with Linux. See
`THIRD_PARTY_NOTICES.md`.

## Release archives

Turn a staged release directory into one deterministic archive:

```bash
python3 scripts/nvx.py archive-release \
  --source dist/0.1.0 \
  --destination dist/nvx-0.1.0.tar.gz
```

`archive-release` checks the staged files against their `SHA256SUMS` before
it writes a `.tar.gz` or `.zip` archive outside the staged directory; see
[`archive-release`](usage.md#archive-release).

CI follows the binary-only path. On `dev` pushes, the `linux-kvm`,
`linux-mshv`, and `windows-whp` platform jobs each stage
`dist/nvx-<version>-<platform>` with `--binary-only`, then archive it as
`.tar.gz` on Linux and `.zip` on Windows through the
[`package-release`](../.github/actions/package-release/action.yml) action.
[Continuous integration](ci.md) describes the jobs that gate and publish the
resulting development release.
