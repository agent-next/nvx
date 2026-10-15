# OpenVMM build patches

The submodule remains at its public source URL and pinned revision. The sorted
`*.patch` series in this directory is applied by `build-openvmm` before Cargo
runs, then reversed on success or failure. Builds refuse a dirty or differently
pinned submodule. Do not build the bare submodule directly when producing NVX
artifacts, because that bypasses the patches.

`0001-control-session-restore.patch` starts restore with a fresh guest parser.
The restored guest starts a fresh control session, so it cannot finish a
snapshotted partial input record. The patch retains snapshot validation and
partial output handling, and includes unit and broker integration regressions.

OpenVMM provenance records the base revision, ordered patch paths and SHA-256
digests, and executable hash. Release validation checks all of them. Binary
cache keys include the patch series, so an old unpatched binary cannot satisfy
the patched build's cache key.

Use `python3 scripts/nvx.py build-openvmm --backend kvm` on Linux.
`CARGO_TARGET_DIR` is supported for an external Cargo output directory.
