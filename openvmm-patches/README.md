# OpenVMM build patches

The submodule remains at its public source URL and pinned revision. The sorted
`*.patch` series in this directory is applied by `build-openvmm`, benchmark
builds, `test-openvmm-unit` and `test-openvmm` before Cargo runs, then reversed
on success or failure. A cleanup failure is reported without masking the original
build/test error. Builds refuse a dirty or differently
pinned submodule. Do not build the bare submodule directly when producing NVX
artifacts, because that bypasses the patches.

Develop OpenVMM changes in a separate checkout at the pinned revision with the
existing series applied. Run its package-scoped checks there, then export the
additional diff as the next numbered patch. Run the NVX build/test commands
against the clean pinned submodule to verify the complete series. After an
interrupted build, save any local work before removing leftover patches with
`git -C openvmm checkout .`; this command discards tracked local edits.

The pinned OpenVMM `.gitattributes` uses `* text=auto eol=lf`, including Rust
sources, so Git checks them out as LF even with `core.autocrlf=true` on Windows.
Patch application deliberately keeps strict whitespace matching. Manually
converted CRLF source files are not supported: save local work and re-check out
the clean pin rather than applying patches with relaxed matching.

`0001-control-session-restore.patch` starts restore with a fresh guest parser.
The restored guest starts a fresh control session, so it cannot finish a
snapshotted partial input record. The saved parser is validated before being
discarded: `ControlSessionBroker::restore` calls `validate_restore`, which calls
`validate_snapshot`, including `Parser::validate_snapshot(&snapshot.guest_parser)`.
See the pinned
[`control_session_broker.rs:774-815`](https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/virtio/virtio_console/src/control_session_broker.rs#L774-L815)
and
[`control_session_protocol.rs:292-329`](https://github.com/nanvix/openvmm/blob/7f225e2cd635bbd1e1839e587e659996433396c8/vm/devices/virtio/virtio_console/src/control_session_protocol.rs#L292-L329).
The patch retains partial output handling and includes unit and broker
integration regressions.

OpenVMM provenance records the base revision, ordered patch paths and SHA-256
digests, and executable hash. Release validation checks all of them. Binary
cache keys include the patch series, so an old unpatched binary cannot satisfy
the patched build's cache key.

Use `python3 scripts/nvx.py build-openvmm --backend kvm` on Linux.
`CARGO_TARGET_DIR` is supported for an external Cargo output directory.
