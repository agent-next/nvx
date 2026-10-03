"""Warm-pool manager: pre-captured OpenVMM snapshot pools for fast starts.

A pool is a directory of pre-captured snapshots (``entry-*``) plus a
``pool.json`` manifest recorded at fill time (CPU class, guest shape).
Serving a sandbox then skips capture entirely: ``acquire`` atomically
claims an entry (``os.rename``), the caller restores it with
``nvx.py run --restore-snapshot <entry>`` (snapshots are not consumed by
restore, so ``release`` returns the entry for reuse), and crashed
claimers are recovered by ``prune --ttl-s``.

``bench`` is the fleet oracle: workers loop acquire -> restore -> release
for a fixed duration and report the sustained restore rate, latency
percentiles, and pool-leak count.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Sequence

from nvx_tools.benchmark import (
    RESTORE_MARKER,
    SNAPSHOT_FILENAMES,
    benchmark,
    capture_snapshot,
    cpu_frequency_classes,
    snapshot_restore_command,
    workload_boot_command,
)
from nvx_tools.build_constants import (
    AlpineBuildConstants,
    BuildConstants,
    KernelBuildConstants,
)
from nvx_tools.common import ScriptError

POOL_MANIFEST = "pool.json"
ENTRY_PREFIX = "entry-"
CLAIMED_PREFIX = "claimed-"


def pool_entry_paths(pool_dir: Path) -> list[Path]:
    return sorted(p for p in pool_dir.iterdir() if p.is_dir() and p.name.startswith(ENTRY_PREFIX))


def pool_claimed_paths(pool_dir: Path) -> list[Path]:
    return sorted(p for p in pool_dir.iterdir() if p.is_dir() and p.name.startswith(CLAIMED_PREFIX))


def write_manifest(pool_dir: Path, fields: dict[str, object]) -> None:
    manifest = pool_dir / POOL_MANIFEST
    manifest.write_text(json.dumps(fields, indent=2, sort_keys=True) + "\n")


def read_manifest(pool_dir: Path) -> dict[str, object]:
    manifest = pool_dir / POOL_MANIFEST
    if not manifest.is_file():
        raise ScriptError(f"{pool_dir} is not a pool: missing {POOL_MANIFEST}")
    return json.loads(manifest.read_text())


def pool_class_frequencies() -> list[int]:
    """Max-frequency (kHz) signature of the CPU class this process runs on."""
    classes = cpu_frequency_classes()
    affinity = os.sched_getaffinity(0)
    return sorted({frequency for frequency, cpus in classes.items() if cpus & affinity})


def validate_pool_class(pool_dir: Path) -> None:
    """Refuse to serve a pool captured on a CPU class this host does not have.

    Snapshot restores are portable only within one CPU frequency class (the
    destination CPU contract check); a pool tagged with frequencies this host
    does not expose, or whose CPUs are outside this process affinity, must not
    be served. Pools filled before the tag existed are served unchanged.
    """
    tag = [int(frequency) for frequency in read_manifest(pool_dir).get("cpu_class_frequencies_khz") or []]
    if not tag:
        return
    classes = cpu_frequency_classes()
    tagged_cpus: set[int] = set()
    for frequency in tag:
        if frequency not in classes:
            raise ScriptError(
                f"pool CPU class {tag} kHz does not exist on this host "
                f"(classes: {sorted(classes)})"
            )
        tagged_cpus |= classes[frequency]
    ordered = sorted(tag)
    if ordered[-1] > ordered[0] * 1.10:
        # same 10% merge as apply_hybrid_cpu_filter: turbo-favored cores of
        # one physical type stay one class, two classes must not mix
        raise ScriptError(f"pool CPU class tag spans multiple classes: {tag}")
    if not tagged_cpus & os.sched_getaffinity(0):
        raise ScriptError("pool CPU class cpus are outside this process affinity")


def acquire_entries(pool_dir: Path, count: int) -> list[Path]:
    """Atomically claim up to ``count`` entries by renaming them aside."""
    claimed: list[Path] = []
    for _ in range(count):
        for entry in pool_entry_paths(pool_dir):
            claimed_path = pool_dir / f"{CLAIMED_PREFIX}{time.time_ns()}-{uuid.uuid4().hex[:8]}"
            try:
                os.rename(entry, claimed_path)
            except OSError:
                continue  # raced with another claimer; try the next entry
            claimed.append(claimed_path)
            break
        else:
            raise ScriptError(
                f"pool exhausted: requested {count}, acquired {len(claimed)}, "
                f"{len(pool_entry_paths(pool_dir))} entries remain"
            )
    return claimed


def release_entry(pool_dir: Path, claimed: Path) -> Path:
    entry = pool_dir / f"{ENTRY_PREFIX}{uuid.uuid4().hex[:8]}"
    os.rename(claimed, entry)
    return entry


def prune_claims(pool_dir: Path, ttl_s: float, *, now: float | None = None) -> int:
    """Delete claims older than the TTL; returns how many were removed."""
    now = time.time() if now is None else now
    removed = 0
    for claimed in pool_claimed_paths(pool_dir):
        age = now - claimed.stat().st_mtime
        if age >= ttl_s:
            shutil.rmtree(claimed)
            removed += 1
    return removed


def _require_artifacts(nvx_dir: Path, openvmm_dir: Path) -> tuple[Path, Path, Path]:
    build = nvx_dir.resolve() / "build"
    kernel = build / KernelBuildConstants.BINARY_NAME
    initrd = build / AlpineBuildConstants.INITRAMFS_NAME
    executable = openvmm_dir.resolve() / "target" / "release" / "openvmm"
    for path, label in (
        (kernel, "NVX Linux direct kernel"),
        (initrd, "NVX initramfs"),
        (executable, "Linux OpenVMM release binary"),
    ):
        if not path.is_file():
            raise ScriptError(f"missing {label}: {path}")
    return kernel, initrd, executable


def command_fill(args: argparse.Namespace) -> int:
    kernel, initrd, executable = _require_artifacts(args.nvx_dir, args.openvmm_dir)
    args.pool_dir.mkdir(parents=True, exist_ok=True)
    boot = workload_boot_command(
        executable,
        args.backend,
        kernel,
        initrd,
        args.memory_mib,
        "quiet loglevel=0",
        processors=args.processors,
    )
    for index in range(args.size):
        entry = args.pool_dir / f"{ENTRY_PREFIX}{uuid.uuid4().hex[:8]}"
        print(f"capture {index + 1}/{args.size} -> {entry.name}", flush=True)
        capture_snapshot(
            [*boot, "--snapshot-destination", str(entry)],
            entry,
            backend=args.backend,
            timeout=args.timeout,
            processors=args.processors,
        )
    write_manifest(
        args.pool_dir,
        {
            "version": 1,
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "cpu_class_frequencies_khz": pool_class_frequencies(),
            "memory_mib": args.memory_mib,
            "processors": args.processors,
            "backend": args.backend,
            "entries": len(pool_entry_paths(args.pool_dir)),
        },
    )
    print(f"pool filled: {len(pool_entry_paths(args.pool_dir))} entries", flush=True)
    return 0


def command_status(args: argparse.Namespace) -> int:
    manifest = read_manifest(args.pool_dir)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"entries: {len(pool_entry_paths(args.pool_dir))}")
    print(f"claimed: {len(pool_claimed_paths(args.pool_dir))}")
    return 0


def command_acquire(args: argparse.Namespace) -> int:
    validate_pool_class(args.pool_dir)
    for claimed in acquire_entries(args.pool_dir, args.count):
        print(claimed)
    return 0


def command_release(args: argparse.Namespace) -> int:
    read_manifest(args.pool_dir)
    released = release_entry(args.pool_dir, args.entry)
    print(released)
    return 0


def command_prune(args: argparse.Namespace) -> int:
    read_manifest(args.pool_dir)
    removed = prune_claims(args.pool_dir, args.ttl_s)
    print(f"pruned {removed} stale claim(s)")
    return 0


def command_bench(args: argparse.Namespace) -> int:
    validate_pool_class(args.pool_dir)
    manifest = read_manifest(args.pool_dir)
    _, _, executable = _require_artifacts(args.nvx_dir, args.openvmm_dir)
    pool_before = len(pool_entry_paths(args.pool_dir))
    if pool_before == 0:
        raise ScriptError("pool is empty; run `warmpool fill` first")

    lock = threading.Lock()
    samples_ms: list[float] = []
    failures = 0
    exhaust_waits = 0

    def worker() -> None:
        nonlocal failures, exhaust_waits
        deadline = time.monotonic() + args.duration_s
        while time.monotonic() < deadline:
            try:
                claimed = acquire_entries(args.pool_dir, 1)[0]
            except ScriptError:
                # every entry is claimed by another worker; retry shortly
                with lock:
                    exhaust_waits += 1
                time.sleep(0.002)
                continue
            try:
                command = snapshot_restore_command(
                    executable,
                    str(manifest.get("backend", "kvm")),
                    claimed,
                    processors=int(manifest.get("processors", 1)),
                )
                result = benchmark(
                    command,
                    warmups=0,
                    runs=1,
                    timeout=args.timeout,
                    marker=RESTORE_MARKER,
                    marker_must_be_line=True,
                    # mirror the shell-snapshot-restore suite: the restored
                    # workload prequeues its own exit, so the harness must not
                    # write guest-exit.sh into the console (input race -> abort)
                    guest_exit_prequeued=True,
                )
                with lock:
                    samples_ms.append(float(result["p50_ms"]))
            except Exception as error:
                failures += 1
                print(f"restore failed: {error!r}", file=sys.stderr, flush=True)
            finally:
                release_entry(args.pool_dir, claimed)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(lambda _: worker(), range(args.workers)))
    elapsed = time.monotonic() - started

    samples_ms.sort()
    p95 = samples_ms[int(0.95 * (len(samples_ms) - 1))] if samples_ms else float("nan")
    print(
        f"restores={len(samples_ms)} failures={failures} exhaust_waits={exhaust_waits} "
        f"rate={len(samples_ms) / elapsed:.1f}/s over {elapsed:.1f}s "
        f"p50={samples_ms[len(samples_ms) // 2]:.3f} ms p95={p95:.3f} ms "
        f"max={samples_ms[-1] if samples_ms else float('nan'):.3f} ms"
    )
    claimed_after = pool_claimed_paths(args.pool_dir)
    pool_after = len(pool_entry_paths(args.pool_dir))
    print(f"pool: {pool_before} -> {pool_after} entries, {len(claimed_after)} leaked claims")
    if claimed_after or pool_after != pool_before:
        raise ScriptError("warm-pool leak detected after bench churn")
    return 0 if failures == 0 else 1


def configure_parser(parser: argparse.ArgumentParser, repo_root: Path) -> None:
    subparsers = parser.add_subparsers(dest="warmpool_operation", required=True)

    def shared(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--pool-dir", type=Path, required=True)
        sub.add_argument("--openvmm-dir", type=Path, default=repo_root / "openvmm")
        sub.add_argument("--nvx-dir", type=Path, default=repo_root)

    fill = subparsers.add_parser("fill", help="capture snapshots into the pool")
    shared(fill)
    fill.add_argument("--size", type=int, default=4)
    fill.add_argument("--memory-mib", type=int, default=128)
    fill.add_argument("--processors", type=int, choices=(1, 2, 4, 8), default=1)
    fill.add_argument("--backend", choices=("kvm", "mshv"), default="kvm")
    fill.add_argument("--timeout", type=float, default=120.0)
    fill.set_defaults(handler=command_fill)

    status = subparsers.add_parser("status", help="show pool manifest and counts")
    shared(status)
    status.set_defaults(handler=command_status)

    acquire = subparsers.add_parser("acquire", help="atomically claim pool entries")
    shared(acquire)
    acquire.add_argument("--count", type=int, default=1)
    acquire.set_defaults(handler=command_acquire)

    release = subparsers.add_parser("release", help="return a claimed entry to the pool")
    shared(release)
    release.add_argument("--entry", type=Path, required=True)
    release.set_defaults(handler=command_release)

    prune = subparsers.add_parser("prune", help="delete claims older than the TTL")
    shared(prune)
    prune.add_argument("--ttl-s", type=float, required=True)
    prune.set_defaults(handler=command_prune)

    bench = subparsers.add_parser("bench", help="sustained acquire/restore/release oracle")
    shared(bench)
    bench.add_argument("--duration-s", type=float, default=60.0)
    bench.add_argument("--workers", type=int, default=4)
    bench.add_argument("--timeout", type=float, default=60.0)
    bench.set_defaults(handler=command_bench)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warmpool")
    configure_parser(parser, BuildConstants.REPO_ROOT)
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
