"""Warm-pool manager: pre-captured OpenVMM snapshot pools for fast starts.

A pool is a directory of pre-captured snapshots (``entry-*``) plus a
``pool.json`` manifest recorded at fill time (CPU class, guest shape).
Serving a sandbox then skips capture entirely: ``acquire`` atomically
claims an entry (``os.rename``), the caller restores it with
``nvx.py run --restore-snapshot <entry>`` (snapshots are not consumed by
restore, so ``release`` returns the entry for reuse). ``prune --ttl-s``
deletes expired claims; it does not return their snapshots to the pool.

``bench`` is the fleet oracle: workers loop acquire -> restore -> release
for a fixed duration and report the sustained restore rate, latency
percentiles, and pool-leak count.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

from nvx_tools.benchmark import (
    RESTORE_MARKER,
    benchmark,
    capture_snapshot,
    cpu_frequency_classes,
    cpu_frequency_clusters,
    positive_float,
    positive_int,
    snapshot_restore_command,
    workload_boot_command,
)
from nvx_tools.benchmark import (
    SNAPSHOT_FILENAMES as SNAPSHOT_FILENAMES,
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


class PoolExhausted(ScriptError):
    """No available entry remains after racing claimers."""


def _require_positive(name: str, value: float) -> None:
    if not math.isfinite(value) or value <= 0:
        raise ScriptError(f"{name} must be finite and greater than zero")


def pool_entry_paths(pool_dir: Path) -> list[Path]:
    return sorted(
        p
        for p in pool_dir.iterdir()
        if not p.is_symlink() and p.is_dir() and p.name.startswith(ENTRY_PREFIX)
    )


def pool_claimed_paths(pool_dir: Path) -> list[Path]:
    return sorted(
        p
        for p in pool_dir.iterdir()
        if not p.is_symlink() and p.is_dir() and p.name.startswith(CLAIMED_PREFIX)
    )


def write_manifest(
    pool_dir: Path, fields: Mapping[str, object], *, exclusive: bool = False
) -> None:
    manifest = pool_dir / POOL_MANIFEST
    with manifest.open("x" if exclusive else "w", encoding="utf-8") as output:
        output.write(json.dumps(dict(fields), indent=2, sort_keys=True) + "\n")


def read_manifest(pool_dir: Path) -> dict[str, Any]:
    manifest = pool_dir / POOL_MANIFEST
    if not manifest.is_file():
        raise ScriptError(f"{pool_dir} is not a pool: missing {POOL_MANIFEST}")
    try:
        value = json.loads(manifest.read_text())
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise ScriptError(f"cannot read pool manifest: {error}") from error
    if not isinstance(value, dict):
        raise ScriptError("pool manifest must be a JSON object")
    fields = cast(dict[str, Any], value)
    for name in ("processors", "memory_mib"):
        if name in fields and (type(fields[name]) is not int or fields[name] <= 0):
            raise ScriptError(f"pool manifest has invalid {name}")
    if "processors" in fields and fields["processors"] not in (1, 2, 4, 8):
        raise ScriptError("pool manifest has unsupported processors")
    if "backend" in fields and fields["backend"] not in ("kvm", "mshv"):
        raise ScriptError("pool manifest has invalid backend")
    tag = fields.get("cpu_class_frequencies_khz", [])
    if not isinstance(tag, list) or any(
        type(frequency) is not int or frequency <= 0
        for frequency in cast(list[object], tag)
    ):
        raise ScriptError("pool manifest has invalid CPU class frequencies")
    return fields


def _process_affinity() -> set[int]:
    if sys.platform != "linux":
        raise ScriptError("warmpool requires Linux CPU affinity support")
    return os.sched_getaffinity(0)


def pool_class_frequencies() -> list[int]:
    """Tag single-class placement; unpinned multi-class captures have no tag."""
    classes = cpu_frequency_classes()
    affinity = _process_affinity()
    if sum(bool(cpus & affinity) for cpus in cpu_frequency_clusters(classes)) > 1:
        return []
    return sorted({frequency for frequency, cpus in classes.items() if cpus & affinity})


def validate_pool_class(pool_dir: Path) -> None:
    """Refuse to serve a pool captured on a CPU class this host does not have.

    This is a conservative placement policy, not OpenVMM's compatibility
    classifier. A pool tagged with frequencies this host does not expose, or
    whose CPUs are outside this process affinity, must not be served.
    Pools filled before the tag existed are served unchanged.
    """
    frequencies = cast(
        list[int], read_manifest(pool_dir).get("cpu_class_frequencies_khz") or []
    )
    tag = [int(frequency) for frequency in frequencies]
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
    if (
        len(
            cpu_frequency_clusters({frequency: classes[frequency] for frequency in tag})
        )
        > 1
    ):
        raise ScriptError(f"pool CPU class tag spans multiple classes: {tag}")
    if not tagged_cpus & _process_affinity():
        raise ScriptError("pool CPU class cpus are outside this process affinity")


def acquire_entries(pool_dir: Path, count: int) -> list[Path]:
    """Claim exactly ``count`` entries, returning partial claims on failure."""
    _require_positive("count", count)
    claimed: list[Path] = []
    try:
        for _ in range(count):
            for entry in pool_entry_paths(pool_dir):
                claimed_path = (
                    pool_dir
                    / f"{CLAIMED_PREFIX}{time.time_ns()}-{uuid.uuid4().hex[:8]}"
                )
                try:
                    os.rename(entry, claimed_path)
                except FileNotFoundError:
                    continue  # raced with another claimer; try the next entry
                claimed.append(claimed_path)
                break
            else:
                raise PoolExhausted(
                    f"pool exhausted: requested {count}, acquired {len(claimed)}, "
                    f"{len(pool_entry_paths(pool_dir))} entries remain"
                )
    except BaseException as error:
        rollback_errors: list[str] = []
        for path in claimed:
            try:
                release_entry(pool_dir, path)
            except Exception as rollback_error:
                rollback_errors.append(f"{path.name}: {rollback_error}")
        if rollback_errors:
            raise ScriptError(
                "failed to return partial claims: " + "; ".join(rollback_errors)
            ) from error
        raise
    return claimed


def release_entry(pool_dir: Path, claimed: Path) -> Path:
    if (
        claimed.parent.resolve() != pool_dir.resolve()
        or not claimed.name.startswith(CLAIMED_PREFIX)
        or claimed.is_symlink()
        or not claimed.is_dir()
    ):
        raise ScriptError(
            "release requires a claimed-* directory directly inside the pool"
        )
    entry = pool_dir / f"{ENTRY_PREFIX}{uuid.uuid4().hex[:8]}"
    os.rename(claimed, entry)
    return entry


def prune_claims(pool_dir: Path, ttl_s: float, *, now: float | None = None) -> int:
    """Delete claims older than the TTL; returns how many were removed."""
    _require_positive("ttl-s", ttl_s)
    now = time.time() if now is None else now
    removed = 0
    for claimed in pool_claimed_paths(pool_dir):
        try:
            claimed_at_ns = int(
                claimed.name.removeprefix(CLAIMED_PREFIX).split("-", 1)[0]
            )
        except ValueError:
            continue  # Unknown claim formats have no reliable expiration time.
        age = now - claimed_at_ns / 1_000_000_000
        if age >= ttl_s:
            try:
                shutil.rmtree(claimed)
            except FileNotFoundError:
                continue  # Released or pruned concurrently.
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
    for name in ("size", "memory_mib", "timeout"):
        _require_positive(name, getattr(args, name))
    kernel, initrd, executable = _require_artifacts(args.nvx_dir, args.openvmm_dir)
    args.pool_dir.mkdir(parents=True, exist_ok=True)
    if any(args.pool_dir.iterdir()):
        raise ScriptError("fill requires an empty pool directory; use a new --pool-dir")
    manifest: dict[str, object] = {
        "version": 1,
        "cpu_affinity": sorted(_process_affinity()),
        "cpu_class_frequencies_khz": pool_class_frequencies(),
        "memory_mib": args.memory_mib,
        "processors": args.processors,
        "backend": args.backend,
        "entries": 0,
    }
    try:
        write_manifest(args.pool_dir, manifest, exclusive=True)
    except FileExistsError as error:
        raise ScriptError(
            "pool is already being filled; use a new --pool-dir"
        ) from error
    boot = workload_boot_command(
        executable,
        args.backend,
        kernel,
        initrd,
        args.memory_mib,
        "quiet loglevel=0",
        processors=args.processors,
    )
    try:
        for index in range(args.size):
            entry = args.pool_dir / f"{ENTRY_PREFIX}{uuid.uuid4().hex[:8]}"
            capturing = args.pool_dir / f"capturing-{uuid.uuid4().hex}"
            print(f"capture {index + 1}/{args.size} -> {entry.name}", flush=True)
            try:
                capture_snapshot(
                    [*boot, "--snapshot-destination", str(capturing)],
                    capturing,
                    timeout=args.timeout,
                    processors=args.processors,
                )
                capturing.rename(entry)
            finally:
                if capturing.is_dir():
                    shutil.rmtree(capturing)
    finally:
        manifest["entries"] = len(pool_entry_paths(args.pool_dir))
        write_manifest(args.pool_dir, manifest)
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
    for name in ("workers", "duration_s", "timeout"):
        _require_positive(name, getattr(args, name))
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

    def worker(_index: int) -> None:
        nonlocal failures, exhaust_waits
        deadline = time.monotonic() + args.duration_s
        while time.monotonic() < deadline:
            try:
                claimed = acquire_entries(args.pool_dir, 1)[0]
            except PoolExhausted:
                # every entry is claimed by another worker; retry shortly
                with lock:
                    exhaust_waits += 1
                time.sleep(0.002)
                continue
            except Exception as error:
                with lock:
                    failures += 1
                print(f"acquire failed: {error!r}", file=sys.stderr, flush=True)
                return
            release_failed = False
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
                with lock:
                    failures += 1
                print(f"restore failed: {error!r}", file=sys.stderr, flush=True)
            finally:
                try:
                    release_entry(args.pool_dir, claimed)
                except Exception as error:
                    with lock:
                        failures += 1
                    print(f"release failed: {error!r}", file=sys.stderr, flush=True)
                    release_failed = True
            if release_failed:
                return

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(worker, range(args.workers)))
    elapsed = max(time.monotonic() - started, 1e-9)

    samples_ms.sort()
    p50 = samples_ms[len(samples_ms) // 2] if samples_ms else float("nan")
    p95 = samples_ms[int(0.95 * (len(samples_ms) - 1))] if samples_ms else float("nan")
    print(
        f"restores={len(samples_ms)} failures={failures} exhaust_waits={exhaust_waits} "
        f"rate={len(samples_ms) / elapsed:.1f}/s over {elapsed:.1f}s "
        f"p50={p50:.3f} ms p95={p95:.3f} ms "
        f"max={samples_ms[-1] if samples_ms else float('nan'):.3f} ms"
    )
    claimed_after = pool_claimed_paths(args.pool_dir)
    pool_after = len(pool_entry_paths(args.pool_dir))
    print(
        f"pool: {pool_before} -> {pool_after} entries, {len(claimed_after)} leaked claims"
    )
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
    fill.add_argument("--size", type=positive_int, default=4)
    fill.add_argument("--memory-mib", type=positive_int, default=128)
    fill.add_argument("--processors", type=int, choices=(1, 2, 4, 8), default=1)
    fill.add_argument("--backend", choices=("kvm", "mshv"), default="kvm")
    fill.add_argument("--timeout", type=positive_float, default=120.0)
    fill.set_defaults(handler=command_fill)

    status = subparsers.add_parser("status", help="show pool manifest and counts")
    shared(status)
    status.set_defaults(handler=command_status)

    acquire = subparsers.add_parser("acquire", help="atomically claim pool entries")
    shared(acquire)
    acquire.add_argument("--count", type=positive_int, default=1)
    acquire.set_defaults(handler=command_acquire)

    release = subparsers.add_parser(
        "release", help="return a claimed entry to the pool"
    )
    shared(release)
    release.add_argument("--entry", type=Path, required=True)
    release.set_defaults(handler=command_release)

    prune = subparsers.add_parser("prune", help="delete claims older than the TTL")
    shared(prune)
    prune.add_argument("--ttl-s", type=positive_float, required=True)
    prune.set_defaults(handler=command_prune)

    bench = subparsers.add_parser(
        "bench", help="sustained acquire/restore/release oracle"
    )
    shared(bench)
    bench.add_argument("--duration-s", type=positive_float, default=60.0)
    bench.add_argument("--workers", type=positive_int, default=4)
    bench.add_argument("--timeout", type=positive_float, default=60.0)
    bench.set_defaults(handler=command_bench)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warmpool")
    configure_parser(parser, BuildConstants.REPO_ROOT)
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
