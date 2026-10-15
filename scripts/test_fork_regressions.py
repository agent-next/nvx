# pyright: reportPrivateUsage=false

import argparse
import contextlib
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))
import nvx  # noqa: E402
from nvx_tools import (  # noqa: E402
    benchmark,
    common,
    control_session,
    microvm_tests,
    release,
    sandbox_lifecycle,
    warmpool,
)


class PoolFixture(unittest.TestCase):
    def make_pool(self, count: int) -> Path:
        root = Path(tempfile.mkdtemp(prefix="nvx-pool-regression-"))
        self.addCleanup(shutil.rmtree, root)
        for index in range(count):
            (root / f"entry-{index}").mkdir()
        return root


class WarmpoolRegressionTests(PoolFixture):
    def test_non_linux_fill_does_not_create_pool_directory(self) -> None:
        pool = self.make_pool(0) / "new-pool"
        args = argparse.Namespace(
            pool_dir=pool,
            nvx_dir=pool.parent,
            openvmm_dir=pool.parent,
            size=1,
            memory_mib=128,
            timeout=1,
        )
        with (
            patch.object(warmpool.sys, "platform", "win32"),
            self.assertRaisesRegex(common.ScriptError, "Linux CPU affinity"),
        ):
            warmpool.command_fill(args)
        self.assertFalse(pool.exists())

    def test_new_claim_of_old_snapshot_survives_prune(self) -> None:
        pool = self.make_pool(1)
        os.utime(pool / "entry-0", (100, 100))
        with patch.object(warmpool.time, "time_ns", return_value=1_000_000_000_000):
            claimed = warmpool.acquire_entries(pool, 1)[0]
        self.assertEqual(warmpool.prune_claims(pool, 60, now=1001), 0)
        self.assertTrue(claimed.is_dir())
        self.assertEqual(warmpool.prune_claims(pool, 60, now=1060), 1)
        self.assertFalse(claimed.exists())

    def test_exhaustion_returns_partial_claims(self) -> None:
        pool = self.make_pool(2)
        with self.assertRaisesRegex(common.ScriptError, "pool exhausted"):
            warmpool.acquire_entries(pool, 3)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 2)
        self.assertEqual(warmpool.pool_claimed_paths(pool), [])

    def test_listing_failure_returns_partial_claims(self) -> None:
        pool = self.make_pool(2)
        entries = warmpool.pool_entry_paths(pool)
        with (
            patch.object(
                warmpool, "pool_entry_paths", side_effect=(entries, OSError("listing"))
            ),
            self.assertRaisesRegex(OSError, "listing"),
        ):
            warmpool.acquire_entries(pool, 2)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 2)
        self.assertEqual(warmpool.pool_claimed_paths(pool), [])

    def test_rename_permission_failure_is_not_pool_exhaustion(self) -> None:
        pool = self.make_pool(1)
        with (
            patch.object(warmpool.os, "rename", side_effect=PermissionError("rename")),
            self.assertRaisesRegex(PermissionError, "rename"),
        ):
            warmpool.acquire_entries(pool, 1)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 1)

    def test_release_rejects_paths_outside_pool_and_unclaimed_entries(self) -> None:
        pool = self.make_pool(1)
        outside = self.make_pool(0)
        outside_claim = outside / "claimed-1000-abcdef"
        outside_claim.mkdir()
        for path in (outside_claim, pool / "entry-0"):
            with self.subTest(path=path):
                with self.assertRaises(common.ScriptError):
                    warmpool.release_entry(pool, path)
                self.assertTrue(path.is_dir())

    @unittest.skipIf(os.name == "nt", "requires unprivileged symlink creation")
    def test_release_rejects_symlink_claim(self) -> None:
        pool = self.make_pool(0)
        outside = self.make_pool(0)
        claimed = pool / "claimed-1000-abcdef"
        claimed.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(common.ScriptError):
            warmpool.release_entry(pool, claimed)
        self.assertTrue(claimed.is_symlink())
        self.assertTrue(outside.is_dir())

    def test_unpinned_pool_has_no_single_class_placement_tag(self) -> None:
        with (
            patch.object(
                warmpool,
                "cpu_frequency_classes",
                return_value={6_000_000: {0, 1}, 4_200_000: {2, 3}},
            ),
            patch.object(warmpool, "_process_affinity", return_value={0, 1, 2, 3}),
        ):
            self.assertEqual(warmpool.pool_class_frequencies(), [])

    def test_bench_all_failed_restores_reports_failures_and_checks_leaks(self) -> None:
        for leaked in (False, True):
            with self.subTest(leaked=leaked):
                pool = self.make_pool(1)
                warmpool.write_manifest(pool, {"processors": 1, "backend": "kvm"})
                args = argparse.Namespace(
                    pool_dir=pool,
                    nvx_dir=pool,
                    openvmm_dir=pool,
                    duration_s=1,
                    workers=1,
                    timeout=1,
                )
                output = io.StringIO()
                with (
                    patch.object(warmpool, "validate_pool_class"),
                    patch.object(
                        warmpool, "_require_artifacts", return_value=(pool, pool, pool)
                    ),
                    patch.object(
                        warmpool.time, "monotonic", side_effect=[0, 0, 0, 2, 3]
                    ),
                    patch.object(
                        warmpool,
                        "benchmark",
                        side_effect=common.ScriptError("restore rejected"),
                    ),
                    patch.object(
                        warmpool,
                        "pool_claimed_paths",
                        return_value=[pool / "claimed-leak"] if leaked else [],
                    ) as check_leaks,
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    if leaked:
                        with self.assertRaisesRegex(
                            common.ScriptError, "leak detected"
                        ):
                            warmpool.command_bench(args)
                    else:
                        self.assertEqual(warmpool.command_bench(args), 1)
                    check_leaks.assert_called_once_with(pool)
                self.assertIn("restores=0 failures=1", output.getvalue())
                self.assertIn("p50=nan ms p95=nan ms max=nan ms", output.getvalue())
                self.assertIn("pool: 1 -> 1 entries", output.getvalue())
                self.assertEqual(len(warmpool.pool_entry_paths(pool)), 1)
                self.assertEqual(warmpool.pool_claimed_paths(pool), [])

    def test_fill_captures_entries_and_records_manifest(self) -> None:
        pool = self.make_pool(0)
        args = argparse.Namespace(
            pool_dir=pool,
            nvx_dir=pool,
            openvmm_dir=pool,
            size=2,
            backend="kvm",
            memory_mib=128,
            processors=2,
            timeout=10,
        )

        def capture(
            _command: list[str], entry: Path, *, timeout: float, processors: int
        ) -> None:
            self.assertEqual(timeout, 10)
            self.assertEqual(processors, 2)
            entry.mkdir()

        with (
            patch.object(
                warmpool, "_require_artifacts", return_value=(pool, pool, pool)
            ),
            patch.object(warmpool, "workload_boot_command", return_value=["openvmm"]),
            patch.object(warmpool, "capture_snapshot", side_effect=capture) as captures,
            patch.object(warmpool, "_process_affinity", return_value={0, 1}),
            patch.object(warmpool, "pool_class_frequencies", return_value=[4_000_000]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(warmpool.command_fill(args), 0)
        self.assertEqual(captures.call_count, 2)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 2)
        self.assertEqual(
            warmpool.read_manifest(pool),
            {
                "version": 1,
                "backend": "kvm",
                "processors": 2,
                "memory_mib": 128,
                "cpu_class_frequencies_khz": [4_000_000],
                "entries": 2,
            },
        )


@unittest.skipUnless(sys.platform == "linux", "requires Linux CPU affinity")
class ProcessAffinityRegressionTests(unittest.TestCase):
    def test_default_and_all_do_not_change_affinity(self) -> None:
        for preference in ("", "all"):
            with (
                self.subTest(preference=preference),
                patch.dict(os.environ, {"NVX_CPU_CLASS": preference}),
                patch.object(os, "sched_getaffinity", return_value=set(range(32))),
                patch.object(os, "sched_setaffinity") as set_affinity,
            ):
                nvx.apply_hybrid_process_affinity()
                set_affinity.assert_not_called()

    def test_opt_in_preserves_all_logical_cpus_in_class(self) -> None:
        classes = {6_000_000: {0, 1}, 5_700_000: {2, 3}, 4_200_000: {4, 5}}
        for preference, expected in (
            ("performance", {0, 1, 2, 3}),
            ("efficiency", {4, 5}),
        ):
            with (
                self.subTest(preference=preference),
                patch.dict(os.environ, {"NVX_CPU_CLASS": preference}),
                patch.object(benchmark, "cpu_frequency_classes", return_value=classes),
                patch.object(
                    benchmark, "physical_cpu_representatives", return_value={0, 2, 4}
                ),
                patch.object(os, "sched_getaffinity", return_value=set(range(6))),
                patch.object(os, "sched_setaffinity") as set_affinity,
            ):
                nvx.apply_hybrid_process_affinity()
                set_affinity.assert_called_once_with(0, expected)

    def test_main_benchmark_uses_supplied_argv_for_skip(self) -> None:
        argv = ["benchmark"]
        handler = MagicMock(return_value=0)
        args = argparse.Namespace(command="benchmark", handler=handler)
        with (
            patch.dict(os.environ, {"NVX_CPU_CLASS": "performance"}),
            patch.object(sys, "argv", ["pytest", "run"]),
            patch.object(nvx, "parse_args", return_value=args) as parse,
            patch.object(
                benchmark, "cpu_frequency_classes", return_value={6: {0}, 4: {2}}
            ),
            patch.object(
                benchmark, "physical_cpu_representatives", return_value={0, 2}
            ),
            patch.object(os, "sched_getaffinity", return_value={0, 1, 2, 3}),
            patch.object(os, "sched_setaffinity") as set_affinity,
        ):
            self.assertEqual(nvx.main(argv), 0)
            parse.assert_called_once_with(argv)
            handler.assert_called_once_with(args)
            set_affinity.assert_not_called()


class FrequencyClusterTests(unittest.TestCase):
    def test_frequency_steps_cannot_chain_beyond_ten_percent(self) -> None:
        classes = {4_000_000: {0}, 4_400_000: {1}, 4_840_000: {2}}
        self.assertEqual(benchmark.cpu_frequency_clusters(classes), [{0, 1}, {2}])

    def test_generated_pool_tags_pass_validation(self) -> None:
        classes = {4_000_000: {0}, 4_400_000: {1}, 4_840_000: {2}}
        with tempfile.TemporaryDirectory() as temporary:
            pool = Path(temporary)
            for affinity in ({0, 1}, {2}, {0, 1, 2}):
                with (
                    self.subTest(affinity=affinity),
                    patch.object(
                        warmpool, "cpu_frequency_classes", return_value=classes
                    ),
                    patch.object(warmpool, "_process_affinity", return_value=affinity),
                ):
                    tag = warmpool.pool_class_frequencies()
                    self.assertEqual(bool(tag), affinity != {0, 1, 2})
                    warmpool.write_manifest(pool, {"cpu_class_frequencies_khz": tag})
                    warmpool.validate_pool_class(pool)

    def test_nearby_frequencies_share_a_cluster_without_mutating_input(self) -> None:
        classes = {6_000_000: {0, 1}, 5_700_000: {2, 3}, 4_200_000: {4, 5}}
        self.assertEqual(
            benchmark.cpu_frequency_clusters(classes), [{4, 5}, {0, 1, 2, 3}]
        )
        self.assertEqual(classes[5_700_000], {2, 3})
        self.assertEqual(benchmark.cpu_frequency_clusters({}), [])

    def test_benchmark_and_matrix_share_turbo_core_grouping(self) -> None:
        classes = {6_000_000: {0, 1}, 5_700_000: {2, 3}, 4_200_000: {4, 5}}
        with (
            patch.dict(os.environ, {"NVX_CPU_CLASS": "performance"}),
            patch.object(benchmark, "cpu_frequency_classes", return_value=classes),
            patch.object(microvm_tests, "cpu_frequency_classes", return_value=classes),
            patch.object(
                microvm_tests, "physical_cpu_representatives", return_value={0, 2, 4}
            ),
        ):
            self.assertEqual(benchmark.apply_hybrid_cpu_filter({0, 2, 4}), {0, 2})
            self.assertEqual(
                microvm_tests._frequency_class_representatives(), ({0, 2}, {4})
            )

    def test_single_cluster_skips_class_matrix(self) -> None:
        with patch.object(
            microvm_tests,
            "cpu_frequency_classes",
            return_value={6_000_000: {0}, 5_700_000: {2}},
        ):
            self.assertIsNone(microvm_tests._frequency_class_representatives())


@unittest.skipIf(os.name == "nt", "execd requires Unix sockets")
class ExecdPermissionsRegressionTests(unittest.TestCase):
    def test_socket_is_private_at_bind_before_chmod(self) -> None:
        if os.name == "nt":
            self.skipTest("execd requires Unix sockets")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "execd.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            proxy = MagicMock(wraps=listener)
            modes: list[int] = []

            def bind(path: str) -> None:
                listener.bind(path)
                modes.append(socket_path.stat().st_mode & 0o777)

            proxy.bind.side_effect = bind
            previous = os.umask(0o002)
            try:
                with (
                    patch.object(sandbox_lifecycle.signal, "signal"),
                    patch.object(
                        sandbox_lifecycle, "_prepare_state_directory", return_value=root
                    ),
                    patch.object(
                        sandbox_lifecycle,
                        "_load_running",
                        return_value=(
                            {"pid": os.getpid(), "control_endpoint": "unused"},
                            b"x" * 32,
                        ),
                    ),
                    patch.object(
                        sandbox_lifecycle.socket, "socket", return_value=proxy
                    ),
                    patch.object(
                        sandbox_lifecycle.ControlSession,
                        "connect",
                        side_effect=RuntimeError("stop after bind"),
                    ),
                    self.assertRaisesRegex(RuntimeError, "stop after bind"),
                ):
                    sandbox_lifecycle.exec_daemon(root, socket_path, timeout=1)
                restored = os.umask(0o002)
            finally:
                os.umask(previous)
                listener.close()
            self.assertEqual(modes, [0o700])
            self.assertEqual(restored, 0o002)
            self.assertFalse(socket_path.exists())

    def test_bind_failure_restores_umask(self) -> None:
        listener = MagicMock()
        listener.bind.side_effect = OSError("bind failed")
        previous = os.umask(0o002)
        try:
            with (
                patch.object(sandbox_lifecycle.signal, "signal"),
                patch.object(
                    sandbox_lifecycle,
                    "_prepare_state_directory",
                    return_value=Path("."),
                ),
                patch.object(
                    sandbox_lifecycle,
                    "_load_running",
                    return_value=({"pid": os.getpid()}, b"x" * 32),
                ),
                patch.object(sandbox_lifecycle.socket, "socket", return_value=listener),
                self.assertRaisesRegex(OSError, "bind failed"),
            ):
                sandbox_lifecycle.exec_daemon(Path("."), Path("unused.sock"), timeout=1)
            restored = os.umask(0o002)
        finally:
            os.umask(previous)
        self.assertEqual(restored, 0o002)
        listener.close.assert_called_once()


class SetupSubmoduleRegressionTests(unittest.TestCase):
    def test_ready_source_message_does_not_claim_a_binary_exists(self) -> None:
        for has_binary in (False, True):
            with (
                self.subTest(has_binary=has_binary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                source = root / "openvmm"
                source.mkdir()
                (source / "Cargo.toml").write_text("[package]\n")
                binary = source / "target" / "release" / "openvmm"
                if has_binary:
                    binary.parent.mkdir(parents=True)
                    binary.write_bytes(b"release")
                with (
                    patch.object(nvx.BuildConstants, "REPO_ROOT", root),
                    patch.object(release, "openvmm_binary_path", return_value=binary),
                    patch.object(release.subprocess, "run") as run,
                    contextlib.redirect_stdout(io.StringIO()) as output,
                ):
                    nvx.command_setup_submodule(argparse.Namespace())
                run.assert_not_called()
                self.assertEqual(
                    output.getvalue(),
                    "openvmm source is ready; any existing release binary was preserved\n",
                )
                self.assertEqual(binary.exists(), has_binary)
                if has_binary:
                    self.assertEqual(binary.read_bytes(), b"release")

    def test_unexpected_contents_are_preserved_and_reported(self) -> None:
        for relative in ("target/release/other", "target/cache/data", "notes.txt"):
            with (
                self.subTest(relative=relative),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                binary = root / "openvmm" / "target" / "release" / "openvmm"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"release")
                extra = root / "openvmm" / relative
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_bytes(b"keep")
                with (
                    patch.object(release, "openvmm_binary_path", return_value=binary),
                    patch.object(release.subprocess, "run") as run,
                    self.assertRaisesRegex(common.ScriptError, "unexpected contents"),
                ):
                    release.ensure_openvmm_source(root)
                run.assert_not_called()
                self.assertEqual(extra.read_bytes(), b"keep")
                self.assertEqual(binary.read_bytes(), b"release")

    def test_interrupted_staging_is_recovered_even_with_initialized_source(
        self,
    ) -> None:
        for initialized in (False, True):
            with (
                self.subTest(initialized=initialized),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                staged = root / "build" / "openvmm-release-binary"
                staged.parent.mkdir()
                staged.write_bytes(b"saved-release")
                binary = root / "openvmm" / "target" / "release" / "openvmm"
                if initialized:
                    binary.parents[2].mkdir()
                    (binary.parents[2] / "Cargo.toml").write_text("[package]\n")
                with (
                    patch.object(release, "openvmm_binary_path", return_value=binary),
                    patch.object(
                        release.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0, b"", b""),
                    ),
                ):
                    release.ensure_openvmm_source(root)
                self.assertEqual(binary.read_bytes(), b"saved-release")
                self.assertFalse(staged.exists())

    def test_staged_binary_collision_preserves_both_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "build" / "openvmm-release-binary"
            staged.parent.mkdir()
            staged.write_bytes(b"saved-release")
            binary = root / "openvmm" / "target" / "release" / "openvmm"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"current-release")
            with (
                patch.object(release, "openvmm_binary_path", return_value=binary),
                self.assertRaisesRegex(common.ScriptError, "both.*binary"),
            ):
                release.ensure_openvmm_source(root)
            self.assertEqual(staged.read_bytes(), b"saved-release")
            self.assertEqual(binary.read_bytes(), b"current-release")

    def test_submodule_init_includes_nested_submodules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                release.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, b"", b""),
            ) as run:
                release.ensure_openvmm_source(root)
            self.assertIn("--recursive", run.call_args.args[0])
            self.assertNotIn("--depth", run.call_args.args[0])

    def test_windows_release_binary_is_preserved_and_init_is_recursive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "openvmm" / "target" / "release" / "openvmm.exe"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"windows-release")
            with (
                patch.object(release, "openvmm_binary_path", return_value=binary),
                patch.object(
                    release.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, b"", b""),
                ) as run,
            ):
                release.ensure_openvmm_source(root)
            self.assertEqual(binary.read_bytes(), b"windows-release")
            self.assertIn("--recursive", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["cwd"], root)

    def test_submodule_failure_is_script_error_and_restores_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "openvmm" / "target" / "release" / "openvmm"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"release")
            with (
                patch.object(release, "openvmm_binary_path", return_value=binary),
                patch.object(
                    release.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 1, b"", b"submodule failed"
                    ),
                ),
                self.assertRaisesRegex(common.ScriptError, "submodule.*exited 1"),
            ):
                release.ensure_openvmm_source(root)
            self.assertEqual(binary.read_bytes(), b"release")


class CpuSelectionValidationTests(unittest.TestCase):
    def test_requested_class_without_candidate_cpus_is_rejected(self) -> None:
        for preference, candidates in (
            ("performance", {2, 3}),
            ("efficiency", {0, 1}),
        ):
            with (
                self.subTest(preference=preference),
                patch.dict(os.environ, {"NVX_CPU_CLASS": preference}),
                patch.object(
                    benchmark,
                    "cpu_frequency_classes",
                    return_value={6_000_000: {0, 1}, 4_200_000: {2, 3}},
                ),
                self.assertRaisesRegex(
                    common.ScriptError, f"NVX_CPU_CLASS={preference}.*no.*CPU"
                ),
            ):
                benchmark.apply_hybrid_cpu_filter(candidates)

    def test_unset_default_keeps_i9_eight_vcpu_benchmark_valid(self) -> None:
        representatives = set(range(0, 16, 2)) | set(range(16, 32))
        with (
            patch.dict(os.environ, clear=True),
            patch.object(
                benchmark, "physical_cpu_representatives", return_value=representatives
            ),
            patch.object(benchmark, "cpu_frequency_classes") as frequencies,
        ):
            args = nvx.parse_args(["benchmark", "--processors", "8"])
            self.assertEqual(benchmark.parse_cpu_set(args.cpus), representatives)
            benchmark.validate_benchmark_cpu_set(
                benchmark.parse_cpu_set(args.cpus), args.processors
            )
            frequencies.assert_not_called()

    def test_explicit_cpus_and_help_never_read_frequencies(self) -> None:
        with (
            patch.dict(os.environ, {"NVX_CPU_CLASS": "performance"}),
            patch.object(benchmark, "cpu_frequency_classes") as frequencies,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            args = nvx.parse_args(["benchmark", "--cpus", "0-15"])
            self.assertEqual(args.cpus, "0-15")
            for argv in (["--help"], ["benchmark", "--help"], ["warmpool", "--help"]):
                with self.assertRaises(SystemExit) as exit_status:
                    nvx.parse_args(argv)
                self.assertEqual(exit_status.exception.code, 0)
            frequencies.assert_not_called()

    def test_unknown_class_is_rejected_in_both_filters_and_cli(self) -> None:
        with (
            patch.dict(os.environ, {"NVX_CPU_CLASS": "perfomance"}),
            patch.object(benchmark, "cpu_frequency_classes") as frequencies,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            for action in (
                lambda: benchmark.apply_hybrid_cpu_filter({0, 1}),
                nvx.apply_hybrid_process_affinity,
            ):
                with self.assertRaisesRegex(common.ScriptError, "NVX_CPU_CLASS"):
                    action()
            self.assertEqual(nvx.main(["benchmark", "--cpus", "0-15"]), 1)
            self.assertEqual(nvx.main(["verify"]), 1)
            self.assertIn("NVX_CPU_CLASS", stderr.getvalue())
            frequencies.assert_not_called()

    def test_default_all_and_homogeneous_class_behavior(self) -> None:
        for preference in ("", "all", "performance", "efficiency"):
            with (
                self.subTest(preference=preference),
                patch.dict(os.environ, {"NVX_CPU_CLASS": preference}),
                patch.object(
                    benchmark, "cpu_frequency_classes", return_value={4_000_000: {0, 1}}
                ) as frequencies,
            ):
                self.assertEqual(benchmark.apply_hybrid_cpu_filter({0, 1}), {0, 1})
                self.assertEqual(
                    frequencies.call_count, int(preference not in ("", "all"))
                )


class StartupTimeoutValidationTests(unittest.TestCase):
    def test_full_first_window_is_not_retried(self) -> None:
        for timeout in (1, 5, 8):
            with (
                self.subTest(timeout=timeout),
                patch.dict(os.environ, {"NVX_START_FIRST_WAIT_S": "8"}),
                patch.object(
                    sandbox_lifecycle,
                    "_start_once",
                    side_effect=TimeoutError(
                        "managed control endpoint did not become available"
                    ),
                ) as start,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
                self.assertRaisesRegex(TimeoutError, "did not become available"),
            ):
                sandbox_lifecycle.start(Path("state"), timeout)
            start.assert_called_once_with(
                Path("state"), timeout, endpoint_wait_s=timeout
            )
            self.assertEqual(stderr.getvalue(), "")

    def test_first_endpoint_wait_is_capped_by_caller_timeout(self) -> None:
        with (
            patch.dict(os.environ, {"NVX_START_FIRST_WAIT_S": "8"}),
            patch.object(sandbox_lifecycle, "_start_once") as start,
        ):
            sandbox_lifecycle.start(Path("state"), 5)
            start.assert_called_once_with(Path("state"), 5, endpoint_wait_s=5)

    def test_attach_keeps_full_timeout_after_short_endpoint_wait(self) -> None:
        stream_type = (
            control_session._NamedPipeStream
            if os.name == "nt"
            else control_session._SocketStream
        )
        with (
            patch.object(stream_type, "connect", return_value=MagicMock()) as connect,
            patch.object(control_session.time, "monotonic", return_value=100),
            patch.object(control_session.ControlSession, "_write_outer") as write,
            patch.object(
                control_session.ControlSession,
                "_read_outer",
                return_value=(control_session.OUTER_READY, b"x" * 16, 1, 0, b""),
            ) as read,
        ):
            with control_session.ControlSession.connect(
                Path("endpoint"), b"x" * 32, 60, endpoint_timeout=8
            ):
                pass
            connect.assert_called_once_with(Path("endpoint"), 8)
            self.assertEqual(write.call_args.args[-1], 160)
            read.assert_called_once_with(160)

    def test_first_wait_rejects_nonfinite_environment_values(self) -> None:
        for raw in ("nan", "inf", "-inf"):
            with (
                patch.dict(os.environ, {"NVX_START_FIRST_WAIT_S": raw}),
                self.assertRaises(common.ScriptError),
            ):
                sandbox_lifecycle._start_first_wait_s()


class PoolInputValidationTests(PoolFixture):
    def test_every_numeric_cli_option_rejects_zero_negative_and_nonfinite(self) -> None:
        options = {
            "fill": ("--size", "--memory-mib", "--timeout", "--processors"),
            "acquire": ("--count",),
            "prune": ("--ttl-s",),
            "bench": ("--workers", "--duration-s", "--timeout"),
        }
        for operation, flags in options.items():
            for flag in flags:
                for value in ("0", "-1", "nan", "inf", "-inf"):
                    with (
                        self.subTest(operation=operation, flag=flag, value=value),
                        contextlib.redirect_stderr(io.StringIO()),
                        self.assertRaises(SystemExit) as exit_status,
                    ):
                        nvx.parse_args(
                            [
                                "warmpool",
                                operation,
                                "--pool-dir",
                                "pool",
                                f"{flag}={value}",
                            ]
                        )
                    self.assertEqual(exit_status.exception.code, 2)

    def test_direct_prune_and_acquire_reject_nonpositive_values(self) -> None:
        pool = self.make_pool(1)
        for value in (0, -1):
            with self.assertRaises(common.ScriptError):
                warmpool.acquire_entries(pool, value)
            with self.assertRaises(common.ScriptError):
                warmpool.prune_claims(pool, value)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 1)

    def test_extreme_positive_counts_fail_without_float_overflow(self) -> None:
        pool = self.make_pool(1)
        with self.assertRaises(common.ScriptError):
            warmpool.acquire_entries(pool, 10**1000)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 1)

    def test_refill_preserves_existing_pool_shape_and_claims(self) -> None:
        pool = self.make_pool(1)
        manifest = {"processors": 1, "memory_mib": 128, "backend": "kvm"}
        warmpool.write_manifest(pool, manifest)
        claimed = warmpool.acquire_entries(pool, 1)[0]
        args = argparse.Namespace(
            pool_dir=pool,
            nvx_dir=pool,
            openvmm_dir=pool,
            size=1,
            memory_mib=256,
            processors=2,
            backend="mshv",
            timeout=1,
        )
        with (
            patch.object(
                warmpool, "_require_artifacts", return_value=(pool, pool, pool)
            ),
            patch.object(warmpool, "capture_snapshot") as capture,
            self.assertRaisesRegex(common.ScriptError, "empty pool directory"),
        ):
            warmpool.command_fill(args)
        capture.assert_not_called()
        self.assertEqual(warmpool.read_manifest(pool), manifest)
        self.assertTrue(claimed.is_dir())

    def test_failed_fill_keeps_shape_and_only_publishes_completed_captures(
        self,
    ) -> None:
        pool = self.make_pool(0)
        args = argparse.Namespace(
            pool_dir=pool,
            nvx_dir=pool,
            openvmm_dir=pool,
            size=2,
            memory_mib=128,
            processors=2,
            backend="kvm",
            timeout=1,
        )
        calls = 0

        def capture(_command: list[str], entry: Path, **_kwargs: object) -> None:
            nonlocal calls
            calls += 1
            entry.mkdir()
            if calls == 2:
                raise OSError("capture failed")

        with (
            patch.object(
                warmpool, "_require_artifacts", return_value=(pool, pool, pool)
            ),
            patch.object(warmpool, "capture_snapshot", side_effect=capture),
            patch.object(warmpool, "_process_affinity", return_value={0, 1}),
            patch.object(warmpool, "pool_class_frequencies", return_value=[]),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(OSError, "capture failed"),
        ):
            warmpool.command_fill(args)
        self.assertEqual(warmpool.read_manifest(pool)["processors"], 2)
        self.assertEqual(warmpool.read_manifest(pool)["entries"], 1)
        self.assertEqual(len(warmpool.pool_entry_paths(pool)), 1)
        self.assertEqual(list(pool.glob("capturing-*")), [])

    def test_bench_acquire_and_release_errors_still_report_and_check_leaks(
        self,
    ) -> None:
        for phase in ("acquire", "release"):
            with self.subTest(phase=phase):
                pool = self.make_pool(1)
                warmpool.write_manifest(pool, {"processors": 1, "backend": "kvm"})
                args = argparse.Namespace(
                    pool_dir=pool,
                    nvx_dir=pool,
                    openvmm_dir=pool,
                    workers=1,
                    duration_s=1,
                    timeout=1,
                )
                operation = "acquire_entries" if phase == "acquire" else "release_entry"
                with (
                    patch.object(warmpool, "validate_pool_class"),
                    patch.object(
                        warmpool, "_require_artifacts", return_value=(pool, pool, pool)
                    ),
                    patch.object(warmpool, operation, side_effect=OSError(phase)),
                    patch.object(warmpool.time, "monotonic", side_effect=[0, 0, 0, 2]),
                    patch.object(warmpool, "benchmark", return_value={"p50_ms": 1.0}),
                    contextlib.redirect_stdout(io.StringIO()) as output,
                    contextlib.redirect_stderr(io.StringIO()) as stderr,
                ):
                    if phase == "release":
                        with self.assertRaisesRegex(
                            common.ScriptError, "leak detected"
                        ):
                            warmpool.command_bench(args)
                    else:
                        self.assertEqual(warmpool.command_bench(args), 1)
                self.assertIn("failures=1", output.getvalue())
                self.assertIn("leaked claims", output.getvalue())
                self.assertIn(f"{phase} failed", stderr.getvalue())

    def test_invalid_manifest_fields_fail_cleanly(self) -> None:
        pool = self.make_pool(0)
        for fields in (
            {"processors": True},
            {"processors": 3},
            {"memory_mib": 0},
            {"backend": "whp"},
            {"cpu_class_frequencies_khz": "4000000"},
            {"cpu_class_frequencies_khz": [None]},
        ):
            warmpool.write_manifest(pool, fields)
            with self.assertRaises(common.ScriptError):
                warmpool.read_manifest(pool)
        (pool / warmpool.POOL_MANIFEST).write_text("{broken")
        with self.assertRaises(common.ScriptError):
            warmpool.read_manifest(pool)


class ExecdInputValidationTests(unittest.TestCase):
    def test_request_limit_including_last_chunk_and_eof(self) -> None:
        limit = sandbox_lifecycle.EXECD_MAX_REQUEST_BYTES
        for size in (limit - 1, limit, limit + 1, limit + 65_535):
            for ending in (b"\n", b""):
                with self.subTest(size=size, ending=ending):
                    data = io.BytesIO(b"x" * size + ending)
                    connection = MagicMock()
                    connection.recv.side_effect = data.read
                    if size > limit:
                        with self.assertRaisesRegex(common.ScriptError, "1 MiB"):
                            sandbox_lifecycle._execd_read_request(connection)
                    else:
                        self.assertEqual(
                            len(sandbox_lifecycle._execd_read_request(connection)), size
                        )

    def test_timeout_bounds_and_deep_json_are_client_errors(self) -> None:
        for timeout in (-1, True, 1.5, 0x100000000, 10**1000):
            raw = json.dumps({"cmd": ["/bin/true"], "timeout_ms": timeout}).encode()
            with self.assertRaisesRegex(common.ScriptError, "timeout_ms"):
                sandbox_lifecycle._execd_parse_request(raw)
        for raw in (b"[" * 2000 + b"]" * 2000, b'{"timeout_ms":' + b"9" * 5000 + b"}"):
            with self.assertRaises(common.ScriptError):
                sandbox_lifecycle._execd_parse_request(raw)
        for timeout in (0, 0xFFFFFFFF):
            raw = json.dumps({"cmd": ["/bin/true"], "timeout_ms": timeout}).encode()
            self.assertEqual(
                sandbox_lifecycle._execd_parse_request(raw), (("/bin/true",), timeout)
            )

    @unittest.skipIf(os.name == "nt", "execd requires Unix sockets")
    def test_sigterm_handler_is_restored_on_all_exit_paths(self) -> None:
        previous = signal.getsignal(signal.SIGTERM)
        for error in (
            common.ScriptError("startup"),
            RuntimeError("serve"),
            SystemExit(0),
        ):
            with (
                patch.object(sandbox_lifecycle, "_exec_daemon", side_effect=error),
                self.assertRaises(type(error)),
            ):
                sandbox_lifecycle.exec_daemon(Path("state"), Path("socket"), timeout=1)
            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
