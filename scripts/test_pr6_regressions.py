# pyright: reportPrivateUsage=false

import argparse
import os
import shutil
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
    microvm_tests,
    release,
    sandbox_lifecycle,
    warmpool,
)


class WarmpoolRegressionTests(unittest.TestCase):
    def make_pool(self, count: int) -> Path:
        root = Path(tempfile.mkdtemp(prefix="nvx-pool-regression-"))
        self.addCleanup(shutil.rmtree, root)
        for index in range(count):
            (root / f"entry-{index}").mkdir()
        return root

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
