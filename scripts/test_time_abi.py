"""Unit tests for the harness-side NVX time ABI checks and host qualification."""

from __future__ import annotations

import contextlib
import io
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nvx_tools import benchmark, doctor, openvmm_process, time_abi  # noqa: E402
from nvx_tools.time_abi import TimeAbiFailure, TimeAbiMonitor  # noqa: E402

BOOT_LINE = (
    "NVX-TIME-ABI: v=1 phase=boot status=ok cpus=4 tsc_hz=2194804000 "
    "lapic_hz=1000000000 generation=0 elapsed_us=1873\n"
)
KVM_BOOT = ["openvmm", "--hypervisor", "kvm", "--kernel", "vmlinux"]
MSHV_RESTORE = ["openvmm", "--hypervisor", "mshv", "--restore-snapshot", "snap"]
# OpenVMM's openvmm_entry fatal_error_message, after a guest prompt.
FATAL_DETAIL = "[E_TSC_SYNC_UNSUPPORTED] failed to launch vm worker"
FATAL = f"~ # fatal error: {FATAL_DETAIL}\r\n\r\nCaused by:\r\n".encode()


def warp_output(
    *,
    pairs: int = 6,
    backward: int = 0,
    offset: int = 15,
    verdict: str = "PASS",
    stalled: int = 0,
    conclusive: int = 1,
) -> str:
    return (
        "pair 0-1: warp_iterations=881154 warps=0 max_backward_ns=0\n"
        f"NVX-TIME-PROBE warp max_backward_cycles=0 max_backward_ns={backward} "
        f"max_abs_offset_ns={offset} pairs={pairs} verdict={verdict} bound_ns=1000\r\n"
        "NVX-TIME-PROBE warp-detail max_abs_offset_cycles=33.0 max_uncertainty_ns=127 "
        "max_skew_bound_ns=130 total_warps=0 inconsistent_pairs=0 "
        f"stalled_pairs={stalled} cpus=0-3 duration_ms=100 tsc_hz=2194804000 "
        f"tsc_hz_source=kmsg-detected-processor conclusive={conclusive}\n"
    )


class FieldParsingTests(unittest.TestCase):
    def test_parses_plain_and_quoted_fields_with_guest_escapes(self):
        fields = time_abi.parse_fields(
            'v=1 code=G_TSC_WARP detail="say \\"hi\\" \\\\ \\x07 end" phase=boot'
        )
        self.assertEqual(
            fields,
            {
                "v": "1",
                "code": "G_TSC_WARP",
                "detail": 'say "hi" \\ \x07 end',
                "phase": "boot",
            },
        )

    def test_rejects_malformed_fields(self):
        for text in (
            "novalue",
            "=x",
            'detail="unterminated',
            'detail="bad \\q escape"',
            'detail="\\x4"',
            "v=1 v=2",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                time_abi.parse_fields(text)

    def test_parses_markers_and_violations(self):
        marker = time_abi.parse_marker(BOOT_LINE)
        self.assertIsNotNone(marker)
        assert marker is not None
        self.assertEqual(marker["phase"], "boot")
        self.assertEqual(marker["tsc_hz"], "2194804000")
        self.assertIsNone(time_abi.parse_marker("NVX-TIME-REPORT: v=1 phase=boot"))
        with self.assertRaises(ValueError):
            time_abi.parse_marker("NVX-TIME-ABI: v=1 status=ok")
        violation = time_abi.parse_violation(
            "noise NVX-TIME-ABI-VIOLATION: v=1 code=G_RCU_STALL source=watcher "
            'phase=runtime generation=1 boottime_ns=5 detail="rcu: INFO: x"\r'
        )
        self.assertIsNotNone(violation)
        assert violation is not None
        self.assertEqual(violation["code"], "G_RCU_STALL")
        self.assertEqual(violation["detail"], "rcu: INFO: x")

    def test_describes_only_time_abi_exit_statuses(self):
        self.assertIn("conformance", time_abi.describe_exit_status(193) or "")
        self.assertIn("runtime violation", time_abi.describe_exit_status(194) or "")
        self.assertIn("restore repair", time_abi.describe_exit_status(195) or "")
        for status in (None, 0, 1, 37, 192, 196, 255):
            self.assertIsNone(time_abi.describe_exit_status(status))

    def test_maps_cpu_generations(self):
        def name(model: int, stepping: int, vendor: str = "GenuineIntel"):
            generation = time_abi.cpu_generation(vendor, 6, model, stepping)
            return generation.name if generation else None

        self.assertEqual(name(85, 4), "skylake-sp")
        self.assertEqual(name(106, 6), "icelake-sp")
        self.assertEqual(name(207, 2), "emeraldrapids")
        # Cascade Lake and Cooper Lake share model 85 but have no profile.
        self.assertIsNone(name(85, 7))
        self.assertIsNone(name(85, 11))
        self.assertIsNone(name(143, 8))
        self.assertIsNone(name(1, 1, "AuthenticAMD"))

    def test_names_the_catalog_profiles(self):
        # One profile per generation serves every backend.
        self.assertEqual(
            [generation.profile_id for generation in time_abi.CPU_GENERATIONS],
            ["intel.skylake-sp.v1", "intel.icelake-sp.v1", "intel.emeraldrapids.v1"],
        )


class MonitorTests(unittest.TestCase):
    def test_classifies_commands(self):
        monitor = TimeAbiMonitor(KVM_BOOT)
        self.assertEqual(monitor.backend, "kvm")
        self.assertTrue(monitor.cold_boot)
        restore = TimeAbiMonitor(MSHV_RESTORE)
        self.assertEqual(restore.backend, "mshv")
        self.assertFalse(restore.cold_boot)

    def test_records_markers_across_chunk_boundaries(self):
        monitor = TimeAbiMonitor(KVM_BOOT)
        data = (
            "[    0.1] early\n"
            + BOOT_LINE
            + " ALPINE-MICROVM-BOOT-OK: 3.22.1\n"
            + "NVX-TIME-ABI: v=1 phase=runtime status=uncertain "
            + "code=G_SAMPLE_UNCERTAIN epsilon_ns=-1\n"
            + "NVX-TIME-ABI: v=1 phase=restore status=ok cpus=4 tsc_hz=2194804000 "
            + "lapic_hz=1000000000 generation=1 elapsed_us=12\n"
        ).encode()
        for index in range(0, len(data), 7):
            monitor.feed(data[index : index + 7])
        self.assertTrue(monitor.guest_booted)
        self.assertEqual(monitor.require_boot("test", online_cpus=4)["cpus"], "4")
        self.assertEqual(len(monitor.uncertain), 1)
        self.assertEqual(monitor.restores[0]["generation"], "1")
        monitor.require_boot_if_booted()

    def test_fails_fast_on_violation_events_and_failed_checks(self):
        monitor = TimeAbiMonitor(KVM_BOOT)
        with self.assertRaisesRegex(TimeAbiFailure, "violation G_TSC_UNSTABLE"):
            monitor.feed(
                b"NVX-TIME-ABI-VIOLATION: v=1 code=G_TSC_UNSTABLE source=watcher "
                b'phase=runtime generation=0 boottime_ns=1 detail="Marking"\n'
            )
        self.assertIn("G_TSC_UNSTABLE", monitor.violation or "")
        with self.assertRaisesRegex(TimeAbiFailure, "boot check C9 failed: token"):
            TimeAbiMonitor(KVM_BOOT).feed(
                b'NVX-TIME-ABI: v=1 phase=boot status=fail check=C9 detail="token"\n'
            )
        with self.assertRaisesRegex(TimeAbiFailure, "malformed"):
            TimeAbiMonitor(KVM_BOOT).feed(b"NVX-TIME-ABI: v=1 phase=boot\n")
        with self.assertRaisesRegex(TimeAbiFailure, "unknown time ABI marker status"):
            TimeAbiMonitor(KVM_BOOT).feed(
                b"NVX-TIME-ABI: v=1 phase=boot status=maybe\n"
            )

    def test_ignores_report_only_lines_but_reports_them_when_the_marker_is_missing(
        self,
    ):
        monitor = TimeAbiMonitor(KVM_BOOT)
        monitor.feed(
            b"NVX-TIME-REPORT-VIOLATION: v=1 code=G_TSC_WARP source=watcher "
            b'phase=boot generation=0 boottime_ns=1 detail="x"\n'
            b"NVX-TIME-REPORT: v=1 phase=boot status=fail cpus=1 failures=3\n"
            b"NVX-GUEST-BOOT-OK: alpine\n"
        )
        self.assertTrue(monitor.report_only)
        with self.assertRaisesRegex(TimeAbiFailure, "report-only"):
            monitor.require_boot_if_booted()

    def test_requires_the_boot_marker_only_for_cold_boots_that_reached_the_shell(
        self,
    ):
        monitor = TimeAbiMonitor(KVM_BOOT)
        monitor.require_boot_if_booted()
        monitor.feed(b"NVX-GUEST-BOOT-OK: alpine\n")
        with self.assertRaisesRegex(TimeAbiFailure, "does not implement time ABI"):
            monitor.require_boot_if_booted()
        restore = TimeAbiMonitor(MSHV_RESTORE)
        restore.feed(b" ALPINE-MICROVM-BOOT-OK: 3.22.1\n")
        restore.require_boot_if_booted()

    def test_validates_boot_marker_fields_against_the_backend(self):
        cases = (
            ("v=1", "v=2", "version"),
            ("lapic_hz=1000000000", "lapic_hz=200000000", "kvm rate"),
            ("tsc_hz=2194804000", "tsc_hz=400000000", "outside 500 MHz"),
            ("tsc_hz=2194804000", "tsc_hz=fast", "not an integer"),
            ("generation=0", "generation=3", "not 0 at cold boot"),
            ("cpus=4", "cpus=2", "cpus=2 is not 4"),
        )
        for valid, invalid, message in cases:
            fields = time_abi.parse_marker(BOOT_LINE.replace(valid, invalid))
            assert fields is not None
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(TimeAbiFailure, message):
                    time_abi.validate_boot_marker(fields, backend="kvm", online_cpus=4)
        mshv = time_abi.parse_marker(
            BOOT_LINE.replace("lapic_hz=1000000000", "lapic_hz=200000000")
        )
        assert mshv is not None
        time_abi.validate_boot_marker(mshv, backend="mshv")

    def test_classifies_time_abi_exit_statuses_with_the_violation_event(self):
        monitor = TimeAbiMonitor(MSHV_RESTORE)
        monitor.check_exit(0)
        monitor.check_exit(None)
        with self.assertRaisesRegex(
            TimeAbiFailure, "status 195 \\(restore repair\\): no NVX-TIME-ABI"
        ):
            monitor.check_exit(195)
        try:
            monitor.feed(
                b"NVX-TIME-ABI-VIOLATION: v=1 code=G_REPAIR_SAMPLE source=repair "
                b'phase=restore generation=1 boottime_ns=9 detail="epsilon"'
            )
            monitor.finish()
        except TimeAbiFailure:
            pass
        with self.assertRaisesRegex(TimeAbiFailure, "status 195.*G_REPAIR_SAMPLE"):
            monitor.check_exit(195)

    def test_bounds_an_unterminated_line(self):
        monitor = TimeAbiMonitor(KVM_BOOT)
        monitor.feed(b"x" * (time_abi._MAX_PENDING_LINE + 10))  # pyright: ignore[reportPrivateUsage]
        monitor.feed(b"\n" + BOOT_LINE.encode())
        self.assertIsNotNone(monitor.boot)

    def test_records_the_first_fatal_time_abi_error_for_exit_errors(self):
        monitor = TimeAbiMonitor(KVM_BOOT)
        monitor.feed(b"fatal error: failed to open the kernel\r\n")
        self.assertIsNone(monitor.fatal)
        self.assertEqual(str(monitor.exit_error(1)), "OpenVMM exited with status 1")
        # A guest prompt without a newline can precede OpenVMM's line.
        monitor.feed(FATAL + b"    0: [E_TSC_SYNC_UNSUPPORTED] no synchronized set\r\n")
        monitor.feed(b"fatal error: [E_TEST_HOOK] later\r\n")
        self.assertEqual(monitor.fatal, FATAL_DETAIL)
        # The line only explains the exit; it never changes its classification.
        monitor.check_exit(1)
        self.assertEqual(
            str(monitor.exit_error(1, "snapshot source", "during teardown")),
            f"snapshot source exited with status 1 during teardown: {FATAL_DETAIL}",
        )


class WarpProbeTests(unittest.TestCase):
    def test_accepts_conclusive_passing_measurements(self):
        results = time_abi.check_warp_probe(warp_output(), cpus=4, context="test")
        self.assertEqual(results[0]["max_abs_offset_ns"], "15")
        single = time_abi.check_warp_probe(
            warp_output(pairs=0, offset=0), cpus=1, context="one vCPU"
        )
        self.assertEqual(single[0]["pairs"], "0")
        self.assertEqual(
            time_abi.warp_probe_command(),
            "/sbin/nvx-time-probe warp --bound-ns 1000",
        )
        self.assertTrue(time_abi.warp_probe_command(cpus="0-3").endswith("--cpus 0-3"))

    def test_rejects_skew_stalls_and_inconclusive_measurements(self):
        cases = (
            (warp_output(backward=1001), "max_backward_ns=1001"),
            (warp_output(offset=1500, verdict="FAIL"), "max_abs_offset_ns=1500"),
            (warp_output(stalled=1, verdict="FAIL"), "1 CPU pair"),
            (warp_output(conclusive=0), "inconclusive"),
            (warp_output(pairs=3), "measured 3 CPU pairs instead of 6"),
            (warp_output(verdict="FAIL"), "verdict=FAIL"),
            ("nothing here\n", "printed no summary"),
            (
                warp_output().split("NVX-TIME-PROBE warp-detail")[0],
                "1 summaries and 0 detail",
            ),
            (
                "NVX-TIME-PROBE warp pairs=6\nNVX-TIME-PROBE warp-detail x=1\n",
                "incomplete",
            ),
            ('NVX-TIME-PROBE warp detail="\n', "malformed"),
        )
        for text, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(TimeAbiFailure, message):
                    time_abi.check_warp_probe(text, cpus=4, context="restore 4")

    def test_counts_rounds_and_names_the_failing_round(self):
        self.assertEqual(
            [time_abi.warp_rounds(cpus) for cpus in (1, 2, 8)],
            [1, time_abi.WARP_PROBE_ROUNDS, time_abi.WARP_PROBE_ROUNDS],
        )
        two = warp_output() + warp_output(offset=30)
        results = time_abi.check_warp_probe(two, cpus=4, context="boot", rounds=2)
        self.assertEqual(
            [result["max_abs_offset_ns"] for result in results], ["15", "30"]
        )
        with self.assertRaisesRegex(TimeAbiFailure, "ran 1 rounds instead of 2"):
            time_abi.check_warp_probe(warp_output(), cpus=4, context="boot", rounds=2)
        with self.assertRaisesRegex(
            TimeAbiFailure, "failed in round 2: max_backward_ns=2000"
        ):
            time_abi.check_warp_probe(
                warp_output() + warp_output(backward=2000, verdict="FAIL"),
                cpus=4,
                context="boot",
            )

    def test_warp_fragment_idles_between_rounds_and_powers_off_on_failure(self):
        shell = shutil.which("sh")
        if shell is None and (git := shutil.which("git")) is not None:
            candidate = Path(git).parent.parent / "bin" / "sh.exe"
            shell = str(candidate) if candidate.is_file() else None
        if shell is None:
            self.skipTest("POSIX shell is unavailable")
        fragment = (
            time_abi.warp_probe_script()
            .replace(time_abi.WARP_PROBE_PATH, "probe")
            .replace("nvx-exit", "nvx_exit")
        )
        for online, failing_round, calls, sleeps in (
            ("0-3", 0, 2, 1),
            ("0-3", 2, 2, 1),
            ("0-3", 1, 1, 0),
            ("0", 0, 1, 0),
        ):
            with self.subTest(online=online, failing_round=failing_round):
                result = subprocess.run(
                    [shell],
                    input=(
                        f"cat() {{ printf '%s\\n' '{online}'; }}\n"
                        "calls=0\n"
                        "probe() {\n"
                        "    calls=$((calls + 1))\n"
                        '    printf "probe %s\\n" "$*"\n'
                        f'    [ "$calls" -ne {failing_round} ]\n'
                        "}\n"
                        'sleep() { printf "SLEEP %s\\n" "$1"; }\n'
                        'nvx_exit() { printf "NVX-EXIT %s\\n" "$1"; }\n'
                        + fragment
                        + "echo after\n"
                    ),
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                lines = result.stdout.splitlines()
                self.assertEqual(
                    lines.count(f"probe warp --bound-ns 1000 --cpus {online}"),
                    calls,
                    result.stdout + result.stderr,
                )
                self.assertEqual(
                    lines.count(f"SLEEP {time_abi.WARP_PROBE_IDLE_SECONDS}"), sleeps
                )
                if failing_round:
                    self.assertEqual(result.returncode, 97)
                    self.assertIn(
                        f"NVX-WARP-PROBE-FAIL status=1 round={failing_round}", lines
                    )
                    self.assertIn("NVX-EXIT 97", lines)
                    self.assertNotIn("NVX-WARP-PROBE-OK", lines)
                    self.assertNotIn("after", lines)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("NVX-WARP-PROBE-OK", lines)
                    self.assertIn("after", lines)


VIOLATION = (
    b"NVX-TIME-ABI-VIOLATION: v=1 code=G_RCU_STALL source=watcher phase=runtime "
    b'generation=1 boottime_ns=99 detail="rcu: INFO: rcu_preempt self-detected stall"\n'
)


class FakeProcess:
    pid = 123

    def __init__(self, status: int) -> None:
        self.status = status
        self.exited = False
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.exited:
            self.returncode = self.status
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.exited = True
        self.returncode = self.status
        return self.status

    def terminate(self) -> None:
        self.exited = True

    def kill(self) -> None:
        self.exited = True


class FakeInteraction:
    def __init__(self, chunks: list[bytes], status: int) -> None:
        self.process = FakeProcess(status)
        self.chunks = chunks
        self.writes: list[bytes] = []

    def read_output(self, chunks: queue.Queue[bytes | None]) -> None:
        for chunk in self.chunks:
            chunks.put(chunk)
        self.process.exited = True
        chunks.put(None)

    def write_input(self, data: bytes) -> None:
        self.writes.append(data)

    def close(self) -> None:
        pass


class RunnerWiringTests(unittest.TestCase):
    def _measure(self, chunks: list[bytes], status: int, command: list[str]):
        interaction = FakeInteraction(chunks, status)
        with (
            patch.object(benchmark, "InteractiveProcess", return_value=interaction),
            patch.object(benchmark, "live_peak_rss_bytes", return_value=1024),
        ):
            return benchmark.measure_once(
                command,
                environment={},
                timeout=5,
                marker=benchmark.RESTORE_MARKER,
                marker_must_be_line=True,
                guest_exit_prequeued=True,
            )

    def test_measure_once_fails_fast_on_a_violation_event(self):
        with self.assertRaisesRegex(RuntimeError, "violation G_RCU_STALL") as raised:
            self._measure(
                [b"restored\n", VIOLATION, benchmark.RESTORE_MARKER + b"\n"],
                194,
                MSHV_RESTORE,
            )
        self.assertIn("--- OpenVMM output ---", str(raised.exception))

    def test_measure_once_classifies_a_time_abi_power_off(self):
        with self.assertRaisesRegex(
            RuntimeError, "status 195 \\(restore repair\\): no NVX-TIME-ABI"
        ):
            self._measure([b"restoring\n"], 195, MSHV_RESTORE)
        with self.assertRaisesRegex(RuntimeError, "OpenVMM exited with status 1"):
            self._measure([b"restoring\n"], 1, MSHV_RESTORE)

    def test_exit_errors_lead_with_openvmm_fatal_time_abi_code(self):
        expected = f"exited with status 1: {re.escape(FATAL_DETAIL)}\n"
        with self.assertRaisesRegex(RuntimeError, f"^OpenVMM {expected}"):
            self._measure([b"restoring\n", FATAL], 1, MSHV_RESTORE)
        interaction = FakeInteraction([b"booting\n", FATAL], 1)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(
                benchmark, "InteractiveProcess", return_value=interaction
            ):
                with self.assertRaisesRegex(
                    RuntimeError, f"^snapshot source {expected}"
                ):
                    benchmark.capture_snapshot(
                        KVM_BOOT,
                        Path(temporary) / "snapshot",
                        backend="kvm",
                        timeout=5,
                    )
            log_path = Path(temporary) / "process.log"
            with patch.object(
                openvmm_process,
                "InteractiveProcess",
                return_value=FakeInteraction([FATAL], 1),
            ):
                with openvmm_process.OpenvmmProcess(KVM_BOOT, log_path) as process:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        f"^OpenVMM exited with status 1 before .*: "
                        f"{re.escape(FATAL_DETAIL)}\n",
                    ):
                        process.wait_for(b"NEVER", 1)
                # An expected failure still returns its status and output.
                with patch.object(
                    openvmm_process,
                    "InteractiveProcess",
                    return_value=FakeInteraction([FATAL], 1),
                ):
                    with openvmm_process.OpenvmmProcess(KVM_BOOT, log_path) as process:
                        self.assertEqual(process.wait(1).returncode, 1)

    def test_measure_once_classifies_a_power_off_during_teardown(self):
        interaction = FakeInteraction([benchmark.RESTORE_MARKER + b"\n"], 194)
        with (
            patch.object(benchmark, "InteractiveProcess", return_value=interaction),
            patch.object(benchmark, "live_peak_rss_bytes", return_value=1024),
            patch.object(benchmark, "wait_for_process_exit", return_value=194),
        ):
            with self.assertRaisesRegex(RuntimeError, "status 194 \\(runtime"):
                benchmark.measure_once(
                    MSHV_RESTORE,
                    environment={},
                    timeout=5,
                    marker=benchmark.RESTORE_MARKER,
                    marker_must_be_line=True,
                    guest_exit_prequeued=True,
                )

    def test_run_guest_script_classifies_a_conformance_power_off(self):
        interaction = FakeInteraction(
            [
                b'NVX-TIME-ABI: v=1 phase=boot status=fail check=C4 detail="kvm-clock"',
            ],
            193,
        )
        with patch.object(benchmark, "InteractiveProcess", return_value=interaction):
            with self.assertRaisesRegex(
                RuntimeError, "boot check C4 failed: kvm-clock"
            ):
                benchmark.run_guest_script(
                    KVM_BOOT, "true\n", b"DONE", timeout=5, boot_marker=b"BOOT"
                )

    def test_capture_snapshot_classifies_a_failed_capture_check(self):
        interaction = FakeInteraction([b"booting\n"], 193)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(
                benchmark, "InteractiveProcess", return_value=interaction
            ):
                with self.assertRaisesRegex(RuntimeError, "status 193 \\(conformance"):
                    benchmark.capture_snapshot(
                        KVM_BOOT,
                        Path(temporary) / "snapshot",
                        backend="kvm",
                        timeout=5,
                    )

    def test_openvmm_process_reports_violations_and_time_abi_statuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "process.log"
            with patch.object(
                openvmm_process,
                "InteractiveProcess",
                return_value=FakeInteraction([b"FIRST\n", VIOLATION], 194),
            ):
                with openvmm_process.OpenvmmProcess(KVM_BOOT, log_path) as process:
                    process.wait_for(b"FIRST", 1)
                    with self.assertRaisesRegex(RuntimeError, "G_RCU_STALL"):
                        process.wait_for(b"NEVER", 1)
            self.assertIn(b"G_RCU_STALL", log_path.read_bytes())
            with patch.object(
                openvmm_process,
                "InteractiveProcess",
                return_value=FakeInteraction([b"working\n"], 194),
            ):
                with openvmm_process.OpenvmmProcess(KVM_BOOT, log_path) as process:
                    with self.assertRaisesRegex(RuntimeError, "status 194"):
                        process.wait(1)
            with patch.object(
                openvmm_process,
                "InteractiveProcess",
                return_value=FakeInteraction([b"working\n"], 195),
            ):
                with openvmm_process.OpenvmmProcess(KVM_BOOT, log_path) as process:
                    with self.assertRaisesRegex(RuntimeError, "status 195"):
                        process.wait_for_line(b"NEVER", 1)

    def test_openvmm_process_waits_for_time_abi_phase_markers(self):
        restore = (
            b"NVX-TIME-ABI: v=1 phase=restore status=ok cpus=2 tsc_hz=2300000000 "
            b"lapic_hz=200000000 generation=1 elapsed_us=310\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "process.log"
            with patch.object(
                openvmm_process,
                "InteractiveProcess",
                return_value=FakeInteraction([b"x\n", restore], 0),
            ):
                with openvmm_process.OpenvmmProcess(MSHV_RESTORE, log_path) as process:
                    marker = process.wait_for_time_abi("restore", 1)
                    self.assertEqual(marker["generation"], "1")
                    self.assertEqual(process.wait(1).returncode, 0)
            with patch.object(
                openvmm_process,
                "InteractiveProcess",
                return_value=FakeInteraction([b"x\n"], 0),
            ):
                with openvmm_process.OpenvmmProcess(MSHV_RESTORE, log_path) as process:
                    with self.assertRaisesRegex(RuntimeError, "restore marker"):
                        process.wait_for_time_abi("restore", 1)

    def test_tcp_console_monitor_reports_violations(self):
        connection, peer = socket.socketpair()
        console = openvmm_process.TcpConsole(connection, TimeAbiMonitor(KVM_BOOT))
        peer.sendall(VIOLATION)
        with self.assertRaisesRegex(TimeAbiFailure, "G_RCU_STALL"):
            console.wait_for(b"NEVER", 1.0)
        console.close()
        peer.close()


def doctor_context(root: Path, backend: str = "kvm") -> doctor.DoctorContext:
    return doctor.DoctorContext(
        backend=backend,
        openvmm=root / "openvmm",
        kernel=root / "vmlinux",
        initrd=root / "initramfs.cpio.gz",
        openvmm_args=(),
        probe_directory=root / "probe",
        timeout=30,
    )


def completed(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(["x"], returncode, stdout, stderr)


CPU = {
    "vendor": "GenuineIntel",
    "family": "6",
    "model": "106",
    "stepping": "6",
    "microcode": "0xffffffff",
    "brand": "Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz",
    "os": "Linux 6.6.150.1-1.azl3",
    "invariant_tsc": "yes",
}
# OpenVMM's cpu_profile FingerprintCheck::summary_line, printed on stderr.
PROFILE_PASS = (
    "NVX-CPU-PROFILE: status=pass backend=kvm generation=icelake-sp "
    f"profile=intel.icelake-sp.v1 profile_digest=sha256:{'a3' * 32} "
    "surface_digest=sha256:6286956acbef host_invariant_tsc=yes\n"
)


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_check_lines_escape_details_for_field_parsers(self):
        line = doctor.CheckResult("H5", False, 'say "x" \\ y').line()
        self.assertTrue(line.startswith("NVX-DOCTOR: check=H5 status=fail "))
        fields = time_abi.parse_fields(line.removeprefix(doctor.DOCTOR_PREFIX))
        self.assertEqual(fields["detail"], 'say "x" \\ y')

    def test_backend_check_requires_a_usable_device(self):
        context = doctor_context(self.root)
        existing: set[str] = set()

        def exists(path: Path) -> bool:
            return path.as_posix() in existing

        with (
            patch.object(doctor, "host_is_windows", return_value=False),
            patch.object(doctor.Path, "exists", exists),
            patch.object(doctor.os, "access", return_value=True) as access,
        ):
            self.assertIn("does not exist", doctor.check_backend(context).detail)
            existing.add("/dev/kvm")
            self.assertTrue(doctor.check_backend(context).passed)
            existing.add("/dev/mshv")
            self.assertIn("select MSHV", doctor.check_backend(context).detail)
            existing.discard("/dev/mshv")
            access.return_value = False
            self.assertIn("not readable", doctor.check_backend(context).detail)
        with patch.object(doctor, "host_is_windows", return_value=False):
            whp = doctor.check_backend(doctor_context(self.root, "whp"))
        self.assertFalse(whp.passed)
        self.assertIn("requires Windows", whp.detail)

    def test_cpu_check_names_the_generation_and_records_invariant_tsc_as_evidence(
        self,
    ):
        context = doctor_context(self.root)
        with patch.object(doctor, "host_cpu", return_value=dict(CPU)):
            result = doctor.check_cpu(context)
        self.assertTrue(result.passed)
        self.assertIn("generation=icelake-sp", result.detail)
        self.assertIn("profile=intel.icelake-sp.v1", result.detail)
        self.assertEqual(context.facts["generation"], "icelake-sp")
        for unknown in (dict(CPU, model="143"), dict(CPU, model="85", stepping="7")):
            with patch.object(doctor, "host_cpu", return_value=unknown):
                result = doctor.check_cpu(doctor_context(self.root))
            self.assertFalse(result.passed)
            self.assertTrue(result.detail.startswith("[E_PROFILE_HOST_UNKNOWN] "))
        emerald = dict(CPU, model="207", stepping="2")
        with patch.object(doctor, "host_cpu", return_value=emerald):
            for backend in ("kvm", "mshv", "whp"):
                result = doctor.check_cpu(doctor_context(self.root, backend))
                self.assertTrue(result.passed, result.detail)
                self.assertIn("profile=intel.emeraldrapids.v1", result.detail)
        # The host OS's invariant-TSC flags are evidence, never a gate.
        variant = dict(CPU, invariant_tsc="no (missing nonstop_tsc)")
        with patch.object(doctor, "host_cpu", return_value=variant):
            for backend in ("kvm", "mshv", "whp"):
                context = doctor_context(self.root, backend)
                result = doctor.check_cpu(context)
                self.assertTrue(result.passed, result.detail)
                self.assertIn("invariant_tsc=no (missing nonstop_tsc)", result.detail)
                self.assertEqual(
                    context.facts["invariant_tsc"], "no (missing nonstop_tsc)"
                )

    def test_cpu_check_verifies_the_profile_with_openvmm_fingerprint(self):
        fingerprint = self.root / "out" / "fingerprint.json"

        def context_with_openvmm(backend: str = "kvm") -> doctor.DoctorContext:
            context = doctor_context(self.root, backend)
            context.openvmm.write_bytes(b"")
            context.fingerprint = fingerprint
            return context

        def check(
            result: subprocess.CompletedProcess[str],
            cpu: dict[str, str] = CPU,
            backend: str = "kvm",
        ) -> tuple[doctor.CheckResult, doctor.DoctorContext]:
            context = context_with_openvmm(backend)
            with (
                patch.object(doctor, "host_cpu", return_value=dict(cpu)),
                patch.object(doctor.subprocess, "run", return_value=result),
            ):
                return doctor.check_cpu(context), context

        context = context_with_openvmm()
        with (
            patch.object(doctor, "host_cpu", return_value=dict(CPU)),
            patch.object(
                doctor.subprocess, "run", return_value=completed("", 0, PROFILE_PASS)
            ) as run,
        ):
            result = doctor.check_cpu(context)
        self.assertTrue(result.passed, result.detail)
        self.assertEqual(
            run.call_args.args[0],
            [
                str(context.openvmm),
                "--hypervisor",
                "kvm",
                "--cpu-fingerprint",
                str(fingerprint),
            ],
        )
        self.assertEqual(run.call_args.kwargs["env"]["OPENVMM_LOG"], "off")
        self.assertTrue(fingerprint.parent.is_dir())
        self.assertIn("surface_digest=sha256:6286956acbef", result.detail)
        self.assertEqual(context.facts["profile"], "intel.icelake-sp.v1")
        self.assertEqual(context.facts["profile_digest"], f"sha256:{'a3' * 32}")
        self.assertEqual(context.facts["surface_digest"], "sha256:6286956acbef")
        # A later revision of the generation's profile is fine.
        revised = PROFILE_PASS.replace("icelake-sp.v1", "icelake-sp.v2")
        self.assertTrue(check(completed("", 0, revised))[0].passed)

        unsupported = (
            "NVX-CPU-PROFILE: status=fail backend=whp generation=icelake-sp "
            "profile=intel.icelake-sp.v1 profile_digest=sha256:a3 "
            "surface_digest=sha256:d67f host_invariant_tsc=no "
            'code=E_PROFILE_UNSUPPORTED detail="CPUID 0x7.0 EDX bits 26, 27 are '
            'not supported; leaf \\"7\\"\\u{a0}subleaf"\n'
        )
        result, context = check(completed("", 1, unsupported), backend="whp")
        self.assertFalse(result.passed)
        self.assertTrue(
            result.detail.startswith(
                "[E_PROFILE_UNSUPPORTED] OpenVMM's CPU profile check failed (exit 1): "
                'CPUID 0x7.0 EDX bits 26, 27 are not supported; leaf "7"\xa0subleaf;'
            ),
            result.detail,
        )
        unknown = (
            "NVX-CPU-PROFILE: status=fail backend=kvm generation=none profile=none "
            "surface_digest=sha256:1 host_invariant_tsc=yes "
            'code=E_PROFILE_HOST_UNKNOWN detail="GenuineIntel family 6 model 143"\n'
        )
        result, context = check(completed("", 1, unknown), dict(CPU, model="143"))
        self.assertFalse(result.passed)
        self.assertTrue(result.detail.startswith("[E_PROFILE_HOST_UNKNOWN] "))
        self.assertIn("[E_PROFILE_HOST_UNKNOWN] OpenVMM's CPU profile", result.detail)
        self.assertEqual(context.facts["profile"], "none")
        for output, message in (
            (
                completed("", 2, "error: unexpected argument '--cpu-fingerprint'"),
                "predates the --cpu-fingerprint tool",
            ),
            (completed("", 1, "fatal error: no backend"), "fatal error: no backend"),
            (
                completed("", 0, PROFILE_PASS.replace("=kvm", "=mshv")),
                "fingerprinted the mshv backend",
            ),
            (
                completed(
                    "",
                    0,
                    PROFILE_PASS.replace(
                        "generation=icelake-sp", "generation=emeraldrapids"
                    ),
                ),
                "generation emeraldrapids, not icelake-sp",
            ),
            (
                completed(
                    "", 0, PROFILE_PASS.replace("intel.icelake", "intel.skylake")
                ),
                "profile intel.skylake-sp.v1, not a revision",
            ),
        ):
            with self.subTest(message=message):
                result = check(output)[0]
                self.assertFalse(result.passed)
                self.assertIn(message, result.detail)
        missing = doctor_context(self.root / "none")
        missing.fingerprint = fingerprint
        with patch.object(doctor, "host_cpu", return_value=dict(CPU)):
            result = doctor.check_cpu(missing)
        self.assertFalse(result.passed)
        self.assertIn("was not found", result.detail)
        self.assertIn("--no-openvmm", result.detail)
        # Without OpenVMM, H2 checks the identity and generation only.
        with (
            patch.object(doctor, "host_cpu", return_value=dict(CPU)),
            patch.object(doctor.subprocess, "run") as run,
        ):
            result = doctor.check_cpu(doctor_context(self.root))
        self.assertTrue(result.passed)
        self.assertIn("CPU profile not checked", result.detail)
        run.assert_not_called()

    def test_reads_the_first_processor_from_cpuinfo(self):
        path = self.root / "cpuinfo"
        path.write_text(
            "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
            "model\t\t: 85\nstepping\t: 4\nmicrocode\t: 0x2007108\n"
            "flags\t\t: fpu tsc constant_tsc nonstop_tsc\n\n"
            "processor\t: 1\nvendor_id\t: Other\n",
            encoding="utf-8",
        )
        fields = doctor._linux_cpuinfo(path)  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(fields["vendor_id"], "GenuineIntel")
        self.assertEqual(fields["model"], "85")
        self.assertIn("nonstop_tsc", fields["flags"])

    def test_preflight_parses_openvmm_verification(self):
        # The line format of OpenVMM's openvmm_entry verify.rs.
        line = (
            "NVX-TIME-ABI-VERIFY: v=1 status=ok backend=kvm "
            "cpu_profile=intel.icelake-sp.v1 tsc_hz=2793437000 "
            "native_tsc_hz=2793437000 lapic_hz=1000000000 msr_route=ExitToVmm "
            "sync=CommonOffset\n"
        )

        def context_with_files(backend: str = "kvm") -> doctor.DoctorContext:
            context = doctor_context(self.root, backend)
            for path in (context.openvmm, context.kernel, context.initrd):
                path.write_bytes(b"")
            return context

        context = context_with_files()
        with patch.object(
            doctor.subprocess, "run", return_value=completed(line)
        ) as run:
            result = doctor.check_openvmm_preflight(context)
        self.assertTrue(result.passed, result.detail)
        self.assertEqual(context.facts["native_tsc_hz"], "2793437000")
        self.assertEqual(context.facts["profile"], "intel.icelake-sp.v1")
        command = run.call_args.args[0]
        self.assertEqual(command[-1], "--x-time-abi-verify")
        self.assertNotIn("--x-time-abi-v1", command)
        self.assertEqual(command[command.index("--kernel") + 1], str(context.kernel))
        switched = context_with_files()
        switched.openvmm_args = ("--x-time-abi-v1",)
        with patch.object(
            doctor.subprocess, "run", return_value=completed(line)
        ) as run:
            self.assertTrue(doctor.check_openvmm_preflight(switched).passed)
        self.assertEqual(
            run.call_args.args[0][-2:], ["--x-time-abi-v1", "--x-time-abi-verify"]
        )
        failure = (
            "NVX-TIME-ABI-VERIFY: v=1 status=fail backend=kvm "
            'code=E_TSC_SYNC_UNSUPPORTED detail="failed: \\"sync\\" unsupported"\n'
        )
        cases = (
            (
                completed(failure, 1),
                '[E_TSC_SYNC_UNSUPPORTED] OpenVMM verification failed (exit 1): failed: "sync" unsupported',
            ),
            (
                completed("", 2, "error: unexpected argument '--x-time-abi-v1' found"),
                "predates the time ABI",
            ),
            (completed(line.replace("1000000000", "200000000")), "[E_LAPIC_RATE_"),
            (
                completed(line.replace("tsc_hz=2793437000", "tsc_hz=4000", 1)),
                "[E_TSC_RATE_",
            ),
            (
                completed(line.replace("backend=kvm", "backend=mshv")),
                "verified backend mshv",
            ),
        )
        for result_value, message in cases:
            with self.subTest(message=message):
                with patch.object(doctor.subprocess, "run", return_value=result_value):
                    result = doctor.check_openvmm_preflight(context_with_files())
                self.assertFalse(result.passed)
                self.assertIn(message, result.detail)
        for selected, passed in (
            ("intel.icelake-sp.v2", True),
            ("intel.skylake-sp.v1", False),
            # OpenVMM selects catalog profiles, so an interim one is a regression.
            ("interim.host.kvm.v1", False),
        ):
            with self.subTest(selected=selected):
                context = context_with_files()
                context.facts["profile"] = "intel.icelake-sp.v1"
                output = line.replace("intel.icelake-sp.v1", selected)
                with patch.object(
                    doctor.subprocess, "run", return_value=completed(output)
                ):
                    result = doctor.check_openvmm_preflight(context)
                self.assertEqual(result.passed, passed, result.detail)
                self.assertEqual(context.facts["profile"], selected)
        missing = doctor.check_openvmm_preflight(doctor_context(self.root / "none"))
        self.assertFalse(missing.passed)
        self.assertIn("was not found", missing.detail)

    def test_rate_check_gates_on_stability_and_the_backend_rate_only(self):
        def records(first: float, second: float):
            return [
                ("rate", {"tsc_hz": f"{first:.3f}"}),
                ("rate", {"tsc_hz": f"{second:.3f}"}),
            ]

        def check(
            context: doctor.DoctorContext,
            probe_records: list[tuple[str, dict[str, str]]],
            clocksource: str = "tsc",
            windows: bool = False,
        ) -> doctor.CheckResult:
            with (
                patch.object(doctor, "run_probe", return_value=probe_records),
                patch.object(doctor, "host_clocksource", return_value=clocksource),
                patch.object(doctor, "host_is_windows", return_value=windows),
            ):
                return doctor.check_rate(context)

        context = doctor_context(self.root)
        context.facts["tsc_hz"] = "2793437000"
        result = check(context, records(2793437500, 2793437800))
        self.assertTrue(result.passed, result.detail)
        self.assertIn("host clocksource tsc (evidence)", result.detail)
        for probe_records, message in (
            (records(2793437000, 2793440000), "unstable"),
            (records(2794000000, 2794000001), "ppm from the measured"),
        ):
            with self.subTest(message=message):
                context = doctor_context(self.root)
                context.facts["tsc_hz"] = "2793437000"
                result = check(context, probe_records)
                self.assertFalse(result.passed)
                self.assertIn(message, result.detail)
        # The clocksource is evidence on every backend.
        for backend, clocksource in (
            ("kvm", "hpet"),
            ("mshv", "hyperv_clocksource_tsc_page"),
        ):
            with self.subTest(backend=backend, clocksource=clocksource):
                context = doctor_context(self.root, backend)
                context.facts["native_tsc_hz"] = "2300000000"
                result = check(context, records(2300000100, 2300000200), clocksource)
                self.assertTrue(result.passed, result.detail)
                self.assertIn(
                    f"host clocksource {clocksource} (evidence)", result.detail
                )
                self.assertEqual(context.facts["host_clocksource"], clocksource)
        windows = check(
            doctor_context(self.root, "whp"),
            records(2300000100, 2300000200),
            windows=True,
        )
        self.assertTrue(windows.passed, windows.detail)
        self.assertNotIn("clocksource", windows.detail)
        # Without H3 (validate-runner), H4 still checks stability.
        standalone = check(doctor_context(self.root), records(2300000100, 2300000200))
        self.assertTrue(standalone.passed, standalone.detail)
        self.assertIn("not compared with the backend's rate", standalone.detail)
        unstable = check(doctor_context(self.root), records(2300000100, 2300009100))
        self.assertFalse(unstable.passed)
        self.assertIn("unstable", unstable.detail)

    def test_host_skew_check_applies_the_bound(self):
        summary = {
            "pairs": "28",
            "cpus": "0-7",
            "max_abs_offset_ns": "40",
            "max_uncertainty_ns": "120",
            "stalled_pairs": "0",
            "conclusive": "1",
        }
        context = doctor_context(self.root)
        context.facts["measured_tsc_hz"] = "2793437000"
        with patch.object(doctor, "run_probe", return_value=[("skew", summary)]) as run:
            self.assertTrue(doctor.check_host_skew(context).passed)
        self.assertIn("--tsc-hz", run.call_args.args)
        for changes, message in (
            ({"max_abs_offset_ns": "1500"}, "exceeds 1000"),
            ({"stalled_pairs": "2", "conclusive": "0"}, "2 CPU pair(s) stalled"),
            ({"conclusive": "0"}, "inconclusive"),
        ):
            with (
                self.subTest(message=message),
                patch.object(
                    doctor, "run_probe", return_value=[("skew", summary | changes)]
                ),
            ):
                result = doctor.check_host_skew(doctor_context(self.root))
                self.assertFalse(result.passed)
                self.assertIn(message, result.detail)

    def test_guest_warp_check_runs_the_idle_schedule_and_applies_the_bound(self):
        context = doctor_context(self.root)
        for path in (context.openvmm, context.kernel, context.initrd):
            path.write_bytes(b"")
        boot = (
            BOOT_LINE.replace("cpus=4", "cpus=8") + " ALPINE-MICROVM-BOOT-OK: 3.22.1\n"
        )
        text = boot + warp_output(pairs=28) + warp_output(pairs=28, offset=60)
        with (
            patch.object(doctor.os, "cpu_count", return_value=8),
            patch.object(
                doctor, "run_guest_script", return_value={"text": text}
            ) as run,
        ):
            result = doctor.check_guest_warp(context)
        self.assertTrue(result.passed, result.detail)
        self.assertIn("rounds=2 idle_s=1", result.detail)
        self.assertEqual(context.facts["guest_warp_ns"], "60")
        command, script, marker = run.call_args.args
        self.assertEqual(command[command.index("--processors") + 1], "8")
        self.assertEqual(script, time_abi.warp_probe_script() + "nvx-exit 0\n")
        self.assertEqual(marker, time_abi.WARP_PROBE_COMPLETION_MARKER)
        cases = (
            (boot + warp_output(pairs=28), "ran 1 rounds instead of 2"),
            (
                boot + warp_output(pairs=28) + warp_output(pairs=28, offset=1500),
                "in round 2: max_abs_offset_ns=1500",
            ),
            (warp_output(pairs=28) * 2, "NVX-TIME-ABI boot marker"),
        )
        for output, message in cases:
            with (
                self.subTest(message=message),
                patch.object(doctor.os, "cpu_count", return_value=8),
                patch.object(doctor, "run_guest_script", return_value={"text": output}),
            ):
                result = doctor.check_guest_warp(context)
                self.assertFalse(result.passed)
                self.assertIn("vcpus=8", result.detail)
                self.assertIn(message, result.detail)
        missing = doctor.check_guest_warp(doctor_context(self.root / "missing"))
        self.assertIn("OpenVMM was not found", missing.detail)

    def test_utc_check_reads_the_host_clock_discipline(self):
        context = doctor_context(self.root)
        with patch.object(doctor, "host_is_windows", return_value=False):
            with patch.object(doctor, "_linux_clock_state", return_value=(0, 0x2001)):
                self.assertTrue(doctor.check_utc(context).passed)
            with patch.object(doctor, "_linux_clock_state", return_value=(5, 0x0041)):
                self.assertIn("STA_UNSYNC", doctor.check_utc(context).detail)
        status = (
            "Leap Indicator: 0(no warning)\nStratum: 2\n"
            "Source: VM IC Time Synchronization Provider\n"
        )
        with (
            patch.object(doctor, "host_is_windows", return_value=True),
            patch.object(doctor.subprocess, "run", return_value=completed(status)),
        ):
            result = doctor.check_utc(context)
        self.assertTrue(result.passed, result.detail)
        self.assertIn("VM IC Time Synchronization Provider", result.detail)
        for unsynchronized in (
            status.replace("0(no warning)", "3(not synchronized)"),
            "Leap Indicator: 0\nSource: Local CMOS Clock\n",
        ):
            with (
                patch.object(doctor, "host_is_windows", return_value=True),
                patch.object(
                    doctor.subprocess, "run", return_value=completed(unsynchronized)
                ),
            ):
                self.assertFalse(doctor.check_utc(context).passed)

    def test_run_prints_lines_writes_the_summary_and_fails_closed(self):
        def passing(check: str):
            def run_check(context: doctor.DoctorContext) -> doctor.CheckResult:
                context.facts["generation"] = "emeraldrapids"
                return doctor.CheckResult(check, True, f"{check} ok")

            return run_check

        def broken(context: doctor.DoctorContext) -> doctor.CheckResult:
            del context
            raise doctor.ScriptError("rustc is required to build the host time probe")

        summary = self.root / "summary.md"
        arguments = doctor_parser().parse_args(
            [
                "--backend",
                "mshv",
                "--checks",
                "H5",
                "H2",
                "--summary",
                str(summary),
                "--probe-dir",
                str(self.root),
            ]
        )
        stdout = io.StringIO()
        with (
            patch.dict(doctor.CHECKS, {"H2": passing("H2"), "H5": passing("H5")}),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(doctor.run(arguments), 0)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(
            [line.split()[1] for line in lines if line.startswith("NVX-DOCTOR")],
            ["check=H2", "check=H5"],
        )
        self.assertIn("passed; generation emeraldrapids", lines[-1])
        self.assertIn("(mshv): passed", summary.read_text(encoding="utf-8"))
        with (
            patch.dict(doctor.CHECKS, {"H2": passing("H2"), "H5": broken}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(doctor.run(arguments), 1)
        text = summary.read_text(encoding="utf-8")
        self.assertIn("**fail** | rustc is required", text)
        self.assertIn("Generation: `emeraldrapids`", text)

    def test_run_selects_the_cpu_fingerprint_or_runs_without_openvmm(self):
        seen: list[Path | None] = []

        def cpu(context: doctor.DoctorContext) -> doctor.CheckResult:
            seen.append(context.fingerprint)
            context.facts["surface_digest"] = "sha256:62"
            return doctor.CheckResult("H2", True, "ok")

        summary = self.root / "summary.md"
        common = ["--backend", "kvm", "--checks", "H2", "--summary", str(summary)]
        common += ["--probe-dir", str(self.root)]
        with (
            patch.dict(doctor.CHECKS, {"H2": cpu}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for extra in (
                [],
                ["--cpu-fingerprint", str(self.root / "fingerprint.json")],
                ["--no-openvmm"],
            ):
                arguments = doctor_parser().parse_args([*common, *extra])
                self.assertEqual(doctor.run(arguments), 0)
        self.assertEqual(
            seen,
            [
                self.root / "nvx-cpu-fingerprint-kvm.json",
                self.root / "fingerprint.json",
                None,
            ],
        )
        self.assertIn("CPU surface digest: `sha256:62`", summary.read_text("utf-8"))
        arguments = doctor_parser().parse_args(["--backend", "kvm", "--no-openvmm"])
        with self.assertRaisesRegex(doctor.ScriptError, "cannot run H3 and H6"):
            doctor.run(arguments)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            doctor_parser().parse_args(
                ["--backend", "kvm", "--no-openvmm", "--cpu-fingerprint", "x"]
            )

    def test_builds_the_host_probe_once_per_source_version(self):
        target = doctor.probe_path(self.root)
        self.assertRegex(target.name, r"^nvx-host-time-probe-[0-9a-f]{16}(\.exe)?$")

        def rustc(command: list[str], **_kwargs: object):
            Path(command[command.index("-o") + 1]).write_bytes(b"probe")
            return completed("")

        with patch.object(doctor.shutil, "which", return_value=None):
            with self.assertRaisesRegex(doctor.ScriptError, "rustc is required"):
                doctor.build_probe(self.root)
        with (
            patch.object(doctor.shutil, "which", return_value="rustc"),
            patch.object(doctor.subprocess, "run", side_effect=rustc) as run,
        ):
            self.assertEqual(doctor.build_probe(self.root), target)
            self.assertEqual(doctor.build_probe(self.root), target)
        run.assert_called_once()
        self.assertEqual(target.read_bytes(), b"probe")
        target.unlink()
        with (
            patch.object(doctor.shutil, "which", return_value="rustc"),
            patch.object(
                doctor.subprocess, "run", return_value=completed("", 1, "error[E0425]")
            ),
        ):
            with self.assertRaisesRegex(doctor.ScriptError, "E0425"):
                doctor.build_probe(self.root)

    def test_parses_probe_records(self):
        context = doctor_context(self.root)
        context.probe = self.root / "probe.exe"
        output = (
            "noise\nNVX-HOST-TIME-PROBE rate index=1 tsc_hz=1.5\n"
            "NVX-HOST-TIME-PROBE skew pairs=1 cpus=0-1\n"
        )
        with patch.object(doctor.subprocess, "run", return_value=completed(output)):
            records = doctor.run_probe(context, "skew")
        self.assertEqual(
            records,
            [
                ("rate", {"index": "1", "tsc_hz": "1.5"}),
                ("skew", {"pairs": "1", "cpus": "0-1"}),
            ],
        )
        with patch.object(
            doctor.subprocess, "run", return_value=completed("", 3, "no CPU")
        ):
            with self.assertRaisesRegex(doctor.ScriptError, "skew failed: no CPU"):
                doctor.run_probe(context, "skew")


def doctor_parser():
    import argparse

    parser = argparse.ArgumentParser()
    doctor.configure_parser(parser)
    return parser


if __name__ == "__main__":
    unittest.main()
