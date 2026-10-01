"""Unit tests for the harness-side NVX time ABI checks and host qualification."""

from __future__ import annotations

import queue
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nvx_tools import benchmark, openvmm_process, time_abi  # noqa: E402
from nvx_tools.time_abi import TimeAbiFailure, TimeAbiMonitor  # noqa: E402

BOOT_LINE = (
    "NVX-TIME-ABI: v=1 phase=boot status=ok cpus=4 tsc_hz=2194804000 "
    "lapic_hz=1000000000 generation=0 elapsed_us=1873\n"
)
KVM_BOOT = ["openvmm", "--hypervisor", "kvm", "--kernel", "vmlinux"]
MSHV_RESTORE = ["openvmm", "--hypervisor", "mshv", "--restore-snapshot", "snap"]


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
        self.assertEqual(time_abi.cpu_generation("GenuineIntel", 6, 85), "skylake-sp")
        self.assertEqual(time_abi.cpu_generation("GenuineIntel", 6, 106), "icelake-sp")
        self.assertEqual(
            time_abi.cpu_generation("GenuineIntel", 6, 207), "emeraldrapids"
        )
        self.assertIsNone(time_abi.cpu_generation("GenuineIntel", 6, 143))
        self.assertIsNone(time_abi.cpu_generation("AuthenticAMD", 25, 1))


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


if __name__ == "__main__":
    unittest.main()
