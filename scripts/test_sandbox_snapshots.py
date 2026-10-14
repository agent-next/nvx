"""Regression oracles for the snapshot/processors configuration rewrite."""
# pyright: reportPrivateUsage=false

import dataclasses
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))
import nvx  # noqa: E402
from nvx_tools import sandbox  # noqa: E402
from nvx_tools import sandbox_lifecycle as lifecycle  # noqa: E402
from nvx_tools.common import ScriptError  # noqa: E402


class SandboxSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.layer = self.root / "layer.erofs"
        self.scratch = self.root / "scratch.ext4"
        self.layer.touch()
        self.scratch.touch()
        self.launch = sandbox.SandboxLaunch(
            layers=(
                sandbox.SandboxLayer(
                    "distro", self.layer, "11111111-1111-1111-1111-111111111111"
                ),
            ),
            scratch=self.scratch,
        )
        self.options: dict[str, Any] = dict(
            hypervisor="kvm",
            memory_mib=128,
            net=None,
            network_profile=None,
            network_egress=None,
            network_ingress=None,
            network_egress_allow=(),
            network_egress_deny=(),
            host_loopback=None,
            network_proxy=None,
            host_loopback_forward=(),
            cmdline="quiet",
        )

    def config(
        self, launch: sandbox.SandboxLaunch | None = None, **options: Any
    ) -> dict[str, Any]:
        return lifecycle._serialize_launch(
            self.launch if launch is None else launch, **self.options, **options
        )

    def test_legacy_default_keeps_format_one(self):
        config = self.config()
        self.assertEqual(config["format"], 1)
        self.assertNotIn("processors", config)
        self.assertEqual(lifecycle._deserialize_launch(config).processors, 1)

    def test_processors_use_new_format_not_upstream_owner_format(self):
        for count in (2, 4, 8):
            launch = dataclasses.replace(self.launch, processors=count)
            config = self.config(launch)
            self.assertEqual(config["format"], 7)
            self.assertEqual(config["mounts"], [])
            self.assertEqual(lifecycle._deserialize_launch(config).processors, count)
            arguments = launch.openvmm_arguments()
            self.assertEqual(arguments[arguments.index("--processors") + 1], str(count))
        for count in (0, 3, True, "2"):
            with self.assertRaises(ScriptError):
                dataclasses.replace(self.launch, processors=count)

    @unittest.skipUnless(os.name == "posix", "caller-owned mounts require POSIX")
    def test_format_seven_preserves_file_and_mount_policy(self):
        share = self.root / "share"
        share.mkdir()
        file = self.root / "file"
        file.touch()
        mounts = (
            sandbox.SandboxMount("/data", share, "rw", owner="caller"),
            sandbox.SandboxMount("/single", file, "ro", owner="caller", kind="file"),
        )
        launch = dataclasses.replace(self.launch, mounts=mounts, processors=2)
        config = self.config(launch)
        decoded = lifecycle._deserialize_launch(config)
        self.assertEqual(decoded.mounts, mounts)
        self.assertEqual(config["mounts"][1]["kind"], "file")
        self.assertEqual(decoded.processors, 2)

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_capture_arms_pre_handoff_trigger_and_instance_tier(self):
        destination = self.root / "snapshot"
        config = self.config(snapshot_destination=destination)
        self.assertEqual(config["format"], 7)
        launch = lifecycle._deserialize_launch(config)
        self.assertIn("sandboxsnap", launch.kernel_command_line())
        self.assertEqual(lifecycle.SNAPSHOT_CAPTURE_TIER, "instance-checkpoint")

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_does_not_redeclare_paired_scratch_or_identity(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        launch = lifecycle._deserialize_launch(self.config(restore_snapshot=snapshot))
        arguments = launch.openvmm_arguments(restore=True)
        self.assertNotIn("--microvm-workload-identity", arguments)
        self.assertFalse(any("scratch:file:" in value for value in arguments))
        self.assertNotIn("sandboxsnap", launch.kernel_command_line())
        self.assertIn(f"distro:file:{self.layer},ro", arguments)

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_uses_paired_scratch_without_original_image(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        self.scratch.unlink()
        args = nvx.parse_args(
            [
                "sandbox",
                "provision",
                "--state-dir",
                str(self.root / "state"),
                "--layer",
                f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                "--restore-snapshot",
                str(snapshot),
            ]
        )
        with patch.object(lifecycle, "provision") as provision:
            nvx.command_sandbox(args)
        launch = provision.call_args.args[1]
        self.assertEqual(launch.scratch, snapshot / "scratch.img")
        config = self.config(restore_snapshot=snapshot)
        lifecycle._deserialize_launch(config)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and mode checks")
    def test_namespace_rejects_public_parent_symlink_and_existing_destination(self):
        public = self.root / "public"
        public.mkdir(mode=0o755)
        with self.assertRaisesRegex(ScriptError, "0700"):
            lifecycle.snapshot_paths({"snapshot_destination": str(public / "snap")})
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ScriptError, "plain directory"):
            lifecycle.snapshot_paths({"snapshot_destination": str(link / "snap")})
        existing = self.root / "snap"
        existing.mkdir()
        with self.assertRaisesRegex(ScriptError, "already exists"):
            lifecycle.snapshot_paths({"snapshot_destination": str(existing)})
        with self.assertRaisesRegex(ScriptError, "mutually exclusive"):
            lifecycle.snapshot_paths(
                {
                    "snapshot_destination": str(self.root / "new"),
                    "restore_snapshot": str(existing),
                }
            )

    def test_cli_rejects_snapshot_options_on_nonlaunch_operations(self):
        for option in ("--processors", "--snapshot-destination", "--restore-snapshot"):
            value = "2" if option == "--processors" else str(self.root / "snap")
            with self.assertRaisesRegex(ScriptError, "only valid"):
                nvx.command_sandbox(nvx.parse_args(["sandbox", "start", option, value]))

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_capture_returns_with_no_live_runtime_record(self):
        destination = self.root / "snap"
        state = self.root / "state"
        lifecycle.provision(
            state,
            self.launch,
            **self.options,
            timeout=10,
            snapshot_destination=destination,
        )
        process = MagicMock()
        process.poll.return_value = 0

        def captured(timeout: float) -> int:
            destination.mkdir()
            for name in ("manifest.bin", "state.bin", "memory.bin", "scratch.img"):
                (destination / name).touch()
            return 0

        process.wait.side_effect = captured
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process) as popen,
            patch.object(lifecycle.ControlSession, "connect") as connect,
        ):
            lifecycle.start(state, 10)
        connect.assert_not_called()
        command = popen.call_args.args[0]
        self.assertEqual(
            command[command.index("--snapshot-tier") + 1], "instance-checkpoint"
        )
        self.assertFalse((state / lifecycle.RUNTIME_NAME).exists())
        self.assertFalse((state / lifecycle.CAPABILITY_NAME).exists())
        lifecycle.deprovision(state, 10)
        self.assertTrue(destination.exists())

    @unittest.skipUnless(os.name == "posix", "Unix control socket namespace")
    def test_restore_command_uses_snapshot_and_external_control_namespace(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        state = self.root / "state"
        lifecycle.provision(
            state,
            self.launch,
            **self.options,
            timeout=10,
            restore_snapshot=snapshot,
        )
        process = MagicMock()
        process.pid = 123
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process) as popen,
            patch.object(lifecycle, "_process_start_time", return_value=456),
            patch.object(lifecycle.ControlSession, "connect"),
        ):
            lifecycle.start(state, 10)
        command = popen.call_args.args[0]
        for forbidden in (
            "--cmdline",
            "--kernel",
            "--initrd",
            "--memory",
            "--microvm-lifecycle",
        ):
            self.assertNotIn(forbidden, command)
        self.assertNotIn("--restore-entropy", command)
        runtime = json.loads((state / lifecycle.RUNTIME_NAME).read_text())
        self.assertEqual(
            runtime["control_endpoint"], str(self.root / "snapshot.control.sock")
        )

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_empty_capture_publication_is_not_success(self):
        destination = self.root / "snap"
        state = self.root / "state"
        lifecycle.provision(
            state,
            self.launch,
            **self.options,
            timeout=10,
            snapshot_destination=destination,
        )
        process = MagicMock()
        process.poll.return_value = 0

        def empty_capture(timeout: float) -> int:
            destination.mkdir()
            return 0

        process.wait.side_effect = empty_capture
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process),
            self.assertRaisesRegex(ScriptError, "complete instance checkpoint"),
        ):
            lifecycle.start(state, 10)
        self.assertFalse((state / lifecycle.RUNTIME_NAME).exists())
        self.assertFalse((state / lifecycle.CAPABILITY_NAME).exists())

    def test_windows_explicitly_rejects_snapshot_options(self):
        for option in ("snapshot_destination", "restore_snapshot"):
            with (
                patch.object(lifecycle, "os", wraps=os) as platform_os,
                self.assertRaisesRegex(ScriptError, "unsupported on Windows"),
            ):
                platform_os.name = "nt"
                lifecycle.snapshot_paths({option: str(self.root / "snap")})

    def test_cli_rejects_one_shot_capture(self):
        with self.assertRaisesRegex(ScriptError, "only valid for sandbox provision"):
            nvx.command_sandbox(
                nvx.parse_args(
                    [
                        "sandbox",
                        "run",
                        "--snapshot-destination",
                        str(self.root / "snap"),
                        "--layer",
                        f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                        "--scratch",
                        str(self.scratch),
                        "--dry-run",
                    ]
                )
            )

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_rejects_explicit_workload_and_machine_overrides(self):
        snapshot = self.root / "snap"
        snapshot.mkdir()
        for option, value in (
            ("--memory-mib", "256"),
            ("--processors", "1"),
            ("--cmdline", ""),
            ("--entrypoint", "/bin/sh"),
            ("--arg", "hello"),
            ("--hostname", "nvx-sandbox"),
            ("--memory-max", "64"),
            ("--pids-max", "3"),
            ("--workload-user", "65534:65534"),
            ("--scratch", str(self.scratch)),
        ):
            with (
                self.subTest(option=option),
                self.assertRaisesRegex(ScriptError, "from the snapshot"),
            ):
                nvx.command_sandbox(
                    nvx.parse_args(
                        [
                            "sandbox",
                            "provision",
                            "--restore-snapshot",
                            str(snapshot),
                            "--state-dir",
                            str(self.root / "state"),
                            "--layer",
                            f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                            option,
                            value,
                        ]
                    )
                )

    def test_restore_never_redeclares_processors(self):
        launch = dataclasses.replace(self.launch, processors=8)
        self.assertNotIn("--processors", launch.openvmm_arguments(restore=True))

    def test_snapshot_trigger_token_is_reserved(self):
        with self.assertRaisesRegex(ScriptError, "owned by the sandbox profile"):
            self.launch.kernel_command_line("quiet sandboxsnap")

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_is_not_retried_after_transport_or_endpoint_failure(self):
        snapshot = self.root / "snap"
        snapshot.mkdir()
        state = self.root / "state"
        lifecycle.provision(
            state, self.launch, **self.options, timeout=10, restore_snapshot=snapshot
        )
        for error in (
            TimeoutError("control endpoint did not become available"),
            BrokenPipeError("first restore failure"),
            ConnectionResetError("first restore failure"),
        ):
            with (
                patch.object(lifecycle, "_start_once", side_effect=error) as start,
                self.assertRaises(type(error)),
            ):
                lifecycle.start(state, 10)
            self.assertEqual(start.call_count, 1)
            self.assertEqual(start.call_args.args, (state, 10))
            self.assertNotIn("endpoint_wait_s", start.call_args.kwargs)

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_capture_timeout_is_a_script_error(self):
        state = self.root / "state"
        lifecycle.provision(
            state,
            self.launch,
            **self.options,
            timeout=10,
            snapshot_destination=self.root / "snap",
        )
        process = MagicMock()
        process.poll.return_value = 0
        process.wait.side_effect = subprocess.TimeoutExpired("openvmm", 10)
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process),
            patch.object(lifecycle, "_end_failed_start", return_value=0),
            self.assertRaisesRegex(ScriptError, "capture.*timed out.*10"),
        ):
            lifecycle.start(state, 10)
        self.assertFalse((state / lifecycle.CAPABILITY_NAME).exists())

    @unittest.skipUnless(os.name == "posix", "Unix control socket namespace")
    def test_sibling_snapshots_have_independent_sockets_and_cleanup(self):
        states: list[Path] = []
        endpoints: list[Path] = []
        process = MagicMock()
        process.pid = 123

        def launch(command: list[str], **_options: Any) -> MagicMock:
            if os.name != "posix":
                self.skipTest("Unix control sockets require POSIX")
            endpoint = Path(command[command.index("--microvm-control-console") + 1][7:])
            listener = socket.socket(socket.AF_UNIX)
            self.addCleanup(listener.close)
            listener.bind(str(endpoint))
            endpoints.append(endpoint)
            return process

        for name in ("a", "b"):
            snapshot = self.root / name
            snapshot.mkdir()
            state = self.root / f"state-{name}"
            states.append(state)
            lifecycle.provision(
                state,
                self.launch,
                **self.options,
                timeout=10,
                restore_snapshot=snapshot,
            )
            with (
                patch.object(lifecycle, "require_file", side_effect=self.require),
                patch.object(lifecycle.subprocess, "Popen", side_effect=launch),
                patch.object(lifecycle, "_process_start_time", return_value=456),
                patch.object(lifecycle.ControlSession, "connect"),
            ):
                lifecycle.start(state, 10)
        self.assertNotEqual(endpoints[0], endpoints[1])
        with patch.object(lifecycle, "_process_running", return_value=False):
            lifecycle.deprovision(states[0], 10)
        self.assertFalse(endpoints[0].exists())
        self.assertTrue(endpoints[1].exists())
        with (
            patch.object(lifecycle, "_process_running", side_effect=[True, False]),
            patch.object(lifecycle.ControlSession, "connect"),
            patch.object(lifecycle, "_read_openvmm_outcome", return_value={}),
        ):
            lifecycle.stop(states[1], 10)
            lifecycle.deprovision(states[1], 10)
        self.assertFalse(endpoints[1].exists())
        self.assertFalse(list(self.root.glob("*.control.sock.lock")))

    @unittest.skipUnless(os.name == "posix", "Unix control socket namespace")
    def test_endpoint_collision_is_rejected_before_process_launch(self):
        if os.name != "posix":
            self.skipTest("Unix control sockets require POSIX")
        for kind in ("socket", "reservation"):
            state = self.root / f"state-{kind}"
            snapshot = self.root / kind
            snapshot.mkdir()
            lifecycle.provision(
                state,
                self.launch,
                **self.options,
                timeout=10,
                restore_snapshot=snapshot,
            )
            endpoint = self.root / f"{kind}.control.sock"
            if kind == "socket":
                listener = socket.socket(socket.AF_UNIX)
                self.addCleanup(listener.close)
                listener.bind(str(endpoint))
            else:
                Path(f"{endpoint}.lock").touch()
            with (
                patch.object(lifecycle, "require_file", side_effect=self.require),
                patch.object(lifecycle.subprocess, "Popen") as popen,
                self.assertRaisesRegex(ScriptError, "control endpoint"),
            ):
                lifecycle.start(state, 10)
            popen.assert_not_called()
            self.assertFalse((state / lifecycle.CAPABILITY_NAME).exists())

    @unittest.skipUnless(os.name == "posix", "Unix control socket ownership")
    def test_stale_deprovision_preserves_replaced_socket_or_regular_file(self):
        if os.name != "posix":
            self.skipTest("Unix control sockets require POSIX")
        for replacement in ("socket", "file", "owner"):
            with self.subTest(replacement=replacement):
                snapshot = self.root / replacement
                snapshot.mkdir()
                state = self.root / f"state-{replacement}"
                lifecycle.provision(
                    state,
                    self.launch,
                    **self.options,
                    timeout=10,
                    restore_snapshot=snapshot,
                )
                endpoint = self.root / f"{replacement}.control.sock"
                listener = socket.socket(socket.AF_UNIX)
                self.addCleanup(listener.close)
                process = MagicMock(pid=123)

                def launch(
                    *_args: Any,
                    listener: socket.socket = listener,
                    endpoint: Path = endpoint,
                    process: MagicMock = process,
                    **_options: Any,
                ) -> MagicMock:
                    listener.bind(str(endpoint))
                    return process

                with (
                    patch.object(lifecycle, "require_file", side_effect=self.require),
                    patch.object(lifecycle.subprocess, "Popen", side_effect=launch),
                    patch.object(lifecycle, "_process_start_time", return_value=456),
                    patch.object(lifecycle.ControlSession, "connect"),
                ):
                    lifecycle.start(state, 10)
                if replacement == "owner":
                    Path(f"{endpoint}.lock").write_text("another owner's reservation")
                else:
                    endpoint.unlink()
                    if replacement == "socket":
                        newer = socket.socket(socket.AF_UNIX)
                        self.addCleanup(newer.close)
                        newer.bind(str(endpoint))
                    else:
                        endpoint.write_text("not a socket")
                with patch.object(lifecycle, "_process_running", return_value=False):
                    lifecycle.deprovision(state, 10)
                self.assertTrue(endpoint.exists())

    @unittest.skipUnless(os.name == "posix", "Unix control socket reservation")
    def test_concurrent_starts_reserve_endpoint_exclusively(self):
        endpoint = self.root / "snap.control.sock"

        def reserve(_index: int) -> str | None:
            try:
                return lifecycle._reserve_snapshot_endpoint(endpoint)
            except ScriptError:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            owners = list(executor.map(reserve, (0, 1)))
        self.assertEqual(sum(owner is not None for owner in owners), 1)
        owner = next(owner for owner in owners if owner is not None)
        reservation = Path(f"{endpoint}.lock")
        self.assertEqual(reservation.read_text(), owner)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        lifecycle._cleanup_snapshot_endpoint(endpoint, "stale-owner", None)
        self.assertEqual(reservation.read_text(), owner)
        lifecycle._cleanup_snapshot_endpoint(endpoint, owner, None)
        self.assertFalse(reservation.exists())

    @unittest.skipUnless(os.name == "posix", "shell guest trigger")
    def test_guest_trigger_runs_exact_token_before_managed_handoff(self):
        source = (
            Path(__file__).parent.parent / "guest/common/nvx-init-agent"
        ).read_text()
        trigger = source.split('case " $cmdline " in', 1)[1].split("esac", 1)[0]
        script = (
            'snapshot() { printf "%s\\n" "$*"; }\n'
            'cmdline=$1\ncase " $cmdline " in'
            + trigger.replace("/sbin/nvx-snapshot", "snapshot")
            + "esac\n"
        )
        for cmdline, expected in (
            ("quiet sandboxsnap", "--tier instance-checkpoint\n"),
            ("quiet sandboxsnapshot", ""),
            ("quiet", ""),
        ):
            result = subprocess.run(
                ["/bin/sh", "-c", script, "trigger", cmdline],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(result.stdout, expected)
        capture = source.index('case " $cmdline " in')
        self.assertLess(source.index("mount_live_shares\n"), capture)
        self.assertLess(
            source.index("failed to assemble the container overlay"), capture
        )
        self.assertLess(capture, source.index('if [ "$workload_lifecycle" = managed ]'))

    @staticmethod
    def require(path: Path, _description: str) -> Path:
        return path


if __name__ == "__main__":
    unittest.main()
