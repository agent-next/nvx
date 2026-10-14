"""Regression oracles for the snapshot/processors configuration rewrite."""
# pyright: reportPrivateUsage=false

import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import nvx
from nvx_tools import sandbox
from nvx_tools import sandbox_lifecycle as lifecycle
from nvx_tools.common import ScriptError


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
            self.assertIn(str(count), launch.openvmm_arguments())
        for count in (0, 3, True, "2"):
            with self.assertRaises(ScriptError):
                dataclasses.replace(self.launch, processors=count)

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

    def test_capture_arms_pre_handoff_trigger_and_instance_tier(self):
        destination = self.root / "snapshot"
        config = self.config(snapshot_destination=destination)
        self.assertEqual(config["format"], 7)
        launch = lifecycle._deserialize_launch(config)
        self.assertIn("sandboxsnap", launch.kernel_command_line())
        self.assertEqual(lifecycle.SNAPSHOT_CAPTURE_TIER, "instance-checkpoint")

    def test_restore_does_not_redeclare_paired_scratch_or_identity(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        launch = lifecycle._deserialize_launch(self.config(restore_snapshot=snapshot))
        arguments = launch.openvmm_arguments(restore=True)
        self.assertNotIn("--microvm-workload-identity", arguments)
        self.assertFalse(any("scratch:file:" in value for value in arguments))
        self.assertNotIn("sandboxsnap", launch.kernel_command_line())
        self.assertIn(f"distro:file:{self.layer},ro", arguments)

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
        self.assertEqual(runtime["control_endpoint"], str(self.root / "control.sock"))

    @staticmethod
    def require(path: Path, _description: str) -> Path:
        return path


if __name__ == "__main__":
    unittest.main()
