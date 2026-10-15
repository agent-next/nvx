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
    def test_capture_arms_pre_handoff_trigger(self):
        destination = self.root / "snapshot"
        config = self.config(snapshot_destination=destination)
        self.assertEqual(config["format"], 7)
        launch = lifecycle._deserialize_launch(config)
        self.assertIn("sandboxsnap", launch.kernel_command_line())

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
        process = MagicMock(pid=os.getpid())
        process.poll.return_value = 0

        def captured(timeout: float) -> int:
            runtime = json.loads((state / lifecycle.RUNTIME_NAME).read_text())
            self.assertEqual(runtime["pid"], process.pid)
            self.assertEqual(
                runtime["start_time"], lifecycle._process_start_time(process.pid)
            )
            self.assertEqual(
                runtime["control_endpoint"], str(self.root / "snap.control.sock")
            )
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
        self.assertEqual(
            command[command.index("--restore-snapshot") + 1], str(snapshot)
        )
        self.assertEqual(command[command.index("--machine") + 1], "microvm")
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
    def test_restore_repasses_network_contract_without_instance_address(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        state = self.root / "state"
        args = nvx.parse_args(
            [
                "sandbox",
                "provision",
                "--state-dir",
                str(state),
                "--layer",
                f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                "--restore-snapshot",
                str(snapshot),
                "--network-profile",
                "portable",
                "--network-egress",
                "deny",
                "--network-ingress",
                "deny",
                "--network-egress-allow",
                "192.0.2.0/24:tcp:443",
                "--network-egress-deny",
                "192.0.2.1:tcp:443",
                "--host-loopback",
                "allow",
                "--network-proxy",
                "192.168.127.1:3128",
            ]
        )
        nvx.command_sandbox(args)
        process = MagicMock(pid=123)
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process) as popen,
            patch.object(lifecycle, "_process_start_time", return_value=456),
            patch.object(lifecycle.ControlSession, "connect"),
        ):
            lifecycle.start(state, 10)
        command = popen.call_args.args[0]
        for option, value in (
            ("--restore-snapshot", str(snapshot)),
            ("--machine", "microvm"),
            ("--network-profile", "portable"),
            ("--network-egress", "deny"),
            ("--network-ingress", "deny"),
            ("--network-egress-allow", "192.0.2.0/24:tcp:443"),
            ("--network-egress-deny", "192.0.2.1:tcp:443"),
            ("--host-loopback", "allow"),
            ("--network-proxy", "192.168.127.1:3128"),
        ):
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertNotIn("--net", command)

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
        process = MagicMock(pid=os.getpid())
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

    def test_restore_passes_expected_snapshot_processor_capacity(self):
        launch = dataclasses.replace(self.launch, processors=8)
        arguments = launch.openvmm_arguments(restore=True)
        self.assertEqual(arguments[arguments.index("--processors") + 1], "8")

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_accepts_processor_capacity_for_vmm_validation(self):
        snapshot = self.root / "snap"
        snapshot.mkdir()
        state = self.root / "state"
        nvx.command_sandbox(
            nvx.parse_args(
                [
                    "sandbox",
                    "provision",
                    "--state-dir",
                    str(state),
                    "--layer",
                    f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                    "--restore-snapshot",
                    str(snapshot),
                    "--processors",
                    "2",
                ]
            )
        )
        self.assertEqual(
            json.loads((state / lifecycle.CONFIG_NAME).read_text())["processors"], 2
        )

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_rejects_only_network_address(self):
        snapshot = self.root / "snap"
        snapshot.mkdir()
        with self.assertRaisesRegex(ScriptError, "network address"):
            nvx.command_sandbox(
                nvx.parse_args(
                    [
                        "sandbox",
                        "provision",
                        "--restore-snapshot",
                        str(snapshot),
                        "--net",
                        "10.0.0.2/24",
                        "--network-profile",
                        "portable",
                    ]
                )
            )

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_accepts_option_like_argument_values(self):
        snapshot = self.root / "snap"
        snapshot.mkdir()
        # Option-like text inside a value is not a workload override.
        layer = self.root / "--memory-max"
        layer.touch()
        args = nvx.parse_args(
            [
                "sandbox",
                "provision",
                "--restore-snapshot",
                str(snapshot),
                "--layer",
                f"distro,{layer},11111111-1111-1111-1111-111111111111",
                "--state-dir",
                str(self.root / "state"),
                "--hypervisor",
                "kvm",
            ]
        )
        with patch.object(lifecycle, "provision") as provision:
            nvx.command_sandbox(args)
        provision.assert_called_once()

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_persists_lowered_policy_without_parser_private_state(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        policy = self.root / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "allow": [{"to": [{"cidr": "192.0.2.0/24"}]}],
                    "deny": [{"to": [{"cidr": "192.0.2.1/32"}]}],
                }
            )
        )
        state = self.root / "state"
        args = nvx.parse_args(
            [
                "sandbox",
                "provision",
                "--state-dir",
                str(state),
                "--layer",
                f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                "--restore-snapshot",
                str(snapshot),
                "--network-profile",
                "portable",
                "--network-egress",
                "deny",
                "--network-egress-policy-file",
                str(policy),
            ]
        )
        # command_sandbox must also work for callers constructing a Namespace,
        # without any attribute synthesized by parse_args' old argv scanner.
        vars(args).pop("sandbox_restore_overrides", None)
        nvx.command_sandbox(args)
        policy.unlink()
        config = json.loads((state / lifecycle.CONFIG_NAME).read_text())
        self.assertEqual(config["network_profile"], "portable")
        self.assertEqual(config["network_egress"], "deny")
        self.assertEqual(config["network_egress_allow"], ["192.0.2.0/24"])
        self.assertEqual(config["network_egress_deny"], ["192.0.2.1/32"])
        self.assertIsNone(config["net"])

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
                patch.object(lifecycle, "_start", side_effect=error) as start,
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
        process = MagicMock(pid=os.getpid())
        process.poll.return_value = 0
        process.wait.side_effect = subprocess.TimeoutExpired("openvmm", 10)
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process),
            patch.object(lifecycle, "_end_failed_start", return_value=0),
            self.assertRaisesRegex(ScriptError, "capture.*timed out.*0.01"),
        ):
            lifecycle.start(state, 0.01)
        self.assertFalse((state / lifecycle.CAPABILITY_NAME).exists())

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_capture_nonzero_exit_reports_real_process_outcome(self):
        executable = self.root / "capture-failure"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys, time\n"
            "time.sleep(0.1)\n"
            "path = pathlib.Path(sys.argv[sys.argv.index('--microvm-report') + 1])\n"
            "path.write_text(json.dumps({'schema_version': 1,"
            "'outcome': {'category': 'guest_error', 'status_code': 125},"
            "'network_policy': {}, 'teardown': {}}))\n"
            "sys.exit(97)\n"
        )
        executable.chmod(0o700)
        popen = subprocess.Popen[bytes]
        identify = lifecycle._process_start_time
        for early_exit in (False, True):
            with self.subTest(early_exit=early_exit):
                state = self.root / f"state-{early_exit}"
                lifecycle.provision(
                    state,
                    self.launch,
                    **self.options,
                    timeout=10,
                    snapshot_destination=self.root / "snap",
                )
                children: list[subprocess.Popen[bytes]] = []

                def spawn(
                    *args: Any,
                    children: list[subprocess.Popen[bytes]] = children,
                    **kwargs: Any,
                ) -> subprocess.Popen[bytes]:
                    child = popen(*args, **kwargs)
                    children.append(child)
                    return child

                def start_time(
                    pid: int,
                    *,
                    early_exit: bool = early_exit,
                    children: list[subprocess.Popen[bytes]] = children,
                ) -> int | None:
                    if early_exit:
                        self.assertEqual(children[0].wait(timeout=10), 97)
                        return None
                    return identify(pid)

                with (
                    patch.object(
                        lifecycle, "openvmm_binary_path", return_value=executable
                    ),
                    patch.object(lifecycle, "artifact_path", return_value=self.layer),
                    patch.object(lifecycle.subprocess, "Popen", side_effect=spawn),
                    patch.object(
                        lifecycle, "_process_start_time", side_effect=start_time
                    ),
                    self.assertRaisesRegex(
                        ScriptError,
                        "^OpenVMM exited during startup: guest_error status 125$",
                    ),
                ):
                    lifecycle.start(state, 10)
                self.assertEqual(children[0].returncode, 97)
                self.assertFalse((state / lifecycle.RUNTIME_NAME).exists())
                self.assertFalse((state / lifecycle.CAPABILITY_NAME).exists())
                self.assertFalse((self.root / "snap.control.sock.lock").exists())

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_capture_preserves_socket_replaced_after_recording_identity(self):
        state = self.root / "state"
        destination = self.root / "snap"
        endpoint = self.root / "snap.control.sock"
        lifecycle.provision(
            state,
            self.launch,
            **self.options,
            timeout=10,
            snapshot_destination=destination,
        )
        original = self.unix_socket()
        replacement = self.unix_socket()
        self.addCleanup(original.close)
        self.addCleanup(replacement.close)
        process = MagicMock(pid=os.getpid())
        process.poll.return_value = None

        def launch(*_args: Any, **_kwargs: Any) -> MagicMock:
            original.bind(str(endpoint))
            return process

        def captured(timeout: float) -> int:
            runtime = json.loads((state / lifecycle.RUNTIME_NAME).read_text())
            self.assertEqual(
                runtime["control_socket_identity"], lifecycle._socket_identity(endpoint)
            )
            endpoint.unlink()
            replacement.bind(str(endpoint))
            destination.mkdir()
            for name in ("manifest.bin", "state.bin", "memory.bin", "scratch.img"):
                (destination / name).touch()
            return 0

        process.wait.side_effect = captured
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", side_effect=launch),
        ):
            lifecycle.start(state, 10)
        self.assertTrue(endpoint.exists())
        self.assertTrue(Path(f"{endpoint}.lock").exists())

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_snapshot_listeners_are_rejected_before_provision(self):
        restore = self.root / "restore"
        restore.mkdir()
        for snapshot_option, path in (
            ("--snapshot-destination", self.root / "capture"),
            ("--restore-snapshot", restore),
        ):
            for option, value in (
                ("--host-loopback-forward", "tcp:18080:80"),
                ("--network-ingress", "allow"),
            ):
                with self.subTest(snapshot=snapshot_option, option=option):
                    state = self.root / "state"
                    args = nvx.parse_args(
                        [
                            "sandbox",
                            "provision",
                            "--state-dir",
                            str(state),
                            "--layer",
                            f"distro,{self.layer},11111111-1111-1111-1111-111111111111",
                            snapshot_option,
                            str(path),
                            option,
                            value,
                        ]
                    )
                    with self.assertRaisesRegex(ScriptError, "do not support"):
                        nvx.command_sandbox(args)
                    self.assertFalse(state.exists())
                    options: dict[str, Any] = {
                        **self.options,
                        option[2:].replace("-", "_"): (
                            (value,) if option == "--host-loopback-forward" else value
                        ),
                    }
                    with self.assertRaisesRegex(ScriptError, "do not support"):
                        lifecycle.provision(
                            state,
                            self.launch,
                            **options,
                            timeout=10,
                            snapshot_destination=(
                                path
                                if snapshot_option == "--snapshot-destination"
                                else None
                            ),
                            restore_snapshot=(
                                path
                                if snapshot_option == "--restore-snapshot"
                                else None
                            ),
                        )
                    self.assertFalse(state.exists())

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_snapshot_paths_normalize_and_bound_encoded_endpoint_length(self):
        nested = self.root / "nested"
        nested.mkdir()
        path = nested / ".." / "snap"
        normalized, _ = lifecycle.snapshot_paths({"snapshot_destination": str(path)})
        self.assertEqual(normalized, self.root / "snap")
        for name in ("x" * 108, "\N{SNOWMAN}" * 40):
            with self.assertRaisesRegex(ScriptError, "socket path exceeds"):
                lifecycle.snapshot_paths(
                    {"snapshot_destination": str(self.root / name)}
                )
        with self.assertRaisesRegex(ScriptError, "invalid"):
            lifecycle.snapshot_paths({"snapshot_destination": str(self.root / "bad\0")})

    def test_sandbox_preserves_unambiguous_option_abbreviations(self):
        args = nvx.parse_args(["sandbox", "start", "--state", str(self.root / "state")])
        self.assertEqual(args.state_dir, self.root / "state")

    def test_start_validates_state_before_reading_configuration(self):
        with (
            patch.object(lifecycle, "_read_json") as read,
            self.assertRaisesRegex(ScriptError, "not a plain directory"),
        ):
            lifecycle.start(self.root / "missing", 10)
        read.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "managed snapshots require POSIX")
    def test_restore_does_not_require_cold_boot_artifacts(self):
        snapshot = self.root / "snap"
        snapshot.mkdir()
        state = self.root / "state"
        lifecycle.provision(
            state, self.launch, **self.options, timeout=10, restore_snapshot=snapshot
        )
        process = MagicMock(pid=123)
        with (
            patch.object(lifecycle, "openvmm_binary_path", return_value=self.layer),
            patch.object(lifecycle, "artifact_path") as artifacts,
            patch.object(lifecycle.subprocess, "Popen", return_value=process),
            patch.object(lifecycle, "_process_start_time", return_value=456),
            patch.object(lifecycle.ControlSession, "connect"),
        ):
            lifecycle.start(state, 10)
        artifacts.assert_not_called()

    def test_cold_start_script_error_retains_outcome_diagnostics(self):
        state = self.root / "state"
        lifecycle.provision(state, self.launch, **self.options, timeout=10)
        process = MagicMock(pid=123)
        process.poll.return_value = 97
        with (
            patch.object(lifecycle, "require_file", side_effect=self.require),
            patch.object(lifecycle.subprocess, "Popen", return_value=process),
            patch.object(lifecycle, "_process_start_time", return_value=None),
            patch.object(lifecycle, "_end_failed_start", return_value=97),
            patch.object(
                lifecycle,
                "_read_openvmm_outcome",
                return_value={
                    "outcome": {"category": "guest_error", "status_code": 125},
                },
            ),
            self.assertRaisesRegex(
                ScriptError, "^OpenVMM exited during startup: guest_error status 125$"
            ),
        ):
            lifecycle.start(state, 10)

    @unittest.skipUnless(os.name == "posix", "Unix control socket ownership")
    def test_missing_socket_identity_keeps_reservation_for_recovery(self):
        endpoint = self.root / "snap.control.sock"
        owner = lifecycle._reserve_snapshot_endpoint(endpoint)
        listener = self.unix_socket()
        self.addCleanup(listener.close)
        listener.bind(str(endpoint))
        lifecycle._cleanup_snapshot_endpoint(endpoint, owner, None)
        self.assertTrue(endpoint.exists())
        self.assertEqual(Path(f"{endpoint}.lock").read_text(), owner)
        lifecycle._cleanup_snapshot_endpoint(
            endpoint, owner, lifecycle._socket_identity(endpoint)
        )
        self.assertFalse(endpoint.exists())
        self.assertFalse(Path(f"{endpoint}.lock").exists())

    @unittest.skipUnless(os.name == "posix", "Unix control socket namespace")
    def test_sibling_snapshots_have_independent_sockets_and_cleanup(self):
        states: list[Path] = []
        endpoints: list[Path] = []
        process = MagicMock()
        process.pid = 123

        def launch(command: list[str], **_options: Any) -> MagicMock:
            endpoint = Path(command[command.index("--microvm-control-console") + 1][7:])
            listener = self.unix_socket()
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
                listener = self.unix_socket()
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
                listener = self.unix_socket()
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
                        newer = self.unix_socket()
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
    def test_managed_capture_keeps_a_raw_control_tty_open(self):
        if sys.platform == "win32":
            self.skipTest("Unix control tty")
        import pty

        source = (
            Path(__file__).parent.parent / "guest/common/nvx-init-agent"
        ).read_text()
        preparation = source.split("mount_live_shares\n", 1)[1].split(
            "# Capture after assembling", 1
        )[0]
        master, slave = pty.openpty()
        try:
            script = (
                "workload_lifecycle=managed\ncontrol_tty=$1\nruntime=$2\n"
                'fatal() { echo "$*" >&2; exit 1; }\n'
                + preparation
                + '\nexec "$3" -c \'import os, termios; '
                "s = termios.tcgetattr(9); "
                "assert not s[3] & (termios.ECHO | termios.ICANON); "
                "assert os.isatty(9)'\n"
            )
            subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    script,
                    "prepare",
                    os.ttyname(slave).removeprefix("/dev/"),
                    str(self.root),
                    sys.executable,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            os.close(master)
            os.close(slave)

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
        self.assertLess(capture, source.index("NVX-SANDBOX-READY: managed"))

    @staticmethod
    def unix_socket() -> socket.socket:
        if os.name != "posix":
            raise RuntimeError("Unix control sockets require POSIX")
        return socket.socket(socket.AF_UNIX)

    @staticmethod
    def require(path: Path, _description: str) -> Path:
        return path


if __name__ == "__main__":
    unittest.main()
