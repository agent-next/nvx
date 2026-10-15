"""Public OpenVMM patch application and provenance regression tests."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from nvx_tools import build, release  # noqa: E402
from nvx_tools.build_config import OpenVmmBuildConfig  # noqa: E402
from nvx_tools.build_constants import BuildConstants  # noqa: E402
from nvx_tools.common import ScriptError  # noqa: E402


class OpenVmmPatchTests(unittest.TestCase):
    def test_external_target_directory_is_used_for_build_output(self):
        config = OpenVmmBuildConfig(directory=Path("/checkout"))
        for target in ("/large-disk/target", "external-target"):
            with (
                self.subTest(target=target),
                patch.dict(os.environ, CARGO_TARGET_DIR=target),
            ):
                expected = Path(target)
                if not expected.is_absolute():
                    expected = config.directory / expected
                self.assertEqual(
                    config.openvmm_target_output("linux-gnu"),
                    expected / "release/openvmm",
                )

    def test_release_rejects_stale_patch_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "openvmm-patches"
            directory.mkdir()
            patch_file = directory / "0001.patch"
            patch_file.write_bytes(b"patch")
            binary = root / "openvmm"
            binary.write_bytes(b"binary")
            provenance = root / "provenance.json"
            config = OpenVmmBuildConfig(
                directory=root,
                output=binary,
                build_directory=root,
            )
            from nvx_tools.build_constants import OpenVMMBuildConstants

            with (
                patch.object(BuildConstants, "REPO_ROOT", root),
                patch.object(build, "openvmm_git_state", return_value=("pin", True)),
                patch.object(release, "openvmm_git_state", return_value=("pin", True)),
            ):
                build.record_openvmm_provenance(config)
                provenance.write_bytes(
                    (root / OpenVMMBuildConstants.PROVENANCE_NAME).read_bytes()
                )
                value = release._validate_openvmm_provenance(binary, provenance)
                self.assertEqual(value["patches"], build.openvmm_patch_inputs())
                patch_file.write_bytes(b"changed")
                with self.assertRaisesRegex(ScriptError, "provenance"):
                    release._validate_openvmm_provenance(binary, provenance)
                patch_file.write_bytes(b"patch")
                value = json.loads(provenance.read_text())
                del value["patches"]
                provenance.write_text(json.dumps(value))
                with self.assertRaisesRegex(ScriptError, "provenance"):
                    release._validate_openvmm_provenance(binary, provenance)

    def test_dirty_source_is_not_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "openvmm-patches").mkdir()
            (root / "openvmm-patches/0001.patch").write_bytes(b"patch")
            with (
                patch.object(BuildConstants, "REPO_ROOT", root),
                patch.object(build, "openvmm_git_state", return_value=("pin", False)),
                patch.object(build, "run_capture") as capture,
                self.assertRaisesRegex(ScriptError, "clean pinned"),
                build.patched_openvmm(OpenVmmBuildConfig(directory=root)),
            ):
                self.fail("dirty source entered the build")
            capture.assert_not_called()

    def test_build_applies_patch_and_restores_source_even_on_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "openvmm"
                source.mkdir()
                (source / "Cargo.toml").touch()
                input_file = source / "input"
                input_file.write_text("before\n")
                patches = root / "openvmm-patches"
                patches.mkdir()
                patch_file = patches / "0001-fix.patch"
                patch_file.write_text(
                    "diff --git a/input b/input\n"
                    "--- a/input\n+++ b/input\n@@ -1 +1 @@\n-before\n+after\n"
                )
                output = source / "target/release/openvmm"
                output.parent.mkdir(parents=True)
                output.write_bytes(b"binary")
                config = OpenVmmBuildConfig(
                    skip_restore=True, directory=source, output=output
                )

                def command(*args, input_file=input_file, fail=fail, **kwargs):
                    self.assertEqual(input_file.read_text(), "after\n")
                    if fail:
                        raise ScriptError("intentional cargo failure")

                with (
                    patch.object(BuildConstants, "REPO_ROOT", root),
                    patch.object(
                        build, "openvmm_git_state", return_value=("pin", True)
                    ),
                    patch.object(build, "_run_openvmm_command", side_effect=command),
                    patch.object(build, "record_openvmm_provenance") as provenance,
                ):
                    if fail:
                        with self.assertRaisesRegex(ScriptError, "intentional cargo"):
                            build.build_openvmm(config, platform="linux-gnu")
                        provenance.assert_not_called()
                    else:
                        build.build_openvmm(config, platform="linux-gnu")
                        provenance.assert_called_once_with(config)
                self.assertEqual(input_file.read_text(), "before\n")
                # The public patch also applies without any private remote.
                subprocess.run(
                    ["git", "apply", "--check", str(patch_file)],
                    cwd=source,
                    check=True,
                )

    def test_patch_manifest_binds_order_and_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "openvmm-patches"
            directory.mkdir()
            (directory / "0002.patch").write_bytes(b"second")
            (directory / "0001.patch").write_bytes(b"first")
            with patch.object(BuildConstants, "REPO_ROOT", root):
                self.assertEqual(
                    build.openvmm_patch_inputs(),
                    [
                        {
                            "path": f"openvmm-patches/{name}.patch",
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                        for name, content in (("0001", b"first"), ("0002", b"second"))
                    ],
                )


if __name__ == "__main__":
    unittest.main()
