"""Public OpenVMM patch application and provenance regression tests."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Literal
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from nvx_tools import benchmark, build, release  # noqa: E402
from nvx_tools.build_config import OpenVmmBuildConfig  # noqa: E402
from nvx_tools.build_constants import BuildConstants  # noqa: E402
from nvx_tools.common import ScriptError  # noqa: E402


class OpenVmmPatchTests(unittest.TestCase):
    def test_empty_target_directory_uses_cargo_default(self):
        config = OpenVmmBuildConfig(directory=Path("/checkout"))
        with patch.dict(os.environ, CARGO_TARGET_DIR=""):
            platforms: tuple[
                tuple[Literal["linux-gnu", "windows-msvc", "linux-musl"], str], ...
            ] = (
                ("linux-gnu", "release/openvmm"),
                ("windows-msvc", "release/openvmm.exe"),
                ("linux-musl", "x86_64-unknown-linux-musl/release/openvmm"),
            )
            for platform, suffix in platforms:
                with self.subTest(platform=platform):
                    self.assertEqual(
                        config.openvmm_target_output(platform),
                        config.directory / "target" / suffix,
                    )

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
                self.assertRaisesRegex(
                    ScriptError,
                    r"clean pinned.*Save any local work.*git -C .* checkout \.",
                ),
                build.patched_openvmm(OpenVmmBuildConfig(directory=root)),
            ):
                self.fail("dirty source entered the build")
            capture.assert_not_called()

    def test_autocrlf_checkout_keeps_patch_round_trip_lf_with_pinned_attributes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "openvmm"
            source.mkdir()
            subprocess.run(["git", "init", "--quiet", str(source)], check=True)
            subprocess.run(
                ["git", "config", "core.autocrlf", "true"], cwd=source, check=True
            )
            # OpenVMM's pinned attributes override the Windows autocrlf setting.
            (source / ".gitattributes").write_bytes(b"* text=auto eol=lf\n")
            input_file = source / "input.rs"
            input_file.write_bytes(b"before\n")
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            input_file.unlink()
            subprocess.run(
                ["git", "checkout", "--", "input.rs"], cwd=source, check=True
            )
            self.assertEqual(input_file.read_bytes(), b"before\n")
            patches = root / "openvmm-patches"
            patches.mkdir()
            (patches / "0001.patch").write_bytes(
                b"diff --git a/input.rs b/input.rs\n"
                b"--- a/input.rs\n+++ b/input.rs\n@@ -1 +1 @@\n-before\n+after\n"
            )
            with (
                patch.object(BuildConstants, "REPO_ROOT", root),
                patch.object(build, "openvmm_git_state", return_value=("pin", True)),
            ):
                with build.patched_openvmm(OpenVmmBuildConfig(directory=source)):
                    self.assertEqual(input_file.read_bytes(), b"after\n")
            self.assertEqual(input_file.read_bytes(), b"before\n")
            subprocess.run(["git", "diff", "--exit-code"], cwd=source, check=True)

    def test_cleanup_failure_preserves_original_and_attempts_remaining_patches(self):
        for original in (None, ScriptError("cargo failed"), KeyboardInterrupt()):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / "openvmm"
                source.mkdir()
                patches = root / "openvmm-patches"
                patches.mkdir()
                for number in (1, 2):
                    (source / f"input{number}").write_text("before\n")
                    (patches / f"000{number}.patch").write_text(
                        f"diff --git a/input{number} b/input{number}\n"
                        f"--- a/input{number}\n+++ b/input{number}\n"
                        "@@ -1 +1 @@\n-before\n+after\n"
                    )
                errors = io.StringIO()
                with (
                    patch.object(BuildConstants, "REPO_ROOT", root),
                    patch.object(
                        build, "openvmm_git_state", return_value=("pin", True)
                    ),
                    patch.object(sys, "stderr", errors),
                    self.assertRaises(
                        ScriptError if original is None else type(original)
                    ) as raised,
                ):
                    with build.patched_openvmm(OpenVmmBuildConfig(directory=source)):
                        self.assertEqual((source / "input1").read_text(), "after\n")
                        self.assertEqual((source / "input2").read_text(), "after\n")
                        (source / "input2").write_text("cannot reverse\n")
                        if original is not None:
                            raise original
                self.assertEqual((source / "input1").read_text(), "before\n")
                self.assertEqual((source / "input2").read_text(), "cannot reverse\n")
                diagnostic = (
                    str(raised.exception) if original is None else errors.getvalue()
                )
                self.assertIn("OpenVMM patch cleanup (0002.patch)", diagnostic)
                self.assertIn("Save any local work", diagnostic)
                self.assertIn("checkout .", diagnostic)
                if original is not None:
                    self.assertIs(raised.exception, original)

    def test_benchmark_builds_apply_and_reverse_series_on_success_and_failure(self):
        for builder in (
            benchmark.build_whp,
            benchmark.build_kvm,
            benchmark.build_kvm_native,
        ):
            for fail in (False, True):
                with (
                    self.subTest(builder=builder.__name__, fail=fail),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    source = root / "openvmm"
                    source.mkdir()
                    input_file = source / "input"
                    input_file.write_text("before\n")
                    patches = root / "openvmm-patches"
                    patches.mkdir()
                    (patches / "0001.patch").write_text(
                        "diff --git a/input b/input\n"
                        "--- a/input\n+++ b/input\n@@ -1 +1 @@\n-before\n+after\n"
                    )
                    for suffix in (
                        "release/openvmm",
                        "release/openvmm.exe",
                        "bench-linux/release/openvmm",
                    ):
                        binary = source / "target" / suffix
                        binary.parent.mkdir(parents=True, exist_ok=True)
                        binary.write_bytes(b"binary")

                    def command(
                        *_args: object,
                        input_file: Path = input_file,
                        fail: bool = fail,
                        **_kwargs: object,
                    ) -> None:
                        self.assertEqual(input_file.read_text(), "after\n")
                        if fail:
                            raise ScriptError("benchmark cargo failed")

                    with (
                        patch.dict(os.environ, CARGO_TARGET_DIR=""),
                        patch.object(BuildConstants, "REPO_ROOT", root),
                        patch.object(
                            build, "openvmm_git_state", return_value=("pin", True)
                        ),
                        patch.object(benchmark, "windows_to_wsl", side_effect=str),
                        patch.object(
                            benchmark, "run_checked", side_effect=command
                        ) as run,
                    ):
                        if fail:
                            with self.assertRaisesRegex(ScriptError, "benchmark cargo"):
                                builder(source)
                        else:
                            self.assertTrue(builder(source).is_file())
                        run.assert_called_once()
                    self.assertEqual(input_file.read_text(), "before\n")

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

                def command(
                    _args: list[str | os.PathLike[str]],
                    *,
                    cwd: Path | None = None,
                    env: dict[str, str] | None = None,
                    input_file: Path = input_file,
                    fail: bool = fail,
                ) -> None:
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
