"""Public CLI acceptance for managed workload environment, CWD and timeouts."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from .build_constants import BuildConstants, UbuntuBuildConstants
from .common import ScriptError, artifact_path, require_file


def run_managed_exec_configuration(
    backend: str, *, timeout: float, output_dir: Path
) -> None:
    distro = require_file(
        artifact_path(UbuntuBuildConstants.DISTRO_NAME), "Ubuntu workload layer"
    )
    manifest_path = require_file(
        distro.with_name(UbuntuBuildConstants.DISTRO_MANIFEST_NAME),
        "Ubuntu layer manifest",
    )
    scratch_template = require_file(
        artifact_path("ubuntu-smoke-scratch.ext4"), "sandbox scratch template"
    )
    manifest: object = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ScriptError("Ubuntu layer manifest must contain a UUID string")
    layer_uuid = cast(dict[str, object], manifest).get("uuid")
    if not isinstance(layer_uuid, str):
        raise ScriptError("Ubuntu layer manifest must contain a UUID string")
    output_dir.mkdir(parents=True, exist_ok=True)
    checks: list[dict[str, str | int]] = []
    with tempfile.TemporaryDirectory(prefix="nvx-public-exec-") as temporary:
        root = Path(temporary)
        state = root / "state"
        scratch = root / "scratch.ext4"
        shutil.copyfile(scratch_template, scratch)
        base = [
            sys.executable,
            str(BuildConstants.REPO_ROOT / "scripts" / "nvx.py"),
            "sandbox",
        ]

        def invoke(
            operation: str, *arguments: str, expected: int = 0
        ) -> subprocess.CompletedProcess[bytes]:
            result = subprocess.run(
                [
                    *base,
                    operation,
                    "--state-dir",
                    str(state),
                    "--timeout",
                    str(timeout),
                    *arguments,
                ],
                cwd=BuildConstants.REPO_ROOT,
                capture_output=True,
                timeout=timeout + 10,
            )
            checks.append({"operation": operation, "returncode": result.returncode})
            if result.returncode != expected:
                raise RuntimeError(
                    f"public sandbox {operation} returned {result.returncode}, "
                    f"expected {expected}: {result.stderr.decode(errors='replace')}"
                )
            return result

        def workload(
            entrypoint: str, *arguments: str, expected: int = 0
        ) -> subprocess.CompletedProcess[bytes]:
            return invoke(
                "exec", "--entrypoint", entrypoint, *arguments, expected=expected
            )

        def expect_output(
            result: subprocess.CompletedProcess[bytes], expected: bytes
        ) -> None:
            if result.stdout != expected or result.stderr:
                raise RuntimeError("public managed workload returned unexpected output")

        invoke(
            "provision",
            "--layer",
            f"distro,{distro},{layer_uuid}",
            "--scratch",
            str(scratch),
            "--hypervisor",
            backend,
            "--memory-mib",
            "256",
        )
        started = False
        try:
            invoke("start")
            started = True
            expect_output(workload("/bin/pwd"), b"/\n")
            expect_output(workload("/bin/pwd", "--cwd", "/tmp"), b"/tmp\n")
            expect_output(workload("/bin/pwd", "--cwd", "/"), b"/\n")

            empty_file = root / "empty-env.json"
            empty_file.write_text("[]", encoding="utf-8")
            expect_output(
                workload("/usr/bin/env", "--environment-file", str(empty_file)), b""
            )
            env_file = root / "env.json"
            entries = ["EMPTY=", "COMPLEX=space = \N{SNOWMAN}"]
            env_file.write_text(json.dumps(entries), encoding="utf-8")
            expected_environment = ("\n".join(entries) + "\n").encode()
            expect_output(
                workload("/usr/bin/env", "--environment-file", str(env_file)),
                expected_environment,
            )
            expect_output(
                workload("/usr/bin/env", "--environment", "FOO=inline value"),
                b"FOO=inline value\n",
            )
            default_environment = workload("/usr/bin/env")
            if (
                default_environment.stderr
                or b"HOME=" not in default_environment.stdout
                or any(
                    line.startswith(
                        (b"COMPLEX=", b"EMPTY=", b"FOO=", b"NVX_EXEC_CONFIG_FD=")
                    )
                    for line in default_environment.stdout.splitlines()
                )
            ):
                raise RuntimeError("public managed environment leaked between requests")

            for cwd in ("/does-not-exist", "/etc/passwd", "/root"):
                failed = workload(
                    "/bin/sh",
                    "--arg=-c",
                    "--arg=printf workload-must-not-run",
                    "--cwd",
                    cwd,
                    expected=125,
                )
                if (
                    failed.stdout
                    or b"cannot use working directory" not in failed.stderr
                ):
                    raise RuntimeError(
                        "invalid CWD did not fail before workload execution"
                    )
            for limit in (0, 3_600_001, 86_400_000, 0xFFFFFFFF):
                expect_output(
                    workload("/bin/true", "--exec-timeout-ms", str(limit)), b""
                )
            workload(
                "/bin/sleep",
                "--arg=5",
                "--exec-timeout-ms",
                "100",
                expected=124,
            )
            expect_output(workload("/bin/pwd"), b"/\n")
        finally:
            try:
                if started:
                    invoke("stop")
            finally:
                for name in ("openvmm.log", "outcome.json"):
                    source = state / name
                    if source.is_file():
                        shutil.copyfile(source, output_dir / f"public-exec-{name}")
                (output_dir / "public-exec-checks.json").write_text(
                    json.dumps(checks, indent=2) + "\n", encoding="utf-8"
                )
        invoke("deprovision")
        if not scratch.is_file() or not distro.is_file():
            raise RuntimeError("managed cleanup removed a supplied workload artifact")
