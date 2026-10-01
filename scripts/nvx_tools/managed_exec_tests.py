"""Public CLI acceptance for managed workload environment, CWD and timeouts."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

from .build_constants import BuildConstants, UbuntuBuildConstants
from .common import ScriptError, artifact_path, require_file

DIAGNOSTIC_LIMIT = 4096


def _bounded_text(value: bytes) -> str:
    text = value[:DIAGNOSTIC_LIMIT].decode(errors="replace")
    if len(value) > DIAGNOSTIC_LIMIT:
        text += f"... ({len(value) - DIAGNOSTIC_LIMIT} bytes omitted)"
    return text


def _evidence_argv(command: list[str]) -> list[str]:
    recorded = command.copy()
    for index, value in enumerate(recorded[:-1]):
        if value == "--environment":
            recorded[index + 1] = "<redacted>"
    return recorded


def _read_exec_outcome(
    path: Path, *, category: str, status_code: int
) -> dict[str, Any]:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"public exec outcome is unreadable: {path}") from error
    if not isinstance(value, dict):
        raise RuntimeError("public exec outcome must be a JSON object")
    typed = cast(dict[str, object], value)
    schema_version = typed.get("schema_version")
    operation_id = typed.get("operation_id")
    outcome = typed.get("outcome")
    if (
        schema_version != 1
        or isinstance(schema_version, bool)
        or not isinstance(operation_id, str)
        or not isinstance(outcome, dict)
        or cast(dict[str, object], outcome).get("operation") != "exec"
        or cast(dict[str, object], outcome).get("category") != category
        or cast(dict[str, object], outcome).get("status_code") != status_code
        or isinstance(cast(dict[str, object], outcome).get("status_code"), bool)
    ):
        raise RuntimeError("public exec outcome has unexpected typed fields")
    return cast(dict[str, Any], typed)


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
    checks: list[dict[str, object]] = []
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
            checks.append(
                {
                    "operation": operation,
                    "argv": _evidence_argv([str(value) for value in result.args]),
                    "expected_returncode": expected,
                    "returncode": result.returncode,
                    "stdout_bytes": len(result.stdout),
                    "stderr_bytes": len(result.stderr),
                    "state_exists": state.is_dir(),
                }
            )
            if result.returncode != expected:
                raise RuntimeError(
                    f"public sandbox {operation} returned {result.returncode}, "
                    f"expected {expected}; stdout={_bounded_text(result.stdout)!r}; "
                    f"stderr={_bounded_text(result.stderr)!r}"
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
                raise RuntimeError(
                    "public managed workload returned unexpected output: "
                    f"stdout={_bounded_text(result.stdout)!r}, "
                    f"stderr={_bounded_text(result.stderr)!r}"
                )

        def expect_rejection(
            result: subprocess.CompletedProcess[bytes], message: bytes
        ) -> None:
            if result.stdout or message not in result.stderr:
                raise RuntimeError(
                    "public managed validation returned unexpected diagnostics: "
                    f"stdout={_bounded_text(result.stdout)!r}, "
                    f"stderr={_bounded_text(result.stderr)!r}"
                )

        def persist_evidence() -> None:
            for name in ("openvmm.log", "outcome.json"):
                source = state / name
                if source.is_file():
                    shutil.copyfile(source, output_dir / f"public-exec-{name}")
            for name in ("exit-outcome.json", "timeout-outcome.json"):
                source = root / name
                if source.is_file():
                    shutil.copyfile(source, output_dir / f"public-exec-{name}")
            (output_dir / "public-exec-checks.json").write_text(
                json.dumps(checks, indent=2) + "\n", encoding="utf-8"
            )

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
        acceptance_error: Exception | None = None
        cleanup_errors: list[Exception] = []
        try:
            invoke("start")
            started = True

            # Supplied values must remain request-scoped across sequential public calls.
            expect_output(workload("/bin/pwd", "--cwd", "/tmp"), b"/tmp\n")
            expect_output(workload("/bin/pwd", "--cwd", "/"), b"/\n")
            expect_output(workload("/bin/pwd"), b"/\n")

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
                workload(
                    "/usr/bin/env",
                    "--environment",
                    "SECOND=inline value",
                    "--environment",
                    "ORDER=two",
                ),
                b"SECOND=inline value\nORDER=two\n",
            )
            default_environment = workload("/usr/bin/env")
            if (
                default_environment.stderr
                or b"HOME=" not in default_environment.stdout
                or any(
                    line.startswith(
                        (
                            b"COMPLEX=",
                            b"EMPTY=",
                            b"SECOND=",
                            b"ORDER=",
                            b"NVX_EXEC_CONFIG_FD=",
                        )
                    )
                    for line in default_environment.stdout.splitlines()
                )
            ):
                raise RuntimeError("public managed environment leaked between requests")

            relative = workload(
                "/bin/sh",
                "--arg=-c",
                "--arg=printf workload-must-not-run",
                "--cwd",
                "relative",
                expected=1,
            )
            expect_rejection(relative, b"working directory must be an absolute path")
            for invalid_timeout in (-1, 0x100000000):
                rejected = workload(
                    "/bin/sh",
                    "--arg=-c",
                    "--arg=printf workload-must-not-run",
                    "--exec-timeout-ms",
                    str(invalid_timeout),
                    expected=1,
                )
                expect_rejection(rejected, b"timeout must be 0 through 4294967295 ms")

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

            exit_outcome = root / "exit-outcome.json"
            result = workload(
                "/bin/sh",
                "--arg=-c",
                "--arg=printf 'public stdout'; printf 'public stderr' >&2; exit 7",
                "--outcome-report",
                str(exit_outcome),
                expected=7,
            )
            if result.stdout != b"public stdout" or result.stderr != b"public stderr":
                raise RuntimeError("public managed stdout/stderr were not preserved")
            _read_exec_outcome(exit_outcome, category="exit", status_code=7)

            for limit in (0, 3_600_001, 86_400_000, 0xFFFFFFFF):
                expect_output(
                    workload("/bin/true", "--exec-timeout-ms", str(limit)), b""
                )
            timeout_outcome = root / "timeout-outcome.json"
            timed_out = workload(
                "/bin/sleep",
                "--arg=5",
                "--exec-timeout-ms",
                "100",
                "--outcome-report",
                str(timeout_outcome),
                expected=124,
            )
            if timed_out.stdout or timed_out.stderr:
                raise RuntimeError(
                    "public timed-out workload returned unexpected output"
                )
            _read_exec_outcome(timeout_outcome, category="timeout", status_code=124)
            expect_output(workload("/bin/pwd"), b"/\n")
        except Exception as error:
            acceptance_error = error
        finally:
            try:
                if started:
                    invoke("stop")
            except Exception as error:
                cleanup_errors.append(error)
            try:
                persist_evidence()
            except Exception as error:
                cleanup_errors.append(error)
        if acceptance_error is not None:
            if cleanup_errors:
                cleanup = "; ".join(str(error) for error in cleanup_errors)
                raise RuntimeError(
                    f"{acceptance_error}; cleanup failed: {cleanup}"
                ) from acceptance_error
            raise acceptance_error.with_traceback(acceptance_error.__traceback__)
        if cleanup_errors:
            cleanup = "; ".join(str(error) for error in cleanup_errors)
            raise RuntimeError(f"public managed cleanup failed: {cleanup}")
        try:
            invoke("deprovision")
        except Exception:
            persist_evidence()
            raise
        persist_evidence()
        if not scratch.is_file() or not distro.is_file():
            raise RuntimeError("managed cleanup removed a supplied workload artifact")
