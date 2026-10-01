"""Real-hypervisor end-to-end test of the aci_edge_sandboxes crate."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import cast

from .build_constants import (
    AlpineBuildConstants,
    BuildConstants,
    KernelBuildConstants,
)
from .ci import OPENVMM_TEST_BACKENDS, validate_openvmm_test_backend
from .common import artifact_path, openvmm_binary_path, require_file

CRATE_DIRECTORY = BuildConstants.REPO_ROOT / "aci_edge_sandboxes"
E2E_TEST_NAME = "openvmm_e2e"


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.description = (
        "Run the aci_edge_sandboxes lifecycle test against a real hypervisor with the Alpine "
        "guest initramfs."
    )
    parser.add_argument("--backend", choices=OPENVMM_TEST_BACKENDS, required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=BuildConstants.BUILD_DIR / "test-results" / "aci_edge_sandboxes",
        help="directory that receives the OpenVMM log on failure",
    )
    parser.add_argument(
        "--cargo",
        default="cargo",
        help="cargo executable used to build and run the test (default: cargo)",
    )
    parser.set_defaults(handler=command_test_aci_edge_sandboxes)


def e2e_environment(backend: str, state_root: Path, output_dir: Path) -> dict[str, str]:
    paths = {
        "ACI_EDGE_SANDBOXES_E2E_OPENVMM": require_file(
            openvmm_binary_path(), "OpenVMM release binary"
        ),
        "ACI_EDGE_SANDBOXES_E2E_KERNEL": require_file(
            artifact_path(KernelBuildConstants.BINARY_NAME), "Linux direct kernel"
        ),
        "ACI_EDGE_SANDBOXES_E2E_INITRD": require_file(
            artifact_path(AlpineBuildConstants.INITRAMFS_NAME), "Alpine initramfs"
        ),
        "ACI_EDGE_SANDBOXES_E2E_STATE_ROOT": state_root,
        "ACI_EDGE_SANDBOXES_E2E_OUTPUT_DIR": output_dir,
    }
    environment = {name: os.fspath(path.resolve()) for name, path in paths.items()}
    environment["ACI_EDGE_SANDBOXES_E2E_HYPERVISOR"] = backend
    return environment


def e2e_command(cargo: str) -> list[str]:
    return [
        cargo,
        "test",
        "--manifest-path",
        os.fspath(CRATE_DIRECTORY / "Cargo.toml"),
        "--locked",
        "--test",
        E2E_TEST_NAME,
        "--",
        "--ignored",
        "--nocapture",
    ]


def command_test_aci_edge_sandboxes(args: argparse.Namespace) -> int:
    backend = cast(str, args.backend)
    validate_openvmm_test_backend(backend)
    output_dir = cast(Path, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="aci-edge-sandboxes-e2e-", ignore_cleanup_errors=True
    ) as temporary:
        environment = os.environ.copy()
        environment.update(
            e2e_environment(backend, Path(temporary) / "state", output_dir)
        )
        command = e2e_command(cast(str, args.cargo))
        print(f">> {shlex.join(command)}", flush=True)
        return subprocess.run(command, env=environment, check=False).returncode
