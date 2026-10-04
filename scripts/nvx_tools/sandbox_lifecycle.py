"""Persistent lifecycle operations for managed NVX microVM sandboxes."""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, cast

from .build_constants import (
    AlpineBuildConstants,
    KernelBuildConstants,
)
from .common import (
    ScriptError,
    artifact_path,
    openvmm_binary_path,
    require_directory,
    require_file,
)
from .control_session import (
    MANAGED_EXIT_CATEGORIES,
    ControlSession,
    ManagedExecResult,
)
from .sandbox import SandboxLaunch, SandboxLayer, SandboxMount

CONFIG_NAME = "config.json"
RUNTIME_NAME = "runtime.json"
CAPABILITY_NAME = "control.capability"
LOG_NAME = "openvmm.log"
CONTROL_SOCKET_NAME = "control.sock"
OUTCOME_NAME = "outcome.json"
STATE_FORMAT = 1
CONFIG_FORMAT = 1
# Format-1 readers ignore unknown fields, so a configuration with a live share
# uses a format that older NVX releases reject instead of starting without it.
MOUNT_CONFIG_FORMAT = 2
# Same rule for a configuration that captures or restores a snapshot: an older
# release must reject it rather than silently boot without the wake plane.
SNAPSHOT_CONFIG_FORMAT = 3
CONFIG_FORMATS = (CONFIG_FORMAT, MOUNT_CONFIG_FORMAT, SNAPSHOT_CONFIG_FORMAT)
SNAPSHOT_TIERS = ("platform", "workload-start", "instance-checkpoint")
OUTCOME_SCHEMA_VERSION = 1


def _write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(
    path: Path,
    description: str,
    *,
    version_field: str = "format",
    version: int | tuple[int, ...] = STATE_FORMAT,
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScriptError(f"failed to read {description}: {path}") from error
    if not isinstance(value, dict):
        raise ScriptError(f"{description} has an unsupported format: {path}")
    typed = cast(dict[str, Any], value)
    accepted = (version,) if isinstance(version, int) else version
    if typed.get(version_field) not in accepted:
        raise ScriptError(f"{description} has an unsupported format: {path}")
    return typed


def _outcome_destination(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    parent = candidate.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ScriptError(f"outcome report parent is not a plain directory: {parent}")
    if not candidate.name:
        raise ScriptError("outcome report path has no filename")
    resolved = parent.resolve() / candidate.name
    if os.path.lexists(resolved):
        raise ScriptError(f"outcome report already exists: {resolved}")
    return resolved


def validate_outcome_destination(path: Path) -> None:
    _outcome_destination(path)


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    resolved = _outcome_destination(path)
    temporary = resolved.with_name(f".{resolved.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except FileExistsError as error:
        raise ScriptError("failed to reserve an outcome report staging file") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, resolved)
        except FileExistsError as error:
            raise ScriptError(f"outcome report already exists: {resolved}") from error
        except OSError as error:
            raise ScriptError(
                f"failed to publish outcome report: {resolved}"
            ) from error
    finally:
        temporary.unlink(missing_ok=True)


def _read_openvmm_outcome(path: Path) -> dict[str, Any]:
    typed = _read_json(
        path,
        "OpenVMM outcome report",
        version_field="schema_version",
        version=OUTCOME_SCHEMA_VERSION,
    )
    for name in ("outcome", "network_policy", "teardown"):
        if not isinstance(typed.get(name), dict):
            raise ScriptError(
                f"OpenVMM outcome report has an invalid {name} section: {path}"
            )
    return typed


def write_exec_outcome(path: Path, result: ManagedExecResult) -> None:
    if result.category not in MANAGED_EXIT_CATEGORIES:
        raise ScriptError("managed workload returned an unsupported outcome category")
    if not -(2**31) <= result.returncode < 2**31:
        raise ScriptError("managed workload returned an out-of-range status")
    _write_new_json(
        path,
        {
            "schema_version": OUTCOME_SCHEMA_VERSION,
            "operation_id": secrets.token_hex(16),
            "outcome": {
                "operation": "exec",
                "category": result.category,
                "status_code": result.returncode,
            },
        },
    )


def _prepare_state_directory(path: Path, *, create: bool) -> Path:
    resolved = path.resolve()
    if create:
        resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(resolved, 0o700)
    if resolved.is_symlink() or not resolved.is_dir():
        raise ScriptError(f"sandbox state path is not a plain directory: {resolved}")
    return resolved


def _serialize_launch(
    launch: SandboxLaunch,
    *,
    hypervisor: str,
    memory_mib: int,
    net: str | None,
    network_profile: str | None,
    network_egress: str | None,
    network_ingress: str | None,
    network_egress_allow: tuple[str, ...],
    network_egress_deny: tuple[str, ...],
    host_loopback: str | None,
    network_proxy: str | None,
    host_loopback_forward: tuple[str, ...],
    cmdline: str,
    snapshot_destination: Path | None = None,
    snapshot_tier: str | None = None,
    restore_snapshot: Path | None = None,
) -> dict[str, Any]:
    snapshot = snapshot_destination is not None or restore_snapshot is not None
    return {
        "format": _config_format(launch, snapshot=snapshot),
        "layers": [
            {
                "role": layer.role,
                "path": os.fspath(layer.path.resolve()),
                "uuid": layer.uuid,
            }
            for layer in launch.ordered_layers()
        ],
        "scratch": os.fspath(launch.scratch.resolve()),
        "hostname": launch.hostname,
        "workload_uid": launch.workload_identity[0],
        "workload_gid": launch.workload_identity[1],
        "memory_max": launch.memory_max,
        "pids_max": launch.pids_max,
        "processors": launch.processors,
        "hypervisor": hypervisor,
        "memory_mib": memory_mib,
        "net": net,
        "network_profile": network_profile,
        "network_egress": network_egress,
        "network_ingress": network_ingress,
        "network_egress_allow": list(network_egress_allow),
        "network_egress_deny": list(network_egress_deny),
        "host_loopback": host_loopback,
        "network_proxy": network_proxy,
        "host_loopback_forward": list(host_loopback_forward),
        "cmdline": cmdline,
        "mount": _serialize_mount(launch.mount),
        "snapshot_destination": (
            None if snapshot_destination is None else os.fspath(snapshot_destination)
        ),
        "snapshot_tier": snapshot_tier,
        "restore_snapshot": (
            None if restore_snapshot is None else os.fspath(restore_snapshot)
        ),
    }


def _config_format(launch: SandboxLaunch, *, snapshot: bool) -> int:
    if snapshot:
        return SNAPSHOT_CONFIG_FORMAT
    return CONFIG_FORMAT if launch.mount is None else MOUNT_CONFIG_FORMAT


def _serialize_mount(mount: SandboxMount | None) -> dict[str, Any] | None:
    if mount is None:
        return None
    absolute = mount.absolute()
    return {
        "guest_target": absolute.guest_target,
        "host_path": os.fspath(absolute.host_path),
        "access": absolute.access,
        "denied_paths": list(absolute.denied_paths),
    }


def _deserialize_mount(value: object) -> SandboxMount | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError("sandbox mount configuration must be an object")
    mount = cast(dict[str, Any], value)
    denied_paths = mount["denied_paths"]
    if not isinstance(denied_paths, list):
        raise TypeError("sandbox mount denied paths must be a list")
    return SandboxMount(
        guest_target=str(mount["guest_target"]),
        host_path=Path(str(mount["host_path"])),
        access=str(mount["access"]),
        denied_paths=tuple(str(path) for path in cast(list[object], denied_paths)),
    )


def _deserialize_launch(config: dict[str, Any]) -> SandboxLaunch:
    try:
        layers = tuple(
            SandboxLayer(
                role=str(layer["role"]),
                path=Path(str(layer["path"])),
                uuid=str(layer["uuid"]),
            )
            for layer in config["layers"]
        )
        identity = (int(config["workload_uid"]), int(config["workload_gid"]))
        launch = SandboxLaunch(
            layers=layers,
            scratch=Path(str(config["scratch"])),
            hostname=str(config["hostname"]),
            workload_identity=identity,
            memory_max=(
                None if config["memory_max"] is None else int(config["memory_max"])
            ),
            pids_max=None if config["pids_max"] is None else int(config["pids_max"]),
            mount=_deserialize_mount(config.get("mount")),
            # Format 1 and 2 predate --processors and stored no value.
            processors=int(config.get("processors", 1)),
            # A restore never re-arms the guest capture point: the restored
            # guest resumes past it from saved state. Only a capture config
            # does, so it survives a stop/start cycle on the same sandbox.
            snapshot_capture=config.get("snapshot_destination") is not None,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ScriptError("sandbox configuration is malformed") from error
    # Format 1 is the no-share configuration, format 2 exists only to carry a
    # live share, and format 3 (snapshot) admits either.
    config_format = config.get("format")
    if (config_format == CONFIG_FORMAT and launch.mount is not None) or (
        config_format == MOUNT_CONFIG_FORMAT and launch.mount is None
    ):
        raise ScriptError("sandbox configuration format does not match its mount")
    return launch.validated()


def _process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_uint32()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
        return exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def _load_running(state_dir: Path) -> tuple[dict[str, Any], bytes]:
    runtime_path = state_dir / RUNTIME_NAME
    if not runtime_path.is_file():
        raise ScriptError("sandbox is not running")
    runtime = _read_json(runtime_path, "sandbox runtime state")
    try:
        pid = int(runtime["pid"])
    except (KeyError, TypeError, ValueError) as error:
        raise ScriptError("sandbox runtime state has an invalid process ID") from error
    if not _process_running(pid):
        raise ScriptError(
            "sandbox runtime state is stale because the OpenVMM process is not running"
        )
    capability = require_file(
        state_dir / CAPABILITY_NAME, "sandbox control capability"
    ).read_bytes()
    if len(capability) != 32 or capability == bytes(32):
        raise ScriptError("sandbox control capability is invalid")
    return runtime, capability


def _endpoint(runtime: dict[str, Any]) -> Path:
    try:
        return Path(str(runtime["control_endpoint"]))
    except KeyError as error:
        raise ScriptError("sandbox runtime state has no control endpoint") from error


def provision(
    state_path: Path,
    launch: SandboxLaunch,
    *,
    hypervisor: str,
    memory_mib: int,
    net: str | None,
    network_profile: str | None,
    network_egress: str | None,
    network_ingress: str | None,
    network_egress_allow: tuple[str, ...],
    network_egress_deny: tuple[str, ...],
    host_loopback: str | None,
    network_proxy: str | None,
    host_loopback_forward: tuple[str, ...],
    cmdline: str,
    snapshot_destination: Path | None = None,
    snapshot_tier: str | None = None,
    restore_snapshot: Path | None = None,
) -> None:
    state_dir = _prepare_state_directory(state_path, create=True)
    config_path = state_dir / CONFIG_NAME
    runtime_path = state_dir / RUNTIME_NAME
    if config_path.exists() or runtime_path.exists():
        raise ScriptError("sandbox is already provisioned")
    if snapshot_destination is not None and restore_snapshot is not None:
        raise ScriptError(
            "sandbox snapshot capture and restore are mutually exclusive"
        )
    if snapshot_tier is not None and snapshot_destination is None:
        raise ScriptError("a sandbox snapshot tier requires a snapshot destination")
    if snapshot_tier is not None and snapshot_tier not in SNAPSHOT_TIERS:
        raise ScriptError(
            "unsupported sandbox snapshot tier; choose " + ", ".join(SNAPSHOT_TIERS)
        )
    if restore_snapshot is not None:
        require_directory(restore_snapshot, "sandbox restore snapshot")
    for snapshot, description in (
        (snapshot_destination, "sandbox snapshot destination"),
        (restore_snapshot, "sandbox restore snapshot"),
    ):
        if snapshot is not None:
            _snapshot_namespace(snapshot, description)
    _write_json(
        config_path,
        _serialize_launch(
            launch.validated(),
            hypervisor=hypervisor,
            memory_mib=memory_mib,
            net=net,
            network_profile=network_profile,
            network_egress=network_egress,
            network_ingress=network_ingress,
            network_egress_allow=network_egress_allow,
            network_egress_deny=network_egress_deny,
            host_loopback=host_loopback,
            network_proxy=network_proxy,
            host_loopback_forward=host_loopback_forward,
            cmdline=cmdline,
            snapshot_destination=snapshot_destination,
            snapshot_tier=snapshot_tier,
            restore_snapshot=restore_snapshot,
        ),
    )


def _snapshot_namespace(snapshot: Path, description: str) -> Path:
    """Return the private directory that must hold a snapshot and its console.

    OpenVMM binds a microVM console socket only inside the snapshot's own
    device namespace, and only into a directory this user owns with mode
    0700. That makes the snapshot's parent directory part of the sandbox
    contract, so an unusable one is rejected before any VM state is written
    rather than at boot.
    """
    parent = snapshot.parent if os.fspath(snapshot.parent) else Path(".")
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise ScriptError(
            f"{description} parent directory is unreadable: {parent}"
        ) from error
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ScriptError(f"{description} parent must be a plain directory: {parent}")
    if metadata.st_uid != os.geteuid():
        raise ScriptError(
            f"{description} parent must be owned by the current user: {parent}"
        )
    if mode != 0o700:
        raise ScriptError(
            f"{description} parent must have mode 0700 so only this user can "
            f"reach the sandbox console socket: {parent} (found {mode:04o})"
        )
    return parent


def _restore_snapshot_path(config: dict[str, Any]) -> Path | None:
    """Return the configured snapshot restore source, if this sandbox restores."""
    value = config.get("restore_snapshot")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ScriptError("sandbox configuration has an invalid restore snapshot")
    return Path(value)


def _snapshot_capture(
    config: dict[str, Any],
) -> tuple[Path | None, str | None]:
    """Return the configured snapshot capture destination and tier."""
    destination = config.get("snapshot_destination")
    tier = config.get("snapshot_tier")
    if destination is None:
        if tier is not None:
            raise ScriptError(
                "--snapshot-tier requires --snapshot-destination in the sandbox "
                "configuration"
            )
        return None, None
    if not isinstance(destination, str) or not destination:
        raise ScriptError("sandbox configuration has an invalid snapshot destination")
    if tier not in SNAPSHOT_TIERS:
        raise ScriptError(
            "sandbox configuration has an unsupported snapshot tier; choose "
            + ", ".join(SNAPSHOT_TIERS)
        )
    return Path(destination), str(tier)


def start(state_path: Path, timeout: float) -> None:
    state_dir = _prepare_state_directory(state_path, create=False)
    config = _read_json(
        require_file(state_dir / CONFIG_NAME, "sandbox configuration"),
        "sandbox configuration",
        version=CONFIG_FORMATS,
    )
    if (state_dir / RUNTIME_NAME).exists():
        raise ScriptError("sandbox is already running or has stale runtime state")
    outcome_path = state_dir / OUTCOME_NAME
    outcome_path.unlink(missing_ok=True)
    launch = _deserialize_launch(config)
    restore_snapshot = _restore_snapshot_path(config)
    snapshot_destination, snapshot_tier = _snapshot_capture(config)
    executable = require_file(openvmm_binary_path(), "OpenVMM release binary")
    kernel = require_file(
        artifact_path(KernelBuildConstants.BINARY_NAME), "Linux direct kernel"
    )
    initrd = require_file(
        artifact_path(AlpineBuildConstants.INITRAMFS_NAME), "initramfs"
    )
    capability = secrets.token_bytes(32)
    if capability == bytes(32):
        raise AssertionError("secrets.token_bytes returned an all-zero capability")
    if os.name == "nt":
        endpoint_value = f"//./pipe/openvmm-microvm-{uuid.uuid4().hex}"
    else:
        # OpenVMM binds the console into the snapshot's device namespace: the
        # socket's parent directory must be exactly the snapshot directory's
        # parent, or it refuses to start. A capture or restore therefore puts
        # the control socket next to the snapshot directory.
        snapshot_dir = restore_snapshot if restore_snapshot is not None else (
            snapshot_destination
        )
        socket_dir = (
            state_dir
            if snapshot_dir is None
            else _snapshot_namespace(snapshot_dir, "sandbox snapshot")
        )
        endpoint_value = os.fspath(socket_dir / CONTROL_SOCKET_NAME)
    # A restore takes the guest kernel, command line, memory size, workload
    # identity, lifecycle, and network from the snapshot itself, so those
    # options are rejected by OpenVMM on this path; the layer and scratch
    # devices are still required so the snapshot's device contract can be
    # re-validated against the same files.
    command = [
        os.fspath(executable),
        *launch.openvmm_arguments(restore=restore_snapshot is not None),
        "--single-process",
        "--hypervisor",
        str(config["hypervisor"]),
        "--virtio-console",
        "none",
        "--microvm-control-console",
        f"listen={endpoint_value}",
        "--microvm-control-auth-stdin",
        "--microvm-report",
        os.fspath(outcome_path),
    ]
    if restore_snapshot is not None:
        command.extend(
            ["--restore-snapshot", os.fspath(restore_snapshot), "--restore-entropy"]
        )
    else:
        command.extend(
            [
                "--microvm-lifecycle",
                "managed",
                "--memory",
                f"{int(config['memory_mib'])}M",
                "--kernel",
                os.fspath(kernel),
                "--initrd",
                os.fspath(initrd),
                "--cmdline",
                launch.kernel_command_line(str(config["cmdline"])),
            ]
        )
        if snapshot_destination is not None:
            command.extend(
                [
                    "--snapshot-destination",
                    os.fspath(snapshot_destination),
                    "--snapshot-tier",
                    str(snapshot_tier),
                ]
            )
    net = config.get("net")
    network_profile = config.get("network_profile")
    if restore_snapshot is not None:
        # OpenVMM rejects network options on a restore: addressing, egress
        # policy, and forwarding all come from the captured state.
        net = None
    if net is not None:
        command.extend(["--net", str(net), "--network-profile", str(network_profile)])
    for name in ("network_egress", "network_ingress", "host_loopback"):
        value = config.get(name)
        if value is not None and restore_snapshot is None:
            command.extend([f"--{name.replace('_', '-')}", str(value)])
    for name in (
        "network_egress_allow",
        "network_egress_deny",
        "host_loopback_forward",
    ):
        values = config.get(name, [])
        if not isinstance(values, list):
            raise ScriptError("sandbox configuration is malformed")
        if restore_snapshot is not None:
            continue
        for value in cast(list[object], values):
            command.extend([f"--{name.replace('_', '-')}", str(value)])
    network_proxy = config.get("network_proxy")
    if network_proxy is not None and restore_snapshot is None:
        command.extend(["--network-proxy", str(network_proxy)])

    capability_path = state_dir / CAPABILITY_NAME
    capability_path.write_bytes(capability)
    os.chmod(capability_path, 0o600)
    log_path = state_dir / LOG_NAME
    log = log_path.open("ab", buffering=0)
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
            creationflags=creationflags,
        )
        if process.stdin is None:
            raise ScriptError("failed to create the OpenVMM capability pipe")
        process.stdin.write(capability)
        process.stdin.close()
        _write_json(
            state_dir / RUNTIME_NAME,
            {
                "format": STATE_FORMAT,
                "pid": process.pid,
                "control_endpoint": endpoint_value,
            },
        )
        with ControlSession.connect(
            Path(endpoint_value), capability, timeout
        ) as session:
            session.ping(timeout)
    except BaseException:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        (state_dir / RUNTIME_NAME).unlink(missing_ok=True)
        capability_path.unlink(missing_ok=True)
        Path(endpoint_value).unlink(missing_ok=True)
        raise
    finally:
        log.close()


def exec_workload(
    state_path: Path,
    arguments: tuple[str, ...],
    *,
    timeout_ms: int,
    response_timeout: float,
) -> ManagedExecResult:
    state_dir = _prepare_state_directory(state_path, create=False)
    runtime, capability = _load_running(state_dir)
    with ControlSession.connect(
        _endpoint(runtime), capability, response_timeout
    ) as session:
        return session.exec(
            arguments,
            timeout_ms=timeout_ms,
            response_timeout=response_timeout,
        )


def stop(state_path: Path, timeout: float) -> dict[str, Any]:
    state_dir = _prepare_state_directory(state_path, create=False)
    runtime, capability = _load_running(state_dir)
    with ControlSession.connect(_endpoint(runtime), capability, timeout) as session:
        session.stop(timeout)
    pid = int(runtime["pid"])
    deadline = time.monotonic() + timeout
    while _process_running(pid):
        if time.monotonic() >= deadline:
            raise TimeoutError("OpenVMM did not terminate after managed stop")
        time.sleep(0.025)
    try:
        outcome = _read_openvmm_outcome(state_dir / OUTCOME_NAME)
    finally:
        (state_dir / RUNTIME_NAME).unlink(missing_ok=True)
        (state_dir / CAPABILITY_NAME).unlink(missing_ok=True)
        _unlink_control_socket(state_dir, runtime)
    return outcome


def _unlink_control_socket(state_dir: Path, runtime: dict[str, Any]) -> None:
    """Remove the control socket wherever the runtime recorded it.

    A capture or restore binds the socket outside the state directory, into
    the snapshot's parent namespace, so the recorded endpoint is the truth.
    A relative endpoint predates that layout and names the state directory's
    own socket.
    """
    try:
        endpoint = _endpoint(runtime)
    except ScriptError:
        return
    if not endpoint.is_absolute():
        endpoint = state_dir / endpoint
    endpoint.unlink(missing_ok=True)


def deprovision(state_path: Path) -> None:
    state_dir = _prepare_state_directory(state_path, create=False)
    runtime_path = state_dir / RUNTIME_NAME
    runtime: dict[str, Any] | None = None
    if runtime_path.is_file():
        runtime = _read_json(runtime_path, "sandbox runtime state")
        try:
            running = _process_running(int(runtime["pid"]))
        except (KeyError, TypeError, ValueError) as error:
            raise ScriptError(
                "sandbox runtime state has an invalid process ID"
            ) from error
        if running:
            raise ScriptError("sandbox must be stopped before deprovision")
        _unlink_control_socket(state_dir, runtime)
    for name in (
        RUNTIME_NAME,
        CAPABILITY_NAME,
        CONTROL_SOCKET_NAME,
        OUTCOME_NAME,
        LOG_NAME,
        CONFIG_NAME,
    ):
        (state_dir / name).unlink(missing_ok=True)
    unknown = tuple(state_dir.iterdir())
    if unknown:
        raise ScriptError(
            "sandbox state directory contains files not owned by NVX: "
            + ", ".join(path.name for path in unknown)
        )
    state_dir.rmdir()
