"""Authenticated control-session client for managed NVX microVM workloads."""

from __future__ import annotations

import contextlib
import errno
import math
import os
import secrets
import socket
import struct
import time
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .common import ScriptError, remaining_timeout

OUTER_HEADER = struct.Struct("<4sHBB16sQQI")
APP_HEADER = struct.Struct("<4sBBHQiI")
OUTER_MAX_PAYLOAD = 65_536
APP_MAX_ARGUMENTS = 64
APP_MAX_ARGUMENT_BYTES = 4096
APP_MAX_ENVIRONMENT = 256
APP_MAX_ENVIRONMENT_BYTES = 4096
APP_MAX_CWD_BYTES = 4096
APP_EXEC_EXTENDED = 1
APP_EXEC_CWD_PRESENT = 1
APP_EXEC_ENVIRONMENT_PRESENT = 2
APP_EXEC_INHERIT_DEFAULT_ENV = 4

OUTER_HOST_ATTACH = 2
OUTER_RESET = 3
OUTER_DATA = 5
OUTER_WAIT = 6
OUTER_READY = 7
OUTER_ERROR = 8

APP_PING = 1
APP_EXEC = 2
APP_STOP = 3
APP_READY = 0x81
APP_STDOUT = 0x82
APP_STDERR = 0x83
APP_EXIT = 0x84
APP_STOPPED = 0x85
APP_ERROR = 0xFF
MANAGED_EXIT_CATEGORIES = frozenset(
    {"exit", "timeout", "output-limit", "signal", "failed"}
)


def encode_exec_environment(environment: tuple[str, ...]) -> tuple[bytes, ...]:
    if len(environment) > APP_MAX_ENVIRONMENT:
        raise ValueError("managed exec environment exceeds 256 entries")
    names: set[str] = set()
    encoded: list[bytes] = []
    for entry in environment:
        if type(entry) is not str:
            raise TypeError("managed exec environment entries must be strings")
        name, separator, _value = entry.partition("=")
        value = entry.encode("utf-8")
        if (
            not separator
            or not name
            or "\0" in entry
            or len(value) > APP_MAX_ENVIRONMENT_BYTES
        ):
            raise ValueError(
                "managed exec environment entries must be non-empty "
                "KEY=VALUE strings of at most 4096 bytes"
            )
        if name in names:
            raise ValueError(f"managed exec environment contains duplicate key: {name}")
        names.add(name)
        encoded.append(value)
    return tuple(encoded)


def capability_pipe(capability: bytes) -> int:
    """Returns the read end of a pipe that holds `capability` and then end of file.

    OpenVMM reads `--microvm-control-auth-stdin` without blocking as soon as it
    starts, and fails unless the whole capability and the end of file are already
    there, so a launcher passes this descriptor as OpenVMM's standard input. The
    caller closes it once OpenVMM has started.
    """
    if len(capability) != 32 or capability == bytes(32):
        raise ValueError("control capability must be 32 nonzero bytes")
    read, write = os.pipe()
    try:
        # The capability fits in any pipe's buffer, so these writes cannot block.
        remaining = memoryview(capability)
        while remaining:
            remaining = remaining[os.write(write, remaining) :]
    except BaseException:
        os.close(read)
        raise
    finally:
        os.close(write)
    return read


@dataclass(frozen=True)
class ManagedExecResult:
    returncode: int
    category: str
    stdout: bytes
    stderr: bytes


class ManagedExecRefused(ScriptError):
    """The managed guest refused an exec request instead of reporting an exit.

    It keeps the refusal's status and category, and any output that the guest
    sent first, such as the diagnostic of a ``cwd-failed`` refusal.
    """

    def __init__(
        self, status: int, category: str, stdout: bytes, stderr: bytes
    ) -> None:
        super().__init__(
            f"managed guest rejected exec (status={status}, category={category})"
        )
        self.status = status
        self.category = category
        self.stdout = stdout
        self.stderr = stderr


class ControlEndpointClosed(ConnectionError):
    """OpenVMM closed the managed control endpoint, as it does when it shuts down.

    A session reset, which comes from an OpenVMM that still serves the endpoint,
    is a plain ConnectionError instead.
    """

    def __init__(self, message: str = "managed control endpoint closed") -> None:
        super().__init__(message)


# A peer that closes with data that it has not read resets the connection, and a
# write after the peer closed fails with a broken pipe.
_PEER_CLOSED = (BrokenPipeError, ConnectionResetError)


class _SocketStream:
    def __init__(self, connection: socket.socket) -> None:
        self._connection = connection

    @classmethod
    def connect(cls, path: Path, timeout: float) -> _SocketStream:
        deadline = time.monotonic() + timeout
        family = getattr(socket, "AF_UNIX", None)
        if family is None:
            raise RuntimeError("Unix-domain sockets are unavailable")
        while True:
            connection = socket.socket(cast(int, family), socket.SOCK_STREAM)
            try:
                connection.settimeout(min(0.25, max(0.01, deadline - time.monotonic())))
                connection.connect(os.fspath(path))
                return cls(connection)
            except OSError as error:
                connection.close()
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"managed control endpoint did not become available: {path}"
                    ) from error
                time.sleep(0.025)

    def read_exact(self, length: int, deadline: float) -> bytes:
        output = bytearray()
        while len(output) != length:
            remaining = remaining_timeout(deadline)
            if remaining <= 0:
                raise TimeoutError("managed control response timed out")
            self._connection.settimeout(min(remaining, 0.25))
            try:
                chunk = self._connection.recv(length - len(output))
            except TimeoutError:
                continue
            except _PEER_CLOSED as error:
                raise ControlEndpointClosed() from error
            if not chunk:
                raise ControlEndpointClosed()
            output.extend(chunk)
        return bytes(output)

    def write_all(self, data: bytes, deadline: float) -> None:
        unsent = memoryview(data)
        while unsent:
            remaining = remaining_timeout(deadline)
            if remaining <= 0:
                raise TimeoutError("managed control request timed out")
            self._connection.settimeout(min(remaining, 0.25))
            try:
                sent = self._connection.send(unsent)
            except TimeoutError:
                continue
            except _PEER_CLOSED as error:
                raise ControlEndpointClosed() from error
            if not sent:
                raise ControlEndpointClosed()
            unsent = unsent[sent:]

    def close(self) -> None:
        self._connection.close()


if os.name == "nt":
    import _winapi
    import ctypes

    _cancel_io_ex = ctypes.WinDLL("kernel32", use_last_error=True).CancelIoEx
    _cancel_io_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _cancel_io_ex.restype = ctypes.c_int
else:
    _winapi = cast(Any, None)
    ctypes = cast(Any, None)
    _cancel_io_ex = cast(Any, None)

# Windows fails a transfer on a pipe that its server closed or disconnected with
# ERROR_BROKEN_PIPE, ERROR_NO_DATA, or ERROR_PIPE_NOT_CONNECTED.
_PIPE_CLOSED_ERRORS = frozenset((109, 232, 233))
_ERROR_NOT_FOUND = 1168


@contextlib.contextmanager
def _pipe_closure_reported() -> Generator[None]:
    try:
        yield
    except OSError as error:
        if getattr(error, "winerror", None) in _PIPE_CLOSED_ERRORS:
            raise ControlEndpointClosed() from error
        raise


def _signaled_before(event: int, deadline: float) -> bool:
    while True:
        remaining = remaining_timeout(deadline)
        if remaining <= 0:
            return False
        try:
            # On the main thread, Ctrl+C ends this wait too.
            result = _winapi.WaitForMultipleObjects(
                [event], False, math.ceil(min(remaining, 0.25) * 1000)
            )
        except InterruptedError:
            continue
        if result == _winapi.WAIT_OBJECT_0:
            return True


def _cancel_transfers(handle: int) -> None:
    # Overlapped.cancel() marks a transfer as ended at once, so that releasing the
    # transfer before GetOverlappedResult() reports its end would free a buffer
    # that Windows may still use. CancelIoEx() leaves the transfer pending, and
    # releasing a pending transfer waits for its end or leaks its buffer.
    if not _cancel_io_ex(handle, None):
        error = ctypes.get_last_error()
        if error != _ERROR_NOT_FOUND:
            raise ctypes.WinError(error)


def _finish_transfer(handle: int, transfer: Any, deadline: float, message: str) -> int:
    """Returns how many bytes an overlapped pipe transfer moved.

    A transfer that is still pending at `deadline` is cancelled, and fails with a
    TimeoutError unless it completed first. Windows uses the transfer's buffer
    until the transfer ends, so this waits for that even when it fails.
    """
    try:
        completed = _signaled_before(transfer.event, deadline)
    except BaseException:
        with contextlib.suppress(OSError):
            _cancel_transfers(handle)
            transfer.GetOverlappedResult(True)
        raise
    if not completed:
        _cancel_transfers(handle)
    count, status = transfer.GetOverlappedResult(True)
    if status == _winapi.ERROR_OPERATION_ABORTED:
        raise TimeoutError(message)
    return count


class _NamedPipeStream:
    """A named-pipe client whose transfers end by their deadlines.

    A synchronous write blocks for as long as the endpoint does not drain the
    pipe, so the client opens the pipe for overlapped I/O and cancels a transfer
    that outlives its deadline.
    """

    def __init__(self, handle: int) -> None:
        self._handle = handle

    @classmethod
    def connect(cls, path: Path, timeout: float) -> _NamedPipeStream:
        normalized = os.fspath(path).replace("/", "\\")
        deadline = time.monotonic() + timeout
        while True:
            try:
                return cls(
                    _winapi.CreateFile(
                        normalized,
                        _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
                        0,
                        _winapi.NULL,
                        _winapi.OPEN_EXISTING,
                        _winapi.FILE_FLAG_OVERLAPPED,
                        _winapi.NULL,
                    )
                )
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"managed control endpoint did not become available: {path}"
                    ) from error
                if error.errno not in (
                    errno.ENOENT,
                    errno.EACCES,
                    errno.EBUSY,
                    errno.EAGAIN,
                    # The reconnect transition fails with ERROR_PIPE_BUSY, which
                    # Python reports as EINVAL.
                    errno.EINVAL,
                ):
                    raise
                time.sleep(0.025)

    def read_exact(self, length: int, deadline: float) -> bytes:
        output = bytearray()
        while len(output) != length:
            if remaining_timeout(deadline) <= 0:
                raise TimeoutError("managed control response timed out")
            with _pipe_closure_reported():
                transfer, _ = _winapi.ReadFile(
                    self._handle, length - len(output), overlapped=True
                )
                _finish_transfer(
                    self._handle,
                    transfer,
                    deadline,
                    "managed control response timed out",
                )
            chunk = transfer.getbuffer()
            if not chunk:
                raise ControlEndpointClosed()
            output.extend(chunk)
        return bytes(output)

    def write_all(self, data: bytes, deadline: float) -> None:
        unsent = memoryview(data)
        while unsent:
            if remaining_timeout(deadline) <= 0:
                raise TimeoutError("managed control request timed out")
            with _pipe_closure_reported():
                transfer, _ = _winapi.WriteFile(self._handle, unsent, overlapped=True)
                count = _finish_transfer(
                    self._handle,
                    transfer,
                    deadline,
                    "managed control request timed out",
                )
            if not count:
                raise ControlEndpointClosed()
            unsent = unsent[count:]

    def close(self) -> None:
        _winapi.CloseHandle(self._handle)


class ControlSession:
    def __init__(self, stream: _SocketStream | _NamedPipeStream) -> None:
        self._stream = stream
        self._closed = False
        self._instance_id = bytes(16)
        self._epoch = 0
        self._send_sequence = 0
        self._receive_sequence = 0

    @classmethod
    def connect(
        cls,
        endpoint: Path,
        capability: bytes,
        timeout: float,
        *,
        endpoint_timeout: float | None = None,
    ) -> ControlSession:
        if len(capability) != 32 or capability == bytes(32):
            raise ValueError("control capability must be 32 nonzero bytes")
        connect_timeout = (
            timeout if endpoint_timeout is None else min(timeout, endpoint_timeout)
        )
        stream = (
            _NamedPipeStream.connect(endpoint, connect_timeout)
            if os.name == "nt"
            else _SocketStream.connect(endpoint, connect_timeout)
        )
        session = cls(stream)
        try:
            deadline = time.monotonic() + timeout
            session._write_outer(
                OUTER_HOST_ATTACH,
                bytes(16),
                0,
                0,
                capability,
                deadline,
            )
            while True:
                record_type, instance_id, epoch, sequence, payload = (
                    session._read_outer(deadline)
                )
                if payload:
                    raise ScriptError(
                        "control attach response carried an invalid payload"
                    )
                if record_type == OUTER_WAIT:
                    continue
                if record_type == OUTER_ERROR:
                    raise ScriptError("control capability authentication failed")
                if record_type != OUTER_READY or instance_id == bytes(16) or epoch == 0:
                    raise ScriptError(
                        "control endpoint returned an invalid attach response"
                    )
                session._instance_id = instance_id
                session._epoch = epoch
                session._receive_sequence = sequence + 1
                return session
        except BaseException:
            session.close()
            raise

    @contextlib.contextmanager
    def _transferring_record(self) -> Generator[None]:
        """Closes the session if sending or receiving a record fails.

        A failed transfer may leave a record partly sent or partly received, after
        which later records would not frame correctly.
        """
        if self._closed:
            raise ValueError("managed control session is closed")
        try:
            yield
        except BaseException:
            self.close()
            raise

    def _write_outer(
        self,
        record_type: int,
        instance_id: bytes,
        epoch: int,
        sequence: int,
        payload: bytes,
        deadline: float,
    ) -> None:
        if len(payload) > OUTER_MAX_PAYLOAD:
            raise ValueError("control payload exceeds the outer protocol limit")
        header = OUTER_HEADER.pack(
            b"NVXS",
            1,
            record_type,
            0,
            instance_id,
            epoch,
            sequence,
            len(payload),
        )
        with self._transferring_record():
            self._stream.write_all(header + payload, deadline)

    def _read_outer(
        self,
        deadline: float,
    ) -> tuple[int, bytes, int, int, bytes]:
        with self._transferring_record():
            header = self._stream.read_exact(OUTER_HEADER.size, deadline)
            magic, version, record_type, flags, instance_id, epoch, sequence, length = (
                OUTER_HEADER.unpack(header)
            )
            if (
                magic != b"NVXS"
                or version != 1
                or flags != 0
                or length > OUTER_MAX_PAYLOAD
            ):
                raise ScriptError("control endpoint returned an invalid outer record")
            payload = self._stream.read_exact(length, deadline) if length else b""
        return record_type, instance_id, epoch, sequence, payload

    def _send_app(
        self,
        kind: int,
        request_id: int,
        deadline: float,
        payload: bytes = b"",
    ) -> None:
        frame = (
            APP_HEADER.pack(
                b"NVXC",
                1,
                kind,
                0,
                request_id,
                0,
                len(payload),
            )
            + payload
        )
        self._write_outer(
            OUTER_DATA,
            self._instance_id,
            self._epoch,
            self._send_sequence,
            frame,
            deadline,
        )
        self._send_sequence += 1

    def _read_app(
        self,
        deadline: float,
    ) -> tuple[int, int, int, bytes]:
        record_type, instance_id, epoch, sequence, frame = self._read_outer(deadline)
        if record_type == OUTER_RESET:
            raise ConnectionError("managed control session was reset")
        if (
            record_type != OUTER_DATA
            or instance_id != self._instance_id
            or epoch != self._epoch
            or sequence != self._receive_sequence
            or len(frame) < APP_HEADER.size
        ):
            raise ScriptError("control endpoint returned an invalid data record")
        self._receive_sequence += 1
        magic, version, kind, flags, request_id, status, length = APP_HEADER.unpack(
            frame[: APP_HEADER.size]
        )
        payload = frame[APP_HEADER.size :]
        if magic != b"NVXC" or version != 1 or flags != 0 or length != len(payload):
            raise ScriptError("control endpoint returned an invalid application frame")
        return kind, request_id, status, payload

    @staticmethod
    def _request_id() -> int:
        return secrets.randbits(64) or 1

    def ping(self, timeout: float) -> None:
        request_id = self._request_id()
        deadline = time.monotonic() + timeout
        self._send_app(APP_PING, request_id, deadline)
        kind, response_id, status, payload = self._read_app(deadline)
        if kind != APP_READY or response_id != request_id or status != 0 or payload:
            raise ScriptError("managed guest did not acknowledge readiness")

    def exec(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        response_timeout: float,
        cwd: str | None = None,
        environment: tuple[str, ...] | None = None,
        inherit_default_environment: bool = False,
    ) -> ManagedExecResult:
        if not 0 < response_timeout < float("inf"):
            raise ValueError(
                "managed exec response timeout must be positive and finite"
            )
        if not 1 <= len(arguments) <= APP_MAX_ARGUMENTS:
            raise ValueError("managed exec requires 1 through 64 arguments")
        encoded: list[bytes] = []
        for argument in arguments:
            if type(argument) is not str:
                raise TypeError("managed exec arguments must be strings")
            value = argument.encode("utf-8")
            if not value or len(value) > APP_MAX_ARGUMENT_BYTES or b"\0" in value:
                raise ValueError("managed exec argument is empty or exceeds 4096 bytes")
            encoded.append(struct.pack("<I", len(value)) + value)
        if not arguments[0].startswith("/"):
            raise ValueError("managed exec entrypoint must be absolute")
        if type(timeout_ms) is not int:
            raise TypeError("managed exec timeout must be an integer")
        if not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("managed exec timeout must be 0 through 4294967295 ms")

        flags = 0
        encoded_cwd = b""
        if cwd is not None:
            if type(cwd) is not str:
                raise TypeError("managed exec working directory must be a string")
            encoded_cwd = cwd.encode("utf-8")
            if (
                not encoded_cwd
                or len(encoded_cwd) > APP_MAX_CWD_BYTES
                or b"\0" in encoded_cwd
                or not cwd.startswith("/")
            ):
                raise ValueError(
                    "managed exec working directory must be an absolute path "
                    "of at most 4096 bytes"
                )
            flags |= APP_EXEC_CWD_PRESENT

        if type(inherit_default_environment) is not bool:
            raise TypeError("managed exec environment inheritance must be a boolean")
        encoded_environment: list[bytes] = []
        if environment is not None:
            for value in encode_exec_environment(environment):
                encoded_environment.append(struct.pack("<I", len(value)) + value)
            flags |= APP_EXEC_ENVIRONMENT_PRESENT
            # An omitted environment already is the default one, so inheritance only
            # changes a supplied environment, as MXC's inheritDefaultEnv does.
            if inherit_default_environment:
                flags |= APP_EXEC_INHERIT_DEFAULT_ENV

        if flags == 0:
            payload = struct.pack("<IHH", timeout_ms, len(arguments), 0) + b"".join(
                encoded
            )
        else:
            payload = (
                struct.pack(
                    "<IHHHHI",
                    timeout_ms,
                    len(arguments),
                    APP_EXEC_EXTENDED,
                    flags,
                    len(encoded_environment),
                    len(encoded_cwd),
                )
                + b"".join(encoded)
                + encoded_cwd
                + b"".join(encoded_environment)
            )
        if len(payload) + APP_HEADER.size > OUTER_MAX_PAYLOAD:
            raise ValueError("managed exec request exceeds the protocol limit")

        request_id = self._request_id()
        # The response timeout bounds the whole exchange, so an endpoint that
        # stops reading cannot hold up sending the request either.
        deadline = time.monotonic() + response_timeout
        self._send_app(APP_EXEC, request_id, deadline, payload)
        stdout = bytearray()
        stderr = bytearray()
        while True:
            kind, response_id, status, response = self._read_app(deadline)
            if response_id != request_id:
                raise ScriptError("managed guest returned a mismatched request ID")
            if kind == APP_STDOUT:
                stdout.extend(response)
            elif kind == APP_STDERR:
                stderr.extend(response)
            elif kind == APP_EXIT:
                try:
                    category = response.decode("ascii")
                except UnicodeDecodeError as error:
                    raise ScriptError(
                        "managed guest returned an invalid exit category"
                    ) from error
                if category not in MANAGED_EXIT_CATEGORIES:
                    raise ScriptError(
                        "managed guest returned an unsupported exit category"
                    )
                return ManagedExecResult(status, category, bytes(stdout), bytes(stderr))
            elif kind == APP_ERROR:
                raise ManagedExecRefused(
                    status,
                    response.decode("ascii", "replace"),
                    bytes(stdout),
                    bytes(stderr),
                )
            else:
                raise ScriptError("managed guest returned an invalid exec response")

    def stop(self, timeout: float) -> None:
        request_id = self._request_id()
        deadline = time.monotonic() + timeout
        self._send_app(APP_STOP, request_id, deadline)
        kind, response_id, status, payload = self._read_app(deadline)
        if kind != APP_STOPPED or response_id != request_id or status != 0 or payload:
            raise ScriptError("managed guest did not acknowledge stop")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stream.close()

    def __enter__(self) -> ControlSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
