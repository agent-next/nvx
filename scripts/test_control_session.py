#!/usr/bin/env python3
# pyright: reportPrivateUsage=false

import socket
import struct
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from nvx_tools import control_session  # noqa: E402


def _read_exact(connection: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) != length:
        chunk = connection.recv(length - len(output))
        if not chunk:
            raise RuntimeError("test control connection closed")
        output.extend(chunk)
    return bytes(output)


def _read_outer(connection: socket.socket):
    header = _read_exact(connection, control_session.OUTER_HEADER.size)
    values = control_session.OUTER_HEADER.unpack(header)
    payload = _read_exact(connection, values[-1]) if values[-1] else b""
    return (*values[:-1], payload)


def _write_app(
    connection: socket.socket,
    *,
    instance_id: bytes,
    sequence: int,
    kind: int,
    request_id: int,
    status: int,
    payload: bytes,
) -> None:
    app = (
        control_session.APP_HEADER.pack(
            b"NVXC",
            1,
            kind,
            0,
            request_id,
            status,
            len(payload),
        )
        + payload
    )
    connection.sendall(
        control_session.OUTER_HEADER.pack(
            b"NVXS",
            1,
            control_session.OUTER_DATA,
            0,
            instance_id,
            1,
            sequence,
            len(app),
        )
        + app
    )


class ControlSessionTests(unittest.TestCase):
    def test_exec_streams_output_and_returns_bounded_status(self):
        client, server = socket.socketpair()
        instance = bytes.fromhex("11" * 16)
        session = control_session.ControlSession(control_session._SocketStream(client))
        session._instance_id = instance
        session._epoch = 1

        def serve() -> None:
            (
                magic,
                version,
                record_type,
                flags,
                actual_instance,
                epoch,
                sequence,
                frame,
            ) = _read_outer(server)
            self.assertEqual(
                (
                    magic,
                    version,
                    record_type,
                    flags,
                    actual_instance,
                    epoch,
                    sequence,
                ),
                (b"NVXS", 1, control_session.OUTER_DATA, 0, instance, 1, 0),
            )
            (
                app_magic,
                app_version,
                kind,
                app_flags,
                request_id,
                status,
                payload_length,
            ) = control_session.APP_HEADER.unpack(
                frame[: control_session.APP_HEADER.size]
            )
            self.assertEqual(
                (app_magic, app_version, kind, app_flags, status),
                (b"NVXC", 1, control_session.APP_EXEC, 0, 0),
            )
            payload = frame[control_session.APP_HEADER.size :]
            self.assertEqual(payload_length, len(payload))
            timeout_ms, argc, reserved = struct.unpack("<IHH", payload[:8])
            self.assertEqual((timeout_ms, argc, reserved), (5000, 3, 0))

            _write_app(
                server,
                instance_id=instance,
                sequence=0,
                kind=control_session.APP_STDOUT,
                request_id=request_id,
                status=0,
                payload=b"hello",
            )
            _write_app(
                server,
                instance_id=instance,
                sequence=1,
                kind=control_session.APP_STDERR,
                request_id=request_id,
                status=0,
                payload=b"warning",
            )
            _write_app(
                server,
                instance_id=instance,
                sequence=2,
                kind=control_session.APP_EXIT,
                request_id=request_id,
                status=7,
                payload=b"exit",
            )
            server.close()

        worker = threading.Thread(target=serve)
        worker.start()
        result = session.exec(
            ("/bin/sh", "-c", "echo hello"),
            timeout_ms=5000,
            response_timeout=5,
        )
        worker.join(timeout=5)
        session.close()

        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.category, "exit")
        self.assertEqual(result.stdout, b"hello")
        self.assertEqual(result.stderr, b"warning")

    def test_exec_rejects_unbounded_or_relative_arguments(self):
        client, server = socket.socketpair()
        session = control_session.ControlSession(control_session._SocketStream(client))
        with self.assertRaisesRegex(ValueError, "absolute"):
            session.exec(("relative",), timeout_ms=0, response_timeout=1)
        with self.assertRaisesRegex(ValueError, "64"):
            session.exec(
                tuple("/bin/true" for _ in range(65)),
                timeout_ms=0,
                response_timeout=1,
            )
        session.close()
        server.close()

    def test_exec_encodes_extended_cwd_and_environment_exactly(self):
        client, server = socket.socketpair()
        instance = bytes.fromhex("33" * 16)
        session = control_session.ControlSession(control_session._SocketStream(client))
        session._instance_id = instance
        session._epoch = 1
        captured: dict[str, object] = {}

        def serve() -> None:
            *_, frame = _read_outer(server)
            header = control_session.APP_HEADER.unpack(
                frame[: control_session.APP_HEADER.size]
            )
            request_id = header[4]
            payload = frame[control_session.APP_HEADER.size :]
            (
                timeout_ms,
                argc,
                extension,
                flags,
                envc,
                cwd_len,
            ) = struct.unpack("<IHHHHI", payload[:16])
            offset = 16
            values: list[bytes] = []
            for _ in range(argc):
                length = struct.unpack("<I", payload[offset : offset + 4])[0]
                offset += 4
                values.append(payload[offset : offset + length])
                offset += length
            cwd = payload[offset : offset + cwd_len]
            offset += cwd_len
            environment: list[bytes] = []
            for _ in range(envc):
                length = struct.unpack("<I", payload[offset : offset + 4])[0]
                offset += 4
                environment.append(payload[offset : offset + length])
                offset += length
            captured.update(
                timeout_ms=timeout_ms,
                extension=extension,
                flags=flags,
                values=values,
                cwd=cwd,
                environment=environment,
                offset=offset,
                payload_len=len(payload),
            )
            _write_app(
                server,
                instance_id=instance,
                sequence=0,
                kind=control_session.APP_EXIT,
                request_id=request_id,
                status=0,
                payload=b"exit",
            )
            server.close()

        worker = threading.Thread(target=serve)
        worker.start()
        session.exec(
            ("/bin/sh", "-c", "printf exact"),
            timeout_ms=0xFFFFFFFF,
            response_timeout=5,
            cwd="/tmp/space \N{SNOWMAN}",
            environment=("EMPTY=", "SPACED=a b", "EQUALS=a=b", "UTF8=\N{SNOWMAN}"),
        )
        worker.join(timeout=5)
        session.close()

        self.assertEqual(captured["timeout_ms"], 0xFFFFFFFF)
        self.assertEqual(captured["extension"], control_session.APP_EXEC_EXTENDED)
        self.assertEqual(
            captured["flags"],
            control_session.APP_EXEC_CWD_PRESENT
            | control_session.APP_EXEC_ENVIRONMENT_PRESENT,
        )
        self.assertEqual(captured["values"], [b"/bin/sh", b"-c", b"printf exact"])
        self.assertEqual(captured["cwd"], "/tmp/space \N{SNOWMAN}".encode())
        self.assertEqual(
            captured["environment"],
            [
                b"EMPTY=",
                b"SPACED=a b",
                b"EQUALS=a=b",
                "UTF8=\N{SNOWMAN}".encode(),
            ],
        )
        self.assertEqual(captured["offset"], captured["payload_len"])

    def _exec_payload(
        self,
        environment: tuple[str, ...] | None,
        *,
        inherit_default_environment: bool = False,
    ) -> bytes:
        client, server = socket.socketpair()
        session = control_session.ControlSession(control_session._SocketStream(client))
        session._instance_id = bytes.fromhex("44" * 16)
        session._epoch = 1
        captured = bytearray()

        def serve() -> None:
            *_, frame = _read_outer(server)
            header = control_session.APP_HEADER.unpack(
                frame[: control_session.APP_HEADER.size]
            )
            captured.extend(frame[control_session.APP_HEADER.size :])
            _write_app(
                server,
                instance_id=session._instance_id,
                sequence=0,
                kind=control_session.APP_EXIT,
                request_id=header[4],
                status=0,
                payload=b"exit",
            )
            server.close()

        worker = threading.Thread(target=serve)
        worker.start()
        session.exec(
            ("/bin/true",),
            timeout_ms=0,
            response_timeout=5,
            environment=environment,
            inherit_default_environment=inherit_default_environment,
        )
        worker.join(timeout=5)
        session.close()
        return bytes(captured)

    def test_exec_distinguishes_omitted_and_empty_environment(self):
        omitted = self._exec_payload(None)
        empty = self._exec_payload(())
        self.assertEqual(struct.unpack("<H", omitted[6:8])[0], 0)
        self.assertEqual(struct.unpack("<H", empty[6:8])[0], 1)
        self.assertEqual(
            struct.unpack("<H", empty[8:10])[0],
            control_session.APP_EXEC_ENVIRONMENT_PRESENT,
        )
        self.assertEqual(struct.unpack("<H", empty[10:12])[0], 0)

    def test_exec_layers_only_a_supplied_environment_over_the_defaults(self):
        layered_flags = (
            control_session.APP_EXEC_ENVIRONMENT_PRESENT
            | control_session.APP_EXEC_INHERIT_DEFAULT_ENV
        )
        layered = self._exec_payload(("A=1",), inherit_default_environment=True)
        self.assertEqual(
            struct.unpack("<HHHI", layered[6:16]),
            (control_session.APP_EXEC_EXTENDED, layered_flags, 1, 0),
        )
        self.assertTrue(layered.endswith(struct.pack("<I", 3) + b"A=1"))
        empty = self._exec_payload((), inherit_default_environment=True)
        self.assertEqual(
            struct.unpack("<HHHI", empty[6:16]),
            (control_session.APP_EXEC_EXTENDED, layered_flags, 0, 0),
        )
        replaced = self._exec_payload(("A=1",))
        self.assertEqual(
            struct.unpack("<H", replaced[8:10])[0],
            control_session.APP_EXEC_ENVIRONMENT_PRESENT,
        )
        # An omitted environment already is the default one, so the request stays the
        # legacy one, which the guest agent accepts without an environment.
        self.assertEqual(
            self._exec_payload(None, inherit_default_environment=True),
            self._exec_payload(None),
        )

    def test_exec_accepts_full_uint32_timeout_range_without_waiting(self):
        for timeout in (0, 3_600_001, 86_400_000, 0xFFFFFFFF):
            with self.subTest(timeout=timeout):
                client, server = socket.socketpair()
                instance = bytes.fromhex("55" * 16)
                session = control_session.ControlSession(
                    control_session._SocketStream(client)
                )
                session._instance_id = instance
                session._epoch = 1

                def serve(
                    server_socket: socket.socket = server,
                    expected_timeout: int = timeout,
                    expected_instance: bytes = instance,
                ) -> None:
                    *_, frame = _read_outer(server_socket)
                    header = control_session.APP_HEADER.unpack(
                        frame[: control_session.APP_HEADER.size]
                    )
                    payload = frame[control_session.APP_HEADER.size :]
                    self.assertEqual(
                        struct.unpack("<I", payload[:4])[0],
                        expected_timeout,
                    )
                    _write_app(
                        server_socket,
                        instance_id=expected_instance,
                        sequence=0,
                        kind=control_session.APP_EXIT,
                        request_id=header[4],
                        status=0,
                        payload=b"exit",
                    )
                    server_socket.close()

                worker = threading.Thread(target=serve)
                worker.start()
                session.exec(
                    ("/bin/true",),
                    timeout_ms=timeout,
                    response_timeout=5,
                )
                worker.join(timeout=5)
                session.close()

    def test_exec_rejects_invalid_timeout_and_execution_fields_before_sending(self):
        client, server = socket.socketpair()
        session = control_session.ControlSession(control_session._SocketStream(client))
        invalid = (-1, 0x100000000, True, 1.5, "1")
        for timeout in invalid:
            with (
                self.subTest(timeout=timeout),
                self.assertRaises((TypeError, ValueError)),
            ):
                session.exec(
                    ("/bin/true",),
                    timeout_ms=timeout,  # type: ignore[arg-type]
                    response_timeout=1,
                )
        for kwargs in (
            {"cwd": ""},
            {"cwd": "relative"},
            {"cwd": "/bad\0path"},
            {"environment": ("MISSING_EQUALS",)},
            {"environment": ("=empty-name",)},
            {"environment": ("DUP=1", "DUP=2")},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                session.exec(
                    ("/bin/true",),
                    timeout_ms=0,
                    response_timeout=1,
                    **kwargs,  # type: ignore[arg-type]
                )
        for inherit in (1, "true", None):
            with (
                self.subTest(inherit=inherit),
                self.assertRaisesRegex(TypeError, "inheritance must be a boolean"),
            ):
                session.exec(
                    ("/bin/true",),
                    timeout_ms=0,
                    response_timeout=1,
                    environment=("A=1",),
                    inherit_default_environment=inherit,  # type: ignore[arg-type]
                )
        server.setblocking(False)
        with self.assertRaises(BlockingIOError):
            server.recv(1)
        session.close()
        server.close()

    def test_exec_rejects_invalid_response_timeout_before_sending(self):
        client, server = socket.socketpair()
        session = control_session.ControlSession(control_session._SocketStream(client))

        for timeout in (0.0, -1.0, float("nan"), float("inf")):
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(ValueError, "response timeout"),
            ):
                session.exec(
                    ("/bin/true",),
                    timeout_ms=0,
                    response_timeout=timeout,
                )

        server.setblocking(False)
        with self.assertRaises(BlockingIOError):
            server.recv(1)
        session.close()
        server.close()

    def test_exec_rejects_unknown_exit_category(self):
        client, server = socket.socketpair()
        instance = bytes.fromhex("22" * 16)
        session = control_session.ControlSession(control_session._SocketStream(client))
        session._instance_id = instance
        session._epoch = 1

        def serve() -> None:
            *_, frame = _read_outer(server)
            request_id = control_session.APP_HEADER.unpack(
                frame[: control_session.APP_HEADER.size]
            )[4]
            _write_app(
                server,
                instance_id=instance,
                sequence=0,
                kind=control_session.APP_EXIT,
                request_id=request_id,
                status=125,
                payload=b"guest-provided-detail",
            )
            server.close()

        worker = threading.Thread(target=serve)
        worker.start()
        with self.assertRaisesRegex(
            control_session.ScriptError, "unsupported exit category"
        ):
            session.exec(("/bin/true",), timeout_ms=0, response_timeout=5)
        worker.join(timeout=5)
        session.close()

    def test_exec_refusal_keeps_status_category_and_diagnostic(self):
        client, server = socket.socketpair()
        instance = bytes.fromhex("33" * 16)
        session = control_session.ControlSession(control_session._SocketStream(client))
        session._instance_id = instance
        session._epoch = 1
        diagnostic = (
            b"nvx-managed-agent: cannot enter working directory /missing: "
            b"No such file or directory\n"
        )

        def serve() -> None:
            *_, frame = _read_outer(server)
            request_id = control_session.APP_HEADER.unpack(
                frame[: control_session.APP_HEADER.size]
            )[4]
            _write_app(
                server,
                instance_id=instance,
                sequence=0,
                kind=control_session.APP_STDERR,
                request_id=request_id,
                status=0,
                payload=diagnostic,
            )
            _write_app(
                server,
                instance_id=instance,
                sequence=1,
                kind=control_session.APP_ERROR,
                request_id=request_id,
                status=2,
                payload=b"cwd-failed",
            )
            server.close()

        worker = threading.Thread(target=serve)
        worker.start()
        with self.assertRaises(control_session.ManagedExecRefused) as raised:
            session.exec(
                ("/bin/true",), timeout_ms=0, response_timeout=5, cwd="/missing"
            )
        worker.join(timeout=5)
        session.close()

        refusal = raised.exception
        self.assertIsInstance(refusal, control_session.ScriptError)
        self.assertEqual(
            (refusal.status, refusal.category, refusal.stdout, refusal.stderr),
            (2, "cwd-failed", b"", diagnostic),
        )
        self.assertEqual(
            str(refusal),
            "managed guest rejected exec (status=2, category=cwd-failed)",
        )

    def test_session_reset_is_not_a_closed_endpoint(self):
        # A reset comes from an OpenVMM that still serves the endpoint, so it must
        # not look like the closure with which OpenVMM shuts down.
        client, server = socket.socketpair()
        instance = bytes.fromhex("11" * 16)
        session = control_session.ControlSession(control_session._SocketStream(client))
        session._instance_id = instance
        session._epoch = 1
        server.sendall(
            control_session.OUTER_HEADER.pack(
                b"NVXS", 1, control_session.OUTER_RESET, 0, instance, 1, 0, 0
            )
        )
        try:
            with self.assertRaisesRegex(
                ConnectionError, "^managed control session was reset$"
            ) as raised:
                session.ping(5)
        finally:
            session.close()
            server.close()

        self.assertNotIsInstance(
            raised.exception, control_session.ControlEndpointClosed
        )


class SocketStreamTests(unittest.TestCase):
    def test_read_reports_a_closed_endpoint(self):
        client, server = socket.socketpair()
        stream = control_session._SocketStream(client)
        server.close()
        try:
            with self.assertRaisesRegex(
                control_session.ControlEndpointClosed,
                "^managed control endpoint closed$",
            ):
                stream.read_exact(1, time.monotonic() + 5)
        finally:
            stream.close()

    def test_reset_and_broken_pipe_report_a_closed_endpoint(self):
        # OpenVMM may close the socket before it reads everything that the client
        # sent, which resets the client's reads, and a later write fails with a
        # broken pipe.
        if sys.platform != "linux":
            self.skipTest("Unix-domain socket closure semantics require Linux")
        client, server = socket.socketpair()
        stream = control_session._SocketStream(client)
        stream.write_all(b"unread request")
        server.close()
        try:
            with self.assertRaises(control_session.ControlEndpointClosed) as raised:
                stream.read_exact(1, time.monotonic() + 5)
            self.assertIsInstance(raised.exception.__cause__, ConnectionResetError)
            with self.assertRaises(control_session.ControlEndpointClosed) as raised:
                stream.write_all(b"record")
            self.assertIsInstance(raised.exception.__cause__, BrokenPipeError)
        finally:
            stream.close()


class NamedPipeStreamTests(unittest.TestCase):
    def test_write_reports_a_closed_endpoint(self):
        # OpenVMM closes the pipe as it tears the VM down, and the CRT reports a
        # later write to it as EINVAL rather than as a broken pipe.
        if sys.platform != "win32":
            self.skipTest("named pipes require a Windows host")
        import _winapi

        name = rf"\\.\pipe\nvx-control-session-test-{uuid.uuid4().hex}"
        server = _winapi.CreateNamedPipe(
            name,
            _winapi.PIPE_ACCESS_DUPLEX,
            _winapi.PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            _winapi.NULL,
        )
        try:
            stream = control_session._NamedPipeStream.connect(Path(name), 5)
        finally:
            _winapi.CloseHandle(server)
        try:
            with self.assertRaisesRegex(
                control_session.ControlEndpointClosed,
                "^managed control endpoint closed$",
            ):
                stream.write_all(b"record")
        finally:
            stream.close()


if __name__ == "__main__":
    unittest.main()
