#!/usr/bin/env python3
"""Compile the existing guest decoder on Linux and test real wire inputs."""

import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform.startswith("linux"), "guest decoder requires Linux")
class ManagedAgentDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("guest decoder requires the guest build C compiler")
        cls.temporary = tempfile.TemporaryDirectory(prefix="nvx-agent-decoder-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.executable = cls.root / "decoder"
        harness = cls.root / "decoder.c"
        harness.write_text(
            """
#define main nvx_agent_main
#include "nvx-managed-agent.c"
#undef main
int main(int argc, char **argv) {
    unsigned char bytes[65536];
    uint32_t timeout_ms = 0;
    char **arguments = NULL;
    struct exec_config config = {0};
    if (argc > 1 && strcmp(argv[1], "--exec-config-fd") == 0)
        return launch_workload(argc, argv);
    int launch = argc == 3 && strcmp(argv[1], "--launch") == 0;
    if (argc != 2 && !launch) return 2;
    FILE *file = fopen(argv[launch ? 2 : 1], "rb");
    if (file == NULL) return 2;
    size_t length = fread(bytes, 1, sizeof(bytes), file);
    if (ferror(file)) return 2;
    fclose(file);
    int result = decode_exec_payload(
        bytes, (uint32_t)length, &timeout_ms, &arguments, &config);
    if (result == 0 && launch) {
        int fd = create_exec_config_fd(&config);
        if (fd < 0) return 2;
        int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        if ((fcntl(fd, F_GET_SEALS) & seals) != seals) return 2;
        char fd_text[32];
        snprintf(fd_text, sizeof(fd_text), "%d", fd);
        char *helper_arguments[MAX_ARGUMENTS + 5] = {
            argv[0], "--exec-config-fd", fd_text, "--"
        };
        int count = 0;
        while (arguments[count] != NULL) {
            helper_arguments[count + 4] = arguments[count];
            count++;
        }
        helper_arguments[count + 4] = NULL;
        return launch_workload(count + 4, helper_arguments);
    }
    if (result == 0) {
        free_arguments(arguments);
        free_exec_config(&config);
    }
    return result == 0 ? 0 : 1;
}
""",
            encoding="utf-8",
        )
        guest = Path(__file__).resolve().parent.parent / "guest" / "common"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-I",
                str(guest),
                str(harness),
                "-o",
                str(cls.executable),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )

    def decode(self, environment: tuple[bytes, ...], *, timeout: int = 0) -> int:
        argument = b"/bin/true"
        payload = struct.pack("<IHHHHI", timeout, 1, 1, 2, len(environment), 0)
        payload += struct.pack("<I", len(argument)) + argument
        payload += b"".join(
            struct.pack("<I", len(entry)) + entry for entry in environment
        )
        source = self.root / "request.bin"
        source.write_bytes(payload)
        result = subprocess.run(
            [str(self.executable), str(source)], capture_output=True, timeout=5
        )
        return result.returncode

    def test_accepts_empty_and_exact_environment(self):
        self.assertEqual(self.decode(()), 0)
        self.assertEqual(self.decode((b"EMPTY=", b"VALUE=space = value")), 0)

    def test_rejects_duplicate_environment_names(self):
        self.assertEqual(self.decode((b"VALUE=one", b"VALUE=two")), 1)

    def test_rejects_malformed_environment(self):
        for entry in (b"NO_EQUALS", b"=empty-key", b"KEY=embedded\0nul"):
            with self.subTest(entry=entry):
                self.assertEqual(self.decode((entry,)), 1)

    def test_accepts_uint32_timeout_boundaries(self):
        for timeout in (0, 3_600_001, 86_400_000, 0xFFFFFFFF):
            with self.subTest(timeout=timeout):
                self.assertEqual(self.decode((), timeout=timeout), 0)

    def launch(
        self,
        arguments: tuple[bytes, ...],
        environment: tuple[bytes, ...] | None,
        cwd: bytes = b"/",
    ) -> subprocess.CompletedProcess[bytes]:
        entries = () if environment is None else environment
        flags = 1 | (2 if environment is not None else 0)
        payload = struct.pack(
            "<IHHHHI", 0, len(arguments), 1, flags, len(entries), len(cwd)
        )
        payload += b"".join(struct.pack("<I", len(arg)) + arg for arg in arguments)
        payload += cwd
        payload += b"".join(struct.pack("<I", len(entry)) + entry for entry in entries)
        source = self.root / "launch.bin"
        source.write_bytes(payload)
        return subprocess.run(
            [str(self.executable), "--launch", str(source)],
            capture_output=True,
            timeout=5,
            env={"BASE": "inherited", "NVX_EXEC_CONFIG_FD": "synthetic"},
        )

    def test_helper_roundtrip_empty_environment_and_cwd(self):
        result = self.launch((b"/usr/bin/env",), ())
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr), (0, b"", b"")
        )
        result = self.launch((b"/bin/pwd",), (), b"/tmp")
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr), (0, b"/tmp\n", b"")
        )

    def test_helper_preserves_defaults_without_internal_descriptor(self):
        result = self.launch((b"/usr/bin/env",), None)
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr),
            (0, b"BASE=inherited\n", b""),
        )

    def test_helper_roundtrip_large_exact_environment(self):
        entries = tuple(f"KEY{index}=".encode() + b"x" * 4000 for index in range(12))
        result = self.launch((b"/usr/bin/env",), entries)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"\n".join(entries) + b"\n")

    def test_helper_defensively_rejects_relative_cwd(self):
        with tempfile.TemporaryFile() as config:
            config.write(struct.pack("<HHI", 1, 0, 1) + b".")
            config.seek(0)
            fd = config.fileno()
            result = subprocess.run(
                [str(self.executable), "--exec-config-fd", str(fd), "--", "/bin/pwd"],
                pass_fds=(fd,),
                capture_output=True,
                timeout=5,
                env={"BASE": "inherited"},
            )
            self.assertEqual(result.returncode, 125)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"invalid working directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
