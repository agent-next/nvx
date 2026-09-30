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
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) return 2;
    size_t length = fread(bytes, 1, sizeof(bytes), file);
    if (ferror(file)) return 2;
    fclose(file);
    int result = decode_exec_payload(
        bytes, (uint32_t)length, &timeout_ms, &arguments, &config);
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


if __name__ == "__main__":
    unittest.main()
