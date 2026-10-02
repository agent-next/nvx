"""Linux-only supervisor for a single explicitly owned process tree."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nvx_tools.adversarial_oracles import supervise_linux_process


def main() -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("process supervisor is supported only on Linux")
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        raise ValueError("usage: process_supervisor.py -- COMMAND [ARG ...]")
    return supervise_linux_process(sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
