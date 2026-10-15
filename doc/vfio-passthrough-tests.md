# VFIO recipe regression checks

Run this block from the NVX repository root with Python 3.10+ and Bash 4+.
It extracts the actual command blocks from
[the guide](vfio-passthrough.md), redirects their sysfs paths into temporary
fixtures and replaces `sudo`, `lspci` and `cargo` with an allowlisted mock.
No root privileges, GPU, KVM, downloads or OpenVMM build are needed. Temporary
files are removed automatically. ShellCheck runs too if installed.

These checks cover shell isolation, input validation, the standalone build
path and multi-member recovery, including failures during recovery itself.
They do **not** validate real sysfs, hardware reset, guest boot or NVIDIA/CUDA.

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

guide = Path("doc/vfio-passthrough.md").read_text()
blocks = [
    textwrap.dedent(body)
    for body in re.findall(
        r"^[ \t]*```(?:bash|sh)\n(.*?)^[ \t]*```", guide, re.M | re.S
    )
]
for block in blocks:
    subprocess.run(["bash", "-n"], input=block, text=True, check=True)
    if shutil.which("shellcheck"):
        subprocess.run(
            ["shellcheck", "--shell=bash", "-"],
            input=block, text=True, check=True,
        )
    for body in re.findall(r"python3 - <<'PY'\n(.*?)\nPY", block, re.S):
        compile(body, "<documented-python>", "exec")
inspect, prepare, build, launch, restore = [
    block for block in blocks if block.startswith("(\nset -euo pipefail\n")
]
assert "even in the same\n   Bash shell" in guide
assert "github.com/microsoft/nvx/blob/" in guide
assert "high_mmio=64G" in launch

mock_program = r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["FIXTURE"])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
if command == "cargo":
    target = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
    assert target.is_relative_to(root)
    assert target.parent == root and target.name.startswith("openvmm-vfio-target.")
    with (root / "cargo.jsonl").open("a") as stream:
        stream.write(json.dumps([args, str(target)]) + "\n")
    if os.environ.get("FAIL_CARGO"):
        sys.exit(9)
    if args == ["build", "-p", "openvmm", "--release", "--target",
                "x86_64-unknown-linux-gnu"]:
        binary = target / "x86_64-unknown-linux-gnu/release/openvmm"
        binary.parent.mkdir(parents=True)
        binary.write_text("standalone fixture")
        binary.chmod(0o700)
    else:
        assert args == ["xflowey", "restore-packages"], args
    sys.exit(0)
if command == "sudo":
    command, *args = args
if command == "lspci":
    assert args[-1] in ("0000:01:00.0", "0000:01:00.1", "0000:01:00.2")
    sys.exit(0)
if command == "modprobe":
    assert args in (["vfio-pci"], ["vfio_iommu_type1"]), args
    sys.exit(0)
if Path(command).is_absolute():
    binary = Path(command).resolve()
    assert binary.is_relative_to(root)
    assert binary.read_text() == "standalone fixture"
    assert args[args.index("--vfio") + 1] == "host=0000:01:00.0,port=rp0"
    sys.exit(int(os.environ.get("LAUNCH_STATUS", "0")))
assert command == "tee" and len(args) == 1, (command, args)
target = Path(args[0]).resolve()
assert target.is_relative_to(root), target
value = sys.stdin.read()
if target.name == "driver_override":
    bdf, operation, driver = target.parent.name, "override", value.strip()
else:
    assert target.name in ("bind", "unbind"), target
    bdf, operation, driver = value.strip(), target.name, target.parent.name
with (root / "events.jsonl").open("a") as stream:
    stream.write(json.dumps([operation, bdf, driver]) + "\n")
if os.environ.get("FAIL") == f"{operation}:{bdf}:{driver}":
    sys.exit(22)
device = root / "sys/bus/pci/devices" / bdf
link = device / "driver"
if operation == "override":
    target.write_text(value)
elif operation == "unbind":
    assert link.is_symlink() and link.resolve() == target.parent
    link.unlink()
else:
    assert not link.is_symlink()
    assert (device / "driver_override").read_text().strip() in ("", driver)
    link.symlink_to(target.parent)
sys.stdout.write(value)
'''

GPU, COMPANION, LAST = "0000:01:00.0", "0000:01:00.1", "0000:01:00.2"
cases = [
    ("snd_hda_intel", "", ""),
    ("-", "", ""),
    ("nvidia-gpu", "", ""),
    ("nvidia-gpu", f"bind:{COMPANION}:vfio-pci", ""),
    ("nvidia-gpu", "", f"bind:{GPU}:nvidia"),
    ("nvidia-gpu", "", f"unbind:{GPU}:vfio-pci"),
    ("nvidia-gpu", "", f"override:{GPU}:"),
    ("nvidia-gpu", "", "missing-driver"),
]
for companion, prepare_failure, restore_failure in cases:
    with tempfile.TemporaryDirectory(prefix="nvx-vfio-test-") as directory:
        root = Path(directory).resolve()
        source = root / "openvmm"
        source.mkdir()
        original = [(GPU, "nvidia"), (COMPANION, companion),
                    (LAST, "snd_hda_intel")]
        drivers = root / "sys/bus/pci/drivers"
        for driver in ("nvidia", "snd_hda_intel", "nvidia-gpu", "vfio-pci"):
            (drivers / driver).mkdir(parents=True)
            for name in ("bind", "unbind"):
                (drivers / driver / name).touch()
        group = root / "sys/kernel/iommu_groups/11"
        (group / "devices").mkdir(parents=True)
        for bdf, driver in original:
            device = root / "sys/bus/pci/devices" / bdf
            device.mkdir(parents=True)
            (device / "driver_override").write_text("(null)\n")
            (device / "iommu_group").symlink_to(group)
            (group / "devices" / bdf).symlink_to(device)
            if driver != "-":
                (device / "driver").symlink_to(drivers / driver)
        vfio = root / "dev/vfio"
        vfio.mkdir(parents=True)
        (vfio / "11").symlink_to("/dev/null")  # Used only by test -c and ls.
        commands = root / "mock-bin"
        commands.mkdir()
        for command in ("sudo", "lspci", "cargo"):
            path = commands / command
            path.write_text(f"#!{sys.executable}\n" + mock_program)
            path.chmod(0o700)
        env = {**os.environ, "FIXTURE": str(root),
               "PATH": str(commands) + os.pathsep + os.environ["PATH"]}
        env.pop("BASH_ENV", None)
        sentinel = source / "target/release/openvmm"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("NVX patched binary")
        provenance = source / "target/release/openvmm.provenance.json"
        provenance.write_text('{"executable_sha256": "fixture"}\n')
        events_file = root / "events.jsonl"

        def events():
            if not events_file.exists():
                return []
            return [json.loads(row) for row in events_file.read_text().splitlines()]

        def execute(block, expected=0, **extra):
            adapted = block.replace("/sys/", str(root / "sys") + "/")
            adapted = adapted.replace("/dev/vfio/", str(vfio) + "/")
            before = (
                "set +e +u\nset +o pipefail\nBDF=parent-value\n"
                "CARGO_TARGET_DIR=parent-target\nbefore=$-\n"
            )
            after = (
                'status=$?\nprintf "BLOCK_STATUS=%s\\n" "$status"\n'
                'test "$before" = "$-" || exit 91\n'
                'test "$BDF" = parent-value || exit 92\n'
                'test "$CARGO_TARGET_DIR" = parent-target || exit 93\n'
                'set -o | grep -q "^pipefail[[:space:]]*off$" || exit 94\n'
                'false\nprintf "PARENT_ALIVE\\n"\n'
            )
            result = subprocess.run(
                ["bash", "--noprofile", "--norc"], cwd=source,
                input=before + adapted + after, env={**env, **extra},
                text=True, capture_output=True,
            )
            assert result.returncode == 0, result.stderr
            assert f"BLOCK_STATUS={expected}\n" in result.stdout, (
                result.stdout, result.stderr
            )
            assert "PARENT_ALIVE\n" in result.stdout
            return result.stdout

        def recovered():
            for bdf, driver in original:
                device = root / "sys/bus/pci/devices" / bdf
                assert (device / "driver_override").read_text() == "\n"
                link = device / "driver"
                if driver == "-":
                    assert not link.is_symlink()
                else:
                    assert link.resolve() == drivers / driver

        execute(inspect)
        execute(prepare, 22 if prepare_failure else 0, FAIL=prepare_failure)
        state, = source.glob("vfio-state.*")
        saved = state / "drivers.tsv"
        snapshot = saved.read_text()
        assert snapshot == "".join(f"{bdf}\t{driver}\n" for bdf, driver in original)
        history = events()
        first_bind = next(i for i, row in enumerate(history) if row[0] == "bind")
        assert sum(row[0] == "unbind" for row in history[:first_bind]) == (
            2 if companion == "-" else 3
        )
        recovery = restore.replace("/absolute/path/to/vfio-state.XXXXXX", str(state))
        if restore_failure == "missing-driver":
            shutil.rmtree(drivers / "nvidia-gpu")
        execute(recovery, 1 if restore_failure else 0, FAIL=restore_failure)
        if restore_failure:
            # A failure on an earlier member must never strand the last one.
            last = root / "sys/bus/pci/devices" / LAST
            assert (last / "driver").resolve() == drivers / "snd_hda_intel"
            assert (last / "driver_override").read_text() == "\n"
            if restore_failure == "missing-driver":
                (drivers / "nvidia-gpu").mkdir()
                (drivers / "nvidia-gpu/bind").touch()
                (drivers / "nvidia-gpu/unbind").touch()
            execute(recovery)  # Recovery is retryable after fixing the error.
        recovered()

        # Validate every row before the first write, even after a valid row.
        for bad in (
            "../../outside\tnvidia\n", f"{GPU}\t../../outside\n",
            f"{GPU}\t..\n", f"{GPU}\tnvidia\textra\n",
            f"{GPU}\n", "\n", snapshot,  # Duplicate BDFs.
        ):
            saved.write_text(snapshot + bad)
            count = len(events())
            execute(recovery, 1)
            assert len(events()) == count
        saved.write_text("")
        count = len(events())
        execute(recovery, 1)
        assert len(events()) == count
        saved.write_text(snapshot)
        execute(restore, 1)  # Placeholder cannot silently pick an old state.
        execute(inspect.replace(GPU, "0000:ff:00.0"), 1)
        for block in (inspect, prepare, launch):
            count = len(events())
            execute(block.replace(f"BDF={GPU}", "BDF=../../outside"), 1)
            assert len(events()) == count

        if not prepare_failure and not restore_failure:
            output = execute(build)
            binary = output.split("Standalone executable: ", 1)[1].splitlines()[0]
            calls = [json.loads(row) for row in (root / "cargo.jsonl").read_text().splitlines()]
            assert len(calls) == 2 and calls[0][1] == calls[1][1]
            assert Path(binary).resolve() == Path(calls[1][1]) / "x86_64-unknown-linux-gnu/release/openvmm"
            assert sentinel.read_text() == "NVX patched binary"
            assert provenance.read_text() == '{"executable_sha256": "fixture"}\n'
            command = launch.replace(
                "/absolute/path/to/openvmm-vfio-target.XXXXXX/x86_64-unknown-linux-gnu/release/openvmm",
                binary,
            )
            execute(command)
            execute(command, 7, LAUNCH_STATUS="7")
            execute(build, 9, FAIL_CARGO="1")
        print(f"PASS: companion={companion}, prepare={prepare_failure or 'ok'}, "
              f"restore={restore_failure or 'ok'}")
print(f"PASS: syntax for {len(blocks)} shell blocks; 8 fake-sysfs scenarios; "
      "saved-state rejection, isolated build/launch and parent-shell isolation")
PY
```
