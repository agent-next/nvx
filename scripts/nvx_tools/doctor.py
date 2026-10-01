"""Host qualification for the NVX time ABI (``nvx.py doctor``).

doc/design/time-abi.md ("Host qualification") defines checks H1 to H7. Each
check prints one ``NVX-DOCTOR: check=<id> status=<pass|fail> detail="..."``
line, and qualification fails closed if any selected check fails. A failure
that matches a time ABI failure code starts its detail with that code in
brackets, as OpenVMM errors do.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .benchmark import run_guest_script, workload_boot_command
from .build_constants import AlpineBuildConstants, BuildConstants, KernelBuildConstants
from .ci import OPENVMM_TEST_BACKENDS
from .common import ScriptError, artifact_path, openvmm_binary_path
from .time_abi import (
    LAPIC_HZ,
    MAX_TSC_HZ,
    MIN_TSC_HZ,
    WARP_BOUND_NS,
    TimeAbiFailure,
    TimeAbiMonitor,
    check_warp_probe,
    cpu_generation,
    parse_fields,
    warp_probe_command,
)

CHECK_IDS = ("H1", "H2", "H3", "H4", "H5", "H6", "H7")
CHECK_TITLES: Mapping[str, str] = {
    "H1": "backend device or API",
    "H2": "CPU fingerprint and generation",
    "H3": "OpenVMM time ABI preflight",
    "H4": "host TSC rate stability",
    "H5": "host cross-CPU TSC skew",
    "H6": "guest warp probe",
    "H7": "host UTC synchronization",
}
DOCTOR_PREFIX = "NVX-DOCTOR: "
PROBE_SOURCE = Path(__file__).with_name("host_time_probe.rs")
PROBE_PREFIX = "NVX-HOST-TIME-PROBE "
VERIFY_PREFIX = "NVX-TIME-ABI-VERIFY:"
RATE_MEASURE_MS = 1000
RATE_AGREEMENT_PPM = 1.0
RATE_TOLERANCE_PPM = 100.0
SKEW_PAIR_DURATION_MS = 5
GUEST_VCPU_COUNTS = (8, 4, 2, 1)
GUEST_MEMORY_MIB = 128
GUEST_WARP_MARKER = b"NVX-DOCTOR-WARP-DONE"
# Azure WHP hosts cannot see an invariant TSC; the spec qualifies them on the
# measured warp (H6) and rate stability (H4), so the bit is only reported.
# A Linux host whose root sees no invariant TSC (azure-azlinux-2) stays
# unqualified, which the spec's restore matrix expects.
WHP_REQUIRES_INVARIANT_TSC = False
LINUX_INVARIANT_TSC_FLAGS = ("constant_tsc", "nonstop_tsc")
# KVM rewrites per-vCPU TSC offsets on a host whose TSC Linux distrusts. An
# MSHV root's Linux reads time through the hypervisor's TSC page instead.
HOST_CLOCKSOURCES: Mapping[str, tuple[str, ...]] = {
    "kvm": ("tsc",),
    "mshv": ("tsc", "hyperv_clocksource_tsc_page"),
}
CLOCKSOURCE_PATH = Path(
    "/sys/devices/system/clocksource/clocksource0/current_clocksource"
)
CPUINFO_PATH = Path("/proc/cpuinfo")
ADJTIMEX_TIME_ERROR = 5
ADJTIMEX_STA_UNSYNC = 0x0040
WHP_CAPABILITY_HYPERVISOR_PRESENT = 0


@dataclass
class CheckResult:
    check: str
    passed: bool
    detail: str

    def line(self) -> str:
        status = "pass" if self.passed else "fail"
        detail = self.detail.replace("\\", "\\\\").replace('"', '\\"')
        return f'{DOCTOR_PREFIX}check={self.check} status={status} detail="{detail}"'


@dataclass
class DoctorContext:
    backend: str
    openvmm: Path
    kernel: Path
    initrd: Path
    openvmm_args: tuple[str, ...]
    probe_directory: Path
    timeout: float
    facts: dict[str, str] = field(default_factory=dict[str, str])
    probe: Path | None = None


def host_is_windows() -> bool:
    return os.name == "nt"


def host_clocksource() -> str:
    return CLOCKSOURCE_PATH.read_text(encoding="utf-8").strip()


def _escape_markdown(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def probe_path(directory: Path) -> Path:
    """Return the cached host probe binary for the current probe source."""
    digest = hashlib.sha256(PROBE_SOURCE.read_bytes()).hexdigest()[:16]
    suffix = ".exe" if os.name == "nt" else ""
    return directory / f"nvx-host-time-probe-{digest}{suffix}"


def build_probe(directory: Path) -> Path:
    """Build the host probe once per source version with rustc."""
    target = probe_path(directory)
    if target.is_file():
        return target
    rustc = shutil.which("rustc")
    if rustc is None:
        raise ScriptError("rustc is required to build the host time probe")
    directory.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.stem}-{os.getpid()}{target.suffix}")
    completed = subprocess.run(
        [
            rustc,
            "--edition=2021",
            "-C",
            "opt-level=2",
            "-C",
            "debuginfo=0",
            "-o",
            os.fspath(temporary),
            os.fspath(PROBE_SOURCE),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise ScriptError(
            f"rustc failed to build the host time probe:\n{completed.stderr.strip()}"
        )
    try:
        os.replace(temporary, target)
    except OSError:
        # Another job built the same version first and may be running it.
        temporary.unlink(missing_ok=True)
        if not target.is_file():
            raise
    temporary.with_suffix(".pdb").unlink(missing_ok=True)
    return target


def run_probe(
    context: DoctorContext, *arguments: str
) -> list[tuple[str, dict[str, str]]]:
    """Run the host probe and parse its ``NVX-HOST-TIME-PROBE`` records."""
    if context.probe is None:
        context.probe = build_probe(context.probe_directory)
    completed = subprocess.run(
        [os.fspath(context.probe), *arguments],
        capture_output=True,
        text=True,
        timeout=context.timeout,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise ScriptError(f"host time probe {arguments[0]} failed: {message}")
    records: list[tuple[str, dict[str, str]]] = []
    for line in completed.stdout.splitlines():
        if line.startswith(PROBE_PREFIX):
            kind, _, fields = line.removeprefix(PROBE_PREFIX).partition(" ")
            records.append((kind, parse_fields(fields)))
    return records


def _probe_record(
    records: Sequence[tuple[str, dict[str, str]]], kind: str
) -> dict[str, str]:
    for record_kind, fields in records:
        if record_kind == kind:
            return fields
    raise ScriptError(f"host time probe printed no {kind} record")


def _linux_cpuinfo(path: Path = CPUINFO_PATH) -> dict[str, str]:
    """Return the first processor's /proc/cpuinfo fields."""
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            if fields:
                break
            continue
        name, separator, value = line.partition(":")
        if separator:
            fields.setdefault(name.strip(), value.strip())
    return fields


def _windows_registry_value(key: str, name: str) -> object:
    if sys.platform != "win32":
        raise ScriptError("the Windows registry is unavailable")
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
        value, _ = winreg.QueryValueEx(handle, name)
        return value


def host_cpu(context: DoctorContext) -> dict[str, str]:
    """Collect the host CPU identity and the host OS's view of its TSC."""
    if host_is_windows():
        match = re.search(
            r"Family (\d+) Model (\d+) Stepping (\d+), (\S+)", platform.processor()
        )
        if match is None:
            raise ScriptError(f"cannot parse the processor {platform.processor()!r}")
        family, model, stepping, vendor = match.groups()
        processor_key = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        info = {
            "vendor": vendor,
            "family": family,
            "model": model,
            "stepping": stepping,
            "brand": str(
                _windows_registry_value(processor_key, "ProcessorNameString")
            ).strip(),
        }
        revision = _windows_registry_value(processor_key, "Update Revision")
        if isinstance(revision, bytes) and len(revision) in (4, 8):
            info["microcode"] = hex(int.from_bytes(revision[-4:], "little"))
        build = _windows_registry_value(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR"
        )
        info["os"] = f"Windows {platform.version()}.{build}"
        try:
            probed = _probe_record(run_probe(context, "cpu"), "cpu")
            info["invariant_tsc"] = "yes" if probed["invariant_tsc"] == "1" else "no"
        except (ScriptError, KeyError, subprocess.TimeoutExpired) as error:
            info["invariant_tsc"] = f"unknown ({error})"
        return info
    cpuinfo = _linux_cpuinfo()
    flags = cpuinfo.get("flags", "").split()
    missing = [flag for flag in LINUX_INVARIANT_TSC_FLAGS if flag not in flags]
    return {
        "vendor": cpuinfo.get("vendor_id", "unknown"),
        "family": cpuinfo.get("cpu family", "?"),
        "model": cpuinfo.get("model", "?"),
        "stepping": cpuinfo.get("stepping", "?"),
        "microcode": cpuinfo.get("microcode", "unknown"),
        "brand": cpuinfo.get("model name", "unknown"),
        "os": f"Linux {platform.release()}",
        "invariant_tsc": "yes" if not missing else f"no (missing {' '.join(missing)})",
    }


def _whp_hypervisor_present() -> bool:
    if sys.platform != "win32":
        raise ScriptError("WHP qualification requires Windows")
    try:
        library = ctypes.WinDLL("WinHvPlatform.dll")
    except OSError as error:
        raise ScriptError(f"WinHvPlatform.dll is unavailable: {error}") from error
    present = ctypes.c_int32(0)
    written = ctypes.c_uint32(0)
    result = int(
        library.WHvGetCapability(
            WHP_CAPABILITY_HYPERVISOR_PRESENT,
            ctypes.byref(present),
            ctypes.sizeof(present),
            ctypes.byref(written),
        )
    )
    if result != 0:
        raise ScriptError(
            f"WHvGetCapability failed with HRESULT 0x{result & 0xFFFFFFFF:08x}"
        )
    return bool(present.value)


def check_backend(context: DoctorContext) -> CheckResult:
    if context.backend == "whp":
        if not host_is_windows():
            return CheckResult("H1", False, "WHP qualification requires Windows")
        if not _whp_hypervisor_present():
            return CheckResult(
                "H1", False, "the Windows Hypervisor Platform reports no hypervisor"
            )
        return CheckResult("H1", True, "the Windows Hypervisor Platform is present")
    if host_is_windows():
        return CheckResult(
            "H1", False, f"{context.backend} qualification requires Linux"
        )
    device = Path("/dev") / context.backend
    if not device.exists():
        return CheckResult("H1", False, f"{device} does not exist")
    if not os.access(device, os.R_OK | os.W_OK):
        return CheckResult("H1", False, f"{device} is not readable and writable")
    if context.backend == "kvm" and Path("/dev/mshv").exists():
        return CheckResult(
            "H1", False, "/dev/mshv exists, so OpenVMM would select MSHV, not KVM"
        )
    return CheckResult("H1", True, f"{device} is readable and writable")


def check_cpu(context: DoctorContext) -> CheckResult:
    info = host_cpu(context)
    signature = f"{info['vendor']} {info['family']}/{info['model']}/{info['stepping']}"
    try:
        generation = cpu_generation(
            info["vendor"],
            int(info["family"]),
            int(info["model"]),
            int(info["stepping"]),
        )
    except ValueError:
        generation = None
    profile = generation.profile_id if generation else None
    name = generation.name if generation else "unknown"
    context.facts.update(
        {
            "generation": name,
            "profile": profile or "none",
            "cpu": signature,
            "brand": info["brand"],
            "microcode": info.get("microcode", "unknown"),
            "os": info["os"],
            "invariant_tsc": info["invariant_tsc"],
        }
    )
    detail = (
        f"generation={name} profile={profile or 'none'} cpu={signature} "
        f"microcode={info.get('microcode', 'unknown')} os={info['os']} "
        f"invariant_tsc={info['invariant_tsc']} brand={info['brand']}"
    )
    if generation is None:
        return CheckResult(
            "H2",
            False,
            f"[E_PROFILE_HOST_UNKNOWN] {signature} is not a time ABI generation "
            "(skylake-sp 6/85 steppings 0-4, icelake-sp 6/106, emeraldrapids "
            f"6/207); {detail}",
        )
    required = context.backend != "whp" or WHP_REQUIRES_INVARIANT_TSC
    if required and info["invariant_tsc"] != "yes":
        return CheckResult(
            "H2",
            False,
            "[E_PROFILE_UNSUPPORTED] the host does not expose an invariant TSC, "
            f"which every CPU profile requires; {detail}",
        )
    return CheckResult("H2", True, detail)


def _guest_vcpus() -> int:
    host_cpus = os.cpu_count() or 1
    return next(count for count in GUEST_VCPU_COUNTS if count <= host_cpus)


def check_openvmm_preflight(context: DoctorContext) -> CheckResult:
    for path, description in (
        (context.openvmm, "OpenVMM"),
        (context.kernel, "guest kernel"),
        (context.initrd, "guest initramfs"),
    ):
        if not path.is_file():
            return CheckResult("H3", False, f"{description} was not found at {path}")
    command = [
        os.fspath(context.openvmm),
        "--machine",
        "microvm",
        "--processors",
        str(_guest_vcpus()),
        "--hypervisor",
        context.backend,
        "--kernel",
        os.fspath(context.kernel),
        "--initrd",
        os.fspath(context.initrd),
        # Before the flip, pass --openvmm-arg=--x-time-abi-v1.
        *context.openvmm_args,
        "--x-time-abi-verify",
    ]
    environment = os.environ.copy()
    environment["OPENVMM_LOG"] = "off"
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=context.timeout,
        env=environment,
        check=False,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    verify = next(
        (
            line.strip()
            for line in output.splitlines()
            if line.strip().startswith(VERIFY_PREFIX)
        ),
        None,
    )
    if verify is None:
        last = next(
            (line.strip() for line in reversed(output.splitlines()) if line.strip()),
            "no output",
        )
        if "x-time-abi" in output and "unexpected argument" in output:
            last = "this OpenVMM predates the time ABI's --x-time-abi-verify mode"
        return CheckResult(
            "H3",
            False,
            f"OpenVMM verification exited {completed.returncode} without a "
            f"verification line: {last}",
        )
    fields = parse_fields(verify.removeprefix(VERIFY_PREFIX).strip())
    if fields.get("status") != "ok" or completed.returncode != 0:
        code = fields.get("code", "none")
        prefix = f"[{code}] " if code.startswith("E_") else ""
        return CheckResult(
            "H3",
            False,
            f"{prefix}OpenVMM verification failed (exit {completed.returncode}): "
            f"{fields.get('detail', verify)}",
        )
    problems: list[str] = []
    if fields.get("backend") != context.backend:
        problems.append(f"OpenVMM verified backend {fields.get('backend')}")
    for name in ("tsc_hz", "native_tsc_hz"):
        try:
            rate = int(fields.get(name, ""))
            if not MIN_TSC_HZ <= rate <= MAX_TSC_HZ:
                problems.append(f"[E_TSC_RATE_IMPLAUSIBLE] {name}={rate}")
        except ValueError:
            problems.append(f"{name}={fields.get(name)!r} is not an integer")
    expected_lapic = LAPIC_HZ[context.backend]
    if fields.get("lapic_hz") != str(expected_lapic):
        problems.append(
            f"[E_LAPIC_RATE_MISMATCH] lapic_hz={fields.get('lapic_hz')} is not "
            f"{expected_lapic}"
        )
    expected_profile = context.facts.get("profile", "none")
    selected_profile = fields.get("cpu_profile", "")
    interim = f"interim.host.{context.backend}.v1"
    if expected_profile != "none" and selected_profile != interim:
        # Later revisions of the same generation are fine.
        lineage = expected_profile.rpartition(".v")[0] + ".v"
        if not selected_profile.startswith(lineage):
            problems.append(
                f"OpenVMM selected CPU profile {selected_profile}, but H2 maps the "
                f"host to {expected_profile}"
            )
    detail = " ".join(f"{name}={value}" for name, value in fields.items())
    if selected_profile == interim:
        # OpenVMM uses an interim host profile until it selects catalog
        # profiles; core-design, "Changes".
        detail += f"; interim CPU profile, expected {expected_profile} later"
    context.facts.update(
        {
            "tsc_hz": fields.get("tsc_hz", ""),
            "native_tsc_hz": fields.get("native_tsc_hz", ""),
            "lapic_hz": fields.get("lapic_hz", ""),
            "profile": selected_profile,
            "route": fields.get("msr_route", ""),
            "sync": fields.get("sync", ""),
        }
    )
    if problems:
        return CheckResult("H3", False, "; ".join(problems) + f"; {detail}")
    return CheckResult("H3", True, detail)


def check_rate(context: DoctorContext) -> CheckResult:
    clocksource = ""
    if context.backend in HOST_CLOCKSOURCES:
        clocksource = host_clocksource()
        context.facts["host_clocksource"] = clocksource
    records = run_probe(
        context, "rate", "--measure-ms", str(RATE_MEASURE_MS), "--count", "2"
    )
    rates = [float(fields["tsc_hz"]) for kind, fields in records if kind == "rate"]
    if len(rates) != 2:
        raise ScriptError(f"host time probe printed {len(rates)} rate records, not 2")
    measured = sum(rates) / len(rates)
    spread_ppm = (max(rates) - min(rates)) / min(rates) * 1e6
    context.facts["measured_tsc_hz"] = f"{measured:.0f}"
    context.facts["rate_spread_ppm"] = f"{spread_ppm:.3f}"
    detail = (
        f"tsc_hz={measured:.0f} two {RATE_MEASURE_MS} ms measurements differ by "
        f"{spread_ppm:.3f} ppm"
    )
    problems: list[str] = []
    if not MIN_TSC_HZ <= measured <= MAX_TSC_HZ:
        problems.append(f"[E_TSC_RATE_IMPLAUSIBLE] measured {measured:.0f} Hz")
    if spread_ppm > RATE_AGREEMENT_PPM:
        problems.append(
            f"the TSC rate is unstable: {spread_ppm:.3f} ppm > {RATE_AGREEMENT_PPM} ppm"
        )
    declared = context.facts.get("native_tsc_hz") or context.facts.get("tsc_hz")
    if declared is None:
        # validate-runner runs before the OpenVMM binary is available; the
        # VM jobs run H3 with H4 to compare against the backend's rate.
        detail += "; not compared with the backend's rate (H3 did not run)"
    else:
        deviation_ppm = abs(measured - int(declared)) / int(declared) * 1e6
        detail += f"; {deviation_ppm:.1f} ppm from the backend's {declared} Hz"
        if deviation_ppm > RATE_TOLERANCE_PPM:
            problems.append(
                f"the backend rate is {deviation_ppm:.1f} ppm from the measured "
                f"rate (limit {RATE_TOLERANCE_PPM:g} ppm)"
            )
    if clocksource:
        detail += f"; host clocksource {clocksource}"
        if clocksource not in HOST_CLOCKSOURCES[context.backend]:
            problems.append(
                f"the host clocksource is {clocksource}, not "
                + " or ".join(HOST_CLOCKSOURCES[context.backend])
            )
    if problems:
        return CheckResult("H4", False, "; ".join(problems) + f"; {detail}")
    return CheckResult("H4", True, detail)


def check_host_skew(context: DoctorContext) -> CheckResult:
    arguments = ["skew", "--duration-ms", str(SKEW_PAIR_DURATION_MS)]
    rate = context.facts.get("measured_tsc_hz") or context.facts.get("tsc_hz")
    if rate is not None:
        arguments.extend(("--tsc-hz", rate))
    summary = _probe_record(run_probe(context, *arguments), "skew")
    offset = int(summary["max_abs_offset_ns"])
    uncertainty = int(summary["max_uncertainty_ns"])
    stalled = int(summary["stalled_pairs"])
    context.facts["host_skew_ns"] = str(offset)
    detail = (
        f"pairs={summary['pairs']} cpus={summary['cpus']} max_abs_offset_ns={offset} "
        f"max_uncertainty_ns={uncertainty}"
    )
    problems: list[str] = []
    if offset > WARP_BOUND_NS:
        problems.append(f"max_abs_offset_ns={offset} exceeds {WARP_BOUND_NS}")
    if stalled:
        problems.append(f"{stalled} CPU pair(s) stalled")
    if summary.get("conclusive") != "1":
        problems.append(
            f"the measurement is inconclusive (uncertainty {uncertainty} ns)"
        )
    if problems:
        return CheckResult("H5", False, "; ".join(problems) + f"; {detail}")
    return CheckResult("H5", True, detail)


def check_guest_warp(context: DoctorContext) -> CheckResult:
    for path, description in (
        (context.openvmm, "OpenVMM"),
        (context.kernel, "guest kernel"),
        (context.initrd, "guest initramfs"),
    ):
        if not path.is_file():
            return CheckResult("H6", False, f"{description} was not found at {path}")
    vcpus = _guest_vcpus()
    command = workload_boot_command(
        context.openvmm,
        context.backend,
        context.kernel,
        context.initrd,
        GUEST_MEMORY_MIB,
        "quiet loglevel=0",
        processors=vcpus,
    )
    command.extend(context.openvmm_args)
    script = f"{warp_probe_command()}\necho {GUEST_WARP_MARKER.decode()}\nnvx-exit 0\n"
    try:
        result = run_guest_script(
            command,
            script,
            GUEST_WARP_MARKER,
            timeout=context.timeout,
        )
        monitor = TimeAbiMonitor(command)
        monitor.feed(result["text"].encode())
        monitor.finish()
        boot = monitor.require_boot("the guest boot marker", online_cpus=vcpus)
        warp = check_warp_probe(result["text"], cpus=vcpus, context="H6")[-1]
    except (RuntimeError, TimeAbiFailure) as error:
        first = str(error).splitlines()[0]
        return CheckResult("H6", False, f"vcpus={vcpus}: {first}")
    context.facts["guest_warp_ns"] = warp["max_abs_offset_ns"]
    context.facts.setdefault("tsc_hz", boot["tsc_hz"])
    context.facts.setdefault("lapic_hz", boot["lapic_hz"])
    return CheckResult(
        "H6",
        True,
        f"vcpus={vcpus} max_backward_ns={warp['max_backward_ns']} "
        f"max_abs_offset_ns={warp['max_abs_offset_ns']} "
        f"max_uncertainty_ns={warp['max_uncertainty_ns']} boot_elapsed_us="
        f"{boot.get('elapsed_us', '?')}",
    )


def _linux_clock_state() -> tuple[int, int]:
    """Return adjtimex's clock state and status without changing the clock."""
    libc = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(256)
    state = int(libc.adjtimex(buffer))
    if state < 0:
        raise ScriptError(f"adjtimex failed: {os.strerror(ctypes.get_errno())}")
    # struct timex: unsigned modes, then the long offset, freq, maxerror, and
    # esterror fields, then the int status.
    status = int.from_bytes(buffer.raw[40:44], sys.byteorder)
    return state, status


def _windows_time_source() -> tuple[bool, str]:
    completed = subprocess.run(
        ["w32tm", "/query", "/status"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise ScriptError(
            "w32tm /query /status failed: "
            + (completed.stdout.strip() or completed.stderr.strip())
        )
    fields: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        name, separator, value = line.partition(":")
        if separator:
            fields[name.strip()] = value.strip()
    source = fields.get("Source", "unknown")
    leap = fields.get("Leap Indicator", "")
    unsynchronized = (
        leap.startswith("3")
        or "Local CMOS Clock" in source
        or "Free-running System Clock" in source
    )
    return not unsynchronized, f"source={source} leap_indicator={leap or 'unknown'}"


def check_utc(context: DoctorContext) -> CheckResult:
    del context
    if host_is_windows():
        synchronized, detail = _windows_time_source()
        if not synchronized:
            return CheckResult("H7", False, f"host UTC is not synchronized: {detail}")
        return CheckResult("H7", True, detail)
    state, status = _linux_clock_state()
    detail = f"adjtimex state={state} status=0x{status:04x}"
    if state == ADJTIMEX_TIME_ERROR or status & ADJTIMEX_STA_UNSYNC:
        return CheckResult(
            "H7", False, f"host UTC is not synchronized (STA_UNSYNC); {detail}"
        )
    return CheckResult("H7", True, detail)


CHECKS: Mapping[str, Callable[[DoctorContext], CheckResult]] = {
    "H1": check_backend,
    "H2": check_cpu,
    "H3": check_openvmm_preflight,
    "H4": check_rate,
    "H5": check_host_skew,
    "H6": check_guest_warp,
    "H7": check_utc,
}


def run_checks(context: DoctorContext, checks: Sequence[str]) -> list[CheckResult]:
    """Run checks in spec order; an exception fails only its own check."""
    results: list[CheckResult] = []
    for check in CHECK_IDS:
        if check not in checks:
            continue
        try:
            result = CHECKS[check](context)
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            ValueError,
        ) as error:
            first = str(error).splitlines()[0] if str(error) else type(error).__name__
            result = CheckResult(check, False, first)
        results.append(result)
        print(result.line(), flush=True)
    return results


def summary_markdown(
    backend: str, results: Sequence[CheckResult], facts: Mapping[str, str]
) -> str:
    status = "passed" if all(result.passed for result in results) else "failed"
    lines = [
        f"### Time ABI host qualification ({backend}): {status}",
        "",
        "| Check | Name | Status | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            f"| {result.check} | {CHECK_TITLES[result.check]} | "
            f"{'pass' if result.passed else '**fail**'} | "
            f"{_escape_markdown(result.detail)} |"
        )
    reported = (
        ("generation", "Generation"),
        ("cpu", "CPU"),
        ("microcode", "Microcode"),
        ("os", "Host OS"),
        ("profile", "Profile"),
        ("tsc_hz", "Declared TSC rate (Hz)"),
        ("lapic_hz", "LAPIC rate (Hz)"),
        ("measured_tsc_hz", "Measured TSC rate (Hz)"),
        ("host_skew_ns", "Host skew (ns)"),
        ("guest_warp_ns", "Guest warp offset (ns)"),
    )
    facts_line = " · ".join(
        f"{label}: `{facts[name]}`" for name, label in reported if name in facts
    )
    if facts_line:
        lines.extend(("", facts_line))
    return "\n".join(lines) + "\n\n"


def run(args: argparse.Namespace) -> int:
    if args.backend not in OPENVMM_TEST_BACKENDS:
        raise ScriptError(f"unsupported backend {args.backend!r}")
    checks = tuple(dict.fromkeys(args.checks or CHECK_IDS))
    context = DoctorContext(
        backend=args.backend,
        openvmm=args.openvmm or openvmm_binary_path(),
        kernel=args.kernel or artifact_path(KernelBuildConstants.BINARY_NAME),
        initrd=args.initrd or artifact_path(AlpineBuildConstants.INITRAMFS_NAME),
        openvmm_args=tuple(args.openvmm_arg),
        probe_directory=args.probe_dir or default_probe_directory(),
        timeout=args.timeout,
    )
    results = run_checks(context, checks)
    failed = [result.check for result in results if not result.passed]
    generation = context.facts.get("generation")
    profile = context.facts.get("profile")
    print(
        f"Time ABI host qualification on {args.backend}: "
        + ("passed" if not failed else f"failed ({', '.join(failed)})")
        + (f"; generation {generation}" if generation else "")
        + (f", profile {profile}" if profile else ""),
        flush=True,
    )
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(summary_markdown(args.backend, results, context.facts))
    return 1 if failed else 0


def default_probe_directory() -> Path:
    tool_cache = os.environ.get("RUNNER_TOOL_CACHE")
    if tool_cache:
        return Path(tool_cache) / "nvx-host-time-probe"
    return BuildConstants.BUILD_DIR / "host-time-probe"


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.description = (
        "Qualify this host for the NVX time ABI (doc/design/time-abi.md, "
        "'Host qualification')."
    )
    parser.add_argument("--backend", choices=OPENVMM_TEST_BACKENDS, required=True)
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=CHECK_IDS,
        metavar="ID",
        help="checks to run, in spec order (default: H1 to H7)",
    )
    parser.add_argument("--openvmm", type=Path, help="OpenVMM binary for H3 and H6")
    parser.add_argument("--kernel", type=Path, help="guest kernel for H6")
    parser.add_argument("--initrd", type=Path, help="guest initramfs for H6")
    parser.add_argument(
        "--probe-dir",
        type=Path,
        help="cache directory for the host probe binary "
        "(default: $RUNNER_TOOL_CACHE or build/)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="append a Markdown summary, for example $GITHUB_STEP_SUMMARY",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="seconds allowed for each probe or guest (default: 120)",
    )
    parser.add_argument(
        "--openvmm-arg",
        action="append",
        default=[],
        help=argparse.SUPPRESS,
    )
    parser.set_defaults(handler=run)
