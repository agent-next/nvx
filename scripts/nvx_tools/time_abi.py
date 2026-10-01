"""Harness checks of the NVX time ABI v1 guest obligations.

doc/design/time-abi.md defines what a conforming guest prints and how it fails:
the ``NVX-TIME-ABI`` marker of each conformance check, the
``NVX-TIME-ABI-VIOLATION`` event, and the power-off statuses 193 (conformance),
194 (runtime violation), and 195 (restore repair). It also fixes the warp
probe's 1 us skew bound and the CPU generation names used in reports.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

MARKER_PREFIX = "NVX-TIME-ABI: "
VIOLATION_PREFIX = "NVX-TIME-ABI-VIOLATION: "
REPORT_ONLY_PREFIX = "NVX-TIME-REPORT"
ABI_VERSION = "1"
STATUS_CLASSES: Mapping[int, str] = {
    193: "conformance",
    194: "runtime violation",
    195: "restore repair",
}
LAPIC_HZ: Mapping[str, int] = {
    "kvm": 1_000_000_000,
    "mshv": 200_000_000,
    "whp": 200_000_000,
}
MIN_TSC_HZ = 500_000_000
MAX_TSC_HZ = 10_000_000_000
WARP_BOUND_NS = 1000
WARP_PROBE_PATH = "/sbin/nvx-time-probe"
WARP_SUMMARY_PREFIX = "NVX-TIME-PROBE warp "
WARP_DETAIL_PREFIX = "NVX-TIME-PROBE warp-detail "
PROFILE_VENDORS: Mapping[str, str] = {"GenuineIntel": "intel"}


@dataclass(frozen=True)
class CpuGeneration:
    """One CPU generation of the spec's CPU profile catalog."""

    name: str
    vendor: str
    family: int
    model: int
    steppings: range

    @property
    def profile_id(self) -> str:
        """The catalog's v1 profile, which every backend shares."""
        return f"{PROFILE_VENDORS[self.vendor]}.{self.name}.v1"


# Model 85 also covers Cascade Lake (steppings 5-7) and Cooper Lake (10-11),
# which have no profile.
CPU_GENERATIONS: tuple[CpuGeneration, ...] = (
    CpuGeneration("skylake-sp", "GenuineIntel", 6, 85, range(5)),
    CpuGeneration("icelake-sp", "GenuineIntel", 6, 106, range(16)),
    CpuGeneration("emeraldrapids", "GenuineIntel", 6, 207, range(16)),
)
# Guest boot markers that init prints after the time ABI boot check.
GUEST_BOOT_MARKERS = ("ALPINE-MICROVM-BOOT-OK", "NVX-GUEST-BOOT-OK:")
_MAX_PENDING_LINE = 64 * 1024


class TimeAbiFailure(RuntimeError):
    """Raised when a guest or its console output violates the time ABI."""


def cpu_generation(
    vendor: str, family: int, model: int, stepping: int
) -> CpuGeneration | None:
    """Return the time ABI generation of a CPU, or None if it has none."""
    for generation in CPU_GENERATIONS:
        if (
            generation.vendor == vendor
            and generation.family == family
            and generation.model == model
            and stepping in generation.steppings
        ):
            return generation
    return None


def parse_fields(text: str) -> dict[str, str]:
    """Parse space-separated ``key=value`` fields; values may be quoted.

    Quoted values use the guest's escapes: ``\\"``, ``\\\\``, and ``\\xNN``.
    """
    fields: dict[str, str] = {}
    index = 0
    length = len(text)
    while index < length:
        if text[index] == " ":
            index += 1
            continue
        separator = text.find("=", index)
        if separator < 0:
            raise ValueError(f"field without a value: {text[index:]!r}")
        key = text[index:separator]
        if not key or " " in key or '"' in key:
            raise ValueError(f"invalid field name {key!r}")
        index = separator + 1
        if index < length and text[index] == '"':
            index += 1
            value: list[str] = []
            while True:
                if index >= length:
                    raise ValueError(f"unterminated quoted value for {key!r}")
                character = text[index]
                if character == '"':
                    index += 1
                    break
                if character != "\\":
                    value.append(character)
                    index += 1
                    continue
                escape = text[index + 1 : index + 2]
                if escape in ('"', "\\"):
                    value.append(escape)
                    index += 2
                elif escape == "x":
                    digits = text[index + 2 : index + 4]
                    if len(digits) != 2:
                        raise ValueError(f"truncated escape in {key!r}")
                    value.append(chr(int(digits, 16)))
                    index += 4
                else:
                    raise ValueError(f"invalid escape in {key!r}")
            parsed = "".join(value)
        else:
            end = text.find(" ", index)
            if end < 0:
                end = length
            parsed = text[index:end]
            index = end
        if key in fields:
            raise ValueError(f"duplicate field {key!r}")
        fields[key] = parsed
    return fields


def _clean_line(line: str) -> str:
    return line.removesuffix("\r").removesuffix("\n").removesuffix("\r")


def parse_marker(line: str) -> dict[str, str] | None:
    """Parse an ``NVX-TIME-ABI:`` marker line, or return None for other lines."""
    line = _clean_line(line)
    if not line.startswith(MARKER_PREFIX):
        return None
    fields = parse_fields(line.removeprefix(MARKER_PREFIX))
    for name in ("v", "phase", "status"):
        if name not in fields:
            raise ValueError(f"time ABI marker lacks {name!r}: {line!r}")
    return fields


def parse_violation(line: str) -> dict[str, str] | None:
    """Parse an ``NVX-TIME-ABI-VIOLATION:`` event anywhere in a console line."""
    line = _clean_line(line)
    start = line.find(VIOLATION_PREFIX)
    if start < 0:
        return None
    fields = parse_fields(line[start + len(VIOLATION_PREFIX) :])
    if "code" not in fields:
        raise ValueError(f"time ABI violation lacks a code: {line!r}")
    return fields


def describe_exit_status(returncode: int | None) -> str | None:
    """Describe an OpenVMM exit status that a time ABI guest failure produced."""
    if returncode is None or returncode not in STATUS_CLASSES:
        return None
    return f"guest powered off with time ABI status {returncode} ({STATUS_CLASSES[returncode]})"


def _command_option(command: Sequence[str], option: str) -> str | None:
    for index, argument in enumerate(command[:-1]):
        if argument == option:
            return command[index + 1]
    return None


def is_cold_boot_command(command: Sequence[str]) -> bool:
    """Whether an OpenVMM command boots a kernel rather than restoring."""
    return "--kernel" in command and "--restore-snapshot" not in command


def validate_boot_marker(
    fields: Mapping[str, str],
    *,
    backend: str | None,
    online_cpus: int | None = None,
) -> None:
    """Check the boot marker's fields against the backend's declared rates."""
    problems: list[str] = []
    if fields.get("v") != ABI_VERSION:
        problems.append(f"version {fields.get('v')!r} is not {ABI_VERSION}")
    if fields.get("phase") != "boot" or fields.get("status") != "ok":
        problems.append("it is not a passing boot check")
    try:
        tsc_hz = int(fields.get("tsc_hz", ""))
        if not MIN_TSC_HZ <= tsc_hz <= MAX_TSC_HZ:
            problems.append(f"tsc_hz={tsc_hz} is outside 500 MHz to 10 GHz")
    except ValueError:
        problems.append(f"tsc_hz={fields.get('tsc_hz')!r} is not an integer")
    lapic = fields.get("lapic_hz")
    expected_lapic = LAPIC_HZ.get(backend) if backend is not None else None
    if expected_lapic is not None and lapic != str(expected_lapic):
        problems.append(f"lapic_hz={lapic} is not the {backend} rate {expected_lapic}")
    if fields.get("generation") != "0":
        problems.append(f"generation={fields.get('generation')} is not 0 at cold boot")
    if online_cpus is not None and fields.get("cpus") != str(online_cpus):
        problems.append(f"cpus={fields.get('cpus')} is not {online_cpus}")
    if problems:
        raise TimeAbiFailure(
            "guest time ABI boot marker is invalid: " + "; ".join(problems)
        )


class TimeAbiMonitor:
    """Scan OpenVMM console output for time ABI markers and violations.

    ``feed`` raises TimeAbiFailure as soon as a completed line carries a
    violation event or a failed conformance check, so a scenario fails fast
    with the guest's own explanation instead of a marker timeout.
    """

    def __init__(self, command: Sequence[str] = ()) -> None:
        self.backend = _command_option(command, "--hypervisor")
        self.cold_boot = is_cold_boot_command(command)
        self.boot: dict[str, str] | None = None
        self.restores: list[dict[str, str]] = []
        self.uncertain: list[dict[str, str]] = []
        self.violation: str | None = None
        self.report_only = False
        self.guest_booted = False
        self._pending = bytearray()

    def feed(self, chunk: bytes | bytearray) -> None:
        self._pending.extend(chunk)
        while True:
            newline = self._pending.find(b"\n")
            if newline < 0:
                break
            line = bytes(self._pending[:newline])
            del self._pending[: newline + 1]
            self._line(line.decode("utf-8", "replace"))
        if len(self._pending) > _MAX_PENDING_LINE:
            del self._pending[: len(self._pending) - 4096]

    def finish(self) -> None:
        """Scan an unterminated final line once the output reached EOF."""
        if self._pending:
            line = bytes(self._pending)
            self._pending.clear()
            self._line(line.decode("utf-8", "replace"))

    def _line(self, line: str) -> None:
        line = _clean_line(line)
        if VIOLATION_PREFIX in line:
            try:
                event = parse_violation(line)
            except ValueError:
                event = None
            self.violation = line[line.find(VIOLATION_PREFIX) :]
            code = event["code"] if event is not None else "unparsed"
            raise TimeAbiFailure(
                f"guest reported time ABI violation {code}: {self.violation}"
            )
        if line.startswith(REPORT_ONLY_PREFIX):
            self.report_only = True
            return
        if any(line.startswith(marker) for marker in GUEST_BOOT_MARKERS) or any(
            f" {marker}" in line for marker in GUEST_BOOT_MARKERS
        ):
            self.guest_booted = True
        if not line.startswith(MARKER_PREFIX):
            return
        try:
            fields = parse_marker(line)
        except ValueError as error:
            raise TimeAbiFailure(f"malformed time ABI marker: {error}") from error
        assert fields is not None
        status = fields["status"]
        if status == "fail":
            raise TimeAbiFailure(
                f"guest time ABI {fields['phase']} check {fields.get('check', '?')} "
                f"failed: {fields.get('detail', line)}"
            )
        if status == "uncertain":
            self.uncertain.append(fields)
        elif status != "ok":
            raise TimeAbiFailure(f"unknown time ABI marker status: {line}")
        elif fields["phase"] == "boot":
            if self.boot is None:
                self.boot = fields
        elif fields["phase"] == "restore":
            self.restores.append(fields)

    def check_exit(self, returncode: int | None) -> None:
        """Fail on an OpenVMM exit status produced by a time ABI power-off."""
        description = describe_exit_status(returncode)
        if description is None:
            return
        event = self.violation or "no NVX-TIME-ABI-VIOLATION event was observed"
        raise TimeAbiFailure(f"{description}: {event}")

    def require_boot(
        self,
        context: str,
        *,
        online_cpus: int | None = None,
    ) -> dict[str, str]:
        """Return the validated boot marker of a cold boot, or fail clearly."""
        if self.boot is None:
            reason = (
                "the guest ran nvx-time in report-only mode"
                if self.report_only
                else "the guest image or OpenVMM does not implement time ABI v1"
            )
            raise TimeAbiFailure(
                f"guest did not print the NVX-TIME-ABI boot marker before {context}; "
                f"{reason}"
            )
        validate_boot_marker(
            self.boot,
            backend=self.backend,
            online_cpus=online_cpus,
        )
        return self.boot

    def require_boot_if_booted(self) -> None:
        """Require the boot marker once a cold-booted guest reached its shell."""
        if self.cold_boot and self.guest_booted:
            self.require_boot("the guest boot marker")


def warp_probe_command(*, cpus: str | None = None) -> str:
    """Return the guest command line that runs the warp probe."""
    command = f"{WARP_PROBE_PATH} warp --bound-ns {WARP_BOUND_NS}"
    return command if cpus is None else f"{command} --cpus {cpus}"


def check_warp_probe(
    text: str,
    *,
    cpus: int,
    context: str,
) -> list[dict[str, str]]:
    """Validate every warp probe summary in console output.

    The spec bounds both the backward step and the ping-pong offset by 1 us
    and forbids stalled pairs; an inconclusive measurement proves nothing.
    """
    summaries: list[dict[str, str]] = []
    details: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = _clean_line(raw)
        try:
            if line.startswith(WARP_DETAIL_PREFIX):
                details.append(parse_fields(line.removeprefix(WARP_DETAIL_PREFIX)))
            elif line.startswith(WARP_SUMMARY_PREFIX):
                summaries.append(parse_fields(line.removeprefix(WARP_SUMMARY_PREFIX)))
        except ValueError as error:
            raise TimeAbiFailure(
                f"{context}: malformed warp probe output: {error}"
            ) from error
    if not summaries:
        raise TimeAbiFailure(f"{context}: the guest warp probe printed no summary")
    if len(details) != len(summaries):
        raise TimeAbiFailure(
            f"{context}: the guest warp probe printed {len(summaries)} summaries "
            f"and {len(details)} detail lines"
        )
    expected_pairs = cpus * (cpus - 1) // 2
    results: list[dict[str, str]] = []
    for summary, detail in zip(summaries, details, strict=True):
        merged = {**summary, **detail}
        problems: list[str] = []
        try:
            backward = int(merged["max_backward_ns"])
            offset = int(merged["max_abs_offset_ns"])
            pairs = int(merged["pairs"])
            stalled = int(merged["stalled_pairs"])
        except (KeyError, ValueError) as error:
            raise TimeAbiFailure(
                f"{context}: incomplete warp probe output: {error}"
            ) from error
        if pairs != expected_pairs:
            problems.append(f"measured {pairs} CPU pairs instead of {expected_pairs}")
        if backward > WARP_BOUND_NS:
            problems.append(f"max_backward_ns={backward} exceeds {WARP_BOUND_NS}")
        if offset > WARP_BOUND_NS:
            problems.append(f"max_abs_offset_ns={offset} exceeds {WARP_BOUND_NS}")
        if stalled:
            problems.append(f"{stalled} CPU pair(s) stalled")
        if merged.get("conclusive") != "1":
            problems.append(
                "the measurement is inconclusive "
                f"(max_uncertainty_ns={merged.get('max_uncertainty_ns')})"
            )
        if merged.get("verdict") != "PASS":
            problems.append(f"verdict={merged.get('verdict')}")
        if problems:
            raise TimeAbiFailure(
                f"{context}: cross-vCPU TSC skew check failed: " + "; ".join(problems)
            )
        results.append(merged)
    return results
