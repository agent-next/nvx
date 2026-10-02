"""Compile structured IPv4 egress policies to the native OpenVMM rule grammar."""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .common import ScriptError, strict_json_object

MAX_RULES_PER_ACTION = 256
MAX_POLICY_FILE_SIZE = 1024 * 1024
_MAX_JSON_INTEGER_DIGITS = 64
_ROOT_FIELDS = frozenset(("allow", "deny"))
_RULE_FIELDS = frozenset(("cidr", "except", "protocol", "port", "endPort"))
_AddressInterval = tuple[int, int]
_AddressIntervals = tuple[_AddressInterval, ...]


@dataclass(frozen=True)
class CompiledEgressPolicy:
    allow: tuple[str, ...]
    deny: tuple[str, ...]


@dataclass(frozen=True)
class _Rule:
    addresses: _AddressIntervals
    protocol: str | None
    start_port: int | None
    end_port: int | None


def _object(value: object, description: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ScriptError(f"{description} must be an object")
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise ScriptError(f"{description} fields must be strings")
    return cast(dict[str, object], value)


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ScriptError(f"{description} must be an array")
    return cast(list[object], value)


def _network(value: object, description: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise ScriptError(f"{description} must be an IPv4 CIDR string")
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise ScriptError(f"{description} is not a valid IPv4 CIDR: {value}") from error
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ScriptError(f"{description} must be an IPv4 CIDR")
    return parsed


def _port(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScriptError(f"{description} must be an integer")
    if not 1 <= value <= 65535:
        raise ScriptError(f"{description} must be between 1 and 65535")
    return value


def _bounded_json_integer(value: str) -> int:
    if len(value.removeprefix("-")) > _MAX_JSON_INTEGER_DIGITS:
        raise ScriptError(
            f"JSON integer exceeds {_MAX_JSON_INTEGER_DIGITS}-digit limit"
        )
    return int(value)


def _merge_intervals(intervals: Iterable[_AddressInterval]) -> _AddressIntervals:
    merged: list[_AddressInterval] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _subtract_intervals(
    sources: _AddressIntervals,
    exclusions: _AddressIntervals,
) -> _AddressIntervals:
    remaining: list[_AddressInterval] = []
    exclusion_index = 0
    for source_start, source_end in sources:
        while (
            exclusion_index < len(exclusions)
            and exclusions[exclusion_index][1] < source_start
        ):
            exclusion_index += 1

        cursor = source_start
        current_index = exclusion_index
        while (
            current_index < len(exclusions)
            and exclusions[current_index][0] <= source_end
        ):
            excluded_start, excluded_end = exclusions[current_index]
            if cursor < excluded_start:
                remaining.append((cursor, excluded_start - 1))
            cursor = max(cursor, excluded_end + 1)
            if cursor > source_end:
                break
            current_index += 1
        if cursor <= source_end:
            remaining.append((cursor, source_end))
    return tuple(remaining)


def _subtract_exclusions(
    parent: ipaddress.IPv4Network,
    exclusions: list[object],
    description: str,
) -> _AddressIntervals:
    parsed: list[_AddressInterval] = []
    for index, value in enumerate(exclusions):
        exclusion = _network(value, f"{description}.except[{index}]")
        if not exclusion.subnet_of(parent):
            raise ScriptError(
                f"{description}.except[{index}] must be contained in {parent}"
            )
        parsed.append(
            (int(exclusion.network_address), int(exclusion.broadcast_address))
        )

    parent_interval = (
        int(parent.network_address),
        int(parent.broadcast_address),
    )
    return _subtract_intervals((parent_interval,), _merge_intervals(parsed))


def _parse_rule(value: object, description: str) -> _Rule:
    rule = _object(value, description)
    unknown = sorted(set(rule) - _RULE_FIELDS)
    if unknown:
        raise ScriptError(f"{description} has unknown field '{unknown[0]}'")
    if "cidr" not in rule:
        raise ScriptError(f"{description}.cidr is required")
    parent = _network(rule["cidr"], f"{description}.cidr")
    exclusions = _array(rule.get("except", []), f"{description}.except")
    addresses = _subtract_exclusions(parent, exclusions, description)

    protocol_value = rule.get("protocol")
    if "protocol" not in rule:
        if "port" in rule or "endPort" in rule:
            raise ScriptError(f"{description}.port requires protocol")
        return _Rule(addresses, None, None, None)
    if not isinstance(protocol_value, str) or protocol_value not in ("tcp", "udp"):
        raise ScriptError(f"{description}.protocol must be tcp or udp")
    if "port" not in rule:
        raise ScriptError(f"{description}.port is required with protocol")
    start = _port(rule["port"], f"{description}.port")
    end = _port(rule.get("endPort", start), f"{description}.endPort")
    if end < start:
        raise ScriptError(f"{description}.endPort cannot be below port")
    return _Rule(addresses, protocol_value, start, end)


def _intervals_to_networks(
    intervals: _AddressIntervals,
    maximum: int,
    category: str,
) -> tuple[ipaddress.IPv4Network, ...]:
    networks: list[ipaddress.IPv4Network] = []
    for start, end in intervals:
        summarized = ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start),
            ipaddress.IPv4Address(end),
        )
        for network in summarized:
            if len(networks) >= maximum:
                raise ScriptError(
                    f"{category} emits at most {MAX_RULES_PER_ACTION} native rules"
                )
            networks.append(network)
    return tuple(networks)


def _protocol_intervals_to_networks(
    protocol_intervals: _AddressIntervals,
    address_only: _AddressIntervals,
    maximum: int,
    category: str,
) -> tuple[ipaddress.IPv4Network, ...]:
    combined = _merge_intervals((*protocol_intervals, *address_only))
    networks: list[ipaddress.IPv4Network] = []
    for start, end in combined:
        summarized = ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start),
            ipaddress.IPv4Address(end),
        )
        for network in summarized:
            network_interval = (
                int(network.network_address),
                int(network.broadcast_address),
            )
            if not _subtract_intervals((network_interval,), address_only):
                continue
            if len(networks) >= maximum:
                raise ScriptError(
                    f"{category} emits at most {MAX_RULES_PER_ACTION} native rules"
                )
            networks.append(network)
    return tuple(networks)


def _lower_protocol_rules(
    rules: list[_Rule],
    protocol: str,
    category: str,
    address_only: _AddressIntervals,
    remaining_budget: int,
) -> list[tuple[ipaddress.IPv4Network, str, int]]:
    events: dict[int, list[tuple[int, _AddressIntervals]]] = {}
    for rule in rules:
        if rule.protocol != protocol or not rule.addresses:
            continue
        uncovered_addresses = _subtract_intervals(rule.addresses, address_only)
        if not uncovered_addresses:
            continue
        assert rule.start_port is not None
        assert rule.end_port is not None
        events.setdefault(rule.start_port, []).append((1, rule.addresses))
        events.setdefault(rule.end_port + 1, []).append((-1, rule.addresses))

    active: Counter[_AddressIntervals] = Counter()
    lowered: list[tuple[ipaddress.IPv4Network, str, int]] = []
    previous_port: int | None = None
    for port in sorted(events):
        if previous_port is not None and previous_port < port and active:
            addresses = _merge_intervals(
                interval for intervals in active for interval in intervals
            )
            port_count = port - previous_port
            network_budget = (remaining_budget - len(lowered)) // port_count
            networks = _protocol_intervals_to_networks(
                addresses,
                address_only,
                network_budget,
                category,
            )
            lowered.extend(
                (network, protocol, current_port)
                for current_port in range(previous_port, port)
                for network in networks
            )
        for direction, addresses in events[port]:
            active[addresses] += direction
            if active[addresses] == 0:
                del active[addresses]
        previous_port = port
    return lowered


def _compile_category(value: object, category: str) -> tuple[str, ...]:
    values = _array(value, category)
    rules = [
        _parse_rule(rule, f"{category}[{index}]") for index, rule in enumerate(values)
    ]
    address_only = _merge_intervals(
        interval
        for rule in rules
        if rule.protocol is None
        for interval in rule.addresses
    )
    address_only_networks = _intervals_to_networks(
        address_only,
        MAX_RULES_PER_ACTION,
        category,
    )
    lowered: list[tuple[ipaddress.IPv4Network, str | None, int | None]] = [
        (network, None, None) for network in address_only_networks
    ]
    for protocol in ("tcp", "udp"):
        lowered.extend(
            _lower_protocol_rules(
                rules,
                protocol,
                category,
                address_only,
                MAX_RULES_PER_ACTION - len(lowered),
            )
        )
    lowered.sort(
        key=lambda item: (
            int(item[0].network_address),
            item[0].prefixlen,
            "" if item[1] is None else item[1],
            0 if item[2] is None else item[2],
        )
    )
    return tuple(
        str(network) if protocol is None else f"{network}:{protocol}:{port}"
        for network, protocol, port in lowered
    )


def compile_policy(value: object) -> CompiledEgressPolicy:
    root = _object(value, "egress policy")
    unknown = sorted(set(root) - _ROOT_FIELDS)
    if unknown:
        raise ScriptError(f"egress policy has unknown field '{unknown[0]}'")
    return CompiledEgressPolicy(
        allow=_compile_category(root.get("allow", []), "allow"),
        deny=_compile_category(root.get("deny", []), "deny"),
    )


def compile_policy_file(path: Path) -> CompiledEgressPolicy:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_POLICY_FILE_SIZE + 1)
    except OSError as error:
        raise ScriptError(f"failed to read egress policy file: {path}") from error
    if len(data) > MAX_POLICY_FILE_SIZE:
        raise ScriptError(
            f"egress policy file exceeds {MAX_POLICY_FILE_SIZE}-byte limit: {path}"
        )
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=strict_json_object,
            parse_int=_bounded_json_integer,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ScriptError(f"failed to read egress policy file: {path}") from error
    return compile_policy(value)
