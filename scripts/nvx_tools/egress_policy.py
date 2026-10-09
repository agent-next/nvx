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
_MXC_RULE_FIELDS = frozenset(("to", "ports"))
_PEER_FIELDS = frozenset(("cidr", "except"))
_PORT_FIELDS = frozenset(("protocol", "port", "endPort"))
_LEGACY_RULE_FIELDS = frozenset(("cidr", "except", "protocol", "port", "endPort"))
_RULE_PROTOCOLS = ("tcp", "udp", "icmp", "any")
# Protocols that a native rule can select on every port, and those with ports.
_NATIVE_PROTOCOLS = ("icmp", "tcp", "udp")
_PORT_PROTOCOLS = ("tcp", "udp")
_AddressInterval = tuple[int, int]
_AddressIntervals = tuple[_AddressInterval, ...]
_PortSelector = tuple[str | None, int | None, int | None]
_ALL_IPV4: _AddressIntervals = ((0, (1 << 32) - 1),)


@dataclass(frozen=True)
class CompiledEgressPolicy:
    allow: tuple[str, ...]
    deny: tuple[str, ...]


@dataclass(frozen=True)
class _Rule:
    addresses: _AddressIntervals
    # None matches every IPv4 protocol.
    protocol: str | None
    # None matches every port of the protocol.
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


def _parse_peer(value: object, description: str) -> _AddressIntervals:
    peer = _object(value, description)
    unknown = sorted(set(peer) - _PEER_FIELDS)
    if unknown:
        raise ScriptError(f"{description} has unknown field '{unknown[0]}'")
    if "cidr" not in peer:
        raise ScriptError(f"{description}.cidr is required")
    parent = _network(peer["cidr"], f"{description}.cidr")
    exclusions = _array(peer.get("except", []), f"{description}.except")
    return _subtract_exclusions(parent, exclusions, description)


def _parse_legacy_rule(rule: dict[str, object], description: str) -> tuple[_Rule, ...]:
    unknown = sorted(set(rule) - _LEGACY_RULE_FIELDS)
    if unknown:
        raise ScriptError(f"{description} has unknown field '{unknown[0]}'")
    if "cidr" not in rule:
        raise ScriptError(f"{description}.cidr is required")
    addresses = _parse_peer(
        {field: rule[field] for field in ("cidr", "except") if field in rule},
        description,
    )
    if "protocol" not in rule:
        if "port" in rule or "endPort" in rule:
            raise ScriptError(f"{description}.port requires protocol")
        return (_Rule(addresses, None, None, None),)
    protocol = rule["protocol"]
    if not isinstance(protocol, str) or protocol not in _RULE_PROTOCOLS:
        raise ScriptError(f"{description}.protocol must be tcp, udp, icmp, or any")
    if "port" not in rule:
        if "endPort" in rule:
            raise ScriptError(f"{description}.endPort requires port")
        return (_Rule(addresses, None if protocol == "any" else protocol, None, None),)
    if protocol == "icmp":
        raise ScriptError(f"{description}.port is not supported with icmp")
    start = _port(rule["port"], f"{description}.port")
    end = _port(rule.get("endPort", start), f"{description}.endPort")
    if end < start:
        raise ScriptError(f"{description}.endPort cannot be below port")
    protocols = _PORT_PROTOCOLS if protocol == "any" else (protocol,)
    return tuple(_Rule(addresses, selected, start, end) for selected in protocols)


def _parse_mxc_port(value: object, description: str) -> tuple[_PortSelector, ...]:
    port = _object(value, description)
    unknown = sorted(set(port) - _PORT_FIELDS)
    if unknown:
        raise ScriptError(f"{description} has unknown field '{unknown[0]}'")
    protocol = port.get("protocol", "any")
    if not isinstance(protocol, str) or protocol not in _RULE_PROTOCOLS:
        raise ScriptError(f"{description}.protocol must be tcp, udp, icmp, or any")
    if "port" not in port:
        if "endPort" in port:
            raise ScriptError(f"{description}.endPort requires port")
        return (
            (
                None if protocol == "any" else protocol,
                None,
                None,
            ),
        )
    if protocol == "icmp":
        raise ScriptError(f"{description}.port is not supported with icmp")
    start = _port(port["port"], f"{description}.port")
    end = _port(port.get("endPort", start), f"{description}.endPort")
    if end < start:
        raise ScriptError(f"{description}.endPort cannot be below port")
    protocols = _PORT_PROTOCOLS if protocol == "any" else (protocol,)
    return tuple((selected, start, end) for selected in protocols)


def _parse_mxc_rule(
    rule: dict[str, object],
    description: str,
) -> tuple[_Rule, ...]:
    unknown = sorted(set(rule) - _MXC_RULE_FIELDS)
    if unknown:
        raise ScriptError(f"{description} has unknown field '{unknown[0]}'")

    addresses = _ALL_IPV4
    if "to" in rule:
        peers = _array(rule["to"], f"{description}.to")
        if not peers:
            raise ScriptError(f"{description}.to must contain at least one destination")
        addresses = _merge_intervals(
            interval
            for index, peer in enumerate(peers)
            for interval in _parse_peer(peer, f"{description}.to[{index}]")
        )

    selectors: list[_PortSelector] = [(None, None, None)]
    if "ports" in rule:
        ports = _array(rule["ports"], f"{description}.ports")
        if not ports:
            raise ScriptError(f"{description}.ports must contain at least one selector")
        selectors = [
            selector
            for index, port in enumerate(ports)
            for selector in _parse_mxc_port(port, f"{description}.ports[{index}]")
        ]
    return tuple(
        _Rule(addresses, protocol, start_port, end_port)
        for protocol, start_port, end_port in selectors
    )


def _parse_rule(value: object, description: str) -> tuple[_Rule, ...]:
    rule = _object(value, description)
    legacy = set(rule) & _LEGACY_RULE_FIELDS
    mxc = set(rule) & _MXC_RULE_FIELDS
    if legacy:
        if mxc:
            raise ScriptError(
                f"{description} cannot mix MXC to/ports fields with legacy flat fields"
            )
        return _parse_legacy_rule(rule, description)
    return _parse_mxc_rule(rule, description)


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
    covered: _AddressIntervals,
    maximum: int,
    category: str,
) -> tuple[ipaddress.IPv4Network, ...]:
    # Rules over `covered` already match this selector, so widening prefixes
    # into it keeps the output compact without changing what matches.
    combined = _merge_intervals((*protocol_intervals, *covered))
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
            if not _subtract_intervals((network_interval,), covered):
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
    covered: _AddressIntervals,
    remaining_budget: int,
) -> list[tuple[ipaddress.IPv4Network, str, int]]:
    events: dict[int, list[tuple[int, _AddressIntervals]]] = {}
    for rule in rules:
        if (
            rule.protocol != protocol
            or rule.start_port is None
            or rule.end_port is None
            or not rule.addresses
        ):
            continue
        uncovered_addresses = _subtract_intervals(rule.addresses, covered)
        if not uncovered_addresses:
            continue
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
                covered,
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


def _native_rule(
    network: ipaddress.IPv4Network, protocol: str | None, port: int | None
) -> str:
    if protocol is None:
        return str(network)
    if port is None:
        return f"{network}:{protocol}"
    return f"{network}:{protocol}:{port}"


def _compile_category(value: object, category: str) -> tuple[str, ...]:
    values = _array(value, category)
    rules = [
        rule
        for index, item in enumerate(values)
        for rule in _parse_rule(item, f"{category}[{index}]")
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
    # Addresses that already match every port of each protocol.
    covered = dict.fromkeys(_NATIVE_PROTOCOLS, address_only)
    for protocol in _NATIVE_PROTOCOLS:
        protocol_wide = _merge_intervals(
            interval
            for rule in rules
            if rule.protocol == protocol and rule.start_port is None
            for interval in rule.addresses
        )
        if not protocol_wide:
            continue
        lowered.extend(
            (network, protocol, None)
            for network in _protocol_intervals_to_networks(
                protocol_wide,
                address_only,
                MAX_RULES_PER_ACTION - len(lowered),
                category,
            )
        )
        covered[protocol] = _merge_intervals((*address_only, *protocol_wide))
    for protocol in _PORT_PROTOCOLS:
        lowered.extend(
            _lower_protocol_rules(
                rules,
                protocol,
                category,
                covered[protocol],
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
        _native_rule(network, protocol, port) for network, protocol, port in lowered
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
