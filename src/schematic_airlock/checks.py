"""Deterministic structural and electrical safety checks.

The checks in this module intentionally answer questions that can be proven
from a bounded netlist parse.  They do not claim to replace simulation or a
foundry design-rule check.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256

from schematic_airlock.bundle import BundleSource
from schematic_airlock.circuit_graph import CircuitGraph, Device, Net
from schematic_airlock.domain import Finding, Severity, SourceLocation
from schematic_airlock.include_graph import IncludeGraph
from schematic_airlock.parse import Directive
from schematic_airlock.policy import AuditPolicy
from schematic_airlock.solvability import (
    MAX_REPORTED_NODES,
    floating_islands,
    has_ground,
    voltage_source_loops,
)
from schematic_airlock.units import evaluate_expression, parse_number


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Read-only inputs supplied to every audit rule."""

    bundle: BundleSource
    includes: IncludeGraph
    graph: CircuitGraph
    policy: AuditPolicy

    @property
    def intended_ports(self) -> Mapping[str, str]:
        ports = self.bundle.manifest.get("intended_ports", {})
        if not isinstance(ports, Mapping):
            return {}
        return {str(name).lower(): str(role) for name, role in ports.items()}


_FORBIDDEN_DIRECTIVES = {
    "control",
    "endc",
    "exec",
    "shell",
    "system",
    "python",
    "py",
    "verilog",
    "hdl",
    "osdi",
    "load",
    "pre_osdi",
}

_KNOWN_DIRECTIVES = {
    "ac",
    "alter",
    "dc",
    "end",
    "ends",
    "global",
    "ic",
    "include",
    "lib",
    "meas",
    "measure",
    "model",
    "nodeset",
    "noise",
    "op",
    "options",
    "param",
    "plot",
    "print",
    "probe",
    "save",
    "sens",
    "step",
    "subckt",
    "temp",
    "tf",
    "tran",
}

_GRAPH_SEVERITY = {
    "GRAPH001": Severity.DENY,
    "GRAPH002": Severity.DENY,
    "GRAPH003": Severity.DENY,
    "GRAPH004": Severity.DENY,
    "GRAPH005": Severity.DENY,
    "GRAPH006": Severity.REVIEW,
    "GRAPH007": Severity.DENY,
    "GRAPH008": Severity.REVIEW,
}

_LOAD_SEVERITY = {
    "INCL001": Severity.DENY,
    "INCL002": Severity.DENY,
    "INCL003": Severity.REVIEW,
    "PARSE001": Severity.DENY,
    "FILE001": Severity.DENY,
    "PATH001": Severity.DENY,
}

_PURE_SPICE_NUMBER = re.compile(
    r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[A-Za-z]*\Z",
    re.ASCII,
)
_MAX_RAIL_WITNESS_DEVICES = 12
_MAX_RAIL_WITNESS_NAME = 96


@dataclass(frozen=True, slots=True)
class _RailTie:
    first: str
    second: str
    device: Device


class _RailUnion:
    """Near-linear disjoint sets for the declared DC short-intent profile."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.size: dict[str, int] = {}

    def find(self, node: str) -> str:
        if node not in self.parent:
            self.parent[node] = node
            self.size[node] = 1
            return node
        root = node
        while self.parent[root] != root:
            self.parent[root] = self.parent[self.parent[root]]
            root = self.parent[root]
        return root

    def union(self, first: str, second: str) -> None:
        left, right = self.find(first), self.find(second)
        if left == right:
            return
        if self.size[left] < self.size[right]:
            left, right = right, left
        self.parent[right] = left
        self.size[left] += self.size[right]


def _finding(
    context: CheckContext,
    code: str,
    title: str,
    severity: Severity,
    message: str,
    location: SourceLocation | None = None,
    *,
    evidence: str = "",
    remediation: str = "",
    metadata: Mapping[str, object] | None = None,
) -> Finding:
    return Finding(
        code=code,
        title=title,
        severity=context.policy.severity_for(code, severity),
        message=message,
        location=location,
        evidence=evidence,
        remediation=remediation,
        metadata=metadata or {},
    )


def _all_directives(includes: IncludeGraph) -> Iterable[Directive]:
    for deck in includes.decks:
        yield from deck.directives
        for subcircuit in deck.subcircuits:
            yield from subcircuit.directives


def _all_elements(graph: CircuitGraph) -> Iterable[Device]:
    yield from graph.devices


def _electrical_elements(graph: CircuitGraph) -> Iterable[Device]:
    yield from graph.expanded_devices


def _numeric(text: str | None, parameters: Mapping[str, Decimal] | None = None) -> Decimal | None:
    if text is None:
        return None
    try:
        return evaluate_expression(text, parameters) if parameters else parse_number(text)
    except ValueError:
        return None


def _load_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for issue in context.includes.issues:
        findings.append(
            _finding(
                context,
                issue.code,
                "Unsafe or unreadable include",
                _LOAD_SEVERITY.get(issue.code, Severity.DENY),
                issue.message,
                issue.location,
                evidence=issue.evidence,
                remediation="Keep every referenced UTF-8 netlist inside the artifact bundle.",
                metadata={"target": issue.target} if issue.target else None,
            )
        )
    return findings


def _graph_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for issue in context.graph.issues:
        findings.append(
            _finding(
                context,
                issue.code,
                "Inconsistent circuit structure",
                _GRAPH_SEVERITY.get(issue.code, Severity.REVIEW),
                issue.message,
                issue.location,
                evidence=issue.evidence,
                remediation="Make instance names and subcircuit calls unambiguous and finite.",
            )
        )
    if context.graph.expanded_instances > context.policy.limits.max_expanded_instances:
        findings.append(
            _finding(
                context,
                "LIM001",
                "Expansion budget exceeded",
                Severity.DENY,
                "the estimated flattened circuit exceeds the configured instance budget",
                metadata={
                    "estimated": context.graph.expanded_instances,
                    "limit": context.policy.limits.max_expanded_instances,
                },
                remediation="Reduce hierarchy fan-out or raise the limit after human review.",
            )
        )
    return findings


def _directive_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for directive in _all_directives(context.includes):
        name = directive.name.lower()
        if name in _FORBIDDEN_DIRECTIVES:
            findings.append(
                _finding(
                    context,
                    "EXEC001",
                    "Executable simulator command",
                    Severity.DENY,
                    f".{name} may execute code or load executable extensions",
                    directive.location,
                    evidence=directive.raw,
                    remediation="Remove executable control commands from the submitted artifact.",
                )
            )
        elif name not in _KNOWN_DIRECTIVES:
            findings.append(
                _finding(
                    context,
                    "DIR001",
                    "Unknown directive",
                    context.policy.rules.unknown_directive,
                    f".{name} is outside the recognized offline subset",
                    directive.location,
                    evidence=directive.raw,
                    remediation="Document and explicitly allow the directive before use.",
                )
            )
        elif (
            name == "lib"
            and len(directive.arguments) == 1
            and not any(mark in directive.arguments[0] for mark in ("/", "\\", "."))
        ):
            findings.append(
                _finding(
                    context,
                    "LIB001",
                    "Ambient library section",
                    Severity.REVIEW,
                    ".lib section selection depends on simulator ambient library state",
                    directive.location,
                    evidence=directive.raw,
                    remediation="Bundle an explicit library file path and section.",
                )
            )
    return findings


def _analysis_points(directive: Directive) -> int | None:
    """Estimate points for the simple, unambiguous forms we support."""

    args = directive.arguments
    try:
        if directive.name == "tran" and len(args) >= 2:
            step = abs(float(parse_number(args[0])))
            stop = abs(float(parse_number(args[1])))
            start = abs(float(parse_number(args[2]))) if len(args) >= 3 else 0.0
            if step == 0:
                return 2**63
            return max(1, math.ceil(max(0.0, stop - start) / step) + 1)
        if directive.name == "dc" and len(args) >= 4:
            start = float(parse_number(args[1]))
            stop = float(parse_number(args[2]))
            step = abs(float(parse_number(args[3])))
            if step == 0:
                return 2**63
            return max(1, math.ceil(abs(stop - start) / step) + 1)
        if directive.name == "ac" and len(args) >= 4:
            mode = args[0].lower()
            count = int(parse_number(args[1]))
            if count <= 0:
                return 0
            if mode == "lin":
                return count
            start = float(parse_number(args[2]))
            stop = float(parse_number(args[3]))
            if start <= 0 or stop <= 0:
                return 0
            decades = abs(math.log10(stop / start))
            span = decades if mode == "dec" else decades * math.log(10, 2)
            return max(1, math.ceil(count * span) + 1)
    except (ValueError, OverflowError, ArithmeticError):
        return None
    return None


def _analysis_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    directives = list(_all_directives(context.includes))
    step_product = 1
    for directive in directives:
        if directive.name == "step":
            points = _step_points(directive)
            if points is None:
                findings.append(
                    _finding(
                        context,
                        "ANL002",
                        "Unbounded analysis expression",
                        Severity.REVIEW,
                        "cannot statically bound the .step analysis multiplier",
                        directive.location,
                        evidence=directive.raw,
                    )
                )
            else:
                step_product *= points
    for directive in directives:
        if directive.name not in {"tran", "dc", "ac"}:
            continue
        points = _analysis_points(directive)
        if points is None:
            findings.append(
                _finding(
                    context,
                    "ANL002",
                    "Unbounded analysis expression",
                    Severity.REVIEW,
                    f"cannot statically bound the .{directive.name} analysis",
                    directive.location,
                    evidence=directive.raw,
                    remediation=(
                        "Use literal finite sweep values or review the expression manually."
                    ),
                )
            )
        elif points <= 0 or points * step_product > context.policy.limits.max_analysis_points:
            findings.append(
                _finding(
                    context,
                    "ANL001",
                    "Analysis budget exceeded",
                    Severity.DENY,
                    f".{directive.name} requests an invalid or excessive number of points",
                    directive.location,
                    evidence=directive.raw,
                    remediation="Reduce the sweep resolution or duration.",
                    metadata={
                        "estimated_points": points * step_product,
                        "limit": context.policy.limits.max_analysis_points,
                    },
                )
            )
    for device in context.graph.devices:
        if device.element.kind not in {"V", "I"}:
            continue
        match = re.search(r"\bpwl\s*\((.*)\)", device.element.raw, re.IGNORECASE)
        if match is None:
            continue
        tokens = [item for item in re.split(r"[\s,]+", match.group(1).strip()) if item]
        if len(tokens) % 2 or len(tokens) // 2 > context.policy.limits.max_pwl_points:
            findings.append(
                _finding(
                    context,
                    "ANL003",
                    "PWL point budget exceeded",
                    Severity.DENY,
                    "piecewise-linear source is malformed or exceeds the configured point budget",
                    device.element.location,
                    evidence=device.element.raw,
                    metadata={
                        "points": len(tokens) // 2,
                        "limit": context.policy.limits.max_pwl_points,
                    },
                )
            )
    return findings


def _step_points(directive: Directive) -> int | None:
    args = directive.arguments
    try:
        lowered = [item.lower() for item in args]
        if "list" in lowered:
            index = lowered.index("list")
            return len(args[index + 1 :]) or None
        offset = 1 if args and args[0].lower() == "param" else 0
        if len(args) < offset + 4:
            return None
        start = float(parse_number(args[offset + 1]))
        stop = float(parse_number(args[offset + 2]))
        step = abs(float(parse_number(args[offset + 3])))
        if step == 0:
            return None
        return max(1, math.ceil(abs(stop - start) / step) + 1)
    except (ValueError, OverflowError, ArithmeticError):
        return None


def _element_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    declared_passives: dict[SourceLocation, Device] = {}
    reached_passives: set[SourceLocation] = set()
    checked_passives: set[tuple[SourceLocation, str | None]] = set()

    def check_passive(device: Device) -> None:
        element = device.element
        key = (element.location, element.value)
        if key in checked_passives:
            return
        checked_passives.add(key)
        value = _numeric(element.value)
        if value is None:
            findings.append(
                _finding(
                    context,
                    "VAL002",
                    "Unevaluated passive value",
                    Severity.REVIEW,
                    f"{element.name!r} has a value that cannot be statically evaluated",
                    element.location,
                    evidence=element.raw,
                )
            )
        elif value < 0 or (element.kind in {"C", "L"} and value == 0):
            findings.append(
                _finding(
                    context,
                    "VAL001",
                    "Non-physical passive value",
                    Severity.DENY,
                    f"{element.name!r} has non-positive or negative value {element.value!r}",
                    element.location,
                    evidence=element.raw,
                )
            )

    known = {"R", "C", "L", "V", "I", "M", "D", "Q", "X", "E", "G", "F", "H", "B"}
    for device in _all_elements(context.graph):
        element = device.element
        if element.kind == "B":
            findings.append(
                _finding(
                    context,
                    "ELEM002",
                    "Behavioral source",
                    context.policy.rules.behavioral_source,
                    f"behavioral source {element.name!r} contains an unevaluated expression",
                    element.location,
                    evidence=element.raw,
                    remediation=(
                        "Replace it with bounded primitive elements or require human review."
                    ),
                )
            )
        elif element.kind not in known:
            findings.append(
                _finding(
                    context,
                    "ELEM001",
                    "Unknown element family",
                    context.policy.rules.unknown_element,
                    f"element {element.name!r} is outside the recognized primitive set",
                    element.location,
                    evidence=element.raw,
                )
            )
        if element.kind in {"R", "C", "L"}:
            declared_passives[element.location] = device
        # A raw literal remains an artifact-level fact even in a dormant
        # definition. Parameter-dependent voltages, however, require a reached
        # instance's final bindings, never a guessed/default scope environment.
        if element.kind == "V":
            voltage = _numeric(element.value)
            limit = context.policy.electrical.max_abs_source_voltage
            if voltage is not None and voltage.copy_abs() > Decimal(str(limit)):
                findings.append(
                    _finding(
                        context,
                        "VOLT001",
                        "Source voltage exceeds policy",
                        Severity.DENY,
                        f"{element.name!r} has magnitude {voltage.copy_abs()} V",
                        element.location,
                        evidence=element.raw,
                        metadata={"limit_volts": limit},
                    )
                )
    for device in _electrical_elements(context.graph):
        element = device.element
        if element.kind in {"R", "C", "L"}:
            reached_passives.add(element.location)
            check_passive(device)
        if element.kind != "V":
            continue
        voltage = _numeric(element.value)
        configured_limit = context.policy.electrical.max_abs_source_voltage
        if voltage is not None and voltage.copy_abs() > Decimal(str(configured_limit)):
            findings.append(
                _finding(
                    context,
                    "VOLT001",
                    "Source voltage exceeds policy",
                    Severity.DENY,
                    f"{element.name!r} has magnitude {voltage.copy_abs()} V",
                    element.location,
                    evidence=element.raw,
                    metadata={"limit_volts": configured_limit},
                )
            )
        elif voltage is None:
            findings.extend(_dynamic_source_findings(context, device, configured_limit))
    for location, device in declared_passives.items():
        if location not in reached_passives:
            check_passive(device)
    return findings


def _dynamic_source_findings(
    context: CheckContext, device: Device, configured_limit: float
) -> list[Finding]:
    element = device.element
    raw = element.raw
    match = re.search(r"\b(pulse|pwl)\s*\((.*)\)", raw, re.IGNORECASE)
    if match is None:
        return [
            _finding(
                context,
                "VOLT002",
                "Dynamic source voltage requires review",
                Severity.REVIEW,
                f"{element.name!r} has no statically bounded DC voltage",
                element.location,
                evidence=raw,
            )
        ]
    tokens = [item for item in re.split(r"[\s,]+", match.group(2).strip()) if item]
    level_tokens = tokens[:2] if match.group(1).lower() == "pulse" else tokens[1::2]
    levels = [_numeric(token) for token in level_tokens]
    if not levels or any(level is None for level in levels):
        return [
            _finding(
                context,
                "VOLT002",
                "Dynamic source voltage requires review",
                Severity.REVIEW,
                f"{element.name!r} contains voltage levels that cannot be bounded",
                element.location,
                evidence=raw,
            )
        ]
    maximum = max(level.copy_abs() for level in levels if level is not None)
    if maximum <= Decimal(str(configured_limit)):
        return []
    return [
        _finding(
            context,
            "VOLT001",
            "Source voltage exceeds policy",
            Severity.DENY,
            f"{element.name!r} has dynamic magnitude {maximum} V",
            element.location,
            evidence=raw,
            metadata={"limit_volts": configured_limit},
        )
    ]


def _top_nets(context: CheckContext) -> dict[str, Net]:
    return {net.name: net for net in context.graph.nets if net.scope == "top"}


def _port_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    nets = _top_nets(context)
    required = {item.lower() for item in context.policy.electrical.required_ports}
    required.update(context.intended_ports)
    for port in sorted(required):
        if port not in nets:
            findings.append(
                _finding(
                    context,
                    "PORT001",
                    "Required port is absent",
                    Severity.DENY,
                    f"intended top-level port {port!r} does not occur in the circuit",
                    remediation="Connect or remove the port from the declared interface.",
                )
            )
    for port, role in sorted(context.intended_ports.items()):
        net = nets.get(port)
        if net is None or role != "output":
            continue
        passive_only = all(
            endpoint.kind in {"C", "M"} and endpoint.terminal in {"p", "n", "g"}
            for endpoint in net.endpoints
        )
        if passive_only:
            findings.append(
                _finding(
                    context,
                    "PORT002",
                    "Output has no evident driver",
                    Severity.REVIEW,
                    f"declared output {port!r} is connected only to capacitive or gate terminals",
                    remediation="Verify the output driver or correct the manifest role.",
                    metadata={"endpoints": len(net.endpoints)},
                )
            )
    return findings


def _connectivity_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    global_names = {"0"}
    global_names.update(name.lower() for name in context.policy.electrical.ground_nets)
    global_names.update(name.lower() for name in context.policy.electrical.power_nets)
    global_names.update(context.intended_ports)
    for net in context.graph.nets:
        if net.is_port or net.name in global_names:
            continue
        if len(net.endpoints) == 1:
            findings.append(
                _finding(
                    context,
                    "NET001",
                    "Dangling internal net",
                    Severity.REVIEW,
                    f"{net.scope} net {net.display_name!r} has only one terminal",
                    remediation="Connect the net, mark it as an intended port, or remove it.",
                    metadata={"device": net.endpoints[0].device},
                )
            )
        if net.endpoints and all(
            (endpoint.kind == "M" and endpoint.terminal == "g") or endpoint.kind == "C"
            for endpoint in net.endpoints
        ):
            findings.append(
                _finding(
                    context,
                    "NET002",
                    "Floating MOS gate",
                    Severity.DENY,
                    f"{net.scope} net {net.display_name!r} has no evident DC drive",
                    remediation="Provide a DC path or declare and drive the intended input port.",
                    metadata={"endpoints": len(net.endpoints)},
                )
            )
    return findings


def _source_conflicts(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    groups: dict[tuple[str, str, str], list[Device]] = defaultdict(list)
    for device in _electrical_elements(context.graph):
        element = device.element
        if element.kind == "V" and len(element.nodes) >= 2:
            p, n = (node.lower() for node in element.nodes[:2])
            node_first, node_second = sorted((p, n))
            groups[("expanded", node_first, node_second)].append(device)
    for (_, _, _), sources in sorted(groups.items()):
        values: set[Decimal] = set()
        for voltage_source in sources:
            value = _numeric(voltage_source.element.value)
            if value is None:
                continue
            p, n = (node.lower() for node in voltage_source.element.nodes[:2])
            values.add(value if p <= n else value.copy_negate())
        if len(values) > 1:
            first_source = min(sources, key=lambda item: item.element.name.lower())
            findings.append(
                _finding(
                    context,
                    "SRC001",
                    "Conflicting ideal voltage sources",
                    Severity.DENY,
                    "parallel ideal voltage sources impose different DC values",
                    first_source.element.location,
                    evidence="; ".join(item.element.raw for item in sources),
                    remediation="Remove the conflict or add an explicit non-zero source impedance.",
                    metadata={"sources": [item.element.name for item in sources]},
                )
            )
    return findings


def _static_literal_voltage(device: Device) -> Decimal | None:
    arguments = device.element.arguments
    if device.element.parameters:
        return None
    token: str | None = None
    if len(arguments) == 1:
        token = arguments[0]
    elif len(arguments) == 2 and arguments[0].casefold() == "dc":
        token = arguments[1]
    if token is None or _PURE_SPICE_NUMBER.fullmatch(token) is None:
        return None
    return _numeric(token)


def _configured_net(node: str, names: set[str]) -> bool:
    return node in names


def _bounded_rail_name(value: str) -> str:
    if len(value) <= _MAX_RAIL_WITNESS_NAME:
        return value
    return value[: _MAX_RAIL_WITNESS_NAME - 3] + "..."


def _rail_path_evidence(
    start: str, goal: str, ties: list[_RailTie]
) -> tuple[int, str, tuple[str, ...], bool, SourceLocation | None]:
    adjacency: dict[str, list[tuple[str, _RailTie]]] = defaultdict(list)
    for tie in ties:
        adjacency[tie.first].append((tie.second, tie))
        adjacency[tie.second].append((tie.first, tie))
    previous: dict[str, tuple[str, _RailTie] | None] = {start: None}
    pending = deque([start])
    while pending and goal not in previous:
        node = pending.popleft()
        for neighbour, tie in adjacency[node]:
            if neighbour not in previous:
                previous[neighbour] = (node, tie)
                pending.append(neighbour)
    if goal not in previous:  # pragma: no cover - guarded by the union proof
        raise RuntimeError("internal rail-short proof is disconnected")

    digest = sha256()
    count = 0
    shown: list[str] = []
    location: SourceLocation | None = None
    cursor = goal
    while cursor != start:
        step = previous[cursor]
        if step is None:  # pragma: no cover - start is the only root marker
            raise RuntimeError("internal rail-short proof is incomplete")
        prior, tie = step
        name = tie.device.qualified_name
        family = tie.device.element.kind
        for value in (cursor, prior, name, family):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        if len(shown) < _MAX_RAIL_WITNESS_DEVICES:
            shown.append(_bounded_rail_name(name))
        candidate = tie.device.element.location
        if location is None or (candidate.path, candidate.line, candidate.column) < (
            location.path,
            location.line,
            location.column,
        ):
            location = candidate
        count += 1
        cursor = prior
    return count, digest.hexdigest(), tuple(shown), count > len(shown), location


def _rail_short_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    grounds = {name.lower() for name in context.policy.electrical.ground_nets} | {"0"}
    powers = {name.lower() for name in context.policy.electrical.power_nets}
    union = _RailUnion()
    ties: list[_RailTie] = []
    legacy_direct: list[_RailTie] = []
    for device in _electrical_elements(context.graph):
        element = device.element
        if len(element.nodes) < 2:
            continue
        value: Decimal | None = None
        if element.kind == "R":
            value = _numeric(element.value)
            proven_tie = value == 0 and not element.arguments and not element.parameters
        elif element.kind == "L":
            value = _numeric(element.value)
            proven_tie = (
                value is not None and value > 0 and not element.arguments and not element.parameters
            )
        elif element.kind == "V":
            value = _static_literal_voltage(device)
            proven_tie = value == 0
        else:
            proven_tie = False
        if not proven_tie:
            continue
        first, second = (node.lower() for node in element.nodes[:2])
        if first == second:
            continue
        tie = _RailTie(first, second, device)
        ties.append(tie)
        union.union(first, second)
        if element.kind == "R" and (
            (_configured_net(first, grounds) and _configured_net(second, powers))
            or (_configured_net(second, grounds) and _configured_net(first, powers))
        ):
            legacy_direct.append(tie)
            findings.append(
                _finding(
                    context,
                    "RAIL001",
                    "Zero-ohm power-to-ground path",
                    Severity.DENY,
                    f"{element.name!r} directly connects a configured power rail to ground",
                    element.location,
                    evidence=element.raw,
                    remediation="Remove the short or correct the configured rail names.",
                )
            )

    component_nodes: dict[str, set[str]] = defaultdict(set)
    component_ties: dict[str, list[_RailTie]] = defaultdict(list)
    for tie in ties:
        root = union.find(tie.first)
        component_nodes[root].update((tie.first, tie.second))
        component_ties[root].append(tie)
    legacy_components = {union.find(tie.first) for tie in legacy_direct}
    for root, nodes in sorted(component_nodes.items()):
        if root in legacy_components:
            continue
        ground_nodes = sorted(node for node in nodes if _configured_net(node, grounds))
        power_nodes = sorted(node for node in nodes if _configured_net(node, powers))
        if not ground_nodes or not power_nodes:
            continue
        power, ground = power_nodes[0], ground_nodes[0]
        count, proof, witness, truncated, location = _rail_path_evidence(
            power, ground, component_ties[root]
        )
        shown_power, shown_ground = _bounded_rail_name(power), _bounded_rail_name(ground)
        findings.append(
            _finding(
                context,
                "RAIL002",
                "Declared DC rail-short path",
                Severity.DENY,
                f"configured power {shown_power!r} is tied to ground {shown_ground!r} "
                f"by {count} declared DC short element(s) (proof {proof[:12]})",
                location,
                evidence=" <- ".join(witness) + (" <- ..." if truncated else ""),
                remediation=(
                    "Break the declared DC short path or correct the configured rail names."
                ),
                metadata={
                    "component_edges": len(component_ties[root]),
                    "component_nodes": len(nodes),
                    "ground": shown_ground,
                    "power": shown_power,
                    "proof_direction": "ground-to-power",
                    "proof_profile": "static-netlist-short-intent-v1",
                    "proof_elements": count,
                    "proof_sha256": proof,
                    "witness_devices": witness,
                    "witness_truncated": truncated,
                },
            )
        )
    return findings


def _solvability_findings(context: CheckContext) -> list[Finding]:
    """Refuse the operating points a simulator would refuse.

    These are the runs a pre-simulation gate exists to save: the netlist parses,
    describes a plausible circuit, and then makes the first DC solve fail with a
    singular matrix.
    """

    findings: list[Finding] = []
    elements = [
        (device.qualified_name, device.element) for device in _electrical_elements(context.graph)
    ]
    if not elements:
        return findings

    grounds = context.policy.electrical.ground_nets
    if not has_ground(elements, grounds):
        # A deck with no ground at all is a fragment or a naming mismatch, not a
        # circuit with one broken connection, so it earns one finding rather
        # than one for every node it contains.
        findings.append(
            _finding(
                context,
                "SOLVE001",
                "No ground reference",
                Severity.REVIEW,
                "no element connects to any configured ground net",
                remediation=("Reference node 0, or configure the ground net names this deck uses."),
                metadata={"ground_nets": list(grounds)},
            )
        )
        return findings

    for island in floating_islands(elements, grounds):
        findings.append(
            _finding(
                context,
                "SOLVE002",
                "No DC path to ground",
                Severity.DENY,
                f"{len(island.nodes)} node(s) have no conducting path to ground: {island.summary}",
                evidence=", ".join(island.devices[:MAX_REPORTED_NODES]),
                remediation=(
                    "Add a resistive or source path to ground. A capacitor and an ideal "
                    "current source do not provide one."
                ),
                metadata={"nodes": list(island.nodes), "devices": list(island.devices)},
            )
        )

    for loop in voltage_source_loops(elements):
        findings.append(
            _finding(
                context,
                "SOLVE003",
                "Ideal voltage source loop",
                Severity.DENY,
                f"{len(loop.devices)} ideal voltage source(s) form a loop",
                evidence=" -> ".join(loop.nodes),
                remediation=("Break the loop, or give one source an explicit series impedance."),
                metadata={"sources": list(loop.devices), "nodes": list(loop.nodes)},
            )
        )
    return findings


def run_checks(context: CheckContext) -> tuple[Finding, ...]:
    """Run every built-in check and return a stable, de-duplicated sequence."""

    findings: list[Finding] = []
    for rule in (
        _load_findings,
        _graph_findings,
        _directive_findings,
        _analysis_findings,
        _element_findings,
        _port_findings,
        _connectivity_findings,
        _source_conflicts,
        _rail_short_findings,
        _solvability_findings,
    ):
        findings.extend(rule(context))
    unique = {finding.finding_id: finding for finding in findings}
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                -item.severity.rank,
                item.location.path if item.location else "",
                item.location.line if item.location else 0,
                item.code,
                item.message,
            ),
        )
    )
