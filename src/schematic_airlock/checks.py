"""Deterministic structural and electrical safety checks.

The checks in this module intentionally answer questions that can be proven
from a bounded netlist parse.  They do not claim to replace simulation or a
foundry design-rule check.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal

from schematic_airlock.bundle import BundleSource
from schematic_airlock.circuit_graph import CircuitGraph, Device, Net
from schematic_airlock.domain import Finding, Severity, SourceLocation
from schematic_airlock.include_graph import IncludeGraph
from schematic_airlock.parse import Directive
from schematic_airlock.policy import AuditPolicy
from schematic_airlock.units import evaluate_expression, parameter_assignments, parse_number


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


def _scope_parameters(context: CheckContext) -> dict[str, dict[str, Decimal]]:
    def safe_assignments(
        tokens: Iterable[str], inherited: Mapping[str, Decimal]
    ) -> dict[str, Decimal]:
        values = dict(inherited)
        for token in tokens:
            try:
                values = parameter_assignments([token], values)
            except ValueError:
                # Keep the successfully evaluated part of this scope. Any source
                # that depends on the failed name remains unevaluated and REVIEWed.
                continue
        return values

    result: dict[str, dict[str, Decimal]] = {"top": {}}
    for directive in context.includes.parameter_directives:
        result["top"] = safe_assignments(directive.arguments, result["top"])
    for deck in context.includes.decks:
        for subcircuit in deck.subcircuits:
            scope = f"subckt:{subcircuit.name.lower()}"
            values = safe_assignments(
                (f"{name}={value}" for name, value in subcircuit.parameters),
                result["top"],
            )
            assignments = [
                arg
                for item in subcircuit.directives
                if item.name == "param"
                for arg in item.arguments
            ]
            result[scope] = safe_assignments(assignments, values)
    return result


def _element_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    parameters = _scope_parameters(context)
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
        if element.kind == "V":
            voltage = _numeric(element.value, parameters.get(device.scope))
            configured_limit = context.policy.electrical.max_abs_source_voltage
            if voltage is not None and abs(voltage) > Decimal(str(configured_limit)):
                findings.append(
                    _finding(
                        context,
                        "VOLT001",
                        "Source voltage exceeds policy",
                        Severity.DENY,
                        f"{element.name!r} has magnitude {abs(voltage)} V",
                        element.location,
                        evidence=element.raw,
                        metadata={"limit_volts": configured_limit},
                    )
                )
            elif voltage is None:
                findings.extend(_dynamic_source_findings(context, device, configured_limit))
    for device in _electrical_elements(context.graph):
        element = device.element
        if element.kind != "V":
            continue
        voltage = _numeric(element.value)
        configured_limit = context.policy.electrical.max_abs_source_voltage
        if voltage is not None and abs(voltage) > Decimal(str(configured_limit)):
            findings.append(
                _finding(
                    context,
                    "VOLT001",
                    "Source voltage exceeds policy",
                    Severity.DENY,
                    f"{element.name!r} has magnitude {abs(voltage)} V",
                    element.location,
                    evidence=element.raw,
                    metadata={"limit_volts": configured_limit},
                )
            )
        elif voltage is None:
            findings.extend(_dynamic_source_findings(context, device, configured_limit))
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
    maximum = max(abs(level) for level in levels if level is not None)
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
            values.add(value if p <= n else -value)
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


def _rail_short_findings(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    grounds = {name.lower() for name in context.policy.electrical.ground_nets} | {"0"}
    powers = {name.lower() for name in context.policy.electrical.power_nets}
    for device in _electrical_elements(context.graph):
        element = device.element
        value = _numeric(element.value)
        if element.kind != "R" or value != 0 or len(element.nodes) < 2:
            continue
        nodes = {node.lower() for node in element.nodes[:2]}
        if nodes & grounds and nodes & powers:
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
