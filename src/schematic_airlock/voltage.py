"""Conservative DC voltage-envelope checks over a confined expanded netlist.

This is not a nonlinear operating-point solver. Only ideal independent DC
voltage sources, literal zero-ohm resistors and explicit envelope assumptions
impose voltage constraints. Other devices never become invented voltage ties.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from schematic_airlock._version import __version__
from schematic_airlock.bundle import ArtifactBundle, BundleSource, MemoryBundle
from schematic_airlock.circuit_graph import Device, build_circuit_graph
from schematic_airlock.domain import FileDigest, SourceLocation
from schematic_airlock.include_graph import load_include_graph
from schematic_airlock.voltage_constraints import (
    InconsistentVoltages,
    VoltageBudgetExceeded,
    VoltageConstraint,
    VoltageConstraintError,
    VoltageInterval,
    VoltageSystem,
    _name,
    volts,
)
from schematic_airlock.voltage_rules import (
    DIODE_PAIRS,
    MOS_PAIRS,
    VoltageRules,
    load_voltage_rules,
    voltage_rules_from_mapping,
)

_LITERAL = re.compile(
    r"([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?)([a-z]*)", re.IGNORECASE
)
_PREFIX = {"t": 12, "g": 9, "meg": 6, "k": 3, "m": -3, "u": -6, "n": -9, "p": -12, "f": -15}


@dataclass(frozen=True, slots=True)
class VoltageCheck:
    name: str
    positive: str
    negative: str
    observed: VoltageInterval
    allowed: VoltageInterval
    status: str
    location: SourceLocation | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "positive": self.positive,
            "negative": self.negative,
            "observed": self.observed.as_dict(),
            "allowed": self.allowed.as_dict(),
            "status": self.status,
            "location": self.location.as_dict() if self.location else None,
        }


@dataclass(frozen=True, slots=True)
class VoltageReport:
    status: str
    root: str
    entry: str
    bundle_sha256: str
    rules_sha256: str
    files: tuple[FileDigest, ...]
    checks: tuple[VoltageCheck, ...]
    notes: tuple[str, ...]
    assumptions: tuple[str, ...]
    constraints: int
    edge_visits: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "org.schematic-airlock.voltage-report",
            "version": 1,
            "tool_version": __version__,
            "mode": "dc-envelope",
            "status": self.status,
            "root": self.root,
            "entry": self.entry,
            "bundle_sha256": self.bundle_sha256,
            "rules_sha256": self.rules_sha256,
            "files": [item.as_dict() for item in self.files],
            "checks": [item.as_dict() for item in self.checks],
            "notes": list(self.notes),
            "assumptions": list(self.assumptions),
            "constraints": self.constraints,
            "edge_visits": self.edge_visits,
        }


def _literal(text: str, unit: str) -> Fraction | None:
    if len(text) > 128:
        return None
    match = _LITERAL.fullmatch(text)
    if match is None:
        return None
    suffix = match[2].casefold()
    if suffix.endswith(unit):
        suffix = suffix[: -len(unit)]
    if suffix and suffix not in _PREFIX:
        return None
    try:
        value = volts(match[1])
        exponent = _PREFIX.get(suffix, 0)
        return value * (Fraction(10**exponent) if exponent >= 0 else Fraction(1, 10**-exponent))
    except VoltageConstraintError:
        return None


def _source(device: Device) -> Fraction | None:
    arguments = device.element.arguments
    if len(arguments) == 1:
        return _literal(arguments[0], "v")
    if len(arguments) == 2 and arguments[0].casefold() == "dc":
        return _literal(arguments[1], "v")
    return None


def _resistance(device: Device) -> Fraction | None:
    # The expanded numeric value may come from a rounded expression. Inspect
    # only the original literal token, never turn underflow into an exact tie.
    from schematic_airlock.lex import LogicalLine, tokenize

    element = device.element
    tokens = tokenize(
        LogicalLine(element.location.path, element.location.line, element.raw, element.raw)
    )
    return _literal(tokens[3].value, "ohm") if len(tokens) >= 4 else None


def _assessment(observed: VoltageInterval, allowed: VoltageInterval) -> str:
    low, high = observed.lower, observed.upper
    minimum, maximum = allowed.lower, allowed.upper
    if minimum is None or maximum is None:
        raise VoltageConstraintError("voltage rating must have finite limits")
    if (high is not None and high < minimum) or (low is not None and low > maximum):
        return "violation"
    if low is None or high is None:
        return "indeterminate"
    if low < minimum or high > maximum:
        return "possible-violation"
    return "pass"


def _envelope_source_loop(constraints: list[VoltageConstraint]) -> bool:
    """Independent ideal-source sweeps around a loop need a correlation model."""

    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    for variable in (False, True):
        for item in constraints:
            if (item.interval.lower != item.interval.upper) != variable:
                continue
            positive, negative = find(item.positive), find(item.negative)
            if variable and positive == negative:
                return True
            parent[positive] = negative
    return False


def _validated_rules(rules: VoltageRules) -> VoltageRules:
    if not isinstance(rules, VoltageRules):
        raise VoltageConstraintError("rules must be a validated VoltageRules object")
    try:
        checked = voltage_rules_from_mapping(rules.as_dict())
    except (AttributeError, TypeError, ValueError) as exc:
        raise VoltageConstraintError(f"invalid voltage rules: {exc}") from exc
    if checked != rules:
        raise VoltageConstraintError(
            "directly constructed voltage rules are noncanonical or duplicated"
        )
    return checked


def _check_bundle(bundle: BundleSource, rules: VoltageRules) -> VoltageReport:
    rules = _validated_rules(rules)
    includes = load_include_graph(bundle)
    try:
        graph = build_circuit_graph(includes)
    except RecursionError as exc:
        raise VoltageBudgetExceeded(
            "netlist hierarchy exceeds the adapter's recursion budget"
        ) from exc
    notes = [f"{issue.code}: {issue.message}" for issue in includes.issues]
    notes.extend(
        f"{issue.code}: {issue.message}" for issue in graph.issues if issue.code != "GRAPH006"
    )
    assumptions: list[str] = []
    constraints: list[VoltageConstraint] = []
    nominal_constraints: list[VoltageConstraint] = []
    checks: list[VoltageCheck] = []
    edge_visits = 0

    def report(status: str) -> VoltageReport:
        return VoltageReport(
            status,
            bundle.root_display,
            bundle.entry,
            bundle.bundle_hash(),
            rules.fingerprint(),
            bundle.digests(),
            tuple(checks),
            tuple(sorted(set(notes))),
            tuple(sorted(assumptions)),
            len(constraints),
            edge_visits,
        )

    if includes.issues or any(issue.code not in {"GRAPH006", "GRAPH008"} for issue in graph.issues):
        return report("indeterminate")
    if graph.expanded_instances > 100_000:
        notes.append("hierarchical expansion exceeds the 100000-device adapter budget")
        return report("indeterminate")
    # The graph's hierarchy separator must not collide with literal flat names.
    raw_names = [
        name for device in graph.devices for name in (device.element.name, *device.element.nodes)
    ]
    raw_names.extend(cell.name for cell in graph.subcircuits)
    raw_names.extend(port for cell in graph.subcircuits for port in cell.ports)
    raw_names.extend(device.element.model for device in graph.devices if device.element.model)
    raw_names.extend(
        directive.arguments[0]
        for deck in includes.decks
        for directive in (
            *deck.directives,
            *(item for cell in deck.subcircuits for item in cell.directives),
        )
        if directive.name == "model" and directive.arguments
    )
    if any(":" in name or "/" in name for name in raw_names):
        notes.append(
            "literal node/device/subcircuit names containing ':' or '/' are ambiguous "
            "in expanded voltage queries"
        )
        return report("indeterminate")
    folded: dict[str, str] = {}
    for name in raw_names:
        try:
            _name(name)
        except VoltageConstraintError:
            notes.append(
                "netlist identifiers must be bounded NFC tokens without "
                "display controls or whitespace"
            )
            return report("indeterminate")
        key = name.casefold()
        if unicodedata.normalize("NFC", key) != key:
            notes.append("case folding produces a noncanonical netlist identifier")
            return report("indeterminate")
        if key in folded and folded[key] != name.lower():
            notes.append("Unicode case folding would merge distinct parser identifiers")
            return report("indeterminate")
        folded[key] = name.lower()
    for deck in includes.decks:
        directives = [
            *deck.directives,
            *(directive for cell in deck.subcircuits for directive in cell.directives),
        ]
        for directive in directives:
            if directive.name not in {"param", "model", "end", "include", "op", "title"}:
                notes.append(
                    f"{directive.location.path}:{directive.location.line}: "
                    f".{directive.name} is not evaluated by DC-envelope checking"
                )
    devices = [device for device in graph.expanded_devices if device.element.kind != "X"]
    nodes = {"0", *(node.casefold() for device in devices for node in device.element.nodes)}
    source_envelopes = dict(rules.source_envelopes)
    seen_sources: set[str] = set()
    for device in devices:
        element = device.element
        name = device.qualified_name.casefold()
        if element.kind == "V":
            literal = _source(device)
            if literal is not None:
                nominal_constraints.append(
                    VoltageConstraint(
                        element.nodes[0].casefold(),
                        element.nodes[1].casefold(),
                        VoltageInterval(literal, literal),
                        f"nominal:{name}",
                    )
                )
            envelope = source_envelopes.get(name)
            if envelope is not None:
                seen_sources.add(name)
                if (
                    literal is not None
                    and _assessment(VoltageInterval(literal, literal), envelope) != "pass"
                ):
                    raise VoltageConstraintError(
                        f"{name}: source envelope excludes its literal DC voltage"
                    )
                assumptions.append(f"source:{name}")
            elif literal is not None:
                envelope = VoltageInterval(literal, literal)
            else:
                notes.append(
                    f"{name}: source has no literal DC constraint or explicit source envelope"
                )
            if envelope is not None:
                constraints.append(
                    VoltageConstraint(
                        element.nodes[0].casefold(),
                        element.nodes[1].casefold(),
                        envelope,
                        f"device:{name}",
                    )
                )
        elif element.kind == "R":
            resistance = _resistance(device)
            if resistance is None or resistance < 0:
                notes.append(
                    f"{name}: resistance is not a nonnegative exact literal; "
                    "voltage behavior is unassessed"
                )
            elif resistance == 0:
                constraints.append(
                    VoltageConstraint(
                        element.nodes[0].casefold(),
                        element.nodes[1].casefold(),
                        VoltageInterval(Fraction(0), Fraction(0)),
                        f"device:{name}",
                    )
                )
                nominal_constraints.append(constraints[-1])
        elif element.kind not in {"R", "C", "I", "M", "D"}:
            notes.append(f"{name}: {element.kind} device voltage behavior is not modeled")
    if set(source_envelopes) - seen_sources:
        raise VoltageConstraintError("source_envelopes names an absent/non-voltage-source device")
    if _envelope_source_loop(constraints):
        notes.append(
            "variable ideal sources form a loop: compatibility of all independent "
            "envelope combinations is not established"
        )
    for node, envelope in rules.net_envelopes:
        if node not in nodes:
            raise VoltageConstraintError(f"net_envelopes references unknown expanded node {node!r}")
        constraints.append(VoltageConstraint(node, "0", envelope, f"net:{node}"))
        assumptions.append(f"net:{node}")
    planned: list[tuple[str, str, str, VoltageInterval, SourceLocation | None]] = []
    for expected in rules.expected:
        if expected.positive not in nodes or expected.negative not in nodes:
            raise VoltageConstraintError(
                f"{expected.name}: expected voltage references unknown expanded node"
            )
        planned.append(
            (
                f"expected:{expected.name}",
                expected.positive,
                expected.negative,
                expected.interval,
                None,
            )
        )
    models = {model.model: model for model in rules.models}
    used_models: set[str] = set()
    for device in devices:
        element = device.element
        if element.kind not in {"M", "D"}:
            continue
        rating = models.get((element.model or "").casefold())
        if rating is None:
            notes.append(
                f"{device.qualified_name}: no explicit {element.kind} voltage model rating"
            )
            continue
        if rating.kind != element.kind:
            raise VoltageConstraintError(
                f"{device.qualified_name}: voltage model kind does not match device"
            )
        used_models.add(rating.model)
        pairs = MOS_PAIRS if element.kind == "M" else DIODE_PAIRS
        for pair, interval in rating.pairs:
            positive_pin, negative_pin = pairs[pair]
            planned.append(
                (
                    f"device:{device.qualified_name.casefold()}:{pair}",
                    element.nodes[positive_pin].casefold(),
                    element.nodes[negative_pin].casefold(),
                    interval,
                    element.location,
                )
            )
    if set(models) - used_models:
        notes.append(
            "unused voltage model ratings: " + ", ".join(sorted(set(models) - used_models))
        )
    if not planned:
        notes.append("no expected voltages or matched device voltage ratings were checked")
    try:
        # A scenario envelope must never erase a contradiction already present
        # in the literal nominal netlist. These are all point constraints.
        VoltageSystem(sorted(nodes), nominal_constraints, limits=rules.limits)
        system = VoltageSystem(sorted(nodes), constraints, limits=rules.limits)
        for name, positive, negative, allowed, location in sorted(
            planned, key=lambda item: item[0]
        ):
            observed = system.difference(positive, negative)
            checks.append(
                VoltageCheck(
                    name,
                    positive,
                    negative,
                    observed,
                    allowed,
                    _assessment(observed, allowed),
                    location,
                )
            )
        edge_visits = system.edge_visits
    except InconsistentVoltages as exc:
        checks.clear()
        notes.append(str(exc))
        return report("inconsistent")
    except VoltageBudgetExceeded as exc:
        checks.clear()
        notes.append(str(exc))
        return report("indeterminate")
    statuses = {check.status for check in checks}
    if "violation" in statuses:
        return report("violation")
    if "possible-violation" in statuses:
        return report("possible-violation")
    return report("indeterminate" if notes or "indeterminate" in statuses else "pass")


def check_voltages_path(
    path: str | Path, *, rules: VoltageRules | str | Path, entry: str | None = None
) -> VoltageReport:
    """Check a local netlist/bundle without executing a simulator."""

    selected = rules if isinstance(rules, VoltageRules) else load_voltage_rules(rules)
    return _check_bundle(ArtifactBundle.open(path, entry=entry), selected)


def check_voltages_text(
    text: str, *, rules: VoltageRules, virtual_name: str = "input.sp"
) -> VoltageReport:
    return _check_bundle(MemoryBundle(text, virtual_name), rules)


def voltage_report_json(report: VoltageReport, *, pretty: bool = False) -> str:
    return (
        json.dumps(report.as_dict(), sort_keys=True, indent=2 if pretty else None, allow_nan=False)
        + "\n"
    )


def voltage_report_text(report: VoltageReport) -> str:
    lines = [
        f"DC voltage-envelope result: {report.status}",
        f"Bundle: {report.bundle_sha256}",
        f"Rules: {report.rules_sha256}",
    ]
    for check in report.checks:
        lines.append(
            f"[{check.status}] {check.name}: V({check.positive})-V({check.negative}) "
            f"in [{check.observed.lower}, {check.observed.upper}] V; "
            f"allowed [{check.allowed.lower}, {check.allowed.upper}] V"
        )
    lines.extend(f"NOTE: {note}" for note in report.notes)
    lines.extend(f"ASSUMPTION: {name}" for name in report.assumptions)
    # Even parser diagnostics and source filenames may contain display controls.
    safe_lines = [
        "".join(
            f"\\u{ord(char):04x}"
            if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            else char
            for char in line
        )
        for line in lines
    ]
    return "\n".join(safe_lines) + "\n"
