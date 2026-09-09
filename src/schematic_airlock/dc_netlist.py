"""Confined, fail-closed netlist adapter for the exact linear R/V/I DC kernel."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from schematic_airlock._version import __version__
from schematic_airlock.bundle import ArtifactBundle, BundleSource, MemoryBundle
from schematic_airlock.circuit_graph import Device, build_circuit_graph
from schematic_airlock.domain import FileDigest, SourceLocation
from schematic_airlock.include_graph import load_include_graph
from schematic_airlock.lex import LogicalLine, logical_lines, tokenize
from schematic_airlock.linear_dc import (
    DEFAULT_DC_LIMITS,
    DCBranch,
    DCBudgetExceeded,
    DCInputError,
    DCLimits,
    DCSolution,
    InconsistentDC,
    SingularDC,
    _rational,
    solve_linear_dc,
)
from schematic_airlock.parse import Deck
from schematic_airlock.voltage import _literal

_RAW_NAME = re.compile(r"[A-Za-z0-9_.$+-]{1,256}\Z")
_MAX_TEXT_BYTES = 2_000_000
_MAX_REPORT_BYTES = 64 * 1024 * 1024


def _metadata_name(value: str) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 1024
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(c) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for c in value)
    ):
        raise DCInputError("DC source paths must be bounded NFC text without display controls")


@dataclass(frozen=True, slots=True)
class DCNetlistReport:
    status: str
    root: str
    entry: str
    bundle_sha256: str
    files: tuple[FileDigest, ...]
    solution: DCSolution | None
    locations: tuple[tuple[str, SourceLocation], ...]
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        _preflight_report(self)
        solution = self.solution
        currents = dict(solution.currents) if solution else {}
        powers = dict(solution.powers) if solution else {}
        return {
            "schema": "org.schematic-airlock.linear-dc-report",
            "version": 1,
            "profile": "linear-rvi-v1",
            "tool_version": __version__,
            "status": self.status,
            "entry": self.entry,
            "bundle_sha256": self.bundle_sha256,
            "files": [item.as_dict() for item in self.files],
            "network_id": solution.network_id if solution else None,
            "nodes": {name: str(value) for name, value in solution.voltages} if solution else {},
            "branches": [
                {
                    "label": label,
                    "current_amperes": str(currents[label]),
                    "absorbed_watts": str(powers[label]),
                    "location": location.as_dict(),
                }
                for label, location in self.locations
            ]
            if solution
            else [],
            "notes": list(self.notes),
            "work": {
                "unknowns": solution.unknowns,
                "operations": solution.operations,
                "peak_nonzeros": solution.peak_nonzeros,
            }
            if solution
            else None,
        }


def _preflight_report(report: DCNetlistReport) -> None:
    """Conservative serialized-size bound before allocating parallel wire trees."""
    size = 4096

    def charge(value: str, overhead: int = 128) -> None:
        nonlocal size
        size += len(json.dumps(value, ensure_ascii=True)) + overhead
        if size > _MAX_REPORT_BYTES:
            raise DCBudgetExceeded("DC report exceeds its conservative 64-MiB output budget")

    charge(report.entry)
    for item in report.files:
        charge(item.path, 512)
    for note in report.notes:
        charge(note)
    if report.solution:
        for name, value in report.solution.voltages:
            charge(name)
            charge(str(_rational(value)))
        for name, value in report.solution.currents:
            charge(name)
            charge(str(_rational(value)))
        for name, value in report.solution.powers:
            charge(name)
            charge(str(_rational(value)))
        for label, location in report.locations:
            charge(label, 512)
            charge(location.path)


def _deck_profile(deck: Deck, bundle: BundleSource) -> None:
    # General audit parsing intentionally retains unknown directives and source
    # following .end. A numeric solver must not silently assign them semantics.
    ended = False
    for line in logical_lines(bundle.read_text(deck.path), deck.path):
        values = [token.value for token in tokenize(line)]
        if not values:
            continue
        if ended:
            raise DCInputError(f"{deck.path}: executable content follows .end")
        command = values[0].lower()
        # The shared tokenizer removes quotes. Examine the comment-stripped
        # source before those expressions/names can become bare electrical
        # literals. Quoting remains valid only for title text and include paths.
        if line.text.split(maxsplit=1)[0].lower() != command or (
            command not in {".title", ".include"}
            and any(quote in line.text for quote in ("'", '"'))
        ):
            raise DCInputError("quoted electrical tokens are outside the literal DC profile")
        if command == ".end":
            if deck.path != bundle.entry or len(values) != 1:
                raise DCInputError(".end must be a bare final card in the entry file only")
            ended = True
        elif command == ".ends" and len(values) > 2:
            raise DCInputError("unexpected .ends arguments")
        elif command == ".subckt" and any(
            "=" in value or value.lower() == "params:" for value in values
        ):
            raise DCInputError(
                "parameterized subcircuits are outside the linear DC literal profile"
            )
    for cell in deck.subcircuits:
        if cell.parameters or cell.directives:
            raise DCInputError("subcircuit parameters/directives are outside the linear DC profile")
        if not all(_RAW_NAME.fullmatch(name) for name in (cell.name, *cell.ports)):
            raise DCInputError("ambiguous or unsupported subcircuit names")
    for directive in deck.directives:
        if directive.name in {"op", "end"} and not directive.arguments:
            continue
        if directive.name == "title":
            continue
        if directive.name == "include" and len(directive.arguments) == 1:
            continue
        raise DCInputError(f".{directive.name}: unassessed directive in linear DC profile")


def _validate_device(device: Device) -> None:
    element = device.element
    if element.kind not in {"R", "V", "I", "X"}:
        raise DCInputError(
            f"{device.qualified_name}: {element.kind} is outside the linear DC profile"
        )
    if element.parameters:
        raise DCInputError(f"{device.qualified_name}: parameter overrides require a separate model")
    if not all(_RAW_NAME.fullmatch(name) for name in (element.name, *element.nodes)):
        raise DCInputError("raw DC names must be ASCII tokens without hierarchy separators")
    if element.kind == "X" and (not element.model or not _RAW_NAME.fullmatch(element.model)):
        raise DCInputError("ambiguous subcircuit model identity")
    if element.kind == "X":
        tokens = tokenize(
            LogicalLine(element.location.path, element.location.line, element.raw, element.raw)
        )
        if len(tokens) != len(element.nodes) + 2:
            raise DCInputError("subcircuit call contains unassessed trailing arguments")


def _branch(device: Device) -> DCBranch:
    element = device.element
    # Re-tokenize the original source so rounded parameter expansion can never
    # turn an expression into a literal or change the exact rational value.
    tokens = [
        token.value
        for token in tokenize(
            LogicalLine(element.location.path, element.location.line, element.raw, element.raw)
        )
    ]
    tail = tokens[3:]
    if element.kind in {"V", "I"} and tail and tail[0].lower() == "dc":
        tail = tail[1:]
    if len(tail) != 1:
        raise DCInputError(f"{device.qualified_name}: exactly one literal DC value is required")
    unit = {"R": "ohm", "V": "v", "I": "a"}[element.kind]
    value = _literal(tail[0], unit)
    if value is None:
        raise DCInputError(f"{device.qualified_name}: unsupported or out-of-range literal")
    return DCBranch(
        device.qualified_name.lower(),
        {"R": "resistor", "V": "voltage", "I": "current"}[element.kind],
        element.nodes[0].lower(),
        element.nodes[1].lower(),
        value,
    )


def _solve_bundle(bundle: BundleSource, limits: DCLimits) -> DCNetlistReport:
    _metadata_name(bundle.entry)
    solution = None
    locations: tuple[tuple[str, SourceLocation], ...] = ()
    notes: tuple[str, ...] = ()
    try:
        includes = load_include_graph(bundle)
        if includes.issues:
            raise DCInputError(
                "; ".join(f"{item.code}: {item.message}" for item in includes.issues)
            )
        for deck in includes.decks:
            _deck_profile(deck, bundle)
        graph = build_circuit_graph(
            includes, max_expanded_instances=min(limits.max_branches, 100_000)
        )
        if graph.expanded_instances > min(limits.max_branches, 100_000):
            raise DCBudgetExceeded("linear DC netlist expansion budget exhausted")
        failures = [item for item in graph.issues if item.code != "GRAPH006"]
        if failures:
            raise DCInputError("; ".join(f"{item.code}: {item.message}" for item in failures))
        for device in graph.devices:
            _validate_device(device)
        primitives = tuple(
            device for device in graph.expanded_devices if device.element.kind != "X"
        )
        if not primitives:
            raise DCInputError("entry contains no reached primitive branches")
        branches = tuple(_branch(device) for device in primitives)
        solution = solve_linear_dc(branches, limits=limits)
        locations = tuple(
            sorted(
                (device.qualified_name.lower(), device.element.location) for device in primitives
            )
        )
        status = "solved"
    except InconsistentDC as error:
        status, notes = "inconsistent", (str(error),)
    except SingularDC as error:
        status, notes = "singular", (str(error),)
    except (DCBudgetExceeded, RecursionError) as error:
        status, notes = "budget-exceeded", (str(error),)
    except DCInputError as error:
        status, notes = "unsupported", (str(error),)
    for item in bundle.digests():
        _metadata_name(item.path)
    return DCNetlistReport(
        status,
        bundle.root_display,
        bundle.entry,
        bundle.bundle_hash(),
        bundle.digests(),
        solution,
        locations,
        notes,
    )


def solve_dc_path(
    path: str | Path,
    *,
    entry: str | None = None,
    limits: DCLimits = DEFAULT_DC_LIMITS,
) -> DCNetlistReport:
    """Solve only a fully supported confined literal R/V/I netlist hierarchy."""
    if type(limits) is not DCLimits:
        raise DCInputError("limits must be DCLimits")
    limits.__post_init__()
    return _solve_bundle(ArtifactBundle.open(path, entry=entry), limits)


def solve_dc_text(
    text: str,
    *,
    virtual_name: str = "input.sp",
    limits: DCLimits = DEFAULT_DC_LIMITS,
) -> DCNetlistReport:
    """In-memory equivalent of :func:`solve_dc_path`, without filesystem includes."""
    if type(limits) is not DCLimits:
        raise DCInputError("limits must be DCLimits")
    limits.__post_init__()
    _metadata_name(virtual_name)
    if type(text) is not str or len(text) > _MAX_TEXT_BYTES:
        raise DCInputError("DC netlist text exceeds the two-million-byte input profile")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as error:
        raise DCInputError("DC netlist text must contain Unicode scalar values") from error
    if size > _MAX_TEXT_BYTES or "\0" in text:
        raise DCInputError("DC netlist text is oversized or contains NUL")
    return _solve_bundle(MemoryBundle(text, virtual_name), limits)


def dc_report_json(report: DCNetlistReport, *, pretty: bool = False) -> str:
    _preflight_report(report)
    return (
        json.dumps(report.as_dict(), sort_keys=True, indent=2 if pretty else None, allow_nan=False)
        + "\n"
    )


def dc_report_text(report: DCNetlistReport) -> str:
    _preflight_report(report)

    # Escape every source-derived string, including paths and diagnostics.
    def safe(text: str) -> str:
        return json.dumps(text, ensure_ascii=True)[1:-1]

    lines = [
        f"Linear DC result (linear-rvi-v1): {report.status}",
        f"Bundle: {report.bundle_sha256}",
    ]
    if report.solution:
        lines.extend(f"V({safe(name)}) = {value} V" for name, value in report.solution.voltages)
        lines.extend(f"I({safe(name)}) = {value} A" for name, value in report.solution.currents)
    lines.extend(f"NOTE: {safe(note)}" for note in report.notes)
    lines.append(
        "Conditional linear operating point; not an artifact safety or nonlinear device verdict."
    )
    return "\n".join(lines) + "\n"
