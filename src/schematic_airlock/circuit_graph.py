"""Structural graph derived from parsed netlists without full expansion."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass, replace
from decimal import Decimal

from schematic_airlock.domain import SourceLocation
from schematic_airlock.include_graph import IncludeGraph
from schematic_airlock.parse import Element, Subcircuit
from schematic_airlock.units import decimal_text, evaluate_expression, parameter_assignments


@dataclass(frozen=True, slots=True)
class Endpoint:
    device: str
    terminal: str
    kind: str


@dataclass(frozen=True, slots=True)
class Net:
    scope: str
    name: str
    display_name: str
    endpoints: tuple[Endpoint, ...]
    is_port: bool


@dataclass(frozen=True, slots=True)
class Device:
    scope: str
    element: Element

    @property
    def qualified_name(self) -> str:
        return f"{self.scope}/{self.element.name}"


@dataclass(frozen=True, slots=True)
class GraphIssue:
    code: str
    message: str
    location: SourceLocation
    evidence: str = ""


@dataclass(frozen=True, slots=True)
class CircuitGraph:
    devices: tuple[Device, ...]
    expanded_devices: tuple[Device, ...]
    nets: tuple[Net, ...]
    subcircuits: tuple[Subcircuit, ...]
    call_edges: tuple[tuple[str, str], ...]
    expanded_instances: int
    logical_lines: int
    issues: tuple[GraphIssue, ...]

    def nets_in_scope(self, scope: str) -> tuple[Net, ...]:
        return tuple(net for net in self.nets if net.scope == scope)


_TERMINALS: dict[str, tuple[str, ...]] = {
    "R": ("p", "n"),
    "C": ("p", "n"),
    "L": ("p", "n"),
    "V": ("p", "n"),
    "I": ("p", "n"),
    "D": ("a", "k"),
    "M": ("d", "g", "s", "b"),
    "Q": ("c", "b", "e", "s"),
    "E": ("p", "n", "cp", "cn"),
    "G": ("p", "n", "cp", "cn"),
    "F": ("p", "n"),
    "H": ("p", "n"),
    "B": ("p", "n"),
}


def _scope_for(subcircuit: Subcircuit) -> str:
    return f"subckt:{subcircuit.name.lower()}"


def build_circuit_graph(
    includes: IncludeGraph,
    *,
    max_expanded_instances: int = 100_000,
) -> CircuitGraph:
    """Build scoped nets, validate calls, and compute an expansion upper bound."""

    issues: list[GraphIssue] = []
    definitions: dict[str, Subcircuit] = {}
    all_subcircuits: list[Subcircuit] = []
    top_elements: list[Element] = []
    logical_lines = 0
    for deck in includes.decks:
        logical_lines += deck.logical_line_count
        top_elements.extend(deck.elements)
        for subcircuit in deck.subcircuits:
            key = subcircuit.name.lower()
            if key in definitions:
                issues.append(
                    GraphIssue(
                        "GRAPH001",
                        f"duplicate subcircuit definition {subcircuit.name!r}",
                        subcircuit.location,
                        subcircuit.name,
                    )
                )
            else:
                definitions[key] = subcircuit
                all_subcircuits.append(subcircuit)
            folded_ports = [port.casefold() for port in subcircuit.ports]
            if len(folded_ports) != len(set(folded_ports)):
                issues.append(
                    GraphIssue(
                        "GRAPH007",
                        f"subcircuit {subcircuit.name!r} has duplicate formal ports",
                        subcircuit.location,
                        subcircuit.name,
                    )
                )

    scoped_elements: dict[str, list[Element]] = {"top": top_elements}
    scope_ports: dict[str, set[str]] = {"top": set()}
    for subcircuit in all_subcircuits:
        scope = _scope_for(subcircuit)
        scoped_elements[scope] = list(subcircuit.elements)
        scope_ports[scope] = {port.lower() for port in subcircuit.ports}

    devices: list[Device] = []
    net_endpoints: dict[tuple[str, str], list[Endpoint]] = defaultdict(list)
    net_display: dict[tuple[str, str], str] = {}
    call_counts: dict[str, Counter[str]] = defaultdict(Counter)
    call_edges: list[tuple[str, str]] = []

    for scope, elements in scoped_elements.items():
        names: dict[str, Element] = {}
        for element in elements:
            normalized_name = element.name.lower()
            if normalized_name in names:
                issues.append(
                    GraphIssue(
                        "GRAPH002",
                        f"duplicate element name {element.name!r} in {scope}",
                        element.location,
                        element.raw,
                    )
                )
            else:
                names[normalized_name] = element
            device = Device(scope, element)
            devices.append(device)
            terminal_names = _TERMINALS.get(element.kind, ())
            if element.kind == "X":
                terminal_names = tuple(f"port{index}" for index in range(len(element.nodes)))
                if element.model is not None:
                    target_key = element.model.lower()
                    target_scope = f"subckt:{target_key}"
                    call_counts[scope][target_scope] += 1
                    call_edges.append((scope, target_scope))
                    definition = definitions.get(target_key)
                    if definition is None:
                        issues.append(
                            GraphIssue(
                                "GRAPH003",
                                f"undefined subcircuit {element.model!r}",
                                element.location,
                                element.raw,
                            )
                        )
                    elif len(element.nodes) != len(definition.ports):
                        issues.append(
                            GraphIssue(
                                "GRAPH004",
                                f"instance {element.name!r} passes {len(element.nodes)} ports to "
                                f"{definition.name!r}, which declares {len(definition.ports)}",
                                element.location,
                                element.raw,
                            )
                        )
            for index, node in enumerate(element.nodes):
                terminal = terminal_names[index] if index < len(terminal_names) else f"t{index}"
                net_key = (scope, node.lower())
                net_display.setdefault(net_key, node)
                net_endpoints[net_key].append(
                    Endpoint(device.qualified_name, terminal, element.kind)
                )

    recursion_reported: set[tuple[str, ...]] = set()
    memo: dict[str, int] = {}

    def expansion_cost(scope: str, stack: tuple[str, ...]) -> int:
        if scope in memo:
            return memo[scope]
        if scope in stack:
            cycle = (*stack[stack.index(scope) :], scope)
            if cycle not in recursion_reported:
                recursion_reported.add(cycle)
                location = _scope_location(scope, definitions)
                issues.append(
                    GraphIssue(
                        "GRAPH005",
                        f"recursive subcircuit call: {' -> '.join(cycle)}",
                        location,
                        " -> ".join(cycle),
                    )
                )
            return max_expanded_instances + 1
        direct = len(scoped_elements.get(scope, ()))
        total = direct
        for target, count in sorted(call_counts.get(scope, {}).items()):
            if target.removeprefix("subckt:") not in definitions:
                continue
            child_cost = expansion_cost(target, (*stack, scope))
            total += count * child_cost
            if total > max_expanded_instances:
                return max_expanded_instances + 1
        memo[scope] = total
        return total

    expanded = expansion_cost("top", ())

    top_parameters: dict[str, Decimal] = {}
    for directive in includes.parameter_directives:
        try:
            top_parameters = parameter_assignments(directive.arguments, top_parameters)
        except ValueError as exc:
            issues.append(
                GraphIssue(
                    "GRAPH008",
                    f"parameter expression cannot be evaluated: {exc}",
                    directive.location,
                    directive.raw,
                )
            )
    expanded_devices: list[Device] = []

    def assignments_with_issues(
        assignments: list[str],
        inherited: dict[str, Decimal],
        element: Element,
    ) -> dict[str, Decimal]:
        values = dict(inherited)
        for assignment in assignments:
            try:
                values = parameter_assignments([assignment], values)
            except ValueError as exc:
                issues.append(
                    GraphIssue(
                        "GRAPH008",
                        f"instance parameter expression cannot be evaluated: {exc}",
                        element.location,
                        element.raw,
                    )
                )
        return values

    def expand_elements(
        elements: list[Element],
        path: str,
        node_map: dict[str, str],
        parameters: dict[str, Decimal],
        stack: tuple[str, ...],
    ) -> None:
        for element in elements:
            # Check before allocating every reached instance, including siblings
            # in a flat scope. The independent cost above retains the overflow
            # evidence used by callers to reject incomplete expansion.
            if len(expanded_devices) >= max_expanded_instances:
                return
            mapped_nodes = tuple(
                "0"
                if node.lower() == "0"
                else node_map.get(
                    node.lower(), node.lower() if path == "top" else f"{path}:{node.lower()}"
                )
                for node in element.nodes
            )
            if element.kind == "X" and element.model is not None:
                definition = definitions.get(element.model.lower())
                expanded_devices.append(Device(path, replace(element, nodes=mapped_nodes)))
                if (
                    definition is None
                    or definition.name.lower() in stack
                    or len(expanded_devices) >= max_expanded_instances
                ):
                    continue
                child_parameters = assignments_with_issues(
                    [f"{name}={value}" for name, value in definition.parameters],
                    parameters,
                    element,
                )
                child_parameters = assignments_with_issues(
                    [f"{name}={value}" for name, value in element.parameters],
                    child_parameters,
                    element,
                )
                child_nodes = {
                    port.lower(): node
                    for port, node in zip(definition.ports, mapped_nodes, strict=False)
                }
                expand_elements(
                    list(definition.elements),
                    f"{path}/{element.name}",
                    child_nodes,
                    child_parameters,
                    (*stack, definition.name.lower()),
                )
                continue
            value = element.value
            if value is not None:
                with suppress(ValueError):
                    value = decimal_text(evaluate_expression(value, parameters))
            expanded_devices.append(Device(path, replace(element, nodes=mapped_nodes, value=value)))

    expand_elements(top_elements, "top", {}, top_parameters, ())
    reachable = {"top"}
    queue = deque(["top"])
    while queue:
        scope = queue.popleft()
        for target in call_counts.get(scope, {}):
            if target not in reachable:
                reachable.add(target)
                queue.append(target)
    for definition_key, definition in sorted(definitions.items()):
        scope = f"subckt:{definition_key}"
        if scope not in reachable:
            issues.append(
                GraphIssue(
                    "GRAPH006",
                    f"subcircuit {definition.name!r} is never reached from the top level",
                    definition.location,
                    definition.name,
                )
            )

    nets = [
        Net(
            scope=scope,
            name=name,
            display_name=net_display[(scope, name)],
            endpoints=tuple(sorted(endpoints, key=lambda item: (item.device, item.terminal))),
            is_port=name in scope_ports.get(scope, set()),
        )
        for (scope, name), endpoints in sorted(net_endpoints.items())
    ]
    return CircuitGraph(
        devices=tuple(sorted(devices, key=lambda item: item.qualified_name.lower())),
        expanded_devices=tuple(
            sorted(expanded_devices, key=lambda item: item.qualified_name.lower())
        ),
        nets=tuple(nets),
        subcircuits=tuple(sorted(all_subcircuits, key=lambda item: item.name.lower())),
        call_edges=tuple(sorted(set(call_edges))),
        expanded_instances=expanded,
        logical_lines=logical_lines,
        issues=tuple(
            sorted(
                issues,
                key=lambda item: (
                    item.location.path,
                    item.location.line,
                    item.code,
                    item.message,
                ),
            )
        ),
    )


def _scope_location(scope: str, definitions: dict[str, Subcircuit]) -> SourceLocation:
    key = scope.removeprefix("subckt:")
    definition = definitions.get(key)
    return definition.location if definition is not None else SourceLocation("<bundle>")
