"""Parser for the intentionally bounded SPICE syntax understood by the gate."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from schematic_airlock.domain import SourceLocation, SyntaxFailure
from schematic_airlock.lex import LogicalLine, logical_lines, tokenize


@dataclass(frozen=True, slots=True)
class Element:
    name: str
    kind: str
    nodes: tuple[str, ...]
    value: str | None
    model: str | None
    arguments: tuple[str, ...]
    parameters: tuple[tuple[str, str], ...]
    location: SourceLocation
    raw: str


@dataclass(frozen=True, slots=True)
class Directive:
    name: str
    arguments: tuple[str, ...]
    location: SourceLocation
    raw: str


@dataclass(frozen=True, slots=True)
class IncludeRef:
    directive: str
    target: str
    section: str | None
    location: SourceLocation
    raw: str


@dataclass(frozen=True, slots=True)
class Subcircuit:
    name: str
    ports: tuple[str, ...]
    parameters: tuple[tuple[str, str], ...]
    elements: tuple[Element, ...]
    directives: tuple[Directive, ...]
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class Deck:
    path: str
    elements: tuple[Element, ...]
    directives: tuple[Directive, ...]
    subcircuits: tuple[Subcircuit, ...]
    includes: tuple[IncludeRef, ...]
    logical_line_count: int


@dataclass(slots=True)
class _SubcircuitBuilder:
    name: str
    ports: tuple[str, ...]
    parameters: tuple[tuple[str, str], ...]
    location: SourceLocation
    elements: list[Element] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)

    def freeze(self) -> Subcircuit:
        return Subcircuit(
            self.name,
            self.ports,
            self.parameters,
            tuple(self.elements),
            tuple(self.directives),
            self.location,
        )


def _parameters(tokens: Iterable[str]) -> tuple[tuple[str, str], ...]:
    result: list[tuple[str, str]] = []
    for token in tokens:
        if "=" in token:
            name, value = token.split("=", 1)
            result.append((name.lower(), value))
    return tuple(result)


def _positional(tokens: Iterable[str]) -> list[str]:
    return [token for token in tokens if "=" not in token]


def _require(line: LogicalLine, values: list[str], count: int, description: str) -> None:
    if len(values) < count:
        raise SyntaxFailure(
            f"{description} requires at least {count - 1} arguments", line.location, line.evidence
        )


def _element(line: LogicalLine, values: list[str]) -> Element:
    name = values[0]
    if not name:
        raise SyntaxFailure("element name must not be empty", line.location, line.evidence)
    kind = name[0].upper()
    params = _parameters(values[1:])
    positional = _positional(values)
    nodes: tuple[str, ...] = ()
    value: str | None = None
    model: str | None = None
    arguments: tuple[str, ...] = ()

    if kind in {"R", "C", "L"}:
        _require(line, positional, 4, f"{kind} element")
        nodes = tuple(positional[1:3])
        value = positional[3]
        arguments = tuple(positional[4:])
    elif kind in {"V", "I"}:
        _require(line, positional, 4, f"{kind} source")
        nodes = tuple(positional[1:3])
        arguments = tuple(positional[3:])
        if len(arguments) >= 2 and arguments[0].lower() == "dc":
            value = arguments[1]
        elif arguments:
            value = arguments[0]
    elif kind == "M":
        _require(line, positional, 6, "MOS element")
        nodes = tuple(positional[1:5])
        model = positional[5]
        arguments = tuple(positional[6:])
    elif kind == "D":
        _require(line, positional, 4, "diode")
        nodes = tuple(positional[1:3])
        model = positional[3]
        arguments = tuple(positional[4:])
    elif kind == "Q":
        _require(line, positional, 5, "BJT element")
        terminal_count = 4 if len(positional) >= 6 else 3
        nodes = tuple(positional[1 : 1 + terminal_count])
        model = positional[1 + terminal_count]
        arguments = tuple(positional[2 + terminal_count :])
    elif kind == "X":
        raw_tail = values[1:]
        marker = next(
            (index for index, token in enumerate(raw_tail) if token.lower() == "params:"),
            len(raw_tail),
        )
        instance_tokens = _positional(raw_tail[:marker])
        _require(line, [name, *instance_tokens], 3, "subcircuit instance")
        nodes = tuple(instance_tokens[:-1])
        model = instance_tokens[-1]
        params = _parameters(raw_tail[marker + 1 :] if marker < len(raw_tail) else raw_tail)
    elif kind in {"E", "G"}:
        _require(line, positional, 6, f"{kind} controlled source")
        nodes = tuple(positional[1:5])
        value = positional[5]
        arguments = tuple(positional[6:])
    elif kind in {"F", "H"}:
        _require(line, positional, 5, f"{kind} controlled source")
        nodes = tuple(positional[1:3])
        arguments = tuple(positional[3:])
        value = positional[4]
    elif kind == "B":
        _require(line, values, 4, "behavioral source")
        nodes = tuple(values[1:3])
        arguments = tuple(values[3:])
    else:
        arguments = tuple(positional[1:])

    return Element(
        name=name,
        kind=kind,
        nodes=nodes,
        value=value,
        model=model,
        arguments=arguments,
        parameters=params,
        location=line.location,
        raw=line.text,
    )


def parse_deck(text: str, path: str) -> Deck:
    """Parse one file. Includes are represented but not opened here."""

    lines = logical_lines(text, path)
    elements: list[Element] = []
    directives: list[Directive] = []
    subcircuits: list[Subcircuit] = []
    includes: list[IncludeRef] = []
    current: _SubcircuitBuilder | None = None

    for line in lines:
        tokens = tokenize(line)
        if not tokens:
            continue
        values = [token.value for token in tokens]
        first = values[0]
        if not first.startswith("."):
            element = _element(line, values)
            (current.elements if current else elements).append(element)
            continue

        directive_name = first[1:].lower()
        arguments = tuple(values[1:])
        if directive_name == "subckt":
            if current is not None:
                raise SyntaxFailure("nested .subckt is not supported", line.location, line.evidence)
            _require(line, values, 2, ".subckt")
            tail = values[1:]
            marker = next(
                (index for index, token in enumerate(tail) if token.lower() == "params:"),
                len(tail),
            )
            positional = _positional(tail[:marker])
            if not positional or not positional[0]:
                raise SyntaxFailure(
                    ".subckt requires a name before parameters", line.location, line.evidence
                )
            current = _SubcircuitBuilder(
                name=positional[0],
                ports=tuple(positional[1:]),
                parameters=_parameters(tail[marker + 1 :] if marker < len(tail) else tail[1:]),
                location=line.location,
            )
            continue
        if directive_name == "ends":
            if current is None:
                raise SyntaxFailure(".ends has no matching .subckt", line.location, line.evidence)
            if arguments and arguments[0].lower() != current.name.lower():
                raise SyntaxFailure(
                    f".ends names {arguments[0]!r}, expected {current.name!r}",
                    line.location,
                    line.evidence,
                )
            subcircuits.append(current.freeze())
            current = None
            continue
        if directive_name == "include":
            _require(line, values, 2, ".include")
            includes.append(IncludeRef("include", arguments[0], None, line.location, line.text))
        elif directive_name == "lib" and arguments:
            target = arguments[0]
            looks_like_path = any(mark in target for mark in ("/", "\\", "."))
            if len(arguments) > 1 or looks_like_path:
                section = arguments[1] if len(arguments) > 1 else None
                includes.append(IncludeRef("lib", target, section, line.location, line.text))

        directive = Directive(directive_name, arguments, line.location, line.text)
        (current.directives if current else directives).append(directive)

    if current is not None:
        raise SyntaxFailure(
            f"subcircuit {current.name!r} is missing .ends", current.location, current.name
        )
    return Deck(
        path=path,
        elements=tuple(elements),
        directives=tuple(directives),
        subcircuits=tuple(subcircuits),
        includes=tuple(includes),
        logical_line_count=len(lines),
    )
