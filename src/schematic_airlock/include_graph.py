"""Safe loading of the include DAG."""

from __future__ import annotations

from dataclasses import dataclass

from schematic_airlock.bundle import BundleSource
from schematic_airlock.domain import InputError, SourceLocation, SyntaxFailure
from schematic_airlock.parse import Deck, Directive, IncludeRef, parse_deck


@dataclass(frozen=True, slots=True)
class LoadIssue:
    code: str
    message: str
    location: SourceLocation
    evidence: str = ""
    target: str = ""


@dataclass(frozen=True, slots=True)
class IncludeEdge:
    source: str
    target: str
    directive: str
    section: str | None


@dataclass(frozen=True, slots=True)
class IncludeGraph:
    entry: str
    decks: tuple[Deck, ...]
    edges: tuple[IncludeEdge, ...]
    issues: tuple[LoadIssue, ...]
    parameter_directives: tuple[Directive, ...] = ()

    def deck_map(self) -> dict[str, Deck]:
        return {deck.path: deck for deck in self.decks}


def load_include_graph(
    bundle: BundleSource,
    *,
    max_depth: int = 16,
) -> IncludeGraph:
    """Parse the entry and every safely reachable include exactly once."""

    decks: dict[str, Deck] = {}
    issues: list[LoadIssue] = []
    edges: list[IncludeEdge] = []
    active: list[str] = []
    parameter_directives: list[Directive] = []
    expansion_counts: dict[str, int] = {}

    def visit(relative: str, depth: int, from_location: SourceLocation | None = None) -> None:
        if depth > max_depth:
            location = from_location or SourceLocation(relative)
            issues.append(
                LoadIssue(
                    "INCL002",
                    f"include depth exceeds the configured limit of {max_depth}",
                    location,
                    relative,
                    relative,
                )
            )
            return
        deck = decks.get(relative)
        if deck is None:
            try:
                text = bundle.read_text(relative)
                deck = parse_deck(text, relative)
            except SyntaxFailure as exc:
                issues.append(
                    LoadIssue("PARSE001", exc.message, exc.location, exc.evidence, relative)
                )
                return
            except InputError as exc:
                location = from_location or SourceLocation(relative)
                issues.append(LoadIssue("FILE001", str(exc), location, relative, relative))
                return
        decks[relative] = deck
        expansion_counts[relative] = expansion_counts.get(relative, 0) + 1
        if expansion_counts[relative] > 1:
            location = from_location or SourceLocation(relative)
            issues.append(
                LoadIssue(
                    "INCL003",
                    f"include target is expanded more than once: {relative}",
                    location,
                    relative,
                    relative,
                )
            )
            # Repeated expansion is already an unsupported result. The first
            # visit fully traversed this deck, so descending again can only
            # duplicate evidence and can expand a small include DAG
            # exponentially. Active-path cycles are detected by the caller
            # before reaching this repeat guard.
            return
        active.append(relative)
        flow: list[Directive | IncludeRef] = [
            directive for directive in deck.directives if directive.name == "param"
        ]
        flow.extend(deck.includes)
        flow.sort(key=lambda item: (item.location.line, item.location.column))
        for item in flow:
            if isinstance(item, Directive):
                parameter_directives.append(item)
                continue
            include = item
            try:
                target = bundle.resolve_reference(relative, include.target)
            except InputError as exc:
                issues.append(
                    LoadIssue("PATH001", str(exc), include.location, include.raw, include.target)
                )
                continue
            edges.append(IncludeEdge(relative, target, include.directive, include.section))
            if target in active:
                cycle = " -> ".join([*active[active.index(target) :], target])
                issues.append(
                    LoadIssue(
                        "INCL001",
                        f"include cycle detected: {cycle}",
                        include.location,
                        include.raw,
                        target,
                    )
                )
                continue
            visit(target, depth + 1, include.location)
        active.pop()

    visit(bundle.entry, 0)
    return IncludeGraph(
        entry=bundle.entry,
        decks=tuple(decks[path] for path in sorted(decks)),
        edges=tuple(sorted(edges, key=lambda edge: (edge.source, edge.target, edge.directive))),
        issues=tuple(
            sorted(
                issues,
                key=lambda issue: (
                    issue.location.path,
                    issue.location.line,
                    issue.code,
                    issue.message,
                ),
            )
        ),
        parameter_directives=tuple(parameter_directives),
    )
