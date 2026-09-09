"""Exact, bounded voltage-difference reasoning, independent of a circuit solver.

An edge encodes ``lower <= V(positive) - V(negative) <= upper``. Exact
equalities are eliminated by a weighted disjoint-set forest. The remaining
difference graph is checked for negative cycles and reweighted for shortest
paths. Missing paths mean unbounded, never zero. All arithmetic is rational.
"""

from __future__ import annotations

import heapq
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from fractions import Fraction

from schematic_airlock.domain import InputError

_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?")
_MAX_BITS = 4_096


class VoltageConstraintError(InputError):
    """Malformed voltage input; not evidence of an electrical violation."""


class VoltageBudgetExceeded(VoltageConstraintError):
    """A configured resource budget prevented a complete proof."""


class InconsistentVoltages(VoltageConstraintError):
    """The supplied ideal constraints have no simultaneous solution."""


def volts(text: str) -> Fraction:
    """Read an exact decimal number of volts (no suffixes or binary floats)."""

    if not isinstance(text, str) or len(text) > 128 or not _DECIMAL.fullmatch(text):
        raise VoltageConstraintError("voltage must be a bounded decimal string in volts")
    value = Fraction(text)
    _rational(value)
    if abs(value) > 10**100 or (value and abs(value) < Fraction(1, 10**100)):
        raise VoltageConstraintError("nonzero voltage magnitude must be between 1e-100 and 1e100")
    return value


def _rational(value: Fraction) -> None:
    if not isinstance(value, Fraction):
        raise VoltageConstraintError("voltage bounds must be exact Fraction values")
    if max(value.numerator.bit_length(), value.denominator.bit_length()) > _MAX_BITS:
        raise VoltageBudgetExceeded("voltage arithmetic exceeds the rational bit budget")


def _name(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_024
        or unicodedata.normalize("NFC", value) != value
        or any(
            character.isspace() or unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            for character in value
        )
    ):
        raise VoltageConstraintError(
            "voltage node/constraint names must be bounded nonblank tokens"
        )


@dataclass(frozen=True, slots=True)
class VoltageInterval:
    """Tight closed bounds in volts; ``None`` is an infinite endpoint."""

    lower: Fraction | None
    upper: Fraction | None

    def __post_init__(self) -> None:
        for endpoint in (self.lower, self.upper):
            if endpoint is not None:
                _rational(endpoint)
        if self.lower is not None and self.upper is not None and self.lower > self.upper:
            raise VoltageConstraintError("voltage interval lower exceeds upper")

    @property
    def bounded(self) -> bool:
        return self.lower is not None and self.upper is not None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "lower_volts": str(self.lower) if self.lower is not None else None,
            "upper_volts": str(self.upper) if self.upper is not None else None,
        }


@dataclass(frozen=True, slots=True)
class VoltageConstraint:
    positive: str
    negative: str
    interval: VoltageInterval
    label: str

    def __post_init__(self) -> None:
        for value in (self.positive, self.negative, self.label):
            _name(value)
        if not isinstance(self.interval, VoltageInterval):
            raise VoltageConstraintError("constraint interval must be a VoltageInterval")
        if self.interval.lower is None and self.interval.upper is None:
            raise VoltageConstraintError("a constraint must have at least one finite endpoint")


@dataclass(frozen=True, slots=True)
class VoltageLimits:
    max_nodes: int = 200_000
    max_constraints: int = 300_000
    max_edge_visits: int = 5_000_000
    max_queries: int = 100_000

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.max_nodes, 2_000_000),
            (self.max_constraints, 3_000_000),
            (self.max_edge_visits, 100_000_000),
            (self.max_queries, 1_000_000),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise VoltageConstraintError(f"voltage limits must be integers in 1..{ceiling}")


DEFAULT_VOLTAGE_LIMITS = VoltageLimits()


class _Forest:
    def __init__(self, nodes: Iterable[str]) -> None:
        self.parent = {node: node for node in nodes}
        self.weight = {node: Fraction(0) for node in self.parent}
        self.size = dict.fromkeys(self.parent, 1)

    def find(self, node: str) -> tuple[str, Fraction]:
        current = node
        offset = Fraction(0)
        while self.parent[current] != current:
            offset += self.weight[current]
            _rational(offset)
            current = self.parent[current]
        root = current
        remaining = offset
        current = node
        while self.parent[current] != current:
            parent = self.parent[current]
            delta = self.weight[current]
            self.parent[current] = root
            self.weight[current] = remaining
            remaining -= delta
            current = parent
        return root, offset

    def join(self, positive: str, negative: str, difference: Fraction, label: str) -> None:
        left, left_offset = self.find(positive)
        right, right_offset = self.find(negative)
        delta = difference - left_offset + right_offset
        _rational(delta)
        if left == right:
            if delta:
                raise InconsistentVoltages(f"{label}: incompatible exact voltage difference")
            return
        if self.size[left] > self.size[right]:
            left, right, delta = right, left, -delta
        self.parent[left] = right
        self.weight[left] = delta
        self.size[right] += self.size[left]


class VoltageSystem:
    """A feasible system with exact pairwise queries and cumulative work budgets.

    Construction raises :class:`InconsistentVoltages` only for a proved
    contradiction. Budget exhaustion raises :class:`VoltageBudgetExceeded`.
    No partial/previous result is returned after a query exhausts its budget.
    Node identity is exact and case-sensitive; netlist adapters normalize it.
    """

    def __init__(
        self,
        nodes: Iterable[str],
        constraints: Iterable[VoltageConstraint],
        *,
        limits: VoltageLimits = DEFAULT_VOLTAGE_LIMITS,
    ) -> None:
        if not isinstance(limits, VoltageLimits):
            raise VoltageConstraintError("limits must be VoltageLimits")
        self.limits = limits
        names: set[str] = set()
        for node in nodes:
            _name(node)
            if node in names:
                raise VoltageConstraintError(f"duplicate voltage node {node!r}")
            names.add(node)
            if len(names) > limits.max_nodes:
                raise VoltageBudgetExceeded("voltage node budget exceeded")
        declarations: list[VoltageConstraint] = []
        labels: set[str] = set()
        for constraint in constraints:
            if not isinstance(constraint, VoltageConstraint):
                raise VoltageConstraintError("constraints must be VoltageConstraint values")
            if constraint.label in labels:
                raise VoltageConstraintError(
                    f"duplicate voltage constraint label {constraint.label!r}"
                )
            labels.add(constraint.label)
            if constraint.positive not in names or constraint.negative not in names:
                raise VoltageConstraintError(
                    f"{constraint.label}: constraint references unknown node"
                )
            declarations.append(constraint)
            if len(declarations) > limits.max_constraints:
                raise VoltageBudgetExceeded("voltage constraint budget exceeded")
        self._edge_visits = 0
        self._queries = 0
        self._failed = False
        forest = _Forest(sorted(names))
        ordered = sorted(declarations, key=lambda declaration: declaration.label)
        for constraint in ordered:
            lower, upper = constraint.interval.lower, constraint.interval.upper
            if lower is not None and lower == upper:
                forest.join(constraint.positive, constraint.negative, lower, constraint.label)
        self._nodes = {node: forest.find(node) for node in sorted(names)}
        self._roots = sorted({root for root, _ in self._nodes.values()})
        edges: dict[tuple[str, str], Fraction] = {}
        for constraint in ordered:
            positive, p_offset = self._nodes[constraint.positive]
            negative, n_offset = self._nodes[constraint.negative]
            for source, target, bound in (
                (negative, positive, constraint.interval.upper),
                (
                    positive,
                    negative,
                    -constraint.interval.lower if constraint.interval.lower is not None else None,
                ),
            ):
                if bound is None:
                    continue
                offset = n_offset - p_offset if source == negative else p_offset - n_offset
                # Equal roots need direction from the constraint, not root names.
                if positive == negative:
                    difference = p_offset - n_offset
                    interval = constraint.interval
                    if (interval.lower is not None and difference < interval.lower) or (
                        interval.upper is not None and difference > interval.upper
                    ):
                        raise InconsistentVoltages(
                            f"{constraint.label}: incompatible voltage bounds"
                        )
                    break
                weight = bound + offset
                _rational(weight)
                key = (source, target)
                edges[key] = min(edges.get(key, weight), weight)
        self._edges = tuple(
            (source, target, weight) for (source, target), weight in sorted(edges.items())
        )
        self._potential = self._feasible_potentials()
        self._forward: dict[str, list[tuple[str, Fraction]]] = {root: [] for root in self._roots}
        self._reverse: dict[str, list[tuple[str, Fraction]]] = {root: [] for root in self._roots}
        for source, target, weight in self._edges:
            reduced = weight + self._potential[source] - self._potential[target]
            _rational(reduced)
            if reduced < 0:
                raise AssertionError("invalid feasible potential")
            self._forward[source].append((target, reduced))
            self._reverse[target].append((source, reduced))
        # Keep only the latest source: all-pairs caching would be quadratic memory.
        self._cached_root: str | None = None
        self._cached_forward: dict[str, Fraction] = {}
        self._cached_reverse: dict[str, Fraction] = {}

    @property
    def edge_visits(self) -> int:
        return self._edge_visits

    @property
    def component_count(self) -> int:
        return len(self._roots)

    def _visit(self) -> None:
        self._edge_visits += 1
        if self._edge_visits > self.limits.max_edge_visits:
            self._failed = True
            raise VoltageBudgetExceeded("voltage edge-visit budget exceeded")

    def _feasible_potentials(self) -> dict[str, Fraction]:
        distance = dict.fromkeys(self._roots, Fraction(0))
        for _ in range(len(self._roots)):
            changed = False
            for source, target, weight in self._edges:
                self._visit()
                candidate = distance[source] + weight
                _rational(candidate)
                if candidate < distance[target]:
                    distance[target] = candidate
                    changed = True
            if not changed:
                return distance
        if self._roots:
            raise InconsistentVoltages("voltage interval constraints contain a negative cycle")
        return distance

    def _distances(self, source: str, *, reverse: bool) -> dict[str, Fraction]:
        adjacency = self._reverse if reverse else self._forward
        distances = {source: Fraction(0)}
        queue = [(Fraction(0), source)]
        while queue:
            distance, node = heapq.heappop(queue)
            if distance != distances[node]:
                continue
            for target, weight in adjacency[node]:
                self._visit()
                candidate = distance + weight
                _rational(candidate)
                previous = distances.get(target)
                if previous is None or candidate < previous:
                    distances[target] = candidate
                    heapq.heappush(queue, (candidate, target))
        return distances

    def difference(self, positive: str, negative: str) -> VoltageInterval:
        """Return tight bounds for ``V(positive) - V(negative)``.

        Correlation is preserved even when neither absolute node voltage is
        bounded. Query exhaustion invalidates this object for further queries.
        """

        if self._failed:
            raise VoltageBudgetExceeded("voltage system already exhausted its budget")
        self._queries += 1
        if self._queries > self.limits.max_queries:
            self._failed = True
            raise VoltageBudgetExceeded("voltage query budget exceeded")
        if positive not in self._nodes or negative not in self._nodes:
            raise VoltageConstraintError("voltage query references unknown node")
        p_root, p_offset = self._nodes[positive]
        n_root, n_offset = self._nodes[negative]
        offset = p_offset - n_offset
        _rational(offset)
        if p_root == n_root:
            return VoltageInterval(offset, offset)
        try:
            if self._cached_root != n_root:
                forward = self._distances(n_root, reverse=False)
                reverse = self._distances(n_root, reverse=True)
                self._cached_root = n_root
                self._cached_forward, self._cached_reverse = forward, reverse
            upper = self._cached_forward.get(p_root)
            lower = self._cached_reverse.get(p_root)
            potential = self._potential[p_root] - self._potential[n_root]
            return VoltageInterval(
                -lower + potential + offset if lower is not None else None,
                upper + potential + offset if upper is not None else None,
            )
        except VoltageBudgetExceeded:
            self._failed = True
            raise
