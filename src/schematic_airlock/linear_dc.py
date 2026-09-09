"""Bounded exact modified nodal analysis for independent linear DC networks.

Positive branch current flows from ``positive`` to ``negative``; positive power
is absorbed. Zero-ohm resistors are ideal zero-volt sources with an explicit
current unknown. No conductance regularization, floating-node grounding, device
model inference, or tolerance-based singularity repair is performed.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256

from schematic_airlock.domain import InputError

_ZERO = Fraction(0)
_ONE = Fraction(1)
_MAX_BITS = 4096
_MAX_NAME = 1024


class DCInputError(InputError):
    """Malformed or unsupported linear-network input."""


class DCBudgetExceeded(DCInputError):
    """A complete result cannot be produced within the configured resource budget."""


class InconsistentDC(DCInputError):
    """The exact ideal equations have no simultaneous solution."""


class SingularDC(DCInputError):
    """The ideal network has no unique set of node voltages and branch currents."""


def _name(value: str) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_NAME
        or unicodedata.normalize("NFC", value) != value
        or any(c.isspace() or unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
    ):
        raise DCInputError("DC names must be bounded NFC tokens without whitespace or controls")


def _rational(value: Fraction) -> Fraction:
    if type(value) is not Fraction:
        raise DCInputError("DC values must be exact Fraction values in SI units")
    if max(value.numerator.bit_length(), value.denominator.bit_length()) > _MAX_BITS:
        raise DCBudgetExceeded("DC arithmetic exceeds the 4096-bit rational budget")
    return value


@dataclass(frozen=True, slots=True)
class DCBranch:
    """An independent resistor (ohms), voltage source (V), or current source (A)."""

    label: str
    kind: str
    positive: str
    negative: str
    value: Fraction

    def __post_init__(self) -> None:
        for name in (self.label, self.positive, self.negative):
            _name(name)
        if type(self.kind) is not str or self.kind not in {"resistor", "voltage", "current"}:
            raise DCInputError("DC branch kind must be resistor, voltage, or current")
        _rational(self.value)
        if self.kind == "resistor" and self.value < 0:
            raise DCInputError("negative resistance is not supported by the passive DC profile")


@dataclass(frozen=True, slots=True)
class DCLimits:
    max_nodes: int = 50_000
    max_branches: int = 100_000
    max_unknowns: int = 100_000
    max_nonzeros: int = 1_000_000
    max_operations: int = 20_000_000
    max_name_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.max_nodes, 2_000_000),
            (self.max_branches, 3_000_000),
            (self.max_unknowns, 3_000_000),
            (self.max_nonzeros, 10_000_000),
            (self.max_operations, 100_000_000),
            (self.max_name_bytes, 64 * 1024 * 1024),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise DCInputError(f"DC limits must be integers in 1..{ceiling}")


@dataclass(frozen=True, slots=True)
class DCSolution:
    """Complete exact solution; values and labels are in stable lexical order.

    The operation count covers stamping, pivot work, rational arithmetic and
    independent physical residual verification. Peak nonzeros counts matrix
    coefficients (not the row/column index overhead or process RSS).
    """

    network_id: str
    ground: str
    voltages: tuple[tuple[str, Fraction], ...]
    currents: tuple[tuple[str, Fraction], ...]
    powers: tuple[tuple[str, Fraction], ...]
    unknowns: int
    operations: int
    peak_nonzeros: int


DEFAULT_DC_LIMITS = DCLimits()


class _Work:
    def __init__(self, limits: DCLimits) -> None:
        self.limits = limits
        self.operations = 0
        self.nonzeros = 0
        self.peak_nonzeros = 0

    def use(self, count: int = 1) -> None:
        self.operations += count
        if self.operations > self.limits.max_operations:
            raise DCBudgetExceeded("DC cumulative operation budget exhausted")

    def add(self, left: Fraction, right: Fraction) -> Fraction:
        self.use()
        return _rational(left + right)

    def multiply(self, left: Fraction, right: Fraction) -> Fraction:
        self.use()
        return _rational(left * right)

    def divide(self, left: Fraction, right: Fraction) -> Fraction:
        self.use()
        return _rational(left / right)


class _Matrix:
    """Sparse rows with an inverted column index and deterministic row pivoting."""

    def __init__(self, size: int, work: _Work) -> None:
        self.rows: list[dict[int, Fraction]] = [{} for _ in range(size)]
        self.columns: list[set[int]] = [set() for _ in range(size)]
        self.rhs = [_ZERO] * size
        self.work = work

    def put(self, row: int, column: int, value: Fraction) -> None:
        self.work.use()
        old = self.rows[row].get(column, _ZERO)
        if value:
            if not old:
                if self.work.nonzeros == self.work.limits.max_nonzeros:
                    raise DCBudgetExceeded("DC sparse fill budget exhausted")
                self.work.nonzeros += 1
                self.work.peak_nonzeros = max(self.work.peak_nonzeros, self.work.nonzeros)
                self.columns[column].add(row)
            self.rows[row][column] = value
        elif old:
            self.work.nonzeros -= 1
            del self.rows[row][column]
            self.columns[column].remove(row)

    def stamp(self, row: int | None, column: int | None, value: Fraction) -> None:
        if row is not None and column is not None:
            self.put(row, column, self.work.add(self.rows[row].get(column, _ZERO), value))

    def inject(self, row: int | None, value: Fraction) -> None:
        if row is not None:
            self.rhs[row] = self.work.add(self.rhs[row], value)

    def solve(self) -> list[Fraction]:
        active = set(range(len(self.rows)))
        pivots: list[tuple[int, int]] = []
        for column, members in enumerate(self.columns):
            self.work.use(len(members) + 1)
            candidates = members & active
            if not candidates:
                continue
            pivot = min(candidates, key=lambda row: (len(self.rows[row]), row))
            active.remove(pivot)
            pivots.append((column, pivot))
            pivot_row = self.rows[pivot]
            for row in sorted(candidates - {pivot}):
                factor = self.work.divide(self.rows[row][column], pivot_row[column])
                for target, coefficient in sorted(pivot_row.items()):
                    product = self.work.multiply(factor, coefficient)
                    self.put(
                        row, target, self.work.add(self.rows[row].get(target, _ZERO), -product)
                    )
                self.rhs[row] = self.work.add(
                    self.rhs[row], -self.work.multiply(factor, self.rhs[pivot])
                )
        if any(self.rhs[row] for row in active):
            raise InconsistentDC("linear DC equations contain a contradictory zero-coefficient row")
        if len(pivots) != len(self.rows):
            raise SingularDC(
                f"linear DC equations have rank {len(pivots)} for {len(self.rows)} unknowns; "
                "floating voltages or ideal-source currents remain undetermined"
            )
        result = [_ZERO] * len(self.rows)
        for column, row in reversed(pivots):
            residual = self.rhs[row]
            for other, coefficient in sorted(self.rows[row].items()):
                if other != column:
                    residual = self.work.add(
                        residual, -self.work.multiply(coefficient, result[other])
                    )
            result[column] = self.work.divide(residual, self.rows[row][column])
        return result


def _input(
    branches: Iterable[DCBranch], ground: str, limits: DCLimits
) -> tuple[tuple[DCBranch, ...], tuple[str, ...]]:
    _name(ground)
    if type(limits) is not DCLimits:
        raise DCInputError("limits must be DCLimits")
    limits.__post_init__()
    try:
        iterator = iter(branches)
    except TypeError as error:
        raise DCInputError("branches must be an iterable of DCBranch objects") from error
    found: dict[str, DCBranch] = {}
    nodes = {ground}
    name_bytes = len(ground.encode("utf-8"))
    for branch in iterator:
        if len(found) == limits.max_branches:
            raise DCBudgetExceeded("DC branch budget exhausted")
        if type(branch) is not DCBranch:
            raise DCInputError("every branch must be a DCBranch")
        branch.__post_init__()
        if branch.label in found:
            raise DCInputError(f"duplicate DC branch label {branch.label!r}")
        name_bytes += sum(
            len(name.encode("utf-8")) for name in (branch.label, branch.positive, branch.negative)
        )
        if name_bytes > limits.max_name_bytes:
            raise DCBudgetExceeded("DC input name byte budget exhausted")
        nodes.update((branch.positive, branch.negative))
        if len(nodes) > limits.max_nodes:
            raise DCBudgetExceeded("DC node budget exhausted")
        found[branch.label] = branch
    if name_bytes > limits.max_name_bytes:
        raise DCBudgetExceeded("DC input name byte budget exhausted")
    return tuple(found[label] for label in sorted(found)), tuple(sorted(nodes))


def _is_voltage(branch: DCBranch) -> bool:
    return branch.kind == "voltage" or (branch.kind == "resistor" and not branch.value)


def _stamp(
    matrix: _Matrix, branch: DCBranch, nodes: dict[str, int], current_index: int | None
) -> None:
    positive, negative = nodes.get(branch.positive), nodes.get(branch.negative)
    if current_index is not None:
        for node, sign in ((positive, _ONE), (negative, -_ONE)):
            matrix.stamp(node, current_index, sign)
            matrix.stamp(current_index, node, sign)
        matrix.inject(current_index, branch.value)
    elif branch.kind == "current":
        matrix.inject(positive, -branch.value)
        matrix.inject(negative, branch.value)
    else:
        conductance = matrix.work.divide(_ONE, branch.value)
        matrix.stamp(positive, positive, conductance)
        matrix.stamp(negative, negative, conductance)
        matrix.stamp(positive, negative, -conductance)
        matrix.stamp(negative, positive, -conductance)


def _outputs(
    branches: tuple[DCBranch, ...],
    voltages: dict[str, Fraction],
    source_indices: dict[str, int],
    solved: list[Fraction],
    work: _Work,
) -> tuple[tuple[tuple[str, Fraction], ...], tuple[tuple[str, Fraction], ...]]:
    currents: list[tuple[str, Fraction]] = []
    powers: list[tuple[str, Fraction]] = []
    residuals = dict.fromkeys(voltages, _ZERO)
    total_power = _ZERO
    for branch in branches:
        difference = work.add(voltages[branch.positive], -voltages[branch.negative])
        if branch.label in source_indices:
            current = solved[source_indices[branch.label]]
            if difference != branch.value:
                raise DCInputError("internal DC verification failed: ideal voltage residual")
        elif branch.kind == "current":
            current = branch.value
        else:
            current = work.divide(difference, branch.value)
        residuals[branch.positive] = work.add(residuals[branch.positive], current)
        residuals[branch.negative] = work.add(residuals[branch.negative], -current)
        power = work.multiply(difference, current)
        total_power = work.add(total_power, power)
        currents.append((branch.label, current))
        powers.append((branch.label, power))
    if any(residuals.values()) or total_power:
        raise DCInputError("internal DC verification failed: Kirchhoff current or power residual")
    return tuple(currents), tuple(powers)


def solve_linear_dc(
    branches: Iterable[DCBranch], *, ground: str = "0", limits: DCLimits = DEFAULT_DC_LIMITS
) -> DCSolution:
    """Solve and independently verify the unique ideal linear DC operating point.

    Names are exact, case-sensitive identifiers at this kernel boundary. Values
    are Fractions in SI units. A netlist adapter must preserve/normalize names
    explicitly and reject all unassessed device semantics before using this API.
    The entire input is validated and all physical residuals must be exactly zero
    before a result is returned. Budget failure never returns a partial solution.
    """
    checked, node_names = _input(branches, ground, limits)
    node_indices = {node: index for index, node in enumerate(n for n in node_names if n != ground)}
    source_indices = {
        branch.label: len(node_indices) + index
        for index, branch in enumerate(branch for branch in checked if _is_voltage(branch))
    }
    size = len(node_indices) + len(source_indices)
    if size > limits.max_unknowns:
        raise DCBudgetExceeded("DC unknown budget exhausted")
    work = _Work(limits)
    matrix = _Matrix(size, work)
    for branch in checked:
        _stamp(matrix, branch, node_indices, source_indices.get(branch.label))
    solved = matrix.solve()
    voltages = {node: solved[index] for node, index in node_indices.items()}
    voltages[ground] = _ZERO
    currents, powers = _outputs(checked, voltages, source_indices, solved, work)
    digest = sha256(b"schematic-airlock-linear-dc-v1\n")
    digest.update(json.dumps(ground, ensure_ascii=True).encode("ascii"))
    for branch in checked:
        digest.update(b"\n")
        digest.update(
            json.dumps(
                [branch.label, branch.kind, branch.positive, branch.negative, str(branch.value)],
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
    return DCSolution(
        f"sha256:{digest.hexdigest()}",
        ground,
        tuple(sorted(voltages.items())),
        currents,
        powers,
        size,
        work.operations,
        work.peak_nonzeros,
    )
