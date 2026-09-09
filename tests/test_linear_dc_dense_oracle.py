"""Independent exact dense oracle for the sparse linear-DC kernel.

This test deliberately does not import or reuse the production matrix implementation.
Its Gauss-Jordan elimination, equation storage, and result reconstruction are local to
the test so that it can detect sparse stamping, pivoting, and sign regressions.
"""

from __future__ import annotations

import random
from collections import Counter
from fractions import Fraction as F
from typing import Literal, TypeAlias

from schematic_airlock.linear_dc import (
    DCBranch,
    InconsistentDC,
    SingularDC,
    solve_linear_dc,
)

Status: TypeAlias = Literal["unique", "singular", "inconsistent"]
OracleValues: TypeAlias = tuple[dict[str, F], dict[str, F], dict[str, F]]


def _dense_oracle(
    branches: list[DCBranch], ground: str = "0"
) -> tuple[Status, OracleValues | None]:
    """Solve an independently assembled dense augmented matrix by Gauss-Jordan."""
    ordered = sorted(branches, key=lambda branch: branch.label)
    node_names = sorted(
        ({ground} | {name for branch in branches for name in (branch.positive, branch.negative)})
        - {ground}
    )
    node_indices = {name: index for index, name in enumerate(node_names)}
    ideal_voltage_branches = [
        branch
        for branch in ordered
        if branch.kind == "voltage" or (branch.kind == "resistor" and branch.value == 0)
    ]
    source_indices = {
        branch.label: len(node_indices) + index
        for index, branch in enumerate(ideal_voltage_branches)
    }
    size = len(node_indices) + len(source_indices)
    augmented = [[F(0) for _ in range(size + 1)] for _ in range(size)]

    for branch in ordered:
        positive = node_indices.get(branch.positive)
        negative = node_indices.get(branch.negative)
        source = source_indices.get(branch.label)
        if source is not None:
            if positive is not None:
                augmented[positive][source] += 1
                augmented[source][positive] += 1
            if negative is not None:
                augmented[negative][source] -= 1
                augmented[source][negative] -= 1
            augmented[source][-1] += branch.value
        elif branch.kind == "current":
            if positive is not None:
                augmented[positive][-1] -= branch.value
            if negative is not None:
                augmented[negative][-1] += branch.value
        else:
            conductance = 1 / branch.value
            if positive is not None:
                augmented[positive][positive] += conductance
            if negative is not None:
                augmented[negative][negative] += conductance
            if positive is not None and negative is not None:
                augmented[positive][negative] -= conductance
                augmented[negative][positive] -= conductance

    pivot_row = 0
    pivot_columns: list[int] = []
    for column in range(size):
        selected = next(
            (row for row in range(pivot_row, size) if augmented[row][column] != 0), None
        )
        if selected is None:
            continue
        augmented[pivot_row], augmented[selected] = augmented[selected], augmented[pivot_row]
        pivot = augmented[pivot_row][column]
        augmented[pivot_row] = [value / pivot for value in augmented[pivot_row]]
        for row in range(size):
            if row == pivot_row or augmented[row][column] == 0:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                value - factor * pivot_value
                for value, pivot_value in zip(augmented[row], augmented[pivot_row], strict=True)
            ]
        pivot_columns.append(column)
        pivot_row += 1

    if any(all(value == 0 for value in row[:-1]) and row[-1] != 0 for row in augmented):
        return "inconsistent", None
    if len(pivot_columns) != size:
        return "singular", None

    solved = [F(0)] * size
    for row, column in enumerate(pivot_columns):
        solved[column] = augmented[row][-1]
    voltages = {ground: F(0)} | {name: solved[index] for name, index in node_indices.items()}
    currents: dict[str, F] = {}
    powers: dict[str, F] = {}
    for branch in ordered:
        difference = voltages[branch.positive] - voltages[branch.negative]
        if branch.label in source_indices:
            current = solved[source_indices[branch.label]]
        elif branch.kind == "current":
            current = branch.value
        else:
            current = difference / branch.value
        currents[branch.label] = current
        powers[branch.label] = difference * current
    return "unique", (voltages, currents, powers)


def _generated_networks(case_count: int) -> list[list[DCBranch]]:
    rng = random.Random(20_731)
    networks: list[list[DCBranch]] = []
    for _ in range(case_count):
        nodes = ["0", *(f"n{index}" for index in range(rng.randrange(1, 6)))]
        branches: list[DCBranch] = []
        for index in range(rng.randrange(10)):
            kind = rng.choice(("resistor", "resistor", "voltage", "current"))
            value = F(rng.randrange(-3, 4), rng.randrange(1, 4))
            if kind == "resistor":
                value = abs(value)
            branches.append(
                DCBranch(
                    f"b{index}",
                    kind,
                    rng.choice(nodes),
                    rng.choice(nodes),
                    value,
                )
            )
        networks.append(branches)
    return networks


def _exercise(case_count: int) -> Counter[Status]:
    observed: Counter[Status] = Counter()
    for case, branches in enumerate(_generated_networks(case_count)):
        expected_status, expected_values = _dense_oracle(branches)
        try:
            actual = solve_linear_dc(branches)
            actual_status: Status = "unique"
        except SingularDC:
            actual_status = "singular"
            actual = None
        except InconsistentDC:
            actual_status = "inconsistent"
            actual = None
        assert actual_status == expected_status, (case, branches)
        observed[actual_status] += 1
        if actual_status == "unique":
            assert actual is not None
            assert expected_values is not None
            expected_voltages, expected_currents, expected_powers = expected_values
            assert dict(actual.voltages) == expected_voltages, case
            assert dict(actual.currents) == expected_currents, case
            assert dict(actual.powers) == expected_powers, case
            assert solve_linear_dc(reversed(branches)) == actual, case
    return observed


def test_seeded_mixed_networks_match_independent_dense_oracle() -> None:
    observed = _exercise(500)
    assert set(observed) == {"unique", "singular", "inconsistent"}


if __name__ == "__main__":
    print(dict(_exercise(10_000)))
