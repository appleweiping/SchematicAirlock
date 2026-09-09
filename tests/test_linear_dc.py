from __future__ import annotations

import random
from fractions import Fraction as F

import pytest

from schematic_airlock.linear_dc import (
    DCBranch,
    DCBudgetExceeded,
    DCInputError,
    DCLimits,
    InconsistentDC,
    SingularDC,
    solve_linear_dc,
)


def branch(label: str, kind: str, p: str, n: str, value: int | F) -> DCBranch:
    return DCBranch(label, kind, p, n, F(value))


def test_divider_exact_voltage_current_power_and_permutation() -> None:
    branches = [
        branch("v", "voltage", "rail", "0", 5),
        branch("r1", "resistor", "rail", "out", 2_000),
        branch("r2", "resistor", "out", "0", 3_000),
    ]
    result = solve_linear_dc(branches)
    assert dict(result.voltages) == {"0": F(0), "out": F(3), "rail": F(5)}
    assert dict(result.currents) == {"r1": F(1, 1000), "r2": F(1, 1000), "v": F(-1, 1000)}
    assert dict(result.powers) == {"r1": F(1, 500), "r2": F(3, 1000), "v": F(-1, 200)}
    assert sum(dict(result.powers).values()) == 0
    assert result == solve_linear_dc(reversed(branches))


def test_current_source_sign_and_zero_ohm_current() -> None:
    result = solve_linear_dc(
        [
            branch("i", "current", "0", "a", 2),
            branch("tie", "resistor", "a", "b", 0),
            branch("r", "resistor", "b", "0", 3),
        ]
    )
    assert dict(result.voltages) == {"0": F(0), "a": F(6), "b": F(6)}
    assert dict(result.currents) == {"i": F(2), "r": F(2), "tie": F(2)}


def test_floating_source_supernode_with_grounded_resistor() -> None:
    result = solve_linear_dc(
        [branch("v", "voltage", "a", "b", 4), branch("r", "resistor", "b", "0", 3)]
    )
    assert dict(result.voltages) == {"0": F(0), "a": F(4), "b": F(0)}
    assert dict(result.currents) == {"r": F(0), "v": F(0)}


@pytest.mark.parametrize(
    "branches,error",
    [
        ([branch("v", "voltage", "a", "b", 1)], SingularDC),
        ([branch("i", "current", "a", "0", 1)], InconsistentDC),
        ([branch("v", "voltage", "0", "0", 1)], InconsistentDC),
        ([branch("v", "voltage", "0", "0", 0)], SingularDC),
        (
            [branch("v", "voltage", "a", "0", 1), branch("w", "voltage", "a", "0", 2)],
            InconsistentDC,
        ),
        ([branch("v", "voltage", "a", "0", 1), branch("w", "voltage", "a", "0", 1)], SingularDC),
    ],
)
def test_inconsistent_and_underdetermined_are_not_solutions(
    branches: list[DCBranch], error: type[DCInputError]
) -> None:
    with pytest.raises(error):
        solve_linear_dc(branches)


def test_bounds_and_invalid_values_fail_explicitly() -> None:
    with pytest.raises(DCInputError):
        branch("r", "resistor", "0", "a", -1)
    with pytest.raises(DCInputError):
        branch("m", "mosfet", "0", "a", 1)
    with pytest.raises(DCInputError):
        DCBranch("i", "current", "0", "a", 1.0)  # type: ignore[arg-type]
    with pytest.raises(DCInputError):
        solve_linear_dc([branch("x", "resistor", "0", "a", 1)] * 2)
    with pytest.raises(DCBudgetExceeded):
        solve_linear_dc([branch("r", "resistor", "0", "a", 1)], limits=DCLimits(max_nodes=1))
    with pytest.raises(DCBudgetExceeded):
        solve_linear_dc([branch("r", "resistor", "0", "a", 1)], limits=DCLimits(max_operations=1))


def test_empty_ground_only_network() -> None:
    result = solve_linear_dc([], ground="ref")
    assert result.voltages == (("ref", F(0)),)
    assert result.currents == result.powers == ()


def test_seeded_resistor_meshes_match_manufactured_physical_solutions() -> None:
    rng = random.Random(916)
    for case in range(80):
        nodes = [f"n{index}" for index in range(rng.randrange(2, 9))]
        expected = {node: F(rng.randrange(-9, 10), rng.randrange(1, 5)) for node in nodes}
        expected["0"] = F(0)
        branches = [
            branch(f"r{index}", "resistor", node, "0", rng.randrange(1, 8))
            for index, node in enumerate(nodes)
        ]
        for index in range(rng.randrange(2, 20)):
            first, second = rng.sample(nodes, 2)
            branches.append(
                branch(f"cross{index}", "resistor", first, second, rng.randrange(1, 10))
            )
        injected = dict.fromkeys(nodes, F(0))
        expected_currents = {}
        for resistor in branches:
            current = (expected[resistor.positive] - expected[resistor.negative]) / resistor.value
            expected_currents[resistor.label] = current
            if resistor.positive != "0":
                injected[resistor.positive] += current
            if resistor.negative != "0":
                injected[resistor.negative] -= current
        # These sources are derived directly from a prescribed physical voltage
        # field and Ohm's law, without constructing or eliminating an MNA matrix.
        for node, current in injected.items():
            branches.append(branch(f"supply_{node}", "current", "0", node, current))
            expected_currents[f"supply_{node}"] = current
        result = solve_linear_dc(branches)
        assert dict(result.voltages) == expected, case
        assert dict(result.currents) == expected_currents, case
        rng.shuffle(branches)
        assert solve_linear_dc(branches) == result


def test_sparse_chain_does_not_allocate_a_dense_matrix() -> None:
    branches = [branch("v", "voltage", "n0", "0", 12)]
    branches.extend(
        branch(f"r{index:04d}", "resistor", f"n{index}", f"n{index + 1}", 2) for index in range(300)
    )
    branches.append(branch("rground", "resistor", "n300", "0", 2))
    result = solve_linear_dc(branches)
    assert dict(result.voltages)["n150"] == F(12 * 151, 301)
    assert dict(result.currents)["rground"] == F(6, 301)
    assert result.peak_nonzeros < 8 * result.unknowns
    assert result.operations < 100 * result.unknowns


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "3", 100_000_001])
def test_limit_types_and_hard_caps(value: object) -> None:
    with pytest.raises(DCInputError):
        DCLimits(max_operations=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["", " ", "x\n", "e\u0301", "x\u202e", "x\ud800", "x" * 1025])
def test_names_are_exact_bounded_display_safe_tokens(name: str) -> None:
    with pytest.raises(DCInputError):
        branch(name, "resistor", "a", "0", 1)


@pytest.mark.parametrize(
    "limits,match",
    [
        (DCLimits(max_branches=1), "branch"),
        (DCLimits(max_unknowns=1), "unknown"),
        (DCLimits(max_nonzeros=1), "fill"),
        (DCLimits(max_name_bytes=1), "name byte"),
    ],
)
def test_resource_budget_failure_never_returns_partial_values(limits: DCLimits, match: str) -> None:
    with pytest.raises(DCBudgetExceeded, match=match):
        solve_linear_dc(
            [branch("v", "voltage", "a", "0", 1), branch("r", "resistor", "a", "0", 1)],
            limits=limits,
        )


def test_rational_budget_applies_before_and_during_elimination() -> None:
    with pytest.raises(DCBudgetExceeded, match="rational"):
        branch("r", "resistor", "a", "0", F(2**4096))
    huge = F(2**3000)
    with pytest.raises(DCBudgetExceeded, match="rational"):
        solve_linear_dc(
            [branch("v", "voltage", "a", "0", huge), branch("r", "resistor", "a", "0", 1 / huge)]
        )


def test_ground_only_self_branches_do_not_invent_injection() -> None:
    result = solve_linear_dc(
        [branch("r", "resistor", "0", "0", 3), branch("i", "current", "0", "0", -2)]
    )
    assert result.voltages == (("0", F(0)),)
    assert dict(result.currents) == {"i": F(-2), "r": F(0)}
    assert all(value == 0 for _, value in result.powers)
    with pytest.raises(DCBudgetExceeded):
        solve_linear_dc([], ground="reference", limits=DCLimits(max_name_bytes=1))


def test_invalid_branch_or_limits_objects_fail_typed() -> None:
    with pytest.raises(DCInputError, match="iterable"):
        solve_linear_dc(None)  # type: ignore[arg-type]
    with pytest.raises(DCInputError):
        solve_linear_dc([None])  # type: ignore[list-item]
    with pytest.raises(DCInputError):
        solve_linear_dc([], limits=None)  # type: ignore[arg-type]


def test_physical_residual_verification_rejects_a_corrupted_solver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from schematic_airlock import linear_dc

    monkeypatch.setattr(linear_dc._Matrix, "solve", lambda self: [F(2), F(-1)])
    branches = [branch("v", "voltage", "a", "0", 1), branch("r", "resistor", "a", "0", 1)]
    with pytest.raises(DCInputError, match="voltage residual"):
        solve_linear_dc(branches)
    monkeypatch.setattr(linear_dc._Matrix, "solve", lambda self: [F(1), F(-2)])
    with pytest.raises(DCInputError, match="current or power residual"):
        solve_linear_dc(branches)
