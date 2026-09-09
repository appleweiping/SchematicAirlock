from __future__ import annotations

import itertools
import random
from fractions import Fraction as F

import pytest

from schematic_airlock.voltage_constraints import (
    InconsistentVoltages,
    VoltageBudgetExceeded,
    VoltageConstraint,
    VoltageConstraintError,
    VoltageInterval,
    VoltageLimits,
    VoltageSystem,
    volts,
)


def constraint(
    positive: str, negative: str, lower: int | None, upper: int | None, label: str
) -> VoltageConstraint:
    return VoltageConstraint(
        positive,
        negative,
        VoltageInterval(
            F(lower) if lower is not None else None, F(upper) if upper is not None else None
        ),
        label,
    )


def test_exact_chain_ground_shift_and_floating_correlation() -> None:
    system = VoltageSystem(
        ["0", "rail", "boost", "a", "b", "isolated"],
        [
            constraint("rail", "0", 3, 3, "v1"),
            constraint("boost", "rail", 2, 2, "v2"),
            constraint("a", "b", -4, -4, "v3"),
        ],
    )
    assert system.difference("boost", "0") == VoltageInterval(F(5), F(5))
    assert system.difference("0", "boost") == VoltageInterval(F(-5), F(-5))
    assert system.difference("a", "b") == VoltageInterval(F(-4), F(-4))
    assert system.difference("a", "0") == VoltageInterval(None, None)
    assert system.difference("isolated", "isolated") == VoltageInterval(F(0), F(0))
    assert system.component_count == 3


def test_interval_paths_retain_shared_source_correlation() -> None:
    system = VoltageSystem(
        ["0", "rail", "shift", "gate"],
        [
            constraint("rail", "0", 2, 4, "v1"),
            constraint("shift", "rail", 1, 2, "v2"),
            constraint("gate", "rail", 1, 1, "v3"),
        ],
    )
    assert system.difference("shift", "0") == VoltageInterval(F(3), F(6))
    assert system.difference("gate", "rail") == VoltageInterval(F(1), F(1))
    assert system.difference("shift", "gate") == VoltageInterval(F(0), F(1))
    assert system.difference("0", "shift") == VoltageInterval(F(-6), F(-3))


def test_one_sided_bounds_and_parallel_edges_choose_tightest() -> None:
    system = VoltageSystem(
        ["a", "b"],
        [constraint("a", "b", None, 9, "loose"), constraint("a", "b", None, 3, "tight")],
    )
    assert system.difference("a", "b") == VoltageInterval(None, F(3))
    assert system.difference("b", "a") == VoltageInterval(F(-3), None)
    assert not system.difference("a", "b").bounded


@pytest.mark.parametrize(
    "declarations",
    [
        [constraint("a", "b", 1, 1, "v1"), constraint("a", "b", 2, 2, "v2")],
        [constraint("a", "b", 1, 1, "v1"), constraint("a", "b", 2, 3, "v2")],
        [constraint("a", "b", 1, 1, "v1"), constraint("a", "b", -3, -2, "v2")],
        [
            constraint("a", "b", 2, 3, "v1"),
            constraint("b", "c", 2, 3, "v2"),
            constraint("a", "c", -1, 3, "v3"),
        ],
        [constraint("a", "a", 1, 2, "self")],
    ],
)
def test_exact_and_interval_contradictions(declarations: list[VoltageConstraint]) -> None:
    with pytest.raises(InconsistentVoltages):
        VoltageSystem(["a", "b", "c"], declarations)


def test_redundant_exact_loop_and_self_constraint_are_consistent() -> None:
    system = VoltageSystem(
        ["a", "b", "c"],
        [
            constraint("a", "b", 1, 1, "v1"),
            constraint("b", "c", 2, 2, "v2"),
            constraint("a", "c", 3, 3, "v3"),
            constraint("a", "a", -1, 1, "self"),
        ],
    )
    assert system.difference("a", "c") == VoltageInterval(F(3), F(3))


def test_seeded_graphs_match_independent_floyd_warshall_oracle() -> None:
    # Independent dense all-pairs algorithm, including infeasible cycles. The
    # implementation instead eliminates equalities and uses sparse reweighting.
    rng = random.Random(27)
    names = ["a", "b", "c", "d", "e"]
    for _ in range(180):
        distances: list[list[F | None]] = [
            [F(0) if row == column else None for column in range(5)] for row in range(5)
        ]
        declarations = []
        for index in range(rng.randrange(1, 16)):
            positive, negative = rng.sample(range(5), 2)
            low = rng.randrange(-4, 5)
            high = low + rng.randrange(0, 5)
            declarations.append(constraint(names[positive], names[negative], low, high, str(index)))
            for source, target, weight in (
                (negative, positive, F(high)),
                (positive, negative, F(-low)),
            ):
                old = distances[source][target]
                distances[source][target] = weight if old is None else min(old, weight)
        for middle, source, target in itertools.product(range(5), repeat=3):
            first, second = distances[source][middle], distances[middle][target]
            if first is not None and second is not None:
                old = distances[source][target]
                distances[source][target] = (
                    first + second if old is None else min(old, first + second)
                )
        if any(distances[index][index] < 0 for index in range(5)):  # type: ignore[operator]
            with pytest.raises(InconsistentVoltages):
                VoltageSystem(names, declarations)
            continue
        system = VoltageSystem(names, declarations)
        for positive, negative in itertools.product(range(5), repeat=2):
            reverse = distances[positive][negative]
            assert system.difference(names[positive], names[negative]) == VoltageInterval(
                -reverse if reverse is not None else None, distances[negative][positive]
            )


def test_exact_arithmetic_is_not_decimal_context_or_float_dependent() -> None:
    tiny = volts("0.00000000000000000000000000000000000000000000000001")
    system = VoltageSystem(
        ["0", "a", "b"],
        [
            VoltageConstraint("a", "0", VoltageInterval(F(1), F(1)), "one"),
            VoltageConstraint("b", "a", VoltageInterval(tiny, tiny), "tiny"),
        ],
    )
    result = system.difference("b", "0")
    assert result.lower == 1 + tiny
    assert result.lower != F(1)
    assert result.as_dict()["lower_volts"] == str(1 + tiny)
    assert result.bounded


def test_large_exact_chain_eliminates_all_edges_without_quadratic_storage() -> None:
    count = 20_000
    system = VoltageSystem(
        (str(index) for index in range(count + 1)),
        (constraint(str(index), str(index - 1), 1, 1, str(index)) for index in range(1, count + 1)),
        limits=VoltageLimits(max_edge_visits=1),
    )
    assert system.component_count == 1
    assert system.edge_visits == 0
    assert system.difference(str(count), "0") == VoltageInterval(F(count), F(count))


@pytest.mark.parametrize(
    "text", ["nan", "inf", "1/2", "1.2V", " 1", "1 ", "", "1e101", "1e-101", "1e9999", "0" * 129]
)
def test_invalid_decimal_volts(text: str) -> None:
    with pytest.raises(VoltageConstraintError):
        volts(text)


@pytest.mark.parametrize(
    "text,expected",
    [("0", F(0)), ("-2.5", F(-5, 2)), ("1e-100", F(1, 10**100)), ("1e100", F(10**100))],
)
def test_decimal_volts(text: str, expected: F) -> None:
    assert volts(text) == expected


def test_runtime_validation_and_budget_fail_closed() -> None:
    with pytest.raises(VoltageConstraintError, match="Fraction"):
        VoltageInterval(0.1, None)  # type: ignore[arg-type]
    with pytest.raises(VoltageConstraintError, match="lower"):
        VoltageInterval(F(2), F(1))
    with pytest.raises(VoltageBudgetExceeded, match="bit"):
        VoltageInterval(F(2**4096), None)
    with pytest.raises(VoltageConstraintError, match="finite"):
        VoltageConstraint("a", "b", VoltageInterval(None, None), "x")
    with pytest.raises(VoltageConstraintError, match="interval"):
        VoltageConstraint("a", "b", None, "x")  # type: ignore[arg-type]
    with pytest.raises(VoltageConstraintError, match="nonblank"):
        VoltageSystem(["a b"], [])
    with pytest.raises(VoltageConstraintError, match="limits"):
        VoltageSystem([], [], limits=None)  # type: ignore[arg-type]
    with pytest.raises(VoltageConstraintError, match="VoltageConstraint"):
        VoltageSystem([], [None])  # type: ignore[list-item]
    with pytest.raises(VoltageConstraintError, match="unknown"):
        VoltageSystem(["a"], [constraint("a", "b", 0, 0, "x")])
    item = constraint("a", "b", 0, 0, "x")
    with pytest.raises(VoltageConstraintError, match="duplicate"):
        VoltageSystem(["a", "b"], [item, item])
    with pytest.raises(VoltageBudgetExceeded, match="node"):
        VoltageSystem(["a", "b"], [], limits=VoltageLimits(max_nodes=1))
    with pytest.raises(VoltageBudgetExceeded, match="constraint"):
        VoltageSystem(
            ["a", "b"],
            [item, constraint("a", "b", 0, 1, "y")],
            limits=VoltageLimits(max_constraints=1),
        )
    with pytest.raises(VoltageBudgetExceeded, match="edge"):
        VoltageSystem(
            ["a", "b"], [constraint("a", "b", 1, 2, "x")], limits=VoltageLimits(max_edge_visits=1)
        )
    system = VoltageSystem(
        ["a", "b"], [constraint("a", "b", 0, 1, "x")], limits=VoltageLimits(max_edge_visits=3)
    )
    with pytest.raises(VoltageBudgetExceeded, match="edge"):
        system.difference("a", "b")
    with pytest.raises(VoltageBudgetExceeded, match="already"):
        system.difference("a", "a")
    system = VoltageSystem(["a"], [], limits=VoltageLimits(max_queries=1))
    assert system.difference("a", "a").bounded
    with pytest.raises(VoltageBudgetExceeded, match="query"):
        system.difference("a", "a")
    with pytest.raises(VoltageConstraintError, match="unknown"):
        VoltageSystem([], []).difference("a", "a")


@pytest.mark.parametrize("value", [True, 0, -1, 2.0, 3_000_001])
def test_limit_validation(value: int) -> None:
    with pytest.raises(VoltageConstraintError):
        VoltageLimits(max_nodes=value)


@pytest.mark.parametrize(
    "name",
    ["a\u202eb", "a\u2066b", "a\u200bb", "a\u2028b", "a\u2029b", "a\u00a0b", "e\u0301", "a\ud800"],
)
def test_node_and_label_cannot_contain_display_controls(name: str) -> None:
    with pytest.raises(VoltageConstraintError):
        VoltageSystem([name], [])
    with pytest.raises(VoltageConstraintError):
        VoltageConstraint("a", "b", VoltageInterval(F(0), F(0)), name)


def test_duplicate_node_input_is_rejected_before_unbounded_duplicate_stream() -> None:
    with pytest.raises(VoltageConstraintError, match="duplicate"):
        VoltageSystem(itertools.repeat("a"), [])


def test_benchmark_checks_closed_form_and_binds_implementation() -> None:
    import hashlib
    import runpy
    from pathlib import Path

    import schematic_airlock.voltage_constraints as implementation

    run = runpy.run_path("benchmarks/voltage_constraints.py")["run"]
    result = run(10, 1)
    assert result["closed_form_oracle_passed"] is True
    assert result["observed"] == {"lower_volts": "1/100", "upper_volts": "1/100"}
    assert (
        result["implementation_sha256"]
        == hashlib.sha256(Path(implementation.__file__).read_bytes()).hexdigest()
    )
    assert result["peak_python_traced_bytes"] > 0
    assert result["edge_visits"] == 0
    for count, repetitions in ((True, 1), (0, 1), (1_000_001, 1), (1, 0), (1, False), (1, 11)):
        with pytest.raises(ValueError):
            run(count, repetitions)
