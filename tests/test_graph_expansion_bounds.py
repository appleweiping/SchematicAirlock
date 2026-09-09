from __future__ import annotations

import pytest

from schematic_airlock.bundle import MemoryBundle
from schematic_airlock.circuit_graph import build_circuit_graph
from schematic_airlock.dc_netlist import solve_dc_text
from schematic_airlock.include_graph import load_include_graph
from schematic_airlock.linear_dc import DCLimits


@pytest.mark.parametrize("cap", [1, 3, 17])
@pytest.mark.parametrize("hierarchy", ["flat", "siblings", "nested"])
def test_expanded_materialization_never_exceeds_the_budget(cap: int, hierarchy: str) -> None:
    primitives = "\n".join(f"R{i} p n 1k" for i in range(200))
    if hierarchy == "flat":
        text = primitives
    elif hierarchy == "siblings":
        text = (
            "\n".join(f"X{i} a 0 cell" for i in range(20))
            + f"\n.subckt cell p n\n{primitives}\n.ends\n"
        )
    else:
        text = (
            "X1 a 0 wrapper\nX2 b 0 wrapper\n.subckt wrapper p n\n"
            "X1 p n cell\nX2 p n cell\n.ends\n"
            f".subckt cell p n\n{primitives}\n.ends\n"
        )
    graph = build_circuit_graph(
        load_include_graph(MemoryBundle(text, "bounds.sp")), max_expanded_instances=cap
    )
    # The static definition graph remains available for diagnostics, but copies
    # of reached instances must stop before the next instance is materialized.
    assert len(graph.devices) >= 200
    assert graph.expanded_instances > cap
    assert len(graph.expanded_devices) == cap
    report = solve_dc_text(text, limits=DCLimits(max_branches=cap))
    assert report.status == "budget-exceeded" and report.solution is None


def test_exact_expansion_budget_retains_all_devices_and_diagnostics() -> None:
    text = "X1 a 0 cell\nX2 b 0 cell\n.subckt cell p n\nR1 p n 1k\n.ends\n"
    graph = build_circuit_graph(
        load_include_graph(MemoryBundle(text, "bounds.sp")), max_expanded_instances=4
    )
    assert graph.expanded_instances == 4
    assert len(graph.expanded_devices) == 4
    assert not graph.issues
    assert {item.qualified_name for item in graph.expanded_devices} == {
        "top/X1",
        "top/X2",
        "top/X1/R1",
        "top/X2/R1",
    }
