"""Operating points a simulator would refuse, caught before it is started."""

from __future__ import annotations

import pytest

from schematic_airlock.bundle import MemoryBundle
from schematic_airlock.checks import CheckContext, run_checks
from schematic_airlock.circuit_graph import build_circuit_graph
from schematic_airlock.domain import Severity
from schematic_airlock.engine import audit_text
from schematic_airlock.include_graph import load_include_graph
from schematic_airlock.parse import Element, SourceLocation
from schematic_airlock.policy import AuditPolicy
from schematic_airlock.solvability import (
    MAX_REPORTED_NODES,
    conducting_pairs,
    floating_islands,
    has_ground,
    voltage_source_loops,
)

LOCATION = SourceLocation(path="t.sp", line=1)


def context(text: str, policy: AuditPolicy | None = None) -> CheckContext:
    bundle = MemoryBundle(text, "test.sp")
    includes = load_include_graph(bundle)
    selected = policy or AuditPolicy()
    graph = build_circuit_graph(
        includes, max_expanded_instances=selected.limits.max_expanded_instances
    )
    return CheckContext(bundle, includes, graph, selected)


def codes(text: str, policy: AuditPolicy | None = None) -> list[str]:
    return [finding.code for finding in run_checks(context(text, policy))]


def element(name: str, *nodes: str, model: str | None = None) -> tuple[str, Element]:
    return (
        name,
        Element(
            name=name,
            kind=name[0].upper(),
            nodes=tuple(nodes),
            value=None,
            model=model,
            arguments=(),
            parameters=(),
            location=LOCATION,
            raw=name,
        ),
    )


# ---------------------------------------------------------------------------
# What conducts at DC.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["R", "L", "V", "D", "E", "H"])
def test_a_two_terminal_conductor_ties_its_nodes(kind: str) -> None:
    _name, item = element(f"{kind}1", "a", "b")
    assert conducting_pairs(item) == (("a", "b"),)


@pytest.mark.parametrize("kind", ["C", "I", "G", "F", "K"])
def test_a_capacitor_or_ideal_current_source_ties_nothing(kind: str) -> None:
    """The whole point of the check.

    A capacitor is open at DC, and forcing a current through a node says
    nothing about its potential.
    """

    _name, item = element(f"{kind}1", "a", "b")
    assert conducting_pairs(item) == ()


def test_a_mos_gate_is_insulated_and_the_rest_of_it_is_not() -> None:
    _name, item = element("M1", "d", "g", "s", "b")
    pairs = set(conducting_pairs(item))
    assert ("d", "s") in pairs
    assert ("d", "b") in pairs and ("s", "b") in pairs
    assert not any("g" in pair for pair in pairs)


def test_a_bipolar_base_conducts_because_it_is_a_junction() -> None:
    _name, item = element("Q1", "c", "b", "e")
    assert ("c", "b") in set(conducting_pairs(item))


def test_a_transistor_with_missing_terminals_does_not_index_past_them() -> None:
    _name, item = element("M1", "d", "g", "s")
    assert set(conducting_pairs(item)) == {("d", "s")}


def test_an_unexpanded_subcircuit_is_assumed_to_connect_its_pins() -> None:
    """The assumption that cannot produce a false accusation.

    Nothing here can see inside a subcircuit that failed to expand. Assuming it
    isolates its pins would refuse an artifact because part of it was
    unreadable; assuming it connects them can only hide a defect.
    """

    _name, item = element("X1", "a", "b", "c", model="amp")
    assert set(conducting_pairs(item)) == {("a", "b"), ("a", "c"), ("b", "c")}


def test_a_one_terminal_element_ties_nothing() -> None:
    _name, item = element("R1", "a")
    assert conducting_pairs(item) == ()


# ---------------------------------------------------------------------------
# Reaching ground.
# ---------------------------------------------------------------------------


def test_a_divider_to_ground_is_fully_referenced() -> None:
    elements = [element("V1", "in", "0"), element("R1", "in", "mid"), element("R2", "mid", "0")]
    assert floating_islands(elements, ("0",)) == ()


def test_a_node_reachable_only_through_a_capacitor_is_stranded() -> None:
    elements = [element("V1", "in", "0"), element("C1", "in", "sum"), element("R1", "sum", "out")]
    islands = floating_islands(elements, ("0",))
    assert len(islands) == 1
    assert set(islands[0].nodes) == {"sum", "out"}


def test_a_stranded_island_names_the_devices_that_touch_it() -> None:
    elements = [element("V1", "in", "0"), element("C1", "in", "a"), element("R9", "a", "b")]
    assert floating_islands(elements, ("0",))[0].devices == ("C1", "R9")


def test_a_current_source_cannot_reference_a_node_on_its_own() -> None:
    elements = [element("V1", "in", "0"), element("I1", "in", "hang")]
    assert len(floating_islands(elements, ("0",))) == 1


def test_a_gate_resistor_rescues_a_gate_that_only_had_capacitors() -> None:
    common = [element("V1", "d", "0"), element("M1", "d", "g", "s", "0"), element("R1", "s", "0")]
    assert len(floating_islands([*common, element("C1", "g", "d")], ("0",))) == 1
    assert floating_islands([*common, element("R2", "g", "0")], ("0",)) == ()


def test_a_configured_ground_name_counts_as_ground() -> None:
    elements = [element("R1", "a", "vss")]
    assert floating_islands(elements, ("0", "vss")) == ()
    assert len(floating_islands(elements, ("0",))) == 1


def test_a_scoped_ground_inside_a_subcircuit_is_recognized() -> None:
    # Expansion prefixes nets with their instance path; ground must still match.
    elements = [element("R1", "x1:a", "x1:gnd")]
    assert floating_islands(elements, ("0", "gnd")) == ()


def test_a_deck_that_never_mentions_ground_is_detected_separately() -> None:
    fragment = [element("R1", "a", "b"), element("R2", "b", "c")]
    assert not has_ground(fragment, ("0", "gnd"))
    assert has_ground([element("R1", "a", "0")], ("0",))


def test_a_long_island_abbreviates_its_node_list() -> None:
    elements = [element("V1", "in", "0"), element("C1", "in", "n0")]
    elements += [element(f"R{i}", f"n{i}", f"n{i + 1}") for i in range(MAX_REPORTED_NODES + 4)]
    island = floating_islands(elements, ("0",))[0]
    assert len(island.nodes) > MAX_REPORTED_NODES
    assert "more" in island.summary
    assert island.summary.count(",") == MAX_REPORTED_NODES


# ---------------------------------------------------------------------------
# Voltage source loops.
# ---------------------------------------------------------------------------


def test_three_sources_around_a_loop_are_found() -> None:
    elements = [
        element("V1", "a", "b"),
        element("V2", "b", "c"),
        element("V3", "c", "a"),
        element("R1", "a", "0"),
    ]
    loops = voltage_source_loops(elements)
    assert len(loops) == 1
    assert loops[0].devices == ("V1", "V2", "V3")


def test_a_loop_names_every_source_in_it_not_just_the_closing_edge() -> None:
    """The closing edge alone is not something an engineer can act on."""

    loops = voltage_source_loops(
        [element("V1", "a", "b"), element("V2", "b", "c"), element("V3", "c", "a")]
    )
    assert set(loops[0].devices) == {"V1", "V2", "V3"}
    assert set(loops[0].nodes) == {"a", "b", "c"}


def test_parallel_sources_are_the_same_defect_at_two_nodes() -> None:
    loops = voltage_source_loops([element("V1", "a", "0"), element("V2", "a", "0")])
    assert len(loops) == 1


def test_sources_in_series_without_a_loop_are_left_alone() -> None:
    elements = [element("V1", "a", "0"), element("V2", "b", "a"), element("R1", "b", "0")]
    assert voltage_source_loops(elements) == ()


def test_a_resistor_in_the_loop_makes_it_solvable() -> None:
    elements = [element("V1", "a", "b"), element("V2", "b", "c"), element("R1", "c", "a")]
    assert voltage_source_loops(elements) == ()


def test_one_finding_per_independent_cycle() -> None:
    # Four sources over a triangle plus a chord close two independent loops.
    elements = [
        element("V1", "a", "b"),
        element("V2", "b", "c"),
        element("V3", "c", "a"),
        element("V4", "a", "b"),
    ]
    assert len(voltage_source_loops(elements)) == 2


def test_a_source_shorted_to_itself_is_not_a_loop() -> None:
    assert voltage_source_loops([element("V1", "a", "a")]) == ()


# ---------------------------------------------------------------------------
# Through the gate.
# ---------------------------------------------------------------------------


CHARGE_AMP = """* charge amplifier with a floating summing node
V1 in 0 DC 1
C1 in sum 1p
C2 sum out 1p
R1 out 0 10k
.op
.end
"""

SOURCE_LOOP = """* three ideal sources around a loop
V1 a b DC 1
V2 b c DC 1
V3 c a DC 1
R1 a 0 1k
.op
.end
"""

GOOD_DIVIDER = """* an ordinary divider
V1 in 0 DC 1
R1 in mid 1k
R2 mid 0 1k
.op
.end
"""


def test_a_capacitively_coupled_node_is_denied() -> None:
    report = audit_text(CHARGE_AMP)
    assert "SOLVE002" in {finding.code for finding in report.findings}
    denied = [item for item in report.findings if item.code == "SOLVE002"]
    assert denied[0].severity is Severity.DENY
    assert "sum" in denied[0].message


def test_a_source_loop_is_denied_and_names_its_sources() -> None:
    findings = {item.code: item for item in audit_text(SOURCE_LOOP).findings}
    assert "SOLVE003" in findings
    # Names are scope-qualified, because a flattened netlist can hold many
    # instances of one subcircuit and a bare `V1` would not say which.
    assert findings["SOLVE003"].metadata["sources"] == ["top/V1", "top/V2", "top/V3"]


def test_an_ordinary_divider_raises_no_solvability_finding() -> None:
    assert not [code for code in codes(GOOD_DIVIDER) if code.startswith("SOLVE")]


def test_a_deck_with_no_ground_earns_one_finding_not_one_per_node() -> None:
    """A naming mismatch is one problem, however many nodes it strands."""

    reported = [code for code in codes("R1 a b 1k\nR2 b c 1k\n.end\n") if code.startswith("SOLVE")]
    assert reported == ["SOLVE001"]


def test_a_deck_with_no_elements_raises_nothing() -> None:
    assert not [code for code in codes(".end\n") if code.startswith("SOLVE")]


def test_a_subcircuit_library_that_is_never_called_raises_nothing() -> None:
    # Nothing is expanded, so there is no flattened circuit to reference.
    text = ".subckt amp a b\nR1 a b 1k\n.ends\n.end\n"
    assert not [code for code in codes(text) if code.startswith("SOLVE")]


def test_the_policy_can_downgrade_a_solvability_finding() -> None:
    policy = AuditPolicy.from_mapping({"rules": {"severity_overrides": {"SOLVE002": "info"}}})
    findings = {item.code: item for item in run_checks(context(CHARGE_AMP, policy))}
    assert findings["SOLVE002"].severity is Severity.INFO


def test_the_finding_says_what_does_not_provide_a_dc_path() -> None:
    findings = {item.code: item for item in audit_text(CHARGE_AMP).findings}
    assert "capacitor" in findings["SOLVE002"].remediation
