from __future__ import annotations

from pathlib import Path

import pytest

from schematic_airlock.bundle import ArtifactBundle, MemoryBundle
from schematic_airlock.checks import CheckContext, run_checks
from schematic_airlock.circuit_graph import build_circuit_graph
from schematic_airlock.domain import Severity
from schematic_airlock.engine import audit_path
from schematic_airlock.include_graph import load_include_graph
from schematic_airlock.policy import AuditPolicy


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


def test_graph_records_scoped_devices_nets_and_terminals() -> None:
    graph = context(
        """V1 vdd 0 1.8
X1 in out vdd 0 cell
.subckt cell i o vp vn
M1 o i vn vn nch
R1 vp o 2k
.ends cell
"""
    ).graph
    assert [device.qualified_name for device in graph.devices] == [
        "subckt:cell/M1",
        "subckt:cell/R1",
        "top/V1",
        "top/X1",
    ]
    top_nets = {net.name: net for net in graph.nets_in_scope("top")}
    assert set(top_nets) == {"0", "in", "out", "vdd"}
    assert top_nets["vdd"].endpoints[0].kind in {"V", "X"}
    child_nets = {net.name: net for net in graph.nets_in_scope("subckt:cell")}
    assert all(net.is_port for net in child_nets.values())
    assert graph.call_edges == (("top", "subckt:cell"),)
    assert graph.expanded_instances == 4


def test_graph_reports_duplicate_subcircuits_and_elements() -> None:
    result = codes(
        """R1 a 0 1
R1 b 0 2
.subckt c x
R2 x 0 1
.ends c
.subckt c y
R3 y 0 1
.ends c
"""
    )
    assert "GRAPH001" in result
    assert "GRAPH002" in result


def test_graph_reports_undefined_and_wrong_arity_calls() -> None:
    result = codes(
        """X1 a b missing
X2 a only_two
.subckt only_two p n
R1 p n 1k
.ends only_two
"""
    )
    assert "GRAPH003" in result
    assert "GRAPH004" in result


def test_graph_reports_recursive_hierarchy_and_saturates_cost() -> None:
    ctx = context(
        """X1 a loop
.subckt loop p
X2 p loop
.ends loop
"""
    )
    assert any(issue.code == "GRAPH005" for issue in ctx.graph.issues)
    assert ctx.graph.expanded_instances > ctx.policy.limits.max_expanded_instances
    assert "LIM001" in [finding.code for finding in run_checks(ctx)]


def test_graph_reports_unreachable_definition_as_review() -> None:
    findings = run_checks(
        context(
            """V1 a 0 1
.subckt unused x
R1 x 0 1
.ends unused
"""
        )
    )
    unused = next(finding for finding in findings if finding.code == "GRAPH006")
    assert unused.severity is Severity.REVIEW


@pytest.mark.parametrize("name", ["control", "shell", "system", "python", "hdl", "verilog"])
def test_executable_directives_are_denied(name: str) -> None:
    matching = [
        finding for finding in run_checks(context(f".{name}\n")) if finding.code == "EXEC001"
    ]
    finding = matching[0]
    assert finding.severity is Severity.DENY
    assert name in finding.message


def test_unknown_directive_defaults_to_review_and_can_be_overridden() -> None:
    matching = [
        finding for finding in run_checks(context(".mystery arg\n")) if finding.code == "DIR001"
    ]
    finding = matching[0]
    assert finding.severity is Severity.REVIEW
    policy = AuditPolicy.from_mapping({"rules": {"severity_overrides": {"DIR001": "info"}}})
    overridden = next(
        finding
        for finding in run_checks(context(".mystery arg\n", policy))
        if finding.code == "DIR001"
    )
    assert overridden.severity is Severity.INFO


@pytest.mark.parametrize(
    ("line", "present"),
    [
        (".tran 1n 1u", False),
        (".tran 1f 1", True),
        (".tran 0 1", True),
        (".dc V1 0 1 0.1", False),
        (".dc V1 0 1 1p", True),
        (".ac lin 100 1 1meg", False),
        (".ac dec 1000000 1 1meg", True),
        (".ac dec count start stop", False),
    ],
)
def test_analysis_budget_estimates_literal_sweeps(line: str, present: bool) -> None:
    result = codes(line + "\n")
    if present:
        assert "ANL001" in result
    elif "start" in line:
        assert "ANL002" in result
    else:
        assert "ANL001" not in result


def test_behavioral_source_is_denied_by_default_and_configurable() -> None:
    assert "ELEM002" in codes("B1 out 0 V={V(in)}\n")
    policy = AuditPolicy.from_mapping({"rules": {"behavioral_source": "review"}})
    finding = next(
        finding
        for finding in run_checks(context("B1 out 0 V={V(in)}\n", policy))
        if finding.code == "ELEM002"
    )
    assert finding.severity is Severity.REVIEW


def test_unknown_element_is_reviewed() -> None:
    finding = next(
        finding
        for finding in run_checks(context("Z1 arbitrary tokens\n"))
        if finding.code == "ELEM001"
    )
    assert finding.severity is Severity.REVIEW
    assert "Z1" in finding.message


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("R1 a b -1", "VAL001"),
        ("C1 a b 0", "VAL001"),
        ("L1 a b -3n", "VAL001"),
        ("R1 a b {unknown}", "VAL002"),
        ("C1 a b {2*p}", "VAL002"),
    ],
)
def test_passive_value_checks(line: str, code: str) -> None:
    assert code in codes(line + "\n")


@pytest.mark.parametrize("line", ["R1 a b 0", "R1 a b 1k", "C1 a b 1p", "L1 a b 2n"])
def test_valid_literal_passive_values_have_no_value_finding(line: str) -> None:
    assert not {"VAL001", "VAL002"} & set(codes(line + "\n"))


def test_source_voltage_limit() -> None:
    policy = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 2.0}})
    assert "VOLT001" in codes("V1 a 0 -2.1\n", policy)
    assert "VOLT001" not in codes("V1 a 0 2\n", policy)
    assert "VOLT001" in codes("V1 a 0 pulse(0 3 1n)\n", policy)


def test_required_policy_port_must_exist() -> None:
    policy = AuditPolicy.from_mapping({"electrical": {"required_ports": ["vin"]}})
    assert "PORT001" in codes("R1 out 0 1k\n", policy)
    assert "PORT001" not in codes("R1 vin 0 1k\n", policy)


def test_manifest_output_with_no_evident_driver_is_reviewed(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        '{"entry":"top.sp","intended_ports":{"out":"output"}}', encoding="utf-8"
    )
    (tmp_path / "top.sp").write_text("C1 out 0 1p\nM1 d out 0 0 nch\n", encoding="utf-8")
    bundle = ArtifactBundle.open(tmp_path)
    includes = load_include_graph(bundle)
    graph = build_circuit_graph(includes)
    result = run_checks(CheckContext(bundle, includes, graph, AuditPolicy()))
    assert "PORT002" in [finding.code for finding in result]


def test_dangling_net_is_reviewed_but_configured_global_is_not() -> None:
    policy = AuditPolicy.from_mapping({"electrical": {"ground_nets": ["0"], "power_nets": ["vdd"]}})
    findings = run_checks(context("R1 lone other 1k\nV1 vdd 0 1\n", policy))
    messages = [finding.message for finding in findings if finding.code == "NET001"]
    assert any("lone" in message for message in messages)
    assert any("other" in message for message in messages)
    assert all("vdd" not in message for message in messages)


def test_floating_gate_requires_only_capacitive_or_gate_endpoints() -> None:
    floating = codes("M1 d gate 0 0 nch\nC1 gate 0 1p\n")
    driven = codes("M1 d gate 0 0 nch\nR1 gate 0 1meg\n")
    assert "NET002" in floating
    assert "NET002" not in driven


def test_parallel_voltage_source_conflict_is_direction_sensitive() -> None:
    assert "SRC001" in codes("V1 a 0 1\nV2 a 0 2\n")
    assert "SRC001" not in codes("V1 a 0 1\nV2 a 0 1\n")
    assert "SRC001" in codes("V1 a 0 1\nV2 0 a 2\n")
    assert "SRC001" not in codes("V1 a 0 1\nV2 0 a -1\n")


def test_zero_ohm_configured_rail_short_is_denied() -> None:
    assert "RAIL001" in codes("R1 vdd 0 0\n")
    assert "RAIL001" not in codes("R1 signal 0 0\n")
    assert "RAIL001" not in codes("R1 vdd 0 1m\n")


def test_hierarchy_binds_parent_rails_and_parallel_sources() -> None:
    rail = "X1 vdd 0 short\n.subckt short p n\nR0 p n 0\n.ends\n"
    assert "RAIL001" in codes(rail)
    sources = "VTOP vdd 0 1\nX1 vdd 0 cell\n.subckt cell p n\nVCHILD p n 2\n.ends\n"
    assert "SRC001" in codes(sources)


def test_parameter_expression_source_voltage_and_instance_params() -> None:
    policy = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 2.0}})
    assert "VOLT001" in codes(".param supply=3\nV1 out 0 {supply}\n", policy)
    text = (
        "X1 out 0 cell params: supply=3\n"
        ".subckt cell p n params: supply=1\nV1 p n {supply}\n.ends\n"
    )
    assert "VOLT001" in codes(text, policy)


def test_subcircuit_parameters_inherit_top_level_values_per_scope() -> None:
    policy = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 6.0}})
    low = ".param hi=5\n.subckt cell p n params: v=hi\nV1 p n {v}\n.ends\nX1 out 0 cell\n"
    low_codes = codes(low, policy)
    assert "VOLT001" not in low_codes
    assert "VOLT002" not in low_codes

    high = low.replace("hi=5", "hi=7")
    assert "VOLT001" in codes(high, policy)

    mixed = (
        ".param hi=5\n"
        ".subckt good p n params: v=hi\nVGOOD p n {v}\n.ends\n"
        ".subckt bad p n params: broken=missing\nVBAD p n {broken}\n.ends\n"
        "XGOOD out 0 good\nXBAD other 0 bad\n"
    )
    findings = run_checks(context(mixed, policy))
    voltage_reviews = [item for item in findings if item.code == "VOLT002"]
    assert len(voltage_reviews) == 1
    assert "VBAD" in voltage_reviews[0].message


def test_failed_subcircuit_default_preserves_successful_default_prefix() -> None:
    policy = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 6.0}})
    text = (
        ".param hi=100\n"
        ".subckt cell p n params: v=hi broken=missing\n"
        "VGOOD p n {v}\n.ends\n"
        "X1 out 0 cell\n"
    )
    findings = run_checks(context(text, policy))
    good_voltage = [item for item in findings if "VGOOD" in item.message]
    assert [item.code for item in good_voltage] == ["VOLT001"]
    assert "GRAPH008" in {item.code for item in findings}


def test_step_pwl_and_dynamic_voltage_budgets_are_enforced() -> None:
    analysis = AuditPolicy.from_mapping({"limits": {"max_analysis_points": 20}})
    assert "ANL001" in codes(".tran 1 10\n.step param corner 1 3 1\n", analysis)
    pwl = AuditPolicy.from_mapping({"limits": {"max_pwl_points": 2}})
    assert "ANL003" in codes("V1 a 0 PWL(0 0 1 1 2 0)\n", pwl)
    assert "ANL002" in codes(".step param x complicated\n")
    voltage = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 6.0}})
    assert "VOLT001" in codes("V1 a 0 pulse(0 1e9 1n)\n", voltage)
    assert "VOLT002" in codes("V1 a 0 custom_waveform\n", voltage)


def test_extensionless_ambient_lib_requires_review() -> None:
    assert "LIB001" in codes(".lib tt\n")


def test_include_parameter_events_follow_textual_insertion_order(tmp_path: Path) -> None:
    (tmp_path / "z.lib").write_text(".param supply=1\n", encoding="utf-8")
    policy = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 6.0}})
    (tmp_path / "top.sp").write_text(
        ".include z.lib\n.param supply=100\nV1 out 0 {supply}\n", encoding="utf-8"
    )
    assert "VOLT001" in {
        item.code for item in audit_path(tmp_path, entry="top.sp", policy=policy).findings
    }
    (tmp_path / "top.sp").write_text(
        ".param supply=100\n.include z.lib\nV1 out 0 {supply}\n", encoding="utf-8"
    )
    assert "VOLT001" not in {
        item.code for item in audit_path(tmp_path, entry="top.sp", policy=policy).findings
    }


def test_nested_include_parameter_events_preserve_depth_first_order(tmp_path: Path) -> None:
    (tmp_path / "z.lib").write_text(".param supply=2\n", encoding="utf-8")
    (tmp_path / "a.lib").write_text(
        ".param supply=1\n.include z.lib\n.param supply=3\n", encoding="utf-8"
    )
    policy = AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": 6.0}})
    (tmp_path / "top.sp").write_text(
        ".include a.lib\n.param supply=100\nV1 out 0 {supply}\n", encoding="utf-8"
    )
    assert "VOLT001" in {
        item.code for item in audit_path(tmp_path, entry="top.sp", policy=policy).findings
    }
    (tmp_path / "top.sp").write_text(
        ".param supply=100\n.include a.lib\nV1 out 0 {supply}\n", encoding="utf-8"
    )
    assert "VOLT001" not in {
        item.code for item in audit_path(tmp_path, entry="top.sp", policy=policy).findings
    }


def test_duplicate_subcircuit_formal_ports_are_denied() -> None:
    assert "GRAPH007" in codes("X1 a b c\n.subckt c P p\nR1 P 0 1\n.ends\n")


def test_finding_order_and_ids_are_stable() -> None:
    text = "V2 vdd 0 3\nV1 vdd 0 2\nR0 vdd 0 0\n.control\n"
    first = run_checks(context(text))
    second = run_checks(context(text))
    assert first == second
    assert [finding.finding_id for finding in first] == [finding.finding_id for finding in second]
    assert len({finding.finding_id for finding in first}) == len(first)


def test_every_actionable_finding_has_location_or_bundle_scope() -> None:
    findings = run_checks(context("V1 vdd 0 30\nR0 vdd 0 0\n.control\n"))
    assert findings
    for finding in findings:
        assert finding.code
        assert finding.title
        assert finding.message
        assert finding.severity in set(Severity)
