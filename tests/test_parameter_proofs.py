import pytest

from schematic_airlock import audit_text


@pytest.mark.parametrize(
    ("global_value", "local_statement", "short_expected"),
    [
        ("0", ".param a=1", False),
        ("1", ".param a=0", True),
        ("0", ".param a=1/3", False),
        ("0", ".param a", False),
    ],
)
def test_subcircuit_parameter_body_controls_its_electrical_proof(
    global_value: str, local_statement: str, short_expected: bool
) -> None:
    report = audit_text(
        f".param a={global_value}\n"
        ".subckt cell p n\n"
        f"{local_statement}\n"
        "RLOCAL p bridge {a}\n"
        "RZERO bridge n 0\n"
        ".ends cell\n"
        "XROOT vdd 0 cell\n"
    )

    assert any(finding.code == "RAIL002" for finding in report.findings) is short_expected


@pytest.mark.parametrize(
    "body",
    [
        ".subckt cell p n params: a=0 a\nR1 p n {a}\n.ends cell\nX1 vdd 0 cell\n",
        ".subckt cell p n params: a=0\nR1 p n {a}\n.ends cell\nX1 vdd 0 cell params: a\n",
    ],
)
def test_explicit_parameter_tail_cannot_discard_malformed_override(body: str) -> None:
    report = audit_text(body)

    assert not any(finding.code in {"RAIL001", "RAIL002"} for finding in report.findings)
    assert report.decision.value != "allow"


@pytest.mark.parametrize("derived", ["header", "body"])
def test_derived_parameter_is_evaluated_with_final_instance_override(derived: str) -> None:
    from schematic_airlock.bundle import MemoryBundle
    from schematic_airlock.circuit_graph import build_circuit_graph
    from schematic_airlock.include_graph import load_include_graph

    text = (
        ".subckt cell p n params: a=0"
        + (" b={a+1}" if derived == "header" else "")
        + "\n"
        + (".param b={a+1}\n" if derived == "body" else "")
        + "R1 p n {b}\n.ends cell\nX1 vdd 0 cell params: a=4\n"
    )
    includes = load_include_graph(MemoryBundle(text, "test.sp"))
    graph = build_circuit_graph(includes, max_expanded_instances=100)

    assert [item.element.value for item in graph.expanded_devices if item.element.kind == "R"] == [
        "5"
    ]


def test_instance_override_wins_over_same_named_body_parameter() -> None:
    report = audit_text(
        ".subckt cell p n params: a=2\n.param a=0\nR1 p n {a}\n.ends cell\n"
        "X1 vdd 0 cell params: a=1\n"
    )
    assert not any(finding.code in {"RAIL001", "RAIL002"} for finding in report.findings)


def test_top_level_derived_value_sees_final_declaration_not_old_zero() -> None:
    report = audit_text(".param a=0 b={a}\n.param a=1\nRDERIVED vdd 0 {b}\n")
    assert not any(finding.code in {"RAIL001", "RAIL002"} for finding in report.findings)


def test_cyclic_and_invalid_parameter_scopes_never_reuse_parent_zero() -> None:
    report = audit_text(
        ".param a=0\n.subckt cell p n params: a={b} b={a}\nR1 p n {a}\n.ends cell\nX1 vdd 0 cell\n"
    )
    assert any(finding.code == "GRAPH008" for finding in report.findings)
    assert not any(finding.code in {"RAIL001", "RAIL002"} for finding in report.findings)


def test_cumulative_parameter_work_exhaustion_is_reported_once(monkeypatch) -> None:
    import schematic_airlock.circuit_graph as graph_module

    monkeypatch.setattr(graph_module, "_MAX_PARAMETER_EVALUATIONS", 1)
    report = audit_text(
        ".param a=0\n.subckt cell p n params: a=1 b={a}\nR1 p n {b}\n.ends cell\n"
        "X1 vdd 0 cell\nX2 vdd 0 cell\n"
    )
    assert sum("evaluation budget exhausted" in finding.message for finding in report.findings) == 1
    assert not any(finding.code in {"RAIL001", "RAIL002"} for finding in report.findings)


@pytest.mark.parametrize("nested", [False, True])
def test_declaration_budget_fails_before_retaining_an_unbounded_mapping(nested: bool) -> None:
    declarations = " ".join(f"p{index}=0" for index in range(129))
    text = (
        f".subckt cell p n params: {declarations}\nR1 p n {{p0}}\n.ends cell\nX1 vdd 0 cell\n"
        if nested
        else f".param {declarations}\nR1 vdd 0 {{p0}}\n"
    )
    report = audit_text(text)
    assert any("128-name budget" in finding.message for finding in report.findings)
    assert not any(finding.code in {"RAIL001", "RAIL002"} for finding in report.findings)


@pytest.mark.parametrize("kind", ["R", "C", "L"])
def test_final_passive_values_are_checked_not_misreported_as_unknown(kind: str) -> None:
    negative = audit_text(f".param a=-1\n{kind}1 vdd 0 {{a}}\n")
    positive = audit_text(f".param a=1\n{kind}1 vdd 0 {{a}}\n")
    assert any(f.code == "VAL001" for f in negative.findings)
    assert not any(f.code == "VAL002" for f in negative.findings)
    assert not any(f.code in {"VAL001", "VAL002"} for f in positive.findings)


@pytest.mark.parametrize(
    ("second_value", "expected_code"),
    [("-1", "VAL001"), ("{missing}", "VAL002")],
)
def test_distinct_final_instance_values_are_not_hidden_by_source_deduplication(
    second_value: str, expected_code: str
) -> None:
    report = audit_text(
        ".subckt cell p n params: a=1\nRLOCAL p n {a}\n.ends cell\n"
        "XGOOD left 0 cell params: a=1\n"
        f"XSECOND right 0 cell params: a={second_value}\n"
    )

    value_findings = [finding for finding in report.findings if finding.code.startswith("VAL")]
    assert [finding.code for finding in value_findings] == [expected_code]
