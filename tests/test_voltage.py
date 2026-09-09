from __future__ import annotations

import json
from dataclasses import replace
from fractions import Fraction as F
from io import StringIO
from pathlib import Path

import pytest

from schematic_airlock.voltage import (
    check_voltages_path,
    check_voltages_text,
    voltage_report_json,
    voltage_report_text,
)
from schematic_airlock.voltage_constraints import VoltageConstraintError, VoltageInterval
from schematic_airlock.voltage_rules import (
    ExpectedVoltage,
    VoltageRules,
    load_voltage_rules,
    parse_voltage_rules,
    voltage_rules_from_mapping,
)


def rule_mapping(**fields: object) -> dict[str, object]:
    return {"schema": "org.schematic-airlock.voltage-rules", "version": 1, **fields}


def expected(
    positive: str = "out", low: str = "1", high: str = "1", negative: str = "0"
) -> list[dict[str, str]]:
    return [{"name": "output", "positive": positive, "negative": negative, "min": low, "max": high}]


def rules(**fields: object) -> VoltageRules:
    return voltage_rules_from_mapping(rule_mapping(**fields))


def mos_rating(low: str = "-2", high: str = "2") -> dict[str, object]:
    return {
        "nch": {
            "kind": "M",
            "limits": {
                pair: {"min": low, "max": high} for pair in ("gs", "gd", "gb", "ds", "bs", "bd")
            },
        }
    }


def test_hierarchical_rails_offsets_and_source_provenance() -> None:
    text = (
        "V1 rail 0 1\nX1 rail out parent\n"
        ".subckt parent p n\nV2 internal p 500mV\nX2 internal n child\n.ends\n"
        ".subckt child p n\nR1 p n 0ohm\n.ends\n"
    )
    result = check_voltages_text(text, rules=rules(expected=expected(low="1.5", high="1.5")))
    assert result.status == "pass"
    assert result.checks[0].observed == VoltageInterval(F(3, 2), F(3, 2))
    assert result.constraints == 3
    assert not result.assumptions
    assert result.files[0].path == "input.sp"
    assert json.loads(voltage_report_json(result))["mode"] == "dc-envelope"
    assert "[pass] expected:output" in voltage_report_text(result)


def test_varying_shared_supply_preserves_gate_source_correlation() -> None:
    selected = rules(
        source_envelopes={"TOP/V1": {"min": "1", "max": "2"}},
        expected=expected("gate", "0.5", "0.5", "supply"),
    )
    result = check_voltages_text("V1 supply 0 1.5\nV2 gate supply .5\n", rules=selected)
    assert result.status == "pass"
    assert result.assumptions == ("source:top/v1",)
    assert result.checks[0].observed == VoltageInterval(F(1, 2), F(1, 2))


def test_source_scenario_never_excludes_declared_dc_value() -> None:
    selected = rules(source_envelopes={"top/v1": {"min": "2", "max": "3"}})
    with pytest.raises(VoltageConstraintError, match="excludes"):
        check_voltages_text("V1 out 0 1\n", rules=selected)


def test_source_envelope_cannot_hide_nominal_ideal_source_contradiction() -> None:
    selected = rules(
        source_envelopes={"top/v1": {"min": "0", "max": "10"}}, expected=expected(low="6", high="6")
    )
    result = check_voltages_text("V1 out 0 5\nV2 out 0 6\n", rules=selected)
    assert result.status == "inconsistent"
    assert not result.checks


def test_independent_envelope_source_loop_needs_correlation_evidence() -> None:
    selected = rules(
        source_envelopes={"top/v1": {"min": "4", "max": "6"}}, expected=expected(low="5", high="5")
    )
    result = check_voltages_text("V1 out 0 5\nV2 out 0 5\n", rules=selected)
    assert result.status == "indeterminate"
    assert "independent envelope" in result.notes[0]
    # A repeated fixed source does not create a variable compatibility problem.
    result = check_voltages_text(
        "V1 out 0 5\nV2 out 0 5\n", rules=rules(expected=expected(low="5", high="5"))
    )
    assert result.status == "pass"


@pytest.mark.parametrize("both", [False, True])
def test_parallel_variable_sources_do_not_silently_choose_feasible_sweep_subset(both: bool) -> None:
    envelopes = {"top/v1": {"min": "4", "max": "6"}}
    if both:
        envelopes["top/v2"] = {"min": "4", "max": "6"}
    result = check_voltages_text(
        "V1 out 0 5\nV2 out 0 5\n",
        rules=rules(source_envelopes=envelopes, expected=expected(low="4", high="6")),
    )
    assert result.status == "indeterminate"


def test_series_independent_source_envelopes_without_loop_are_supported() -> None:
    result = check_voltages_text(
        "V1 mid 0 1\nV2 out mid 2\n",
        rules=rules(
            source_envelopes={
                "top/v1": {"min": "1", "max": "2"},
                "top/v2": {"min": "2", "max": "3"},
            },
            expected=expected(low="3", high="5"),
        ),
    )
    assert result.status == "pass"
    assert result.checks[0].observed == VoltageInterval(F(3), F(5))


def test_point_source_envelopes_obey_ordinary_exact_consistency() -> None:
    selected = rules(
        source_envelopes={"top/v1": {"min": "5", "max": "5"}}, expected=expected(low="5", high="5")
    )
    assert check_voltages_text("V1 out 0 {param}\nV2 out 0 5\n", rules=selected).status == "pass"
    assert (
        check_voltages_text("V1 out 0 {param}\nV2 out 0 6\n", rules=selected).status
        == "inconsistent"
    )


def test_packaged_schemas_and_original_example() -> None:
    from jsonschema import Draft202012Validator

    root = Path(__file__).parents[1]
    selected = load_voltage_rules(root / "examples/voltage_envelope/rules.json")
    result = check_voltages_path(root / "examples/voltage_envelope/design.sp", rules=selected)
    assert result.status == "possible-violation"
    assert len(result.checks) == 13
    assert [check.name for check in result.checks if check.status != "pass"] == ["device:top/mp:bd"]
    for filename, instance in (
        ("voltage-rules-v1.schema.json", selected.as_dict()),
        ("voltage-report-v1.schema.json", result.as_dict()),
    ):
        schema = json.loads((root / "docs/schemas" / filename).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        validator.check_schema(schema)
        validator.validate(instance)


@pytest.mark.parametrize(
    "source", ["PULSE(0 3 1n)", "DC 1 AC 1", "{supply}", "custom", "1e-999", "1gibberish"]
)
def test_dynamic_or_unresolved_source_is_indeterminate_not_zero(source: str) -> None:
    result = check_voltages_text(f"V1 out 0 {source}\n", rules=rules(expected=expected()))
    assert result.status == "indeterminate"
    assert result.checks[0].observed == VoltageInterval(None, None)
    assert "no literal DC constraint" in result.notes[0]


def test_explicit_source_envelope_can_bound_an_unresolved_source() -> None:
    result = check_voltages_text(
        "V1 out 0 {input}\n",
        rules=rules(source_envelopes={"top/v1": {"min": "1", "max": "1"}}, expected=expected()),
    )
    assert result.status == "pass"
    assert result.assumptions == ("source:top/v1",)


@pytest.mark.parametrize("source", ["1", "DC 1", "1000m", "1V", "+1.000", "0.001kV"])
def test_literal_dc_source_spellings(source: str) -> None:
    assert (
        check_voltages_text(f"V1 out 0 {source}\n", rules=rules(expected=expected())).status
        == "pass"
    )


def test_mos_all_six_pairs_and_explicit_signed_body_ratings() -> None:
    text = "V1 d 0 1\nV2 g 0 1.8\nM1 d g 0 0 nch\n"
    result = check_voltages_text(text, rules=rules(models=mos_rating()))
    assert result.status == "pass"
    assert len(result.checks) == 6
    assert all(check.location and check.location.line == 3 for check in result.checks)
    limits = mos_rating()
    limits["nch"]["limits"]["gb"] = {"min": "-1", "max": "1"}  # type: ignore[index]
    result = check_voltages_text(text, rules=rules(models=limits))
    assert result.status == "violation"
    assert [check.name for check in result.checks if check.status == "violation"] == [
        "device:top/m1:gb"
    ]


@pytest.mark.parametrize(
    "voltage,status", [(".2", "pass"), (".8", "violation"), ("-6", "violation"), ("-.1", "pass")]
)
def test_diode_anode_cathode_forward_reverse_limits(voltage: str, status: str) -> None:
    selected = rules(models={"diode": {"kind": "D", "limits": {"ak": {"min": "-5", "max": ".6"}}}})
    result = check_voltages_text(f"V1 a 0 {voltage}\nD1 a 0 diode\n", rules=selected)
    assert result.status == status


def test_possible_violation_and_unknown_are_not_definite_violation() -> None:
    selected = rules(
        source_envelopes={"top/v1": {"min": "1", "max": "3"}}, expected=expected(low="1", high="2")
    )
    result = check_voltages_text("V1 out 0 2\n", rules=selected)
    assert result.status == "possible-violation"
    # No invented voltage drop/current through a resistor or MOS channel.
    result = check_voltages_text(
        "V1 supply 0 1\nR1 supply out 1k\nR2 out 0 1k\n",
        rules=rules(expected=expected(low=".5", high=".5")),
    )
    assert result.status == "indeterminate"
    assert result.checks[0].observed == VoltageInterval(None, None)


def test_node_envelope_is_explicit_assumption_not_measurement() -> None:
    result = check_voltages_text(
        "R1 out 0 1k\n",
        rules=rules(net_envelopes={"out": {"min": "1", "max": "1"}}, expected=expected()),
    )
    assert result.status == "pass"
    assert result.assumptions == ("net:out",)
    assert "ASSUMPTION: net:out" in voltage_report_text(result)


def test_nonliteral_zero_resistance_is_not_an_invented_short() -> None:
    result = check_voltages_text("V1 vdd 0 1\nR1 vdd out {0}\n", rules=rules(expected=expected()))
    assert result.status == "indeterminate"
    assert result.constraints == 1


@pytest.mark.parametrize("resistance", ["{0}", "{unknown}", "-1"])
def test_unassessed_resistance_cannot_be_hidden_by_an_already_bounded_query(
    resistance: str,
) -> None:
    result = check_voltages_text(
        f"V1 out 0 1\nR1 out 0 {resistance}\n", rules=rules(expected=expected())
    )
    assert result.status == "indeterminate"
    assert result.notes


def test_large_literal_precision_is_preserved_past_graph_rounding() -> None:
    number = "1.00000000000000000000000000000000000000000000000001"
    result = check_voltages_text(
        f"V1 out 0 {number}\n", rules=rules(expected=expected(low="1", high="1"))
    )
    assert result.status == "violation"
    assert result.checks[0].observed.lower > F(1)  # type: ignore[operator]


def test_inconsistent_cycle_or_short_never_returns_earlier_passes() -> None:
    for text in ("V1 out a 1\nV2 a 0 1\nV3 out 0 3\n", "V1 out 0 1\nR1 out 0 0\n"):
        result = check_voltages_text(text, rules=rules(expected=expected()))
        assert result.status == "inconsistent"
        assert not result.checks
        assert result.notes


@pytest.mark.parametrize(
    "text",
    [
        "X1 out 0 missing\n",
        "R1 a\n",
        ".include unavailable.sp\n",
        "V1 out 0 1\nV1 out 0 1\n",
        "V1 top/x:n 0 1\n",
    ],
)
def test_invalid_or_ambiguous_netlist_is_indeterminate(text: str) -> None:
    result = check_voltages_text(text, rules=rules())
    assert result.status == "indeterminate"
    assert not result.checks


@pytest.mark.parametrize(
    "extra", [".global supply", "L1 supply 0 1n", "M1 supply 0 0 0 unrated", ".tran 1n 1u"]
)
def test_unmodeled_semantics_prevent_overall_pass(extra: str) -> None:
    result = check_voltages_text(
        f"V1 supply 0 1\n{extra}\n", rules=rules(expected=expected("supply"))
    )
    assert result.status == "indeterminate"
    assert result.notes


def test_empty_obligations_unused_models_and_limits_fail_closed() -> None:
    assert check_voltages_text("V1 out 0 1\n", rules=rules()).status == "indeterminate"
    result = check_voltages_text(
        "V1 out 0 1\n", rules=rules(expected=expected(), models=mos_rating())
    )
    assert "unused" in result.notes[0]
    result = check_voltages_text(
        "V1 out 0 1\n", rules=rules(expected=expected(), limits={"max_nodes": 1})
    )
    assert result.status == "indeterminate"
    assert not result.checks
    result = check_voltages_text(
        "V1 d 0 1\nV2 g 0 1\nM1 d g 0 0 nch\n",
        rules=rules(models=mos_rating(), limits={"max_queries": 2}),
    )
    assert result.status == "indeterminate"
    assert not result.checks


@pytest.mark.parametrize(
    "fields,match",
    [
        ({"source_envelopes": {"top/missing": {"min": "0", "max": "1"}}}, "absent"),
        ({"net_envelopes": {"missing": {"min": "0", "max": "1"}}}, "unknown"),
        ({"expected": expected("missing")}, "unknown"),
        ({"models": {"nch": {"kind": "D", "limits": {"ak": {"min": "-2", "max": "2"}}}}}, "kind"),
    ],
)
def test_rule_references_are_validated(fields: dict[str, object], match: str) -> None:
    with pytest.raises(VoltageConstraintError, match=match):
        check_voltages_text("V1 out 0 1\nM1 out 0 0 0 nch\n", rules=rules(**fields))


def test_rules_canonical_fingerprint_and_path_io(tmp_path: Path) -> None:
    value = rule_mapping(expected=expected(low="-1.250", high="1e0"))
    source = tmp_path / "rules.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    selected = load_voltage_rules(source)
    assert selected == parse_voltage_rules(json.dumps(selected.as_dict()))
    assert selected.fingerprint() == rules(expected=expected(low="-1.25", high="1")).fingerprint()
    (tmp_path / "top.sp").write_text(".include sources.lib\n", encoding="utf-8")
    (tmp_path / "sources.lib").write_text("V1 out 0 1\n", encoding="utf-8")
    result = check_voltages_path(tmp_path, entry="top.sp", rules=source)
    assert result.status == "pass"
    assert {item.path for item in result.files} == {"sources.lib", "top.sp"}
    assert check_voltages_path(tmp_path / "top.sp", rules=selected) == result


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        rule_mapping(version=True),
        rule_mapping(unknown=1),
        rule_mapping(net_envelopes=[]),
        rule_mapping(
            net_envelopes={"OUT": {"min": "0", "max": "1"}, "out": {"min": "0", "max": "1"}}
        ),
        rule_mapping(net_envelopes={"out": {"min": 0, "max": 1}}),
        rule_mapping(net_envelopes={"out": {"min": "2", "max": "1"}}),
        rule_mapping(net_envelopes={"out": {"min": "1"}}),
        rule_mapping(expected={}),
        rule_mapping(expected=expected() * 2),
        rule_mapping(expected=[{"name": "a"}]),
        rule_mapping(expected=expected(positive="two words")),
        rule_mapping(models=[]),
        rule_mapping(models={"a": {"kind": "Q"}}),
        rule_mapping(models={"nch": {"kind": "M", "limits": {}}}),
        rule_mapping(
            models={
                "a": {"kind": "D", "limits": {"ak": {"min": "0", "max": "1"}}},
                "A": {"kind": "D", "limits": {"ak": {"min": "0", "max": "1"}}},
            }
        ),
        rule_mapping(limits={"max_queries": False}),
    ],
)
def test_invalid_voltage_rules(value: object) -> None:
    with pytest.raises(VoltageConstraintError):
        voltage_rules_from_mapping(value)


def test_direct_objects_cannot_hide_duplicate_rules_or_nondecimal_endpoints() -> None:
    selected = rules(expected=expected())
    with pytest.raises(VoltageConstraintError):
        check_voltages_text("", rules=replace(selected, expected=selected.expected * 2))
    with pytest.raises(VoltageConstraintError):
        check_voltages_text(
            "",
            rules=VoltageRules(
                expected=(ExpectedVoltage("a", "a", "b", VoltageInterval(F(1, 3), F(1))),)
            ),
        )
    with pytest.raises(VoltageConstraintError):
        check_voltages_text("", rules=None)  # type: ignore[arg-type]


def test_cli_and_output_alias_protection(tmp_path: Path) -> None:
    from schematic_airlock.cli import main

    deck = tmp_path / "top.sp"
    policy = tmp_path / "voltage.json"
    deck.write_text("V1 out 0 1\n", encoding="utf-8")
    policy.write_text(json.dumps(rule_mapping(expected=expected())), encoding="utf-8")
    stdout, stderr = StringIO(), StringIO()
    assert (
        main(
            ["voltage-check", str(deck), "--rules", str(policy), "--format", "json"],
            stdout=stdout,
            stderr=stderr,
        )
        == 0
    )
    assert json.loads(stdout.getvalue())["status"] == "pass"
    for protected in (deck, policy):
        assert (
            main(
                [
                    "voltage-check",
                    str(deck),
                    "--rules",
                    str(policy),
                    "--output",
                    str(protected),
                    "--force",
                ],
                stdout=StringIO(),
                stderr=StringIO(),
            )
            == 3
        )
    deck.write_text("V1 out 0 2\n", encoding="utf-8")
    assert (
        main(
            ["voltage-check", str(deck), "--rules", str(policy)],
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 2
    )


@pytest.mark.parametrize(
    "name",
    [
        "safe\u202efail",
        "a\u2066b",
        "a\u200bb",
        "a\u2028b",
        "a\u2029b",
        "a\u00a0b",
        "e\u0301",
        "a\ud800",
    ],
)
@pytest.mark.parametrize("field", ["net_envelopes", "source_envelopes", "models", "expected"])
def test_rules_reject_display_controls_and_noncanonical_names(name: str, field: str) -> None:
    if field in {"net_envelopes", "source_envelopes"}:
        value: object = {name: {"min": "0", "max": "1"}}
    elif field == "models":
        value = {name: {"kind": "D", "limits": {"ak": {"min": "0", "max": "1"}}}}
    else:
        value = [{**expected()[0], "name": name}]
    with pytest.raises(VoltageConstraintError):
        rules(**{field: value})


def test_report_escapes_untrusted_diagnostic_controls() -> None:
    result = check_voltages_text("V1 out 0 1\n", rules=rules(expected=expected()))
    result = replace(result, notes=("safe\u202efail\n[pass] fake",), entry="entry\u202e.sp")
    rendered = voltage_report_text(result)
    assert "\u202e" not in rendered
    assert "safe\\u202efail\\u000a[pass] fake" in rendered


def test_literal_instance_separator_cannot_alias_nested_instance_identity() -> None:
    text = (
        "X1/X2 a 0 leafa\nX1 b 0 parent\n.subckt parent p n\nX2 p n leafb\n.ends\n"
        ".subckt leafa p n\nVA internal p 1\n.ends\n"
        ".subckt leafb p n\nVB internal p 2\n.ends\n"
    )
    result = check_voltages_text(text, rules=rules(expected=expected("b", "-1", "-1", "a")))
    assert result.status == "indeterminate"
    assert not result.checks
    assert "ambiguous" in result.notes[0]


@pytest.mark.parametrize("name", ["bad/name", "bad:name"])
def test_subcircuit_separator_is_not_a_qualified_identity(name: str) -> None:
    result = check_voltages_text(
        f"X1 out 0 {name}\n.subckt {name} p n\nV1 p n 1\n.ends\n", rules=rules(expected=expected())
    )
    assert result.status == "indeterminate"


def test_casefold_does_not_merge_distinct_parser_hierarchy_identifiers() -> None:
    text = (
        "Xß a 0 leafa\nXss b 0 leafb\n"
        ".subckt leafa p n\nVA internal p 1\n.ends\n"
        ".subckt leafb p n\nVB internal p 2\n.ends\n"
    )
    result = check_voltages_text(text, rules=rules(expected=expected("b", "-1", "-1", "a")))
    assert result.status == "indeterminate"
    assert not result.checks


@pytest.mark.parametrize("name", ["a\u202eb", "a\u200bb", "e\u0301"])
@pytest.mark.parametrize(
    "extra", ["R{name} a b 1k", ".subckt unused {name}\nR1 {name} 0 1k\n.ends"]
)
def test_ignored_devices_and_unreachable_ports_cannot_hide_unsafe_identifiers(
    name: str, extra: str
) -> None:
    result = check_voltages_text(
        "V1 out 0 1\n" + extra.format(name=name) + "\n", rules=rules(expected=expected())
    )
    assert result.status == "indeterminate"
    assert not result.checks
    assert "NFC tokens" in result.notes[0]


def test_deep_real_hierarchy_reports_a_typed_budget_failure() -> None:
    from schematic_airlock.voltage_constraints import VoltageBudgetExceeded

    text = (
        "XROOT out c0\n"
        + "".join(f".subckt c{index} p\nXCHILD p c{index + 1}\n.ends\n" for index in range(1_100))
        + ".subckt c1100 p\nV1 p 0 1\n.ends\n"
    )
    with pytest.raises(VoltageBudgetExceeded, match="recursion"):
        check_voltages_text(text, rules=rules(expected=expected()))


def test_nfc_name_whose_casefold_is_noncanonical_fails_closed() -> None:
    with pytest.raises(VoltageConstraintError, match="noncanonical"):
        rules(expected=expected("\u01f0"))
    result = check_voltages_text("V1 out 0 1\nR\u01f0 a b 1k\n", rules=rules(expected=expected()))
    assert result.status == "indeterminate"
    assert "noncanonical" in result.notes[0]
