from __future__ import annotations

import pytest

from schematic_airlock import AuditPolicy, audit_text


def codes(deck: str, policy: AuditPolicy | None = None) -> list[str]:
    return [finding.code for finding in audit_text(deck, policy=policy).findings]


@pytest.mark.parametrize(
    "deck",
    [
        "RZERO1 vdd bridge 0\nRZERO2 bridge 0 0\n",
        "VZERO vdd 0 DC 0\n",
        "LRETURN vdd 0 1u\n",
    ],
    ids=("zero-ohm-chain", "zero-volt-source", "positive-inductor-at-dc"),
)
def test_proven_dc_zero_voltage_rail_paths_are_denied(deck: str) -> None:
    report = audit_text(deck)

    assert report.decision.value == "deny"
    assert [finding.code for finding in report.findings] == ["RAIL002"]


@pytest.mark.parametrize(
    "element",
    [
        "RNEAR vdd 0 1m",
        "RUNKNOWN vdd 0 {unknown}",
        "RNEGATIVE vdd 0 -1",
        "VNONZERO vdd 0 1u",
        "VPARAM vdd 0 {zero}",
        "VDYNAMIC vdd 0 PULSE(0 0 0 1n 1n 1n 2n)",
        "LZERO vdd 0 0",
        "LNEGATIVE vdd 0 -1n",
        "LUNKNOWN vdd 0 {unknown}",
        "COPEN vdd 0 1p",
        "EDEPENDENT vdd 0 control 0 0",
        "MSTATE vdd gate 0 0 nch",
        "DSTATE vdd 0 diode",
        "QSTATE vdd base 0 npn",
    ],
    ids=(
        "nonzero-resistance",
        "unknown-resistance",
        "negative-resistance",
        "nonzero-voltage",
        "parameterized-zero-voltage",
        "dynamic-zero-level-voltage",
        "zero-inductance",
        "negative-inductance",
        "unknown-inductance",
        "capacitor-open-at-dc",
        "controlled-source",
        "mos-state-dependent",
        "diode-state-dependent",
        "bjt-state-dependent",
    ),
)
def test_unproven_or_nonzero_paths_do_not_claim_a_rail_short(element: str) -> None:
    assert "RAIL002" not in codes(element + "\n")


def test_existing_direct_zero_ohm_rule_is_not_duplicated() -> None:
    assert codes("RSTRAP vdd 0 0\n") == ["RAIL001"]


def test_direct_zero_ohm_suppresses_composite_duplicate_for_the_component() -> None:
    deck = "RSTRAP vdd 0 0\nRZERO1 vdd bridge 0\nRZERO2 bridge 0 0\n"

    assert codes(deck) == ["RAIL001"]


def test_hierarchical_formal_port_aliases_retain_the_direct_rule() -> None:
    deck = """XWRAP vdd 0 wrapper
.subckt wrapper input output
RSTRAP input output 0
.ends wrapper
"""

    assert codes(deck) == ["RAIL001"]


def test_hierarchical_proof_uses_expanded_nodes_and_instance_devices() -> None:
    deck = """XSHORT supply return rail_cell params: strap=0 feed=2n
.subckt rail_cell positive negative params: strap=1 feed=1n
RZERO positive bridge {strap}
LRETURN bridge negative {feed}
.ends rail_cell
"""
    policy = AuditPolicy.from_mapping(
        {"electrical": {"power_nets": ["supply"], "ground_nets": ["return"]}}
    )

    report = audit_text(deck, policy=policy)
    finding = next(item for item in report.findings if item.code == "RAIL002")

    assert finding.severity.value == "deny"
    assert finding.metadata["power"] == "supply"
    assert finding.metadata["ground"] == "return"
    assert finding.metadata["proof_elements"] == 2
    assert set(finding.metadata["witness_devices"]) == {
        "top/XSHORT/RZERO",
        "top/XSHORT/LRETURN",
    }
    assert finding.location is not None
    assert finding.location.line in {3, 4}


def test_only_a_pure_literal_zero_voltage_source_is_rail_evidence() -> None:
    deck = ".param zero=0\nVPARAM vdd 0 {zero}\n"

    assert "RAIL002" not in codes(deck)


def test_hierarchy_separator_text_does_not_alias_a_configured_top_net() -> None:
    deck = "RZERO1 domain:vdd bridge 0\nRZERO2 bridge 0 0\n"

    assert "RAIL002" not in codes(deck)


def test_long_proof_has_bounded_witness_and_full_stable_digest() -> None:
    edges = ["R0 vdd n0 0"]
    edges.extend(f"R{index} n{index - 1} n{index} 0" for index in range(1, 20))
    edges.append("RLAST n19 0 0")
    deck = "\n".join(edges) + "\n"

    first = next(item for item in audit_text(deck).findings if item.code == "RAIL002")
    second = next(item for item in audit_text(deck).findings if item.code == "RAIL002")

    assert first == second
    assert first.metadata["proof_elements"] == 21
    assert len(first.metadata["witness_devices"]) == 12
    assert first.metadata["witness_truncated"] is True
    assert len(first.metadata["proof_sha256"]) == 64
    assert len(first.evidence.encode("utf-8")) < 2048


@pytest.mark.parametrize(
    "deck",
    [
        "VNONZERO vdd 0 1e-9999999\n",
        "RNONZERO vdd bridge {1e60+1-1e60}\nRZERO bridge 0 0\n",
        ".param a=1e60+1 b=a-1e60\nRNONZERO vdd bridge {b}\nRZERO bridge 0 0\n",
    ],
)
def test_underflow_and_rounded_cancellation_are_not_short_proofs(deck: str) -> None:
    assert not {"RAIL001", "RAIL002"}.intersection(codes(deck))


def test_hostile_decimal_context_cannot_make_a_nonzero_source_into_a_short() -> None:
    from decimal import localcontext

    with localcontext() as context:
        context.prec, context.Emin, context.Emax = 2, -2, 2
        assert "RAIL002" not in codes("VNONZERO vdd 0 1e-100\n")


@pytest.mark.parametrize(
    "element",
    [
        "LUNKNOWN vdd 0 1u m=0",
        "LUNKNOWN vdd 0 1u rser=1",
        "LUNKNOWN vdd 0 1u opaque_model",
        "RUNKNOWN vdd 0 0 m=0",
        "RUNKNOWN vdd 0 0 opaque_model",
        "VUNKNOWN vdd 0 0 opaque=1",
    ],
)
def test_opaque_device_modifiers_cannot_support_an_ideal_short_proof(element: str) -> None:
    assert not {"RAIL001", "RAIL002"}.intersection(codes(element + "\n"))


@pytest.mark.parametrize(
    "deck",
    [
        ".param a=0\n.param a=1/3\nRUNKNOWN vdd 0 {a}\n",
        "X1 vdd 0 cell params: a=1/3\n.subckt cell p n params: a=0\nRUNKNOWN p n {a}\n.ends cell\n",
    ],
)
def test_failed_parameter_override_cannot_reuse_an_inherited_zero(deck: str) -> None:
    findings = codes(deck)
    assert "GRAPH008" in findings
    assert not {"RAIL001", "RAIL002"}.intersection(findings)


def test_malformed_parameter_override_cannot_reuse_an_inherited_zero() -> None:
    deck = ".param a=0\n.param a\nRUNKNOWN vdd bridge {a}\nRZERO bridge 0 0\n"

    findings = codes(deck)

    assert "GRAPH008" in findings
    assert not {"RAIL001", "RAIL002"}.intersection(findings)


def test_later_valid_assignment_cannot_erase_an_earlier_malformed_declaration() -> None:
    deck = ".param a\n.param a=0\nRPATH vdd bridge {a}\nRZERO bridge 0 0\n"

    assert "GRAPH008" in codes(deck)


def test_spice_ground_zero_cannot_be_reconfigured_as_a_power_rail() -> None:
    from schematic_airlock.domain import PolicyError

    with pytest.raises(PolicyError):
        AuditPolicy.from_mapping({"electrical": {"ground_nets": ["gnd"], "power_nets": ["0"]}})
