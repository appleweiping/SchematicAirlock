from __future__ import annotations

from decimal import ROUND_FLOOR, Decimal, localcontext
from fractions import Fraction

import pytest

from schematic_airlock import audit_text
from schematic_airlock.units import (
    decimal_text,
    evaluate_expression,
    parameter_assignments,
    parse_number,
)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("1e100 + 1 - 1e100", Fraction(1)),
        ("1e-100 / 2 * 2", Fraction(1, 10**100)),
        ("7 / 8 + 11 / 20", Fraction(57, 40)),
        ("(9 - 4) * (3 + 2) / 4", Fraction(25, 4)),
        ("1e50 * 1e-50", Fraction(1)),
    ],
)
def test_exact_expression_matches_independent_fraction_oracle(
    expression: str, expected: Fraction
) -> None:
    assert Fraction(evaluate_expression(expression, exact=True)) == expected


@pytest.mark.parametrize("expression", ["1/3", "2/7", "1/3*0", "10/6-5/3"])
def test_exact_expression_rejects_nonterminating_intermediate_results(expression: str) -> None:
    with pytest.raises(ValueError, match="inexact"):
        evaluate_expression(expression, exact=True)


@pytest.mark.parametrize("expression", ["1e-100/10", "-1e-100/10", "1e100*10", "-1e100*10"])
def test_exact_expression_rejects_final_values_outside_supported_range(expression: str) -> None:
    with pytest.raises(ValueError, match="supported finite range"):
        evaluate_expression(expression, exact=True)


def test_numeric_outputs_ignore_every_host_decimal_trap_and_rounding_mode() -> None:
    expected = Decimal("1.0000000000000000000000000000000000000000000000001")
    with localcontext() as context:
        context.prec = 1
        context.Emin = -1
        context.Emax = 1
        context.rounding = ROUND_FLOOR
        for signal in context.traps:
            context.traps[signal] = True

        assert parse_number(str(expected)) == expected
        assert Fraction(evaluate_expression("1e50 + 1e-50", exact=True)) == Fraction(
            10**100 + 1, 10**50
        )
        assert decimal_text(Decimal("1.230000")) == "1.23"


@pytest.mark.parametrize(
    "deck",
    [
        "VHOST vdd 0 1e3\n",
        "VHOST vdd 0 PULSE(-1e3 1e3 0 1n 1n 1n 2n)\n",
        "VFIRST vdd 0 1e3\nVCONFLICT 0 vdd 1e3\n",
    ],
)
def test_voltage_findings_ignore_every_host_decimal_trap_and_rounding_mode(
    deck: str,
) -> None:
    expected = [
        (finding.code, finding.severity.value, finding.message)
        for finding in audit_text(deck).findings
    ]

    with localcontext() as context:
        context.prec = 1
        context.Emin = -1
        context.Emax = 1
        context.rounding = ROUND_FLOOR
        for signal in context.traps:
            context.traps[signal] = True

        observed = [
            (finding.code, finding.severity.value, finding.message)
            for finding in audit_text(deck).findings
        ]

    assert observed == expected


@pytest.mark.parametrize("literal", ["1e-100f", "1e100t", "1e-9999999", "1e9999999"])
def test_suffix_and_exponent_paths_cannot_escape_the_numeric_range(literal: str) -> None:
    with pytest.raises(ValueError):
        parse_number(literal)


@pytest.mark.parametrize("literal", ["0e-9999999", "-0e9999999"])
def test_extreme_zero_exponents_have_bounded_canonical_output(literal: str) -> None:
    assert decimal_text(parse_number(literal)) == "0"


def test_parameter_limit_counts_the_new_key_before_evaluation() -> None:
    values = {f"p{index}": Decimal(index) for index in range(128)}

    assert len(parameter_assignments(["p0=2"], values, exact=True)) == 128
    with pytest.raises(ValueError, match="at most 128"):
        parameter_assignments(["overflow=1"], values, exact=True)
    with pytest.raises(ValueError, match="at most 128"):
        parameter_assignments([f"p{index}=1" for index in range(129)], exact=True)


@pytest.mark.parametrize(
    ("deck", "expected"),
    [
        (".param a=1000 b={a}\n.param a=1\nV1 vdd 0 {b}\n", False),
        (".param a=1 b={a}\n.param a=1000\nV1 vdd 0 {b}\n", True),
    ],
)
def test_voltage_findings_use_final_parameter_bindings(deck: str, expected: bool) -> None:
    assert ("VOLT001" in {finding.code for finding in audit_text(deck).findings}) is expected
