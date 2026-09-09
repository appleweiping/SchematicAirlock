from __future__ import annotations

from decimal import ROUND_UP, Decimal, Inexact, localcontext

import pytest

from schematic_airlock.domain import InputError
from schematic_airlock.units import (
    decimal_text,
    evaluate_expression,
    parameter_assignments,
    parse_number,
)


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ("0", "0"),
        ("1", "1"),
        ("-1.5", "-1.5"),
        ("+2.5e2", "250"),
        ("1T", "1e12"),
        ("2g", "2e9"),
        ("3meg", "3e6"),
        ("4k", "4e3"),
        ("5m", "5e-3"),
        ("6u", "6e-6"),
        ("7n", "7e-9"),
        ("8p", "8e-12"),
        ("9f", "9e-15"),
        ("10mil", "0.000254"),
        ("1.8V", "1.8"),
        ("2kohm", "2e3"),
        ("{3.3}", "3.3"),
        ("'4.2'", "4.2"),
    ],
)
def test_parse_number_accepts_bounded_spice_literals(literal: str, expected: str) -> None:
    assert parse_number(literal) == Decimal(expected)


@pytest.mark.parametrize(
    "literal",
    [
        "",
        "nan",
        "inf",
        "1e101",
        "1foo",
        "--1",
        "1+2",
        "{1+2}",
        "0x10",
        "1µ",
    ],
)
def test_parse_number_rejects_ambiguous_or_unbounded_input(literal: str) -> None:
    with pytest.raises(ValueError):
        parse_number(literal)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("1 + 2 * 3", "7"),
        ("(1 + 2) * 3", "9"),
        ("-2 * -4", "8"),
        ("{1k / 4}", "250"),
        ("'10m + 5m'", "0.015"),
        ("+7", "7"),
        ("18 / 3 / 2", "3"),
        ("2 - 3 - 4", "-5"),
    ],
)
def test_expression_precedence_and_spice_suffixes(expression: str, expected: str) -> None:
    assert evaluate_expression(expression) == Decimal(expected)


def test_expression_resolves_parameter_names_case_insensitively() -> None:
    parameters = {"width": parse_number("2u"), "Scale": Decimal("3")}
    assert evaluate_expression("WIDTH * scale", parameters) == Decimal("6e-6")


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "1 // 2",
        "1 ** 2",
        "sin(1)",
        "unknown + 1",
        "1 / 0",
        "(1 + 2",
        "1 + 2)",
        "1,2",
    ],
)
def test_expression_rejects_unsupported_semantics(expression: str) -> None:
    with pytest.raises(ValueError):
        evaluate_expression(expression)


def test_expression_enforces_token_budget() -> None:
    with pytest.raises(ValueError, match="token budget"):
        evaluate_expression("+".join("1" for _ in range(20)), max_tokens=8)


def test_expression_enforces_depth_budget() -> None:
    with pytest.raises(ValueError, match="depth budget"):
        evaluate_expression("((((1))))", max_depth=3)


def test_parameter_assignments_are_left_to_right_and_inherited() -> None:
    inherited = {"base": Decimal("2")}
    result = parameter_assignments(["gain=base*3", "total=gain+1"], inherited)
    assert result == {
        "base": Decimal("2"),
        "gain": Decimal("6"),
        "total": Decimal("7"),
    }


def test_parameter_assignments_reject_invalid_name() -> None:
    with pytest.raises(InputError, match="invalid parameter"):
        parameter_assignments(["not-name=3"])


@pytest.mark.parametrize(
    ("value", "rendered"),
    [
        (Decimal("0"), "0"),
        (Decimal("1.000"), "1"),
        (Decimal("-2.500"), "-2.5"),
        (Decimal("0.00000120"), "0.0000012"),
        (Decimal("1000000"), "1000000"),
    ],
)
def test_decimal_text_is_stable(value: Decimal, rendered: str) -> None:
    assert decimal_text(value) == rendered


def test_number_parser_does_not_execute_python(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fail(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("must not execute")

    monkeypatch.setattr("builtins.eval", fail)
    assert evaluate_expression("2 * (3 + 4)") == Decimal("14")
    assert called is False


def test_numeric_contract_is_independent_of_the_callers_decimal_context() -> None:
    value = Decimal("1.23456789012345678901234567890123456789")
    with localcontext() as context:
        context.prec, context.Emin, context.Emax = 2, -2, 2
        context.rounding = ROUND_UP
        context.traps[Inexact] = True
        assert parse_number("1e-100") == Decimal("1e-100")
        assert parse_number("1e100") == Decimal("1e100")
        assert parse_number("1.23456789012345678901234567890123456789") == value
        assert decimal_text(value) == "1.23456789012345678901234567890123456789"
        assert evaluate_expression("1e-50*1e-50", exact=True) == Decimal("1e-100")


@pytest.mark.parametrize("literal", ["1e-101", "1e-9999999", "1e9999999", "1" * 1025])
def test_out_of_range_numbers_never_round_or_underflow_to_zero(literal: str) -> None:
    with pytest.raises(ValueError):
        parse_number(literal)


def test_exact_proof_expressions_never_round_cancellation_into_zero() -> None:
    assert evaluate_expression("1e60 + 1 - 1e60", exact=True) == Decimal(1)
    with pytest.raises(ValueError):
        evaluate_expression("1/3", exact=True)
    assert Decimal("0.3333") < evaluate_expression("1/3") < Decimal("0.3334")


def test_exact_parameter_propagation_preserves_small_difference() -> None:
    values = parameter_assignments(["a=1e60+1", "b=a-1e60"], exact=True)
    assert values["b"] == Decimal(1)


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("1e-9999999")])
def test_formatting_cannot_expand_unbounded_or_nonfinite_values(value: Decimal) -> None:
    with pytest.raises(ValueError):
        decimal_text(value)


def test_parameter_count_checks_the_new_key_before_insertion() -> None:
    boundary = {f"p{index}": Decimal(1) for index in range(128)}
    assert len(parameter_assignments(["P0=2"], boundary, exact=True)) == 128
    with pytest.raises(ValueError, match="128"):
        parameter_assignments(["overflow=1"], boundary, exact=True)
    with pytest.raises(ValueError, match="128"):
        parameter_assignments([f"p{index}=1" for index in range(129)], exact=True)


@pytest.mark.parametrize("tokens", ["a=1", [None], ["x" * 18000]])
def test_parameter_assignment_container_has_a_bounded_typed_contract(tokens) -> None:
    with pytest.raises(ValueError):
        parameter_assignments(tokens)


@pytest.mark.parametrize("literal", ["{{0}}", "{0", "0}", "'0", "0'", "{0'"])
def test_numeric_quotes_and_braces_must_be_one_matching_pair(literal: str) -> None:
    with pytest.raises(ValueError):
        parse_number(literal)
