from __future__ import annotations

import pytest

from schematic_airlock.dc_netlist import solve_dc_text
from schematic_airlock.domain import SyntaxFailure
from schematic_airlock.parse import parse_deck


@pytest.mark.parametrize(
    "header",
    (
        ".subckt params:",
        ".subckt params: x=1",
        ".subckt =x",
        ".subckt x=1",
        '.subckt ""',
        ".subckt ''",
    ),
)
def test_subcircuit_header_without_positional_name_fails_typed(header: str) -> None:
    text = f"{header}\n.ends\n"

    with pytest.raises(SyntaxFailure, match="name"):
        parse_deck(text, "input.sp")

    report = solve_dc_text(text)
    assert report.status == "unsupported"
    assert report.solution is None
    assert report.notes and "name" in report.notes[0]


@pytest.mark.parametrize("text", ('""\n', '"" a 0 1\n', "'' a 0 1\n"))
def test_empty_quoted_element_name_fails_typed(text: str) -> None:
    with pytest.raises(SyntaxFailure, match="name"):
        parse_deck(text, "input.sp")

    report = solve_dc_text(text)
    assert report.status == "unsupported"
    assert report.solution is None
