from __future__ import annotations

import io
import json
from fractions import Fraction as F
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from schematic_airlock.cli import main
from schematic_airlock.dc_netlist import solve_dc_path, solve_dc_text
from schematic_airlock.linear_dc import DCBudgetExceeded, DCInputError, DCLimits

DECK = "* divider\nV1 rail 0 DC 5V\nR1 rail out 2kohm\nR2 out 0 3k\n.op\n.end\n"


@pytest.mark.parametrize("branch", ["R1 a 0 1\u212a", "V1 a 0 1\u212a", "I1 a 0 1\u212a"])
def test_unicode_confusable_scale_suffix_is_not_a_spice_literal(branch: str) -> None:
    report = solve_dc_text(branch + "\nR2 a 0 1k\n")
    assert report.status == "unsupported" and report.solution is None


@pytest.mark.parametrize("suffix", ["K", "k"])
def test_ascii_scale_suffix_remains_case_insensitive(suffix: str) -> None:
    report = solve_dc_text(f"V1 a 0 1{suffix}\nR1 a 0 1{suffix}\n")
    assert report.status == "solved" and report.solution is not None
    assert dict(report.solution.voltages)["a"] == F(1000)
    assert dict(report.solution.currents)["top/r1"] == F(1)


@pytest.mark.parametrize(
    "text",
    [
        "V1 a 0 '1k'\nR1 a 0 1k",
        'V1 a 0 "1k"\nR1 a 0 1k',
        "'V1' a 0 1\nR1 a 0 1k",
        'V1 "a" 0 1\nR1 a 0 1k',
        "V1 a 0 1\nR1 a 0 '1k'",
        "I1 a 0 '1m'\nR1 a 0 1k",
        "X1 a 0 'cell'\n.subckt cell p n\nR1 p n 1\n.ends",
        "X1 a 0 cell\n.subckt 'cell' p n\nR1 p n 1\n.ends",
        "X1 a 0 cell\n.subckt cell 'p' n\nR1 p n 1\n.ends",
        "V1 a 0 1\nR1 a 0 1k\n'.op'",
        "V1 a 0 1\nR1 a 0 1k\n'.title' quoted command",
    ],
)
def test_quoted_electrical_tokens_are_not_reinterpreted_as_bare_literals(text: str) -> None:
    report = solve_dc_text(text)
    assert report.status == "unsupported" and report.solution is None


def test_quoted_include_paths_titles_and_comments_preserve_their_non_electrical_role(
    tmp_path: Path,
) -> None:
    (tmp_path / "cell library.sp").write_text("R1 a 0 1k\n", encoding="utf-8")
    entry = tmp_path / "entry.sp"
    entry.write_text(
        '.title "literal divider"\n.include "cell library.sp"\nV1 a 0 1 ; "a comment"\n.end\n',
        encoding="utf-8",
    )
    report = solve_dc_path(entry)
    assert report.status == "solved" and report.solution is not None
    assert dict(report.solution.voltages)["a"] == F(1)


def test_exact_netlist_output_retains_source_and_closed_profile() -> None:
    report = solve_dc_text(DECK)
    assert report.status == "solved" and report.solution is not None
    assert dict(report.solution.voltages)["out"] == F(3)
    assert report.locations[0][1].line == 3
    wire = report.as_dict()
    assert wire["profile"] == "linear-rvi-v1"
    assert wire["status"] == "solved"
    assert wire["nodes"] == {"0": "0", "out": "3", "rail": "5"}


def test_hierarchical_internal_nets_remain_instance_specific() -> None:
    report = solve_dc_text(
        "V1 rail 0 6\nX1 rail mid div\nX2 mid 0 div\n"
        ".subckt div p n\nR1 p internal 1k\nR2 internal n 1k\n.ends div\n.end\n"
    )
    assert report.solution is not None and report.status == "solved"
    assert dict(report.solution.voltages) == {
        "0": F(0),
        "rail": F(6),
        "mid": F(3),
        "top/x1:internal": F(9, 2),
        "top/x2:internal": F(3, 2),
    }


@pytest.mark.parametrize(
    "text",
    [
        "R1 a 0 {1/3}",
        "R1 a 0 1k tc=1",
        "R1 a 0 -1",
        "R1 a 0 1k extra",
        "V1 a 0 PULSE(0 1 1n 1n 1n 1n 4n)",
        "I1 a 0 AC 1",
        "C1 a 0 1p",
        "M1 a b 0 0 n",
        ".param r=1\nR1 a 0 r",
        ".global g\nR1 g 0 1",
        ".temp 25\nR1 a 0 1",
        ".control\nquit\n.endc",
        ".op extra\nR1 a 0 1",
        "R1 a:b 0 1",
        "R1 a/b 0 1",
        "R1 n\u212a 0 1",
        "X1 a 0 unknown",
        "R1 a 0 1\n.end\nV1 a 0 1",
        ".include absent.sp",
        ".lib models.lib tt",
        ".subckt div p n params: r=1\nR1 p n 1\n.ends\nX1 a 0 div",
        ".subckt div p n\n.include cells.sp\n.ends\nX1 a 0 div",
        "R1 a 0 1\nR1 a 0 2",
        ".end extra",
        "* empty library",
        ".subckt div p n\nR1 p n 1\n.ends\nX1 a 0 div params: ignored",
    ],
)
def test_unassessed_or_ambiguous_semantics_never_produce_a_solution(text: str) -> None:
    report = solve_dc_text(text)
    assert report.status == "unsupported"
    assert report.solution is None and report.notes


@pytest.mark.parametrize(
    "text,status",
    [("V1 a 0 1\nV2 a 0 2", "inconsistent"), ("R1 a b 1", "singular")],
)
def test_physical_failure_is_reported_without_fabricated_values(text: str, status: str) -> None:
    report = solve_dc_text(text)
    assert report.status == status and report.solution is None
    assert report.as_dict()["nodes"] == {}


def test_confined_include_and_atomic_cli_outputs(tmp_path: Path) -> None:
    source = tmp_path / "main.sp"
    source.write_text('.include "resistors.sp"\nV1 rail 0 5\n.end\n', encoding="utf-8")
    resistor_file = tmp_path / "resistors.sp"
    resistor_file.write_text("R1 rail out 2k\nR2 out 0 3k\n", encoding="utf-8")
    report = solve_dc_path(source)
    assert report.status == "solved" and len(report.files) == 2
    destination = tmp_path / "output.json"
    assert main(["linear-dc", str(source), "--format", "json", "--output", str(destination)]) == 0
    assert json.loads(destination.read_text())["nodes"]["out"] == "3"
    assert main(["linear-dc", str(source), "--output", str(destination)]) == 3
    assert main(["linear-dc", str(source), "--output", str(resistor_file), "--force"]) == 3
    assert resistor_file.read_text().startswith("R1")
    text = io.StringIO()
    assert main(["linear-dc", str(source)], stdout=text) == 0
    assert "linear-rvi-v1" in text.getvalue()


def test_limits_return_budget_status_and_cli_unsupported_is_nonzero(tmp_path: Path) -> None:
    report = solve_dc_text(DECK, limits=DCLimits(max_operations=1))
    assert report.status == "budget-exceeded" and report.solution is None
    source = tmp_path / "source.sp"
    source.write_text("C1 a 0 1p\n", encoding="utf-8")
    assert main(["linear-dc", str(source)], stdout=io.StringIO()) == 2


def test_report_schema_describes_solved_and_fail_closed_shapes() -> None:
    schema = json.loads(Path("docs/schemas/linear-dc-report-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for source in (DECK, "R1 a b 1", "V1 0 0 1", "C1 a 0 1p"):
        report = solve_dc_text(source).as_dict()
        validator.validate(report)
        if report["status"] != "solved":
            report["nodes"] = {"0": "0"}
            assert list(validator.iter_errors(report))


def test_text_api_preflights_bytes_and_metadata_before_bundle_allocation() -> None:
    for text in ("x" * 2_000_001, "*" + "\u4e2d" * 700_000, "*\ud800", "R1 a 0 1\0"):
        with pytest.raises(DCInputError):
            solve_dc_text(text)
    for name in ("x" * 1025, "x\u202e.sp", "e\u0301.sp"):
        with pytest.raises(DCInputError):
            solve_dc_text(DECK, virtual_name=name)
    with pytest.raises(DCInputError):
        solve_dc_text(DECK, limits=None)  # type: ignore[arg-type]
    with pytest.raises(DCInputError):
        solve_dc_path("ignored.sp", limits=None)  # type: ignore[arg-type]


def test_report_budget_fails_before_building_the_wire_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    from schematic_airlock import dc_netlist

    report = solve_dc_text(DECK)
    monkeypatch.setattr(dc_netlist, "_MAX_REPORT_BYTES", 4200)
    with pytest.raises(DCBudgetExceeded, match="output budget"):
        report.as_dict()
    for render in (dc_netlist.dc_report_json, dc_netlist.dc_report_text):
        with pytest.raises(DCBudgetExceeded, match="output budget"):
            render(report)
