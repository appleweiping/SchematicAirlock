from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
from datetime import date
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from schematic_airlock import (
    Decision,
    Severity,
    parse_klayout_drc,
    parse_magic_drc,
    parse_magic_pex,
    parse_netgen_lvs,
    verification_report_json,
    verify_path,
)
from schematic_airlock.cli import EXIT_GATE, EXIT_INPUT, EXIT_OK, main
from schematic_airlock.domain import InputError

FIXTURE = Path(__file__).parent / "fixtures" / "verification_bundle"


def _manifest(root: Path) -> dict[str, object]:
    return json.loads((root / "verification.json").read_text(encoding="utf-8"))


def _write_manifest(root: Path, value: dict[str, object]) -> None:
    (root / "verification.json").write_text(
        json.dumps(value, indent=2), encoding="utf-8", newline="\n"
    )


def _copy_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "bundle"
    shutil.copytree(FIXTURE, target)
    return target


def test_complete_fixture_is_content_bound_and_waived() -> None:
    first = verify_path(FIXTURE, as_of=date(2026, 9, 8))
    second = verify_path(FIXTURE / "verification.json", as_of=date(2026, 9, 8))
    assert first.decision is Decision.ALLOW
    assert first.assessment_date == "2026-09-07"
    assert first.evaluated_as_of == "2026-09-08"
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.artifacts == second.artifacts
    assert len(first.lineage) == 4
    assert {item.adapter.value for item in first.lineage} == {
        "magic-drc",
        "klayout-drc",
        "netgen-lvs",
        "magic-pex",
    }
    violation = next(item for item in first.findings if item.rule == "M1.MIN_SPACE")
    assert violation.severity is Severity.DENY
    assert len(violation.finding_id.rsplit("-", 1)[1]) == 64
    assert violation.waived_by == "demo_spacing_reviewed"
    assert first.waivers[0].status == "applied"
    assert first.waivers[0].finding_id == violation.finding_id
    assert all(len(item.digest.sha256) == 64 for item in first.artifacts)
    for record in first.lineage:
        assert len(record.report.sha256) == 64
        assert all(len(item.digest.sha256) == 64 for item in (*record.inputs, *record.outputs))


def test_artifact_edit_changes_only_content_identity(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    before = verify_path(root)
    (root / "design.sp").write_text("R1 changed 0 4k\n", encoding="utf-8")
    after = verify_path(root)
    before_by_id = {item.artifact_id: item for item in before.artifacts}
    after_by_id = {item.artifact_id: item for item in after.artifacts}
    assert before_by_id["schematic"].digest.sha256 != after_by_id["schematic"].digest.sha256
    assert before_by_id["layout"] == after_by_id["layout"]
    assert before_by_id["pex"] == after_by_id["pex"]
    assert before.manifest_sha256 == after.manifest_sha256


def test_report_is_checkout_location_independent(tmp_path: Path) -> None:
    first = verify_path(_copy_fixture(tmp_path / "first"), as_of=date(2026, 9, 8))
    second = verify_path(_copy_fixture(tmp_path / "second"), as_of=date(2026, 9, 8))
    assert first.root == second.root == "."
    assert first.as_dict() == second.as_dict()


def test_magic_drc_normalizes_rule_box_objects_and_clean_result() -> None:
    text = """Cell: sample
Rule: VIA1.ENCLOSURE | Via enclosure is below the project rule
Box: -1um, 2um; 3um, 4um | objects=via_a, M2
"""
    findings = parse_magic_drc(text, source="reports/a.drc", tool_version="8.3.1")
    assert len(findings) == 1
    assert findings[0].rule == "VIA1.ENCLOSURE"
    assert findings[0].objects == ("M2", "via_a")
    assert findings[0].location is not None
    assert findings[0].location.bbox_um == (-1.0, 2.0, 3.0, 4.0)
    assert (
        parse_magic_drc(
            "Cell: sample\nNo DRC errors found.\n",
            source="reports/a.drc",
            tool_version="8.3.1",
        )
        == ()
    )


def test_klayout_drc_normalizes_category_cell_and_box() -> None:
    text = """<report-database>
<description>Synthetic DRC markers</description><original-file/><generator>KLayout</generator>
<top-cell>amp_core</top-cell><tags/>
<categories><category><name>M2.MIN_WIDTH</name>
<description>Metal-2 width is below the project rule</description></category></categories>
<cells><cell><name>amp_core</name><layout-name>amp_core</layout-name></cell></cells>
<items><item><tags/><category>'M2.MIN_WIDTH'</category><cell>amp_core</cell><visited>false</visited>
<multiplicity>1</multiplicity><comment>Synthetic marker</comment><image/><values>
<value>box: (0.1,0.2;0.3,0.4)</value></values></item></items>
</report-database>"""
    finding = parse_klayout_drc(text, source="reports/a.lyrdb", tool_version="0.29.12")[0]
    assert finding.rule == "M2.MIN_WIDTH"
    assert finding.objects == ("amp_core",)
    assert finding.location is not None
    assert finding.location.bbox_um == (0.1, 0.2, 0.3, 0.4)


def test_klayout_drc_supports_native_numeric_cell_variants() -> None:
    text = """<report-database><categories><category><name>WIDTH</name></category></categories>
<cells><cell><name>amp_core</name><variant>1</variant></cell></cells>
<items><item><category>WIDTH</category><cell>amp_core:1</cell>
<values><value>text: synthetic marker</value></values></item></items></report-database>"""
    finding = parse_klayout_drc(text, source="reports/a.lyrdb", tool_version="0.29.12")[0]
    assert finding.rule == "WIDTH"
    assert finding.objects == ("amp_core",)
    assert finding.location is not None
    assert finding.location.bbox_um is None


@pytest.mark.parametrize(
    ("text", "match"),
    [
        (
            '<report-database unsafe="1"><categories/><cells/><items/></report-database>',
            "attributes",
        ),
        (
            "<report-database><categories><category><name>A</name><categories/>"
            "</category></categories><cells/><items/></report-database>",
            "unknown field",
        ),
        (
            "<report-database><categories><category><name>M1.SPACE</name></category>"
            "</categories><cells><cell><name>top</name></cell></cells><items><item>"
            "<category>M1.SPACE</category><cell>top</cell><values><value>text: marker</value>"
            "</values></item></items></report-database>",
            "must quote",
        ),
    ],
)
def test_klayout_native_profile_rejects_ambiguous_structures(text: str, match: str) -> None:
    with pytest.raises(InputError, match=match):
        parse_klayout_drc(text, source="reports/a.lyrdb", tool_version="0.29.12")


@pytest.mark.parametrize(
    ("text", "rules"),
    [
        ("Result: Circuits match uniquely.\nLVS Done\n", set()),
        ("Netlists do not match.\n2 unmatched nets\n", {"LVS.MISMATCH", "LVS.UNMATCHED_NET"}),
        ("Property errors were found.\n", {"LVS.PROPERTY"}),
        ("Error: extraction stopped\n", {"LVS.ERROR"}),
    ],
)
def test_netgen_lvs_terminal_profiles(text: str, rules: set[str]) -> None:
    findings = parse_netgen_lvs(text, source="reports/a.lvs", tool_version="1.5.290")
    assert {item.rule for item in findings} == rules


def test_magic_pex_normalizes_warning_and_error() -> None:
    complete = parse_magic_pex(
        "PEX status: complete\nOutput: out.pex.sp\nDevices: 4\nWarning: fringe model omitted\n",
        source="reports/a.pex",
        tool_version="8.3.1",
    )
    assert [(item.rule, item.severity) for item in complete] == [("PEX.WARNING", Severity.REVIEW)]
    failed = parse_magic_pex(
        "Error: extraction did not finish\n",
        source="reports/a.pex",
        tool_version="8.3.1",
    )
    assert failed[0].rule == "PEX.ERROR"


def test_magic_pex_output_must_match_content_bound_lineage(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    (root / "reports" / "magic.pex").write_text(
        "PEX status: complete\nOutput: different.pex.sp\nDevices: 2\nNets: 3\n",
        encoding="utf-8",
    )
    report = verify_path(root)
    assert report.decision is Decision.DENY
    assert "LINEAGE.PEX_OUTPUT_MISMATCH" in {item.rule for item in report.findings}


def test_physical_file_aliases_are_rejected(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    alias = root / "schematic-alias.sp"
    try:
        os.link(root / "design.sp", alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    value = _manifest(root)
    artifacts = value["artifacts"]
    assert isinstance(artifacts, list)
    artifacts.append({"id": "schematic_alias", "kind": "support", "path": alias.name})
    _write_manifest(root, value)
    with pytest.raises(InputError, match="same physical file"):
        verify_path(root)


@pytest.mark.parametrize(
    ("parser", "text", "match"),
    [
        (
            parse_magic_drc,
            "Rule: M1.SPACE | bad\nBox: NaN 0 1 2\n",
            "non-finite",
        ),
        (
            parse_klayout_drc,
            "<!DOCTYPE x><report-database />",
            "DTD",
        ),
        (
            parse_netgen_lvs,
            "Circuits match uniquely.\nNetlists do not match.\n",
            "conflicting",
        ),
        (
            parse_magic_pex,
            "PEX status: complete\nError: failed\n",
            "conflicting",
        ),
        (
            parse_netgen_lvs,
            "A vague status line\nCircuits match uniquely.\n",
            "ambiguous record",
        ),
    ],
)
def test_adapters_reject_nonfinite_entity_and_ambiguous_results(
    parser, text: str, match: str
) -> None:
    with pytest.raises(InputError, match=match):
        parser(text, source="reports/a.txt", tool_version="1.0")


def test_clean_adapters_still_validate_source_and_version() -> None:
    with pytest.raises(InputError, match="bundle-relative"):
        parse_magic_drc("No DRC errors found.\n", source="../escape.drc", tool_version="8.3.1")
    with pytest.raises(InputError, match="version"):
        parse_klayout_drc(
            "<report-database><categories/><cells/><items/></report-database>",
            source="reports/clean.lyrdb",
            tool_version="not a version",
        )


@pytest.mark.parametrize(
    "source",
    ["./reports/a.drc", "reports//a.drc", "reports/a.drc/", "reports/e\u0301.drc"],
)
def test_adapter_rejects_noncanonical_source_paths(source: str) -> None:
    with pytest.raises(InputError, match=r"bundle-relative|NFC"):
        parse_magic_drc("No DRC errors found.\n", source=source, tool_version="8.3.1")


@pytest.mark.parametrize("unsafe", ["\x7f", "\x85", "\u2028", "\u202e", "\u2066"])
def test_adapter_rejects_unsafe_unicode_in_text_fields(unsafe: str) -> None:
    with pytest.raises(InputError, match="unsafe Unicode control or separator"):
        parse_magic_drc(
            "No DRC errors found.\n",
            source="reports/a.drc",
            tool_version=f"8.3.1{unsafe}",
        )


@pytest.mark.parametrize("value", [None, b"No DRC errors found.\n", 42])
def test_public_adapters_reject_non_text_input(value: object) -> None:
    with pytest.raises(InputError, match="must be text"):
        parse_magic_drc(value, source="reports/a.drc", tool_version="8.3.1")  # type: ignore[arg-type]


def test_public_adapter_does_not_dispatch_to_string_subclass_encode() -> None:
    class HostileText(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise AssertionError("subclass encode must not run")

    assert (
        parse_magic_drc(
            HostileText("No DRC errors found.\n"),
            source="reports/a.drc",
            tool_version="8.3.1",
        )
        == ()
    )


@pytest.mark.parametrize(
    "parser,text",
    [
        (parse_magic_drc, "Cell: bad\ud800\nNo DRC errors found.\n"),
        (
            parse_klayout_drc,
            "<report-database><categories/><cells/><items/>\ud800</report-database>",
        ),
        (parse_netgen_lvs, "warning: bad\ud800\nCircuits match uniquely.\n"),
        (parse_magic_pex, "warning: bad\ud800\nPEX status: complete\nOutput: out.sp\n"),
    ],
)
def test_public_adapters_reject_non_scalar_unicode(parser, text: str) -> None:
    with pytest.raises(InputError, match="Unicode scalar"):
        parser(text, source="reports/a.txt", tool_version="1.0")


def test_public_adapter_enforces_the_same_byte_limit_as_bundle_reports() -> None:
    with pytest.raises(InputError, match="byte limit"):
        parse_magic_drc(
            "x" * (2 * 1024 * 1024 + 1),
            source="reports/a.drc",
            tool_version="8.3.1",
        )


def test_magic_clean_result_rejects_duplicate_cell_metadata() -> None:
    with pytest.raises(InputError, match="ambiguous cell"):
        parse_magic_drc(
            "Cell: first\nCell: second\nNo DRC errors found.\n",
            source="reports/a.drc",
            tool_version="8.3.1",
        )
    with pytest.raises(InputError, match="non-empty string"):
        parse_magic_drc(
            "Cell:\nNo DRC errors found.\n",
            source="reports/a.drc",
            tool_version="8.3.1",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("<categories>", "hidden<categories>", 1),
        lambda text: text.replace("<name>amp_core</name>", "<name>amp_core<x/></name>", 1),
        lambda text: text.replace("</value>", "<x/></value>", 1),
    ],
)
def test_klayout_rejects_mixed_or_nested_unrepresented_xml(mutation) -> None:
    text = """<report-database><categories><category><name>M1.SPACE</name>
<description>spacing</description></category></categories><cells><cell><name>amp_core</name>
</cell></cells><items><item><category>'M1.SPACE'</category><cell>amp_core</cell>
<values><value>box: (0,0;1,1)</value></values></item></items></report-database>"""
    with pytest.raises(InputError, match=r"mixed text|nested|exactly one"):
        parse_klayout_drc(mutation(text), source="reports/a.lyrdb", tool_version="0.29.12")


def test_netgen_unmatched_record_rejects_unparsed_suffix() -> None:
    with pytest.raises(InputError, match="ambiguous record"):
        parse_netgen_lvs(
            "1 unmatched net ignored-suffix\nNetlists do not match.\n",
            source="reports/a.lvs",
            tool_version="1.5.290",
        )


def test_adapter_findings_are_deterministic() -> None:
    parsers = (
        (
            parse_magic_drc,
            "Rule: M1.SPACE | spacing failure\nBox: 0 0 1 1\n",
        ),
        (
            parse_klayout_drc,
            """<report-database><categories><category><name>M1.SPACE</name>
<description>spacing failure</description></category></categories><cells><cell>
<name>top</name></cell></cells><items><item><category>'M1.SPACE'</category><cell>top</cell>
<values><value>box: (0,0;1,1)</value></values></item></items></report-database>""",
        ),
        (parse_netgen_lvs, "Netlists do not match.\n"),
        (parse_magic_pex, "Error: failed\n"),
    )
    for parser, text in parsers:
        first = parser(text, source="reports/result.txt", tool_version="1.2.3")
        second = parser(text, source="reports/result.txt", tool_version="1.2.3")
        assert first == second
        assert [item.finding_id for item in first] == [item.finding_id for item in second]


def test_expired_and_unused_waivers_do_not_weaken_gate(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    waivers = value["waivers"]
    assert isinstance(waivers, list)
    active = waivers[0]
    assert isinstance(active, dict)
    active["expires"] = "2020-01-01"
    waivers.append(
        {
            "id": "unused_exact_waiver",
            "finding_id": (
                "LVS.MISMATCH-0000000000000000000000000000000000000000000000000000000000000000"
            ),
            "tool": "Netgen",
            "rule": "LVS.MISMATCH",
            "source": "reports/netgen.lvs",
            "line": 3,
            "objects": [],
            "expires": "2099-01-01",
            "reason": "Exercises stale-waiver detection.",
        }
    )
    _write_manifest(root, value)
    report = verify_path(root)
    assert report.decision is Decision.DENY
    assert {item.status for item in report.waivers} == {"expired", "unused"}
    assert {item.rule for item in report.findings} >= {
        "M1.MIN_SPACE",
        "WAIVER.EXPIRED",
        "WAIVER.UNUSED",
    }


def test_manifest_date_cannot_backdate_waiver_expiration(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    value["assessment_date"] = "2000-01-01"
    waivers = value["waivers"]
    assert isinstance(waivers, list)
    waiver = waivers[0]
    assert isinstance(waiver, dict)
    waiver["expires"] = "2001-01-01"
    _write_manifest(root, value)

    report = verify_path(root, as_of=date(2026, 9, 8))

    assert report.assessment_date == "2000-01-01"
    assert report.evaluated_as_of == "2026-09-08"
    assert report.decision is Decision.DENY
    assert report.waivers[0].status == "expired"


def test_future_manifest_date_and_invalid_as_of_are_rejected(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    value["assessment_date"] = "2026-09-09"
    _write_manifest(root, value)
    with pytest.raises(InputError, match="later than the evaluation date"):
        verify_path(root, as_of=date(2026, 9, 8))
    with pytest.raises(InputError, match="as_of must be"):
        verify_path(root, as_of="2026-09-08")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "path",
    ["reports/foo:stream", "reports/NUL.txt", "reports/bad*name", "reports/trailing."],
)
def test_manifest_rejects_nonportable_windows_path_components(tmp_path: Path, path: str) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    value["reports"][0]["path"] = path
    _write_manifest(root, value)
    with pytest.raises(InputError, match="portable bundle-relative path"):
        verify_path(root, as_of=date(2026, 9, 8))


def test_changed_diagnostic_cannot_inherit_a_stale_finding_waiver(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    magic = root / "reports" / "magic.drc"
    magic.write_text(
        magic.read_text(encoding="utf-8").replace("project minimum", "reviewed minimum"),
        encoding="utf-8",
    )

    report = verify_path(root)

    spacing = next(item for item in report.findings if item.rule == "M1.MIN_SPACE")
    original_finding_id = (
        "M1.MIN_SPACE-a36e8f186f1be849956a878fe984efd43f3fb603ca2923ca8365c5e2b0467c62"
    )
    assert spacing.finding_id != original_finding_id
    assert spacing.waived_by is None
    assert report.decision is Decision.DENY
    assert report.waivers[0].status == "unused"
    assert any(item.rule == "WAIVER.UNUSED" for item in report.findings)


def test_multiple_waivers_for_one_finding_are_rejected(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    waivers = value["waivers"]
    assert isinstance(waivers, list)
    duplicate = dict(waivers[0])
    duplicate["id"] = "second_spacing_waiver"
    waivers.append(duplicate)
    _write_manifest(root, value)
    with pytest.raises(InputError, match="ambiguously match one finding"):
        verify_path(root)


def test_missing_cross_view_and_adapter_edges_are_denied(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    artifacts = value["artifacts"]
    reports = value["reports"]
    assert isinstance(artifacts, list)
    assert isinstance(reports, list)
    value["artifacts"] = [item for item in artifacts if item["kind"] != "pex"]
    value["reports"] = [item for item in reports if item["adapter"] != "magic-pex"]
    value["waivers"] = []
    _write_manifest(root, value)
    report = verify_path(root)
    assert report.decision is Decision.DENY
    assert {item.rule for item in report.findings} >= {
        "LINEAGE.MISSING_VIEW",
        "LINEAGE.MISSING_PEX",
    }


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update({"schema_version": True}), "schema_version"),
        (
            lambda value: value["artifacts"].append(
                {"id": "SCHEMATIC", "kind": "support", "path": "other.sp"}
            ),
            "unique",
        ),
        (
            lambda value: value["artifacts"][0].update({"path": "../escape.sp"}),
            "bundle-relative",
        ),
        (
            lambda value: value["reports"][0]["tool"].update({"name": "KLayout"}),
            "does not match",
        ),
        (
            lambda value: value["reports"][0]["tool"].update({"name": "magic"}),
            "does not match",
        ),
        (
            lambda value: value["reports"][0].update({"inputs": ["LAYOUT"]}),
            "unknown artifact",
        ),
        (
            lambda value: value["reports"][3].update({"outputs": ["layout"]}),
            "both input and output",
        ),
        (
            lambda value: value["waivers"][0].update({"finding_id": "not-a-fingerprint"}),
            "canonical finding identity",
        ),
    ],
)
def test_manifest_rejects_duplicate_traversal_and_ambiguous_data(
    tmp_path: Path, mutation, match: str
) -> None:
    root = _copy_fixture(tmp_path)
    value = _manifest(root)
    mutation(value)
    if "other.sp" in json.dumps(value):
        (root / "other.sp").write_text("fixture\n", encoding="utf-8")
    _write_manifest(root, value)
    with pytest.raises(InputError, match=match):
        verify_path(root)


def test_duplicate_json_key_and_oversized_report_are_rejected(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    text = (root / "verification.json").read_text(encoding="utf-8")
    text = text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    (root / "verification.json").write_text(text, encoding="utf-8")
    with pytest.raises(InputError, match="duplicate key"):
        verify_path(root)

    root = _copy_fixture(tmp_path / "second")
    (root / "reports" / "magic.pex").write_text("X" * (2 * 1024 * 1024 + 1), encoding="utf-8")
    with pytest.raises(InputError, match="byte limit"):
        verify_path(root)


def test_cli_json_output_threshold_and_input_error(tmp_path: Path) -> None:
    stdout = io.StringIO()
    assert (
        main(
            [
                "verification-check",
                str(FIXTURE),
                "--format",
                "json",
                "--pretty",
            ],
            stdout=stdout,
        )
        == EXIT_OK
    )
    value = json.loads(stdout.getvalue())
    assert value["schema_version"] == 1
    assert value["decision"] == "allow"

    root = _copy_fixture(tmp_path)
    manifest = _manifest(root)
    manifest["waivers"] = []
    _write_manifest(root, manifest)
    assert main(["verification-check", str(root)], stdout=io.StringIO()) == EXIT_GATE

    errors = io.StringIO()
    assert main(["verification-check", str(tmp_path / "missing")], stderr=errors) == EXIT_INPUT
    assert "manifest does not exist" in errors.getvalue()


def test_verification_output_refuses_manifest_artifact_and_existing_paths(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    manifest = root / "verification.json"
    before = manifest.read_bytes()
    for force in ([], ["--force"]):
        errors = io.StringIO()
        assert (
            main(
                [
                    "verification-check",
                    str(root),
                    "--format",
                    "json",
                    "--output",
                    str(manifest),
                    *force,
                ],
                stderr=errors,
            )
            == EXIT_INPUT
        )
        assert "aliases an input" in errors.getvalue()
        assert manifest.read_bytes() == before

    destination = root / "verification-report.json"
    destination.write_text("sentinel", encoding="utf-8")
    errors = io.StringIO()
    assert (
        main(
            [
                "verification-check",
                str(root),
                "--format",
                "json",
                "--output",
                str(destination),
            ],
            stderr=errors,
        )
        == EXIT_INPUT
    )
    assert destination.read_text(encoding="utf-8") == "sentinel"
    assert "refusing to overwrite" in errors.getvalue()
    assert (
        main(
            [
                "verification-check",
                str(root),
                "--format",
                "json",
                "--output",
                str(destination),
                "--force",
            ]
        )
        == EXIT_OK
    )
    assert json.loads(destination.read_text(encoding="utf-8"))["decision"] == "allow"


def test_cli_never_opens_process_or_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("external execution is forbidden")

    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(socket, "socket", fail)
    assert main(["verification-check", str(FIXTURE)], stdout=io.StringIO()) == EXIT_OK


def test_report_json_rejects_nonfinite_values() -> None:
    report = verify_path(FIXTURE)
    assert verification_report_json(report) == verification_report_json(report)
    location = next(item.location for item in report.findings if item.location is not None)
    assert location is not None
    assert all(value == value for value in location.bbox_um or ())


def test_published_manifest_and_report_schemas_validate_fixture() -> None:
    schemas = Path(__file__).parents[1] / "docs" / "schemas"
    manifest_schema = json.loads(
        (schemas / "verification-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    report_schema = json.loads(
        (schemas / "verification-report-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(manifest_schema)
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator(manifest_schema, format_checker=FormatChecker()).validate(
        _manifest(FIXTURE)
    )
    Draft202012Validator(report_schema, format_checker=FormatChecker()).validate(
        verify_path(FIXTURE, as_of=date(2026, 9, 8)).as_dict()
    )

    for control in ("\u00ad", "\u061c", "\u180e", "\u202e"):
        unsafe_manifest = _manifest(FIXTURE)
        unsafe_manifest["waivers"][0]["reason"] = f"looks safe{control}but is reordered"
        assert list(Draft202012Validator(manifest_schema).iter_errors(unsafe_manifest))

    unsafe_path_manifest = _manifest(FIXTURE)
    unsafe_path_manifest["reports"][0]["path"] = "reports/foo:stream"
    assert list(Draft202012Validator(manifest_schema).iter_errors(unsafe_path_manifest))
