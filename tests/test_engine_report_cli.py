from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from schematic_airlock import AuditPolicy, Decision, audit_path, audit_text
from schematic_airlock.cli import EXIT_GATE, EXIT_INPUT, EXIT_OK, main
from schematic_airlock.domain import InputError, PolicyError, Severity
from schematic_airlock.report import explain_finding, load_report, report_json, report_text

FIXTURES = Path(__file__).parent / "fixtures"


def test_safe_fixture_audit_is_deterministic_and_non_denied() -> None:
    first = audit_path(FIXTURES / "safe_bundle")
    second = audit_path(FIXTURES / "safe_bundle")
    assert first == second
    assert first.decision is Decision.ALLOW
    assert first.risk_score == 0
    assert first.stats.files == 3
    assert first.stats.devices == 6
    assert first.stats.subcircuits == 1
    assert first.bundle_sha256 == second.bundle_sha256
    assert first.policy_sha256 == AuditPolicy().fingerprint()


def test_unsafe_fixture_collects_independent_denials() -> None:
    report = audit_path(FIXTURES / "unsafe_bundle")
    result_codes = {finding.code for finding in report.findings}
    assert report.decision is Decision.DENY
    assert report.risk_score == 100
    assert {
        "EXEC001",
        "ANL001",
        "ELEM002",
        "PORT001",
        "NET002",
        "SRC001",
        "RAIL001",
    } <= result_codes


def test_audit_text_is_single_file_and_reports_ambient_include() -> None:
    report = audit_text(".include models.lib\nR1 a 0 1k\n", virtual_name="generated.sp")
    assert report.root == "<memory>"
    assert report.entry == "generated.sp"
    assert report.files[0].path == "generated.sp"
    assert report.decision is Decision.DENY
    assert "PATH001" in {finding.code for finding in report.findings}


def test_policy_severity_override_changes_final_decision() -> None:
    default = audit_text("Z1 custom thing\n")
    assert default.decision is Decision.REVIEW
    policy = AuditPolicy.from_mapping(
        {
            "rules": {
                "severity_overrides": {
                    "ELEM001": "info",
                    "NET001": "info",
                }
            }
        }
    )
    overridden = audit_text("Z1 custom thing\n", policy=policy)
    assert overridden.decision is Decision.ALLOW
    assert all(finding.severity is Severity.INFO for finding in overridden.findings)


def test_report_json_round_trip_has_stable_schema() -> None:
    report = audit_text("R1 a 0 1k\n")
    compact = report_json(report)
    pretty = report_json(report, pretty=True)
    assert compact.endswith("\n")
    assert pretty.endswith("\n")
    assert '\n  "' in pretty
    loaded = load_report(compact)
    assert loaded == report.as_dict()
    assert json.loads(compact)["schema_version"] == 1


def test_human_report_includes_summary_and_finding_id() -> None:
    report = audit_text(".control\n")
    text = report_text(report)
    assert text.startswith("SchematicAirlock: DENY")
    assert "entry: input.sp" in text
    assert "stats:" in text
    assert report.findings[0].finding_id in text
    assert "EXEC001" in text


def test_human_report_says_none_for_empty_findings() -> None:
    report = audit_text("V1 vdd 0 1\nR1 vdd out 1k\nR2 out 0 1k\n")
    assert report.findings == ()
    assert "findings: none" in report_text(report)


def test_explain_finding_uses_stored_evidence_and_remediation() -> None:
    report = audit_text(".control\n")
    finding = next(item for item in report.findings if item.code == "EXEC001")
    text = explain_finding(load_report(report_json(report)), finding.finding_id)
    assert "Executable simulator command" in text
    assert "test" not in text
    assert ".control" in text
    assert "remediation:" in text


@pytest.mark.parametrize(
    "value",
    [
        "not json",
        "[]",
        '{"schema_version":2,"tool":{"name":"SchematicAirlock"},"findings":[]}',
        '{"schema_version":1,"tool":{"name":"Other"},"findings":[]}',
        '{"schema_version":1,"tool":{"name":"SchematicAirlock"},"findings":{}}',
    ],
)
def test_load_report_rejects_confusing_documents(value: str) -> None:
    with pytest.raises(InputError):
        load_report(value)


def test_explain_rejects_unknown_id() -> None:
    report = load_report(report_json(audit_text("R1 a 0 1k\n")))
    with pytest.raises(InputError, match="not present"):
        explain_finding(report, "NOPE-0000000000")


def test_policy_defaults_validate_and_fingerprint_stably() -> None:
    policy = AuditPolicy()
    policy.validate()
    assert len(policy.fingerprint()) == 64
    assert policy.fingerprint() == AuditPolicy.from_mapping({}).fingerprint()
    assert policy.as_dict()["schema_version"] == 1


@pytest.mark.parametrize(
    "mapping",
    [
        {7: {}},
        {"limits": {7: 1}},
        {"electrical": {7: 1}},
        {"rules": {7: "deny"}},
        {"rules": {"severity_overrides": {7: "deny"}}},
        {"rules": {"severity_overrides": {"": "deny"}}},
        {"rules": {"severity_overrides": {"elem001": "deny", "ELEM001": "review"}}},
    ],
)
def test_policy_mapping_requires_string_field_and_severity_code_names(mapping) -> None:
    with pytest.raises(PolicyError, match=r"strings|string|unique"):
        AuditPolicy.from_mapping(mapping)


@pytest.mark.parametrize(
    "mapping",
    [
        {"unknown": 1},
        {"schema_version": 2},
        {"schema_version": True},
        {"limits": []},
        {"limits": {"max_files": 0}},
        {"limits": {"max_files": "bad"}},
        {"limits": {"max_file_bytes": 200, "max_total_bytes": 100}},
        {"electrical": {"required_ports": "vin"}},
        {"electrical": {"max_abs_source_voltage": 0}},
        {"electrical": {"ground_nets": ["same"], "power_nets": ["SAME"]}},
        {"rules": {"unknown_directive": "maybe"}},
        {"rules": {"severity_overrides": []}},
        {"rules": {"extra": True}},
    ],
)
def test_policy_rejects_unknown_ambiguous_or_unsafe_values(mapping: dict[str, object]) -> None:
    with pytest.raises(PolicyError):
        AuditPolicy.from_mapping(mapping)


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_policy_limit_requires_exact_toml_integer(value: object) -> None:
    with pytest.raises(PolicyError):
        AuditPolicy.from_mapping({"limits": {"max_files": value}})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, True, "2"])
def test_policy_voltage_limit_requires_positive_finite_number(value: object) -> None:
    with pytest.raises(PolicyError):
        AuditPolicy.from_mapping({"electrical": {"max_abs_source_voltage": value}})


def test_policy_from_toml_and_cli_validation(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(
        """schema_version = 1
[rules]
unknown_directive = "info"
[rules.severity_overrides]
EXEC001 = "review"
""",
        encoding="utf-8",
    )
    loaded = AuditPolicy.from_toml(policy_path)
    assert loaded.rules.unknown_directive is Severity.INFO
    assert loaded.rules.severity_overrides["EXEC001"] is Severity.REVIEW
    stdout = io.StringIO()
    assert main(["policy-check", str(policy_path)], stdout=stdout) == EXIT_OK
    assert stdout.getvalue().startswith("valid policy: sha256:")


def test_cli_audit_text_and_json_thresholds(tmp_path: Path) -> None:
    source = tmp_path / "review.sp"
    source.write_text("Z1 custom data\n", encoding="utf-8")
    stdout = io.StringIO()
    assert main(["audit", str(source)], stdout=stdout) == EXIT_GATE
    assert "REVIEW" in stdout.getvalue()
    stdout = io.StringIO()
    assert (
        main(
            ["audit", str(source), "--format", "json", "--pretty", "--fail-on", "deny"],
            stdout=stdout,
        )
        == EXIT_OK
    )
    assert json.loads(stdout.getvalue())["decision"] == "review"


def test_cli_writes_report_and_explains_it(tmp_path: Path) -> None:
    source = tmp_path / "deny.sp"
    destination = tmp_path / "report.json"
    source.write_text(".control\n", encoding="utf-8")
    stdout = io.StringIO()
    assert (
        main(
            ["audit", str(source), "--format", "json", "--output", str(destination)],
            stdout=stdout,
        )
        == EXIT_GATE
    )
    assert stdout.getvalue() == ""
    data = json.loads(destination.read_text(encoding="utf-8"))
    finding_id = data["findings"][0]["id"]
    explanation = io.StringIO()
    assert main(["explain", str(destination), finding_id], stdout=explanation) == EXIT_OK
    assert "EXEC001" in explanation.getvalue()


def test_cli_fingerprint_default_policy() -> None:
    stdout = io.StringIO()
    assert main(["fingerprint"], stdout=stdout) == EXIT_OK
    assert stdout.getvalue().strip() == AuditPolicy().fingerprint()


def test_cli_input_error_has_dedicated_exit_code(tmp_path: Path) -> None:
    errors = io.StringIO()
    result = main(["audit", str(tmp_path / "missing.sp")], stderr=errors)
    assert result == EXIT_INPUT
    assert errors.getvalue().startswith("schematic-airlock:")


def test_cli_argument_errors_return_input_code_without_system_exit() -> None:
    errors = io.StringIO()
    assert main(["audit"], stderr=errors) == EXIT_INPUT
    assert "required" in errors.getvalue()


def test_cli_does_not_run_subprocess_or_open_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "hostile.sp"
    source.write_text(".control\nshell calc\n.endc\n", encoding="utf-8")

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("external execution is forbidden")

    monkeypatch.setattr("subprocess.Popen", fail)
    monkeypatch.setattr("socket.socket", fail)
    assert main(["audit", str(source)], stdout=io.StringIO()) == EXIT_GATE


def test_file_order_does_not_change_bundle_or_report(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root, order in ((first, ("a.lib", "b.lib")), (second, ("b.lib", "a.lib"))):
        root.mkdir()
        (root / "top.sp").write_text(".include a.lib\n.include b.lib\n", encoding="utf-8")
        contents = {"a.lib": "R1 a 0 1\n", "b.lib": "R2 b 0 2\n"}
        for name in order:
            (root / name).write_text(contents[name], encoding="utf-8")
    one = audit_path(first, entry="top.sp")
    two = audit_path(second, entry="top.sp")
    assert one.bundle_sha256 == two.bundle_sha256
    assert one.findings == two.findings
    assert one.stats == two.stats


def test_source_edit_changes_bundle_hash_but_not_policy_hash(tmp_path: Path) -> None:
    source = tmp_path / "a.sp"
    source.write_text("R1 a 0 1\n", encoding="utf-8")
    first = audit_path(source)
    source.write_text("R1 a 0 2\n", encoding="utf-8")
    second = audit_path(source)
    assert first.bundle_sha256 != second.bundle_sha256
    assert first.policy_sha256 == second.policy_sha256
