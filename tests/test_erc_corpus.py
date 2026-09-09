from __future__ import annotations

import ast
import re
import unicodedata
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

import pytest

from schematic_airlock import AuditPolicy, audit_path, check_voltages_path
from schematic_airlock._strict_json import load_strict_json_path
from schematic_airlock.domain import AuditReport
from schematic_airlock.voltage_rules import voltage_rules_from_mapping

CORPUS = Path(__file__).parent / "corpus" / "erc"
RULE_ID = re.compile(r"[A-Z]+[0-9]{3}\Z", re.ASCII)
NON_ELECTRICAL_RULE_FUNCTIONS = {
    "_load_findings",
    "_graph_findings",
    "_directive_findings",
    "_analysis_findings",
}
AUDIT_FIELDS = {
    "id",
    "runner",
    "bundle",
    "entry",
    "boundary",
    "physical_explanation",
    "expected_decision",
    "expected_rule_ids",
    "expected_severities",
    "forbidden_rule_ids",
    "policy",
}
VOLTAGE_FIELDS = {
    "id",
    "runner",
    "bundle",
    "entry",
    "boundary",
    "physical_explanation",
    "rules",
    "expected_status",
    "expected_checks",
    "expected_note_fragments",
}


def _object(value: object, label: str) -> dict[str, object]:
    assert isinstance(value, dict), f"{label} must be an object"
    assert all(isinstance(key, str) for key in value), f"{label} keys must be strings"
    return value


def _strings(value: object, label: str) -> list[str]:
    assert isinstance(value, list), f"{label} must be an array"
    assert all(isinstance(item, str) for item in value), f"{label} items must be strings"
    return value


def _load_manifest() -> dict[str, object]:
    return _object(
        load_strict_json_path(CORPUS / "manifest.json", context="ERC corpus manifest"),
        "manifest",
    )


MANIFEST = _load_manifest()
CASES = [_object(item, "case") for item in MANIFEST.get("cases", [])]


def _case_path(case: Mapping[str, object]) -> tuple[Path, str]:
    bundle = case["bundle"]
    entry = case["entry"]
    assert isinstance(bundle, str) and isinstance(entry, str)
    relative = PurePosixPath(bundle, entry)
    assert not relative.is_absolute() and ".." not in relative.parts
    target = CORPUS.joinpath(*relative.parts)
    assert target.is_file() and not target.is_symlink()
    assert target.resolve().is_relative_to(CORPUS.resolve())
    return target.parent, target.name


def _audit_case(case: Mapping[str, object]) -> AuditReport:
    bundle, entry = _case_path(case)
    policy = _object(case.get("policy", {}), f"{case['id']}.policy")
    return audit_path(bundle, entry=entry, policy=AuditPolicy.from_mapping(policy))


def _runtime_electrical_rule_ids() -> set[str]:
    source = Path(__file__).parents[1] / "src" / "schematic_airlock" / "checks.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    run_checks = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_checks"
    )
    dispatched_functions = {
        item.id
        for node in ast.walk(run_checks)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and node.target.id == "rule"
        and isinstance(node.iter, ast.Tuple)
        for item in node.iter.elts
        if isinstance(item, ast.Name)
    }
    assert dispatched_functions >= NON_ELECTRICAL_RULE_FUNCTIONS
    electrical_functions = dispatched_functions - NON_ELECTRICAL_RULE_FUNCTIONS
    definitions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert electrical_functions <= definitions.keys()
    rules: set[str] = set()
    pending = list(electrical_functions)
    visited: set[str] = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        node = definitions[name]
        rules.update(
            value.value
            for value in ast.walk(node)
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and RULE_ID.fullmatch(value.value)
        )
        pending.extend(
            call.func.id
            for call in ast.walk(node)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in definitions
        )
    return rules


def test_corpus_manifest_is_strict_complete_and_bounded() -> None:
    assert set(MANIFEST) == {
        "schema",
        "version",
        "description",
        "electrical_rule_inventory",
        "device_family_inventory",
        "voltage_status_inventory",
        "cases",
    }
    assert MANIFEST["schema"] == "org.schematic-airlock.erc-regression-corpus"
    assert MANIFEST["version"] == 1
    assert isinstance(MANIFEST["description"], str)
    assert 1 <= len(CASES) <= 100

    case_ids: set[str] = set()
    referenced: set[Path] = set()
    boundaries: set[str] = set()
    for case in CASES:
        case_id = case.get("id")
        assert isinstance(case_id, str) and re.fullmatch(r"[a-z0-9-]{1,80}", case_id)
        assert unicodedata.normalize("NFC", case_id) == case_id
        assert case_id not in case_ids
        case_ids.add(case_id)
        explanation = case.get("physical_explanation")
        assert isinstance(explanation, str) and 80 <= len(explanation.encode("utf-8")) <= 500
        assert case.get("boundary") in {"positive", "negative", "indeterminate"}
        boundaries.add(str(case["boundary"]))
        target = _case_path(case)[0] / str(case["entry"])
        assert target not in referenced
        referenced.add(target)

        runner = case.get("runner")
        assert runner in {"audit", "voltage"}
        allowed = AUDIT_FIELDS if runner == "audit" else VOLTAGE_FIELDS
        assert not set(case) - allowed
        required = allowed - (
            {"forbidden_rule_ids", "policy"} if runner == "audit" else {"expected_note_fragments"}
        )
        assert required <= set(case)

    assert boundaries == {"positive", "negative", "indeterminate"}
    assert referenced == set((CORPUS / "audit").glob("*.sp")) | set(
        (CORPUS / "ports").glob("*.sp")
    ) | set((CORPUS / "voltage").glob("*.sp"))


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.get("runner") == "audit"],
    ids=lambda case: str(case["id"]),
)
def test_audit_corpus_case(case: Mapping[str, object]) -> None:
    expected = _strings(case["expected_rule_ids"], f"{case['id']}.expected_rule_ids")
    expected_severities = _object(case["expected_severities"], f"{case['id']}.expected_severities")
    assert all(RULE_ID.fullmatch(code) for code in expected)
    assert set(expected_severities) == set(expected)
    assert set(expected_severities.values()) <= {"info", "review", "deny"}

    report = _audit_case(case)

    assert report.decision.value == case["expected_decision"]
    assert sorted(finding.code for finding in report.findings) == sorted(expected)
    assert all(
        finding.severity.value == expected_severities[finding.code] for finding in report.findings
    )
    forbidden = set(_strings(case.get("forbidden_rule_ids", []), "forbidden_rule_ids"))
    assert forbidden.isdisjoint(finding.code for finding in report.findings)


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.get("runner") == "voltage"],
    ids=lambda case: str(case["id"]),
)
def test_voltage_corpus_case(case: Mapping[str, object]) -> None:
    bundle, entry = _case_path(case)
    rules = voltage_rules_from_mapping(case["rules"])

    report = check_voltages_path(bundle, entry=entry, rules=rules)

    expected_checks = _object(case["expected_checks"], f"{case['id']}.expected_checks")
    assert all(
        isinstance(name, str) and isinstance(status, str)
        for name, status in expected_checks.items()
    )
    assert report.status == case["expected_status"]
    assert {check.name: check.status for check in report.checks} == expected_checks
    for fragment in _strings(case.get("expected_note_fragments", []), "expected_note_fragments"):
        assert any(fragment in note for note in report.notes)


def test_corpus_inventory_covers_every_electrical_rule_family_and_voltage_status() -> None:
    declared_rules = set(_strings(MANIFEST["electrical_rule_inventory"], "rule inventory"))
    declared_devices = set(_strings(MANIFEST["device_family_inventory"], "device inventory"))
    declared_statuses = set(_strings(MANIFEST["voltage_status_inventory"], "status inventory"))
    observed_rules: set[str] = set()
    observed_devices: set[str] = set()
    observed_statuses: set[str] = set()

    for case in CASES:
        if case["runner"] == "audit":
            report = _audit_case(case)
            observed_rules.update(finding.code for finding in report.findings)
            observed_devices.update(family for family, _count in report.structure.element_families)
        else:
            bundle, entry = _case_path(case)
            report = check_voltages_path(
                bundle, entry=entry, rules=voltage_rules_from_mapping(case["rules"])
            )
            observed_statuses.add(report.status)

    assert declared_rules == _runtime_electrical_rule_ids()
    assert declared_rules <= observed_rules
    assert declared_devices == observed_devices
    assert declared_statuses == observed_statuses
