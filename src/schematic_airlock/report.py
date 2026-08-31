"""Stable JSON and compact terminal rendering for audit reports."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from schematic_airlock._strict_json import load_strict_json, load_strict_json_path
from schematic_airlock.domain import AuditReport, InputError

_REPORT_FIELDS = {
    "schema_version",
    "tool",
    "decision",
    "risk_score",
    "root",
    "entry",
    "bundle_sha256",
    "policy_sha256",
    "files",
    "stats",
    "findings",
}
_STATS_FIELDS = {
    "files",
    "bytes",
    "logical_lines",
    "devices",
    "nets",
    "subcircuits",
    "expanded_instances",
}
_FINDING_FIELDS = {
    "id",
    "code",
    "title",
    "severity",
    "message",
    "evidence",
    "remediation",
    "metadata",
    "location",
}


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise InputError(f"{context} fields are invalid")


def _text(value: object, context: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise InputError(f"{context} must be a{' non-empty' if not empty else ''} string")
    return value


def _integer(value: object, context: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InputError(f"{context} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise InputError(f"{context} must not exceed {maximum}")
    return value


def _digest(value: object, context: str) -> str:
    text = _text(value, context)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise InputError(f"{context} must be a lowercase SHA-256 digest")
    return text


def _portable_path(value: object, context: str) -> str:
    text = _text(value, context)
    path = PurePosixPath(text)
    if "\\" in text or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise InputError(f"{context} must be a portable bundle-relative path")
    return text


def report_json(report: AuditReport, *, pretty: bool = False) -> str:
    """Serialize a report without timestamps or platform-dependent values."""

    return (
        json.dumps(
            report.as_dict(),
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    )


def report_text(report: AuditReport) -> str:
    """Render a concise report suitable for logs and human review."""

    lines = [
        f"SchematicAirlock: {report.decision.value.upper()} (risk {report.risk_score}/100)",
        f"entry: {report.entry}",
        f"bundle: sha256:{report.bundle_sha256}",
        f"policy: sha256:{report.policy_sha256}",
        (
            "stats: "
            f"{report.stats.files} files, {report.stats.devices} devices, "
            f"{report.stats.nets} nets, {report.stats.expanded_instances} expanded instances"
        ),
    ]
    if not report.findings:
        lines.append("findings: none")
    else:
        lines.append(f"findings: {len(report.findings)}")
        for finding in report.findings:
            location = "bundle"
            if finding.location is not None:
                location = f"{finding.location.path}:{finding.location.line}"
            lines.append(
                f"- [{finding.severity.value.upper()}] {finding.code} "
                f"{location}: {finding.message} ({finding.finding_id})"
            )
    return "\n".join(lines) + "\n"


def load_report(text: str) -> Mapping[str, object]:
    """Strictly decode and validate a SchematicAirlock JSON report."""

    value = load_strict_json(text, context="report JSON")
    return _load_report_value(value)


def load_report_path(path: str | Path) -> Mapping[str, object]:
    """Read a report through the same bounded, strict trust boundary."""

    return _load_report_value(load_strict_json_path(path, context="report JSON"))


def _load_report_value(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InputError("report must contain a JSON object")
    _exact(value, _REPORT_FIELDS, "report")
    schema_version = value["schema_version"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        raise InputError("report schema_version must be 1")
    tool = value["tool"]
    if not isinstance(tool, Mapping):
        raise InputError("report tool must be an object")
    _exact(tool, {"name", "version"}, "report tool")
    if tool["name"] != "SchematicAirlock":
        raise InputError("report was not produced by SchematicAirlock")
    _text(tool["version"], "report tool.version")
    if value["decision"] not in {"allow", "review", "deny"}:
        raise InputError("report decision is invalid")
    _integer(value["risk_score"], "report risk_score", maximum=100)
    _text(value["root"], "report root")
    _portable_path(value["entry"], "report entry")
    _digest(value["bundle_sha256"], "report bundle_sha256")
    _digest(value["policy_sha256"], "report policy_sha256")

    files = value["files"]
    if not isinstance(files, list) or not files:
        raise InputError("report files must be a non-empty array")
    file_names: set[str] = set()
    for index, item in enumerate(files):
        context = f"report files[{index}]"
        if not isinstance(item, Mapping):
            raise InputError(f"{context} must be an object")
        _exact(item, {"path", "size", "sha256"}, context)
        path = _portable_path(item["path"], f"{context}.path")
        if path.casefold() in file_names:
            raise InputError("report file paths must be case-insensitively unique")
        file_names.add(path.casefold())
        _integer(item["size"], f"{context}.size")
        _digest(item["sha256"], f"{context}.sha256")

    stats = value["stats"]
    if not isinstance(stats, Mapping):
        raise InputError("report stats must be an object")
    _exact(stats, _STATS_FIELDS, "report stats")
    for field in _STATS_FIELDS:
        _integer(stats[field], f"report stats.{field}")
    if stats["files"] != len(files):
        raise InputError("report stats.files does not match the file records")

    findings = value["findings"]
    if not isinstance(findings, list):
        raise InputError("report findings must be an array")
    finding_ids: set[str] = set()
    for index, item in enumerate(findings):
        context = f"report findings[{index}]"
        if not isinstance(item, Mapping):
            raise InputError(f"{context} must be an object")
        _exact(item, _FINDING_FIELDS, context)
        finding_id = _text(item["id"], f"{context}.id")
        code = _text(item["code"], f"{context}.code")
        if finding_id in finding_ids or not finding_id.startswith(f"{code}-"):
            raise InputError("report finding IDs must be unique and match their code")
        finding_ids.add(finding_id)
        _text(item["title"], f"{context}.title")
        if item["severity"] not in {"info", "review", "deny"}:
            raise InputError(f"{context}.severity is invalid")
        _text(item["message"], f"{context}.message", empty=True)
        _text(item["evidence"], f"{context}.evidence", empty=True)
        _text(item["remediation"], f"{context}.remediation", empty=True)
        metadata = item["metadata"]
        if not isinstance(metadata, Mapping) or not all(isinstance(key, str) for key in metadata):
            raise InputError(f"{context}.metadata must be an object with string keys")
        location = item["location"]
        if location is not None:
            if not isinstance(location, Mapping):
                raise InputError(f"{context}.location must be an object or null")
            _exact(location, {"path", "line", "column"}, f"{context}.location")
            _portable_path(location["path"], f"{context}.location.path")
            if _integer(location["line"], f"{context}.location.line") < 1:
                raise InputError(f"{context}.location.line must be positive")
            if _integer(location["column"], f"{context}.location.column") < 1:
                raise InputError(f"{context}.location.column must be positive")
    return value


def explain_finding(report: Mapping[str, object], finding_id: str) -> str:
    """Extract a self-contained explanation for one stable finding ID."""

    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise InputError("report findings must be an array")
    for value in findings:
        if not isinstance(value, Mapping) or value.get("id") != finding_id:
            continue
        title = str(value.get("title", "Finding"))
        code = str(value.get("code", "UNKNOWN"))
        severity = str(value.get("severity", "unknown")).upper()
        message = str(value.get("message", ""))
        evidence = str(value.get("evidence", ""))
        remediation = str(value.get("remediation", ""))
        location_value = value.get("location")
        location = "bundle"
        if isinstance(location_value, Mapping):
            location = (
                f"{location_value.get('path', '?')}:"
                f"{location_value.get('line', '?')}:"
                f"{location_value.get('column', '?')}"
            )
        lines = [f"{title} [{code}, {severity}]", f"location: {location}", message]
        if evidence:
            lines.append(f"evidence: {evidence}")
        if remediation:
            lines.append(f"remediation: {remediation}")
        return "\n".join(lines) + "\n"
    raise InputError(f"finding ID not present in report: {finding_id}")
