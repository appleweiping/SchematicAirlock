"""Stable JSON and compact terminal rendering for audit reports."""

from __future__ import annotations

import json
from collections.abc import Mapping

from schematic_airlock.domain import AuditReport, InputError


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
    """Load and minimally validate a SchematicAirlock JSON report."""

    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"report is invalid JSON: {exc.msg}") from exc
    if not isinstance(value, Mapping):
        raise InputError("report must contain a JSON object")
    if value.get("schema_version") != 1:
        raise InputError("report schema_version must be 1")
    tool = value.get("tool")
    if not isinstance(tool, Mapping) or tool.get("name") != "SchematicAirlock":
        raise InputError("report was not produced by SchematicAirlock")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise InputError("report findings must be an array")
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
