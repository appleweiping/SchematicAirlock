"""Immutable domain objects shared by the audit pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Any

from schematic_airlock._version import __version__


class Decision(StrEnum):
    """Final gate result, ordered from least to most restrictive."""

    ALLOW = "allow"
    REVIEW = "review"
    DENY = "deny"

    @property
    def rank(self) -> int:
        return {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.DENY: 2}[self]


class Severity(StrEnum):
    """Effect a finding has before policy overrides are applied."""

    INFO = "info"
    REVIEW = "review"
    DENY = "deny"

    @property
    def rank(self) -> int:
        return {Severity.INFO: 0, Severity.REVIEW: 1, Severity.DENY: 2}[self]


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """One-based location in a bundle-relative source file."""

    path: str
    line: int = 1
    column: int = 1

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "line": self.line, "column": self.column}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single human-auditable observation."""

    code: str
    title: str
    severity: Severity
    message: str
    location: SourceLocation | None = None
    evidence: str = ""
    remediation: str = ""
    metadata: Mapping[str, object] = field(default_factory=dict)

    @property
    def finding_id(self) -> str:
        location = "<bundle>"
        if self.location is not None:
            location = f"{self.location.path}:{self.location.line}:{self.location.column}"
        payload = f"{self.code}\0{location}\0{self.message}".encode()
        return f"{self.code}-{sha256(payload).hexdigest()[:10]}"

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.finding_id,
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "metadata": dict(sorted(self.metadata.items())),
        }
        result["location"] = self.location.as_dict() if self.location else None
        return result


@dataclass(frozen=True, slots=True)
class FileDigest:
    """Digest of one file actually read during an audit."""

    path: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class AuditStats:
    """Stable counters useful in CI and regression tests."""

    files: int = 0
    bytes: int = 0
    logical_lines: int = 0
    devices: int = 0
    nets: int = 0
    subcircuits: int = 0
    expanded_instances: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "files": self.files,
            "bytes": self.bytes,
            "logical_lines": self.logical_lines,
            "devices": self.devices,
            "nets": self.nets,
            "subcircuits": self.subcircuits,
            "expanded_instances": self.expanded_instances,
        }


@dataclass(frozen=True, slots=True)
class AuditStructure:
    """Case-normalized structural facts retained for independent interop checks."""

    includes: int
    element_families: tuple[tuple[str, int], ...]
    parameters: tuple[str, ...]
    models: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Complete deterministic result of an audit."""

    decision: Decision
    risk_score: int
    root: str
    entry: str
    bundle_sha256: str
    policy_sha256: str
    files: tuple[FileDigest, ...]
    findings: tuple[Finding, ...]
    stats: AuditStats
    structure: AuditStructure = AuditStructure(0, (), (), ())
    tool_version: str = __version__

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "tool": {"name": "SchematicAirlock", "version": self.tool_version},
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "root": self.root,
            "entry": self.entry,
            "bundle_sha256": self.bundle_sha256,
            "policy_sha256": self.policy_sha256,
            "files": [item.as_dict() for item in self.files],
            "stats": self.stats.as_dict(),
            "findings": [finding.as_dict() for finding in self.findings],
        }


class AirlockError(Exception):
    """Base class for expected input and policy failures."""


class InputError(AirlockError):
    """The artifact bundle cannot be safely opened."""


class PolicyError(AirlockError):
    """A policy is malformed or internally inconsistent."""


class SyntaxFailure(AirlockError):
    """A source file cannot be parsed safely."""

    def __init__(self, message: str, location: SourceLocation, evidence: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.location = location
        self.evidence = evidence


def json_safe(value: Any) -> object:
    """Convert small metadata values into deterministic JSON-compatible data."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [json_safe(item) for item in value]
    return str(value)
